import os
import socket, os, time, hashlib, itertools
ADDR=os.environ.get("GLASSES_MAC","XX:XX:XX:XX:XX:XX"); BTPROTO_RFCOMM=3
HDR=bytes.fromhex("807080018100000502000001")
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def varint(n):
    o=b""
    while True:
        b=n&0x7f;n>>=7;o+=bytes([b|(0x80 if n else 0)])
        if not n:break
    return o
def ld(f,d):return varint(f<<3|2)+varint(len(d))+d
def vf(f,v):return varint(f<<3|0)+varint(v)
def readvar(b,i):
    s=0;r=0
    while i<len(b):
        c=b[i];i+=1;r|=(c&0x7f)<<s
        if not c&0x80:return r,i
        s+=7
    return 0,-1
def parse(buf):
    out={};i=0
    while i<len(buf):
        k,i=readvar(buf,i)
        if i<0:break
        f=k>>3;wt=k&7
        if wt==0:v,i=readvar(buf,i);out[f]=('var',v)
        elif wt==2:ln,i=readvar(buf,i);out[f]=('len',buf[i:i+ln]);i+=ln
        elif wt==5:out[f]=('i32',buf[i:i+4]);i+=4
        elif wt==1:out[f]=('i64',buf[i:i+8]);i+=8
        else:break
    return out
def body(msg):
    idx=msg.find(b'\x0a\x40'); return msg[idx:], msg[:idx]

def is_p256_point(raw64):
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04'+raw64)
        return True
    except Exception:
        return False

def handshake(our_field1=None):
    """returns dict with our_priv, m1, m2 parsed, or None"""
    for _att in range(8):
        s=socket.socket(socket.AF_BLUETOOTH,socket.SOCK_STREAM,BTPROTO_RFCOMM)
        s.settimeout(4.0)
        try:
            s.connect((ADDR,7)); break
        except OSError as e:
            s.close()
            if e.errno==16: time.sleep(1.5); continue
            raise
    s.settimeout(1.5);m1=b""
    try:
        while True:
            c=s.recv(4096)
            if not c:break
            m1+=c
    except socket.timeout:pass
    priv=ec.generate_private_key(ec.SECP256R1())
    if our_field1 is None:
        f1=priv.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)[1:]
    else:
        f1=our_field1
    ournonce=os.urandom(12)
    s.sendall(HDR+ld(1,f1)+ld(2,os.urandom(16))+vf(3,0)+vf(4,0x31)+ld(5,ournonce)+vf(7,0x17))
    s.settimeout(4.0);m2=b"";t0=time.time()
    try:
        while time.time()-t0<4:
            c=s.recv(4096)
            if not c:break
            m2+=c
    except socket.timeout:pass
    s.close()
    return dict(priv=priv, ournonce=ournonce, m1=m1, m2=m2)

# ---- 1) point validation of server fields ----
h=handshake()
m1b,_=body(h['m1']); m2b,m2hdr=body(h['m2'])
p1=parse(m1b); p2=parse(m2b)
sA=p1[1][1]; sB=p2[1][1]
print("server M1.field1 valid P-256 point?", is_p256_point(sA))
print("server M2.field1 valid P-256 point?", is_p256_point(sB))
print("M2 field2 (ct?) len", len(p2[2][1]), "field3 (tag?) len", len(p2[3][1]))
m1nonce=p1[5][1]; ct=p2[2][1]; tag=p2[3][1]
print("M1 nonce(field5):", m1nonce.hex(), " our nonce:", h['ournonce'].hex())

# ---- 2) does server validate OUR ephemeral as a real point? ----
bad=handshake(our_field1=os.urandom(64))  # invalid point, correct framing
adv = len(bad['m2'])>0
print(f"\nInvalid-point client hello -> server {'ADVANCED (does NOT validate our point)' if adv else 'STALLED (validates our point => real ECDH on our key)'} (m2={len(bad['m2'])}B)")

# ---- 3) decrypt sweep on M2.field2/field3 ----
def ecdh(priv, peer64):
    pk=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04'+peer64)
    return priv.exchange(ec.ECDH(), pk)  # 32B X coord

secrets=[]
try: secrets.append(("ee(sA)", ecdh(h['priv'], sA)))
except Exception as e: print("ecdh sA fail", e)
try: secrets.append(("ee(sB)", ecdh(h['priv'], sB)))
except Exception as e: print("ecdh sB fail", e)

def keys_from(x):
    ks=[]
    ks.append(("sha256", hashlib.sha256(x).digest()))
    ks.append(("sha256[:16]", hashlib.sha256(x).digest()[:16]))
    ks.append(("raw[:16]", x[:16]))
    ks.append(("raw[:32]", x[:32] if len(x)>=32 else x))
    for info in [b"", b"handshake", b"noise", b"session", b"meta", b"data", b"AriaControl", b"key"]:
        for salt in [None, b"", m1nonce, h['ournonce']]:
            try:
                ks.append((f"hkdf32/i={info!r}/s={'n' if salt else '0'}",
                    HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=info).derive(x)))
                ks.append((f"hkdf16/i={info!r}/s={'n' if salt else '0'}",
                    HKDF(algorithm=hashes.SHA256(),length=16,salt=salt,info=info).derive(x)))
            except Exception: pass
    return ks

nonces=[("m1nonce",m1nonce),("ournonce",h['ournonce']),("zeros",b"\x00"*12),
        ("ctr0le",(0).to_bytes(12,'little')),("ctr1le",(1).to_bytes(12,'little')),
        ("ctr0be",(0).to_bytes(12,'big')),("ctr1be",(1).to_bytes(12,'big'))]
aads=[("none",None),("hdr",m2hdr),("empty",b""),("m1",h['m1']),("sA",sA)]

hit=False; tried=0
for sname,x in secrets:
    for kname,key in keys_from(x):
        if len(key) not in (16,32): continue
        aes=AESGCM(key)
        for nname,nonce in nonces:
            for aname,aad in aads:
                tried+=1
                try:
                    pt=aes.decrypt(nonce, ct+tag, aad)
                    print(f"\n*** DECRYPT SUCCESS *** secret={sname} key={kname} nonce={nname} aad={aname}")
                    print("plaintext:", pt.hex())
                    hit=True
                except InvalidTag:
                    pass
                except Exception:
                    pass
print(f"\nsweep tried {tried} combos; {'MATCH FOUND' if hit else 'no combination verified'}")

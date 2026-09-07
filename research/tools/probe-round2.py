import os
import socket, time, os
ADDR=os.environ.get("GLASSES_MAC","XX:XX:XX:XX:XX:XX"); BTPROTO_RFCOMM=3
HDR=bytes.fromhex("807080018100000502000001")
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
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
    out=[];i=0
    while i<len(buf):
        k,i=readvar(buf,i)
        if i<0:break
        f=k>>3;wt=k&7
        if wt==0: v,i=readvar(buf,i);out.append((f,'var',v))
        elif wt==2: ln,i=readvar(buf,i);out.append((f,'len',buf[i:i+ln]));i+=ln
        elif wt==5: out.append((f,'i32',buf[i:i+4]));i+=4
        elif wt==1: out.append((f,'i64',buf[i:i+8]));i+=8
        else: break
    return out
def new_priv():
    return ec.generate_private_key(ec.SECP256R1())
def pub64(k):
    return k.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)[1:]

def do_round(send_round3=None):
    s=socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
    s.settimeout(4.0); s.connect((ADDR,7)); s.settimeout(1.5)
    m1=b""
    try:
        while True:
            c=s.recv(4096)
            if not c:break
            m1+=c
    except socket.timeout:pass
    priv=new_priv()
    hello=HDR+ld(1,pub64(priv))+ld(2,os.urandom(16))+vf(3,0)+vf(4,0x31)+ld(5,os.urandom(12))+vf(7,0x17)
    s.sendall(hello)
    s.settimeout(4.0); m2=b""; t0=time.time()
    try:
        while time.time()-t0<4:
            c=s.recv(4096)
            if not c:break
            m2+=c
    except socket.timeout:pass
    r3state=None; r3resp=b""
    if send_round3 is not None and m2:
        try: s.sendall(send_round3)
        except Exception as e: r3state=f"send_fail:{e!r}"
        if r3state is None:
            s.settimeout(5.0); t0=time.time(); r3state="open_idle"
            try:
                while time.time()-t0<5:
                    c=s.recv(4096)
                    if not c: r3state="closed_EOF"; break
                    r3resp+=c
            except socket.timeout: r3state="open_idle"
            except ConnectionResetError: r3state="RESET"
            except Exception as e: r3state=f"err:{e!r}"
    s.close()
    return m1,m2,priv,r3state,r3resp

# 1) reproduce 3x, confirm server round-2 ephemeral changes
eph=[]
for k in range(3):
    m1,m2,priv,_,_=do_round()
    print(f"run{k}: m1={len(m1)}B m2={len(m2)}B")
    if m2:
        idx=m2.find(b'\x0a\x40'); body=m2[idx:]
        f=parse(body)
        f1=[v for (fn,t,v) in f if fn==1 and t=='len']
        if f1: eph.append(f1[0].hex())
        if k==0:
            print("  m2 header:",m2[:idx].hex())
            for fn,t,v in f:
                vv=v.hex() if isinstance(v,(bytes,bytearray)) else v
                print(f"  m2 field {fn} ({t}, {len(v) if isinstance(v,(bytes,bytearray)) else '-'}): {str(vv)[:60]}")
    time.sleep(0.7)
print("server round-2 ephemerals distinct?", len(set(eph)), "of", len(eph))

# 2) find the verification wall: send a bogus round-3 after a real round-2
time.sleep(0.8)
bogus3=HDR+ld(1,os.urandom(64))+ld(2,os.urandom(16))+vf(3,0)+vf(4,0x31)+ld(5,os.urandom(12))+vf(7,0x17)
m1,m2,priv,st,rr=do_round(send_round3=bogus3)
print(f"\nbogus round-3 test: m2={len(m2)}B then sent bogus msg3 -> state={st} resp={len(rr)}B")
if rr: print("  resp_hex:",rr.hex()[:120])

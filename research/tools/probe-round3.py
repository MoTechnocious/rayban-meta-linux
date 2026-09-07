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
def pub64(k):return k.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)[1:]

def run(msg3):
    s=socket.socket(socket.AF_BLUETOOTH,socket.SOCK_STREAM,BTPROTO_RFCOMM)
    s.settimeout(4.0);s.connect((ADDR,7));s.settimeout(1.5);m1=b""
    try:
        while True:
            c=s.recv(4096)
            if not c:break
            m1+=c
    except socket.timeout:pass
    priv=ec.generate_private_key(ec.SECP256R1())
    s.sendall(HDR+ld(1,pub64(priv))+ld(2,os.urandom(16))+vf(3,0)+vf(4,0x31)+ld(5,os.urandom(12))+vf(7,0x17))
    s.settimeout(4.0);m2=b"";t0=time.time()
    try:
        while time.time()-t0<4:
            c=s.recv(4096)
            if not c:break
            m2+=c
    except socket.timeout:pass
    resp=b"";st="open_idle"
    if m2:
        s.sendall(msg3()); s.settimeout(5.0);t0=time.time()
        try:
            while time.time()-t0<5:
                c=s.recv(4096)
                if not c:st="closed_EOF";break
                resp+=c
        except socket.timeout:st="open_idle"
        except ConnectionResetError:st="RESET"
    s.close();return m2,resp,st

def bogus3(): return HDR+ld(1,os.urandom(64))+ld(2,os.urandom(16))+vf(3,0)+vf(4,0x31)+ld(5,os.urandom(12))+vf(7,0x17)

reps=[]
for k in range(4):
    m2,resp,st=run(bogus3)
    print(f"run{k}: m2={len(m2)}B  bogus-msg3 -> state={st} resp={len(resp)}B  {resp.hex()}")
    if resp: reps.append(resp.hex())
    time.sleep(0.8)
print("distinct round-3 replies:", len(set(reps)), "of", len(reps),
      "=> ", "VARIES (encrypted/nonce'd)" if len(set(reps))>1 else "FIXED (constant nack)")

# also: send a STRUCTURALLY EMPTY msg3 (just header) after real m2
def empty3(): return HDR
m2,resp,st=run(empty3)
print(f"\nempty msg3 (header only) -> state={st} resp={len(resp)}B {resp.hex()}")

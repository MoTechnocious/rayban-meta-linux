import os
import socket, time, os
ADDR=os.environ.get("GLASSES_MAC","XX:XX:XX:XX:XX:XX"); BTPROTO_RFCOMM=3
HDR=bytes.fromhex("807080018100000502000001")

# genuine P-256 ephemeral point if we can, else random
def ephemeral64():
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        k=ec.generate_private_key(ec.SECP256R1())
        pub=k.public_key().public_bytes(serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint)  # 0x04||X||Y = 65 bytes
        return pub[1:], True  # drop 0x04 -> 64 bytes raw
    except Exception:
        return os.urandom(64), False

def varint(n):
    out=b""
    while True:
        b=n&0x7f; n>>=7
        out+=bytes([b|(0x80 if n else 0)])
        if not n: break
    return out
def ld(field,data):  # length-delimited
    return varint(field<<3|2)+varint(len(data))+data
def vf(field,val):   # varint field
    return varint(field<<3|0)+varint(val)

def client_hello():
    pt,real=ephemeral64()
    body = ld(1,pt)+ld(2,os.urandom(16))+vf(3,0)+vf(4,0x31)+ld(5,os.urandom(12))+vf(7,0x17)
    return HDR+body, real

def trial(name, payload_fn, hold=5.0):
    s=socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
    s.settimeout(4.0)
    try: s.connect((ADDR,7))
    except Exception as e: return f"[{name}] connect_fail {e!r}"
    s.settimeout(1.5); hello=b""
    try:
        while True:
            c=s.recv(4096)
            if not c: break
            hello+=c
    except socket.timeout: pass
    # now send our payload
    sent_desc=""
    if payload_fn is not None:
        pl,desc=payload_fn(); sent_desc=desc
        try: s.sendall(pl)
        except Exception as e:
            s.close(); return f"[{name}] hello={len(hello)}B; SEND FAILED {e!r}"
    # observe reaction
    s.settimeout(hold); resp=b""; state="open"
    t0=time.time()
    try:
        while time.time()-t0<hold:
            c=s.recv(4096)
            if not c: state="closed_by_peer(EOF)"; break
            resp+=c
    except socket.timeout: state="open_idle"
    except ConnectionResetError: state="RESET_by_peer"
    except Exception as e: state=f"err:{e!r}"
    s.close()
    return (f"[{name}] hello={len(hello)}B  sent={sent_desc}  "
            f"reaction: state={state} resp={len(resp)}B"
            + (f"\n        resp_hex={resp.hex()}" if resp else ""))

print(trial("A_no_reply(baseline)", None, hold=6.0))
time.sleep(0.8)
print(trial("B_echo_server", lambda: (grab_echo(), "server-frame-echoed")) if False else "skip")

def grab():
    s=socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
    s.settimeout(4.0); s.connect((ADDR,7)); s.settimeout(1.5); d=b""
    try:
        while True:
            c=s.recv(4096); 
            if not c: break
            d+=c
    except socket.timeout: pass
    s.close(); return d

last=grab()
print(trial("B_echo_server",   lambda:(last, f"echo {len(last)}B server hello"), hold=5))
time.sleep(0.8)
print(trial("C_real_ecdh_hello", client_hello, hold=6))
time.sleep(0.8)
print(trial("D_garbage_128",  lambda:(os.urandom(128), "128B random"), hold=5))
time.sleep(0.8)
print(trial("E_header_only",  lambda:(HDR, "12B header only"), hold=5))

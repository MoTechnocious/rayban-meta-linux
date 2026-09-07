import os
import socket, time
ADDR=os.environ.get("GLASSES_MAC","XX:XX:XX:XX:XX:XX"); BTPROTO_RFCOMM=3
def grab():
    s=socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
    s.settimeout(4.0)
    s.connect((ADDR,7))
    s.settimeout(1.5)
    d=b""
    try:
        while True:
            c=s.recv(4096)
            if not c: break
            d+=c
    except socket.timeout: pass
    s.close(); return d

def parse_pb(buf):
    # returns list of (field, wiretype, value_repr, raw_len)
    out=[]; i=0; n=len(buf)
    try:
        while i<n:
            key,i2=readvar(buf,i)
            if i2<0: out.append(("<trunc-key>",)); break
            i=i2; f=key>>3; wt=key&7
            if wt==0:
                v,i=readvar(buf,i); out.append((f,0,v,None))
            elif wt==2:
                ln,i=readvar(buf,i); val=buf[i:i+ln]; i+=ln; out.append((f,2,val,ln))
            elif wt==5:
                val=buf[i:i+4]; i+=4; out.append((f,5,val,4))
            elif wt==1:
                val=buf[i:i+8]; i+=8; out.append((f,1,val,8))
            else:
                out.append((f,wt,"<unknown-wt>",None)); break
    except Exception as e:
        out.append(("<err>",str(e)))
    return out
def readvar(b,i):
    shift=0; res=0
    while i<len(b):
        c=b[i]; i+=1; res|=(c&0x7f)<<shift
        if not (c&0x80): return res,i
        shift+=7
    return 0,-1

caps=[]
for k in range(4):
    try:
        d=grab(); caps.append(d)
        print(f"--- capture {k}: {len(d)} bytes ---")
        print("hex:", d.hex())
    except Exception as e:
        print("cap fail", repr(e))
    time.sleep(0.8)

if caps:
    d=caps[0]
    # header appears to be 12 bytes before 0x0a40
    idx=d.find(b'\x0a\x40')
    print(f"\nprotobuf starts at offset {idx}; header={d[:idx].hex()}")
    body=d[idx:]
    print("Top-level protobuf fields (field, wiretype, len, value-prefix):")
    for rec in parse_pb(body):
        if len(rec)>=4 and rec[1]==2:
            f,wt,val,ln=rec
            print(f"  field {f} (len {ln}): {val.hex()[:48]}{'...' if ln and ln>24 else ''}")
        elif len(rec)>=4:
            f,wt,val,ln=rec
            print(f"  field {f} (varint/fixed): {val if wt==0 else val.hex()}")
        else:
            print("  ", rec)
    # compare ephemerality across captures
    print("\nEphemerality check (field-by-field equality across captures):")
    if len(caps)>1:
        bodies=[c[c.find(b'\x0a\x40'):] for c in caps if c.find(b'\x0a\x40')>=0]
        parsed=[parse_pb(b) for b in bodies]
        # align by field number
        from collections import defaultdict
        vals=defaultdict(list)
        for p in parsed:
            for rec in p:
                if len(rec)>=4 and isinstance(rec[0],int):
                    f,wt,val,ln=rec
                    vals[f].append(val.hex() if isinstance(val,(bytes,bytearray)) else str(val))
        for f in sorted(vals):
            uniq=set(vals[f])
            print(f"  field {f}: {'CHANGES' if len(uniq)>1 else 'stable '} across {len(vals[f])} caps  e.g. {list(uniq)[0][:32]}")
    # header ephemerality
    print("\nHeaders:", [c[:12].hex() for c in caps])

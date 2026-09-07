import os
import socket, sys, time
ADDR = os.environ.get("GLASSES_MAC","XX:XX:XX:XX:XX:XX")
BTPROTO_RFCOMM = 3
def probe(ch, wait=1.2):
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
    s.settimeout(4.0)
    try:
        s.connect((ADDR, ch))
    except Exception as e:
        s.close(); return (ch, "connect_fail", repr(e), b"")
    # got a connection; try to read whatever it volunteers
    s.settimeout(wait)
    data=b""
    try:
        while True:
            chunk=s.recv(4096)
            if not chunk: break
            data+=chunk
            if len(data)>8192: break
    except socket.timeout:
        pass
    except Exception as e:
        s.close(); return (ch, "recv_err_after_connect", repr(e), data)
    s.close()
    return (ch, "connected", "", data)

lo,hi = (int(sys.argv[1]),int(sys.argv[2])) if len(sys.argv)>2 else (1,30)
for ch in range(lo,hi+1):
    r=probe(ch)
    tag=r[1]; err=r[2]; data=r[3]
    if tag=="connect_fail":
        # only print interesting refusals succinctly
        msg=err
        print(f"ch {ch:2d}: {tag:22s} {msg}")
    else:
        print(f"ch {ch:2d}: {tag:22s} err={err!r} bytes={len(data)}")
        if data:
            print(f"        hex: {data.hex()}")
    time.sleep(0.3)

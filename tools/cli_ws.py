# A minimal client of simplex-chat's WebSocket API (-p PORT): sends one
# command, prints every response until the one for it -- and, with --wait N,
# whatever else comes for N seconds. Local tests only.
import base64, json, os, socket, sys, time

def connect(port):
    s = socket.create_connection(("127.0.0.1", port))
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(1)
    if b" 101 " not in head.split(b"\r\n")[0]:
        raise SystemExit("no websocket: " + head.decode(errors="replace"))
    return s

def send(s, text):
    data = text.encode()
    mask = os.urandom(4)
    header = bytearray([0x81])
    n = len(data)
    if n < 126: header.append(0x80 | n)
    elif n < 65536: header += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    else: header += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    s.sendall(bytes(header) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

def exact(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk: raise EOFError
        out += chunk
    return out

def receive(s):
    first, second = exact(s, 2)
    n = second & 0x7f
    if n == 126: n = int.from_bytes(exact(s, 2), "big")
    elif n == 127: n = int.from_bytes(exact(s, 8), "big")
    data = exact(s, n)
    return first & 0x0f, data

port, command = int(sys.argv[1]), sys.argv[2]
wait = float(sys.argv[sys.argv.index("--wait") + 1]) if "--wait" in sys.argv else 0
s = connect(port)
corr = str(int(time.time() * 1000))
send(s, json.dumps({"corrId": corr, "cmd": command}))
deadline = None
s.settimeout(30)
while True:
    try:
        if deadline is not None:
            left = deadline - time.time()
            if left <= 0: break
            s.settimeout(left)
        op, data = receive(s)
    except (socket.timeout, EOFError):
        break
    if op != 1: continue
    message = json.loads(data)
    print(json.dumps(message), flush=True)
    if message.get("corrId") == corr and deadline is None:
        if not wait: break
        deadline = time.time() + wait

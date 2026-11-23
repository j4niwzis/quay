# A TLS 1.3 client to an SMP router (ALPN smp/1), as a plain TCP port on
# 127.0.0.1 for a test that speaks SMP's blocks without TLS of its own:
# each connection accepted is relayed both ways. Local tests only.
import socket, ssl, sys, threading
listen_port, host, port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  # the test checks the router's identity in its hello instead
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.set_alpn_protocols(["smp/1"])
def pump(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass
def serve(client):
    raw = socket.create_connection((host, port))
    tls = context.wrap_socket(raw, server_hostname=host)
    print("tls", tls.version(), tls.cipher()[0], "alpn", tls.selected_alpn_protocol(), flush=True)
    threading.Thread(target=pump, args=(client, tls), daemon=True).start()
    pump(tls, client)
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", listen_port))
server.listen()
print("listening", flush=True)
while True:
    client, _ = server.accept()
    threading.Thread(target=serve, args=(client,), daemon=True).start()

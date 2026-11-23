# A TLS 1.3 client to an SMP router through OpenSSL itself (ctypes, libssl.so.3),
# as a plain TCP port on 127.0.0.1 for a test that speaks SMP's blocks without
# TLS of its own -- and that is told, before anything else, what the TLS
# connection says: the peer's certificate chain (leaf first, DER) and this
# client's Finished message (the channel binding simplexmq takes for its
# session id). Preamble: u8 count, each certificate u16 length + DER, then u16
# length + Finished. Then the bytes both ways. Local tests and CI only.
import ctypes, ctypes.util, select, socket, sys, threading

listen_port, host, port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
ssl = ctypes.CDLL(ctypes.util.find_library("ssl") or "libssl.so.3")
crypto = ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so.3")
vp, ip = ctypes.c_void_p, ctypes.c_int
for name, res, args in [("TLS_client_method", vp, []), ("SSL_CTX_new", vp, [vp]), ("SSL_new", vp, [vp]), ("SSL_set_fd", ip, [vp, ip]),
                        ("SSL_connect", ip, [vp]), ("SSL_read", ip, [vp, ctypes.c_char_p, ip]), ("SSL_write", ip, [vp, ctypes.c_char_p, ip]),
                        ("SSL_get_finished", ctypes.c_size_t, [vp, ctypes.c_char_p, ctypes.c_size_t]), ("SSL_get_peer_cert_chain", vp, [vp]),
                        ("SSL_CTX_set_alpn_protos", ip, [vp, ctypes.c_char_p, ctypes.c_uint]), ("SSL_CTX_ctrl", ctypes.c_long, [vp, ip, ctypes.c_long, vp]),
                        ("SSL_CTX_set_ciphersuites", ip, [vp, ctypes.c_char_p]), ("SSL_pending", ip, [vp]), ("SSL_get_error", ip, [vp, ip]),
                        ("SSL_ctrl", ctypes.c_long, [vp, ip, ctypes.c_long, vp])]:
    f = getattr(ssl, name); f.restype = res; f.argtypes = args
for name, res, args in [("OPENSSL_sk_num", ip, [vp]), ("OPENSSL_sk_value", vp, [vp, ip]), ("i2d_X509", ip, [vp, ctypes.POINTER(ctypes.c_char_p)])]:
    f = getattr(crypto, name); f.restype = res; f.argtypes = args
SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_3_VERSION, SSL_CTRL_SET_TLSEXT_HOSTNAME = 123, 0x0304, 55

def serve(client):
    ctx = ssl.SSL_CTX_new(ssl.TLS_client_method())
    ssl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_3_VERSION, None)
    ssl.SSL_CTX_set_ciphersuites(ctx, b"TLS_CHACHA20_POLY1305_SHA256")
    alpn = b"\x05smp/1"
    ssl.SSL_CTX_set_alpn_protos(ctx, alpn, len(alpn))
    raw = socket.create_connection((host, port))
    conn = ssl.SSL_new(ctx)
    ssl.SSL_ctrl(conn, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, ctypes.c_char_p(host.encode()))
    ssl.SSL_set_fd(conn, raw.fileno())
    if ssl.SSL_connect(conn) != 1:
        print("TLS handshake failed", flush=True); client.close(); return
    chain = ssl.SSL_get_peer_cert_chain(conn)
    certs = []
    for i in range(crypto.OPENSSL_sk_num(chain)):
        x = crypto.OPENSSL_sk_value(chain, i)
        n = crypto.i2d_X509(x, None)
        buf = ctypes.create_string_buffer(n)
        p = ctypes.c_char_p(ctypes.addressof(buf))
        crypto.i2d_X509(x, ctypes.byref(p))
        certs.append(buf.raw[:n])
    fin = ctypes.create_string_buffer(64)
    n = ssl.SSL_get_finished(conn, fin, 64)
    finished = fin.raw[:n]
    print(f"tls up: {len(certs)} certificates, Finished {len(finished)} bytes", flush=True)
    pre = bytes([len(certs)]) + b"".join(len(c).to_bytes(2, "big") + c for c in certs) + len(finished).to_bytes(2, "big") + finished
    client.sendall(pre)
    buf = ctypes.create_string_buffer(65536)
    while True:
        if ssl.SSL_pending(conn) == 0:
            r, _, _ = select.select([client, raw], [], [])
        else:
            r = [raw]
        if client in r:
            data = client.recv(65536)
            if not data: break
            off = 0
            while off < len(data):
                w = ssl.SSL_write(conn, data[off:], len(data) - off)
                if w <= 0: return
                off += w
        if raw in r:
            got = ssl.SSL_read(conn, buf, 65536)
            if got <= 0:
                if ssl.SSL_get_error(conn, got) in (2, 3): continue  # want read/write
                break
            client.sendall(buf.raw[:got])
    client.close()

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", listen_port))
server.listen()
print("listening", flush=True)
while True:
    c, _ = server.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()

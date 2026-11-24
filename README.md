# quay

SimpleX -- its messaging protocol (SMP), its agent (duplex connections, the
post-quantum double ratchet) and its chat protocol -- as a C++26 library of
modules, sans-IO: what is sent is written into a sink of the caller's, what
comes is fed to it, and the caller's transport and control flow carry it.

## Modules

| module | what it is |
|---|---|
| `quay.bytes` | the protocols' encodings: big-endian integers, shortString/largeString, the padded fixed-size blocks, keys as X.509 SubjectPublicKeyInfo (X25519, Ed25519, X448, Ed448), base64url -- read from any input range, written into any sink |
| `quay.crypto` | on [Botan](https://botan.randombit.net) 3: X25519/X448, Ed25519/Ed448, NaCl box and secretbox (XSalsa20-Poly1305), AES-256-GCM with any IV length (SimpleX's ratchet uses 16 bytes), SHA-256/512, SHA3-256/384, Keccak-256, HMAC-SHA512, HKDF-SHA512; and sntrup761 (OpenSSH's public-domain implementation, vendored) |
| `quay.snapshot` | a value as bytes and back, written from its type -- for keeping connections between runs |
| `quay.smp` | SMP: commands and responses, transmissions and blocks, the hellos, the router's and the sender's layers |
| `quay.session` | the router authenticated: its certificate chain against the identity its address pins, the session key it signs, this TLS session's Finished; a destination reached through a proxy authenticated from what the proxy relays, and commands sealed for it (private message routing) |
| `quay.tls` | TLS 1.3 to a router, sans-IO, on Botan (ALPN `smp/1`; EdDSA certificates, which Botan's TLS leaves out, put back at configure time) |
| `quay.ratchet` | the post-quantum double ratchet (X448, sntrup761 KEM), as simplexmq's |
| `quay.agent` | the agent's messages, envelopes, queue addresses and links (`simplex:/invitation`, `simplex:/contact`) |
| `quay.connection` | duplex connections as state machines: both sides of an invitation by the fast (SKEY) and the standard flow, contact addresses both ways, messages and receipts, queue switching both ways, re-subscription, save and restore |
| `quay.client` | one session with one router for any number of connections: socket bytes in and out, answers and deliveries routed back; actions for other routers sent through it as a proxy |
| `quay.hpack`, `quay.http2` | HTTP/2 for XFTP, sans-IO: HPACK with its tables read at compile time from RFC 7541's text, frames, streams, flow control |
| `quay.xftp` | XFTP: a session with a files router (the handshake, the router authenticated), FNEW/FADD/FPUT/FGET/FACK/FDEL, chunks opened |
| `quay.xfile` | files over XFTP: a file sealed whole and cut into chunks, as simplexmq's xftp does, and file descriptions read and written |
| `quay.compression` | simplex-chat's compressed batches (zstd) |
| `quay.chat` | simplex-chat's messages read into types through knot (`x.info`, `x.msg.new` with its file, `x.msg.file.descr`, ...), and written; a file's description put together from its parts |

Tested live, in CI, against smp-server 6.5.0 and simplex-chat 7.1.4's CLI:
quay invites the CLI and joins its invitations, connects through its address
and accepts it on quay's own, by both flows; messages, receipts, compressed
chat, files both ways over XFTP, save/restore, re-subscription and queue switching
both ways -- over quay's own TLS.

Not yet: blocking and member restrictions, hosting a group link.

## Keeping a connection: save before you send

A connection's state can be saved (`saved()`) and restored (`restored()`)
between runs. **Save it after every call that returns actions, and before
sending any of them; never restore a snapshot older than the last one
saved.** A stale snapshot encrypts again with message keys and IVs that were
already used, which breaks AES-GCM for those messages. Record
`generation()` with each save and restore with `restored(bytes, generation)`
so that an older snapshot is refused rather than silently reused. A snapshot
holds private and chain keys: keep it as secret as the keys themselves.

## Building

CMake 4.3, clang 23 with libc++ (`import std`). Botan and zstd are fetched
at their releases, pinned by hash; only the Botan modules quay uses are
amalgamated and built (Python 3 runs its configure.py). knot comes as a
port. Tests: googletest, against
vectors from independent implementations -- Python's cryptography
(OpenSSL), libsodium's own tests, and liboqs's known answers for sntrup761.

## Licence

AGPL-3.0-only. `third_party/sntrup761/sntrup761.c` is OpenSSH's, in the
public domain.

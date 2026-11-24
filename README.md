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

Next: the SMP client (commands, transmissions, private routing), the agent
(connections, envelopes, the PQ double ratchet, links), the chat protocol,
XFTP.

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

CMake 4.3, clang 23 with libc++ (`import std`). Botan is fetched at its
release, pinned by hash, and only the modules quay uses are amalgamated
and built (Python 3 runs its configure.py). Tests: googletest, against
vectors from independent implementations -- Python's cryptography
(OpenSSL), libsodium's own tests, and liboqs's known answers for sntrup761.

## Licence

AGPL-3.0-only. `third_party/sntrup761/sntrup761.c` is OpenSSH's, in the
public domain.

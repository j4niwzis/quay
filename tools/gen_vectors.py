# Writes test/vectors.inc: what an independent implementation -- Python's
# cryptography (OpenSSL) and hashlib -- says for fixed inputs, for quay's
# crypto to be checked against. Run again only where an input changes.
import hashlib, hmac, sys
from cryptography.hazmat.primitives.asymmetric import x25519, x448, ed25519, ed448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

out = sys.argv[1]
raw = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
der = dict(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
def seq(n, start=1):
    return bytes((start + 7 * i) % 256 for i in range(n))
def c(name, data):
    return "inline constexpr std::array<quay::byte, %d> %s{%s};" % (len(data), name, ", ".join("0x%02x" % b for b in data))

lines = ["// Written by tools/gen_vectors.py: Python's cryptography (OpenSSL) and hashlib, for fixed inputs."]
# X25519 and X448: two keys each, their publics, and what they agree on.
for name, mod, n in (("x25519", x25519, 32), ("x448", x448, 56)):
    a, b = seq(n, 1), seq(n, 101)
    ka, kb = mod.__dict__[name.upper() + "PrivateKey"].from_private_bytes(a), mod.__dict__[name.upper() + "PrivateKey"].from_private_bytes(b)
    lines += [c(name + "_a", a), c(name + "_b", b), c(name + "_a_pub", ka.public_key().public_bytes(**raw)),
              c(name + "_b_pub", kb.public_key().public_bytes(**raw)), c(name + "_shared", ka.exchange(kb.public_key())),
              c(name + "_a_spki", ka.public_key().public_bytes(**der))]
# Ed25519 and Ed448: a key, its public, a message signed.
message = b"quay signs this"
lines.append(c("signed_message", message))
for name, mod, n in (("ed25519", ed25519, 32), ("ed448", ed448, 57)):
    k = mod.__dict__[name.capitalize().replace("ed", "Ed") + "PrivateKey"].from_private_bytes(seq(n, 3))
    lines += [c(name + "_seed", seq(n, 3)), c(name + "_pub", k.public_key().public_bytes(**raw)), c(name + "_sig", k.sign(message)),
              c(name + "_spki", k.public_key().public_bytes(**der))]
# AES-256-GCM with a 16-byte IV, as SimpleX's ratchet uses it.
key, iv, ad, plain = seq(32, 9), seq(16, 50), b"associated", b"the ratchet's message body"
sealed = AESGCM(key).encrypt(iv, plain, ad)
lines += [c("gcm_key", key), c("gcm_iv", iv), c("gcm_ad", ad), c("gcm_plain", plain), c("gcm_cipher", sealed[:-16]), c("gcm_expected_tag", sealed[-16:])]
# HKDF-SHA512 (RFC 5869, by hand on hmac).
salt, ikm, info = seq(13, 7), seq(40, 77), b"SimpleXChainRatchet"
prk = hmac.new(salt, ikm, hashlib.sha512).digest()
okm, t, i = b"", b"", 1
while len(okm) < 96:
    t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest(); okm += t; i += 1
lines += [c("hkdf_salt", salt), c("hkdf_ikm", ikm), c("hkdf_info", info), c("hkdf_out", okm[:96])]
# Hashes of "abc".
lines += [c("abc_sha256", hashlib.sha256(b"abc").digest()), c("abc_sha512", hashlib.sha512(b"abc").digest()),
          c("abc_sha3_256", hashlib.sha3_256(b"abc").digest()), c("abc_sha3_384", hashlib.sha3_384(b"abc").digest()),
          c("abc_hmac_sha512", hmac.new(b"key", b"abc", hashlib.sha512).digest())]
open(out, "w").write("\n".join(lines) + "\n")
print(len(lines))

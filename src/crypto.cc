// SPDX-License-Identifier: AGPL-3.0-only
// quay.crypto -- What SimpleX's protocols need of cryptography, on Botan:
// X25519 and X448 (agreement), Ed25519 and Ed448 (signatures), NaCl's box
// and secretbox (XSalsa20-Poly1305: every queue's own layer), AES-256-GCM
// with SimpleX's 16-byte IVs (the double ratchet), SHA-256/512, SHA3-256/384,
// Keccak-256, HMAC-SHA512, HKDF-SHA512, and sntrup761 (the ratchet's
// post-quantum KEM; OpenSSH's public-domain implementation, vendored).
//
// Randomness is the caller's: a random_source fills the bytes it is given
// -- the system's (system_random), or a test's, deterministic. Keys are
// their raw bytes, typed by their curve; what fails is a type, in a
// spl::variant.
module;
#include "botan_all.h"
// sntrup761, as third_party/sntrup761 builds it (its glue, src/sntrup761_glue.cc).
extern "C" {
int crypto_kem_sntrup761_keypair(unsigned char* pk, unsigned char* sk);
int crypto_kem_sntrup761_enc(unsigned char* c, unsigned char* k, const unsigned char* pk);
int crypto_kem_sntrup761_dec(unsigned char* k, const unsigned char* c, const unsigned char* sk);
// The generator its randomness comes from, for the calls on this thread.
void quay_sntrup761_use(void* rng);
}
export module quay.crypto;

import std;
import splice;
import quay.bytes;

export namespace quay::crypto {

// What failed.
namespace errors {
struct forged {  // an authentication tag that does not match: tampered with, or the wrong key
  friend constexpr bool operator==(forged, forged) = default;
};
struct bad_key {  // a key the operation refuses (a low-order point, for one)
  friend constexpr bool operator==(bad_key, bad_key) = default;
};
struct too_short {  // less than a tag
  friend constexpr bool operator==(too_short, too_short) = default;
};
}  // namespace errors
using crypto_error = spl::variant<errors::forged, errors::bad_key, errors::too_short>;

// What fills bytes with randomness.
template <class R>
concept random_source = requires(R& random, std::span<byte> out) { random(out); };
// The system's (getrandom, and the like).
struct system_random {
  void operator()(std::span<byte> out) const { Botan::system_rng().randomize(out); }
};

// Bytes wiped where they are let go (Botan's secure_scrub_memory): what a
// secret's storage held is not left in freed memory.
inline void scrub(std::span<byte> bytes) { Botan::secure_scrub_memory(bytes.data(), bytes.size()); }
// A secret of N bytes: an array, wiped when it goes. Copied where it must
// be; each copy wiped in turn.
template <std::size_t N>
struct secret {
  std::array<byte, N> raw{};
  secret() = default;
  secret(const secret&) = default;
  secret& operator=(const secret&) = default;
  ~secret() { scrub(raw); }
  friend bool operator==(const secret&, const secret&) = default;
  friend auto operator<=>(const secret& a, const secret& b) { return a.raw <=> b.raw; }
};

template <class Curve>
struct private_key {
  std::array<byte, Curve::private_size> raw{};
  private_key() = default;
  private_key(const private_key&) = default;
  private_key& operator=(const private_key&) = default;
  ~private_key() { scrub(raw); }
  friend bool operator==(const private_key&, const private_key&) = default;
};
template <class Curve>
struct key_pair {
  public_key<Curve> pub;
  private_key<Curve> priv;
};
template <class Curve>
struct signature {
  std::array<byte, Curve::signature_size> raw{};
  friend constexpr bool operator==(const signature&, const signature&) = default;
};

namespace detail {
// What Botan gave, as the array it must be: a size other than N is a bug,
// said, not padded or cut.
template <std::size_t N>
std::array<byte, N> array_of(std::span<const std::uint8_t> from) {
  if (from.size() != N) throw std::logic_error(std::format("quay.crypto: {} bytes where {} were due", from.size(), N));
  std::array<byte, N> out{};
  std::ranges::copy(from, out.begin());
  return out;
}
inline bytes owned(std::span<const std::uint8_t> from) { return bytes(from.begin(), from.end()); }
}  // namespace detail

// ---- keys -----------------------------------------------------------------------

// A private key's public one.
inline public_key<curve::x25519> public_of(const private_key<curve::x25519>& one) {
  return {detail::array_of<32>(Botan::X25519_PrivateKey(std::span<const std::uint8_t>(one.raw)).public_value())};
}
inline public_key<curve::x448> public_of(const private_key<curve::x448>& one) {
  return {detail::array_of<56>(Botan::X448_PrivateKey(std::span<const std::uint8_t>(one.raw)).public_value())};
}
inline public_key<curve::ed25519> public_of(const private_key<curve::ed25519>& one) {
  return {detail::array_of<32>(Botan::Ed25519_PrivateKey::from_seed(one.raw).raw_public_key_bits())};
}
inline public_key<curve::ed448> public_of(const private_key<curve::ed448>& one) {
  return {detail::array_of<57>(Botan::Ed448_PrivateKey(std::span<const std::uint8_t>(one.raw)).raw_public_key_bits())};
}
// A key pair made: its private key the random source's bytes.
template <class Curve, random_source R>
key_pair<Curve> generate(R& random) {
  private_key<Curve> priv;
  random(std::span<byte>(priv.raw));
  return {public_of(priv), priv};
}

// ---- agreement --------------------------------------------------------------------

namespace detail {
template <class Key, std::size_t N, class Curve>
std::expected<std::array<byte, N>, crypto_error> agree(const private_key<Curve>& mine, const public_key<Curve>& theirs) {
  try {
    const Key key(std::span<const std::uint8_t>(mine.raw));
    Botan::PK_Key_Agreement agreement(key, Botan::system_rng(), "Raw");
    const auto shared = agreement.derive_key(0, std::span<const std::uint8_t>(theirs.raw)).bits_of();
    if (std::ranges::all_of(shared, [](std::uint8_t b) { return b == 0; })) return std::unexpected(errors::bad_key{});
    return array_of<N>(shared);
  } catch (const Botan::Exception&) {
    return std::unexpected(errors::bad_key{});
  }
}
}  // namespace detail
// What two keys agree on (Diffie-Hellman); refused for a key of low order,
// which agrees on nothing but zeros.
inline std::expected<std::array<byte, 32>, crypto_error> agree(const private_key<curve::x25519>& mine, const public_key<curve::x25519>& theirs) {
  return detail::agree<Botan::X25519_PrivateKey, 32>(mine, theirs);
}
inline std::expected<std::array<byte, 56>, crypto_error> agree(const private_key<curve::x448>& mine, const public_key<curve::x448>& theirs) {
  return detail::agree<Botan::X448_PrivateKey, 56>(mine, theirs);
}

// ---- signatures -------------------------------------------------------------------

inline signature<curve::ed25519> sign(const private_key<curve::ed25519>& key, std::span<const byte> message) {
  const auto signer_key = Botan::Ed25519_PrivateKey::from_seed(key.raw);
  Botan::PK_Signer signer(signer_key, Botan::system_rng(), "Pure");
  return {detail::array_of<64>(signer.sign_message(message, Botan::system_rng()))};
}
inline signature<curve::ed448> sign(const private_key<curve::ed448>& key, std::span<const byte> message) {
  const Botan::Ed448_PrivateKey signer_key(std::span<const std::uint8_t>(key.raw));
  Botan::PK_Signer signer(signer_key, Botan::system_rng(), "Pure");
  return {detail::array_of<114>(signer.sign_message(message, Botan::system_rng()))};
}
inline bool verify(const public_key<curve::ed25519>& key, std::span<const byte> message, const signature<curve::ed25519>& said) {
  try {
    const Botan::Ed25519_PublicKey verifier_key(std::span<const std::uint8_t>(key.raw));
    Botan::PK_Verifier verifier(verifier_key, "Pure");
    return verifier.verify_message(message, said.raw);
  } catch (const Botan::Exception&) {
    return false;
  }
}
inline bool verify(const public_key<curve::ed448>& key, std::span<const byte> message, const signature<curve::ed448>& said) {
  try {
    const Botan::Ed448_PublicKey verifier_key(std::span<const std::uint8_t>(key.raw));
    Botan::PK_Verifier verifier(verifier_key, "Pure");
    return verifier.verify_message(message, said.raw);
  } catch (const Botan::Exception&) {
    return false;
  }
}

// ---- NaCl: box and secretbox (XSalsa20-Poly1305) -------------------------------------

using box_key = std::array<byte, 32>;
using box_nonce = std::array<byte, 24>;
// A box's key: X25519's agreement, through HSalsa20 (crypto_box_beforenm).
inline std::expected<box_key, crypto_error> box_key_of(const public_key<curve::x25519>& theirs, const private_key<curve::x25519>& mine) {
  box_key out{};
  if (Botan::Sodium::crypto_box_beforenm(out.data(), theirs.raw.data(), mine.raw.data()) != 0) return std::unexpected(errors::bad_key{});
  return out;
}
// Sealed: the tag (16 bytes), then the ciphertext -- NaCl's "easy" form,
// as SimpleX sends it.
inline bytes secretbox(const box_key& key, const box_nonce& nonce, std::span<const byte> message) {
  bytes out(message.size() + 16);
  Botan::Sodium::crypto_secretbox_easy(out.data(), message.data(), message.size(), nonce.data(), key.data());
  return out;
}
inline std::expected<bytes, crypto_error> secretbox_open(const box_key& key, const box_nonce& nonce, std::span<const byte> sealed) {
  if (sealed.size() < 16) return std::unexpected(errors::too_short{});
  bytes out(sealed.size() - 16);
  if (Botan::Sodium::crypto_secretbox_open_easy(out.data(), sealed.data(), sealed.size(), nonce.data(), key.data()) != 0)
    return std::unexpected(errors::forged{});
  return out;
}

// ---- AES-256-GCM, any IV length (SimpleX's ratchet: 16 bytes) -------------------------

using aes_key = std::array<byte, 32>;
using gcm_tag = std::array<byte, 16>;
struct sealed {
  bytes cipher;
  gcm_tag tag{};
};
inline sealed gcm_seal(const aes_key& key, std::span<const byte> iv, std::span<const byte> associated, std::span<const byte> plain) {
  auto mode = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
  mode->set_key(key);
  mode->set_associated_data(associated);
  mode->start(iv);
  Botan::secure_vector<std::uint8_t> buffer(plain.begin(), plain.end());
  mode->finish(buffer);
  sealed out;
  out.cipher.assign(buffer.begin(), buffer.end() - 16);
  std::ranges::copy(std::span(buffer).last(16), out.tag.begin());
  return out;
}
inline std::expected<bytes, crypto_error> gcm_open(const aes_key& key, std::span<const byte> iv, std::span<const byte> associated,
                                                   std::span<const byte> cipher, const gcm_tag& tag) {
  auto mode = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
  mode->set_key(key);
  mode->set_associated_data(associated);
  mode->start(iv);
  Botan::secure_vector<std::uint8_t> buffer(cipher.begin(), cipher.end());
  buffer.insert(buffer.end(), tag.begin(), tag.end());
  try {
    mode->finish(buffer);
  } catch (const Botan::Invalid_Authentication_Tag&) {
    return std::unexpected(errors::forged{});
  }
  return bytes(buffer.begin(), buffer.end());
}

// One block of AES-256 (ECB): what NIST's known-answer generator is made of.
inline std::array<byte, 16> aes256_block(const aes_key& key, const std::array<byte, 16>& block) {
  auto cipher = Botan::BlockCipher::create_or_throw("AES-256");
  cipher->set_key(key);
  std::array<byte, 16> out{};
  cipher->encrypt(block.data(), out.data());
  return out;
}

// ---- hashes, HMAC, HKDF -------------------------------------------------------------------

namespace detail {
template <std::size_t N>
std::array<byte, N> digest(std::string_view name, std::span<const byte> data) {
  auto hash = Botan::HashFunction::create_or_throw(name);
  hash->update(data);
  return array_of<N>(hash->final());
}
}  // namespace detail
inline std::array<byte, 32> sha256(std::span<const byte> data) { return detail::digest<32>("SHA-256", data); }
inline std::array<byte, 64> sha512(std::span<const byte> data) { return detail::digest<64>("SHA-512", data); }
inline std::array<byte, 32> sha3_256(std::span<const byte> data) { return detail::digest<32>("SHA-3(256)", data); }
inline std::array<byte, 48> sha3_384(std::span<const byte> data) { return detail::digest<48>("SHA-3(384)", data); }
inline std::array<byte, 32> keccak256(std::span<const byte> data) { return detail::digest<32>("Keccak-1600(256)", data); }
inline std::array<byte, 64> hmac_sha512(std::span<const byte> key, std::span<const byte> data) {
  auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");
  mac->set_key(key);
  mac->update(data);
  return detail::array_of<64>(mac->final());
}
// HKDF-SHA512 (RFC 5869): `length` bytes, from the input key, a salt and
// what it is for.
inline bytes hkdf_sha512(std::span<const byte> salt, std::span<const byte> input, std::span<const byte> info, std::size_t length) {
  auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-512)");
  return detail::owned(kdf->derive_key(length, input, salt, info));
}

// ---- sntrup761 ---------------------------------------------------------------------------

namespace sntrup761 {
inline constexpr std::size_t public_size = 1158, secret_size = 1763, ciphertext_size = 1039, shared_size = 32;
struct public_key {
  std::array<byte, public_size> raw{};
  friend constexpr bool operator==(const public_key&, const public_key&) = default;
};
struct secret_key {  // wiped when it goes, as secret<N> is
  std::array<byte, secret_size> raw{};
  secret_key() = default;
  secret_key(const secret_key&) = default;
  secret_key& operator=(const secret_key&) = default;
  ~secret_key() { scrub(raw); }
  friend bool operator==(const secret_key&, const secret_key&) = default;
};
struct key_pair {
  public_key pub;
  secret_key secret;
};
using ciphertext = std::array<byte, ciphertext_size>;
using shared_secret = secret<shared_size>;  // wiped when it goes
struct encapsulated {
  ciphertext cipher{};
  shared_secret shared{};
};

namespace detail {
// The random source, as the vendored code's randombytes reaches it: a
// Botan generator, set for the calls on this thread. (A C function with a
// fixed signature is what reads it: the one place randomness goes through
// an object it does not know the type of.)
template <class R>
class generator final : public Botan::RandomNumberGenerator {
 public:
  explicit generator(R& random) : random_(&random) {}
  bool accepts_input() const override { return false; }
  std::string name() const override { return "quay"; }
  bool is_seeded() const override { return true; }
  void clear() override {}

 private:
  void fill_bytes_with_input(std::span<std::uint8_t> out, std::span<const std::uint8_t>) override {
    if (!out.empty()) (*random_)(std::span<byte>(out.data(), out.size()));
  }
  R* random_;
};
template <class R>
struct using_random {
  generator<R> made;
  explicit using_random(R& random) : made(random) { quay_sntrup761_use(&made); }
  ~using_random() { quay_sntrup761_use(nullptr); }
};
}  // namespace detail

template <random_source R>
key_pair generate(R& random) {
  detail::using_random<R> scope(random);
  key_pair out;
  crypto_kem_sntrup761_keypair(out.pub.raw.data(), out.secret.raw.data());
  return out;
}
template <random_source R>
encapsulated encapsulate(const public_key& to, R& random) {
  detail::using_random<R> scope(random);
  encapsulated out;
  crypto_kem_sntrup761_enc(out.cipher.data(), out.shared.raw.data(), to.raw.data());
  return out;
}
// Implicit rejection: a ciphertext not made for the key gives a secret
// all the same -- one no one else has.
inline shared_secret decapsulate(const secret_key& key, const ciphertext& cipher) {
  shared_secret out{};
  crypto_kem_sntrup761_dec(out.raw.data(), cipher.data(), key.raw.data());
  return out;
}
}  // namespace sntrup761

}  // namespace quay::crypto

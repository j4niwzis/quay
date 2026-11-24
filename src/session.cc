// SPDX-License-Identifier: AGPL-3.0-only
// quay.session -- a router authenticated, as simplexmq's client does it
// (Transport.hs smpClientHandshake, Transport/Shared.hs chainIdCaCerts),
// and more: what the TLS connection says -- the peer's certificate chain,
// and the session's channel binding (the client's Finished message, the
// "tls-unique" simplexmq takes for its session id) -- held against the
// router's hello and its pinned identity.
//
//   - the TLS chain is 2-4 certificates, each signed by the next;
//   - its identity certificate (the second) hashes, SHA-256 over its DER,
//     to the identity pinned in the router's address;
//   - the hello's chain is the TLS chain, byte for byte;
//   - the hello's session key (X25519) is signed by the TLS leaf's key;
//   - the hello's session id is the TLS channel binding.
//
// Only a hello verified so is a session (verified): commands are signed
// and authenticated with one alone -- a hello not verified cannot be used.
module;
#include "botan_all.h"
export module quay.session;

import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.smp;

export namespace quay::session {

// What the TLS layer gives: the peer's chain, the leaf first, each DER; and
// the client's Finished message (its verify data).
struct tls_facts {
  std::vector<bytes> peer_chain;
  bytes finished;
};

namespace errors {
struct chain_shape {
  std::size_t count = 0;
};
struct bad_certificate {
  std::size_t at = 0;
};
struct chain_signature {  // certificate `at` is not signed by the next
  std::size_t at = 0;
};
struct identity {};        // the identity certificate is not the one pinned
struct chain_mismatch {};  // the hello's chain is not the TLS chain
struct no_session_key {};
struct session_key_signature {};
struct session {};         // the hello's session id is not this TLS session's
struct version {};         // no SMP version both speak
}  // namespace errors
using pin_error = spl::variant<errors::chain_shape, errors::bad_certificate, errors::chain_signature, errors::identity,
                               errors::chain_mismatch, errors::no_session_key, errors::session_key_signature, errors::session, errors::version>;

// A router's session, authenticated: made by verify() alone.
class verified;
std::expected<verified, pin_error> verify(const smp::router_hello& hello, std::span<const byte> identity, const tls_facts& tls,
                                         smp::version_range ours = {smp::min_version, smp::max_version});
std::expected<verified, pin_error> verify_relayed(const smp::response::proxy_session_key& key, std::span<const byte> identity,
                                                 smp::version_range ours = {smp::min_version, smp::max_version});
class verified {
 public:
  [[nodiscard]] const smp::router_hello& hello() const { return hello_; }
  [[nodiscard]] std::span<const byte> id() const { return hello_.session_id; }
  [[nodiscard]] const public_key<curve::x25519>& router_key() const { return router_key_; }  // what deniable authenticators are keyed by
  [[nodiscard]] std::uint16_t version() const { return version_; }  // the version both speak (SMP's, or XFTP's)

 private:
  verified(smp::router_hello hello, public_key<curve::x25519> key, std::uint16_t version)
      : hello_(std::move(hello)), router_key_(key), version_(version) {}
  friend std::expected<verified, pin_error> verify(const smp::router_hello&, std::span<const byte>, const tls_facts&, smp::version_range);
  friend std::expected<verified, pin_error> verify_relayed(const smp::response::proxy_session_key&, std::span<const byte>, smp::version_range);
  smp::router_hello hello_;
  public_key<curve::x25519> router_key_;
  std::uint16_t version_ = 0;
};

namespace detail {
// One DER element: its whole encoding, and its content.
struct element {
  std::span<const byte> whole, content;
  byte tag = 0;
};
inline std::optional<element> next_element(std::span<const byte>& in) {
  if (in.size() < 2) return std::nullopt;
  const byte tag = in[0];
  std::size_t length = in[1], header = 2;
  if (length & 0x80) {
    const std::size_t count = length & 0x7f;
    if (count == 0 || count > 4 || in.size() < 2 + count) return std::nullopt;
    length = 0;
    for (std::size_t i = 0; i < count; ++i) length = (length << 8) | in[2 + i];
    header += count;
  }
  if (in.size() < header + length) return std::nullopt;
  element out{in.first(header + length), in.subspan(header, length), tag};
  in = in.subspan(header + length);
  return out;
}
// The signed key, as X.509's SignedExact writes it: SEQUENCE { the signed
// data (here SEQUENCE { SPKI }), algorithm, BIT STRING signature }.
struct signed_object {
  std::span<const byte> signed_data;
  std::span<const byte> inner;  // what the signed data wraps: the key's SubjectPublicKeyInfo
  bool ed448 = false;
  std::span<const byte> signature;
};
inline std::optional<signed_object> signed_object_of(std::span<const byte> der) {
  auto outer = next_element(der);
  if (!outer || outer->tag != 0x30) return std::nullopt;
  auto inside = outer->content;
  const auto data = next_element(inside);
  const auto algorithm = next_element(inside);
  const auto bits = next_element(inside);
  if (!data || !algorithm || !bits || bits->tag != 0x03 || bits->content.empty() || bits->content[0] != 0) return std::nullopt;
  auto alg = algorithm->content;
  const auto oid = next_element(alg);
  if (!oid || oid->tag != 0x06 || oid->content.size() != 3 || oid->content[0] != 0x2b || oid->content[1] != 0x65) return std::nullopt;
  if (oid->content[2] != 0x70 && oid->content[2] != 0x71) return std::nullopt;  // Ed25519, Ed448
  return signed_object{data->whole, data->content, oid->content[2] == 0x71, bits->content.subspan(1)};
}
}  // namespace detail

// A router's chain and the session key its leaf signs, checked: each
// certificate signed by the next, the second the identity pinned, the
// session key signed by the leaf. The session key, where all holds.
inline std::expected<public_key<curve::x25519>, pin_error> session_key_of(const std::vector<bytes>& chain, std::span<const byte> signed_key_der,
                                                                         std::span<const byte> identity) {
  if (chain.size() < 2 || chain.size() > 4) return std::unexpected(errors::chain_shape{chain.size()});
  std::vector<std::unique_ptr<Botan::X509_Certificate>> certificates;
  for (std::size_t i = 0; i < chain.size(); ++i) {
    try {
      certificates.push_back(std::make_unique<Botan::X509_Certificate>(chain[i]));
    } catch (const Botan::Exception&) {
      return std::unexpected(errors::bad_certificate{i});
    }
  }
  // Each signed by the next.
  for (std::size_t i = 0; i + 1 < certificates.size(); ++i) {
    try {
      const auto issuer_key = certificates[i + 1]->subject_public_key();
      if (!certificates[i]->check_signature(*issuer_key)) return std::unexpected(errors::chain_signature{i});
    } catch (const Botan::Exception&) {
      return std::unexpected(errors::chain_signature{i});
    }
  }
  // The identity certificate -- the second, whatever the length (chainIdCaCerts).
  if (!std::ranges::equal(crypto::sha256(chain[1]), identity)) return std::unexpected(errors::identity{});
  // The session key, signed by the TLS leaf's key.
  const auto signed_key = detail::signed_object_of(signed_key_der);
  if (!signed_key) return std::unexpected(errors::no_session_key{});
  try {
    const auto leaf_key = certificates[0]->subject_public_key();
    Botan::PK_Verifier verifier(*leaf_key, "Pure");
    if (!verifier.verify_message(signed_key->signed_data, signed_key->signature)) return std::unexpected(errors::session_key_signature{});
  } catch (const Botan::Exception&) {
    return std::unexpected(errors::session_key_signature{});
  }
  // The signed data is the key as x509's PubKey is encoded -- its
  // SubjectPublicKeyInfo inside one more SEQUENCE (as smp-server 6.5.0 sends it).
  auto session_key = key_from_spki<curve::x25519>(signed_key->inner);
  if (!session_key) session_key = key_from_spki<curve::x25519>(signed_key->signed_data);
  if (!session_key) return std::unexpected(errors::no_session_key{});
  return *session_key;
}

inline std::expected<verified, pin_error> verify(const smp::router_hello& hello, std::span<const byte> identity, const tls_facts& tls,
                                                smp::version_range ours) {
  const auto key = session_key_of(tls.peer_chain, hello.signed_key, identity);
  if (!key) return std::unexpected(key.error());
  if (hello.certificates != tls.peer_chain) return std::unexpected(errors::chain_mismatch{});
  // The session: this TLS connection's, not another's relayed.
  if (hello.session_id != tls.finished) return std::unexpected(errors::session{});
  const auto agreed = smp::agreed_version(hello.versions, ours);
  if (!agreed) return std::unexpected(errors::version{});
  return verified{hello, *key, *agreed};
}

// A destination router reached through a proxy (private message routing):
// what the proxy said of it (PKEY) -- its session with it, its versions, its
// chain and signed session key -- checked as a router's own hello is,
// against the identity its address pins; the session is the proxy's, not
// ours, so no TLS of ours to bind it to.
inline std::expected<verified, pin_error> verify_relayed(const smp::response::proxy_session_key& key, std::span<const byte> identity,
                                                        smp::version_range ours) {
  const auto session_key = session_key_of(key.certificates, key.signed_key, identity);
  if (!session_key) return std::unexpected(session_key.error());
  const auto agreed = smp::agreed_version(key.versions, ours);
  if (!agreed) return std::unexpected(errors::version{});
  return verified{smp::router_hello{key.versions, key.session_id, key.certificates, key.signed_key}, *session_key, *agreed};
}

// A recipient's command signed with its Ed25519 key, in a verified session
// (its identifier signed, though not sent).
inline bytes signature_over(const verified& session, const crypto::private_key<curve::ed25519>& key, const smp::corr_id& correlation,
                            std::span<const byte> entity, std::span<const byte> body) {
  bytes authorized;
  smp::put_authorized(authorized, session.id(), correlation, entity, body);
  const auto s = crypto::sign(key, authorized);
  return bytes(s.raw.begin(), s.raw.end());
}
// A command authenticated deniably: a box over the SHA-512 of what is
// authorized, keyed by the client's X25519 key and the verified router's
// session key, its nonce the correlation id.
inline std::expected<bytes, crypto::crypto_error> authenticator_over(const verified& session, const crypto::private_key<curve::x25519>& key,
                                                                     const smp::corr_id& correlation, std::span<const byte> entity,
                                                                     std::span<const byte> body) {
  bytes authorized;
  smp::put_authorized(authorized, session.id(), correlation, entity, body);
  const auto box = crypto::box_key_of(session.router_key(), key);
  if (!box) return std::unexpected(box.error());
  const auto digest = crypto::sha512(authorized);
  return crypto::secretbox(*box, correlation, digest);
}

// ---- private message routing ----------------------------------------------------

// A command for a router reached through a proxy, as simplexmq's
// proxySMPCommand makes one: the transmission as the destination router
// takes it -- in its session (verify_relayed), signed where `key` is given
// -- batched, padded and sealed to a key of ours used once with the
// destination's session key, the nonce its correlation id. Sent to the
// proxy as PFWD, for the proxy session, with the same correlation id.
struct proxied {
  smp::command::proxy_forward command;
  smp::corr_id correlation{};  // the nonce: the PFWD's correlation id too
  crypto::box_key secret{};
};
inline constexpr std::size_t proxied_length = 16226;  // simplexmq's paddedProxiedTLength
template <crypto::random_source R>
std::expected<proxied, std::string> proxy_command(const verified& destination, std::span<const byte> entity, const smp::command_t& command,
                                                  const std::optional<crypto::private_key<curve::ed25519>>& key, R& random) {
  const auto once = crypto::generate<curve::x25519>(random);
  const auto secret = crypto::box_key_of(destination.router_key(), once.priv);
  if (!secret) return std::unexpected("the destination's session key refuses ours");
  proxied out;
  out.secret = *secret;
  random(std::span<byte>(out.correlation));
  bytes body;
  smp::put_command(body, command);
  const bytes auth = key ? signature_over(destination, *key, out.correlation, entity, body) : bytes{};
  const smp::transmission t{auth, out.correlation, bytes(entity.begin(), entity.end()), std::move(body)};
  const auto batch = smp::batch_of(std::span(&t, 1), destination.version());
  if (!batch) return std::unexpected("the command does not batch");
  bytes padded;
  if (!put_padded(padded, *batch, proxied_length)) return std::unexpected("the command is too large to proxy");
  out.command = smp::command::proxy_forward{destination.version(), once.pub, crypto::secretbox(out.secret, out.correlation, padded)};
  return out;
}
// The destination's response, as the proxy passed it back (PRES): opened
// with the nonce reversed, its one transmission read.
inline std::expected<smp::response_t, std::string> proxied_response(const proxied& p, const smp::response::proxy_response& pres, std::uint16_t version) {
  crypto::box_nonce reversed{};
  std::ranges::reverse_copy(p.correlation, reversed.begin());
  const auto plain = crypto::secretbox_open(p.secret, pres.nonce.value_or(reversed), pres.encrypted);
  if (!plain) return std::unexpected("the destination's response does not open");
  const auto all = smp::transmissions_of(*plain, version);
  if (!all || all->size() != 1) return std::unexpected("not one transmission");
  const auto r = smp::response_of(all->front().body);
  if (!r) return std::unexpected("the destination's response does not read");
  return *r;
}

}  // namespace quay::session

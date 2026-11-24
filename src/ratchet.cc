// SPDX-License-Identifier: AGPL-3.0-only
// quay.ratchet -- SimpleX's post-quantum double ratchet with header
// encryption (pqdr.md), as simplexmq 6.5.0's Crypto/Ratchet.hs makes it:
// X448, HKDF-SHA512 ("SimpleXX3DH", "SimpleXRootRatchet",
// "SimpleXChainRatchet"), AES-256-GCM with 16-byte IVs over padded bodies,
// and sntrup761 as two KEMs in parallel. What pqdr.md leaves out is taken
// from that code: the initial agreement's salt (64 zero bytes) and output
// order (header key, next header key, root key), the associated data (the
// two first public keys' raw bytes), the header's padding (88, or 2310 with
// PQ), the version-dependent lengths.
//
// The state is a plain value the caller keeps between messages; randomness
// is the caller's.
export module quay.ratchet;

import std;
import splice;
import quay.bytes;
import quay.crypto;

export namespace quay::ratchet {

inline constexpr std::uint16_t kdf_x3dh_version = 2, pq_version = 3, current_version = 3;
inline constexpr std::uint32_t max_skip = 512;
// And skipped keys held in all, whatever the steps: a peer stepping the
// ratchet again and again cannot make them grow without end.
inline constexpr std::size_t max_skipped_total = 2048;

using key32 = crypto::secret<32>;
using iv16 = crypto::secret<16>;
using x448_private = crypto::private_key<curve::x448>;
using x448_public = public_key<curve::x448>;

// The KEM a ratchet step is augmented with.
struct kem_pair {
  crypto::sntrup761::public_key pub;
  crypto::sntrup761::secret_key secret;
};
// What a message's header says of the KEM: its key proposed, or -- the
// other's key received -- a ciphertext to it and this side's next key.
namespace kem_params {
struct proposed {
  crypto::sntrup761::public_key key;
};
struct accepted {
  crypto::sntrup761::ciphertext cipher{};
  crypto::sntrup761::public_key key;
};
}  // namespace kem_params
using kem_params_t = spl::variant<kem_params::proposed, kem_params::accepted>;

// The parameters a party sends to start a ratchet: its version, two X448
// keys, and its KEM where it uses one -- in the invitation (the receiving
// side's), or in reply (the sending side's).
struct e2e_params {
  std::uint16_t version = current_version;
  x448_public key1, key2;
  std::optional<kem_params_t> kem;
};
// And their private halves.
struct e2e_private {
  x448_private key1, key2;
  std::optional<kem_pair> kem;
  std::optional<std::pair<crypto::sntrup761::ciphertext, crypto::sntrup761::shared_secret>> accepted;  // where it accepted the other's
};

namespace errors {
struct header {};         // no header key opens it
struct kem_state {};      // KEM parameters the state does not allow
struct duplicate {};      // already received
struct earlier {          // older than what was received, and not skipped
  std::uint32_t by = 0;
};
struct too_many_skipped {
  std::uint32_t count = 0;
};
struct no_sending_chain {};
struct too_large {};
}  // namespace errors
using ratchet_error = spl::variant<errors::header, errors::kem_state, errors::duplicate, errors::earlier, errors::too_many_skipped,
                                   errors::no_sending_chain, errors::too_large, crypto::crypto_error, decode_error>;

// ---- encodings ----------------------------------------------------------------------

namespace detail {
template <class Out, class Curve>
void put_key(Out& out, const public_key<Curve>& key) {
  (void)put_short(out, spki_of(key));
}
template <class Out>
void put_kem(Out& out, const std::optional<kem_params_t>& kem) {
  if (!kem) return put_byte(out, '0');
  put_byte(out, '1');
  spl::visit(spl::overloaded{[&](const kem_params::proposed& p) {
                               put_byte(out, 'P');
                               (void)put_large(out, p.key.raw);
                             },
                             [&](const kem_params::accepted& a) {
                               put_byte(out, 'A');
                               (void)put_large(out, a.cipher);
                               (void)put_large(out, a.key.raw);
                             }},
             *kem);
}
template <class R>
std::expected<x448_public, decode_error> read_x448(R& in) {
  auto der = in.short_string();
  if (!der) return std::unexpected(der.error());
  return key_from_spki<curve::x448>(*der);
}
template <class R>
std::expected<std::optional<kem_params_t>, decode_error> read_kem(R& in) {
  const auto flag = in.u8();
  if (!flag) return std::unexpected(flag.error());
  if (*flag == '0') return std::optional<kem_params_t>();
  if (*flag != '1') return std::unexpected(quay::errors::bad_flag{});
  const auto kind = in.u8();
  if (!kind) return std::unexpected(kind.error());
  const auto key_of = [&]() -> std::expected<crypto::sntrup761::public_key, decode_error> {
    auto raw = in.large_string();
    if (!raw) return std::unexpected(raw.error());
    if (raw->size() != crypto::sntrup761::public_size) return std::unexpected(quay::errors::bad_key{});
    crypto::sntrup761::public_key k;
    std::ranges::copy(*raw, k.raw.begin());
    return k;
  };
  if (*kind == 'P') {
    auto k = key_of();
    if (!k) return std::unexpected(k.error());
    return std::optional<kem_params_t>(kem_params::proposed{*k});
  }
  if (*kind == 'A') {
    auto ct = in.large_string();
    if (!ct) return std::unexpected(ct.error());
    if (ct->size() != crypto::sntrup761::ciphertext_size) return std::unexpected(quay::errors::bad_key{});
    auto k = key_of();
    if (!k) return std::unexpected(k.error());
    kem_params::accepted a;
    std::ranges::copy(*ct, a.cipher.begin());
    a.key = *k;
    return std::optional<kem_params_t>(a);
  }
  return std::unexpected(quay::errors::bad_flag{});
}
}  // namespace detail

// E2E parameters as the agent's envelopes carry them (sndE2EEncryptionParams).
template <byte_sink Out>
void put_e2e_params(Out& out, const e2e_params& p) {
  put_u16(out, p.version);
  detail::put_key(out, p.key1);
  detail::put_key(out, p.key2);
  if (p.version >= pq_version) detail::put_kem(out, p.kem);
}
template <class R>
std::expected<e2e_params, decode_error> read_e2e_params(R& in) {
  e2e_params out;
  const auto v = in.u16();
  if (!v) return std::unexpected(v.error());
  out.version = *v;
  auto k1 = detail::read_x448(in);
  if (!k1) return std::unexpected(k1.error());
  auto k2 = detail::read_x448(in);
  if (!k2) return std::unexpected(k2.error());
  out.key1 = *k1, out.key2 = *k2;
  if (out.version >= pq_version) {
    auto kem = detail::read_kem(in);
    if (!kem) return std::unexpected(kem.error());
    out.kem = std::move(*kem);
  }
  return out;
}

// ---- the initial agreement ----------------------------------------------------------

struct init_params {
  bytes associated;  // the two first public keys, raw
  key32 root{}, send_header{}, next_receive_header{};
  // The KEM agreed in the agreement itself, where one was: the other's key,
  // the shared secret, the ciphertext that carried it.
  struct kem_accepted {
    crypto::sntrup761::public_key their_key;
    crypto::sntrup761::shared_secret shared{};
    crypto::sntrup761::ciphertext cipher{};
  };
  std::optional<kem_accepted> kem;
};

namespace detail {
inline std::array<bytes, 3> hkdf3(std::span<const byte> salt, std::span<const byte> input, std::string_view info) {
  const bytes label(info.begin(), info.end());
  const bytes out = crypto::hkdf_sha512(salt, input, label, 96);
  return {bytes(out.begin(), out.begin() + 32), bytes(out.begin() + 32, out.begin() + 64), bytes(out.begin() + 64, out.end())};
}
inline key32 key_of(const bytes& b) {
  key32 k{};
  std::ranges::copy(std::span(b).first(32), k.raw.begin());
  return k;
}
inline std::expected<bytes, ratchet_error> dh(const x448_public& theirs, const x448_private& mine) {
  const auto s = crypto::agree(mine, theirs);
  if (!s) return std::unexpected(ratchet_error(s.error()));
  return bytes(s->begin(), s->end());
}
inline std::expected<init_params, ratchet_error> x3dh(const x448_public& sender_key1, const x448_public& receiver_key1, const bytes& dh1,
                                                      const bytes& dh2, const bytes& dh3, std::optional<init_params::kem_accepted> kem) {
  init_params out;
  out.associated.assign(sender_key1.raw.begin(), sender_key1.raw.end());
  out.associated.insert(out.associated.end(), receiver_key1.raw.begin(), receiver_key1.raw.end());
  bytes secrets = dh1;
  secrets.insert(secrets.end(), dh2.begin(), dh2.end());
  secrets.insert(secrets.end(), dh3.begin(), dh3.end());
  if (kem) secrets.insert(secrets.end(), kem->shared.begin(), kem->shared.end());
  const bytes salt(64, 0);
  const auto [hk, nhk, sk] = hkdf3(salt, secrets, "SimpleXX3DH");
  out.send_header = key_of(hk), out.next_receive_header = key_of(nhk), out.root = key_of(sk);
  out.kem = std::move(kem);
  return out;
}
}  // namespace detail

// The joining side (Alice in the spec): its own private keys and what it
// replies, against the parameters it was invited with.
inline std::expected<std::pair<init_params, std::optional<kem_pair>>, ratchet_error> x3dh_sending(const e2e_private& mine, const e2e_params& theirs) {
  std::optional<init_params::kem_accepted> accepted;
  std::optional<kem_pair> pair;
  if (mine.kem && theirs.version >= pq_version) {
    pair = mine.kem;
    if (mine.accepted) {
      const auto* proposed = theirs.kem ? theirs.kem->template get_if<kem_params::proposed>() : nullptr;
      if (!proposed) return std::unexpected(errors::kem_state{});
      accepted = init_params::kem_accepted{proposed->key, mine.accepted->second, mine.accepted->first};
    }
  }
  const auto dh1 = detail::dh(theirs.key1, mine.key2);
  const auto dh2 = detail::dh(theirs.key2, mine.key1);
  const auto dh3 = detail::dh(theirs.key2, mine.key2);
  if (!dh1 || !dh2 || !dh3) return std::unexpected(errors::header{});
  auto params = detail::x3dh(crypto::public_of(mine.key1), theirs.key1, *dh1, *dh2, *dh3, std::move(accepted));
  if (!params) return std::unexpected(params.error());
  return std::pair{std::move(*params), std::move(pair)};
}
// The inviting side (Bob), on the reply.
inline std::expected<std::pair<init_params, std::optional<kem_pair>>, ratchet_error> x3dh_receiving(const e2e_private& mine,
                                                                                                    const e2e_params& theirs) {
  std::optional<init_params::kem_accepted> accepted;
  std::optional<kem_pair> pair;
  if (theirs.version >= pq_version && theirs.kem) {
    if (const auto* a = theirs.kem->template get_if<kem_params::accepted>()) {
      if (!mine.kem) return std::unexpected(errors::kem_state{});
      const auto shared = crypto::sntrup761::decapsulate(mine.kem->secret, a->cipher);
      accepted = init_params::kem_accepted{a->key, shared, a->cipher};
      pair = mine.kem;
    }
  }
  const auto dh1 = detail::dh(theirs.key2, mine.key1);
  const auto dh2 = detail::dh(theirs.key1, mine.key2);
  const auto dh3 = detail::dh(theirs.key2, mine.key2);
  if (!dh1 || !dh2 || !dh3) return std::unexpected(errors::header{});
  auto params = detail::x3dh(theirs.key1, crypto::public_of(mine.key1), *dh1, *dh2, *dh3, std::move(accepted));
  if (!params) return std::unexpected(params.error());
  return std::pair{std::move(*params), std::move(pair)};
}

// ---- the ratchet ------------------------------------------------------------------------

struct message_key {
  key32 key{};
  iv16 iv{};
  friend bool operator==(const message_key&, const message_key&) = default;
};
struct kem_state {
  kem_pair own;  // PQRs
  std::optional<init_params::kem_accepted> accepted;  // PQRr, PQRss, PQRct
};
struct state {
  std::uint16_t current = current_version, max_supported = current_version;
  bytes associated;
  x448_private dh_own;  // DHRs
  std::optional<kem_state> kem;
  bool support_kem = false, enable_kem = false, send_kem = false, receive_kem = false;
  key32 root{};
  struct sending {
    x448_public their_dh;  // DHRr
    key32 chain{}, header{};
  };
  struct receiving {
    key32 chain{}, header{};
  };
  std::optional<sending> send;
  std::optional<receiving> receive;
  std::uint32_t ns = 0, nr = 0, pn = 0;
  key32 next_send_header{}, next_receive_header{};
  // Keys of messages skipped, by the header key they came under and their number.
  std::map<key32, std::map<std::uint32_t, message_key>> skipped;

  // Move-only: encrypting from an old copy would use a message key and IV
  // again -- the state is moved, not copied. The caller keeps the state as
  // it is after encrypt() before what encrypt() gave is sent.
  state() = default;
  state(state&&) = default;
  state& operator=(state&&) = default;
  state(const state&) = delete;
  state& operator=(const state&) = delete;
  // A copy where one is meant: decrypt() tries a step on one.
  [[nodiscard]] state clone() const {
    state out;
    out.current = current, out.max_supported = max_supported, out.associated = associated, out.dh_own = dh_own, out.kem = kem;
    out.support_kem = support_kem, out.enable_kem = enable_kem, out.send_kem = send_kem, out.receive_kem = receive_kem;
    out.root = root, out.send = send, out.receive = receive, out.ns = ns, out.nr = nr, out.pn = pn;
    out.next_send_header = next_send_header, out.next_receive_header = next_receive_header, out.skipped = skipped;
    return out;
  }
};
// What a snapshot of a state holds (quay.snapshot): all of it, in this order.
template <class S>
  requires std::same_as<std::remove_const_t<S>, state>
auto snapshot_fields(S& s) {
  return std::tie(s.current, s.max_supported, s.associated, s.dh_own, s.kem, s.support_kem, s.enable_kem, s.send_kem, s.receive_kem, s.root,
                  s.send, s.receive, s.ns, s.nr, s.pn, s.next_send_header, s.next_receive_header, s.skipped);
}

namespace detail {
// A DH that fails (a low-order point) is refused here, as the initial
// agreement refuses it; simplexmq does not check, and would go on with
// what X448 gave.
inline std::expected<std::tuple<key32, key32, key32>, ratchet_error> root_kdf(const key32& root, const x448_public& theirs, const x448_private& mine,
                                                                             const std::optional<crypto::sntrup761::shared_secret>& kem) {
  auto secret = dh(theirs, mine);
  if (!secret) return std::unexpected(secret.error());
  if (kem) secret->insert(secret->end(), kem->begin(), kem->end());
  const auto [rk, ck, nhk] = hkdf3(root.raw, *secret, "SimpleXRootRatchet");
  crypto::scrub(*secret);
  return std::tuple{key_of(rk), key_of(ck), key_of(nhk)};
}
inline std::tuple<key32, message_key, iv16> chain_kdf(const key32& chain) {
  auto [ck, mk, ivs] = hkdf3(std::span<const byte>(), chain.raw, "SimpleXChainRatchet");
  message_key m;
  m.key = key_of(mk);
  std::ranges::copy(std::span(ivs).first(16), m.iv.raw.begin());
  iv16 header_iv{};
  std::ranges::copy(std::span(ivs).subspan(16, 16), header_iv.raw.begin());
  key32 next = key_of(ck);
  crypto::scrub(ck), crypto::scrub(mk), crypto::scrub(ivs);
  return {next, m, header_iv};
}
inline std::size_t padded_header_length(std::uint16_t version, bool support_kem) { return support_kem && version >= pq_version ? 2310 : 88; }
template <class Out>
void put_versioned_length(Out& out, std::uint16_t version, std::span<const byte> data) {
  if (version >= pq_version) (void)put_large(out, data);
  else (void)put_short(out, data);
}
template <class R>
std::expected<bytes, decode_error> read_versioned_length(R& in, std::span<const byte> rest) {
  // A first byte below 32: a two-byte length (a header is never that short).
  // Upstream reads it so too (Ratchet.hs largeP), so that a message can
  // carry a version upgrade; it is written by version (put_versioned_length).
  if (!rest.empty() && rest.front() < 32) return in.large_string();
  return in.short_string();
}
}  // namespace detail

// The joining side's ratchet: it sends first.
inline state sending_ratchet(std::uint16_t current, std::uint16_t max_supported, const x448_public& their_key2, const x448_private& own_dh,
                             const init_params& params, const std::optional<kem_pair>& own_kem) {
  state s;
  s.current = current, s.max_supported = max_supported;
  s.associated = params.associated;
  s.dh_own = own_dh;
  // (The agreement refused a failing DH already: this one, with the same
  // keys' second halves, is only refused where the other's key is bad.)
  auto stepped = detail::root_kdf(params.root, their_key2, own_dh, params.kem ? std::optional(params.kem->shared) : std::nullopt);
  if (!stepped) throw std::invalid_argument("quay.ratchet: the other side's ratchet key agrees on nothing");
  auto [rk, cks, nhks] = *stepped;
  s.root = rk;
  s.send = state::sending{their_key2, cks, params.send_header};
  s.next_send_header = nhks;
  s.next_receive_header = params.next_receive_header;
  if (own_kem) s.kem = kem_state{*own_kem, params.kem};
  s.support_kem = s.enable_kem = own_kem.has_value();
  s.send_kem = params.kem.has_value();
  return s;
}
// The inviting side's: it receives first.
inline state receiving_ratchet(std::uint16_t current, std::uint16_t max_supported, const x448_private& own_key2, const init_params& params,
                               const std::optional<kem_pair>& own_kem, bool support_pq) {
  state s;
  s.current = current, s.max_supported = max_supported;
  s.associated = params.associated;
  s.dh_own = own_key2;
  s.root = params.root;
  s.next_send_header = params.next_receive_header;
  s.next_receive_header = params.send_header;
  if (own_kem) s.kem = kem_state{*own_kem, params.kem};
  s.support_kem = support_pq;
  s.enable_kem = support_pq;
  return s;
}

// A message encrypted: its header under the sending header key, its body --
// padded to `padded_length` -- under the next message key.
template <crypto::random_source R>
std::expected<bytes, ratchet_error> encrypt(state& s, std::span<const byte> plain, std::size_t padded_length, R&) {
  if (!s.send) return std::unexpected(errors::no_sending_chain{});
  if (plain.size() + 2 > padded_length) return std::unexpected(errors::too_large{});
  const auto [chain, key, header_iv] = detail::chain_kdf(s.send->chain);
  const std::uint16_t v = s.current;
  s.support_kem = s.support_kem || (v >= pq_version && s.enable_kem);
  // The header: the versions, this side's DH key, its KEM, the counters.
  bytes header;
  put_u16(header, s.max_supported);
  detail::put_key(header, crypto::public_of(s.dh_own));
  if (v >= pq_version) {
    std::optional<kem_params_t> kem;
    if (s.kem) {
      if (s.kem->accepted) kem = kem_params::accepted{s.kem->accepted->cipher, s.kem->own.pub};
      else kem = kem_params::proposed{s.kem->own.pub};
    }
    detail::put_kem(header, kem);
  }
  put_u32(header, s.pn);
  put_u32(header, s.ns);
  bytes padded_header;
  if (auto ok = put_padded(padded_header, header, detail::padded_header_length(v, s.support_kem)); !ok) return std::unexpected(ok.error());
  const auto sealed_header = crypto::gcm_seal(s.send->header.raw, header_iv.raw, s.associated, padded_header);
  bytes enc_header;
  put_u16(enc_header, v);
  put_bytes(enc_header, header_iv.raw);
  put_bytes(enc_header, sealed_header.tag);
  detail::put_versioned_length(enc_header, v, sealed_header.cipher);
  // The body, its associated data the ratchet's and the encrypted header.
  bytes padded_body;
  if (auto ok = put_padded(padded_body, plain, padded_length); !ok) return std::unexpected(ok.error());
  bytes body_ad = s.associated;
  body_ad.insert(body_ad.end(), enc_header.begin(), enc_header.end());
  const auto sealed_body = crypto::gcm_seal(key.key.raw, key.iv.raw, body_ad, padded_body);
  bytes out;
  detail::put_versioned_length(out, v, enc_header);
  put_bytes(out, sealed_body.tag);
  put_bytes(out, sealed_body.cipher);
  s.send->chain = chain;
  ++s.ns;
  return out;
}

namespace detail {
struct header {
  std::uint16_t max_version = 0;
  x448_public dh;
  std::optional<kem_params_t> kem;
  std::uint32_t pn = 0, n = 0;
};
struct parsed_message {
  std::uint16_t version = 0;
  std::array<byte, 16> header_iv{};
  crypto::gcm_tag header_tag{};
  bytes header_cipher;
  bytes enc_header;  // as it came: the body's associated data
  crypto::gcm_tag body_tag{};
  bytes body_cipher;
};
inline std::expected<parsed_message, ratchet_error> parse(std::span<const byte> wire) {
  parsed_message out;
  auto in = reader_of(wire);
  auto enc_header = read_versioned_length(in, wire);
  if (!enc_header) return std::unexpected(enc_header.error());
  out.enc_header = *enc_header;
  auto tag = in.template fixed<16>();
  if (!tag) return std::unexpected(tag.error());
  out.body_tag = *tag;
  out.body_cipher = in.rest();
  auto h = reader_of(out.enc_header);
  const auto v = h.u16();
  if (!v) return std::unexpected(v.error());
  out.version = *v;
  auto iv = h.template fixed<16>();
  auto htag = h.template fixed<16>();
  if (!iv || !htag) return std::unexpected(decode_error(quay::errors::short_input{}));
  out.header_iv = *iv, out.header_tag = *htag;
  const std::span<const byte> rest = std::span(out.enc_header).subspan(2 + 16 + 16);
  auto body = read_versioned_length(h, rest);
  if (!body) return std::unexpected(body.error());
  out.header_cipher = std::move(*body);
  return out;
}
inline std::optional<header> open_header(const key32& key, const bytes& associated, const parsed_message& m) {
  const auto plain = crypto::gcm_open(key.raw, m.header_iv, associated, m.header_cipher, m.header_tag);
  if (!plain) return std::nullopt;
  const auto inner = unpadded(*plain);
  if (!inner) return std::nullopt;
  auto in = reader_of(*inner);
  header out;
  const auto mv = in.u16();
  if (!mv) return std::nullopt;
  out.max_version = *mv;
  auto dh_key = read_x448(in);
  if (!dh_key) return std::nullopt;
  out.dh = *dh_key;
  if (m.version >= pq_version) {
    auto kem = read_kem(in);
    if (!kem) return std::nullopt;
    out.kem = std::move(*kem);
  }
  const auto pn = in.u32(), n = in.u32();
  if (!pn || !n) return std::nullopt;
  out.pn = *pn, out.n = *n;
  return out;
}
inline std::expected<bytes, ratchet_error> open_body(const message_key& key, const bytes& associated, const parsed_message& m) {
  bytes ad = associated;
  ad.insert(ad.end(), m.enc_header.begin(), m.enc_header.end());
  const auto plain = crypto::gcm_open(key.key.raw, key.iv.raw, ad, m.body_cipher, m.body_tag);
  if (!plain) return std::unexpected(ratchet_error(plain.error()));
  const auto inner = unpadded(*plain);
  if (!inner) return std::unexpected(inner.error());
  return bytes(inner->begin(), inner->end());
}
// The keys of the messages before `until` in the receiving chain, kept.
inline std::expected<void, ratchet_error> skip(state& s, std::uint32_t until) {
  if (!s.receive) return {};
  if (s.nr > until + 1) return std::unexpected(errors::earlier{s.nr - until - 1});
  if (s.nr == until + 1) return std::unexpected(errors::duplicate{});
  if (s.nr + max_skip < until) return std::unexpected(errors::too_many_skipped{until + 1 - s.nr});
  std::size_t held = 0;
  for (const auto& [hk, keys] : s.skipped) held += keys.size();
  if (held + (until - s.nr) > max_skipped_total) return std::unexpected(errors::too_many_skipped{until + 1 - s.nr});
  auto& keys = s.skipped[s.receive->header];
  while (s.nr < until) {
    const auto [chain, key, ignored] = chain_kdf(s.receive->chain);
    keys[s.nr] = key;
    s.receive->chain = chain;
    ++s.nr;
  }
  if (keys.empty()) s.skipped.erase(s.receive->header);
  return {};
}
}  // namespace detail

// A message decrypted: by a skipped key where it is one, else in the
// receiving chain -- a DH ratchet step first where it comes under the next
// header key, with its KEM.
template <crypto::random_source R>
std::expected<bytes, ratchet_error> decrypt(state& s, std::span<const byte> wire, R& random) {
  const auto parsed = detail::parse(wire);
  if (!parsed) return std::unexpected(parsed.error());
  // A skipped message's key.
  for (auto& [hk, keys] : s.skipped) {
    const auto h = detail::open_header(hk, s.associated, *parsed);
    if (!h) continue;
    if (const auto found = keys.find(h->n); found != keys.end()) {
      auto plain = detail::open_body(found->second, s.associated, *parsed);
      if (plain) {
        keys.erase(found);
        if (keys.empty()) s.skipped.erase(hk);
      }
      return plain;
    }
    break;
  }
  state next = s.clone();
  bool step = false;
  std::optional<detail::header> h;
  if (next.receive) h = detail::open_header(next.receive->header, next.associated, *parsed);
  if (!h) {
    h = detail::open_header(next.next_receive_header, next.associated, *parsed);
    step = true;
  }
  if (!h) return std::unexpected(errors::header{});
  if (h->max_version > next.current) next.current = std::max(next.current, std::min(h->max_version, next.max_supported));
  if (step) {
    if (auto ok = detail::skip(next, h->pn); !ok) return std::unexpected(ok.error());
    // The KEM of the step: the secret decapsulated from the header's
    // ciphertext (KEM #2), and a new one encapsulated to its key (KEM #1).
    std::optional<crypto::sntrup761::shared_secret> received_secret, sent_secret;
    std::optional<kem_state> kem_next;
    const bool pq = next.enable_kem && next.current >= pq_version;
    if (!h->kem) {
      if (!next.kem && pq) kem_next = kem_state{[&] {
        const auto made = crypto::sntrup761::generate(random);
        return kem_pair{made.pub, made.secret};
      }(), std::nullopt};
    } else {
      crypto::sntrup761::public_key their_key;
      if (const auto* p = h->kem->template get_if<kem_params::proposed>()) {
        their_key = p->key;
      } else {
        const auto& a = *h->kem->template get_if<kem_params::accepted>();
        if (!next.kem) return std::unexpected(errors::kem_state{});
        received_secret = crypto::sntrup761::decapsulate(next.kem->own.secret, a.cipher);
        their_key = a.key;
      }
      if (pq) {
        const auto sent = crypto::sntrup761::encapsulate(their_key, random);
        const auto made = crypto::sntrup761::generate(random);
        kem_next = kem_state{kem_pair{made.pub, made.secret}, init_params::kem_accepted{their_key, sent.shared, sent.cipher}};
        sent_secret = sent.shared;
      }
    }
    const auto fresh = crypto::generate<curve::x448>(random);
    const auto first = detail::root_kdf(next.root, h->dh, next.dh_own, received_secret);
    if (!first) return std::unexpected(first.error());
    const auto [rk1, ckr, nhkr] = *first;
    const auto second = detail::root_kdf(rk1, h->dh, fresh.priv, sent_secret);
    if (!second) return std::unexpected(second.error());
    const auto [rk2, cks, nhks] = *second;
    next.enable_kem = sent_secret.has_value() || received_secret.has_value() || kem_next.has_value();
    next.support_kem = next.support_kem || (next.current >= pq_version && next.enable_kem);
    next.send_kem = sent_secret.has_value();
    next.receive_kem = received_secret.has_value();
    next.kem = kem_next;
    next.dh_own = fresh.priv;
    next.root = rk2;
    next.send = state::sending{h->dh, cks, next.next_send_header};
    next.receive = state::receiving{ckr, next.next_receive_header};
    next.pn = next.ns;
    next.ns = 0, next.nr = 0;
    next.next_send_header = nhks;
    next.next_receive_header = nhkr;
  }
  if (auto ok = detail::skip(next, h->n); !ok) return std::unexpected(ok.error());
  if (!next.receive) return std::unexpected(errors::no_sending_chain{});
  const auto [chain, key, ignored] = detail::chain_kdf(next.receive->chain);
  auto plain = detail::open_body(key, next.associated, *parsed);
  if (!plain) return plain;
  next.receive->chain = chain;
  ++next.nr;
  s = std::move(next);
  return plain;
}

// A party's parameters made: two X448 key pairs, and a KEM -- proposed, or
// accepting the other's key -- where it uses one.
template <crypto::random_source R>
std::pair<e2e_params, e2e_private> make_params(std::uint16_t version, bool with_kem, const std::optional<crypto::sntrup761::public_key>& accepting,
                                              R& random) {
  const auto k1 = crypto::generate<curve::x448>(random), k2 = crypto::generate<curve::x448>(random);
  e2e_params pub{version, k1.pub, k2.pub, std::nullopt};
  e2e_private priv{k1.priv, k2.priv, std::nullopt, std::nullopt};
  if (with_kem && version >= pq_version) {
    const auto made = crypto::sntrup761::generate(random);
    priv.kem = kem_pair{made.pub, made.secret};
    if (accepting) {
      const auto sent = crypto::sntrup761::encapsulate(*accepting, random);
      pub.kem = kem_params::accepted{sent.cipher, made.pub};
      priv.accepted = std::pair{sent.cipher, sent.shared};
    } else {
      pub.kem = kem_params::proposed{made.pub};
    }
  }
  return {pub, priv};
}

}  // namespace quay::ratchet

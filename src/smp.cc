// SPDX-License-Identifier: AGPL-3.0-only
// quay.smp -- SimpleX Messaging Protocol (simplex-messaging.md, v23): what
// a client says to a router and what the router says back, each a type;
// the transmissions they go in, many to a padded 16384-byte block; the
// handshake; queue URIs; and the layers a message goes through -- the
// router's to the recipient (NaCl box keyed by the queue's DH, the
// message id its nonce) and the sender's to the recipient (box keyed by
// the URI's DH key) -- read once, where they come in, into types.
//
// Sans-IO: blocks are bytes in, bytes out; the caller's transport (TLS 1.3,
// ALPN smp/1, the router's certificate pinned) carries them.
export module quay.smp;

import std;
import splice;
import quay.bytes;
import quay.crypto;

export namespace quay::smp {

inline constexpr std::size_t block_size = 16384;
inline constexpr std::uint16_t min_version = 6, max_version = 23;
// From v16 every authorized transmission has a place for a client service's
// signature: '0' where there is none, '1' and the signature where there is.
// (The spec's text calls it present only in service sessions; simplexmq's
// own parser -- transmissionP, serviceAuth = v >= 16 -- reads it always.)
inline constexpr std::uint16_t service_signature_version = 16;
inline constexpr std::size_t max_message_length = 16048;     // smpEncMessage, v11+
inline constexpr std::size_t e2e_message_length = 16000;      // padded smpClientMessage
inline constexpr std::size_t e2e_confirmation_length = 15904; // padded smpConfirmation

using corr_id = std::array<byte, 24>;
using entity_id = bytes;  // a queue's recipient, sender or notifier id; a proxy session's

// ---- routers and queue URIs -----------------------------------------------------

struct version_range {
  std::uint16_t min = 1, max = 1;
  friend constexpr bool operator==(const version_range&, const version_range&) = default;
};
// A router: its identity (the fingerprint of its CA certificate), its hosts
// (any of which reaches it), and its port where it is not 5223.
struct router {
  bytes identity;
  std::vector<std::string> hosts;
  std::optional<std::uint16_t> port;
  friend constexpr bool operator==(const router&, const router&) = default;
};
// A queue as a sender is given it: where, its sender id, the versions of
// the client protocol, the recipient's X25519 key for the E2E layer, and
// whether the sender may secure it (SKEY).
struct queue_uri {
  smp::router router;
  bytes sender_id;
  version_range versions;
  public_key<curve::x25519> dh;
  bool sender_can_secure = false;
  friend constexpr bool operator==(const queue_uri&, const queue_uri&) = default;
};

namespace uri_errors {
struct not_smp {};
struct bad_router {};
struct bad_id {};
struct bad_versions {};
struct bad_key {};
}  // namespace uri_errors
using uri_error = spl::variant<uri_errors::not_smp, uri_errors::bad_router, uri_errors::bad_id, uri_errors::bad_versions, uri_errors::bad_key>;

namespace detail {
constexpr std::string decimal(std::uint32_t n) {
  std::string out;
  do out.insert(out.begin(), static_cast<char>('0' + n % 10)), n /= 10;
  while (n != 0);
  return out;
}
constexpr std::optional<std::uint16_t> number(std::string_view s) {
  if (s.empty() || s.size() > 5) return std::nullopt;
  std::uint32_t n = 0;
  for (const char c : s) {
    if (c < '0' || c > '9') return std::nullopt;
    n = n * 10 + static_cast<std::uint32_t>(c - '0');
  }
  if (n > 65535) return std::nullopt;
  return static_cast<std::uint16_t>(n);
}
constexpr std::optional<version_range> versions_of(std::string_view s) {
  const auto dash = s.find('-');
  const auto low = number(s.substr(0, dash));
  const auto high = dash == std::string_view::npos ? low : number(s.substr(dash + 1));
  if (!low || !high || *low > *high) return std::nullopt;
  return version_range{*low, *high};
}
}  // namespace detail

// identity@host1,host2[:port]
[[nodiscard]] constexpr std::expected<router, uri_error> router_of(std::string_view text) {
  const auto at = text.find('@');
  if (at == std::string_view::npos) return std::unexpected(uri_errors::bad_router{});
  auto identity = base64url_decode(text.substr(0, at));
  if (!identity || identity->empty()) return std::unexpected(uri_errors::bad_router{});
  router out{std::move(*identity), {}, std::nullopt};
  std::string_view where = text.substr(at + 1);
  // A port after the last colon -- unless that colon is inside an IPv6 literal's brackets.
  if (const auto colon = where.rfind(':'); colon != std::string_view::npos && where.find(']', colon) == std::string_view::npos) {
    const auto port = detail::number(where.substr(colon + 1));
    if (!port) return std::unexpected(uri_errors::bad_router{});
    out.port = *port;
    where = where.substr(0, colon);
  }
  for (auto host : where | std::views::split(',')) {
    const std::string_view one(host.begin(), host.end());
    if (one.empty()) return std::unexpected(uri_errors::bad_router{});
    out.hosts.emplace_back(one);
  }
  if (out.hosts.empty()) return std::unexpected(uri_errors::bad_router{});
  return out;
}
// smp://identity@hosts[:port]/senderId#/?v=1-4&dh=...[&k=s]
[[nodiscard]] constexpr std::expected<queue_uri, uri_error> queue_uri_of(std::string_view text) {
  if (!text.starts_with("smp://")) return std::unexpected(uri_errors::not_smp{});
  text.remove_prefix(6);
  const auto slash = text.find('/');
  if (slash == std::string_view::npos) return std::unexpected(uri_errors::bad_router{});
  auto where = router_of(text.substr(0, slash));
  if (!where) return std::unexpected(where.error());
  text.remove_prefix(slash + 1);
  const auto hash = text.find('#');
  auto id = base64url_decode(text.substr(0, hash));
  if (!id || id->empty()) return std::unexpected(uri_errors::bad_id{});
  queue_uri out{std::move(*where), std::move(*id), {}, {}, false};
  std::string_view query = hash == std::string_view::npos ? std::string_view() : text.substr(hash + 1);
  if (query.starts_with('/')) query.remove_prefix(1);
  if (query.starts_with('?')) query.remove_prefix(1);
  bool versions = false, key = false;
  for (auto pair : query | std::views::split('&')) {
    const std::string_view one(pair.begin(), pair.end());
    const auto eq = one.find('=');
    const auto name = one.substr(0, eq);
    const auto value = eq == std::string_view::npos ? std::string_view() : one.substr(eq + 1);
    if (name == "v") {
      const auto range = detail::versions_of(value);
      if (!range) return std::unexpected(uri_errors::bad_versions{});
      out.versions = *range, versions = true;
    } else if (name == "dh") {
      const auto der = base64url_decode(value);
      if (!der) return std::unexpected(uri_errors::bad_key{});
      const auto k = key_from_spki<curve::x25519>(*der);
      if (!k) return std::unexpected(uri_errors::bad_key{});
      out.dh = *k, key = true;
    } else if (name == "k") {
      out.sender_can_secure = value == "s";
    }  // unknown parameters ignored, as the spec says
  }
  if (!versions) return std::unexpected(uri_errors::bad_versions{});
  if (!key) return std::unexpected(uri_errors::bad_key{});
  return out;
}
template <class Out>
constexpr void put_router(Out& out, const router& where) {
  put_base64url(out, where.identity);
  out.push_back('@');
  bool first = true;
  for (const auto& host : where.hosts) {
    if (!first) out.push_back(',');
    first = false;
    for (const char c : host) out.push_back(c);
  }
  if (where.port) {
    out.push_back(':');
    for (const char c : detail::decimal(*where.port)) out.push_back(c);
  }
}
[[nodiscard]] constexpr std::string text_of(const queue_uri& q) {
  std::string out = "smp://";
  put_router(out, q.router);
  out += '/';
  put_base64url(out, q.sender_id);
  out += "#/?v=" + detail::decimal(q.versions.min);
  if (q.versions.max != q.versions.min) out += "-" + detail::decimal(q.versions.max);
  out += "&dh=";
  put_base64url(out, spki_of(q.dh));
  if (q.sender_can_secure) out += "&k=s";
  return out;
}

// ---- what a client says ---------------------------------------------------------

// A key that authorizes a queue's commands: signed with Ed25519, or
// authenticated (deniably) by a box keyed with X25519.
using auth_key = spl::variant<public_key<curve::ed25519>, public_key<curve::x25519>>;
struct messaging_link {  // a queue's short link data, for a messaging queue
  bytes sender_id, fixed, user;
  friend constexpr bool operator==(const messaging_link&, const messaging_link&) = default;
};
struct contact_link {
  bytes link_id, sender_id, fixed, user;
  friend constexpr bool operator==(const contact_link&, const contact_link&) = default;
};
namespace queue_request {
struct messaging {  // the sender may secure it (SKEY); its link data, where it has a short link
  std::optional<messaging_link> link;
  friend constexpr bool operator==(const messaging&, const messaging&) = default;
};
struct contact {
  std::optional<contact_link> link;
  friend constexpr bool operator==(const contact&, const contact&) = default;
};
}  // namespace queue_request
using queue_request_t = spl::variant<queue_request::messaging, queue_request::contact>;
struct notifier_keys {
  auth_key key;
  public_key<curve::x25519> dh;
  friend constexpr bool operator==(const notifier_keys&, const notifier_keys&) = default;
};

namespace command {
struct ping {};
struct create {  // NEW
  auth_key recipient_key;
  public_key<curve::x25519> recipient_dh;
  std::optional<bytes> basic_auth;
  bool subscribe = true;
  std::optional<queue_request_t> request;
  std::optional<notifier_keys> notifications;
};
struct subscribe {};  // SUB
struct subscribe_many {  // SUBS
  std::uint64_t count = 0;
  std::array<byte, 16> ids_hash{};
};
struct secure {  // KEY (the recipient)
  auth_key sender_key;
};
struct recipient_keys {  // RKEY
  std::vector<auth_key> keys;
};
struct set_link {  // LSET
  bytes link_id, fixed, user;
};
struct delete_link {};  // LDEL
struct enable_notifications {  // NKEY
  auth_key notifier_key;
  public_key<curve::x25519> dh;
};
struct disable_notifications {};  // NDEL
struct get {};                    // GET
struct acknowledge {              // ACK
  bytes message_id;
};
struct suspend {};     // OFF
struct remove {};      // DEL
struct queue_info {};  // QUE
struct sender_secure {  // SKEY
  auth_key sender_key;
};
struct send {  // SEND
  bool notify = true;
  bytes message;  // smpEncMessage, as made by e2e_message / e2e_confirmation
};
struct set_link_key {  // LKEY
  auth_key sender_key;
};
struct get_link {};                 // LGET
struct subscribe_notifications {};  // NSUB
struct proxy_session {              // PRXY
  smp::router router;
  std::optional<bytes> basic_auth;
};
struct proxy_forward {  // PFWD
  std::uint16_t version = max_version;
  public_key<curve::x25519> command_key;
  bytes encrypted;
};
struct resolve {  // RSLV
  std::string query;
};
}  // namespace command
using command_t = spl::variant<command::ping, command::create, command::subscribe, command::subscribe_many, command::secure,
                               command::recipient_keys, command::set_link, command::delete_link, command::enable_notifications,
                               command::disable_notifications, command::get, command::acknowledge, command::suspend, command::remove,
                               command::queue_info, command::sender_secure, command::send, command::set_link_key, command::get_link,
                               command::subscribe_notifications, command::proxy_session, command::proxy_forward, command::resolve>;

namespace detail {
template <class Out, class Key>
constexpr void put_key(Out& out, const public_key<Key>& key) {
  const bytes der = spki_of(key);
  (void)put_short(out, der);
}
template <class Out>
constexpr void put_auth_key(Out& out, const auth_key& key) {
  spl::visit([&](const auto& one) { put_key(out, one); }, key);
}
template <class Out>
constexpr void put_word(Out& out, std::string_view word) {
  for (const char c : word) put_byte(out, static_cast<byte>(c));
}
template <class Out>
constexpr void put_optional_short(Out& out, const std::optional<bytes>& value) {
  if (!value) return put_byte(out, '0');
  put_byte(out, '1');
  (void)put_short(out, *value);
}
template <class Out>
constexpr void put_smp_router(Out& out, const router& where) {  // as PRXY carries it
  put_byte(out, static_cast<byte>(where.hosts.size()));
  for (const auto& host : where.hosts) (void)put_short(out, host);
  (void)put_short(out, where.port ? decimal(*where.port) : std::string());
  (void)put_short(out, where.identity);
}
}  // namespace detail

// A command's bytes, as the transmission carries them.
template <byte_sink Out>
constexpr void put_command(Out& out, const command_t& what) {
  using namespace detail;
  spl::visit(spl::overloaded{
                 [&](const command::ping&) { put_word(out, "PING"); },
                 [&](const command::create& c) {
                   put_word(out, "NEW ");
                   put_auth_key(out, c.recipient_key);
                   put_key(out, c.recipient_dh);
                   put_optional_short(out, c.basic_auth);
                   put_byte(out, c.subscribe ? 'S' : 'C');
                   if (!c.request) {
                     put_byte(out, '0');
                   } else {
                     put_byte(out, '1');
                     spl::visit(spl::overloaded{[&](const queue_request::messaging& m) {
                                                  put_byte(out, 'M');
                                                  if (!m.link) return put_byte(out, '0');
                                                  put_byte(out, '1');
                                                  (void)put_short(out, m.link->sender_id);
                                                  (void)put_large(out, m.link->fixed);
                                                  (void)put_large(out, m.link->user);
                                                },
                                                [&](const queue_request::contact& k) {
                                                  put_byte(out, 'C');
                                                  if (!k.link) return put_byte(out, '0');
                                                  put_byte(out, '1');
                                                  (void)put_short(out, k.link->link_id);
                                                  (void)put_short(out, k.link->sender_id);
                                                  (void)put_large(out, k.link->fixed);
                                                  (void)put_large(out, k.link->user);
                                                }},
                                *c.request);
                   }
                   if (!c.notifications) {
                     put_byte(out, '0');
                   } else {
                     put_byte(out, '1');
                     put_auth_key(out, c.notifications->key);
                     put_key(out, c.notifications->dh);
                   }
                 },
                 [&](const command::subscribe&) { put_word(out, "SUB"); },
                 [&](const command::subscribe_many& c) {
                   put_word(out, "SUBS ");
                   put_u64(out, c.count);
                   (void)put_short(out, c.ids_hash);
                 },
                 [&](const command::secure& c) {
                   put_word(out, "KEY ");
                   put_auth_key(out, c.sender_key);
                 },
                 [&](const command::recipient_keys& c) {
                   put_word(out, "RKEY ");
                   put_byte(out, static_cast<byte>(c.keys.size()));
                   for (const auto& k : c.keys) put_auth_key(out, k);
                 },
                 [&](const command::set_link& c) {
                   put_word(out, "LSET ");
                   (void)put_short(out, c.link_id);
                   (void)put_large(out, c.fixed);
                   (void)put_large(out, c.user);
                 },
                 [&](const command::delete_link&) { put_word(out, "LDEL"); },
                 [&](const command::enable_notifications& c) {
                   put_word(out, "NKEY ");
                   put_auth_key(out, c.notifier_key);
                   put_key(out, c.dh);
                 },
                 [&](const command::disable_notifications&) { put_word(out, "NDEL"); },
                 [&](const command::get&) { put_word(out, "GET"); },
                 [&](const command::acknowledge& c) {
                   put_word(out, "ACK ");
                   (void)put_short(out, c.message_id);
                 },
                 [&](const command::suspend&) { put_word(out, "OFF"); },
                 [&](const command::remove&) { put_word(out, "DEL"); },
                 [&](const command::queue_info&) { put_word(out, "QUE"); },
                 [&](const command::sender_secure& c) {
                   put_word(out, "SKEY ");
                   put_auth_key(out, c.sender_key);
                 },
                 [&](const command::send& c) {
                   put_word(out, "SEND ");
                   put_byte(out, c.notify ? 'T' : 'F');
                   put_byte(out, ' ');
                   put_bytes(out, c.message);
                 },
                 [&](const command::set_link_key& c) {
                   put_word(out, "LKEY ");
                   put_auth_key(out, c.sender_key);
                 },
                 [&](const command::get_link&) { put_word(out, "LGET"); },
                 [&](const command::subscribe_notifications&) { put_word(out, "NSUB"); },
                 [&](const command::proxy_session& c) {
                   put_word(out, "PRXY ");
                   put_smp_router(out, c.router);
                   put_optional_short(out, c.basic_auth);
                 },
                 [&](const command::proxy_forward& c) {
                   put_word(out, "PFWD ");
                   put_u16(out, c.version);
                   put_key(out, c.command_key);
                   put_bytes(out, c.encrypted);
                 },
                 [&](const command::resolve& c) {
                   put_word(out, "RSLV ");
                   put_word(out, c.query);
                 }},
             what);
}

// ---- what a router says -----------------------------------------------------------

// Its errors, read into types (errorType). A proxy's and a store's are kept
// as the router said them: what a client does about them is to show them.
namespace error {
struct block {};
struct session {};
namespace cmd {
struct unknown {};
struct syntax {};
struct prohibited {};
struct no_auth {};
struct has_auth {};
struct no_entity {};
}  // namespace cmd
using cmd_t = spl::variant<cmd::unknown, cmd::syntax, cmd::prohibited, cmd::no_auth, cmd::has_auth, cmd::no_entity>;
struct command {
  cmd_t what;
};
struct proxy {
  std::string detail;
};
struct auth {};
struct blocked {
  std::string reason;  // spam, content
  std::string notice;  // JSON, where it gives one
};
struct service {};
struct crypto {};
struct quota {};
struct store {
  std::string detail;
};
struct expired {};
struct no_msg {};
struct large_msg {};
struct internal {};
struct duplicate {};
struct other {  // one this version does not know
  std::string text;
};
}  // namespace error
using error_t = spl::variant<error::block, error::session, error::command, error::proxy, error::auth, error::blocked, error::service,
                             error::crypto, error::quota, error::store, error::expired, error::no_msg, error::large_msg, error::internal,
                             error::duplicate, error::other>;

namespace response {
struct queue_ids {  // IDS
  bytes recipient_id, sender_id;
  public_key<curve::x25519> server_dh;
  std::optional<byte> mode;  // 'M' messaging, 'C' contact
  std::optional<bytes> link_id, service_id;
  std::optional<std::pair<bytes, public_key<curve::x25519>>> notifier;  // its id, its DH key
};
struct link {  // LNK
  bytes sender_id, fixed, user;
};
struct service_ok {  // SOK
  std::optional<bytes> service_id;
};
struct service_ok_many {  // SOKS
  std::uint64_t count = 0;
  bytes ids_hash;
};
struct message {  // MSG: its id, and its body as the router encrypted it
  bytes id, encrypted;
};
struct all_received {};  // ALLS
struct notifier_id {     // NID
  bytes id;
  public_key<curve::x25519> dh;
};
struct notification {  // NMSG
  std::array<byte, 24> nonce{};
  bytes encrypted_meta;
};
struct proxy_session_key {  // PKEY
  bytes session_id;
  version_range versions;
  std::vector<bytes> certificates;
  bytes signed_key;
};
struct proxy_response {  // PRES
  std::optional<std::array<byte, 24>> nonce;
  bytes encrypted;
};
struct unsubscribed {};          // END
struct service_unsubscribed {};  // ENDS
struct deleted {};               // DELD
struct queue_info {              // INFO
  std::string json;
};
struct ok {};
struct pong {};
struct failed {  // ERR
  error_t error;
};
struct name {  // RNAME
  std::string json;
};
}  // namespace response
using response_t = spl::variant<response::queue_ids, response::link, response::service_ok, response::service_ok_many, response::message,
                                response::all_received, response::notifier_id, response::notification, response::proxy_session_key,
                                response::proxy_response, response::unsubscribed, response::service_unsubscribed, response::deleted,
                                response::queue_info, response::ok, response::pong, response::failed, response::name>;

namespace detail {
template <class R>
constexpr std::expected<public_key<curve::x25519>, decode_error> x25519_key(R& in) {
  const auto der = in.short_string();
  if (!der) return std::unexpected(der.error());
  return key_from_spki<curve::x25519>(*der);
}
template <class R>
constexpr std::expected<std::optional<bytes>, decode_error> optional_short(R& in) {
  const auto flag = in.u8();
  if (!flag) return std::unexpected(flag.error());
  if (*flag == '0') return std::optional<bytes>();
  if (*flag != '1') return std::unexpected(errors::bad_flag{});
  auto v = in.short_string();
  if (!v) return std::unexpected(v.error());
  return std::optional<bytes>(std::move(*v));
}
constexpr std::string text(std::span<const byte> b) { return b | std::views::transform([](byte c) { return static_cast<char>(c); }) | std::ranges::to<std::string>(); }
constexpr error_t error_of(std::string_view s) {
  const auto word = s.substr(0, s.find(' '));
  const auto rest = word.size() < s.size() ? s.substr(word.size() + 1) : std::string_view();
  if (word == "BLOCK") return error::block{};
  if (word == "SESSION") return error::session{};
  if (word == "CMD") {
    if (rest == "UNKNOWN") return error::command{error::cmd::unknown{}};
    if (rest == "SYNTAX") return error::command{error::cmd::syntax{}};
    if (rest == "PROHIBITED") return error::command{error::cmd::prohibited{}};
    if (rest == "NO_AUTH") return error::command{error::cmd::no_auth{}};
    if (rest == "HAS_AUTH") return error::command{error::cmd::has_auth{}};
    if (rest == "NO_ENTITY") return error::command{error::cmd::no_entity{}};
    return error::other{std::string(s)};
  }
  if (word == "PROXY") return error::proxy{std::string(rest)};
  if (word == "AUTH") return error::auth{};
  if (word == "BLOCKED") {
    error::blocked out;
    for (auto part : rest | std::views::split(',')) {
      const std::string_view one(part.begin(), part.end());
      if (one.starts_with("reason=")) out.reason = std::string(one.substr(7));
      else if (one.starts_with("notice=")) out.notice = std::string(one.substr(7));
    }
    return out;
  }
  if (word == "SERVICE") return error::service{};
  if (word == "CRYPTO") return error::crypto{};
  if (word == "QUOTA") return error::quota{};
  if (word == "STORE") return error::store{std::string(rest)};
  if (word == "EXPIRED") return error::expired{};
  if (word == "NO_MSG") return error::no_msg{};
  if (word == "LARGE_MSG") return error::large_msg{};
  if (word == "INTERNAL") return error::internal{};
  if (word.starts_with("DUPLICATE")) return error::duplicate{};
  return error::other{std::string(s)};
}
}  // namespace detail

namespace response_errors {
struct unknown {  // a response this version does not read
  std::string word;
};
}  // namespace response_errors
using response_error = spl::variant<decode_error, response_errors::unknown>;

// A response's bytes (after the transmission's ids), read.
[[nodiscard]] constexpr std::expected<response_t, response_error> response_of(std::span<const byte> wire) {
  using detail::text;
  const auto space = std::ranges::find(wire, byte{' '});
  const std::string word = text(std::span(wire.begin(), space));
  std::span<const byte> rest = space == wire.end() ? std::span<const byte>() : std::span(space + 1, wire.end());
  auto in = reader_of(rest);
  const auto fail = [](decode_error e) { return std::unexpected(response_error(e)); };
  if (word == "OK") return response::ok{};
  if (word == "PONG") return response::pong{};
  if (word == "END") return response::unsubscribed{};
  if (word == "ENDS") return response::service_unsubscribed{};
  if (word == "DELD") return response::deleted{};
  if (word == "ALLS") return response::all_received{};
  if (word == "ERR") return response::failed{detail::error_of(text(rest))};
  if (word == "INFO") return response::queue_info{text(rest)};
  if (word == "RNAME") return response::name{text(rest)};
  if (word == "MSG") {
    auto id = in.short_string();
    if (!id) return fail(id.error());
    return response::message{std::move(*id), in.rest()};
  }
  if (word == "IDS") {
    response::queue_ids out;
    auto r = in.short_string();
    if (!r) return fail(r.error());
    auto s = in.short_string();
    if (!s) return fail(s.error());
    auto dh = detail::x25519_key(in);
    if (!dh) return fail(dh.error());
    out.recipient_id = std::move(*r), out.sender_id = std::move(*s), out.server_dh = *dh;
    if (in.done()) return out;  // older routers stop here
    const auto mode = in.u8();
    if (!mode) return fail(mode.error());
    if (*mode == '1') {
      const auto m = in.u8();
      if (!m) return fail(m.error());
      out.mode = *m;
    }
    if (in.done()) return out;
    auto link = detail::optional_short(in);
    if (!link) return fail(link.error());
    out.link_id = std::move(*link);
    if (in.done()) return out;
    auto service = detail::optional_short(in);
    if (!service) return fail(service.error());
    out.service_id = std::move(*service);
    if (in.done()) return out;
    const auto ntf = in.u8();
    if (!ntf) return fail(ntf.error());
    if (*ntf == '1') {
      auto id = in.short_string();
      if (!id) return fail(id.error());
      auto key = detail::x25519_key(in);
      if (!key) return fail(key.error());
      out.notifier = std::pair{std::move(*id), *key};
    }
    return out;
  }
  if (word == "LNK") {
    auto s = in.short_string();
    if (!s) return fail(s.error());
    auto f = in.large_string();
    if (!f) return fail(f.error());
    auto u = in.large_string();
    if (!u) return fail(u.error());
    return response::link{std::move(*s), std::move(*f), std::move(*u)};
  }
  if (word == "SOK") {
    auto id = detail::optional_short(in);
    if (!id) return fail(id.error());
    return response::service_ok{std::move(*id)};
  }
  if (word == "SOKS") {
    const auto n = in.u64();
    if (!n) return fail(n.error());
    auto h = in.short_string();
    if (!h) return fail(h.error());
    return response::service_ok_many{*n, std::move(*h)};
  }
  if (word == "NID") {
    auto id = in.short_string();
    if (!id) return fail(id.error());
    auto key = detail::x25519_key(in);
    if (!key) return fail(key.error());
    return response::notifier_id{std::move(*id), *key};
  }
  if (word == "NMSG") {
    auto nonce = in.template fixed<24>();
    if (!nonce) return fail(nonce.error());
    auto meta = in.short_string();
    if (!meta) return fail(meta.error());
    return response::notification{*nonce, std::move(*meta)};
  }
  if (word == "PKEY") {
    response::proxy_session_key out;
    auto id = in.short_string();
    if (!id) return fail(id.error());
    const auto low = in.u16(), high = in.u16();
    if (!low || !high) return fail(errors::short_input{});
    const auto count = in.u8();
    if (!count) return fail(count.error());
    out.session_id = std::move(*id), out.versions = {*low, *high};
    for (byte i = 0; i < *count; ++i) {
      auto cert = in.large_string();
      if (!cert) return fail(cert.error());
      out.certificates.push_back(std::move(*cert));
    }
    auto key = in.large_string();
    if (!key) return fail(key.error());
    out.signed_key = std::move(*key);
    return out;
  }
  if (word == "PRES") {
    response::proxy_response out;
    // From v23 a nonce flag first; before it, the encrypted response alone.
    if (!rest.empty() && (rest.front() == '0' || rest.front() == '1')) {
      const auto flag = in.u8();
      if (*flag == '1') {
        auto nonce = in.template fixed<24>();
        if (!nonce) return fail(nonce.error());
        out.nonce = *nonce;
      }
    }
    out.encrypted = in.rest();
    return out;
  }
  return std::unexpected(response_errors::unknown{word});
}

// ---- transmissions and blocks ------------------------------------------------------

// A transmission as it goes: its authorization (a signature, an
// authenticator, or none), its correlation id (none in a router's
// notifications), its entity, and its command or response bytes.
struct transmission {
  bytes authorization;
  std::optional<corr_id> correlation;
  entity_id entity;
  bytes body;
  friend constexpr bool operator==(const transmission&, const transmission&) = default;
};

// What is authorized -- signed or authenticated: the session's identifier
// (not sent, but part of what is signed), the correlation id, the entity,
// the command.
template <byte_sink Out>
constexpr void put_unsigned_part(Out& out, const std::optional<corr_id>& correlation, std::span<const byte> entity, std::span<const byte> body) {
  if (correlation) {
    put_byte(out, 24);
    put_bytes(out, *correlation);
  } else {
    put_byte(out, 0);
  }
  (void)put_short(out, entity);
  put_bytes(out, body);
}
template <byte_sink Out>
constexpr void put_authorized(Out& out, std::span<const byte> session_id, const std::optional<corr_id>& correlation,
                              std::span<const byte> entity, std::span<const byte> body) {
  (void)put_short(out, session_id);
  put_unsigned_part(out, correlation, entity, body);
}
// A transmission's bytes on the wire, for the version agreed: the session
// identifier left out whole -- not even its length -- as from v7; and from
// v16, after an authorization, no service signature ('0').
template <byte_sink Out>
constexpr void put_transmission(Out& out, const transmission& t, std::uint16_t version) {
  (void)put_short(out, t.authorization);
  if (version >= service_signature_version && !t.authorization.empty()) put_byte(out, '0');
  put_unsigned_part(out, t.correlation, t.entity, t.body);
}
// Transmissions in a padded block: their count, each with its length.
// Too many for one block: nothing written.
[[nodiscard]] constexpr std::expected<bytes, decode_error> block_of(std::span<const transmission> all, std::uint16_t version) {
  bytes content;
  if (all.empty() || all.size() > 255) return std::unexpected(errors::too_long{all.size()});
  put_byte(content, static_cast<byte>(all.size()));
  for (const auto& t : all) {
    bytes one;
    put_transmission(one, t, version);
    if (one.size() > 65535) return std::unexpected(errors::too_long{one.size()});
    put_u16(content, static_cast<std::uint16_t>(one.size()));
    put_bytes(content, one);
  }
  bytes block;
  if (auto padded = put_padded(block, content, block_size); !padded) return std::unexpected(padded.error());
  return block;
}
// A block's transmissions, read, for the version agreed.
[[nodiscard]] constexpr std::expected<std::vector<transmission>, decode_error> transmissions_of(std::span<const byte> block,
                                                                                              std::uint16_t version) {
  const auto content = unpadded(block);
  if (!content) return std::unexpected(content.error());
  auto in = reader_of(*content);
  const auto count = in.u8();
  if (!count) return std::unexpected(count.error());
  std::vector<transmission> out;
  for (byte i = 0; i < *count; ++i) {
    const auto length = in.u16();
    if (!length) return std::unexpected(length.error());
    auto one = in.take(*length);
    if (!one) return std::unexpected(one.error());
    auto t = reader_of(*one);
    transmission got;
    auto auth = t.short_string();
    if (!auth) return std::unexpected(auth.error());
    got.authorization = std::move(*auth);
    if (version >= service_signature_version && !got.authorization.empty()) {
      const auto flag = t.u8();
      if (!flag) return std::unexpected(flag.error());
      if (*flag == '1') {
        if (auto sig = t.short_string(); !sig) return std::unexpected(sig.error());
      } else if (*flag != '0') {
        return std::unexpected(errors::bad_flag{});
      }
    }
    const auto corr_length = t.u8();
    if (!corr_length) return std::unexpected(corr_length.error());
    if (*corr_length == 24) {
      auto c = t.template fixed<24>();
      if (!c) return std::unexpected(c.error());
      got.correlation = *c;
    } else if (*corr_length != 0) {
      return std::unexpected(errors::bad_padding{});
    }
    auto entity = t.short_string();
    if (!entity) return std::unexpected(entity.error());
    got.entity = std::move(*entity);
    got.body = t.rest();
    out.push_back(std::move(got));
  }
  return out;
}

// ---- the handshake ------------------------------------------------------------------

// What the router says first: its versions, the session's identifier, and
// -- from a router that has them -- its certificate chain and the X25519
// key it signed for this session (what authenticators are keyed by).
struct router_hello {
  version_range versions;
  bytes session_id;
  std::vector<bytes> certificates;  // DER, the CA's first
  bytes signed_key;                 // DER: the key and the online certificate's signature over it
};
[[nodiscard]] constexpr std::expected<router_hello, decode_error> router_hello_of(std::span<const byte> block) {
  const auto content = unpadded(block);
  if (!content) return std::unexpected(content.error());
  auto in = reader_of(*content);
  const auto low = in.u16(), high = in.u16();
  if (!low || !high) return std::unexpected(errors::short_input{});
  auto session = in.short_string();
  if (!session) return std::unexpected(session.error());
  router_hello out{{*low, *high}, std::move(*session), {}, {}};
  if (in.done()) return out;
  const auto count = in.u8();
  if (!count) return std::unexpected(count.error());
  for (byte i = 0; i < *count; ++i) {
    auto cert = in.large_string();
    if (!cert) return std::unexpected(cert.error());
    out.certificates.push_back(std::move(*cert));
  }
  auto key = in.large_string();
  if (!key) return std::unexpected(key.error());
  out.signed_key = std::move(*key);
  return out;  // what follows is ignored, as later versions add it
}
// The client's answer: the version chosen (the highest both have), the
// router's identity as the client knows it, not a proxy, no service.
[[nodiscard]] constexpr std::expected<bytes, decode_error> client_hello(std::uint16_t version, std::span<const byte> key_hash) {
  bytes content;
  put_u16(content, version);
  if (auto ok = put_short(content, key_hash); !ok) return std::unexpected(ok.error());
  put_byte(content, 'F');  // not a proxy router
  put_byte(content, '0');  // no service credentials
  bytes block;
  if (auto ok = put_padded(block, content, block_size); !ok) return std::unexpected(ok.error());
  return block;
}
// The version both speak: the highest in both ranges; none where they do not meet.
[[nodiscard]] constexpr std::optional<std::uint16_t> agreed_version(version_range theirs, version_range ours = {min_version, max_version}) {
  const auto high = std::min(theirs.max, ours.max), low = std::max(theirs.min, ours.min);
  if (high < low) return std::nullopt;
  return high;
}

// ---- authorization ------------------------------------------------------------------

// Commands are signed and authenticated in a verified session alone:
// quay.session's signature_over and authenticator_over.

// ---- the layers a message goes through ------------------------------------------------

// What the router gives the recipient, its own layer taken off (a box keyed
// by the queue's DH -- the recipient's key and the router's from IDS -- its
// nonce the message id): when it was sent, whether to notify, and the
// sender's message; or that the queue was full from then.
namespace received {
struct sent {
  std::uint64_t timestamp = 0;  // seconds since 1970
  bool notify = true;
  bytes message;  // smpEncMessage
};
struct quota_exceeded {
  std::uint64_t timestamp = 0;
};
}  // namespace received
using received_t = spl::variant<received::sent, received::quota_exceeded>;
namespace layer_errors {
struct bad_id {};  // a message id that is not a nonce (24 bytes)
}
using layer_error = spl::variant<crypto::crypto_error, decode_error, layer_errors::bad_id>;

inline std::expected<received_t, layer_error> router_layer_off(const crypto::box_key& queue_key, const response::message& got) {
  if (got.id.size() != 24) return std::unexpected(layer_errors::bad_id{});
  crypto::box_nonce nonce{};
  std::ranges::copy(got.id, nonce.begin());
  const auto plain = crypto::secretbox_open(queue_key, nonce, got.encrypted);
  if (!plain) return std::unexpected(plain.error());
  const auto body = unpadded(*plain);
  if (!body) return std::unexpected(body.error());
  auto in = reader_of(*body);
  if (body->size() >= 5 && std::ranges::equal(body->first(5), std::string_view("QUOTA"))) {
    in.template fixed<6>();  // "QUOTA "
    const auto at = in.u64();
    if (!at) return std::unexpected(at.error());
    return received::quota_exceeded{*at};
  }
  const auto at = in.u64();
  if (!at) return std::unexpected(at.error());
  const auto flag = in.flag();
  if (!flag) return std::unexpected(flag.error());
  if (const auto space = in.u8(); !space || *space != ' ') return std::unexpected(decode_error(errors::short_input{}));
  return received::sent{*at, *flag, in.rest()};
}

// The sender's layer: a box keyed by the sender's (ephemeral) X25519 key and
// the recipient's from the queue URI. A message, or -- the first, a
// confirmation -- carrying the sender's key in the clear, and, inside, the
// key its SENDs are authorized by where it did not secure the queue itself.
namespace e2e {
struct message {
  bytes body;
};
struct confirmation {
  public_key<curve::x25519> sender_dh;
  std::optional<auth_key> sender_key;  // 'K': the recipient secures the queue with it
  bytes body;
};
}  // namespace e2e
using e2e_t = spl::variant<e2e::message, e2e::confirmation>;

template <crypto::random_source R>
std::expected<bytes, layer_error> e2e_message(const crypto::box_key& key, std::uint16_t client_version, std::span<const byte> body, R& random) {
  bytes padded;
  bytes inner{'_'};
  inner.insert(inner.end(), body.begin(), body.end());
  if (auto ok = put_padded(padded, inner, e2e_message_length); !ok) return std::unexpected(ok.error());
  crypto::box_nonce nonce{};
  random(std::span<byte>(nonce));
  bytes out;
  put_u16(out, client_version);
  put_byte(out, '0');
  put_bytes(out, nonce);
  put_bytes(out, crypto::secretbox(key, nonce, padded));
  return out;
}
template <crypto::random_source R>
std::expected<bytes, layer_error> e2e_confirmation(const crypto::box_key& key, std::uint16_t client_version,
                                                   const public_key<curve::x25519>& sender_dh, const std::optional<auth_key>& sender_key,
                                                   std::span<const byte> body, R& random) {
  bytes inner;
  if (sender_key) {
    put_byte(inner, 'K');
    detail::put_auth_key(inner, *sender_key);
  } else {
    put_byte(inner, '_');
  }
  inner.insert(inner.end(), body.begin(), body.end());
  bytes padded;
  if (auto ok = put_padded(padded, inner, e2e_confirmation_length); !ok) return std::unexpected(ok.error());
  crypto::box_nonce nonce{};
  random(std::span<byte>(nonce));
  bytes out;
  put_u16(out, client_version);
  put_byte(out, '1');
  detail::put_key(out, sender_dh);
  put_bytes(out, nonce);
  put_bytes(out, crypto::secretbox(key, nonce, padded));
  return out;
}
// A message's sender layer taken off. A confirmation's key is in the clear,
// before the box: what the recipient's key agrees with is asked of the
// caller (`key_for`), which keeps the recipient's private key.
template <class KeyFor>
std::expected<std::pair<std::uint16_t, e2e_t>, layer_error> e2e_open(std::span<const byte> wire, KeyFor&& key_for) {
  auto in = reader_of(wire);
  const auto version = in.u16();
  if (!version) return std::unexpected(version.error());
  const auto kind = in.u8();
  if (!kind) return std::unexpected(kind.error());
  std::optional<public_key<curve::x25519>> sender_dh;
  if (*kind == '1') {
    auto k = detail::x25519_key(in);
    if (!k) return std::unexpected(k.error());
    sender_dh = *k;
  } else if (*kind != '0') {
    return std::unexpected(decode_error(errors::bad_flag{}));
  }
  const auto nonce = in.template fixed<24>();
  if (!nonce) return std::unexpected(nonce.error());
  const bytes sealed_body = in.rest();
  const std::expected<crypto::box_key, crypto::crypto_error> key = key_for(sender_dh);
  if (!key) return std::unexpected(key.error());
  const auto plain = crypto::secretbox_open(*key, *nonce, sealed_body);
  if (!plain) return std::unexpected(plain.error());
  const auto inner = unpadded(*plain);
  if (!inner) return std::unexpected(inner.error());
  auto body = reader_of(*inner);
  const auto header = body.u8();
  if (!header) return std::unexpected(header.error());
  if (!sender_dh) {
    if (*header != '_') return std::unexpected(decode_error(errors::bad_flag{}));
    return std::pair{*version, e2e_t(e2e::message{body.rest()})};
  }
  e2e::confirmation out{*sender_dh, std::nullopt, {}};
  if (*header == 'K') {
    auto der = body.short_string();
    if (!der) return std::unexpected(der.error());
    if (auto ed = key_from_spki<curve::ed25519>(*der)) out.sender_key = auth_key(*ed);
    else if (auto x = key_from_spki<curve::x25519>(*der)) out.sender_key = auth_key(*x);
    else return std::unexpected(decode_error(errors::bad_key{}));
  } else if (*header != '_') {
    return std::unexpected(decode_error(errors::bad_flag{}));
  }
  out.body = body.rest();
  return std::pair{*version, e2e_t(std::move(out))};
}

// A new queue's sender id, where the recipient chooses it (short links): the
// first 24 bytes of SHA3-384 of the correlation id.
inline bytes sender_id_for(const corr_id& correlation) {
  const auto h = crypto::sha3_384(correlation);
  return bytes(h.begin(), h.begin() + 24);
}

}  // namespace quay::smp

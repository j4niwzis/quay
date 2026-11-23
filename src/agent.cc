// SPDX-License-Identifier: AGPL-3.0-only
// quay.agent -- what SimpleX agents say to each other (agent-protocol.md v7,
// as simplexmq 6.5.0's Agent/Protocol.hs writes it): the envelopes a
// queue's messages are (confirmation, message, invitation, ratchet key),
// the messages inside them once the ratchet is off (connection info, with
// reply queues or not; HELLO, A_MSG, A_RCVD, the queue rotation's QADD,
// QKEY, QUSE, QTEST, A_QCONT, EREADY), the queues' addresses as they carry
// them, and connection links -- invitations and contact addresses -- as
// text, both ways. Each a type; read once, where it comes in.
export module quay.agent;

import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.smp;
import quay.ratchet;

export namespace quay::agent {

// Agent protocol versions: v2 duplex handshake, v3 ratchet sync, v4
// receipts, v5 PQ, v6 sender auth key, v7 ratchet on confirmation.
inline constexpr std::uint16_t min_agent_version = 2, current_agent_version = 7;
inline constexpr std::uint16_t pqdr_agent_version = 5;
// SMP client versions (of a queue's sender): v2 hostnames, v3 sender auth
// key, v4 short links.
inline constexpr std::uint16_t current_client_version = 4, short_links_client_version = 4, snd_auth_key_client_version = 3;

// The padded length of what the ratchet encrypts: connection info, and
// agent messages -- smaller with PQ, the header and keys being larger.
constexpr std::size_t conn_info_length(bool pq) { return pq ? 11106 : 14832; }
constexpr std::size_t agent_message_length(bool pq) { return pq ? 13618 : 15840; }

// ---- queues ----------------------------------------------------------------------

namespace queue_mode {
struct messaging {  // the sender may secure it (SKEY)
  friend constexpr bool operator==(messaging, messaging) = default;
};
struct contact {
  friend constexpr bool operator==(contact, contact) = default;
};
}  // namespace queue_mode
using queue_mode_t = spl::variant<queue_mode::messaging, queue_mode::contact>;

struct queue_address {
  smp::router router;
  bytes sender_id;
  public_key<curve::x25519> dh;
  std::optional<queue_mode_t> mode;
  friend constexpr bool operator==(const queue_address&, const queue_address&) = default;
};
// A queue as a connection's messages carry it: the sender's client version,
// its address.
struct queue_info {
  std::uint16_t client_version = current_client_version;
  queue_address address;
  friend constexpr bool operator==(const queue_info&, const queue_info&) = default;
};
// As a link carries it: the range of client versions.
struct queue_uri {
  smp::version_range client_versions{1, current_client_version};
  queue_address address;
  friend constexpr bool operator==(const queue_uri&, const queue_uri&) = default;
};
// A queue a sender sends to: its router and sender id.
struct send_queue_address {
  smp::router router;
  bytes sender_id;
  friend constexpr bool operator==(const send_queue_address&, const send_queue_address&) = default;
};

namespace detail {
constexpr bool sender_can_secure(const std::optional<queue_mode_t>& mode) {
  return mode && mode->template get_if<queue_mode::messaging>() != nullptr;
}
template <class Out>
constexpr void put_router_binary(Out& out, const smp::router& where) {
  put_byte(out, static_cast<byte>(where.hosts.size()));
  for (const auto& host : where.hosts) (void)put_short(out, host);
  std::string port;
  if (where.port) {
    std::uint32_t n = *where.port;
    do port.insert(port.begin(), static_cast<char>('0' + n % 10)), n /= 10;
    while (n != 0);
  }
  (void)put_short(out, port);
  (void)put_short(out, where.identity);
}
template <class R>
constexpr std::expected<smp::router, decode_error> read_router(R& in) {
  const auto count = in.u8();
  if (!count) return std::unexpected(count.error());
  smp::router out;
  for (byte i = 0; i < *count; ++i) {
    auto host = in.short_string();
    if (!host) return std::unexpected(host.error());
    out.hosts.emplace_back(host->begin(), host->end());
  }
  auto port = in.short_string();
  if (!port) return std::unexpected(port.error());
  if (!port->empty()) {
    std::uint32_t n = 0;
    for (const byte c : *port) {
      if (c < '0' || c > '9') return std::unexpected(quay::errors::bad_flag{});
      n = n * 10 + (c - '0');
    }
    if (n > 65535) return std::unexpected(quay::errors::too_long{n});
    out.port = static_cast<std::uint16_t>(n);
  }
  auto key = in.short_string();
  if (!key) return std::unexpected(key.error());
  out.identity = std::move(*key);
  return out;
}
template <class Out>
constexpr void put_mode(Out& out, const queue_mode_t& mode) {
  put_byte(out, mode.template get_if<queue_mode::messaging>() ? 'M' : 'C');
}
// A queue's mode after its address: 'M' or 'C'; or an older sender's
// T/F (whether it may secure it); or nothing.
template <class R>
constexpr std::optional<queue_mode_t> read_mode(R& in) {
  if (in.done()) return std::nullopt;
  auto peek = in;  // a copy: read only where it is one
  const auto b = peek.u8();
  if (!b) return std::nullopt;
  std::optional<queue_mode_t> got;
  if (*b == 'M') got = queue_mode::messaging{};
  else if (*b == 'C') got = queue_mode::contact{};
  else if (*b == 'T') got = queue_mode::messaging{};
  else if (*b == 'F') got = queue_mode::contact{};
  if (got) in = peek;
  return got;
}
template <class Out>
constexpr void put_address(Out& out, const queue_address& a) {
  put_router_binary(out, a.router);
  (void)put_short(out, a.sender_id);
  (void)put_short(out, spki_of(a.dh));
}
template <class R>
constexpr std::expected<queue_address, decode_error> read_address(R& in) {
  auto where = read_router(in);
  if (!where) return std::unexpected(where.error());
  auto sender = in.short_string();
  if (!sender) return std::unexpected(sender.error());
  auto der = in.short_string();
  if (!der) return std::unexpected(der.error());
  auto dh = key_from_spki<curve::x25519>(*der);
  if (!dh) return std::unexpected(dh.error());
  return queue_address{std::move(*where), std::move(*sender), *dh, std::nullopt};
}
}  // namespace detail

template <byte_sink Out>
constexpr void put_queue_info(Out& out, const queue_info& q) {
  put_u16(out, q.client_version);
  detail::put_address(out, q.address);
  if (q.client_version >= short_links_client_version) {
    if (q.address.mode) detail::put_mode(out, *q.address.mode);
  } else if (q.client_version >= snd_auth_key_client_version && detail::sender_can_secure(q.address.mode)) {
    put_byte(out, 'T');
  }
}
template <class R>
constexpr std::expected<queue_info, decode_error> read_queue_info(R& in) {
  const auto v = in.u16();
  if (!v) return std::unexpected(v.error());
  auto a = detail::read_address(in);
  if (!a) return std::unexpected(a.error());
  a->mode = detail::read_mode(in);
  return queue_info{*v, std::move(*a)};
}
template <byte_sink Out>
constexpr void put_send_queue_address(Out& out, const send_queue_address& q) {
  detail::put_router_binary(out, q.router);
  (void)put_short(out, q.sender_id);
}
template <class R>
constexpr std::expected<send_queue_address, decode_error> read_send_queue_address(R& in) {
  auto where = detail::read_router(in);
  if (!where) return std::unexpected(where.error());
  auto sender = in.short_string();
  if (!sender) return std::unexpected(sender.error());
  return send_queue_address{std::move(*where), std::move(*sender)};
}

// ---- what agents say once the ratchet is off -------------------------------------------

struct receipt {
  std::uint64_t message_id = 0;
  bytes hash;
  bytes info;
  friend constexpr bool operator==(const receipt&, const receipt&) = default;
};
namespace a_message {
struct hello {};
struct msg {  // A_MSG: the client's message
  bytes body;
};
struct received {  // A_RCVD
  std::vector<receipt> receipts;
};
struct continue_sending {  // A_QCONT
  send_queue_address queue;
};
struct add_queues {  // QADD: new queues, each replacing one or not
  std::vector<std::pair<queue_uri, std::optional<send_queue_address>>> queues;
};
struct queue_keys {  // QKEY: the queues, the sender's key for each
  std::vector<std::pair<queue_info, smp::auth_key>> queues;
};
struct use_queues {  // QUSE: which are ready, and the primary
  std::vector<std::pair<send_queue_address, bool>> queues;
};
struct test_queues {  // QTEST
  std::vector<send_queue_address> queues;
};
struct ready {  // EREADY: the ratchet agreed again, the last message decrypted
  std::uint64_t last_decrypted = 0;
};
}  // namespace a_message
using a_message_t = spl::variant<a_message::hello, a_message::msg, a_message::received, a_message::continue_sending, a_message::add_queues,
                                 a_message::queue_keys, a_message::use_queues, a_message::test_queues, a_message::ready>;

struct message_header {
  std::uint64_t id = 0;     // the sender's sequential id
  bytes previous_hash;      // the SHA-256 of the previous message it sent
};
namespace agent_message {
struct conn_info {  // 'I': the inviting side's connection info
  bytes info;
};
struct conn_info_reply {  // 'D': the joining side's, with its reply queues
  std::vector<queue_info> queues;
  bytes info;
};
struct ratchet_info {  // 'R'
  bytes info;
};
struct message {  // 'M'
  message_header header;
  a_message_t body;
};
}  // namespace agent_message
using agent_message_t = spl::variant<agent_message::conn_info, agent_message::conn_info_reply, agent_message::ratchet_info, agent_message::message>;

namespace detail {
template <class Out>
void put_auth_key(Out& out, const smp::auth_key& key) {
  spl::visit([&](const auto& k) { (void)put_short(out, spki_of(k)); }, key);
}
template <class R>
std::expected<smp::auth_key, decode_error> read_auth_key(R& in) {
  auto der = in.short_string();
  if (!der) return std::unexpected(der.error());
  if (auto ed = key_from_spki<curve::ed25519>(*der)) return smp::auth_key(*ed);
  if (auto x = key_from_spki<curve::x25519>(*der)) return smp::auth_key(*x);
  return std::unexpected(quay::errors::bad_key{});
}
template <class Out>
void put_queue_uri_binary(Out& out, const queue_uri& q) {
  put_u16(out, q.client_versions.min);
  put_u16(out, q.client_versions.max);
  put_address(out, q.address);
  if (q.client_versions.min >= short_links_client_version) {
    if (q.address.mode) put_mode(out, *q.address.mode);
  } else if (q.client_versions.min >= snd_auth_key_client_version ||
             (q.client_versions.max >= snd_auth_key_client_version && sender_can_secure(q.address.mode))) {
    put_byte(out, sender_can_secure(q.address.mode) ? 'T' : 'F');
  }
}
template <class R>
std::expected<queue_uri, decode_error> read_queue_uri_binary(R& in) {
  const auto low = in.u16(), high = in.u16();
  if (!low || !high) return std::unexpected(quay::errors::short_input{});
  auto a = read_address(in);
  if (!a) return std::unexpected(a.error());
  a->mode = read_mode(in);
  return queue_uri{{*low, *high}, std::move(*a)};
}
}  // namespace detail

template <byte_sink Out>
void put_a_message(Out& out, const a_message_t& m) {
  using namespace detail;
  spl::visit(spl::overloaded{
                 [&](const a_message::hello&) { put_byte(out, 'H'); },
                 [&](const a_message::msg& x) {
                   put_byte(out, 'M');
                   put_bytes(out, x.body);
                 },
                 [&](const a_message::received& x) {
                   put_byte(out, 'V');
                   put_byte(out, static_cast<byte>(x.receipts.size()));
                   for (const auto& r : x.receipts) {
                     put_u64(out, r.message_id);
                     (void)put_short(out, r.hash);
                     (void)put_large(out, r.info);
                   }
                 },
                 [&](const a_message::continue_sending& x) {
                   put_byte(out, 'Q'), put_byte(out, 'C');
                   put_send_queue_address(out, x.queue);
                 },
                 [&](const a_message::add_queues& x) {
                   put_byte(out, 'Q'), put_byte(out, 'A');
                   put_byte(out, static_cast<byte>(x.queues.size()));
                   for (const auto& [uri, replaced] : x.queues) {
                     put_queue_uri_binary(out, uri);
                     if (!replaced) {
                       put_byte(out, '0');
                     } else {
                       put_byte(out, '1');
                       put_send_queue_address(out, *replaced);
                     }
                   }
                 },
                 [&](const a_message::queue_keys& x) {
                   put_byte(out, 'Q'), put_byte(out, 'K');
                   put_byte(out, static_cast<byte>(x.queues.size()));
                   for (const auto& [info, key] : x.queues) {
                     put_queue_info(out, info);
                     put_auth_key(out, key);
                   }
                 },
                 [&](const a_message::use_queues& x) {
                   put_byte(out, 'Q'), put_byte(out, 'U');
                   put_byte(out, static_cast<byte>(x.queues.size()));
                   for (const auto& [q, primary] : x.queues) {
                     put_send_queue_address(out, q);
                     put_flag(out, primary);
                   }
                 },
                 [&](const a_message::test_queues& x) {
                   put_byte(out, 'Q'), put_byte(out, 'T');
                   put_byte(out, static_cast<byte>(x.queues.size()));
                   for (const auto& q : x.queues) put_send_queue_address(out, q);
                 },
                 [&](const a_message::ready& x) {
                   put_byte(out, 'E');
                   put_u64(out, x.last_decrypted);
                 }},
             m);
}
template <class R>
std::expected<a_message_t, decode_error> read_a_message(R& in) {
  using namespace detail;
  const auto t = in.u8();
  if (!t) return std::unexpected(t.error());
  const auto count = [&]() -> std::expected<byte, decode_error> {
    const auto n = in.u8();
    if (!n) return std::unexpected(n.error());
    if (*n == 0) return std::unexpected(quay::errors::short_input{});  // a non-empty list
    return *n;
  };
  switch (*t) {
    case 'H': return a_message::hello{};
    case 'M': return a_message::msg{in.rest()};
    case 'V': {
      const auto n = count();
      if (!n) return std::unexpected(n.error());
      a_message::received out;
      for (byte i = 0; i < *n; ++i) {
        const auto id = in.u64();
        if (!id) return std::unexpected(id.error());
        auto hash = in.short_string();
        if (!hash) return std::unexpected(hash.error());
        auto info = in.large_string();
        if (!info) return std::unexpected(info.error());
        out.receipts.push_back({*id, std::move(*hash), std::move(*info)});
      }
      return out;
    }
    case 'E': {
      const auto id = in.u64();
      if (!id) return std::unexpected(id.error());
      return a_message::ready{*id};
    }
    case 'Q': {
      const auto sub = in.u8();
      if (!sub) return std::unexpected(sub.error());
      if (*sub == 'C') {
        auto q = read_send_queue_address(in);
        if (!q) return std::unexpected(q.error());
        return a_message::continue_sending{std::move(*q)};
      }
      const auto n = count();
      if (!n) return std::unexpected(n.error());
      if (*sub == 'A') {
        a_message::add_queues out;
        for (byte i = 0; i < *n; ++i) {
          auto uri = read_queue_uri_binary(in);
          if (!uri) return std::unexpected(uri.error());
          const auto flag = in.u8();
          if (!flag) return std::unexpected(flag.error());
          std::optional<send_queue_address> replaced;
          if (*flag == '1') {
            auto q = read_send_queue_address(in);
            if (!q) return std::unexpected(q.error());
            replaced = std::move(*q);
          }
          out.queues.emplace_back(std::move(*uri), std::move(replaced));
        }
        return out;
      }
      if (*sub == 'K') {
        a_message::queue_keys out;
        for (byte i = 0; i < *n; ++i) {
          auto info = read_queue_info(in);
          if (!info) return std::unexpected(info.error());
          auto key = read_auth_key(in);
          if (!key) return std::unexpected(key.error());
          out.queues.emplace_back(std::move(*info), *key);
        }
        return out;
      }
      if (*sub == 'U') {
        a_message::use_queues out;
        for (byte i = 0; i < *n; ++i) {
          auto q = read_send_queue_address(in);
          if (!q) return std::unexpected(q.error());
          const auto primary = in.flag();
          if (!primary) return std::unexpected(primary.error());
          out.queues.emplace_back(std::move(*q), *primary);
        }
        return out;
      }
      if (*sub == 'T') {
        a_message::test_queues out;
        for (byte i = 0; i < *n; ++i) {
          auto q = read_send_queue_address(in);
          if (!q) return std::unexpected(q.error());
          out.queues.push_back(std::move(*q));
        }
        return out;
      }
      return std::unexpected(quay::errors::bad_flag{});
    }
    default: return std::unexpected(quay::errors::bad_flag{});
  }
}

template <byte_sink Out>
void put_agent_message(Out& out, const agent_message_t& m) {
  spl::visit(spl::overloaded{[&](const agent_message::conn_info& x) {
                               put_byte(out, 'I');
                               put_bytes(out, x.info);
                             },
                             [&](const agent_message::conn_info_reply& x) {
                               put_byte(out, 'D');
                               put_byte(out, static_cast<byte>(x.queues.size()));
                               for (const auto& q : x.queues) put_queue_info(out, q);
                               put_bytes(out, x.info);
                             },
                             [&](const agent_message::ratchet_info& x) {
                               put_byte(out, 'R');
                               put_bytes(out, x.info);
                             },
                             [&](const agent_message::message& x) {
                               put_byte(out, 'M');
                               put_u64(out, x.header.id);
                               (void)put_short(out, x.header.previous_hash);
                               put_a_message(out, x.body);
                             }},
             m);
}
inline std::expected<agent_message_t, decode_error> agent_message_of(std::span<const byte> wire) {
  auto in = reader_of(wire);
  const auto t = in.u8();
  if (!t) return std::unexpected(t.error());
  switch (*t) {
    case 'I': return agent_message::conn_info{in.rest()};
    case 'R': return agent_message::ratchet_info{in.rest()};
    case 'D': {
      const auto n = in.u8();
      if (!n) return std::unexpected(n.error());
      if (*n == 0) return std::unexpected(quay::errors::short_input{});
      agent_message::conn_info_reply out;
      for (byte i = 0; i < *n; ++i) {
        auto q = read_queue_info(in);
        if (!q) return std::unexpected(q.error());
        out.queues.push_back(std::move(*q));
      }
      out.info = in.rest();
      return out;
    }
    case 'M': {
      const auto id = in.u64();
      if (!id) return std::unexpected(id.error());
      auto hash = in.short_string();
      if (!hash) return std::unexpected(hash.error());
      auto body = read_a_message(in);
      if (!body) return std::unexpected(body.error());
      return agent_message::message{{*id, std::move(*hash)}, std::move(*body)};
    }
    default: return std::unexpected(quay::errors::bad_flag{});
  }
}

// ---- envelopes -----------------------------------------------------------------------

namespace envelope {
struct confirmation {  // 'C': the joining side's parameters (where it sends them), and its info, ratchet-encrypted
  std::uint16_t version = current_agent_version;
  std::optional<ratchet::e2e_params> e2e;
  bytes encrypted;
};
struct message {  // 'M': an agent message, ratchet-encrypted
  std::uint16_t version = current_agent_version;
  bytes encrypted;
};
struct invitation {  // 'I': to a contact address -- a connection link and info, not ratchet-encrypted
  std::uint16_t version = current_agent_version;
  std::string connection_link;
  bytes info;
};
struct ratchet_key {  // 'R': parameters to agree the ratchet again
  std::uint16_t version = current_agent_version;
  ratchet::e2e_params e2e;
  bytes info;
};
}  // namespace envelope
using envelope_t = spl::variant<envelope::confirmation, envelope::message, envelope::invitation, envelope::ratchet_key>;

template <byte_sink Out>
void put_envelope(Out& out, const envelope_t& e) {
  spl::visit(spl::overloaded{[&](const envelope::confirmation& c) {
                               put_u16(out, c.version);
                               put_byte(out, 'C');
                               if (!c.e2e) {
                                 put_byte(out, '0');
                               } else {
                                 put_byte(out, '1');
                                 ratchet::put_e2e_params(out, *c.e2e);
                               }
                               put_bytes(out, c.encrypted);
                             },
                             [&](const envelope::message& m) {
                               put_u16(out, m.version);
                               put_byte(out, 'M');
                               put_bytes(out, m.encrypted);
                             },
                             [&](const envelope::invitation& i) {
                               put_u16(out, i.version);
                               put_byte(out, 'I');
                               (void)put_large(out, i.connection_link);
                               put_bytes(out, i.info);
                             },
                             [&](const envelope::ratchet_key& r) {
                               put_u16(out, r.version);
                               put_byte(out, 'R');
                               ratchet::put_e2e_params(out, r.e2e);
                               put_bytes(out, r.info);
                             }},
             e);
}
inline std::expected<envelope_t, decode_error> envelope_of(std::span<const byte> wire) {
  auto in = reader_of(wire);
  const auto v = in.u16();
  if (!v) return std::unexpected(v.error());
  const auto t = in.u8();
  if (!t) return std::unexpected(t.error());
  switch (*t) {
    case 'C': {
      envelope::confirmation out{*v, std::nullopt, {}};
      const auto flag = in.u8();
      if (!flag) return std::unexpected(flag.error());
      if (*flag == '1') {
        auto p = ratchet::read_e2e_params(in);
        if (!p) return std::unexpected(p.error());
        out.e2e = std::move(*p);
      } else if (*flag != '0') {
        return std::unexpected(quay::errors::bad_flag{});
      }
      out.encrypted = in.rest();
      return out;
    }
    case 'M': return envelope::message{*v, in.rest()};
    case 'I': {
      auto link = in.large_string();
      if (!link) return std::unexpected(link.error());
      return envelope::invitation{*v, std::string(link->begin(), link->end()), in.rest()};
    }
    case 'R': {
      auto p = ratchet::read_e2e_params(in);
      if (!p) return std::unexpected(p.error());
      return envelope::ratchet_key{*v, std::move(*p), in.rest()};
    }
    default: return std::unexpected(quay::errors::bad_flag{});
  }
}

// ---- connection links, as text ---------------------------------------------------------

// What a link's query values are escaped with (http-types' renderSimpleQuery):
// all but A-Z a-z 0-9 - _ . ~ as %XX.
namespace text {
inline std::string escaped(std::string_view s) {
  std::string out;
  constexpr std::string_view hex = "0123456789ABCDEF";
  for (const char c : s) {
    const auto u = static_cast<unsigned char>(c);
    if ((u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') || (u >= '0' && u <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
      out += c;
    } else {
      out += '%', out += hex[u >> 4], out += hex[u & 15];
    }
  }
  return out;
}
inline std::optional<std::string> unescaped(std::string_view s) {
  std::string out;
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '+') {
      out += ' ';
    } else if (s[i] == '%') {
      if (i + 2 >= s.size()) return std::nullopt;
      const auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
      };
      const int hi = v(s[i + 1]), lo = v(s[i + 2]);
      if (hi < 0 || lo < 0) return std::nullopt;
      out += static_cast<char>(hi * 16 + lo);
      i += 2;
    } else {
      out += s[i];
    }
  }
  return out;
}
// A query string's parameters, unescaped, in their order.
inline std::optional<std::vector<std::pair<std::string, std::string>>> parameters(std::string_view query) {
  std::vector<std::pair<std::string, std::string>> out;
  for (auto part : query | std::views::split('&')) {
    const std::string_view one(part.begin(), part.end());
    if (one.empty()) continue;
    const auto eq = one.find('=');
    auto name = unescaped(one.substr(0, eq));
    auto value = unescaped(eq == std::string_view::npos ? std::string_view() : one.substr(eq + 1));
    if (!name || !value) return std::nullopt;
    out.emplace_back(std::move(*name), std::move(*value));
  }
  return out;
}
inline const std::string* parameter(const std::vector<std::pair<std::string, std::string>>& all, std::string_view name) {
  const auto found = std::ranges::find(all, name, &std::pair<std::string, std::string>::first);
  return found == all.end() ? nullptr : &found->second;
}
inline std::string b64(std::span<const byte> data) {
  std::string out;
  put_base64url(out, data);
  return out;
}
inline std::string range(smp::version_range r) {
  return r.min == r.max ? std::to_string(r.min) : std::to_string(r.min) + "-" + std::to_string(r.max);
}
inline std::optional<smp::version_range> range_of(std::string_view s) {
  const auto dash = s.find('-');
  const auto number = [](std::string_view n) -> std::optional<std::uint16_t> {
    unsigned v = 0;
    const auto [end, ec] = std::from_chars(n.data(), n.data() + n.size(), v);
    if (ec != std::errc{} || end != n.data() + n.size() || v > 65535) return std::nullopt;
    return static_cast<std::uint16_t>(v);
  };
  const auto low = number(s.substr(0, dash));
  const auto high = dash == std::string_view::npos ? low : number(s.substr(dash + 1));
  if (!low || !high || *low > *high) return std::nullopt;
  return smp::version_range{*low, *high};
}
}  // namespace text

// A queue as a link carries it: smp://identity@hosts[:port]/senderId#/?v=1-4&dh=...[&q=m]
inline std::string text_of(const queue_uri& q) {
  std::string out = "smp://";
  out += text::b64(q.address.router.identity);
  out += '@';
  bool first = true;
  for (const auto& h : q.address.router.hosts) {
    if (!first) out += ',';
    first = false;
    out += h;
  }
  if (q.address.router.port) out += ':' + std::to_string(*q.address.router.port);
  out += '/' + text::b64(q.address.sender_id) + "#/?";
  out += "v=" + text::escaped(text::range(q.client_versions));
  out += "&dh=" + text::escaped(text::b64(spki_of(q.address.dh)));
  if (q.address.mode) out += q.address.mode->template get_if<queue_mode::messaging>() ? "&q=m" : "&q=c";
  if (detail::sender_can_secure(q.address.mode) && q.client_versions.min < short_links_client_version) out += "&k=s";
  return out;
}
inline std::optional<queue_uri> queue_uri_of(std::string_view s) {
  if (!s.starts_with("smp://")) return std::nullopt;
  s.remove_prefix(6);
  const auto slash = s.find('/');
  if (slash == std::string_view::npos) return std::nullopt;
  auto where = smp::router_of(s.substr(0, slash));
  if (!where) return std::nullopt;
  s.remove_prefix(slash + 1);
  const auto hash = s.find('#');
  auto id = base64url_decode(s.substr(0, hash));
  if (!id || hash == std::string_view::npos) return std::nullopt;
  std::string_view query = s.substr(hash + 1);
  if (query.starts_with('/')) query.remove_prefix(1);
  if (query.starts_with('?')) query.remove_prefix(1);
  const auto params = text::parameters(query);
  if (!params) return std::nullopt;
  const auto* v = text::parameter(*params, "v");
  const auto* dh = text::parameter(*params, "dh");
  if (!v || !dh) return std::nullopt;
  const auto versions = text::range_of(*v);
  const auto der = base64url_decode(*dh);
  if (!versions || !der) return std::nullopt;
  const auto key = key_from_spki<curve::x25519>(*der);
  if (!key) return std::nullopt;
  queue_uri out{*versions, {std::move(*where), std::move(*id), *key, std::nullopt}};
  // More hosts, as older links give them.
  if (const auto* srv = text::parameter(*params, "srv"))
    for (auto h : *srv | std::views::split(',')) out.address.router.hosts.emplace_back(h.begin(), h.end());
  const auto* q = text::parameter(*params, "q");
  const auto* k = text::parameter(*params, "k");
  if (q && *q == "m") out.address.mode = queue_mode::messaging{};
  else if (q && *q == "c") out.address.mode = queue_mode::contact{};
  else if (k && *k == "s") out.address.mode = queue_mode::messaging{};
  return out;
}

// The inviting side's ratchet parameters as a link carries them -- a range of
// versions, not one -- written unescaped: v=2-3&x3dh=k1,k2[&kem_key=...].
struct e2e_params_uri {
  smp::version_range versions{ratchet::kdf_x3dh_version, ratchet::current_version};
  ratchet::x448_public key1, key2;
  std::optional<crypto::sntrup761::public_key> kem_key;
};
inline std::string text_of(const e2e_params_uri& e) {
  std::string out = "v=" + text::range(e.versions) + "&x3dh=" + text::b64(spki_of(e.key1)) + "," + text::b64(spki_of(e.key2));
  if (e.kem_key && e.versions.max >= ratchet::pq_version) out += "&kem_key=" + text::b64(e.kem_key->raw);
  return out;
}
inline std::optional<e2e_params_uri> e2e_params_uri_of(std::string_view s) {
  const auto params = text::parameters(s);
  if (!params) return std::nullopt;
  const auto* v = text::parameter(*params, "v");
  const auto* keys = text::parameter(*params, "x3dh");
  if (!v || !keys) return std::nullopt;
  const auto versions = text::range_of(*v);
  const auto comma = keys->find(',');
  if (!versions || comma == std::string::npos) return std::nullopt;
  const auto d1 = base64url_decode(std::string_view(*keys).substr(0, comma));
  const auto d2 = base64url_decode(std::string_view(*keys).substr(comma + 1));
  if (!d1 || !d2) return std::nullopt;
  const auto k1 = key_from_spki<curve::x448>(*d1), k2 = key_from_spki<curve::x448>(*d2);
  if (!k1 || !k2) return std::nullopt;
  e2e_params_uri out{*versions, *k1, *k2, std::nullopt};
  if (const auto* kem = text::parameter(*params, "kem_key"); kem && versions->max >= ratchet::pq_version) {
    const auto raw = base64url_decode(*kem);
    if (!raw || raw->size() != crypto::sntrup761::public_size) return std::nullopt;
    crypto::sntrup761::public_key k;
    std::ranges::copy(*raw, k.raw.begin());
    out.kem_key = k;
  }
  return out;
}

// A connection link: a one-time invitation (with the inviting side's ratchet
// parameters) or a contact address (without: they come in its invitations).
namespace link {
struct invitation {
  smp::version_range agent_versions{min_agent_version, current_agent_version};
  std::vector<queue_uri> queues;
  e2e_params_uri e2e;
  std::optional<std::string> client_data;
};
struct contact {
  smp::version_range agent_versions{min_agent_version, current_agent_version};
  std::vector<queue_uri> queues;
  std::optional<std::string> client_data;
};
}  // namespace link
using link_t = spl::variant<link::invitation, link::contact>;

// simplex:/invitation#/?v=2-7&smp=...&e2e=... -- the values escaped, the
// queues separated by ';' before.
inline std::string text_of(const link_t& l) {
  return spl::visit(spl::overloaded{[](const link::invitation& i) {
                                      std::string queues;
                                      for (const auto& q : i.queues) queues += (queues.empty() ? "" : ";") + text_of(q);
                                      std::string out = "simplex:/invitation#/?v=" + text::escaped(text::range(i.agent_versions)) +
                                                        "&smp=" + text::escaped(queues) + "&e2e=" + text::escaped(text_of(i.e2e));
                                      if (i.client_data) out += "&data=" + text::escaped(*i.client_data);
                                      return out;
                                    },
                                    [](const link::contact& c) {
                                      std::string queues;
                                      for (const auto& q : c.queues) queues += (queues.empty() ? "" : ";") + text_of(q);
                                      std::string out = "simplex:/contact#/?v=" + text::escaped(text::range(c.agent_versions)) +
                                                        "&smp=" + text::escaped(queues);
                                      if (c.client_data) out += "&data=" + text::escaped(*c.client_data);
                                      return out;
                                    }},
                    l);
}
// simplex:/... or https://host/... (a client app server's page): the same.
inline std::optional<link_t> link_of(std::string_view s) {
  if (s.starts_with("simplex:")) {
    s.remove_prefix(8);
  } else if (s.starts_with("https://")) {
    s.remove_prefix(8);
    s.remove_prefix(std::min(s.find('/'), s.size()));
  } else {
    return std::nullopt;
  }
  if (s.starts_with('/')) s.remove_prefix(1);
  const auto hash = s.find('#');
  if (hash == std::string_view::npos) return std::nullopt;
  std::string_view mode = s.substr(0, hash);
  if (mode.ends_with('/')) mode.remove_suffix(1);
  std::string_view query = s.substr(hash + 1);
  if (query.starts_with('/')) query.remove_prefix(1);
  if (query.starts_with('?')) query.remove_prefix(1);
  const auto params = text::parameters(query);
  if (!params) return std::nullopt;
  const auto* v = text::parameter(*params, "v");
  const auto* smp_queues = text::parameter(*params, "smp");
  if (!v || !smp_queues) return std::nullopt;
  const auto versions = text::range_of(*v);
  if (!versions) return std::nullopt;
  std::vector<queue_uri> queues;
  for (auto part : *smp_queues | std::views::split(';')) {
    const auto q = queue_uri_of(std::string_view(part.begin(), part.end()));
    if (!q) return std::nullopt;
    queues.push_back(*q);
  }
  if (queues.empty()) return std::nullopt;
  std::optional<std::string> data;
  if (const auto* d = text::parameter(*params, "data")) data = *d;
  if (mode == "invitation") {
    const auto* e2e = text::parameter(*params, "e2e");
    if (!e2e) return std::nullopt;
    const auto params_uri = e2e_params_uri_of(*e2e);
    if (!params_uri) return std::nullopt;
    return link::invitation{*versions, std::move(queues), *params_uri, std::move(data)};
  }
  if (mode == "contact") return link::contact{*versions, std::move(queues), std::move(data)};
  return std::nullopt;
}

// The hash a message carries of the one before it (A_MSG's integrity, and
// receipts): SHA-256 of the agent message as sent.
inline bytes message_hash(std::span<const byte> agent_message) {
  const auto h = crypto::sha256(agent_message);
  return bytes(h.begin(), h.end());
}

}  // namespace quay::agent

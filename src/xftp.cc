// SPDX-License-Identifier: AGPL-3.0-only
// quay.xftp -- SimpleX's file transfer protocol, sans-IO: one session with
// one XFTP router, over HTTP/2 (quay.http2) inside TLS (quay.tls, ALPN
// xftp/1). The socket's bytes in and out; between them the handshake --
// the router's hello (its chain, its signed session key, this TLS
// session's id: authenticated by quay.session, its identity pinned), our
// hello -- and then commands, each a POST of one padded block, a file
// chunk after it where the command uploads one, answered by a block and,
// for FGET, the chunk sealed to a key agreed for it.
export module quay.xftp;

import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.smp;
import quay.session;
import quay.tls;
import quay.http2;

export namespace quay::xftp {

inline constexpr std::size_t block_size = 16384;
inline constexpr smp::version_range versions{1, 3};
// The sizes a router takes a chunk in.
inline constexpr std::array<std::uint32_t, 4> chunk_sizes{64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024};

using auth_key = public_key<curve::ed25519>;
struct file_info {
  auth_key sender_key;
  std::uint32_t size = 0;
  bytes digest;  // SHA-256 of the chunk as uploaded
};

namespace command {
struct create {  // FNEW: a chunk to upload, the keys its recipients will sign with
  file_info file;
  std::vector<auth_key> recipients;
};
struct add_recipients {  // FADD
  std::vector<auth_key> recipients;
};
struct put {};  // FPUT: the chunk follows the block
struct remove {};  // FDEL
struct get {  // FGET: the key the chunk is to be sealed to
  public_key<curve::x25519> dh;
};
struct acknowledge {};  // FACK
struct ping {};  // PING
}  // namespace command
using command_t = spl::variant<command::create, command::add_recipients, command::put, command::remove, command::get, command::acknowledge, command::ping>;

namespace response {
struct sender_ids {  // SIDS
  bytes sender_id;
  std::vector<bytes> recipient_ids;
};
struct recipient_ids {  // RIDS
  std::vector<bytes> ids;
};
struct file {  // FILE: the router's key and the nonce the chunk that follows is sealed with
  public_key<curve::x25519> dh;
  crypto::box_nonce nonce{};
};
struct ok {};
struct error {  // ERR, as the router names it
  std::string what;
};
struct pong {};
}  // namespace response
using response_t = spl::variant<response::sender_ids, response::recipient_ids, response::file, response::ok, response::error, response::pong>;

namespace detail {
template <byte_sink Out>
void put_word(Out& out, std::string_view w) {
  for (const char c : w) put_byte(out, static_cast<byte>(c));
}
template <byte_sink Out, class Curve>
void put_key(Out& out, const public_key<Curve>& key) {
  bytes der;
  put_spki(der, key);
  (void)put_short(out, der);
}
template <byte_sink Out>
void put_keys(Out& out, const std::vector<auth_key>& keys) {
  put_byte(out, static_cast<byte>(keys.size()));
  for (const auto& k : keys) put_key(out, k);
}
}  // namespace detail

template <byte_sink Out>
void put_command(Out& out, const command_t& c) {
  spl::visit(spl::overloaded{[&](const command::create& x) {
                               detail::put_word(out, "FNEW ");
                               detail::put_key(out, x.file.sender_key);
                               put_u32(out, x.file.size);
                               (void)put_short(out, x.file.digest);
                               detail::put_keys(out, x.recipients);
                               put_byte(out, '0');  // no basic auth
                             },
                             [&](const command::add_recipients& x) {
                               detail::put_word(out, "FADD ");
                               detail::put_keys(out, x.recipients);
                             },
                             [&](const command::put&) { detail::put_word(out, "FPUT"); },
                             [&](const command::remove&) { detail::put_word(out, "FDEL"); },
                             [&](const command::get& x) {
                               detail::put_word(out, "FGET ");
                               detail::put_key(out, x.dh);
                             },
                             [&](const command::acknowledge&) { detail::put_word(out, "FACK"); },
                             [&](const command::ping&) { detail::put_word(out, "PING"); }},
             c);
}

// A response's text read into its type: the tag read once into its kind, by a table.
namespace tag {
struct sids {};
struct rids {};
struct file {};
struct ok {};
struct err {};
struct pong {};
}  // namespace tag
using tag_t = spl::variant<tag::sids, tag::rids, tag::file, tag::ok, tag::err, tag::pong>;
inline std::optional<response_t> response_of(std::span<const byte> body) {
  static const std::array<std::pair<std::string_view, tag_t>, 6> tags{{{"SIDS", tag::sids{}}, {"RIDS", tag::rids{}}, {"FILE", tag::file{}},
                                                                       {"OK", tag::ok{}}, {"ERR", tag::err{}}, {"PONG", tag::pong{}}}};
  const auto space = std::ranges::find(body, static_cast<byte>(' '));
  const std::string word(body.begin(), space);
  const auto found = std::ranges::find(tags, std::string_view(word), &std::pair<std::string_view, tag_t>::first);
  if (found == tags.end()) return std::nullopt;
  const auto rest = space == body.end() ? std::span<const byte>() : std::span<const byte>(space + 1, body.end());
  auto in = reader_of(rest);
  const auto ids = [&]() -> std::optional<std::vector<bytes>> {
    const auto n = in.u8();
    if (!n) return std::nullopt;
    std::vector<bytes> out;
    for (byte i = 0; i < *n; ++i) {
      auto id = in.short_string();
      if (!id) return std::nullopt;
      out.push_back(std::move(*id));
    }
    return out;
  };
  return spl::visit(spl::overloaded{[&](tag::sids) -> std::optional<response_t> {
                                      auto sender = in.short_string();
                                      auto recipients = ids();
                                      if (!sender || !recipients) return std::nullopt;
                                      return response::sender_ids{std::move(*sender), std::move(*recipients)};
                                    },
                                    [&](tag::rids) -> std::optional<response_t> {
                                      auto recipients = ids();
                                      if (!recipients) return std::nullopt;
                                      return response::recipient_ids{std::move(*recipients)};
                                    },
                                    [&](tag::file) -> std::optional<response_t> {
                                      const auto der = in.short_string();
                                      const auto nonce = in.template fixed<24>();
                                      if (!der || !nonce) return std::nullopt;
                                      const auto key = key_from_spki<curve::x25519>(*der);
                                      if (!key) return std::nullopt;
                                      return response::file{*key, *nonce};
                                    },
                                    [&](tag::ok) -> std::optional<response_t> { return response::ok{}; },
                                    [&](tag::err) -> std::optional<response_t> { return response::error{std::string(rest.begin(), rest.end())}; },
                                    [&](tag::pong) -> std::optional<response_t> { return response::pong{}; }},
                    found->second);
}

// A chunk FGET gave, opened: sealed to the key agreed with the router's
// (XSalsa20-Poly1305, its tag after it).
inline std::expected<bytes, crypto::crypto_error> open_chunk(const response::file& file, const crypto::private_key<curve::x25519>& ours,
                                                             std::span<const byte> sealed) {
  if (sealed.size() < 16) return std::unexpected(crypto::errors::too_short{});
  const auto key = crypto::box_key_of(file.dh, ours);
  if (!key) return std::unexpected(key.error());
  bytes easy(sealed.end() - 16, sealed.end());  // NaCl's form: the tag first
  easy.insert(easy.end(), sealed.begin(), sealed.end() - 16);
  return crypto::secretbox_open(*key, file.nonce, easy);
}

namespace incoming {
struct ready {};  // the router authenticated, the hellos done
struct answered {  // a command's answer, and the chunk after it (FGET)
  std::uint64_t id = 0;
  response_t response;
  bytes chunk;
};
struct failed {
  std::string what;
};
}  // namespace incoming
using incoming_t = spl::variant<incoming::ready, incoming::answered, incoming::failed>;

// A router as an address gives it: its identity (the CA certificate's
// fingerprint), its host and port.
struct router {
  bytes identity;
  std::string host;
  std::uint16_t port = 443;
};

class router_session {
 public:
  explicit router_session(router r)
      : router_(std::move(r)), tls_(router_.host, router_.port, {"xftp/1"}), http_(router_.host + ":" + std::to_string(router_.port)) {
    flush_tls();
  }

  // A command for `entity`, signed by `key` (none for PING), with `chunk`
  // after it (FPUT); its answer comes with the id it returns. Held until ready.
  std::uint64_t submit(const command_t& c, bytes entity, std::optional<crypto::private_key<curve::ed25519>> key, bytes chunk = {}) {
    const auto id = ++submitted_;
    queued_.push_back({id, c, std::move(entity), std::move(key), std::move(chunk)});
    if (verified_ && hello_done_) send_queued();
    return id;
  }

  void received(std::span<const byte> data) {
    if (failed_) return;
    if (auto fed = tls_.received(data); !fed) return fail(fed.error());
    flush_tls();
    if (tls_.ready() && !hello_asked_) {
      hello_asked_ = true;
      hello_stream_ = http_.post("/", {});
      flush_http();
    }
    const auto plain = tls_.take_incoming();
    if (!plain.empty()) {
      http_.received(plain);
      flush_http();
    }
    for (auto& e : http_.take_events())
      spl::visit(spl::overloaded{[&](http2::event::response& r) { response(r); },
                                 [&](const http2::event::reset& r) { fail("the router reset stream " + std::to_string(r.stream)); },
                                 [&](const http2::event::failed& f) { fail(f.what); }},
                 e);
  }
  [[nodiscard]] bytes take_outgoing() { return std::exchange(outgoing_, {}); }
  [[nodiscard]] std::vector<incoming_t> take_incoming() { return std::exchange(incoming_, {}); }

 private:
  struct queued {
    std::uint64_t id;
    command_t command;
    bytes entity;
    std::optional<crypto::private_key<curve::ed25519>> key;
    bytes chunk;
  };
  void fail(std::string what) {
    failed_ = true;
    incoming_.push_back(incoming::failed{std::move(what)});
  }
  void flush_tls() {
    const auto out = tls_.take_outgoing();
    outgoing_.insert(outgoing_.end(), out.begin(), out.end());
  }
  void flush_http() {
    const auto out = http_.take_outgoing();
    if (!out.empty()) {
      if (auto sent = tls_.send(out); !sent) return fail(sent.error());
      flush_tls();
    }
  }
  void response(http2::event::response& r) {
    if (r.stream == hello_stream_) return router_hello(r.body);
    if (r.stream == client_hello_stream_) {
      if (!r.body.empty()) return fail("the router answered our hello");
      hello_done_ = true;
      incoming_.push_back(incoming::ready{});
      return send_queued();
    }
    const auto found = streams_.find(r.stream);
    if (found == streams_.end()) return;
    const auto id = found->second;
    streams_.erase(found);
    if (r.body.size() < block_size) return fail("an answer shorter than a block");
    const auto block = std::span<const byte>(r.body).first(block_size);
    const auto content = unpadded(block);
    if (!content) return fail("an answer block that does not unpad");
    // One transmission, batched: its count, then it as a large string.
    auto in = reader_of(*content);
    const auto count = in.u8();
    auto t = in.large_string();
    if (!count || *count != 1 || !t) return fail("an answer that is not one transmission");
    auto tr = reader_of(*t);
    const auto auth = tr.short_string(), session_id = tr.short_string(), corr = tr.short_string(), entity = tr.short_string();
    if (!auth || !session_id || !corr || !entity) return fail("an answer transmission that does not read");
    if (!std::ranges::equal(*session_id, verified_->id())) return fail("an answer for another session");
    const auto parsed = response_of(tr.rest());
    if (!parsed) return fail("an answer that does not read");
    incoming_.push_back(incoming::answered{id, *parsed, bytes(r.body.begin() + block_size, r.body.end())});
  }
  void router_hello(const bytes& body) {
    const auto facts = tls_.facts();
    if (!facts) return fail("TLS gave no chain or Finished");
    const auto hello = smp::router_hello_of(body);
    if (!hello) return fail("not an XFTP router's hello");
    auto checked = quay::session::verify(*hello, router_.identity, *facts, versions);
    if (!checked) return fail("the router is not the one its address pins (or not this TLS session's)");
    verified_ = std::move(*checked);
    // Ours: the version chosen, the identity we pinned.
    bytes content;
    put_u16(content, verified_->version());
    (void)put_short(content, router_.identity);
    bytes block;
    if (auto ok = put_padded(block, content, block_size); !ok) return fail("our hello does not fit a block");
    client_hello_stream_ = http_.post("/", std::move(block));
    flush_http();
  }
  void send_queued() {
    for (auto& q : std::exchange(queued_, {})) {
      bytes cmd;
      put_command(cmd, q.command);
      // What is signed and sent: the session id, an empty correlation id, the entity, the command.
      bytes signed_part;
      (void)put_short(signed_part, verified_->id());
      (void)put_short(signed_part, bytes{});
      (void)put_short(signed_part, q.entity);
      put_bytes(signed_part, cmd);
      bytes auth;
      if (q.key) {
        const auto s = crypto::sign(*q.key, signed_part);
        auth.assign(s.raw.begin(), s.raw.end());
      }
      bytes t;
      (void)put_short(t, auth);
      put_bytes(t, signed_part);
      bytes batch{1};
      if (auto ok = put_large(batch, t); !ok) return fail("a command too large");
      bytes body;
      if (auto ok = put_padded(body, batch, block_size); !ok) return fail("a command too large for a block");
      put_bytes(body, q.chunk);
      streams_[http_.post("/", std::move(body))] = q.id;
    }
    flush_http();
  }

  router router_;
  tls::client tls_;
  http2::client http_;
  std::optional<quay::session::verified> verified_;
  std::uint32_t hello_stream_ = 0, client_hello_stream_ = 0;
  bool hello_asked_ = false, hello_done_ = false, failed_ = false;
  std::map<std::uint32_t, std::uint64_t> streams_;
  std::vector<queued> queued_;
  std::uint64_t submitted_ = 0;
  bytes outgoing_;
  std::vector<incoming_t> incoming_;
};

}  // namespace quay::xftp

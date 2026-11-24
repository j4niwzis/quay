// SPDX-License-Identifier: AGPL-3.0-only
// quay.http2 -- an HTTP/2 client (RFC 9113), sans-IO, as XFTP needs one:
// requests with a body, each on its own stream, and their responses -- the
// status and the whole body -- once each stream ends. Bytes in, bytes out:
// what it writes goes through the caller's TLS (quay.tls, ALPN xftp/1).
//
// It sends the connection preface and its settings, acknowledges the
// server's settings and pings, keeps to the server's frame size and flow
// control windows when sending bodies, and opens its own receiving windows
// wide (giving back what each DATA frame took). No server push (disabled),
// no priorities, no trailers but as ignored headers.
export module quay.http2;

import std;
import splice;
import quay.bytes;
import quay.hpack;

export namespace quay::http2 {

namespace event {
struct response {  // a stream ended: its status and body
  std::uint32_t stream = 0;
  int status = 0;
  bytes body;
};
struct reset {  // a stream the server reset (RST_STREAM)
  std::uint32_t stream = 0;
  std::uint32_t code = 0;
};
struct failed {  // the connection is no good: a frame that does not read, GOAWAY, a header block that does not decode
  std::string what;
};
}  // namespace event
using event_t = spl::variant<event::response, event::reset, event::failed>;

namespace detail {
enum class frame_type : byte { data = 0, headers = 1, priority = 2, rst_stream = 3, settings = 4, push_promise = 5, ping = 6, goaway = 7, window_update = 8, continuation = 9 };
inline constexpr byte end_stream = 0x1, ack = 0x1, end_headers = 0x4, padded = 0x8, priority_flag = 0x20;
inline constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
inline constexpr std::uint32_t our_window = 1u << 24;  // what we let the server send before we give it back
enum class setting : std::uint16_t { header_table_size = 1, enable_push = 2, max_concurrent_streams = 3, initial_window_size = 4, max_frame_size = 5, max_header_list_size = 6 };
}  // namespace detail

class client {
 public:
  // A connection to `authority` (host:port), its preface and settings written.
  explicit client(std::string authority) : authority_(std::move(authority)) {
    put_bytes(out_, detail::preface | std::views::transform([](char c) { return static_cast<byte>(c); }));
    bytes settings;
    put_setting(settings, detail::setting::enable_push, 0);
    put_setting(settings, detail::setting::initial_window_size, detail::our_window);
    frame(detail::frame_type::settings, 0, 0, settings);
    // And the connection's own window, opened as wide.
    window_update(0, detail::our_window - 65535);
  }

  // A POST of `body` to `path`: its stream's id. The body goes out as the
  // server's windows let it (take_outgoing() after received(), too).
  std::uint32_t post(std::string_view path, bytes body) {
    const std::uint32_t id = next_stream_;
    next_stream_ += 2;
    const std::vector<hpack::field> headers{{":method", "POST"}, {":scheme", "https"}, {":path", std::string(path)}, {":authority", authority_}};
    frame(detail::frame_type::headers, body.empty() ? detail::end_headers | detail::end_stream : detail::end_headers, id, hpack::encode(headers));
    auto& s = streams_[id];
    s.send_window = peer_initial_window_;
    if (!body.empty()) {
      s.pending = std::move(body);
      s.sending = true;
    }
    pump();
    return id;
  }

  // Bytes from the server.
  void received(std::span<const byte> data) {
    if (failed_) return;
    in_.insert(in_.end(), data.begin(), data.end());
    std::size_t at = 0;
    while (!failed_ && in_.size() - at >= 9) {
      const std::size_t length = (std::size_t{in_[at]} << 16) | (std::size_t{in_[at + 1]} << 8) | in_[at + 2];
      if (length > max_frame_in_) return fail("a frame larger than we allow");
      if (in_.size() - at < 9 + length) break;
      const auto type = in_[at + 3];
      const byte flags = in_[at + 4];
      const std::uint32_t stream = ((std::uint32_t{in_[at + 5]} << 24) | (std::uint32_t{in_[at + 6]} << 16) | (std::uint32_t{in_[at + 7]} << 8) | in_[at + 8]) & 0x7fffffffu;
      const bytes payload(in_.begin() + static_cast<std::ptrdiff_t>(at + 9), in_.begin() + static_cast<std::ptrdiff_t>(at + 9 + length));
      at += 9 + length;
      handle(type, flags, stream, payload);
    }
    in_.erase(in_.begin(), in_.begin() + static_cast<std::ptrdiff_t>(at));
    pump();
  }

  [[nodiscard]] bytes take_outgoing() { return std::exchange(out_, {}); }
  [[nodiscard]] std::vector<event_t> take_events() { return std::exchange(events_, {}); }

 private:
  struct stream_state {
    bytes pending;  // body still to send
    std::size_t sent = 0;
    bool sending = false;
    std::int64_t send_window = 65535;
    bytes header_block;  // HEADERS and CONTINUATION gathered
    bool headers_end_stream = false;
    int status = 0;
    bytes body;
  };

  static void put_setting(bytes& out, detail::setting which, std::uint32_t value) {
    put_u16(out, std::to_underlying(which));
    put_u32(out, value);
  }
  void frame(detail::frame_type type, byte flags, std::uint32_t stream, std::span<const byte> payload) {
    put_byte(out_, static_cast<byte>(payload.size() >> 16));
    put_byte(out_, static_cast<byte>(payload.size() >> 8));
    put_byte(out_, static_cast<byte>(payload.size()));
    put_byte(out_, std::to_underlying(type));
    put_byte(out_, flags);
    put_u32(out_, stream & 0x7fffffffu);
    put_bytes(out_, payload);
  }
  void window_update(std::uint32_t stream, std::uint32_t increment) {
    bytes p;
    put_u32(p, increment & 0x7fffffffu);
    frame(detail::frame_type::window_update, 0, stream, p);
  }
  void fail(std::string what) {
    failed_ = true;
    events_.push_back(event::failed{std::move(what)});
  }
  // Bodies sent as far as the windows and the frame size let them.
  void pump() {
    for (auto& [id, s] : streams_) {
      while (s.sending && conn_send_window_ > 0 && s.send_window > 0) {
        const std::size_t left = s.pending.size() - s.sent;
        const auto n = std::min<std::size_t>({left, max_frame_out_, static_cast<std::size_t>(conn_send_window_), static_cast<std::size_t>(s.send_window)});
        const bool last = n == left;
        frame(detail::frame_type::data, last ? detail::end_stream : 0, id, std::span(s.pending).subspan(s.sent, n));
        s.sent += n;
        conn_send_window_ -= static_cast<std::int64_t>(n);
        s.send_window -= static_cast<std::int64_t>(n);
        if (last) {
          s.sending = false;
          s.pending.clear();
          s.pending.shrink_to_fit();
        }
      }
    }
  }
  // A frame's payload with its padding taken off, where it is padded.
  static std::optional<std::span<const byte>> unpadded(byte flags, std::span<const byte> payload) {
    if (!(flags & detail::padded)) return payload;
    if (payload.empty() || payload[0] >= payload.size()) return std::nullopt;
    return payload.subspan(1, payload.size() - 1 - payload[0]);
  }
  void headers_done(std::uint32_t id, stream_state& s) {
    auto fields = decoder_.decode(s.header_block);
    s.header_block.clear();
    if (!fields) return fail("a header block that does not decode");
    for (const auto& f : *fields)
      if (f.name == ":status") std::from_chars(f.value.data(), f.value.data() + f.value.size(), s.status);
    if (s.headers_end_stream) end(id);
  }
  void end(std::uint32_t id) {
    auto node = streams_.extract(id);
    if (node.empty()) return;
    events_.push_back(event::response{id, node.mapped().status, std::move(node.mapped().body)});
  }
  void handle(byte type_byte, byte flags, std::uint32_t stream, const bytes& payload) {
    // The frame types read once into their enumerators; unknown ones are passed over.
    if (type_byte > std::to_underlying(detail::frame_type::continuation)) return;
    switch (static_cast<detail::frame_type>(type_byte)) {
      case detail::frame_type::settings: {
        if (flags & detail::ack) return;
        if (payload.size() % 6 != 0) return fail("a SETTINGS frame of a bad size");
        for (std::size_t i = 0; i < payload.size(); i += 6) {
          const std::uint16_t id = static_cast<std::uint16_t>((payload[i] << 8) | payload[i + 1]);
          const std::uint32_t value = (std::uint32_t{payload[i + 2]} << 24) | (std::uint32_t{payload[i + 3]} << 16) | (std::uint32_t{payload[i + 4]} << 8) | payload[i + 5];
          if (id == std::to_underlying(detail::setting::initial_window_size)) {
            const auto delta = static_cast<std::int64_t>(value) - peer_initial_window_;
            for (auto& [sid, s] : streams_) s.send_window += delta;
            peer_initial_window_ = value;
          } else if (id == std::to_underlying(detail::setting::max_frame_size)) {
            max_frame_out_ = value;
          }
        }
        frame(detail::frame_type::settings, detail::ack, 0, {});
        return;
      }
      case detail::frame_type::ping:
        if (!(flags & detail::ack)) frame(detail::frame_type::ping, detail::ack, 0, payload);
        return;
      case detail::frame_type::window_update: {
        if (payload.size() != 4) return fail("a WINDOW_UPDATE of a bad size");
        const std::uint32_t increment = ((std::uint32_t{payload[0]} << 24) | (std::uint32_t{payload[1]} << 16) | (std::uint32_t{payload[2]} << 8) | payload[3]) & 0x7fffffffu;
        if (stream == 0) conn_send_window_ += increment;
        else if (const auto s = streams_.find(stream); s != streams_.end()) s->second.send_window += increment;
        return;
      }
      case detail::frame_type::headers: {
        const auto s = streams_.find(stream);
        if (s == streams_.end()) return;
        auto block = unpadded(flags, payload);
        if (!block) return fail("a HEADERS frame's padding is bad");
        if (flags & detail::priority_flag) {
          if (block->size() < 5) return fail("a HEADERS frame's priority is cut");
          block = block->subspan(5);
        }
        s->second.header_block.insert(s->second.header_block.end(), block->begin(), block->end());
        s->second.headers_end_stream = flags & detail::end_stream;
        if (flags & detail::end_headers) headers_done(stream, s->second);
        return;
      }
      case detail::frame_type::continuation: {
        const auto s = streams_.find(stream);
        if (s == streams_.end()) return;
        s->second.header_block.insert(s->second.header_block.end(), payload.begin(), payload.end());
        if (flags & detail::end_headers) headers_done(stream, s->second);
        return;
      }
      case detail::frame_type::data: {
        // What it took of our windows, given back at once.
        if (!payload.empty()) {
          window_update(0, static_cast<std::uint32_t>(payload.size()));
          if (!(flags & detail::end_stream)) window_update(stream, static_cast<std::uint32_t>(payload.size()));
        }
        const auto s = streams_.find(stream);
        if (s == streams_.end()) return;
        const auto body = unpadded(flags, payload);
        if (!body) return fail("a DATA frame's padding is bad");
        s->second.body.insert(s->second.body.end(), body->begin(), body->end());
        if (flags & detail::end_stream) end(stream);
        return;
      }
      case detail::frame_type::rst_stream: {
        const std::uint32_t code = payload.size() == 4 ? (std::uint32_t{payload[0]} << 24) | (std::uint32_t{payload[1]} << 16) | (std::uint32_t{payload[2]} << 8) | payload[3] : 0;
        streams_.erase(stream);
        events_.push_back(event::reset{stream, code});
        return;
      }
      case detail::frame_type::goaway:
        return fail("the server sent GOAWAY");
      case detail::frame_type::priority:
      case detail::frame_type::push_promise:
        return;
    }
  }

  std::string authority_;
  bytes out_, in_;
  std::vector<event_t> events_;
  std::map<std::uint32_t, stream_state> streams_;
  hpack::decoder decoder_;
  std::uint32_t next_stream_ = 1;
  std::int64_t conn_send_window_ = 65535, peer_initial_window_ = 65535;
  std::size_t max_frame_out_ = 16384, max_frame_in_ = 16384;
  bool failed_ = false;
};

}  // namespace quay::http2

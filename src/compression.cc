// SPDX-License-Identifier: AGPL-3.0-only
// quay.compression -- simplexmq's Compressed and simplex-chat's compressed
// batches: a message body that starts with 'X' is a non-empty list of
// pieces, each either passed through as it is ('0', a short string: at most
// 180 bytes) or one zstd frame ('1', a large string) that says its own
// decompressed size; each piece, decompressed, is one chat message body as
// it would be sent uncompressed. Sizes are checked before anything is
// decompressed: none above 64 KiB, nor all together.
module;
#include <zstd.h>
export module quay.compression;

import std;
import splice;
import quay.bytes;

export namespace quay::compression {

inline constexpr std::size_t max_passthrough = 180;     // simplexmq's maxLengthPassthrough
inline constexpr std::size_t max_decompressed = 65536;  // simplex-chat's maxDecompressedMsgLength
inline constexpr int level = 3;                         // simplexmq's compressionLevel
inline constexpr byte batch_mark = 'X';

namespace piece {
struct passthrough {  // '0'
  bytes body;
  friend constexpr bool operator==(const passthrough&, const passthrough&) = default;
};
struct zstd {  // '1': one zstd frame
  bytes frame;
  friend constexpr bool operator==(const zstd&, const zstd&) = default;
};
}  // namespace piece
using piece_t = spl::variant<piece::passthrough, piece::zstd>;

namespace errors {
struct decode {  // the batch's framing does not read
  decode_error error;
  friend bool operator==(const decode&, const decode&) = default;
};
struct bad_tag {  // a piece neither '0' nor '1'
  byte tag = 0;
  friend bool operator==(const bad_tag&, const bad_tag&) = default;
};
struct empty {  friend bool operator==(const empty&, const empty&) = default;
};  // a batch of no pieces
struct no_size {  friend bool operator==(const no_size&, const no_size&) = default;
};  // a zstd frame that does not say its decompressed size
struct too_large {  // a piece, or all of them, above the limit
  std::size_t size = 0;
  friend bool operator==(const too_large&, const too_large&) = default;
};
struct zstd_failed {  // zstd's own error
  std::string what;
  friend bool operator==(const zstd_failed&, const zstd_failed&) = default;
};
}  // namespace errors
using error = spl::variant<errors::decode, errors::bad_tag, errors::empty, errors::no_size, errors::too_large, errors::zstd_failed>;

namespace detail {
// zstd's C API wants contiguous memory: the narrowest view of it.
template <class R>
concept contiguous_bytes = std::ranges::contiguous_range<R> && std::same_as<std::ranges::range_value_t<R>, byte>;
}  // namespace detail

// A body as one piece: passed through where short, zstd's frame otherwise.
template <detail::contiguous_bytes R>
piece_t compress(const R& body) {
  const std::size_t size = std::ranges::size(body);
  if (size <= max_passthrough) return piece::passthrough{bytes(std::ranges::begin(body), std::ranges::end(body))};
  bytes frame(ZSTD_compressBound(size));
  const std::size_t n = ZSTD_compress(frame.data(), frame.size(), std::ranges::data(body), size, level);
  // Compressing into its own bound cannot fail but for memory; then passed through.
  if (ZSTD_isError(n)) return piece::passthrough{bytes(std::ranges::begin(body), std::ranges::end(body))};
  frame.resize(n);
  return piece::zstd{std::move(frame)};
}

// What a piece decompresses to, as it says (a zstd frame may not say).
inline std::optional<std::size_t> decompressed_size(const piece_t& p) {
  return spl::visit(spl::overloaded{[](const piece::passthrough& x) { return std::optional(x.body.size()); },
                                    [](const piece::zstd& x) {
                                      const auto n = ZSTD_getFrameContentSize(x.frame.data(), x.frame.size());
                                      if (n == ZSTD_CONTENTSIZE_UNKNOWN || n == ZSTD_CONTENTSIZE_ERROR) return std::optional<std::size_t>();
                                      return std::optional(static_cast<std::size_t>(n));
                                    }},
                    p);
}

// A piece decompressed, no larger than `limit`.
inline std::expected<bytes, error> decompress(const piece_t& p, std::size_t limit = max_decompressed) {
  const auto size = decompressed_size(p);
  if (!size) return std::unexpected(errors::no_size{});
  if (*size > limit) return std::unexpected(errors::too_large{*size});
  return spl::visit(spl::overloaded{[](const piece::passthrough& x) -> std::expected<bytes, error> { return x.body; },
                                    [&](const piece::zstd& x) -> std::expected<bytes, error> {
                                      bytes out(*size);
                                      const std::size_t n = ZSTD_decompress(out.data(), out.size(), x.frame.data(), x.frame.size());
                                      if (ZSTD_isError(n)) return std::unexpected(errors::zstd_failed{ZSTD_getErrorName(n)});
                                      out.resize(n);
                                      return out;
                                    }},
                    p);
}

// A batch written: 'X', the count, each piece tagged.
template <byte_sink Out>
std::expected<void, error> put_batch(Out& out, std::span<const piece_t> pieces) {
  if (pieces.empty()) return std::unexpected(errors::empty{});
  if (pieces.size() > 255) return std::unexpected(errors::too_large{pieces.size()});
  put_byte(out, batch_mark);
  put_byte(out, static_cast<byte>(pieces.size()));
  for (const auto& p : pieces) {
    const auto put = spl::visit(spl::overloaded{[&](const piece::passthrough& x) {
                                                  put_byte(out, '0');
                                                  return put_short(out, x.body);
                                                },
                                                [&](const piece::zstd& x) {
                                                  put_byte(out, '1');
                                                  return put_large(out, x.frame);
                                                }},
                                p);
    if (!put) return std::unexpected(errors::decode{put.error()});
  }
  return {};
}

// A batch read, from just after its 'X'.
template <std::ranges::input_range R>
std::expected<std::vector<piece_t>, error> batch_of(R&& after_mark) {
  auto in = reader_of(after_mark);
  const auto count = in.u8();
  if (!count) return std::unexpected(errors::decode{count.error()});
  if (*count == 0) return std::unexpected(errors::empty{});
  std::vector<piece_t> pieces;
  for (byte i = 0; i < *count; ++i) {
    const auto tag = in.u8();
    if (!tag) return std::unexpected(errors::decode{tag.error()});
    if (*tag == '0') {
      auto body = in.short_string();
      if (!body) return std::unexpected(errors::decode{body.error()});
      pieces.push_back(piece::passthrough{std::move(*body)});
    } else if (*tag == '1') {
      auto frame = in.large_string();
      if (!frame) return std::unexpected(errors::decode{frame.error()});
      pieces.push_back(piece::zstd{std::move(*frame)});
    } else {
      return std::unexpected(errors::bad_tag{*tag});
    }
  }
  return pieces;
}

// The chat message bodies a message body carries: itself where it is not a
// compressed batch, each piece decompressed where it is -- every size
// checked first, as simplex-chat checks them.
template <detail::contiguous_bytes R>
std::expected<std::vector<bytes>, error> bodies_of(const R& body) {
  const auto all = std::span<const byte>(std::ranges::data(body), std::ranges::size(body));
  if (all.empty() || all.front() != batch_mark) return std::vector<bytes>{bytes(all.begin(), all.end())};
  const auto pieces = batch_of(all.subspan(1));
  if (!pieces) return std::unexpected(pieces.error());
  std::size_t total = 0;
  for (const auto& p : *pieces) {
    const auto size = decompressed_size(p);
    if (!size) return std::unexpected(errors::no_size{});
    if (*size > max_decompressed) return std::unexpected(errors::too_large{*size});
    total += *size;
  }
  if (total > max_decompressed) return std::unexpected(errors::too_large{total});
  std::vector<bytes> out;
  for (const auto& p : *pieces) {
    auto one = decompress(p);
    if (!one) return std::unexpected(one.error());
    out.push_back(std::move(*one));
  }
  return out;
}

}  // namespace quay::compression

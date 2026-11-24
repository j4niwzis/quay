// SPDX-License-Identifier: AGPL-3.0-only
// quay.hpack -- HTTP/2's header compression (RFC 7541), as much as a client
// needs: a header block decoded -- indexed fields, literals with and
// without indexing, dynamic table size updates, Huffman-coded strings --
// against a dynamic table it keeps; and request headers encoded as fields
// from the static table and literals not indexed.
//
// The static table and the Huffman code are not copied out by hand: they
// are read, while quay is compiled, from RFC 7541's own text (Appendices A
// and B), vendored as published.
export module quay.hpack;

import std;
import splice;
import quay.bytes;

namespace quay::hpack::detail {

inline constexpr char rfc[] = {
#embed "../third_party/rfc7541/rfc7541.txt"
    , 0};
inline constexpr std::string_view text(rfc, sizeof rfc - 1);

constexpr bool digit(char c) { return c >= '0' && c <= '9'; }
constexpr std::uint32_t hex_value(char c) {
  return digit(c) ? static_cast<std::uint32_t>(c - '0') : static_cast<std::uint32_t>(c - 'a' + 10);
}
constexpr std::string_view trimmed(std::string_view s) {
  while (!s.empty() && s.front() == ' ') s.remove_prefix(1);
  while (!s.empty() && s.back() == ' ') s.remove_suffix(1);
  return s;
}

// Appendix B's lines: "    ' ' ( 32)  |010100      14  [ 6]" -- the symbol in
// parentheses, the code in hex before the length in brackets.
struct code {
  std::uint32_t bits = 0;
  std::uint8_t length = 0;
};
consteval std::array<code, 257> huffman_codes() {
  std::array<code, 257> codes{};
  std::size_t found = 0;
  // The appendix itself, not its line in the contents (which is indented).
  const auto from = text.find("\nAppendix B.  Huffman Code\n");
  const auto to = text.find("\nAppendix C.  Examples\n", from);
  if (from == std::string_view::npos || to == std::string_view::npos) throw "RFC 7541's Appendix B not found";
  std::size_t at = from;
  while (at < to) {
    const auto end = text.find('\n', at);
    const auto line = text.substr(at, end - at);
    at = end + 1;
    // The symbol: "(" and three columns of its number, right-aligned, and ")"
    // -- not the quoted character before it, which may itself be '('.
    std::size_t open = std::string_view::npos;
    for (std::size_t p = line.find('('); p != std::string_view::npos && p + 4 < line.size(); p = line.find('(', p + 1)) {
      const auto inside = line.substr(p + 1, 3);
      if (line[p + 4] == ')' && std::ranges::all_of(inside, [](char c) { return c == ' ' || digit(c); }) && digit(inside.back())) {
        open = p;
        break;
      }
    }
    const auto close = open == std::string_view::npos ? open : open + 4;
    const auto bracket = line.rfind('[');
    const auto bracket_end = line.rfind(']');
    if (open == std::string_view::npos || bracket == std::string_view::npos || bracket_end == std::string_view::npos || bracket_end < bracket) continue;
    const auto symbol_text = trimmed(line.substr(open + 1, close - open - 1));
    const auto length_text = trimmed(line.substr(bracket + 1, bracket_end - bracket - 1));
    if (symbol_text.empty() || length_text.empty() || !std::ranges::all_of(symbol_text, digit) || !std::ranges::all_of(length_text, digit)) continue;
    std::uint32_t symbol = 0, length = 0;
    for (const char c : symbol_text) symbol = symbol * 10 + static_cast<std::uint32_t>(c - '0');
    for (const char c : length_text) length = length * 10 + static_cast<std::uint32_t>(c - '0');
    // The hex code: the word just before the bracket.
    auto before = trimmed(line.substr(0, bracket));
    const auto space = before.rfind(' ');
    const auto hex = before.substr(space + 1);
    std::uint32_t bits = 0;
    for (const char c : hex) bits = bits * 16 + hex_value(c);
    if (symbol > 256) throw "a Huffman symbol out of range";
    codes[symbol] = code{bits, static_cast<std::uint8_t>(length)};
    ++found;
  }
  if (found != 257) throw "RFC 7541's Huffman table did not read whole";
  return codes;
}
inline constexpr auto huffman = huffman_codes();
static_assert(huffman['a'].bits == 0x3 && huffman['a'].length == 5);
static_assert(huffman[256].bits == 0x3fffffff && huffman[256].length == 30);

// Appendix A's rows: "| 2     | :method                     | GET           |".
struct entry {
  std::string_view name, value;
};
consteval std::array<entry, 61> static_entries() {
  std::array<entry, 61> table{};
  std::size_t found = 0;
  const auto from = text.find("\nAppendix A.  Static Table Definition\n");
  const auto to = text.find("\nAppendix B.  Huffman Code\n", from);
  if (from == std::string_view::npos || to == std::string_view::npos) throw "RFC 7541's Appendix A not found";
  std::size_t at = from;
  while (at < to) {
    const auto end = text.find('\n', at);
    const auto line = trimmed(text.substr(at, end - at));
    at = end + 1;
    if (!line.starts_with("| ") || !line.ends_with("|")) continue;
    const auto c1 = line.find('|', 1), c2 = line.find('|', c1 + 1), c3 = line.find('|', c2 + 1);
    if (c1 == std::string_view::npos || c2 == std::string_view::npos || c3 == std::string_view::npos) continue;
    const auto index_text = trimmed(line.substr(1, c1 - 1));
    if (index_text.empty() || !std::ranges::all_of(index_text, digit)) continue;
    std::size_t index = 0;
    for (const char c : index_text) index = index * 10 + static_cast<std::size_t>(c - '0');
    if (index < 1 || index > 61) throw "a static table index out of range";
    table[index - 1] = entry{trimmed(line.substr(c1 + 1, c2 - c1 - 1)), trimmed(line.substr(c2 + 1, c3 - c2 - 1))};
    ++found;
  }
  if (found != 61) throw "RFC 7541's static table did not read whole";
  return table;
}
inline constexpr auto static_table = static_entries();
static_assert(static_table[1].name == ":method" && static_table[2].value == "POST");
static_assert(static_table[60].name == "www-authenticate");

// The codes sorted by length, then code: decoding looks a code up by both.
struct by_length {
  std::uint32_t bits = 0;
  std::uint8_t length = 0;
  std::uint16_t symbol = 0;
  friend constexpr auto operator<=>(const by_length&, const by_length&) = default;
};
consteval std::array<by_length, 257> sorted_codes() {
  std::array<by_length, 257> out{};
  for (std::size_t s = 0; s < 257; ++s) out[s] = by_length{huffman[s].bits, huffman[s].length, static_cast<std::uint16_t>(s)};
  std::ranges::sort(out, [](const by_length& a, const by_length& b) { return std::pair(a.length, a.bits) < std::pair(b.length, b.bits); });
  return out;
}
inline constexpr auto decoding = sorted_codes();

}  // namespace quay::hpack::detail

export namespace quay::hpack {

struct field {
  std::string name, value;
  friend bool operator==(const field&, const field&) = default;
};

namespace errors {
struct truncated {};
struct bad_index {
  std::uint64_t index = 0;
};
struct bad_huffman {};
struct too_large {};  // a table size update past what we allow
}  // namespace errors
using error = spl::variant<errors::truncated, errors::bad_index, errors::bad_huffman, errors::too_large>;

// A Huffman-coded string decoded: its padding must be the EOS code's
// leading ones, no longer than 7 bits, and EOS itself must not appear.
template <std::ranges::input_range R>
std::expected<std::string, error> huffman_decode(R&& coded) {
  std::string out;
  std::uint64_t bits = 0;
  std::uint8_t length = 0;
  for (const auto byte_value : coded) {
    for (int i = 7; i >= 0; --i) {
      bits = (bits << 1) | ((static_cast<std::uint8_t>(byte_value) >> i) & 1u);
      ++length;
      if (length < 5) continue;
      const auto key = detail::by_length{static_cast<std::uint32_t>(bits), length, 0};
      const auto found = std::ranges::lower_bound(detail::decoding, key, [](const detail::by_length& a, const detail::by_length& b) {
        return std::pair(a.length, a.bits) < std::pair(b.length, b.bits);
      });
      if (found != detail::decoding.end() && found->length == length && found->bits == bits) {
        if (found->symbol == 256) return std::unexpected(errors::bad_huffman{});
        out.push_back(static_cast<char>(found->symbol));
        bits = 0, length = 0;
      } else if (length >= 30) {
        return std::unexpected(errors::bad_huffman{});
      }
    }
  }
  if (length > 7 || bits != (1u << length) - 1) return std::unexpected(errors::bad_huffman{});
  return out;
}

// A header block's decoder, with the dynamic table it keeps between blocks.
class decoder {
 public:
  explicit decoder(std::size_t max_table_size = 4096) : allowed_(max_table_size), max_(max_table_size) {}

  std::expected<std::vector<field>, error> decode(std::span<const byte> block) {
    std::vector<field> out;
    std::size_t at = 0;
    while (at < block.size()) {
      const byte first = block[at];
      if (first & 0x80) {  // indexed
        const auto index = integer(block, at, 7);
        if (!index) return std::unexpected(index.error());
        const auto f = lookup(*index);
        if (!f) return std::unexpected(f.error());
        out.push_back(*f);
      } else if ((first & 0xc0) == 0x40) {  // literal, with incremental indexing
        auto f = literal(block, at, 6);
        if (!f) return std::unexpected(f.error());
        insert(*f);
        out.push_back(std::move(*f));
      } else if ((first & 0xe0) == 0x20) {  // dynamic table size update
        const auto size = integer(block, at, 5);
        if (!size) return std::unexpected(size.error());
        if (*size > allowed_) return std::unexpected(errors::too_large{});
        max_ = static_cast<std::size_t>(*size);
        evict(0);
      } else {  // literal without indexing (0000) or never indexed (0001)
        auto f = literal(block, at, 4);
        if (!f) return std::unexpected(f.error());
        out.push_back(std::move(*f));
      }
    }
    return out;
  }
  [[nodiscard]] std::size_t table_size() const { return size_; }
  [[nodiscard]] const std::deque<field>& table() const { return table_; }

 private:
  static std::expected<std::uint64_t, error> integer(std::span<const byte> in, std::size_t& at, int prefix) {
    if (at >= in.size()) return std::unexpected(errors::truncated{});
    const std::uint64_t mask = (1u << prefix) - 1;
    std::uint64_t value = in[at++] & mask;
    if (value < mask) return value;
    for (int shift = 0; shift < 56; shift += 7) {
      if (at >= in.size()) return std::unexpected(errors::truncated{});
      const byte b = in[at++];
      value += static_cast<std::uint64_t>(b & 0x7f) << shift;
      if (!(b & 0x80)) return value;
    }
    return std::unexpected(errors::truncated{});
  }
  static std::expected<std::string, error> string(std::span<const byte> in, std::size_t& at) {
    if (at >= in.size()) return std::unexpected(errors::truncated{});
    const bool coded = in[at] & 0x80;
    const auto length = integer(in, at, 7);
    if (!length) return std::unexpected(length.error());
    if (*length > in.size() - at) return std::unexpected(errors::truncated{});
    const auto piece = in.subspan(at, static_cast<std::size_t>(*length));
    at += piece.size();
    if (coded) return huffman_decode(piece);
    return std::string(piece.begin(), piece.end());
  }
  std::expected<field, error> literal(std::span<const byte> in, std::size_t& at, int prefix) {
    const auto index = integer(in, at, prefix);
    if (!index) return std::unexpected(index.error());
    field f;
    if (*index == 0) {
      auto name = string(in, at);
      if (!name) return std::unexpected(name.error());
      f.name = std::move(*name);
    } else {
      const auto named = lookup(*index);
      if (!named) return std::unexpected(named.error());
      f.name = named->name;
    }
    auto value = string(in, at);
    if (!value) return std::unexpected(value.error());
    f.value = std::move(*value);
    return f;
  }
  std::expected<field, error> lookup(std::uint64_t index) const {
    if (index >= 1 && index <= detail::static_table.size()) {
      const auto& e = detail::static_table[index - 1];
      return field{std::string(e.name), std::string(e.value)};
    }
    const auto dynamic = index - detail::static_table.size() - 1;
    if (index == 0 || dynamic >= table_.size()) return std::unexpected(errors::bad_index{index});
    return table_[static_cast<std::size_t>(dynamic)];
  }
  static std::size_t size_of(const field& f) { return f.name.size() + f.value.size() + 32; }
  void evict(std::size_t room) {
    while (!table_.empty() && size_ + room > max_) {
      size_ -= size_of(table_.back());
      table_.pop_back();
    }
  }
  void insert(const field& f) {
    const auto n = size_of(f);
    evict(n);
    if (n > max_) return;  // larger than the table: it empties, nothing added
    table_.push_front(f);
    size_ += n;
  }

  std::deque<field> table_;
  std::size_t size_ = 0, allowed_ = 4096, max_ = 4096;
};

// Request headers encoded: each field the static table has whole as its
// index; one whose name it has as a literal not indexed, by the name's
// index; any other as a literal with its name. Strings are not Huffman-coded.
inline bytes encode(std::span<const field> fields) {
  bytes out;
  const auto integer = [&](std::uint64_t value, int prefix, byte flags) {
    const std::uint64_t mask = (1u << prefix) - 1;
    if (value < mask) return put_byte(out, static_cast<byte>(flags | value));
    put_byte(out, static_cast<byte>(flags | mask));
    value -= mask;
    while (value >= 0x80) {
      put_byte(out, static_cast<byte>((value & 0x7f) | 0x80));
      value >>= 7;
    }
    put_byte(out, static_cast<byte>(value));
  };
  const auto string = [&](std::string_view s) {
    integer(s.size(), 7, 0);
    for (const char c : s) put_byte(out, static_cast<byte>(c));
  };
  for (const auto& f : fields) {
    const auto whole = std::ranges::find_if(detail::static_table, [&](const detail::entry& e) { return e.name == f.name && e.value == f.value; });
    if (whole != detail::static_table.end()) {
      integer(static_cast<std::uint64_t>(whole - detail::static_table.begin()) + 1, 7, 0x80);
      continue;
    }
    const auto named = std::ranges::find(detail::static_table, std::string_view(f.name), &detail::entry::name);
    if (named != detail::static_table.end()) {
      integer(static_cast<std::uint64_t>(named - detail::static_table.begin()) + 1, 4, 0x00);
    } else {
      integer(0, 4, 0x00);
      string(f.name);
    }
    string(f.value);
  }
  return out;
}

}  // namespace quay::hpack

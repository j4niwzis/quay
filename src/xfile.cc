// SPDX-License-Identifier: AGPL-3.0-only
// quay.xfile -- files over XFTP, as simplexmq's xftp sends and receives
// them: a file sealed whole (XSalsa20-Poly1305 under a key and nonce of its
// own -- keyed through HSalsa20, as simplexmq's XSalsa20 keys it: its
// length, its header -- its name -- and its bytes, padded with '#'
// to the sum of its chunks' sizes, the tag at the end), cut into chunks of
// the routers' sizes; and the file description that says where the chunks
// are and how to open them -- the text a recipient is given, read once
// into types and written from them.
export module quay.xfile;

import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.xftp;

export namespace quay::xfile {

// ---- sealing ----------------------------------------------------------------------

struct header {
  std::string file_name;
  std::optional<std::string> extra;
};

// The chunk sizes a file of `size` sealed bytes (its length, header and
// content, and the tag) is cut into, as simplexmq's prepareChunkSizes cuts.
inline std::vector<std::uint32_t> chunk_sizes_for(std::uint64_t size) {
  const auto& c = xftp::chunk_sizes;
  const auto three_quarters = [](std::uint64_t s) { return s * 3 / 4; };
  const auto [small, big] = size > three_quarters(c[3]) ? std::pair{c[2], c[3]} : size > three_quarters(c[2]) ? std::pair{c[1], c[2]} : std::pair{c[0], c[1]};
  std::vector<std::uint32_t> out;
  std::uint64_t left = size;
  while (left > 0) {
    if (left >= big) {
      out.insert(out.end(), static_cast<std::size_t>(left / big), big);
      left %= big;
    } else if (left > three_quarters(big)) {
      out.push_back(big);
      left = 0;
    } else {
      out.insert(out.end(), static_cast<std::size_t>((left + small - 1) / small), small);
      left = 0;
    }
  }
  return out;
}

struct sealed_file {
  bytes data;  // the sealed file, the chunks' sizes long in all
  std::vector<std::uint32_t> chunk_sizes;
  crypto::box_key key{};
  crypto::box_nonce nonce{};
};
template <crypto::random_source R>
sealed_file seal(const header& h, std::span<const byte> content, R& random) {
  bytes head;
  (void)put_short(head, h.file_name | std::views::transform([](char c) { return static_cast<byte>(c); }));
  if (h.extra) {
    put_byte(head, '1');
    (void)put_short(head, *h.extra | std::views::transform([](char c) { return static_cast<byte>(c); }));
  } else {
    put_byte(head, '0');
  }
  const std::uint64_t length = head.size() + content.size();
  sealed_file out;
  out.chunk_sizes = chunk_sizes_for(length + 8 + 16);
  const auto total = std::accumulate(out.chunk_sizes.begin(), out.chunk_sizes.end(), std::uint64_t{0});
  bytes plain;
  plain.reserve(static_cast<std::size_t>(total));
  put_u64(plain, length);
  put_bytes(plain, head);
  put_bytes(plain, content);
  plain.resize(static_cast<std::size_t>(total - 16), '#');
  random(std::span<byte>(out.key));
  random(std::span<byte>(out.nonce));
  const auto easy = crypto::secretbox(crypto::secretbox_key_of(out.key), out.nonce, plain);  // the tag first
  crypto::scrub(plain);
  out.data.assign(easy.begin() + 16, easy.end());  // simplexmq's: the tag last
  out.data.insert(out.data.end(), easy.begin(), easy.begin() + 16);
  return out;
}

struct opened_file {
  header head;
  bytes content;
};
inline std::expected<opened_file, std::string> open(std::span<const byte> sealed, const crypto::box_key& key, const crypto::box_nonce& nonce) {
  if (sealed.size() < 16 + 8) return std::unexpected("too short to be a sealed file");
  bytes easy(sealed.end() - 16, sealed.end());
  easy.insert(easy.end(), sealed.begin(), sealed.end() - 16);
  const auto plain = crypto::secretbox_open(crypto::secretbox_key_of(key), nonce, easy);
  if (!plain) return std::unexpected("the file does not open (its tag)");
  auto in = reader_of(*plain);
  const auto length = in.u64();
  if (!length || *length > plain->size() - 8) return std::unexpected("a length past the file");
  const auto name = in.short_string();
  const auto flag = in.u8();
  if (!name || !flag) return std::unexpected("a header that does not read");
  opened_file out;
  out.head.file_name.assign(name->begin(), name->end());
  std::size_t head_size = 1 + name->size() + 1;
  if (*flag == '1') {
    const auto extra = in.short_string();
    if (!extra) return std::unexpected("a header that does not read");
    out.head.extra = std::string(extra->begin(), extra->end());
    head_size += 1 + extra->size();
  }
  if (head_size > *length) return std::unexpected("a header past the file");
  out.content.assign(plain->begin() + 8 + static_cast<std::ptrdiff_t>(head_size), plain->begin() + 8 + static_cast<std::ptrdiff_t>(*length));
  return out;
}

// ---- descriptions ---------------------------------------------------------------------

namespace party {
struct recipient {};
struct sender {};
}  // namespace party
using party_t = spl::variant<party::recipient, party::sender>;

struct replica {
  xftp::router router;
  bytes id;
  crypto::private_key<curve::ed25519> key;
};
struct chunk {
  std::uint32_t number = 0;
  std::uint32_t size = 0;
  bytes digest;  // SHA-256 of the chunk
  std::vector<replica> replicas;
};
struct description {
  party_t party;
  std::uint64_t size = 0;  // the sealed file's
  bytes digest;            // SHA-512 of the sealed file
  crypto::box_key key{};
  crypto::box_nonce nonce{};
  std::uint32_t chunk_size = 0;
  std::vector<chunk> chunks;
};

namespace detail {
// Sizes as simplexmq writes them: in gb, mb or kb where they divide, else bytes.
inline std::string size_text(std::uint64_t n) {
  if (n % 1024) return std::to_string(n);
  if ((n / 1024) % 1024) return std::to_string(n / 1024) + "kb";
  if ((n / (1024 * 1024)) % 1024) return std::to_string(n / (1024 * 1024)) + "mb";
  return std::to_string(n / (1024 * 1024 * 1024)) + "gb";
}
inline std::optional<std::uint64_t> size_of(std::string_view s) {
  std::uint64_t unit = 1;
  if (s.ends_with("gb")) unit = 1024ull * 1024 * 1024, s.remove_suffix(2);
  else if (s.ends_with("mb")) unit = 1024ull * 1024, s.remove_suffix(2);
  else if (s.ends_with("kb")) unit = 1024, s.remove_suffix(2);
  std::uint64_t n = 0;
  const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), n);
  if (ec != std::errc{} || end != s.data() + s.size()) return std::nullopt;
  return n * unit;
}
inline std::string b64(std::span<const byte> data) {
  std::string out;
  put_base64url(out, data);
  return out;
}
// Ed25519 private keys as PKCS#8 DER: a fixed prefix, then the 32 bytes.
inline constexpr std::array<byte, 16> pkcs8_ed25519{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};
inline std::optional<crypto::private_key<curve::ed25519>> private_key_of(std::span<const byte> der) {
  if (der.size() != 48 || !std::ranges::equal(der.first(16), pkcs8_ed25519)) return std::nullopt;
  crypto::private_key<curve::ed25519> k;
  std::ranges::copy(der.subspan(16), k.raw.begin());
  return k;
}
inline bytes der_of(const crypto::private_key<curve::ed25519>& k) {
  bytes out(pkcs8_ed25519.begin(), pkcs8_ed25519.end());
  out.insert(out.end(), k.raw.begin(), k.raw.end());
  return out;
}
// xftp://<identity>@<host>[,<host>...][:<port>]
inline std::optional<xftp::router> router_of(std::string_view s) {
  if (!s.starts_with("xftp://")) return std::nullopt;
  s.remove_prefix(7);
  const auto at = s.find('@');
  if (at == std::string_view::npos) return std::nullopt;
  const auto identity = base64url_decode(s.substr(0, at));
  if (!identity) return std::nullopt;
  auto rest = s.substr(at + 1);
  std::uint16_t port = 443;
  if (const auto colon = rest.rfind(':'); colon != std::string_view::npos) {
    const auto p = rest.substr(colon + 1);
    if (std::from_chars(p.data(), p.data() + p.size(), port).ec != std::errc{}) return std::nullopt;
    rest = rest.substr(0, colon);
  }
  const auto comma = rest.find(',');
  return xftp::router{*identity, std::string(rest.substr(0, comma)), port};
}
inline std::string text_of(const xftp::router& r) { return "xftp://" + b64(r.identity) + "@" + r.host + ":" + std::to_string(r.port); }
inline std::string_view trimmed(std::string_view s) {
  while (!s.empty() && s.front() == ' ') s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\r')) s.remove_suffix(1);
  return s;
}
}  // namespace detail

// A description's text, written as simplexmq writes it (YAML, keys sorted).
inline std::string text_of(const description& d) {
  std::string out;
  out += "chunkSize: " + detail::size_text(d.chunk_size) + "\n";
  out += "digest: " + detail::b64(d.digest) + "\n";
  out += "key: " + detail::b64(d.key) + "\n";
  out += "nonce: " + detail::b64(d.nonce) + "\n";
  out += std::string("party: ") + spl::visit(spl::overloaded{[](party::recipient) { return "recipient"; }, [](party::sender) { return "sender"; }}, d.party) + "\n";
  out += "replicas:\n";
  // By router, in the order chunks name them; the first replica of a chunk says its digest, and its size where not the usual.
  std::vector<std::string> routers;
  for (const auto& c : d.chunks)
    for (const auto& r : c.replicas)
      if (std::ranges::find(routers, detail::text_of(r.router)) == routers.end()) routers.push_back(detail::text_of(r.router));
  for (const auto& router : routers) {
    out += "- chunks:\n";
    for (const auto& c : d.chunks)
      for (std::size_t i = 0; i < c.replicas.size(); ++i) {
        if (detail::text_of(c.replicas[i].router) != router) continue;
        out += "  - " + std::to_string(c.number) + ":" + detail::b64(c.replicas[i].id) + ":" + detail::b64(detail::der_of(c.replicas[i].key));
        if (i == 0) out += ":" + detail::b64(c.digest);
        if (i == 0 && c.size != d.chunk_size) out += ":" + detail::size_text(c.size);
        out += "\n";
      }
    out += "  server: " + router + "\n";
  }
  out += "size: " + detail::size_text(d.size) + "\n";
  return out;
}

// A description's text read: the YAML simplexmq writes, line by line.
inline std::expected<description, std::string> description_of(std::string_view text) {
  description d;
  struct pending {
    std::vector<std::string> chunks;
    std::optional<xftp::router> router;
  };
  std::vector<pending> groups;
  bool in_replicas = false, in_chunks = false;
  std::optional<std::uint64_t> chunk_size;
  for (const auto line_range : text | std::views::split('\n')) {
    const std::string_view raw(line_range.begin(), line_range.end());
    const auto line = detail::trimmed(raw);
    if (line.empty()) continue;
    if (raw.front() != ' ' && raw.front() != '-') {  // a top-level key
      in_replicas = in_chunks = false;
      const auto colon = line.find(':');
      if (colon == std::string_view::npos) return std::unexpected("a line that is not a key");
      const auto key = line.substr(0, colon);
      const auto value = detail::trimmed(line.substr(colon + 1));
      static const std::array<std::pair<std::string_view, int>, 8> keys{
          {{"chunkSize", 0}, {"digest", 1}, {"key", 2}, {"nonce", 3}, {"party", 4}, {"replicas", 5}, {"size", 6}, {"redirect", 7}}};
      const auto found = std::ranges::find(keys, key, &std::pair<std::string_view, int>::first);
      if (found == keys.end()) continue;  // a key this version does not know
      const auto decoded = [&] { return base64url_decode(value); };
      switch (found->second) {
        case 0: chunk_size = detail::size_of(value); if (!chunk_size) return std::unexpected("a bad chunkSize"); break;
        case 1: { const auto b = decoded(); if (!b) return std::unexpected("a bad digest"); d.digest = *b; break; }
        case 2: { const auto b = decoded(); if (!b || b->size() != 32) return std::unexpected("a bad key"); std::ranges::copy(*b, d.key.begin()); break; }
        case 3: { const auto b = decoded(); if (!b || b->size() != 24) return std::unexpected("a bad nonce"); std::ranges::copy(*b, d.nonce.begin()); break; }
        case 4: {
          static const std::array<std::pair<std::string_view, party_t>, 2> parties{{{"recipient", party::recipient{}}, {"sender", party::sender{}}}};
          const auto p = std::ranges::find(parties, value, &std::pair<std::string_view, party_t>::first);
          if (p == parties.end()) return std::unexpected("a bad party");
          d.party = p->second;
          break;
        }
        case 5: in_replicas = true; break;
        case 6: { const auto s = detail::size_of(value); if (!s) return std::unexpected("a bad size"); d.size = *s; break; }
        default: break;  // redirect: not followed here
      }
      continue;
    }
    if (!in_replicas) continue;
    // "- chunks:" or "- server: ..." opens a group; "  server: ..." / "  chunks:" continue it; "  - ..." is a chunk.
    std::string_view item = line;
    if (raw.front() == '-') {
      groups.emplace_back();
      in_chunks = false;
      item = detail::trimmed(line.substr(1));
    } else if (line.starts_with("- ")) {
      if (!in_chunks || groups.empty()) return std::unexpected("a chunk outside a replica group");
      groups.back().chunks.emplace_back(detail::trimmed(line.substr(2)));
      continue;
    }
    if (groups.empty()) return std::unexpected("a replica line outside a group");
    if (item.starts_with("chunks:")) in_chunks = true;
    else if (item.starts_with("server:")) {
      groups.back().router = detail::router_of(detail::trimmed(item.substr(7)));
      if (!groups.back().router) return std::unexpected("a bad server");
      in_chunks = false;
    }
  }
  if (!chunk_size) return std::unexpected("no chunkSize");
  d.chunk_size = static_cast<std::uint32_t>(*chunk_size);
  // The replicas folded into chunks, by number.
  std::map<std::uint32_t, chunk> chunks;
  for (const auto& g : groups) {
    if (!g.router) return std::unexpected("a replica group without its server");
    for (const auto& c : g.chunks) {
      std::vector<std::string_view> parts;
      for (const auto p : std::string_view(c) | std::views::split(':')) parts.emplace_back(p.begin(), p.end());
      if (parts.size() < 3 || parts.size() > 5) return std::unexpected("a bad chunk replica");
      std::uint32_t number = 0;
      if (std::from_chars(parts[0].data(), parts[0].data() + parts[0].size(), number).ec != std::errc{}) return std::unexpected("a bad chunk number");
      const auto id = base64url_decode(parts[1]);
      const auto key_der = base64url_decode(parts[2]);
      const auto key = key_der ? detail::private_key_of(*key_der) : std::nullopt;
      if (!id || !key) return std::unexpected("a bad replica id or key");
      auto& ch = chunks[number];
      ch.number = number;
      if (parts.size() >= 4) {
        const auto digest = base64url_decode(parts[3]);
        if (!digest) return std::unexpected("a bad chunk digest");
        ch.digest = *digest;
      }
      if (parts.size() == 5) {
        const auto s = detail::size_of(parts[4]);
        if (!s) return std::unexpected("a bad chunk size");
        ch.size = static_cast<std::uint32_t>(*s);
      }
      ch.replicas.push_back(replica{*g.router, *id, *key});
    }
  }
  std::uint64_t total = 0;
  std::uint32_t expected = 1;
  for (auto& [n, ch] : chunks) {
    if (n != expected++) return std::unexpected("chunk numbers that are not 1, 2, ...");
    if (ch.size == 0) ch.size = d.chunk_size;
    if (ch.digest.empty()) return std::unexpected("a chunk without a digest");
    total += ch.size;
    d.chunks.push_back(std::move(ch));
  }
  if (total != d.size) return std::unexpected("chunks that do not add up to the file's size");
  return d;
}

}  // namespace quay::xfile

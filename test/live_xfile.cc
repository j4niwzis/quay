// SPDX-License-Identifier: AGPL-3.0-only
// quay.xfile against simplexmq's own xftp client, through xftp-server: a
// file it sent, received by quay from its description (each chunk got,
// opened, its digest checked, the file's digest checked, the file opened);
// and a file quay sends, with the description quay writes for the xftp
// client to receive (tools/live_xftp_cli.sh compares what it gets).
// Usage: live_xfile <their description> <their file> <our description out>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.xftp;
import quay.xfile;

using namespace quay;

namespace {
void check(bool ok, std::string_view what) {
  std::println("{}: {}", ok ? "ok" : "FAILED", what);
  if (!ok) throw std::runtime_error(std::string(what));
}
std::string read_text(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(f)), {});
}
bytes read_file(const std::string& path) {
  return read_text(path) | std::views::transform([](char c) { return static_cast<byte>(c); }) | std::ranges::to<bytes>();
}
// One router session over a blocking socket, a command at a time.
struct xftp_link {
  int fd = -1;
  xftp::router_session session;
  std::deque<xftp::incoming::answered> answers;
  explicit xftp_link(const xftp::router& r) : session(r) {
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(r.port);
    inet_pton(AF_INET, r.host.c_str(), &where.sin_addr);
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval wait{20, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection");
  }
  void pump() {
    for (auto out = session.take_outgoing(); !out.empty();) {
      const auto n = ::send(fd, out.data(), out.size(), 0);
      if (n <= 0) throw std::runtime_error("send failed");
      out.erase(out.begin(), out.begin() + n);
    }
    std::array<byte, 65536> buffer{};
    const auto n = ::recv(fd, buffer.data(), buffer.size(), 0);
    if (n <= 0) throw std::runtime_error(n == 0 ? "closed" : "quiet for 20 seconds");
    session.received(std::span<const byte>(buffer.data(), static_cast<std::size_t>(n)));
    for (auto& in : session.take_incoming())
      spl::visit(spl::overloaded{[](const xftp::incoming::ready&) {}, [&](xftp::incoming::answered& a) { answers.push_back(std::move(a)); },
                                 [](const xftp::incoming::failed& f) { throw std::runtime_error(f.what); }},
                 in);
  }
  xftp::incoming::answered ask(const xftp::command_t& c, bytes entity, std::optional<crypto::private_key<curve::ed25519>> key, bytes chunk = {}) {
    const auto id = session.submit(c, std::move(entity), std::move(key), std::move(chunk));
    while (answers.empty() || answers.front().id != id) pump();
    auto a = std::move(answers.front());
    answers.pop_front();
    return a;
  }
};
}  // namespace

int main(int, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    crypto::system_random rng;
    // Theirs, received.
    const auto d = xfile::description_of(read_text(argv[1]));
    check(d.has_value(), "the xftp client's description read");
    std::println("  {} bytes sealed in {} chunk(s) of {}", d->size, d->chunks.size(), d->chunk_size);
    xftp_link l(d->chunks.front().replicas.front().router);
    bytes sealed;
    for (const auto& c : d->chunks) {
      const auto& r = c.replicas.front();
      const auto dh = crypto::generate<curve::x25519>(rng);
      const auto got = l.ask(xftp::command::get{dh.pub}, r.id, r.key);
      const auto* file = got.response.template get_if<xftp::response::file>();
      check(file != nullptr, std::format("chunk {}: FGET", c.number));
      const auto opened = xftp::open_chunk(*file, dh.priv, got.chunk);
      const auto digest = opened ? crypto::sha256(*opened) : std::array<byte, 32>{};
      check(opened && std::ranges::equal(digest, c.digest), std::format("chunk {}: opened, its digest as described", c.number));
      sealed.insert(sealed.end(), opened->begin(), opened->end());
      check(l.ask(xftp::command::acknowledge{}, r.id, r.key).response.template get_if<xftp::response::ok>() != nullptr, std::format("chunk {}: FACK", c.number));
    }
    check(std::ranges::equal(crypto::sha512(sealed), d->digest), "the file's digest as described");
    const auto file = xfile::open(sealed, d->key, d->nonce);
    check(file.has_value(), "the file opened");
    std::println("  its name: {}", file->head.file_name);
    check(file->content == read_file(argv[2]), "its bytes as the xftp client sent them");

    // Ours, sent: 300000 bytes, its description written for the xftp client.
    bytes content(300000);
    rng(std::span<byte>(content));
    const auto s = xfile::seal({"from quay.bin", std::nullopt}, content, rng);
    xfile::description ours{xfile::party::recipient{}, s.data.size(), {}, s.key, s.nonce, s.chunk_sizes.front(), {}};
    const auto file_digest = crypto::sha512(s.data);
    ours.digest.assign(file_digest.begin(), file_digest.end());
    std::size_t at = 0;
    const auto& router = d->chunks.front().replicas.front().router;
    for (std::size_t i = 0; i < s.chunk_sizes.size(); ++i) {
      const bytes piece(s.data.begin() + static_cast<std::ptrdiff_t>(at), s.data.begin() + static_cast<std::ptrdiff_t>(at + s.chunk_sizes[i]));
      at += s.chunk_sizes[i];
      const auto sender = crypto::generate<curve::ed25519>(rng), recipient = crypto::generate<curve::ed25519>(rng);
      const auto digest = crypto::sha256(piece);
      const auto created = l.ask(xftp::command::create{{sender.pub, s.chunk_sizes[i], bytes(digest.begin(), digest.end())}, {recipient.pub}}, {}, sender.priv);
      const auto* ids = created.response.template get_if<xftp::response::sender_ids>();
      check(ids != nullptr, std::format("our chunk {}: FNEW", i + 1));
      check(l.ask(xftp::command::put{}, ids->sender_id, sender.priv, piece).response.template get_if<xftp::response::ok>() != nullptr,
            std::format("our chunk {}: FPUT ({} bytes)", i + 1, piece.size()));
      ours.chunks.push_back({static_cast<std::uint32_t>(i + 1), s.chunk_sizes[i], bytes(digest.begin(), digest.end()), {{router, ids->recipient_ids.front(), recipient.priv}}});
    }
    std::ofstream(argv[3]) << xfile::text_of(ours);
    std::ofstream(std::string(argv[3]) + ".expected", std::ios::binary) << (content | std::views::transform([](byte b) { return static_cast<char>(b); }) | std::ranges::to<std::string>());
    // And our own description read back.
    const auto again = xfile::description_of(xfile::text_of(ours));
    check(again && again->chunks.size() == ours.chunks.size(), "our description reads back");
    std::println("live xfile: passed");
    return 0;
  } catch (const std::exception& failed) {
    std::println("live xfile: FAILED: {}", failed.what());
    return 1;
  }
}

// SPDX-License-Identifier: AGPL-3.0-only
// quay.xftp against xftp-server itself: TCP, TLS 1.3 (xftp/1), HTTP/2, the
// router authenticated and the hellos; then a chunk's life -- PING, FNEW
// with one recipient, FPUT of 64 KiB, FGET and the chunk opened, FACK,
// FDEL. The router is QUAY_XFTP_FINGERPRINT at QUAY_XFTP (127.0.0.1:15443).
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

using namespace quay;

namespace {
void check(bool ok, std::string_view what) {
  std::println("{}: {}", ok ? "ok" : "FAILED", what);
  if (!ok) throw std::runtime_error(std::string(what));
}
std::string said(const xftp::response_t& r) {
  return spl::visit(spl::overloaded{[](const xftp::response::sender_ids& x) { return std::format("SIDS ({} recipient)", x.recipient_ids.size()); },
                                    [](const xftp::response::recipient_ids&) { return std::string("RIDS"); },
                                    [](const xftp::response::file&) { return std::string("FILE"); },
                                    [](const xftp::response::ok&) { return std::string("OK"); },
                                    [](const xftp::response::error& e) { return "ERR " + e.what; },
                                    [](const xftp::response::pong&) { return std::string("PONG"); }},
                    r);
}
}  // namespace

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    const std::string address = std::getenv("QUAY_XFTP") ? std::getenv("QUAY_XFTP") : "127.0.0.1:15443";
    const auto identity = base64url_decode(std::getenv("QUAY_XFTP_FINGERPRINT") ? std::getenv("QUAY_XFTP_FINGERPRINT") : "");
    check(identity && identity->size() == 32, "the router's fingerprint");
    const auto colon = address.rfind(':');
    xftp::router router{*identity, address.substr(0, colon), static_cast<std::uint16_t>(std::stoi(address.substr(colon + 1)))};
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(router.port);
    inet_pton(AF_INET, router.host.c_str(), &where.sin_addr);
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval wait{20, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    check(::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) == 0, "connected over TCP");

    xftp::router_session s(router);
    std::deque<xftp::incoming::answered> answers;
    bool ready = false;
    const auto pump = [&] {
      for (auto out = s.take_outgoing(); !out.empty();) {
        const auto n = ::send(fd, out.data(), out.size(), 0);
        if (n <= 0) throw std::runtime_error("send failed");
        out.erase(out.begin(), out.begin() + n);
      }
      std::array<byte, 65536> buffer{};
      const auto n = ::recv(fd, buffer.data(), buffer.size(), 0);
      if (n <= 0) throw std::runtime_error(n == 0 ? "closed" : "quiet for 20 seconds");
      s.received(std::span<const byte>(buffer.data(), static_cast<std::size_t>(n)));
      for (auto& in : s.take_incoming())
        spl::visit(spl::overloaded{[&](const xftp::incoming::ready&) { ready = true; },
                                   [&](xftp::incoming::answered& a) { answers.push_back(std::move(a)); },
                                   [&](const xftp::incoming::failed& f) { throw std::runtime_error(f.what); }},
                   in);
    };
    const auto ask = [&](const xftp::command_t& c, bytes entity, std::optional<crypto::private_key<curve::ed25519>> key, bytes chunk = {}) {
      const auto id = s.submit(c, std::move(entity), std::move(key), std::move(chunk));
      while (answers.empty() || answers.front().id != id) pump();
      auto a = std::move(answers.front());
      answers.pop_front();
      std::println("  <- {}{}", said(a.response), a.chunk.empty() ? "" : std::format(", and {} bytes after it", a.chunk.size()));
      return a;
    };

    while (!ready) pump();
    check(ready, "TLS, HTTP/2, the router authenticated, the hellos");
    check(ask(xftp::command::ping{}, {}, std::nullopt).response.template get_if<xftp::response::pong>() != nullptr, "PING");

    crypto::system_random rng;
    const auto sender = crypto::generate<curve::ed25519>(rng);
    const auto recipient = crypto::generate<curve::ed25519>(rng);
    bytes chunk(xftp::chunk_sizes[0]);
    rng(std::span<byte>(chunk));
    const auto digest = crypto::sha256(chunk);
    const auto created = ask(xftp::command::create{{sender.pub, static_cast<std::uint32_t>(chunk.size()), bytes(digest.begin(), digest.end())}, {recipient.pub}},
                             {}, sender.priv);
    const auto* ids = created.response.template get_if<xftp::response::sender_ids>();
    check(ids && ids->recipient_ids.size() == 1, "FNEW: the chunk's ids");
    check(ask(xftp::command::put{}, ids->sender_id, sender.priv, chunk).response.template get_if<xftp::response::ok>() != nullptr, "FPUT: 64 KiB up");

    const auto dh = crypto::generate<curve::x25519>(rng);
    const auto got = ask(xftp::command::get{dh.pub}, ids->recipient_ids.front(), recipient.priv);
    const auto* file = got.response.template get_if<xftp::response::file>();
    check(file != nullptr, "FGET: the chunk, sealed to our key");
    const auto opened = xftp::open_chunk(*file, dh.priv, got.chunk);
    check(opened && *opened == chunk, "the chunk opened, as it was put");
    check(ask(xftp::command::acknowledge{}, ids->recipient_ids.front(), recipient.priv).response.template get_if<xftp::response::ok>() != nullptr, "FACK");
    check(ask(xftp::command::remove{}, ids->sender_id, sender.priv).response.template get_if<xftp::response::ok>() != nullptr, "FDEL");
    std::println("live xftp: passed");
    return 0;
  } catch (const std::exception& failed) {
    std::println("live xftp: FAILED: {}", failed.what());
    return 1;
  }
}

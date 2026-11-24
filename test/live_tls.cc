// SPDX-License-Identifier: AGPL-3.0-only
// quay.tls against smp-server itself, no relay: TCP to the router, TLS 1.3
// by quay.tls (ALPN smp/1), the router authenticated by quay.session from
// what quay.tls says -- its chain, our Finished -- then hellos, and a queue
// made and deleted. The router is QUAY_SMP_FINGERPRINT at QUAY_SMP_TLS
// (127.0.0.1:15223 by default).
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
import quay.smp;
import quay.session;
import quay.tls;

using namespace quay;

namespace {
int fd = -1;
bytes plain;  // what the router said, not yet taken as blocks

void check(bool ok, std::string_view what) {
  std::println("{}: {}", ok ? "ok" : "FAILED", what);
  if (!ok) throw std::runtime_error(std::string(what));
}
void write_all(std::span<const byte> data) {
  while (!data.empty()) {
    const auto n = ::send(fd, data.data(), data.size(), 0);
    if (n <= 0) throw std::runtime_error("send failed");
    data = data.subspan(static_cast<std::size_t>(n));
  }
}
// One read from the socket through TLS: its records answered, its plaintext kept.
void pump(tls::client& t) {
  std::array<byte, 16384> buffer{};
  const auto n = ::recv(fd, buffer.data(), buffer.size(), 0);
  if (n <= 0) throw std::runtime_error(n == 0 ? "closed" : "quiet for 20 seconds");
  const auto fed = t.received(std::span<const byte>(buffer.data(), static_cast<std::size_t>(n)));
  if (!fed) throw std::runtime_error(fed.error());
  write_all(t.take_outgoing());
  const auto got = t.take_incoming();
  plain.insert(plain.end(), got.begin(), got.end());
}
bytes read_block(tls::client& t) {
  while (plain.size() < smp::block_size) pump(t);
  bytes block(plain.begin(), plain.begin() + smp::block_size);
  plain.erase(plain.begin(), plain.begin() + smp::block_size);
  return block;
}
void send_block(tls::client& t, std::span<const byte> block) {
  const auto sent = t.send(block);
  if (!sent) throw std::runtime_error(sent.error());
  write_all(t.take_outgoing());
}
}  // namespace

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    const std::string address = std::getenv("QUAY_SMP_TLS") ? std::getenv("QUAY_SMP_TLS") : "127.0.0.1:15223";
    const auto identity = base64url_decode(std::getenv("QUAY_SMP_FINGERPRINT") ? std::getenv("QUAY_SMP_FINGERPRINT") : "");
    check(identity && identity->size() == 32, "the router's fingerprint");
    const auto colon = address.rfind(':');
    const std::string host = address.substr(0, colon);
    const auto port = static_cast<std::uint16_t>(std::stoi(address.substr(colon + 1)));
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &where.sin_addr);
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval wait{20, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    check(::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) == 0, "connected over TCP");

    tls::client t(host, port);
    write_all(t.take_outgoing());
    while (!t.ready()) pump(t);
    check(t.ready(), "TLS 1.3 up");
    std::println("  ALPN: {}", t.protocol());
    const auto facts = t.facts();
    check(facts.has_value(), "the chain and our Finished");
    std::println("  {} certificates, Finished {} bytes", facts->peer_chain.size(), facts->finished.size());

    const auto hello = smp::router_hello_of(read_block(t));
    check(hello.has_value(), "the router's hello");
    std::println("  versions {}-{}", hello->versions.min, hello->versions.max);
    const auto verified = session::verify(*hello, *identity, *facts);
    check(verified.has_value(), "the router authenticated through quay.tls: chain, pinned identity, signed session key, this session");
    // Another identity pinned: refused.
    auto other = *identity;
    other[0] ^= 1;
    check(!session::verify(*hello, other, *facts).has_value(), "another identity refused");
    const auto version = verified->version();
    send_block(t, *smp::client_hello(version, *identity));

    // A queue made and deleted, through it.
    crypto::system_random rng;
    const auto auth = crypto::generate<curve::ed25519>(rng);
    const auto dh = crypto::generate<curve::x25519>(rng);
    const auto command_of = [&](const bytes& entity, smp::command_t command) {
      smp::corr_id c{};
      rng(std::span<byte>(c));
      bytes body;
      smp::put_command(body, command);
      const smp::transmission tx{session::signature_over(*verified, auth.priv, c, entity, body), c, entity, std::move(body)};
      send_block(t, *smp::block_of(std::span(&tx, 1), version));
    };
    command_of({}, smp::command::create{auth.pub, dh.pub, std::nullopt, true, smp::queue_request_t(smp::queue_request::messaging{}), std::nullopt});
    const auto ids_block = read_block(t);
    const auto ids_tx = smp::transmissions_of(ids_block, version);
    check(ids_tx && !ids_tx->empty(), "an answer");
    const auto ids = smp::response_of(ids_tx->front().body);
    const auto* queue = ids ? ids->template get_if<smp::response::queue_ids>() : nullptr;
    check(queue != nullptr, "a queue made (IDS)");
    command_of(queue->recipient_id, smp::command::remove{});
    const auto del_block = read_block(t);
    const auto del_tx = smp::transmissions_of(del_block, version);
    check(del_tx && !del_tx->empty(), "an answer to DEL");
    const auto ok = smp::response_of(del_tx->front().body);
    check(ok && ok->template get_if<smp::response::ok>() != nullptr, "the queue deleted (DEL)");
    t.close();
    write_all(t.take_outgoing());
    std::println("live tls: passed");
    return 0;
  } catch (const std::exception& failed) {
    std::println("live tls: FAILED: {}", failed.what());
    return 1;
  }
}

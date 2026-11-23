// SPDX-License-Identifier: AGPL-3.0-only
// quay.tls_pin against a real router: through a TLS relay that tells what
// the TLS connection says (tools/tls_relay.py) -- the peer chain and the
// channel binding -- the router's hello verified against them and its
// pinned identity; and the same hello refused where any of them is wrong.
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

using namespace quay;

namespace {
int fd = -1;
bytes exactly(std::size_t n) {
  bytes out(n);
  std::size_t got = 0;
  while (got < n) {
    const auto r = ::recv(fd, out.data() + got, n - got, 0);
    if (r <= 0) throw std::runtime_error("the relay closed the connection");
    got += static_cast<std::size_t>(r);
  }
  return out;
}
std::size_t u16() {
  const auto b = exactly(2);
  return (std::size_t{b[0]} << 8) | b[1];
}
std::string said(const std::expected<session::verified, session::pin_error>& r) {
  if (r) return "verified";
  return spl::visit(spl::overloaded{[](const session::errors::chain_shape&) { return std::string("refused: chain shape"); },
                                    [](const session::errors::bad_certificate&) { return std::string("refused: bad certificate"); },
                                    [](const session::errors::chain_signature&) { return std::string("refused: chain signature"); },
                                    [](const session::errors::identity&) { return std::string("refused: not the pinned identity"); },
                                    [](const session::errors::chain_mismatch&) { return std::string("refused: hello chain is not the TLS chain"); },
                                    [](const session::errors::no_session_key&) { return std::string("refused: no session key"); },
                                    [](const session::errors::session_key_signature&) { return std::string("refused: session key not signed by the TLS leaf"); },
                                    [](const session::errors::session&) { return std::string("refused: not this TLS session"); },
                                    [](const session::errors::version&) { return std::string("refused: no common version"); }},
                    r.error());
}
}  // namespace

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  const auto identity = base64url_decode(std::getenv("QUAY_SMP_FINGERPRINT") ? std::getenv("QUAY_SMP_FINGERPRINT") : "");
  sockaddr_in where{};
  where.sin_family = AF_INET;
  where.sin_port = htons(15225);
  inet_pton(AF_INET, "127.0.0.1", &where.sin_addr);
  fd = ::socket(AF_INET, SOCK_STREAM, 0);
  timeval wait{20, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
  // The one place a C API asks for its own pointer type: sockaddr*.
  if (!identity || ::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) {
    std::println("live pin: FAILED: no relay or no fingerprint");
    return 1;
  }
  session::tls_facts facts;
  const auto count = exactly(1)[0];
  for (byte i = 0; i < count; ++i) facts.peer_chain.push_back(exactly(u16()));
  facts.finished = exactly(u16());
  std::println("the TLS side: {} certificates, Finished {} bytes", facts.peer_chain.size(), facts.finished.size());
  const auto hello = smp::router_hello_of(exactly(smp::block_size));
  if (!hello) {
    std::println("live pin: FAILED: no hello");
    return 1;
  }
  {
    std::string h;
    for (std::size_t i = 0; i < std::min<std::size_t>(80, hello->signed_key.size()); ++i) h += std::format("{:02x}", hello->signed_key[i]);
    std::println("the signed key ({} bytes): {}", hello->signed_key.size(), h);
  }
  bool ok = true;
  const auto check = [&](std::string_view what, const std::expected<session::verified, session::pin_error>& r, bool want) {
    std::println("{}: {}", what, said(r));
    ok = ok && r.has_value() == want;
  };
  check("the router as it is", session::verify(*hello, *identity, facts), true);
  auto other_identity = *identity;
  other_identity[0] ^= 1;
  check("another identity pinned", session::verify(*hello, other_identity, facts), false);
  auto other_session = facts;
  other_session.finished[0] ^= 1;
  check("another TLS session (a relayed hello)", session::verify(*hello, *identity, other_session), false);
  auto pasted = *hello;
  pasted.signed_key.back() ^= 1;
  check("a session key not signed by the leaf", session::verify(pasted, *identity, facts), false);
  auto short_chain = facts;
  short_chain.peer_chain.resize(1);
  check("a chain of one", session::verify(*hello, *identity, short_chain), false);
  auto swapped = facts;
  std::swap(swapped.peer_chain[0], swapped.peer_chain[1]);
  check("the chain's order changed", session::verify(*hello, *identity, swapped), false);
  std::println("live pin: {}", ok ? "passed" : "FAILED");
  return ok ? 0 : 1;
}

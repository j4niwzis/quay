// SPDX-License-Identifier: AGPL-3.0-only
// The live tests' socket around a quay.client session: a blocking TCP
// connection to the router, and the session pumped through it -- what it
// has to say written, one read fed to it. Included after the test's
// imports of std, quay.bytes, quay.smp and quay.client.

// A connection to the router's first host and port; reads time out after `seconds`.
inline int connect_to(const quay::smp::router& router, int seconds = 30) {
  sockaddr_in where{};
  where.sin_family = AF_INET;
  where.sin_port = htons(router.port.value_or(5223));
  inet_pton(AF_INET, router.hosts.front().c_str(), &where.sin_addr);
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  timeval wait{seconds, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
  // The one place a C API asks for its own pointer type: sockaddr*.
  if (::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection");
  return fd;
}
// What the session has to say, written.
inline void flush(int fd, quay::client::router_session& session) {
  for (auto out = session.take_outgoing(); !out.empty();) {
    const auto n = ::send(fd, out.data(), out.size(), 0);
    if (n <= 0) throw std::runtime_error("send failed");
    out.erase(out.begin(), out.begin() + n);
  }
}
// Written, then one read fed to it.
inline void pump(int fd, quay::client::router_session& session) {
  flush(fd, session);
  std::array<quay::byte, 16384> buffer{};
  const auto n = ::recv(fd, buffer.data(), buffer.size(), 0);
  if (n <= 0) throw std::runtime_error(n == 0 ? "closed" : "quiet for too long");
  session.received(std::span<const quay::byte>(buffer.data(), static_cast<std::size_t>(n)));
}

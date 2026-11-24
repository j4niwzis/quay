// SPDX-License-Identifier: AGPL-3.0-only
// The live tests' link to the router: TLS 1.3 by quay.tls over the socket
// `fd` the test has connected, one TLS client per socket. Included inside
// a test's anonymous namespace, after its `int fd` and its imports of std,
// quay.bytes, quay.session, quay.smp and quay.tls.

struct live_link {
  std::unique_ptr<quay::tls::client> tls;
  quay::bytes plain;  // what the router said, not yet taken as blocks
};
inline std::map<int, live_link> live_links;

inline void live_write(std::span<const quay::byte> data) {
  while (!data.empty()) {
    const auto n = ::send(fd, data.data(), data.size(), 0);
    if (n <= 0) throw std::runtime_error("send failed");
    data = data.subspan(static_cast<std::size_t>(n));
  }
}
// One read from the socket through TLS: its records answered, its plaintext kept.
inline void live_pump(live_link& link) {
  std::array<quay::byte, 16384> buffer{};
  const auto n = ::recv(fd, buffer.data(), buffer.size(), 0);
  if (n <= 0) throw std::runtime_error(n == 0 ? "closed" : "quiet for 20 seconds");
  const auto fed = link.tls->received(std::span<const quay::byte>(buffer.data(), static_cast<std::size_t>(n)));
  if (!fed) throw std::runtime_error(fed.error());
  live_write(link.tls->take_outgoing());
  const auto got = link.tls->take_incoming();
  link.plain.insert(link.plain.end(), got.begin(), got.end());
}
// The handshake on the socket just connected: what quay.session needs.
inline quay::session::tls_facts read_tls_facts() {
  auto& link = live_links[fd];
  link = live_link{std::make_unique<quay::tls::client>("127.0.0.1", 15223), {}};
  live_write(link.tls->take_outgoing());
  while (!link.tls->ready()) live_pump(link);
  const auto facts = link.tls->facts();
  if (!facts) throw std::runtime_error("TLS: no chain or Finished");
  return *facts;
}
inline void send_all(std::span<const quay::byte> data) {
  auto& link = live_links.at(fd);
  if (auto sent = link.tls->send(data); !sent) throw std::runtime_error(sent.error());
  live_write(link.tls->take_outgoing());
}
inline quay::bytes read_block() {
  auto& link = live_links.at(fd);
  while (link.plain.size() < quay::smp::block_size) live_pump(link);
  quay::bytes block(link.plain.begin(), link.plain.begin() + quay::smp::block_size);
  link.plain.erase(link.plain.begin(), link.plain.begin() + quay::smp::block_size);
  return block;
}

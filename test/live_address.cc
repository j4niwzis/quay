// SPDX-License-Identifier: AGPL-3.0-only
// quay's own contact address against simplex-chat's CLI: the address made
// and written out for the CLI to connect to (tools/live_cli_address.sh), its
// contact request accepted by joining the invitation it carries -- two state
// machines over one router connection -- and a message sent once connected.
// The router is the one the CLI's own invitation names.
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
import quay.ratchet;
import quay.agent;
import quay.connection;
import quay.chat;

using namespace quay;

namespace {
int fd = -1;

// What the TLS relay says first (tools/tls_relay.py): the peer chain, the Finished.
session::tls_facts read_tls_facts() {
  const auto exact = [](std::size_t n) {
    bytes out(n);
    std::size_t got = 0;
    while (got < n) {
      const auto r = ::recv(fd, out.data() + got, n - got, 0);
      if (r <= 0) throw std::runtime_error("the relay closed the connection");
      got += static_cast<std::size_t>(r);
    }
    return out;
  };
  const auto u16 = [&] {
    const auto b = exact(2);
    return (std::size_t{b[0]} << 8) | b[1];
  };
  session::tls_facts facts;
  const auto count = exact(1)[0];
  for (byte i = 0; i < count; ++i) facts.peer_chain.push_back(exact(u16()));
  facts.finished = exact(u16());
  return facts;
}
std::uint16_t agreed = 0;
std::optional<session::verified> verified;
crypto::system_random rng;
std::map<smp::corr_id, std::pair<int, std::uint64_t>> pending;  // to the address (0) or the connection (1)
void send_all(std::span<const byte> data) {
  while (!data.empty()) {
    const auto n = ::send(fd, data.data(), data.size(), 0);
    if (n <= 0) throw std::runtime_error("send failed");
    data = data.subspan(static_cast<std::size_t>(n));
  }
}
bytes read_block() {
  bytes out(smp::block_size);
  std::size_t got = 0;
  while (got < out.size()) {
    const auto n = ::recv(fd, out.data() + got, out.size() - got, 0);
    if (n <= 0) throw std::runtime_error(n == 0 ? "closed" : "quiet for 20 seconds");
    got += static_cast<std::size_t>(n);
  }
  return out;
}
std::string shown(std::span<const byte> b) {
  std::string out;
  for (const byte c : b.first(std::min<std::size_t>(200, b.size()))) out += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
  return out;
}
std::string link_path;
std::optional<connection::event::contact_request> requested;
bool is_connected = false;
void perform(int which, const connection::output& out) {
  for (const auto& a : out.actions) {
    smp::corr_id c{};
    rng(std::span<byte>(c));
    pending[c] = {which, a.id};
    const auto t = connection::transmission_of(a, *verified, c);
    send_all(*smp::block_of(std::span(&t, 1), agreed));
    std::println("  -> {} action {}", which == 0 ? "address" : "connection", a.id);
  }
  for (const auto& e : out.events)
    spl::visit(spl::overloaded{[](const connection::event::address& x) {
                                 std::println("event: our address: {}...", x.link.substr(0, 60));
                                 std::ofstream(link_path + ".tmp") << x.link;
                                 std::filesystem::rename(link_path + ".tmp", link_path);
                               },
                               [](const connection::event::contact_request& x) {
                                 std::println("event: a contact request: {}", shown(x.info));
                                 requested = x;
                               },
                               [](const connection::event::confirmed& x) { std::println("event: confirmed, their info: {}", shown(x.info)); },
                               [](const connection::event::connected&) {
                                 std::println("event: connected");
                                 is_connected = true;
                               },
                               [](const connection::event::message& x) {
                                 const auto chats = chat::messages_of(x.body);
                                 std::println("event: message {}: {}", x.id, chats ? std::format("{} chat message(s), the first {}", chats->size(), chats->front().event) : shown(x.body));
                               },
                               [](const connection::event::received& x) { std::println("event: receipt for our message {}", x.id); },
                               [](const connection::event::invitation&) {},
                               [](const connection::event::other&) { std::println("event: another agent message"); },
                               [](const connection::event::failed& x) { std::println("event: FAILED: {}", x.what); }},
               e);
}
}  // namespace

int main(int, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    std::ifstream file(argv[1]);
    const std::string text((std::istreambuf_iterator<char>(file)), {});
    const auto link = agent::link_of(text);
    if (!link) throw std::runtime_error("not a link");
    const auto router = spl::visit([](const auto& l) { return l.queues.front().address.router; }, *link);
    link_path = argv[2];
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(15225);
    inet_pton(AF_INET, "127.0.0.1", &where.sin_addr);
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval wait{20, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection");
    const auto facts = read_tls_facts();
    const auto hello = smp::router_hello_of(read_block());
    auto checked = session::verify(*hello, router.identity, facts);
    if (!checked) throw std::runtime_error("the router is not the one pinned (or not this TLS session's)");
    verified = std::move(*checked);
    agreed = verified->version();
    send_all(*smp::client_hello(agreed, router.identity));

    auto [addr, first] = connection::address::create(router, rng);
    perform(0, first);
    std::optional<connection::joining> conn;
    bool sent = false;
    for (int i = 0; i < 40; ++i) {
      bytes block;
      try {
        block = read_block();
      } catch (const std::exception& e) {
        std::println("({})", e.what());
        break;
      }
      for (const auto& t : *smp::transmissions_of(block, agreed)) {
        const auto r = smp::response_of(t.body);
        if (!r) continue;
        if (const auto* m = r->template get_if<smp::response::message>()) {
          if (t.entity == addr.queue_id()) perform(0, addr.delivered(*m, rng));
          else if (conn) perform(1, conn->delivered(*m, rng));
        } else if (t.correlation && pending.contains(*t.correlation)) {
          const auto [which, id] = pending[*t.correlation];
          if (which == 0) perform(0, addr.answered(id, *r, rng));
          else if (conn) perform(1, conn->answered(id, *r, rng));
        }
      }
      if (requested && !conn) {
        // Accepted: its invitation joined, our profile said.
        const std::string profile = R"({"v":"1-22","event":"x.info","params":{"profile":{"displayName":"quay address","fullName":""}}})";
        auto joined = connection::joining::join(requested->invitation, router, bytes(profile.begin(), profile.end()), rng);
        if (!joined) throw std::runtime_error(joined.error());
        std::println("accepting it");
        conn.emplace(std::move(joined->first));
        perform(1, joined->second);
      }
      if (is_connected && !sent) {
        const auto body = chat::body_of(chat::message_of(chat::event::message_new{chat::text_content("hello from quay's own address")}, "cXVheWFkZHI="));
        auto out = conn->send(body, rng);
        if (!out) throw std::runtime_error(out.error());
        std::println("sending our message {}", out->first);
        perform(1, out->second);
        sent = true;
      }
    }
    std::println("live address: {}", is_connected && sent ? "passed" : "FAILED");
    return is_connected && sent ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live address: FAILED: {}", failed.what());
    return 1;
  }
}

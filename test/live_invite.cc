// SPDX-License-Identifier: AGPL-3.0-only
// quay.connection's inviting side against simplex-chat's CLI: our
// invitation made by the state machine alone and either written out for the
// CLI to join (tools/live_cli_invite.sh), or -- given the CLI's contact
// address (tools/live_cli_contact.sh) -- sent to it as a contact request the
// CLI accepts; its confirmation allowed, and a message sent once connected.
// The router is the one the CLI's own invitation or address names.
// Over plain TCP to a TLS relay in front of the router.
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
std::map<smp::corr_id, std::uint64_t> pending;
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
bool confirmed = false;
void perform(const connection::output& out, bool& is_connected) {
  for (const auto& a : out.actions) {
    smp::corr_id c{};
    rng(std::span<byte>(c));
    pending[c] = a.id;
    const auto t = connection::transmission_of(a, *verified, c);
    send_all(*smp::block_of(std::span(&t, 1), agreed));
    std::println("  -> action {}", a.id);
  }
  for (const auto& e : out.events)
    spl::visit(spl::overloaded{[](const connection::event::invitation& x) {
                                 std::println("event: our invitation: {}...", x.link.substr(0, 60));
                                 std::ofstream(link_path + ".tmp") << x.link;
                                 std::filesystem::rename(link_path + ".tmp", link_path);
                               },
                               [](const connection::event::confirmed& x) {
                                 std::println("event: confirmed, their info: {}", shown(x.info));
                                 confirmed = true;
                               },
                               [&](const connection::event::connected&) {
                                 std::println("event: connected");
                                 is_connected = true;
                               },
                               [](const connection::event::message& x) {
                                 std::println("event: message {}{}", x.id, x.in_sequence ? "" : " (out of sequence)");
                                 const auto chats = chat::messages_of(x.body);
                                 if (!chats) return std::println("  not a chat message: {}", shown(x.body));
                                 for (const auto& m : *chats)
                                   spl::visit(spl::overloaded{[](const chat::event::info& i) { std::println("  chat: x.info, {}", i.profile.display_name); },
                                                              [](const chat::event::info_probe&) { std::println("  chat: x.info.probe"); },
                                                              [](const chat::event::message_new& n) { std::println("  chat: x.msg.new, {}", n.content.text); },
                                                              [&](const auto&) { std::println("  chat: {}", m.event); }},
                                              m.params.data());
                               },
                               [](const connection::event::received& x) { std::println("event: receipt for our message {}", x.id); },
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
    if (!link) throw std::runtime_error("not a link: " + text);
    // The CLI's invitation (only its router used), or its contact address.
    const auto queues = spl::visit([](const auto& l) { return l.queues; }, *link);
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
    const auto router = queues.front().address.router;
    auto checked = session::verify(*hello, router.identity, facts);
    if (!checked) throw std::runtime_error("the router is not the one pinned (or not this TLS session's)");
    verified = std::move(*checked);
    agreed = verified->version();
    send_all(*smp::client_hello(agreed, router.identity));

    link_path = argv[2];
    const std::string profile = R"({"v":"1-22","event":"x.info","params":{"profile":{"displayName":"quay inviting","fullName":""}}})";
    const std::string request = R"({"v":"1-22","event":"x.contact","params":{"profile":{"displayName":"quay inviting","fullName":""}}})";
    auto made = spl::visit(spl::overloaded{[&](const agent::link::invitation&) {
                                             return std::expected<std::pair<connection::inviting, connection::output>, std::string>(
                                                 connection::inviting::invite(router, bytes(profile.begin(), profile.end()), true, rng));
                                           },
                                           [&](const agent::link::contact& address) {
                                             std::println("through the CLI's contact address");
                                             return connection::inviting::invite_through(address, router, bytes(request.begin(), request.end()),
                                                                                         bytes(profile.begin(), profile.end()), true, rng);
                                           }},
                           *link);
    if (!made) throw std::runtime_error(made.error());
    auto& [conn, first] = *made;
    bool is_connected = false, sent = false;
    perform(first, is_connected);
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
          perform(conn.delivered(*m, rng), is_connected);
        } else if (t.correlation && pending.contains(*t.correlation)) {
          perform(conn.answered(pending[*t.correlation], *r, rng), is_connected);
        }
      }
      if (confirmed) {
        std::println("allowing it");
        confirmed = false;
        perform(conn.allow(), is_connected);
      }
      if (is_connected && !sent) {
        // As a program restarted would: the connection saved, and taken back from the bytes alone.
        const auto saved = conn.saved();
        auto back = connection::inviting::restored(saved);
        if (!back) throw std::runtime_error("the saved connection did not restore");
        conn = std::move(*back);
        std::println("connection saved ({} bytes) and restored", saved.size());
        // Long enough to go compressed: a zstd batch of one, as simplex-chat sends.
        const auto text = "hello from quay.chat, the inviting side, compressed: " + std::string(300, 'q');
        const auto body = chat::body_of(chat::message_of(chat::event::message_new{chat::text_content(text)}, "cXVheWNoYXQ="));
        std::println("our chat message: {} bytes as a compressed batch (from {})", body.size(), text.size());
        auto out = conn.send(body, rng);
        if (!out) throw std::runtime_error(out.error());
        std::println("sending our message {}", out->first);
        perform(out->second, is_connected);
        sent = true;
      }
    }
    std::println("live invite: {}", is_connected && sent ? "passed" : "FAILED");
    return is_connected && sent ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live invite: FAILED: {}", failed.what());
    return 1;
  }
}

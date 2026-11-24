// SPDX-License-Identifier: AGPL-3.0-only
// quay.client against simplex-chat's CLI, the way a bot is written: one
// router session (quay.client) carrying two connections' actions -- our
// contact address, and the connection made by accepting the CLI's request
// -- with a plain blocking socket around it; then a chat message sent and
// its receipt back. The router is the one the CLI's invitation names; our
// address is written out for the CLI to connect to (tools/live_cli_invite.sh).
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
import quay.agent;
import quay.connection;
import quay.chat;
import quay.client;

using namespace quay;

namespace {
constexpr std::uint64_t address_tag = 0, contact_tag = 1;

int connect_to(const smp::router& router) {
  sockaddr_in where{};
  where.sin_family = AF_INET;
  where.sin_port = htons(router.port.value_or(5223));
  inet_pton(AF_INET, router.hosts.front().c_str(), &where.sin_addr);
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  timeval wait{20, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
  // The one place a C API asks for its own pointer type: sockaddr*.
  if (::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection");
  return fd;
}
void write_all(int fd, std::span<const byte> data) {
  while (!data.empty()) {
    const auto n = ::send(fd, data.data(), data.size(), 0);
    if (n <= 0) throw std::runtime_error("send failed");
    data = data.subspan(static_cast<std::size_t>(n));
  }
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
    crypto::system_random rng;

    const int fd = connect_to(router);
    client::router_session session(router);
    auto [address, first] = connection::address::create(router, rng);
    session.submit(address_tag, first, rng);  // held until the session is ready
    std::optional<connection::joining> contact;
    bool connected = false, sent = false, receipt = false;

    const auto handle = [&](std::uint64_t tag, const connection::output& out) {
      session.submit(tag, out, rng);
      for (const auto& e : out.events)
        spl::visit(spl::overloaded{[&](const connection::event::address& a) {
                                     std::println("our address: {}...", a.link.substr(0, 50));
                                     std::ofstream(std::string(argv[2]) + ".tmp") << a.link;
                                     std::filesystem::rename(std::string(argv[2]) + ".tmp", argv[2]);
                                   },
                                   [&](const connection::event::contact_request& r) {
                                     std::println("a contact request: {}", std::string(r.info.begin(), r.info.begin() + std::min<std::size_t>(60, r.info.size())));
                                     const std::string profile = R"({"v":"1-22","event":"x.info","params":{"profile":{"displayName":"quay client","fullName":""}}})";
                                     auto joined = connection::joining::join(r.invitation, router, bytes(profile.begin(), profile.end()), rng);
                                     if (!joined) throw std::runtime_error(joined.error());
                                     contact.emplace(std::move(joined->first));
                                     session.submit(contact_tag, joined->second, rng);
                                   },
                                   [&](const connection::event::connected&) {
                                     std::println("connected");
                                     connected = true;
                                   },
                                   [&](const connection::event::message& m) {
                                     const auto chats = chat::messages_of(m.body);
                                     std::println("message {}: {}", m.id, chats && !chats->empty() ? chats->front().event : std::string("(not chat)"));
                                   },
                                   [&](const connection::event::received& r) {
                                     std::println("receipt for our message {}", r.id);
                                     receipt = true;
                                   },
                                   [](const connection::event::failed& f) { std::println("FAILED: {}", f.what); },
                                   [](const auto&) {}},
                   e);
    };

    for (int i = 0; i < 60 && !receipt; ++i) {
      write_all(fd, session.take_outgoing());
      std::array<byte, 16384> buffer{};
      const auto n = ::recv(fd, buffer.data(), buffer.size(), 0);
      if (n <= 0) throw std::runtime_error(n == 0 ? "closed" : "quiet for 20 seconds");
      session.received(std::span<const byte>(buffer.data(), static_cast<std::size_t>(n)));
      for (const auto& in : session.take_incoming())
        spl::visit(spl::overloaded{[&](const client::incoming::ready&) { std::println("the router authenticated, the session ready"); },
                                   [&](const client::incoming::failed& f) { throw std::runtime_error(f.what); },
                                   [&](const client::incoming::answered& a) {
                                     if (a.tag == address_tag) handle(a.tag, address.answered(a.action_id, a.response, rng));
                                     else if (contact) handle(a.tag, contact->answered(a.action_id, a.response, rng));
                                   },
                                   [&](const client::incoming::delivered& d) {
                                     if (d.queue_id == address.queue_id()) handle(address_tag, address.delivered(d.message, rng));
                                     else if (contact && d.queue_id == contact->queue_id()) handle(contact_tag, contact->delivered(d.message, rng));
                                   }},
                   in);
      if (connected && !sent) {
        const auto body = chat::body_of(chat::message_of(chat::event::message_new{chat::text_content("hello from quay.client")}, "cXVheWNsaWVudA=="));
        auto out = contact->send(body, rng);
        if (!out) throw std::runtime_error(out.error());
        handle(contact_tag, out->second);
        sent = true;
      }
    }
    write_all(fd, session.take_outgoing());
    std::println("live client: {}", receipt ? "passed" : "FAILED");
    return receipt ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live client: FAILED: {}", failed.what());
    return 1;
  }
}

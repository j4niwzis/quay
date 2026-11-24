// SPDX-License-Identifier: AGPL-3.0-only
// A group joined through its link: the CLI's group link (a contact address
// of the group's) given; quay sends its contact request there (x.contact);
// the CLI, as the group's host, joins quay's invitation saying
// x.grp.link.inv (the group, who hosts it, the member quay is to be); quay
// allows it saying x.info, says x.grp.link.mem once connected, and then
// takes the host's group message and answers in the group
// (tools/live_cli_group_link.sh checks the CLI's side).
// Usage: live_group_link <the group's link>
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

int main(int, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    std::ifstream file(argv[1]);
    const std::string text((std::istreambuf_iterator<char>(file)), {});
    const auto link = agent::link_of(text);
    const auto* address = link ? link->template get_if<agent::link::contact>() : nullptr;
    if (!address) throw std::runtime_error("not a contact address: " + text);
    const auto router = address->queues.front().address.router;
    crypto::system_random rng;
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(router.port.value_or(5223));
    inet_pton(AF_INET, router.hosts.front().c_str(), &where.sin_addr);
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval wait{30, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection");

    client::router_session session(router);
    const std::string name = std::format("quay{}", ::getpid());
    std::println("our name: {}", name);
    const chat::profile me{name, "", {}, {}, {}, {}};
    const auto request = chat::body_of(chat::message_of(chat::event::contact_request{me}), false);
    const auto info = chat::body_of(chat::message_of(chat::event::info{me}), false);
    auto made = connection::inviting::invite_through(*address, router, request, info, true, rng);
    if (!made) throw std::runtime_error(made.error());
    auto& [conn, first] = *made;
    bool allowed = false, connected = false, introduced = false, said = false, heard = false;
    std::vector<connection::output> later;
    const auto handle = [&](const connection::output& out) {
      session.submit(0, out, rng);
      for (const auto& e : out.events)
        spl::visit(spl::overloaded{[&](const connection::event::confirmed& c) {
                                     const auto chats = chat::messages_of(c.info);
                                     const auto* inv = chats && !chats->empty() ? chats->front().params.data().template get_if<chat::event::group_link_invite>() : nullptr;
                                     if (!inv || allowed) return;
                                     std::println("the host joins us: the group {}, hosted by {}, we are {} ({})", inv->invitation.group_profile.display_name,
                                                  inv->invitation.from_member_name, inv->invitation.invited_member.member_role, inv->invitation.invited_member.member_id);
                                     allowed = true;
                                     later.push_back(conn.allow());
                                   },
                                   [&](const connection::event::connected&) {
                                     std::println("our member connection: connected");
                                     connected = true;
                                   },
                                   [&](const connection::event::message& m) {
                                     const auto chats = chat::messages_of(m.body);
                                     if (!chats) return;
                                     for (const auto& c : *chats)
                                       spl::visit(spl::overloaded{[&](const chat::event::message_new& n) {
                                                                    std::println("group: x.msg.new: {}", n.content.text);
                                                                    heard = true;
                                                                  },
                                                                  [&](const auto&) { std::println("group: {}", c.event); }},
                                                  c.params.data());
                                   },
                                   [](const connection::event::failed& f) { std::println("FAILED: {}", f.what); },
                                   [](const auto&) {}},
                   e);
    };
    handle(first);
    for (int i = 0; i < 160 && !(said && heard); ++i) {
      for (auto out = session.take_outgoing(); !out.empty();) {
        const auto n = ::send(fd, out.data(), out.size(), 0);
        if (n <= 0) throw std::runtime_error("send failed");
        out.erase(out.begin(), out.begin() + n);
      }
      std::array<byte, 16384> buffer{};
      const auto n = ::recv(fd, buffer.data(), buffer.size(), 0);
      if (n <= 0) throw std::runtime_error(n == 0 ? "closed" : "quiet for 30 seconds");
      session.received(std::span<const byte>(buffer.data(), static_cast<std::size_t>(n)));
      for (const auto& in : session.take_incoming())
        spl::visit(spl::overloaded{[](const client::incoming::ready&) {}, [](const client::incoming::failed& f) { throw std::runtime_error(f.what); },
                                   [&](const client::incoming::answered& a) { handle(conn.answered(a.action_id, a.response, rng)); },
                                   [&](const client::incoming::delivered& d) {
                                     if (conn.owns(d.queue_id)) handle(conn.delivered(d.queue_id, d.message, rng));
                                   }},
                   in);
      for (auto todo = std::exchange(later, {}); const auto& out : todo) handle(out);
      if (connected && !introduced) {
        // As a member joining by a link says, once connected: who it is (x.grp.link.mem).
        auto out = conn.send(chat::body_of(chat::message_of(chat::event::group_link_member{me}, "cXVheWxpbmsxMjM0")), rng);
        if (!out) throw std::runtime_error(out.error());
        handle(out->second);
        introduced = true;
      }
      if (connected && heard && !said) {
        auto out = conn.send(chat::body_of(chat::message_of(chat::event::message_new{chat::text_content("hello, from quay, who came by the link")}, "cXVheWxpbmsyMzQ1")), rng);
        if (!out) throw std::runtime_error(out.error());
        handle(out->second);
        said = true;
        std::println("our group message sent");
      }
    }
    for (auto out = session.take_outgoing(); !out.empty();) {
      const auto n = ::send(fd, out.data(), out.size(), 0);
      if (n <= 0) break;
      out.erase(out.begin(), out.begin() + n);
    }
    ::sleep(2);
    std::println("live group link: {}", said && heard ? "passed" : "FAILED");
    return said && heard ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live group link: FAILED: {}", failed.what());
    return 1;
  }
}

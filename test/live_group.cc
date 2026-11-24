// SPDX-License-Identifier: AGPL-3.0-only
// A group of simplex-chat's CLI, joined by quay: quay joins the CLI's
// invitation (a contact); the CLI makes a group and invites quay (x.grp.inv);
// quay joins the group's invitation link with x.grp.acpt as its member
// connection's info -- a second connection on the same router session
// (quay.client) -- and once connected, takes the CLI's group message and
// sends its own into the group (tools/live_cli_group.sh checks the CLI got it).
// Usage: live_group <the CLI's invitation>
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
    const auto& inv = *link->template get_if<agent::link::invitation>();
    const auto router = inv.queues.front().address.router;
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
    const std::string profile = std::format(R"({{"v":"1-22","event":"x.info","params":{{"profile":{{"displayName":"{}","fullName":""}}}}}})", name);
    auto joined = connection::joining::join(inv, router, bytes(profile.begin(), profile.end()), rng);
    if (!joined) throw std::runtime_error(joined.error());
    std::array<std::optional<connection::joining>, 2> conns;  // 0: the contact, 1: our member connection
    conns[0].emplace(std::move(joined->first));
    session.submit(0, joined->second, rng);
    std::optional<chat::group_invitation> invited;
    bool member_connected = false, said = false, heard = false;

    const auto handle = [&](std::uint64_t tag, const connection::output& out) {
      session.submit(tag, out, rng);
      for (const auto& e : out.events)
        spl::visit(spl::overloaded{[&](const connection::event::connected&) {
                                     std::println("{}: connected", tag == 0 ? "the contact" : "our member connection");
                                     if (tag == 1) member_connected = true;
                                   },
                                   [&](const connection::event::confirmed& c) {
                                     if (tag == 1) std::println("the host's info: {}", std::string(c.info.begin(), c.info.begin() + std::min<std::size_t>(70, c.info.size())));
                                   },
                                   [&](const connection::event::message& m) {
                                     const auto chats = chat::messages_of(m.body);
                                     if (!chats) return;
                                     for (const auto& c : *chats)
                                       spl::visit(spl::overloaded{[&](const chat::event::group_invite& g) {
                                                                    std::println("invited to the group {} as {} ({})", g.group_invitation.group_profile.display_name,
                                                                                 g.group_invitation.invited_member.member_role, g.group_invitation.invited_member.member_id);
                                                                    invited = g.group_invitation;
                                                                  },
                                                                  [&](const chat::event::message_new& n) {
                                                                    std::println("{}: x.msg.new: {}", tag == 0 ? "contact" : "group", n.content.text);
                                                                    if (tag == 1) heard = true;
                                                                  },
                                                                  [&](const auto&) { std::println("{}: {}", tag == 0 ? "contact" : "group", c.event); }},
                                                  c.params.data());
                                   },
                                   [](const connection::event::failed& f) { std::println("FAILED: {}", f.what); },
                                   [](const auto&) {}},
                   e);
    };

    for (int i = 0; i < 120 && !(said && heard); ++i) {
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
                                   [&](const client::incoming::answered& a) {
                                     if (conns[a.tag]) handle(a.tag, conns[a.tag]->answered(a.action_id, a.response, rng));
                                   },
                                   [&](const client::incoming::delivered& d) {
                                     for (std::uint64_t tag = 0; tag < conns.size(); ++tag)
                                       if (conns[tag] && conns[tag]->owns(d.queue_id)) return handle(tag, conns[tag]->delivered(d.queue_id, d.message, rng));
                                   }},
                   in);
      if (invited && !conns[1]) {
        // Accepted: the group's invitation link joined, x.grp.acpt as what our member connection says.
        const auto group_link = agent::link_of(invited->connection_link);
        const auto* group_inv = group_link ? group_link->template get_if<agent::link::invitation>() : nullptr;
        if (!group_inv) throw std::runtime_error("the group invitation's link does not read");
        const auto accept = chat::body_of(chat::message_of(chat::event::group_accept{invited->invited_member.member_id, std::nullopt}), false);
        auto member = connection::joining::join(*group_inv, router, accept, rng);
        if (!member) throw std::runtime_error(member.error());
        conns[1].emplace(std::move(member->first));
        handle(1, member->second);
        std::println("joining the group");
      }
      if (member_connected && heard && !said) {
        const auto body = chat::body_of(chat::message_of(chat::event::message_new{chat::text_content("hello group, from quay")}, "cXVheWdyb3VwMTIz"));
        auto out = conns[1]->send(body, rng);
        if (!out) throw std::runtime_error(out.error());
        handle(1, out->second);
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
    std::println("live group: {}", said && heard ? "passed" : "FAILED");
    return said && heard ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live group: FAILED: {}", failed.what());
    return 1;
  }
}

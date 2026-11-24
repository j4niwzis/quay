// SPDX-License-Identifier: AGPL-3.0-only
// A group of simplex-chat's CLI, joined by quay: quay joins the CLI's
// invitation (a contact); the CLI makes a group and invites quay (x.grp.inv);
// quay joins the group's invitation link with x.grp.acpt as its member
// connection's info -- a second connection on the same router session
// (quay.client) -- and once connected, takes the CLI's group message and
// sends its own into the group (tools/live_cli_group.sh checks the CLI got it);
// with another member (QUAY_GROUP_FORWARD, tools/live_cli_group3.sh), takes
// that member's message as the host forwards it.
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
    const auto* invitation = link ? link->template get_if<agent::link::invitation>() : nullptr;
    if (!invitation) throw std::runtime_error("not an invitation link: " + text);
    const auto& inv = *invitation;
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
    std::optional<connection::inviting> member_link;  // 2: the member we were introduced to, joining our invitation
    std::optional<std::string> introduced_id;
    bool member_connected = false, said = false, heard = false, forwarded = false, allowed = false;
    const bool want_forward = std::getenv("QUAY_GROUP_FORWARD") != nullptr;

    std::optional<connection::output> pending_member_output;
    std::vector<std::pair<std::uint64_t, connection::output>> handle_later;
    const auto handle = [&](std::uint64_t tag, const connection::output& out) {
      session.submit(tag, out, rng);
      for (const auto& e : out.events)
        spl::visit(spl::overloaded{[&](const connection::event::invitation& i) {
                                     if (tag != 2) return;
                                     std::println("our invitation for the introduced member, sent to the host (x.grp.mem.inv)");
                                     const auto body = chat::body_of(chat::message_of(chat::event::group_member_invite{*introduced_id, {i.link}}));
                                     auto sent = conns[1]->send(body, rng);
                                     if (!sent) throw std::runtime_error(sent.error());
                                     handle_later.push_back({1, std::move(sent->second)});
                                   },
                                   [&](const connection::event::connected&) {
                                     std::println("{}: connected", tag == 0 ? "the contact" : tag == 1 ? "our member connection" : "the introduced member");
                                     if (tag == 1) member_connected = true;
                                   },
                                   [&](const connection::event::confirmed& c) {
                                     if (tag == 1) std::println("the host's info: {}", std::string(c.info.begin(), c.info.begin() + std::min<std::size_t>(70, c.info.size())));
                                     if (tag == 2 && !allowed) {
                                       std::println("the introduced member joins us: {}", std::string(c.info.begin(), c.info.begin() + std::min<std::size_t>(70, c.info.size())));
                                       allowed = true;
                                       handle_later.push_back({2, member_link->allow()});
                                     }
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
                                                                    std::println("{}: x.msg.new: {}", tag == 0 ? "contact" : tag == 1 ? "group (the host)" : "group (the member, directly)", n.content.text);
                                                                    if (tag == 1) heard = true;
                                                                    if (tag == 2) forwarded = true;  // the other member's message reached us
                                                                  },
                                                                  [&](const chat::event::group_forward& f) {
                                                                    spl::visit(spl::overloaded{[&](const chat::event::message_new& n) {
                                                                                                 std::println("group: forwarded from {}: {}", f.member_name.value_or("?"), n.content.text);
                                                                                                 forwarded = true;
                                                                                               },
                                                                                               [&](const auto&) { std::println("group: forwarded {}", f.message.event); }},
                                                                               f.message.params.data());
                                                                  },
                                                                  [&](const chat::event::group_member_intro& m) {
                                                                    std::println("group: introduced to {} ({})", m.member_info.profile.display_name, m.member_info.member_role);
                                                                    if (member_link) return;
                                                                    // Our invitation for it, its info x.grp.mem.info -- ours -- and no KEM, as simplex-chat makes these.
                                                                    const auto info = chat::body_of(
                                                                        chat::message_of(chat::event::group_member_info{invited->invited_member.member_id, chat::profile{name, "", {}, {}, {}, {}}}), false);
                                                                    auto [conn, first] = connection::inviting::invite(router, info, false, rng);
                                                                    member_link.emplace(std::move(conn));
                                                                    introduced_id = m.member_info.member_id;
                                                                    pending_member_output = std::move(first);
                                                                  },
                                                                  [&](const chat::event::group_member_new& m) {
                                                                    std::println("group: a new member, {}", m.member_info.profile.display_name);
                                                                  },
                                                                  [&](const auto&) { std::println("{}: {}", tag == 0 ? "contact" : "group", c.event); }},
                                                  c.params.data());
                                   },
                                   [](const connection::event::failed& f) { std::println("FAILED: {}", f.what); },
                                   [](const auto&) {}},
                   e);
    };

    for (int i = 0; i < 160 && !(said && heard && (forwarded || !want_forward)); ++i) {
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
                                     if (a.tag == 2 && member_link) handle(2, member_link->answered(a.action_id, a.response, rng));
                                     else if (a.tag < conns.size() && conns[a.tag]) handle(a.tag, conns[a.tag]->answered(a.action_id, a.response, rng));
                                   },
                                   [&](const client::incoming::delivered& d) {
                                     if (member_link && member_link->owns(d.queue_id)) return handle(2, member_link->delivered(d.queue_id, d.message, rng));
                                     for (std::uint64_t tag = 0; tag < conns.size(); ++tag)
                                       if (conns[tag] && conns[tag]->owns(d.queue_id)) return handle(tag, conns[tag]->delivered(d.queue_id, d.message, rng));
                                   }},
                   in);
      if (pending_member_output) handle(2, *std::exchange(pending_member_output, std::nullopt));
      for (auto later = std::exchange(handle_later, {}); auto& [tag, out] : later) handle(tag, out);
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
        // A group message goes to every member we are connected with: the host, and the member it introduced.
        auto out = conns[1]->send(body, rng);
        if (!out) throw std::runtime_error(out.error());
        handle(1, out->second);
        if (member_link && member_link->connected()) {
          auto direct = member_link->send(body, rng);
          if (!direct) throw std::runtime_error(direct.error());
          handle(2, direct->second);
          std::println("our group message sent to the introduced member as well");
        }
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
    const bool ok = said && heard && (forwarded || !want_forward);
    std::println("live group: {}", ok ? "passed" : "FAILED");
    return ok ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live group: FAILED: {}", failed.what());
    return 1;
  }
}

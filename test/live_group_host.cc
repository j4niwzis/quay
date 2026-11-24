// SPDX-License-Identifier: AGPL-3.0-only
// quay as a group's host, with simplex-chat's CLI as its member: quay joins
// the CLI's invitation (a contact), makes a group and invites the CLI
// (x.grp.inv: an invitation of quay's for the member connection, without
// KEM, its info x.grp.mem.info); the CLI joins the group (/j), its member
// connection says x.grp.acpt and quay allows it; then a message each way
// in the group (tools/live_cli_group_host.sh checks the CLI's side).
// Usage: live_group_host <the CLI's invitation> <the group's name>
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
std::string member_id(crypto::system_random& rng) {
  bytes id(12);
  rng(std::span<byte>(id));
  std::string out;
  put_base64url(out, id);
  return out;
}
}  // namespace

int main(int, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    std::ifstream file(argv[1]);
    const std::string text((std::istreambuf_iterator<char>(file)), {});
    const std::string group_name = argv[2];
    const auto link = agent::link_of(text);
    const auto* invitation = link ? link->template get_if<agent::link::invitation>() : nullptr;
    if (!invitation) throw std::runtime_error("not an invitation link: " + text);
    const auto router = invitation->queues.front().address.router;
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
    auto joined = connection::joining::join(*invitation, router, bytes(profile.begin(), profile.end()), rng);
    if (!joined) throw std::runtime_error(joined.error());
    std::optional<connection::joining> contact;
    contact.emplace(std::move(joined->first));
    session.submit(0, joined->second, rng);
    std::optional<connection::inviting> member;  // 1: the CLI's member connection, joining our invitation
    const auto ours = member_id(rng), theirs = member_id(rng);
    bool contact_connected = false, invited = false, member_connected = false, allowed = false, said = false, heard = false;
    std::vector<std::pair<std::uint64_t, connection::output>> later;

    const auto handle = [&](std::uint64_t tag, const connection::output& out) {
      session.submit(tag, out, rng);
      for (const auto& e : out.events)
        spl::visit(spl::overloaded{[&](const connection::event::invitation& i) {
                                     // The group invitation, over the contact.
                                     chat::group_invitation g{{ours, "owner"}, {theirs, "member"}, i.link, {group_name, "", {}, {}, {}}, std::nullopt, 2};
                                     auto sent = contact->send(chat::body_of(chat::message_of(chat::event::group_invite{g}, member_id(rng))), rng);
                                     if (!sent) throw std::runtime_error(sent.error());
                                     later.push_back({0, std::move(sent->second)});
                                     std::println("the CLI invited to {} (x.grp.inv)", group_name);
                                   },
                                   [&](const connection::event::confirmed& c) {
                                     if (tag != 1 || allowed) return;
                                     const auto said_ = chat::messages_of(c.info);
                                     const auto* accept = said_ && !said_->empty() ? said_->front().params.data().template get_if<chat::event::group_accept>() : nullptr;
                                     if (!accept || accept->member_id != theirs) throw std::runtime_error("the member connection did not say x.grp.acpt for the member invited");
                                     std::println("the CLI accepts (x.grp.acpt as {})", accept->member_id);
                                     allowed = true;
                                     later.push_back({1, member->allow()});
                                   },
                                   [&](const connection::event::connected&) {
                                     std::println("{}: connected", tag == 0 ? "the contact" : "the member connection");
                                     (tag == 0 ? contact_connected : member_connected) = true;
                                   },
                                   [&](const connection::event::message& m) {
                                     const auto chats = chat::messages_of(m.body);
                                     if (!chats) return;
                                     for (const auto& c : *chats)
                                       spl::visit(spl::overloaded{[&](const chat::event::message_new& n) {
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
                                   [&](const client::incoming::answered& a) {
                                     if (a.tag == 0) handle(0, contact->answered(a.action_id, a.response, rng));
                                     else if (member) handle(1, member->answered(a.action_id, a.response, rng));
                                   },
                                   [&](const client::incoming::delivered& d) {
                                     if (contact->owns(d.queue_id)) handle(0, contact->delivered(d.queue_id, d.message, rng));
                                     else if (member && member->owns(d.queue_id)) handle(1, member->delivered(d.queue_id, d.message, rng));
                                   }},
                   in);
      for (auto todo = std::exchange(later, {}); auto& [tag, out] : todo) handle(tag, out);
      if (contact_connected && !invited) {
        // The group made: our invitation for the CLI's member connection, no KEM, saying who we are in the group.
        const auto info = chat::body_of(chat::message_of(chat::event::group_member_info{ours, chat::profile{name, "", {}, {}, {}, {}}}), false);
        auto [conn, first] = connection::inviting::invite(router, info, false, rng);
        member.emplace(std::move(conn));
        handle(1, first);
        invited = true;
      }
      if (member_connected && heard && !said) {
        auto out = member->send(chat::body_of(chat::message_of(chat::event::message_new{chat::text_content("hello members, from your host quay")}, member_id(rng))), rng);
        if (!out) throw std::runtime_error(out.error());
        handle(1, out->second);
        std::println("our group message sent");
        // As its owner: the CLI made an admin, then the group deleted.
        for (const auto& body : {chat::body_of(chat::message_of(chat::event::group_member_role{theirs, "admin"}, member_id(rng))),
                                 chat::body_of(chat::message_of(chat::event::group_delete{}, member_id(rng)))}) {
          auto next = member->send(body, rng);
          if (!next) throw std::runtime_error(next.error());
          handle(1, next->second);
        }
        std::println("the CLI made an admin (x.grp.mem.role), the group deleted (x.grp.del)");
        said = true;
      }
    }
    for (auto out = session.take_outgoing(); !out.empty();) {
      const auto n = ::send(fd, out.data(), out.size(), 0);
      if (n <= 0) break;
      out.erase(out.begin(), out.begin() + n);
    }
    ::sleep(2);
    std::println("live group host: {}", said && heard ? "passed" : "FAILED");
    return said && heard ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live group host: FAILED: {}", failed.what());
    return 1;
  }
}

// SPDX-License-Identifier: AGPL-3.0-only
// quay hosting a group of two simplex-chat CLIs: quay joins each one's
// invitation (contacts), invites both into its group, and once the second
// has joined, introduces them to each other as simplex-chat's host does --
// x.grp.mem.new to the one there before, x.grp.mem.intro to the newcomer;
// the newcomer's x.grp.mem.inv (its invitation for the other) passed on as
// x.grp.mem.fwd -- so that the two connect directly and talk without quay
// (tools/live_cli_group_host3.sh checks that the first CLI hears the second).
// Usage: live_group_host3 <group name> <first CLI's invitation> <second CLI's invitation>
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

#include "live_client_io.h"

namespace {
crypto::system_random rng;
std::string new_id() {
  bytes id(12);
  rng(std::span<byte>(id));
  std::string out;
  put_base64url(out, id);
  return out;
}
struct member {
  std::optional<connection::joining> contact;   // tag 2i
  std::optional<connection::inviting> link;     // tag 2i+1: its member connection, joining our invitation
  std::optional<chat::profile> profile;
  std::string versions = "9-22";
  std::string id = new_id();
  bool contact_connected = false, invited = false, allowed = false, connected = false;
};
std::string text_of_file(const char* path) {
  std::ifstream f(path);
  return std::string((std::istreambuf_iterator<char>(f)), {});
}
}  // namespace

int main(int argc, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    const std::string group_name = argv[1];
    std::vector<member> members(static_cast<std::size_t>(argc - 2));
    std::vector<agent::link::invitation> invitations;
    for (int i = 2; i < argc; ++i) {
      const auto l = agent::link_of(text_of_file(argv[i]));
      const auto* inv = l ? l->template get_if<agent::link::invitation>() : nullptr;
      if (!inv) throw std::runtime_error("not an invitation link");
      invitations.push_back(*inv);
    }
    const auto router = invitations.front().queues.front().address.router;
    const int fd = connect_to(router);

    client::router_session session(router);
    const std::string name = std::format("quay{}", ::getpid());
    const std::string ours = new_id();
    std::println("our name: {}", name);
    const std::string profile_json = std::format(R"({{"v":"1-22","event":"x.info","params":{{"profile":{{"displayName":"{}","fullName":""}}}}}})", name);
    for (std::size_t i = 0; i < members.size(); ++i) {
      auto joined = connection::joining::join(invitations[i], router, bytes(profile_json.begin(), profile_json.end()), rng);
      if (!joined) throw std::runtime_error(joined.error());
      members[i].contact.emplace(std::move(joined->first));
      session.submit(2 * i, joined->second, rng);
    }
    std::vector<std::pair<std::uint64_t, connection::output>> later;
    bool forwarded = false, heard_second = false;
    std::optional<std::string> bob_message;  // the second member's message, to moderate
    const auto info_of = [&](const member& m) { return chat::event::member_info{m.id, "member", m.versions, *m.profile}; };
    const auto send_to_member = [&](std::size_t i, const auto& event) {
      auto sent = members[i].link->send(chat::body_of(chat::message_of(event, new_id())), rng);
      if (!sent) throw std::runtime_error(sent.error());
      later.push_back({2 * i + 1, std::move(sent->second)});
    };

    const auto handle = [&](std::uint64_t tag, const connection::output& out) {
      session.submit(tag, out, rng);
      const auto i = static_cast<std::size_t>(tag / 2);
      const bool is_link = tag % 2;
      auto& m = members[i];
      for (const auto& e : out.events)
        spl::visit(spl::overloaded{[&](const connection::event::invitation& inv) {
                                     chat::group_invitation g{{ours, "owner"}, {m.id, "member"}, inv.link, {group_name, "", {}, {}, {}}, std::nullopt,
                                                              static_cast<std::int64_t>(members.size() + 1)};
                                     auto sent = m.contact->send(chat::body_of(chat::message_of(chat::event::group_invite{g}, new_id())), rng);
                                     if (!sent) throw std::runtime_error(sent.error());
                                     later.push_back({2 * i, std::move(sent->second)});
                                     std::println("member {} invited (x.grp.inv)", i + 1);
                                   },
                                   [&](const connection::event::confirmed& c) {
                                     const auto said = chat::messages_of(c.info);
                                     if (!said || said->empty()) return;
                                     if (!is_link) {  // the contact's x.info: its profile, its versions
                                       if (const auto* x = said->front().params.data().template get_if<chat::event::info>()) m.profile = x->profile;
                                       if (said->front().v) m.versions = *said->front().v;
                                       return;
                                     }
                                     const auto* accept = said->front().params.data().template get_if<chat::event::group_accept>();
                                     if (!accept || accept->member_id != m.id || m.allowed) return;
                                     std::println("member {} accepts (x.grp.acpt)", i + 1);
                                     m.allowed = true;
                                     later.push_back({2 * i + 1, m.link->allow()});
                                   },
                                   [&](const connection::event::connected&) {
                                     if (!is_link) {
                                       m.contact_connected = true;
                                       std::println("contact {}: connected", i + 1);
                                       return;
                                     }
                                     m.connected = true;
                                     std::println("member {}: connected", i + 1);
                                     // Introduced: to each member there before, this one; to this one, each of them.
                                     for (std::size_t j = 0; j < members.size(); ++j) {
                                       if (j == i || !members[j].connected) continue;
                                       send_to_member(j, chat::event::group_member_new{info_of(m)});
                                       send_to_member(i, chat::event::group_member_intro{info_of(members[j])});
                                       std::println("member {} told of member {} (x.grp.mem.new), member {} introduced to member {} (x.grp.mem.intro)", j + 1, i + 1, i + 1, j + 1);
                                     }
                                   },
                                   [&](const connection::event::message& msg) {
                                     const auto chats = chat::messages_of(msg.body);
                                     if (!chats) return;
                                     for (const auto& c : *chats)
                                       spl::visit(spl::overloaded{[&](const chat::event::group_member_invite& inv) {
                                                                    // Its invitation for the member named: passed on to that member.
                                                                    const auto to = std::ranges::find(members, inv.member_id, &member::id);
                                                                    if (to == members.end()) return;
                                                                    send_to_member(static_cast<std::size_t>(to - members.begin()), chat::event::group_member_forward{info_of(m), inv.introduction});
                                                                    forwarded = true;
                                                                    std::println("member {}'s invitation passed on to member {} (x.grp.mem.fwd)", i + 1, to - members.begin() + 1);
                                                                  },
                                                                  [&](const chat::event::group_member_connected& con) {
                                                                    const auto with = std::ranges::find(members, con.member_id, &member::id);
                                                                    std::println("member {}: connected to member {} (x.grp.mem.con)", i + 1, with == members.end() ? 0 : with - members.begin() + 1);
                                                                  },
                                                                  [&](const chat::event::message_new& n) {
                                                                    std::println("{} {}: x.msg.new: {}", is_link ? "member" : "contact", i + 1, n.content.text);
                                                                    if (is_link && i == 1) {
                                                                      heard_second = true;
                                                                      bob_message = c.message_id;
                                                                    }
                                                                  },
                                                                  [&](const auto&) { std::println("{} {}: {}", is_link ? "member" : "contact", i + 1, c.event); }},
                                                  c.params.data());
                                   },
                                   [](const connection::event::failed& f) { std::println("FAILED: {}", f.what); },
                                   [](const auto&) {}},
                   e);
    };

    for (int round = 0; round < 200 && !(forwarded && heard_second); ++round) {
      pump(fd, session);
      for (const auto& in : session.take_incoming())
        spl::visit(spl::overloaded{[](const client::incoming::ready&) {}, [](const client::incoming::failed& f) { throw std::runtime_error(f.what); },
                                   [&](const client::incoming::answered& a) {
                                     auto& m = members[a.tag / 2];
                                     if (a.tag % 2 == 0) handle(a.tag, m.contact->answered(a.action_id, a.response, rng));
                                     else if (m.link) handle(a.tag, m.link->answered(a.action_id, a.response, rng));
                                   },
                                   [&](const client::incoming::delivered& d) {
                                     for (std::size_t i = 0; i < members.size(); ++i) {
                                       if (members[i].contact->owns(d.queue_id)) return handle(2 * i, members[i].contact->delivered(d.queue_id, d.message, rng));
                                       if (members[i].link && members[i].link->owns(d.queue_id)) return handle(2 * i + 1, members[i].link->delivered(d.queue_id, d.message, rng));
                                     }
                                   }},
                   in);
      for (auto todo = std::exchange(later, {}); auto& [tag, out] : todo) handle(tag, out);
      // The group made once every contact is up: each member invited in turn, the next once the one before has joined.
      for (std::size_t i = 0; i < members.size(); ++i) {
        auto& m = members[i];
        if (m.invited || !m.contact_connected || !m.profile || (i > 0 && !members[i - 1].connected)) continue;
        const auto info = chat::body_of(chat::message_of(chat::event::group_member_info{ours, chat::profile{name, "", {}, {}, {}, {}}}), false);
        auto [conn, first] = connection::inviting::invite(router, info, false, rng);
        m.link.emplace(std::move(conn));
        m.invited = true;
        handle(2 * i + 1, first);
      }
    }
    // As its owner: the second member's message moderated (x.msg.del with its
    // member id), then the member removed (x.grp.mem.del), told to everyone.
    if (bob_message) {
      for (std::size_t i = 0; i < members.size(); ++i) {
        send_to_member(i, chat::event::message_delete{*bob_message, members[1].id});
        send_to_member(i, chat::event::group_member_delete{members[1].id, std::nullopt});
      }
      for (auto todo = std::exchange(later, {}); auto& [tag, out] : todo) session.submit(tag, out, rng);
      std::println("the second member's message moderated (x.msg.del), the member removed (x.grp.mem.del)");
      // Long enough for the router to take them.
      for (int round = 0; round < 6; ++round) {
        for (auto out = session.take_outgoing(); !out.empty();) {
          const auto n = ::send(fd, out.data(), out.size(), 0);
          if (n <= 0) break;
          out.erase(out.begin(), out.begin() + n);
        }
        std::array<byte, 16384> buffer{};
        const auto n = ::recv(fd, buffer.data(), buffer.size(), MSG_DONTWAIT);
        if (n > 0) session.received(std::span<const byte>(buffer.data(), static_cast<std::size_t>(n)));
        for (const auto& in : session.take_incoming())
          spl::visit(spl::overloaded{[&](const client::incoming::answered& a) {
                                       auto& m = members[a.tag / 2];
                                       if (a.tag % 2 == 1 && m.link) session.submit(a.tag, m.link->answered(a.action_id, a.response, rng), rng);
                                     },
                                     [](const auto&) {}},
                     in);
        ::usleep(300000);
      }
    }
    flush(fd, session);
    ::sleep(2);
    std::println("live group host3: {}", forwarded && heard_second ? "passed" : "FAILED");
    return forwarded && heard_second ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live group host3: FAILED: {}", failed.what());
    return 1;
  }
}

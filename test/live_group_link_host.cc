// SPDX-License-Identifier: AGPL-3.0-only
// quay hosting a group's link: an address of the group's (its data naming
// the group link, as simplex-chat writes it), written out for the CLI to
// connect to; the CLI's contact request accepted by joining its invitation
// saying x.grp.link.inv -- the group, quay as its host, the member the CLI
// is to be -- and then a message each way in the group
// (tools/live_cli_group_link_host.sh checks the CLI's side).
// Usage: live_group_link_host <the CLI's invitation (for the router)> <where to write the link> <the group's name>
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
std::string random_id(crypto::system_random& rng, std::size_t n) {
  bytes id(n);
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
    const std::string group_name = argv[3];
    const auto link = agent::link_of(text);
    if (!link) throw std::runtime_error("not a link");
    const auto router = spl::visit([](const auto& l) { return l.queues.front().address.router; }, *link);
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
    const auto ours = random_id(rng, 12);
    // The group link's data, as simplex-chat's CReqClientData is written.
    const std::string data = std::format(R"({{"groupLinkId":"{}"}})", random_id(rng, 16));
    auto [address, first] = connection::address::create(router, rng, data);
    session.submit(0, first, rng);
    std::optional<connection::joining> member;  // 1
    bool connected = false, said = false, heard = false;

    const auto handle = [&](std::uint64_t tag, const connection::output& out) {
      session.submit(tag, out, rng);
      for (const auto& e : out.events)
        spl::visit(spl::overloaded{[&](const connection::event::address& a) {
                                     std::println("our group link: {}...", a.link.substr(0, 50));
                                     std::ofstream(std::string(argv[2]) + ".tmp") << a.link;
                                     std::filesystem::rename(std::string(argv[2]) + ".tmp", argv[2]);
                                   },
                                   [&](const connection::event::contact_request& r) {
                                     if (member) return;
                                     const auto said_ = chat::messages_of(r.info);
                                     const auto* request = said_ && !said_->empty() ? said_->front().params.data().template get_if<chat::event::contact_request>() : nullptr;
                                     std::println("a request by the link, from {}", request ? request->profile.display_name : std::string("?"));
                                     const chat::group_link_invitation g{{ours, "owner"}, name, {random_id(rng, 12), "member"}, {group_name, "", {}, {}, {}}, 2};
                                     auto joined = connection::joining::join(r.invitation, router, chat::body_of(chat::message_of(chat::event::group_link_invite{g}), false), rng);
                                     if (!joined) throw std::runtime_error(joined.error());
                                     member.emplace(std::move(joined->first));
                                     session.submit(1, joined->second, rng);
                                     std::println("accepted into {} (x.grp.link.inv)", group_name);
                                   },
                                   [&](const connection::event::connected&) {
                                     std::println("the member connection: connected");
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
                                                                  [&](const chat::event::group_link_member& l) { std::println("group: x.grp.link.mem, {}", l.profile.display_name); },
                                                                  [&](const auto&) { std::println("group: {}", c.event); }},
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
                                     if (a.tag == 0) handle(0, address.answered(a.action_id, a.response, rng));
                                     else if (member) handle(1, member->answered(a.action_id, a.response, rng));
                                   },
                                   [&](const client::incoming::delivered& d) {
                                     if (d.queue_id == address.queue_id()) handle(0, address.delivered(d.message, rng));
                                     else if (member && member->owns(d.queue_id)) handle(1, member->delivered(d.queue_id, d.message, rng));
                                   }},
                   in);
      if (connected && heard && !said) {
        auto out = member->send(chat::body_of(chat::message_of(chat::event::message_new{chat::text_content("welcome, from quay, the link's host")}, random_id(rng, 12))), rng);
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
    std::println("live group link host: {}", said && heard ? "passed" : "FAILED");
    return said && heard ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live group link host: FAILED: {}", failed.what());
    return 1;
  }
}

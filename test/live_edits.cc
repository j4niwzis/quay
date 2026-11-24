// SPDX-License-Identifier: AGPL-3.0-only
// Messages changed after they are sent, both ways, with simplex-chat's CLI:
// quay joins the CLI's invitation; the CLI sends a message, edits it, reacts
// to quay's, and deletes its own (tools/live_cli_edits.sh, through the
// CLI's API); quay takes each typed -- x.msg.update, x.msg.react,
// x.msg.del, by the message's shared id -- and does the same to the CLI:
// reacts to its message and edits its own (the wrapper checks the CLI's side).
// Usage: live_edits <the CLI's invitation>
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

int main(int, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    std::ifstream file(argv[1]);
    const std::string text((std::istreambuf_iterator<char>(file)), {});
    const auto link = agent::link_of(text);
    const auto* invitation = link ? link->template get_if<agent::link::invitation>() : nullptr;
    if (!invitation) throw std::runtime_error("not an invitation link: " + text);
    const auto router = invitation->queues.front().address.router;
    crypto::system_random rng;
    const int fd = connect_to(router);
    client::router_session session(router);
    const std::string name = std::format("quay{}", ::getpid());
    std::println("our name: {}", name);
    const auto profile = chat::body_of(chat::message_of(chat::event::info{chat::profile{name, "", {}, {}, {}, {}}}), false);
    auto joined = connection::joining::join(*invitation, router, profile, rng);
    if (!joined) throw std::runtime_error(joined.error());
    auto& [conn, first] = *joined;
    bool connected = false, ours_sent = false, answered = false, updated = false, reacted = false, deleted = false;
    std::optional<std::string> theirs;  // the CLI's message, by its shared id
    const std::string ours_id = "cXVheWVkaXQxMjM0";
    std::vector<connection::output> later;
    const auto send = [&](const chat::message& m) {
      auto out = conn.send(chat::body_of(m), rng);
      if (!out) throw std::runtime_error(out.error());
      later.push_back(std::move(out->second));
    };
    const auto handle = [&](const connection::output& out) {
      session.submit(0, out, rng);
      for (const auto& e : out.events)
        spl::visit(spl::overloaded{[&](const connection::event::connected&) {
                                     std::println("connected");
                                     connected = true;
                                   },
                                   [&](const connection::event::message& m) {
                                     const auto chats = chat::messages_of(m.body);
                                     if (!chats) return;
                                     for (const auto& c : *chats)
                                       spl::visit(spl::overloaded{[&](const chat::event::message_new& n) {
                                                                    std::println("x.msg.new {}: {}", c.message_id.value_or("?"), n.content.text);
                                                                    theirs = c.message_id;
                                                                  },
                                                                  [&](const chat::event::message_update& u) {
                                                                    std::println("x.msg.update {}: now {}", u.message_id, u.content.text);
                                                                    updated = theirs && u.message_id == *theirs;
                                                                  },
                                                                  [&](const chat::event::message_react& r) {
                                                                    std::println("x.msg.react {}: {} {}", r.message_id, r.add ? "added" : "removed", r.reaction.emoji.value_or(r.reaction.type));
                                                                    reacted = r.message_id == ours_id;
                                                                  },
                                                                  [&](const chat::event::message_delete& d) {
                                                                    std::println("x.msg.del {}", d.message_id);
                                                                    deleted = theirs && d.message_id == *theirs;
                                                                  },
                                                                  [&](const auto&) { std::println("{}", c.event); }},
                                                  c.params.data());
                                   },
                                   [](const connection::event::failed& f) { std::println("FAILED: {}", f.what); },
                                   [](const auto&) {}},
                   e);
    };
    handle(first);
    for (int i = 0; i < 200 && !(answered && updated && reacted && deleted); ++i) {
      pump(fd, session);
      for (const auto& in : session.take_incoming())
        spl::visit(spl::overloaded{[](const client::incoming::failed& f) { throw std::runtime_error(f.what); },
                                   [&](const client::incoming::answered& a) { handle(conn.answered(a.action_id, a.response, rng)); },
                                   [&](const client::incoming::delivered& d) {
                                     if (conn.owns(d.queue_id)) handle(conn.delivered(d.queue_id, d.message, rng));
                                   },
                                   [](const auto&) {}},
                   in);
      if (connected && !ours_sent) {
        send(chat::message_of(chat::event::message_new{chat::text_content("quay's first draft")}, ours_id));
        ours_sent = true;
        std::println("ours sent: {}", ours_id);
      }
      if (theirs && !answered) {
        // Ours changed, and theirs reacted to.
        send(chat::message_of(chat::event::message_update{ours_id, chat::text_content("quay's edited text"), std::nullopt, std::nullopt}, "cXVheWVkaXQyMzQ1"));
        send(chat::message_of(chat::event::message_react{*theirs, std::nullopt, chat::reaction{"emoji", "👍"}, true}, "cXVheWVkaXQzNDU2"));
        answered = true;
        std::println("ours edited (x.msg.update), theirs reacted to (x.msg.react)");
      }
      for (auto todo = std::exchange(later, {}); const auto& out : todo) handle(out);
    }
    flush(fd, session);
    ::sleep(2);
    const bool ok = answered && updated && reacted && deleted;
    std::println("live edits: {}", ok ? "passed" : "FAILED");
    return ok ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live edits: FAILED: {}", failed.what());
    return 1;
  }
}

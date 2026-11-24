// SPDX-License-Identifier: AGPL-3.0-only
// quay.connection against simplex-chat's CLI: its invitation joined by the
// state machine alone -- its actions sent, the router's answers and
// deliveries fed back, its events printed -- and a message sent once
// connected. Over TLS by quay.tls, straight to the router.
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
import quay.tls;
import quay.ratchet;
import quay.agent;
import quay.connection;
import quay.chat;

using namespace quay;

// The flow asked for: QUAY_FLOW=standard, or the fast one.
connection::flow flow_asked() {
  const char* asked = std::getenv("QUAY_FLOW");
  return asked && std::string_view(asked) == "standard" ? connection::flow::standard : connection::flow::fast;
}

namespace {
int fd = -1;

#include "live_io.h"
std::uint16_t agreed = 0;
std::optional<session::verified> verified;
crypto::system_random rng;
std::map<smp::corr_id, std::uint64_t> pending;
std::vector<agent::receipt> to_receipt;  // messages to send a receipt for
bool switched = false;  // the CLI's queue switched, QUSE answered
std::string shown(std::span<const byte> b) {
  std::string out;
  for (const byte c : b.first(std::min<std::size_t>(200, b.size()))) out += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
  return out;
}
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
    spl::visit(spl::overloaded{[](const connection::event::invitation&) { std::println("event: an invitation (not the joining side's)"); },
                               [](const connection::event::confirmed& x) { std::println("event: confirmed, their info: {}", shown(x.info)); },
                               [&](const connection::event::connected&) {
                                 std::println("event: connected");
                                 is_connected = true;
                               },
                               [](const connection::event::message& x) {
                                 // A chat message from the CLI: a receipt for it (sent by the loop).
                                 if (const auto chats = chat::messages_of(x.body)) {
                                   for (const auto& m : *chats)
                                     spl::visit(spl::overloaded{[&](const chat::event::message_new&) { to_receipt.push_back(agent::receipt{x.id, x.hash, {}}); },
                                                                [](const auto&) {}},
                                                m.params.data());
                                 }
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
                               [](const connection::event::other& o) {
                                 spl::visit(spl::overloaded{[](const agent::agent_message::message& m) {
                                                              spl::visit(spl::overloaded{[](const agent::a_message::add_queues&) { std::println("event: QADD, the CLI moves its queue"); },
                                                                                         [](const agent::a_message::use_queues&) {
                                                                                           std::println("event: QUSE, its new queue secured");
                                                                                           switched = true;
                                                                                         },
                                                                                         [](const auto&) { std::println("event: another agent message"); }},
                                                                         m.body);
                                                            },
                                                            [](const auto&) { std::println("event: another agent message"); }},
                                            o.message);
                               },
                               [](const connection::event::failed& x) { std::println("event: FAILED: {}", x.what); },
                               [](const connection::event::address&) { std::println("event: an address (not this test's)"); },
                               [](const connection::event::contact_request&) { std::println("event: a contact request (not this test's)"); }},
               e);
}
}  // namespace

int main(int, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    std::ifstream file(argv[1]);
    const std::string text((std::istreambuf_iterator<char>(file)), {});
    const auto link = agent::link_of(text);
    const auto& inv = *link->template get_if<agent::link::invitation>();
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(15223);
    inet_pton(AF_INET, "127.0.0.1", &where.sin_addr);
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval wait{20, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection");
    const auto facts = read_tls_facts();
    const auto hello = smp::router_hello_of(read_block());
    const auto router = inv.queues.front().address.router;
    auto checked = session::verify(*hello, router.identity, facts);
    if (!checked) throw std::runtime_error("the router is not the one pinned (or not this TLS session's)");
    verified = std::move(*checked);
    agreed = verified->version();
    send_all(*smp::client_hello(agreed, router.identity));

    const std::string name = std::format("quay{}", ::getpid());
    std::println("our name: {}", name);
    const std::string profile = std::format(R"({{"v":"1-22","event":"x.info","params":{{"profile":{{"displayName":"{}","fullName":""}}}}}})", name);
    auto joined = connection::joining::join(inv, router, bytes(profile.begin(), profile.end()), rng, flow_asked());
    if (!joined) throw std::runtime_error(joined.error());
    auto& [conn, first] = *joined;
    bool is_connected = false, sent = false, receipted = false, sent_after = false;
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
      if (!to_receipt.empty()) {
        auto out = conn.send_receipt(to_receipt, rng);
        if (!out) throw std::runtime_error(out.error());
        std::println("sending a receipt for message {}", to_receipt.front().message_id);
        perform(*out, is_connected);
        to_receipt.clear();
        receipted = true;
      }
      // The CLI's queue switched (QADD, QUSE answered): a message again, to the new queue.
      if (switched && !sent_after) {
        const auto body = chat::body_of(chat::message_of(chat::event::message_new{chat::text_content("hello again, on your new queue")}, "cXVheWFnYWlu"));
        auto out = conn.send(body, rng);
        if (!out) throw std::runtime_error(out.error());
        std::println("sending our message {} to the new queue", out->first);
        perform(out->second, is_connected);
        sent_after = true;
      }
      if (is_connected && !sent) {
        // As a program restarted would: the connection saved, and taken back from the bytes alone.
        const auto saved = conn.saved();
        auto back = connection::joining::restored(saved, conn.generation());
        if (!back) throw std::runtime_error("the saved connection did not restore");
        // An older generation asked for than the one saved: refused as stale.
        if (connection::joining::restored(saved, conn.generation() + 1)) throw std::runtime_error("a stale snapshot restored");
        conn = std::move(*back);
        std::println("connection saved ({} bytes) and restored", saved.size());
        // Long enough to go compressed: a zstd batch of one, as simplex-chat sends.
        const auto text = "hello from quay.chat, the joining side, compressed: " + std::string(300, 'q');
        const auto body = chat::body_of(chat::message_of(chat::event::message_new{chat::text_content(text)}, "cXVheWNoYXQ="));
        std::println("our chat message: {} bytes as a compressed batch (from {})", body.size(), text.size());
        auto out = conn.send(body, rng);
        if (!out) throw std::runtime_error(out.error());
        std::println("sending our message {}", out->first);
        perform(out->second, is_connected);
        sent = true;
      }
    }
    // Where the CLI switched its queue (QUAY_CLI_SWITCHES), a message sent to the new one too.
    if (std::getenv("QUAY_CLI_SWITCHES") && !sent_after) std::println("no message to the new queue");
    if (std::getenv("QUAY_CLI_SWITCHES") && !sent_after) return 1;
    // Where the CLI was asked to say something (QUAY_CLI_SAYS), a receipt sent for it too.
    const bool ok = is_connected && sent && (!std::getenv("QUAY_CLI_SAYS") || receipted);
    std::println("live connection: {}", ok ? "passed" : "FAILED");
    return ok ? 0 : 1;
  } catch (const std::exception& failed) {
    std::println("live connection: FAILED: {}", failed.what());
    return 1;
  }
}

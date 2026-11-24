// SPDX-License-Identifier: AGPL-3.0-only
// quay.smp against a real router (smp-server): the handshake, a queue made
// (NEW), a message sent to it as its sender (SEND, a confirmation), received
// as its recipient (MSG, both layers taken off), acknowledged (ACK), and the
// queue deleted (DEL). Over plain TCP to QUAY_SMP_ADDRESS (host:port) -- a
// TLS by quay.tls to the router -- whose identity is QUAY_SMP_FINGERPRINT.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <sys/time.h>
import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.smp;
import quay.session;
import quay.tls;

using namespace quay;
using namespace quay::smp;

namespace {
int fd = -1;

#include "live_io.h"
std::uint16_t agreed = 0;  // the version both speak
void check(bool ok, std::string_view what) {
  if (!ok) throw std::runtime_error(std::string(what));
  std::println("ok: {}", what);
}
crypto::system_random rng;
corr_id fresh() {
  corr_id c{};
  rng(std::span<byte>(c));
  return c;
}
std::string word_of(const response_t& r) {
  return spl::visit(spl::overloaded{[](const response::ok&) { return std::string("OK"); },
                                    [](const response::failed& f) {
                                      return spl::visit(spl::overloaded{[](const error::command&) { return std::string("ERR CMD"); },
                                                                        [](const error::auth&) { return std::string("ERR AUTH"); },
                                                                        [](const error::other& o) { return "ERR " + o.text; },
                                                                        [](const auto&) { return std::string("ERR ..."); }},
                                                        f.error);
                                    },
                                    [](const response::queue_ids&) { return std::string("IDS"); },
                                    [](const response::message&) { return std::string("MSG"); },
                                    [](const auto&) { return std::string("other"); }},
                    r);
}
// Responses as they come, until the one asked for.
template <class Want>
std::pair<transmission, Want> await(const std::optional<corr_id>& correlation = std::nullopt) {
  for (int blocks = 0; blocks < 10; ++blocks) {
    const auto all = transmissions_of(read_block(), agreed);
    if (!all) throw std::runtime_error("a block that does not read");
    for (const auto& t : *all) {
      const auto r = response_of(t.body);
      if (!r) throw std::runtime_error("a response that does not read");
      std::string said;
      for (const byte c : t.body) said += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
      std::println("  <- {} (corr {}, entity {} bytes): {}", word_of(*r), t.correlation ? "set" : "none", t.entity.size(), said.substr(0, 80));
      if (const auto* want = r->template get_if<Want>(); want && (!correlation || t.correlation == correlation)) return {t, *want};
      if (const auto* f = r->template get_if<response::failed>(); f && correlation && t.correlation == correlation)
        throw std::runtime_error("refused: " + word_of(*r));
    }
  }
  throw std::runtime_error("no such response");
}
}  // namespace

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);  // each line as it is said, though killed after
  try {
    const std::string address = std::getenv("QUAY_SMP_ADDRESS") ? std::getenv("QUAY_SMP_ADDRESS") : "127.0.0.1:15223";
    const auto identity = base64url_decode(std::getenv("QUAY_SMP_FINGERPRINT") ? std::getenv("QUAY_SMP_FINGERPRINT") : "");
    check(identity && identity->size() == 32, "the router's fingerprint");
    const auto colon = address.rfind(':');
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(static_cast<std::uint16_t>(std::stoi(address.substr(colon + 1))));
    inet_pton(AF_INET, address.substr(0, colon).c_str(), &where.sin_addr);
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    // Ten seconds for anything the router is to say: a silence said, not waited out.
    timeval wait{10, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    check(::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) == 0, "connected");

    const auto facts = read_tls_facts();
    const auto hello = router_hello_of(read_block());
    check(hello.has_value(), "the router's hello");
    std::println("  versions {}-{}, session id {} bytes, {} certificates", hello->versions.min, hello->versions.max, hello->session_id.size(),
                 hello->certificates.size());
    const auto version = agreed_version(hello->versions);
    check(version.has_value(), "a version both speak");
    // Its identity: the SHA-256 of its CA certificate's DER -- which of the
    // chain it is, said.
    const auto verified = session::verify(*hello, *identity, facts);
    check(verified.has_value(), "the router authenticated: its TLS chain, pinned identity, signed session key and TLS session");
    agreed = *version;
    send_all(*client_hello(*version, *identity));

    // A queue: the recipient's keys -- for its commands (Ed25519), for the
    // router's layer (X25519) -- and, for the sender's layer, the key a URI
    // would carry.
    const auto recipient_auth = crypto::generate<curve::ed25519>(rng);
    const auto recipient_dh = crypto::generate<curve::x25519>(rng);
    const auto recipient_e2e = crypto::generate<curve::x25519>(rng);
    command::create made{recipient_auth.pub, recipient_dh.pub, std::nullopt, true, queue_request_t(queue_request::messaging{}), std::nullopt};
    bytes body;
    put_command(body, made);
    const auto c1 = fresh();
    const transmission create{session::signature_over(*verified, recipient_auth.priv, c1, {}, body), c1, {}, body};
    send_all(*block_of(std::span(&create, 1), agreed));
    const auto [ids_t, ids] = await<response::queue_ids>(c1);
    check(!ids.recipient_id.empty() && !ids.sender_id.empty(), "a queue made (IDS)");

    // Its sender: a confirmation, its key in the clear, to the recipient's
    // E2E key; SEND unauthorized, the queue not secured yet.
    const auto sender_dh = crypto::generate<curve::x25519>(rng);
    const auto e2e_key = *crypto::box_key_of(recipient_e2e.pub, sender_dh.priv);
    const auto sealed = e2e_confirmation(e2e_key, 4, sender_dh.pub, std::nullopt, bytes{'h', 'e', 'l', 'l', 'o', ' ', 'q', 'u', 'a', 'y'}, rng);
    check(sealed.has_value(), "a confirmation sealed");
    bytes send_body;
    put_command(send_body, command::send{true, *sealed});
    const auto c2 = fresh();
    const transmission send{{}, c2, ids.sender_id, send_body};
    send_all(*block_of(std::span(&send, 1), agreed));

    // As its recipient (subscribed by NEW's 'S'): the message, both layers off.
    auto [msg_t, msg] = await<response::message>();
    check(msg_t.entity == ids.recipient_id, "a message for the queue (MSG)");
    const auto received = router_layer_off(*crypto::box_key_of(ids.server_dh, recipient_dh.priv), msg);
    check(received.has_value(), "the router's layer off");
    const auto* sent = received->template get_if<received::sent>();
    check(sent != nullptr, "a message, not a quota notice");
    const auto opened = e2e_open(sent->message, [&](const std::optional<public_key<curve::x25519>>& theirs) {
      return crypto::box_key_of(*theirs, recipient_e2e.priv);
    });
    check(opened.has_value(), "the sender's layer off");
    const auto* confirmation = opened->second.template get_if<e2e::confirmation>();
    check(confirmation && confirmation->body == bytes({'h', 'e', 'l', 'l', 'o', ' ', 'q', 'u', 'a', 'y'}), "its body as sent: hello quay");

    // Private message routing: the router asked to proxy to a destination
    // (itself, here) -- PRXY; the destination as the proxy says it (PKEY),
    // checked; a confirmation sent there through it (PFWD), the
    // destination's answer passed back (PRES); the message received.
    bytes prxy_body;
    put_command(prxy_body, command::proxy_session{router{*identity, {address.substr(0, colon)}, static_cast<std::uint16_t>(std::stoi(address.substr(colon + 1)))}, std::nullopt});
    const auto c5 = fresh();
    const transmission prxy{{}, c5, {}, prxy_body};
    send_all(*block_of(std::span(&prxy, 1), agreed));
    const auto [pkey_t, pkey] = await<response::proxy_session_key>(c5);
    check(!pkey.session_id.empty(), "PRXY: the proxy's session with the destination (PKEY)");
    const auto destination = session::verify_relayed(pkey, *identity);
    check(destination.has_value(), "the destination authenticated as the proxy relays it: its chain, pinned identity, signed session key");
    auto other = *identity;
    other[0] ^= 1;
    check(!session::verify_relayed(pkey, other).has_value(), "another identity refused");
    const auto sealed2 = e2e_confirmation(e2e_key, 4, sender_dh.pub, std::nullopt, bytes{'v', 'i', 'a', ' ', 'p', 'r', 'o', 'x', 'y'}, rng);
    const auto proxied = session::proxy_command(*destination, ids.sender_id, command::send{true, *sealed2}, std::nullopt, rng);
    check(proxied.has_value(), "a SEND sealed for the destination");
    bytes pfwd_body;
    put_command(pfwd_body, proxied->command);
    const transmission pfwd{{}, proxied->correlation, pkey.session_id, pfwd_body};
    send_all(*block_of(std::span(&pfwd, 1), agreed));
    const auto [pres_t, pres] = await<response::proxy_response>(proxied->correlation);
    const auto answer = session::proxied_response(*proxied, pres, destination->version());
    check(answer && answer->template get_if<response::ok>() != nullptr, "PFWD: the destination's OK, passed back (PRES)");
    // The first message acknowledged, the proxied one comes.
    bytes ack0;
    put_command(ack0, command::acknowledge{msg.id});
    const auto c6 = fresh();
    const transmission ack0_t{session::signature_over(*verified, recipient_auth.priv, c6, ids.recipient_id, ack0), c6, ids.recipient_id, ack0};
    send_all(*block_of(std::span(&ack0_t, 1), agreed));
    auto [via_t, via] = await<response::message>();
    const auto via_received = router_layer_off(*crypto::box_key_of(ids.server_dh, recipient_dh.priv), via);
    const auto* via_sent = via_received ? via_received->template get_if<received::sent>() : nullptr;
    const auto via_opened = via_sent ? e2e_open(via_sent->message, [&](const std::optional<public_key<curve::x25519>>& theirs) {
      return crypto::box_key_of(*theirs, recipient_e2e.priv);
    }) : std::unexpected(layer_error(decode_error(errors::short_input{})));
    const auto* via_confirmation = via_opened ? via_opened->second.template get_if<e2e::confirmation>() : nullptr;
    check(via_confirmation && via_confirmation->body == bytes({'v', 'i', 'a', ' ', 'p', 'r', 'o', 'x', 'y'}), "the message sent through the proxy received: via proxy");
    msg = via;

    bytes ack_body;
    put_command(ack_body, command::acknowledge{msg.id});
    const auto c3 = fresh();
    const transmission ack{session::signature_over(*verified, recipient_auth.priv, c3, ids.recipient_id, ack_body), c3, ids.recipient_id, ack_body};
    send_all(*block_of(std::span(&ack, 1), agreed));
    await<response::ok>(c3);
    check(true, "acknowledged (ACK)");

    bytes del_body;
    put_command(del_body, command::remove{});
    const auto c4 = fresh();
    const transmission del{session::signature_over(*verified, recipient_auth.priv, c4, ids.recipient_id, del_body), c4, ids.recipient_id, del_body};
    send_all(*block_of(std::span(&del, 1), agreed));
    await<response::ok>(c4);
    check(true, "the queue deleted (DEL)");
    std::println("live smp: passed");
    return 0;
  } catch (const std::exception& failed) {
    std::println("live smp: FAILED: {}", failed.what());
    return 1;
  }
}

// SPDX-License-Identifier: AGPL-3.0-only
// quay joins a one-time invitation simplex-chat's CLI made (the fast flow:
// SKEY), over a router reached through a TLS relay (QUAY_SMP_ADDRESS): its
// reply queue made, the invitation's queue secured, a confirmation sent (its
// ratchet parameters, and connection info -- a chat profile -- through the
// ratchet), the CLI's confirmation received and opened, a chat message sent,
// and what comes back read. Every step said.
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
import quay.ratchet;
import quay.agent;

using namespace quay;

namespace {
int fd = -1;
std::uint16_t agreed = 0;
bytes session;
crypto::system_random rng;
void send_all(std::span<const byte> data) {
  while (!data.empty()) {
    const auto n = ::send(fd, data.data(), data.size(), 0);
    if (n <= 0) throw std::runtime_error("send failed");
    data = data.subspan(static_cast<std::size_t>(n));
  }
}
bytes read_block() {
  bytes out(smp::block_size);
  std::size_t got = 0;
  while (got < out.size()) {
    const auto n = ::recv(fd, out.data() + got, out.size() - got, 0);
    if (n <= 0) throw std::runtime_error(n == 0 ? "the router closed the connection" : "the router said nothing for 20 seconds");
    got += static_cast<std::size_t>(n);
  }
  return out;
}
void step(std::string_view what) { std::println("ok: {}", what); }
smp::corr_id fresh() {
  smp::corr_id c{};
  rng(std::span<byte>(c));
  return c;
}
bytes text(std::string_view s) { return bytes(s.begin(), s.end()); }
std::string shown(std::span<const byte> b, std::size_t most = 300) {
  std::string out;
  for (const byte c : b.first(std::min(most, b.size()))) out += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
  return out;
}
// A command, signed by `key` where one is given, sent to `entity`.
smp::corr_id command(const smp::command_t& what, const bytes& entity, const crypto::private_key<curve::ed25519>* key) {
  bytes body;
  smp::put_command(body, what);
  const auto c = fresh();
  const smp::transmission t{key ? smp::signature_over(*key, session, c, entity, body) : bytes{}, c, entity, body};
  send_all(*smp::block_of(std::span(&t, 1), agreed));
  return c;
}
// Responses until the one for `c` (or, none given, a message).
std::pair<smp::transmission, smp::response_t> await(const std::optional<smp::corr_id>& c) {
  for (int blocks = 0; blocks < 20; ++blocks) {
    const auto all = smp::transmissions_of(read_block(), agreed);
    if (!all) throw std::runtime_error("a block that does not read");
    for (const auto& t : *all) {
      const auto r = smp::response_of(t.body);
      if (!r) throw std::runtime_error("a response that does not read: " + shown(t.body));
      std::println("  <- {}", shown(t.body, 40));
      if (const auto* f = r->template get_if<smp::response::failed>(); f && c && t.correlation == c)
        throw std::runtime_error("refused: " + shown(t.body));
      if (c && t.correlation == c) return {t, *r};
      if (!c && r->template get_if<smp::response::message>()) return {t, *r};
    }
  }
  throw std::runtime_error("nothing came");
}
}  // namespace

int main(int, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    std::ifstream file(argv[1]);
    const std::string invitation_text((std::istreambuf_iterator<char>(file)), {});
    const auto link = agent::link_of(invitation_text);
    if (!link || !link->template get_if<agent::link::invitation>()) throw std::runtime_error("the invitation does not read");
    const auto& inv = *link->template get_if<agent::link::invitation>();
    const auto& their_queue = inv.queues.front();
    step("the CLI's invitation read");

    const std::string address = std::getenv("QUAY_SMP_ADDRESS") ? std::getenv("QUAY_SMP_ADDRESS") : "127.0.0.1:15224";
    const auto colon = address.rfind(':');
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(static_cast<std::uint16_t>(std::stoi(address.substr(colon + 1))));
    inet_pton(AF_INET, address.substr(0, colon).c_str(), &where.sin_addr);
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval wait{20, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection");
    const auto hello = smp::router_hello_of(read_block());
    if (!hello) throw std::runtime_error("no hello");
    agreed = *smp::agreed_version(hello->versions);
    session = hello->session_id;
    send_all(*smp::client_hello(agreed, their_queue.address.router.identity));
    step(std::format("connected to the router, SMP v{}", agreed));

    // Our reply queue: our keys for it, its router layer's, and the E2E key
    // the CLI will encrypt to.
    const auto our_auth = crypto::generate<curve::ed25519>(rng);
    const auto our_router_dh = crypto::generate<curve::x25519>(rng);
    const auto our_e2e = crypto::generate<curve::x25519>(rng);
    const auto c1 = command(smp::command::create{our_auth.pub, our_router_dh.pub, std::nullopt, true,
                                                 smp::queue_request_t(smp::queue_request::messaging{}), std::nullopt},
                            {}, &our_auth.priv);
    const auto [ids_t, ids_r] = await(c1);
    const auto ids = *ids_r.template get_if<smp::response::queue_ids>();
    step("our reply queue made (NEW)");

    // The CLI's queue secured, as its sender, with our sender key (SKEY).
    const auto our_sender = crypto::generate<curve::ed25519>(rng);
    await(command(smp::command::sender_secure{our_sender.pub}, their_queue.address.sender_id, &our_sender.priv));
    step("the CLI's queue secured (SKEY)");

    // Our ratchet: our parameters (accepting its KEM key), the agreement,
    // the sending ratchet.
    const std::uint16_t e2e_version = std::min(inv.e2e.versions.max, ratchet::current_version);
    auto [our_params, our_private] = ratchet::make_params(e2e_version, inv.e2e.kem_key.has_value(), inv.e2e.kem_key, rng);
    ratchet::e2e_params theirs{e2e_version, inv.e2e.key1, inv.e2e.key2, std::nullopt};
    if (inv.e2e.kem_key) theirs.kem = ratchet::kem_params::proposed{*inv.e2e.kem_key};
    const auto agreed_ratchet = ratchet::x3dh_sending(our_private, theirs);
    if (!agreed_ratchet) throw std::runtime_error("no ratchet agreement");
    const auto own_dh = crypto::generate<curve::x448>(rng);
    ratchet::state rc = ratchet::sending_ratchet(e2e_version, ratchet::current_version, inv.e2e.key2, own_dh.priv, agreed_ratchet->first,
                                                 agreed_ratchet->second);
    const bool pq = rc.support_kem;
    step(std::format("our ratchet made (e2e v{}, PQ {})", e2e_version, pq ? "on" : "off"));

    // The confirmation: our reply queue and a chat profile, through the ratchet.
    const std::uint16_t agent_version = std::min<std::uint16_t>(inv.agent_versions.max, agent::current_agent_version);
    const agent::queue_info reply{agent::current_client_version,
                                  {smp::router{their_queue.address.router.identity, their_queue.address.router.hosts, their_queue.address.router.port},
                                   ids.sender_id, our_e2e.pub, agent::queue_mode_t(agent::queue_mode::messaging{})}};
    const std::string profile = R"({"v":"1-22","event":"x.info","params":{"profile":{"displayName":"quay","fullName":""}}})";
    bytes conn_info;
    agent::put_agent_message(conn_info, agent::agent_message::conn_info_reply{{reply}, text(profile)});
    const auto enc_info = ratchet::encrypt(rc, conn_info, agent::conn_info_length(pq), rng);
    if (!enc_info) throw std::runtime_error("the connection info not encrypted");
    bytes envelope;
    agent::put_envelope(envelope, agent::envelope::confirmation{agent_version, our_params, *enc_info});
    const auto sender_dh = crypto::generate<curve::x25519>(rng);
    const auto queue_key = *crypto::box_key_of(their_queue.address.dh, sender_dh.priv);
    const std::uint16_t client_version = std::min<std::uint16_t>(their_queue.client_versions.max, agent::current_client_version);
    const auto confirmation = smp::e2e_confirmation(queue_key, client_version, sender_dh.pub, std::nullopt, envelope, rng);
    if (!confirmation) throw std::runtime_error("the confirmation not sealed");
    await(command(smp::command::send{true, *confirmation}, their_queue.address.sender_id, &our_sender.priv));
    step(std::format("our confirmation sent (agent v{}, {} bytes)", agent_version, confirmation->size()));

    // The CLI's confirmation, on our reply queue.
    const auto [msg_t, msg_r] = await(std::nullopt);
    const auto& msg = *msg_r.template get_if<smp::response::message>();
    const auto received = smp::router_layer_off(*crypto::box_key_of(ids.server_dh, our_router_dh.priv), msg);
    if (!received || !received->template get_if<smp::received::sent>()) throw std::runtime_error("the router's layer not off");
    const auto opened = smp::e2e_open(received->template get_if<smp::received::sent>()->message,
                                      [&](const std::optional<public_key<curve::x25519>>& k) -> std::expected<crypto::box_key, crypto::crypto_error> {
                                        if (!k) return std::unexpected(crypto::errors::bad_key{});
                                        return crypto::box_key_of(*k, our_e2e.priv);
                                      });
    if (!opened) throw std::runtime_error("the sender's layer not off");
    const auto* their_confirmation = opened->second.template get_if<smp::e2e::confirmation>();
    if (!their_confirmation) throw std::runtime_error("not a confirmation");
    const auto their_envelope = agent::envelope_of(their_confirmation->body);
    if (!their_envelope) throw std::runtime_error("its envelope does not read");
    const auto* c_env = their_envelope->template get_if<agent::envelope::confirmation>();
    if (!c_env) throw std::runtime_error("not a confirmation envelope");
    const auto their_info = ratchet::decrypt(rc, c_env->encrypted, rng);
    if (!their_info) throw std::runtime_error("the CLI's connection info did not decrypt through our ratchet");
    const auto info_message = agent::agent_message_of(*their_info);
    if (!info_message) throw std::runtime_error("its agent message does not read");
    const auto* ci = info_message->template get_if<agent::agent_message::conn_info>();
    step(std::format("the CLI's confirmation opened through our ratchet: {}", ci ? shown(ci->info, 200) : std::string("(another message)")));
    await(command(smp::command::acknowledge{msg.id}, ids.recipient_id, &our_auth.priv));

    // A chat message to the CLI.
    bytes msg_id(12);
    rng(std::span<byte>(msg_id));
    std::string id_text;
    put_base64url(id_text, msg_id);
    const std::string chat = R"({"v":"1-22","msgId":")" + id_text + R"(","event":"x.msg.new","params":{"content":{"type":"text","text":"hello from quay"}}})";
    bytes agent_msg;
    agent::put_agent_message(agent_msg, agent::agent_message::message{{1, bytes{}}, agent::a_message::msg{text(chat)}});
    const auto enc_msg = ratchet::encrypt(rc, agent_msg, agent::agent_message_length(pq), rng);
    bytes msg_envelope;
    agent::put_envelope(msg_envelope, agent::envelope::message{agent_version, *enc_msg});
    const auto sealed = smp::e2e_message(queue_key, client_version, msg_envelope, rng);
    await(command(smp::command::send{true, *sealed}, their_queue.address.sender_id, &our_sender.priv));
    step("a chat message sent: hello from quay");

    // What else comes, for a while: printed.
    for (int i = 0; i < 3; ++i) {
      try {
        const auto [t, r] = await(std::nullopt);
        const auto& m = *r.template get_if<smp::response::message>();
        const auto rl = smp::router_layer_off(*crypto::box_key_of(ids.server_dh, our_router_dh.priv), m);
        const auto their_dh = their_confirmation->sender_dh;
        const auto ol = smp::e2e_open(rl->template get_if<smp::received::sent>()->message,
                                      [&](const auto&) { return crypto::box_key_of(their_dh, our_e2e.priv); });
        if (!ol) throw std::runtime_error("a later message's sender layer not off");
        const auto* em = ol->second.template get_if<smp::e2e::message>();
        const auto env = em ? agent::envelope_of(em->body) : std::expected<agent::envelope_t, decode_error>(std::unexpected(decode_error(quay::errors::short_input{})));
        const auto* menv = env ? env->template get_if<agent::envelope::message>() : nullptr;
        if (!menv) throw std::runtime_error("not a message envelope");
        const auto plain = ratchet::decrypt(rc, menv->encrypted, rng);
        if (!plain) throw std::runtime_error("a later message did not decrypt");
        const auto am = agent::agent_message_of(*plain);
        const auto* mm = am ? am->template get_if<agent::agent_message::message>() : nullptr;
        std::println("  from the CLI: agent message {}: {}", mm ? mm->header.id : 0, shown(*plain, 300));
        await(command(smp::command::acknowledge{m.id}, ids.recipient_id, &our_auth.priv));
      } catch (const std::exception& e) {
        std::println("  ({})", e.what());
        break;
      }
    }
    std::println("live join: passed");
    return 0;
  } catch (const std::exception& failed) {
    std::println("live join: FAILED: {}", failed.what());
    return 1;
  }
}

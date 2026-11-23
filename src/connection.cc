// SPDX-License-Identifier: AGPL-3.0-only
// quay.connection -- a SimpleX duplex connection, sans-IO: what it asks of
// routers is a list of actions (a command, to an entity, authorized by a
// key of the connection's), what routers answer and deliver is fed back,
// and what comes of it is a list of events. The joining side, by the fast
// flow (SKEY), as simplexmq's agent runs it: its reply queue made, the
// invitation's queue secured, a confirmation sent -- its ratchet
// parameters, and the connection info through the ratchet -- the other
// side's confirmation opened, then messages both ways, each acknowledged,
// numbered and hashed as the agent numbers and hashes them.
//
// The state is a plain value: the caller keeps it between calls, and
// across runs.
export module quay.connection;

import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.smp;
import quay.ratchet;
import quay.agent;
import quay.session;

export namespace quay::connection {

// What authorizes a command: nothing (a SEND to a queue not secured yet),
// or a key of the connection's.
namespace authorization {
struct none {};
struct signed_by {
  crypto::private_key<curve::ed25519> key;
};
}  // namespace authorization
using authorization_t = spl::variant<authorization::none, authorization::signed_by>;

// What the connection asks of a router: a command, its entity, how it is
// authorized; `id` comes back with the answer (answered()).
struct action {
  std::uint64_t id = 0;
  smp::router router;
  bytes entity;
  smp::command_t command;
  authorization_t authorization;
};
// The transmission an action is, in a verified session (its identifier signed).
inline smp::transmission transmission_of(const action& a, const session::verified& in, const smp::corr_id& correlation) {
  bytes body;
  smp::put_command(body, a.command);
  bytes auth = spl::visit(spl::overloaded{[](const authorization::none&) { return bytes{}; },
                                          [&](const authorization::signed_by& s) {
                                            return session::signature_over(in, s.key, correlation, a.entity, body);
                                          }},
                          a.authorization);
  return smp::transmission{std::move(auth), correlation, a.entity, std::move(body)};
}

// What comes of it.
namespace event {
struct confirmed {  // the other side's confirmation: its connection info
  bytes info;
};
struct connected {};
struct message {  // a message from the other side: its id, and whether it is the one expected
  std::uint64_t id = 0;
  bytes body;
  bool in_sequence = true;
};
struct received {  // a receipt for a message sent
  std::uint64_t id = 0;
};
struct other {  // an agent message this layer does not act on (queue rotation, ratchet sync)
  agent::agent_message_t message;
};
struct failed {
  std::string what;
};
}  // namespace event
using event_t = spl::variant<event::confirmed, event::connected, event::message, event::received, event::other, event::failed>;

struct output {
  std::vector<action> actions;
  std::vector<event_t> events;
};

// The joining side of a connection.
class joining {
 public:
  // An invitation joined: its queue, its parameters; our reply queue to be
  // made on `reply_router`; `info` what the other side is told (a chat profile).
  template <crypto::random_source R>
  static std::expected<std::pair<joining, output>, std::string> join(const agent::link::invitation& invitation, smp::router reply_router,
                                                                     bytes info, R& random) {
    joining c;
    c.their_queue_ = invitation.queues.front();
    c.reply_router_ = std::move(reply_router);
    c.info_ = std::move(info);
    c.agent_version_ = std::min<std::uint16_t>(invitation.agent_versions.max, agent::current_agent_version);
    c.client_version_ = std::min<std::uint16_t>(c.their_queue_.client_versions.max, agent::current_client_version);
    if (!agent::detail::sender_can_secure(c.their_queue_.address.mode)) return std::unexpected("the invitation's queue cannot be secured by its sender (no fast flow)");
    // Our keys: the reply queue's (its commands, the router's layer, the
    // other side's E2E), our sender key for theirs, our E2E key to it.
    c.rcv_auth_ = crypto::generate<curve::ed25519>(random);
    c.rcv_router_dh_ = crypto::generate<curve::x25519>(random);
    c.rcv_e2e_ = crypto::generate<curve::x25519>(random);
    c.snd_auth_ = crypto::generate<curve::ed25519>(random);
    c.snd_e2e_ = crypto::generate<curve::x25519>(random);
    // The ratchet: our parameters, accepting its KEM key where it proposed one.
    c.e2e_version_ = std::min(invitation.e2e.versions.max, ratchet::current_version);
    auto [params, priv] = ratchet::make_params(c.e2e_version_, invitation.e2e.kem_key.has_value(), invitation.e2e.kem_key, random);
    ratchet::e2e_params theirs{c.e2e_version_, invitation.e2e.key1, invitation.e2e.key2, std::nullopt};
    if (invitation.e2e.kem_key) theirs.kem = ratchet::kem_params::proposed{*invitation.e2e.kem_key};
    const auto agreed = ratchet::x3dh_sending(priv, theirs);
    if (!agreed) return std::unexpected("no ratchet agreement with the invitation's keys");
    const auto own_dh = crypto::generate<curve::x448>(random);
    c.ratchet_ = ratchet::sending_ratchet(c.e2e_version_, ratchet::current_version, invitation.e2e.key2, own_dh.priv, agreed->first, agreed->second);
    c.params_ = params;
    output out;
    out.actions.push_back(c.act(c.reply_router_, {},
                                smp::command::create{c.rcv_auth_.pub, c.rcv_router_dh_.pub, std::nullopt, true,
                                                     smp::queue_request_t(smp::queue_request::messaging{}), std::nullopt},
                                authorization::signed_by{c.rcv_auth_.priv}));
    c.step_ = step::creating_reply;
    return std::pair{std::move(c), std::move(out)};
  }

  // A router's answer to an action.
  template <crypto::random_source R>
  output answered(std::uint64_t action_id, const smp::response_t& response, R& random) {
    output out;
    if (const auto* f = response.template get_if<smp::response::failed>()) {
      (void)f;
      out.events.push_back(event::failed{"the router refused action " + std::to_string(action_id)});
      return out;
    }
    switch (step_) {
      case step::creating_reply: {
        const auto* ids = response.template get_if<smp::response::queue_ids>();
        if (!ids) return failed(out, "no queue ids for the reply queue");
        rcv_id_ = ids->recipient_id, rcv_snd_id_ = ids->sender_id, rcv_server_dh_ = ids->server_dh;
        out.actions.push_back(act(their_queue_.address.router, their_queue_.address.sender_id, smp::command::sender_secure{snd_auth_.pub},
                                  authorization::signed_by{snd_auth_.priv}));
        step_ = step::securing_theirs;
        return out;
      }
      case step::securing_theirs: {
        // The confirmation: our reply queue and our info, through the ratchet.
        const bool pq = ratchet_.support_kem;
        const agent::queue_info reply{agent::current_client_version,
                                      {reply_router_, rcv_snd_id_, rcv_e2e_.pub, agent::queue_mode_t(agent::queue_mode::messaging{})}};
        bytes conn_info;
        agent::put_agent_message(conn_info, agent::agent_message::conn_info_reply{{reply}, info_});
        const auto encrypted = ratchet::encrypt(ratchet_, conn_info, agent::conn_info_length(pq), random);
        if (!encrypted) return failed(out, "the connection info could not be encrypted");
        bytes envelope;
        agent::put_envelope(envelope, agent::envelope::confirmation{agent_version_, params_, *encrypted});
        const auto key = crypto::box_key_of(their_queue_.address.dh, snd_e2e_.priv);
        if (!key) return failed(out, "the invitation's queue key refuses ours");
        snd_key_ = *key;
        const auto sealed = smp::e2e_confirmation(snd_key_, client_version_, snd_e2e_.pub, std::nullopt, envelope, random);
        if (!sealed) return failed(out, "the confirmation could not be sealed");
        // The connection info is the sender's message 1, its hash what message 2 says came before.
        snd_message_id_ = 1;
        snd_previous_hash_ = agent::message_hash(conn_info);
        out.actions.push_back(act(their_queue_.address.router, their_queue_.address.sender_id, smp::command::send{true, *sealed},
                                  authorization::signed_by{snd_auth_.priv}));
        step_ = step::confirming;
        return out;
      }
      default:
        return out;  // an OK to a SEND or an ACK: nothing to do
    }
  }

  // A message the router delivered to our reply queue.
  template <crypto::random_source R>
  output delivered(const smp::response::message& got, R& random) {
    output out;
    const auto router_key = crypto::box_key_of(rcv_server_dh_, rcv_router_dh_.priv);
    if (!router_key) return failed(out, "no router key");
    const auto received = smp::router_layer_off(*router_key, got);
    // Whatever comes, acknowledged, so that the next is delivered.
    out.actions.push_back(act(reply_router_, rcv_id_, smp::command::acknowledge{got.id}, authorization::signed_by{rcv_auth_.priv}));
    if (!received) return failed(out, "the router's layer did not come off");
    const auto* sent = received->template get_if<smp::received::sent>();
    if (!sent) return out;  // a quota notice
    const auto opened = smp::e2e_open(sent->message, [&](const std::optional<public_key<curve::x25519>>& their_dh) {
      if (their_dh) rcv_their_e2e_ = *their_dh;
      if (!rcv_their_e2e_) return std::expected<crypto::box_key, crypto::crypto_error>(std::unexpected(crypto::errors::bad_key{}));
      return crypto::box_key_of(*rcv_their_e2e_, rcv_e2e_.priv);
    });
    if (!opened) return failed(out, "the sender's layer did not come off");
    const auto body = spl::visit(spl::overloaded{[](const smp::e2e::message& m) { return m.body; },
                                                 [](const smp::e2e::confirmation& c) { return c.body; }},
                                 opened->second);
    const auto envelope = agent::envelope_of(body);
    if (!envelope) return failed(out, "an envelope that does not read");
    const auto encrypted = spl::visit(spl::overloaded{[](const agent::envelope::confirmation& c) { return std::optional(c.encrypted); },
                                                      [](const agent::envelope::message& m) { return std::optional(m.encrypted); },
                                                      [](const auto&) { return std::optional<bytes>(); }},
                                      *envelope);
    if (!encrypted) return failed(out, "an envelope this side does not take");
    const auto plain = ratchet::decrypt(ratchet_, *encrypted, random);
    if (!plain) return failed(out, "a message the ratchet does not open");
    const auto message = agent::agent_message_of(*plain);
    if (!message) return failed(out, "an agent message that does not read");
    spl::visit(spl::overloaded{
                   [&](const agent::agent_message::conn_info& ci) {
                     rcv_message_id_ = 1;
                     rcv_previous_hash_ = agent::message_hash(*plain);
                     step_ = step::connected;
                     out.events.push_back(event::confirmed{ci.info});
                     out.events.push_back(event::connected{});
                   },
                   [&](const agent::agent_message::message& m) {
                     const bool in_sequence = m.header.id == rcv_message_id_ + 1 && m.header.previous_hash == rcv_previous_hash_;
                     rcv_message_id_ = m.header.id;
                     rcv_previous_hash_ = agent::message_hash(*plain);
                     spl::visit(spl::overloaded{[&](const agent::a_message::msg& x) { out.events.push_back(event::message{m.header.id, x.body, in_sequence}); },
                                                [&](const agent::a_message::received& x) {
                                                  for (const auto& r : x.receipts) out.events.push_back(event::received{r.message_id});
                                                },
                                                [&](const agent::a_message::hello&) {},
                                                [&](const auto&) { out.events.push_back(event::other{*message}); }},
                                m.body);
                   },
                   [&](const auto&) { out.events.push_back(event::other{*message}); }},
               *message);
    return out;
  }

  // A message sent to the other side: its id, and the action that sends it.
  template <crypto::random_source R>
  std::expected<std::pair<std::uint64_t, output>, std::string> send(std::span<const byte> body, R& random) {
    if (step_ != step::connected && step_ != step::confirming) return std::unexpected("not connected");
    const std::uint64_t id = ++snd_message_id_;
    bytes plain;
    agent::put_agent_message(plain, agent::agent_message::message{{id, snd_previous_hash_}, agent::a_message::msg{bytes(body.begin(), body.end())}});
    snd_previous_hash_ = agent::message_hash(plain);
    const auto encrypted = ratchet::encrypt(ratchet_, plain, agent::agent_message_length(ratchet_.support_kem), random);
    if (!encrypted) return std::unexpected("the message could not be encrypted (too large?)");
    bytes envelope;
    agent::put_envelope(envelope, agent::envelope::message{agent_version_, *encrypted});
    const auto sealed = smp::e2e_message(snd_key_, client_version_, envelope, random);
    if (!sealed) return std::unexpected("the message could not be sealed");
    output out;
    out.actions.push_back(act(their_queue_.address.router, their_queue_.address.sender_id, smp::command::send{true, *sealed},
                              authorization::signed_by{snd_auth_.priv}));
    return std::pair{id, std::move(out)};
  }

  [[nodiscard]] bool connected() const { return step_ == step::connected; }
  [[nodiscard]] bool post_quantum() const { return ratchet_.support_kem; }

 private:
  enum class step { creating_reply, securing_theirs, confirming, connected };
  action act(const smp::router& where, bytes entity, smp::command_t command, authorization_t auth) {
    return action{++actions_, where, std::move(entity), std::move(command), std::move(auth)};
  }
  output& failed(output& out, std::string what) {
    out.events.push_back(event::failed{std::move(what)});
    return out;
  }

  agent::queue_uri their_queue_;
  smp::router reply_router_;
  bytes info_;
  std::uint16_t agent_version_ = agent::current_agent_version, client_version_ = agent::current_client_version;
  std::uint16_t e2e_version_ = ratchet::current_version;
  crypto::key_pair<curve::ed25519> rcv_auth_, snd_auth_;
  crypto::key_pair<curve::x25519> rcv_router_dh_, rcv_e2e_, snd_e2e_;
  bytes rcv_id_, rcv_snd_id_;
  public_key<curve::x25519> rcv_server_dh_;
  std::optional<public_key<curve::x25519>> rcv_their_e2e_;
  crypto::box_key snd_key_{};
  ratchet::state ratchet_;
  ratchet::e2e_params params_;
  std::uint64_t snd_message_id_ = 0, rcv_message_id_ = 0, actions_ = 0;
  bytes snd_previous_hash_, rcv_previous_hash_;
  step step_ = step::creating_reply;
};

}  // namespace quay::connection

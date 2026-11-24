// SPDX-License-Identifier: AGPL-3.0-only
// quay.connection -- a SimpleX duplex connection, sans-IO: what it asks of
// routers is a list of actions (a command, to an entity, authorized by a
// key of the connection's), what routers answer and deliver is fed back,
// and what comes of it is a list of events. Both sides, by the fast flow
// (SKEY), as simplexmq's agent runs it:
//   - inviting: its queue made, the invitation link said; the joining
//     side's confirmation opened -- its ratchet parameters, its reply queue
//     and its info; then, allowed, the reply queue secured and our
//     confirmation sent;
//   - joining: its reply queue made, the invitation's queue secured, a
//     confirmation sent -- its ratchet parameters, and the connection info
//     through the ratchet -- the other side's confirmation opened;
// then messages both ways, each delivery acknowledged, numbered and hashed
// as the agent numbers and hashes them.
//
// A connection is moved, not copied (its ratchet's keys and IVs must not be
// used twice); the caller keeps it between calls -- and between runs, as
// the bytes saved() gives and restored() takes back (quay.snapshot).
//
// !!! KEEPING A CONNECTION: SAVE BEFORE YOU SEND. !!!
// Every call that returns actions has changed the connection -- its ratchet
// has used a message key and IV for what it asks to be sent. Save it after
// every such call and BEFORE sending any of its actions, and never restore
// a snapshot older than the last one saved: a stale snapshot encrypts again
// with keys and IVs already used, which breaks AES-GCM's confidentiality
// and integrity for those messages. Move-only state guards against copies
// in memory, not against an old file. To catch the wrong file, record
// generation() with every save (it grows with every action) and restore
// with restored(bytes, generation): an older snapshot is refused (stale).
export module quay.connection;

import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.smp;
import quay.ratchet;
import quay.agent;
import quay.session;
import quay.snapshot;

export namespace quay::connection {

// How a connection is made: by the fast flow, the joining side securing the
// invitation's queue itself (SKEY) and the inviting side the reply queue;
// or by the standard one, each side giving the other the key its SENDs are
// signed by, each securing its own queue with it (KEY), then HELLO both
// ways -- for peers whose queues do not let their senders secure them.
enum class flow : std::uint8_t { fast, standard };

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
                                          [&](const authorization::signed_by& s) { return session::signature_over(in, s.key, correlation, a.entity, body); }},
                          a.authorization);
  return smp::transmission{std::move(auth), correlation, a.entity, std::move(body)};
}

// What comes of it.
namespace event {
struct invitation {  // the inviting side's link, to be given to the other side out of band
  std::string link;
};
struct confirmed {  // the other side's confirmation: its connection info
  bytes info;
};
struct connected {};
struct message {  // a message from the other side: its id, whether it is the one expected, and its hash (for a receipt)
  std::uint64_t id = 0;
  bytes body;
  bool in_sequence = true;
  bytes hash;
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
struct address {  // our contact address, to be published
  std::string link;
};
struct contact_request {  // someone asking to connect through it: their invitation, joined to accept, and what they say (a chat x.contact)
  agent::link::invitation invitation;
  bytes info;
};
}  // namespace event
using event_t = spl::variant<event::invitation, event::confirmed, event::connected, event::message, event::received, event::other, event::failed,
                             event::address, event::contact_request>;

struct output {
  std::vector<action> actions;
  std::vector<event_t> events;
};

namespace detail {
// What both sides have: a queue they receive on, one they send to, the
// ratchet, and the counting and hashing of messages.
class duplex {
 public:
  duplex() = default;
  duplex(duplex&&) = default;
  duplex& operator=(duplex&&) = default;
  duplex(const duplex&) = delete;
  duplex& operator=(const duplex&) = delete;

  [[nodiscard]] bool connected() const { return connected_; }
  // Our queue moved to a new one on `router` (see next_receive). Only one
  // switch at a time, and none while the other side's is going on.
  template <crypto::random_source R>
  std::expected<output, std::string> switch_queue(smp::router router, R& random) {
    if (!connected_ || !snd_queue_) return std::unexpected("not connected");
    if (next_rcv_ || next_snd_) return std::unexpected("a switch is going on");
    next_receive n{std::move(router), {}, {}, crypto::generate<curve::ed25519>(random), crypto::generate<curve::x25519>(random),
                   crypto::generate<curve::x25519>(random), {}, std::nullopt};
    output out;
    out.actions.push_back(act(n.router, {}, smp::command::create{n.auth.pub, n.router_dh.pub, std::nullopt, true, std::nullopt, std::nullopt},
                              authorization::signed_by{n.auth.priv}));
    n.create_action = out.actions.back().id;
    next_rcv_ = std::move(n);
    return out;
  }
  [[nodiscard]] bool switching() const { return next_rcv_.has_value(); }
  // Whether a delivery for `queue_id` is this connection's (its queue, or the one it is moving to).
  [[nodiscard]] bool owns(std::span<const byte> queue_id) const {
    return std::ranges::equal(queue_id, rcv_id_) || (next_rcv_ && !next_rcv_->id.empty() && std::ranges::equal(queue_id, next_rcv_->id));
  }
  // How far it has gone: grows with every action it asks for, so with every
  // call that changed it. A snapshot of a lower generation is stale.
  [[nodiscard]] std::uint64_t generation() const { return actions_; }
  // The queue it receives on: a delivery for this id is this connection's.
  [[nodiscard]] const bytes& queue_id() const { return rcv_id_; }
  // Its queue subscribed to again -- in a new session with its router, as
  // after a restart: what waits in the queue is delivered then (delivered()).
  [[nodiscard]] output subscribe() {
    output out;
    if (!rcv_id_.empty()) out.actions.push_back(act(rcv_router_, rcv_id_, smp::command::subscribe{}, authorization::signed_by{rcv_auth_.priv}));
    return out;
  }
  [[nodiscard]] bool post_quantum() const { return ratchet_ && ratchet_->support_kem; }

  // A message sent to the other side: its id, and the action that sends it.
  template <crypto::random_source R>
  std::expected<std::pair<std::uint64_t, output>, std::string> send(std::span<const byte> body, R& random) {
    if (!ratchet_ || !snd_queue_) return std::unexpected("not connected");
    const std::uint64_t id = ++snd_message_id_;
    bytes plain;
    agent::put_agent_message(plain, agent::agent_message::message{{id, snd_previous_hash_}, agent::a_message::msg{bytes(body.begin(), body.end())}});
    output out;
    if (auto sent = send_agent_message(plain, random, out); !sent) return std::unexpected(sent.error());
    snd_previous_hash_ = agent::message_hash(plain);
    return std::pair{id, std::move(out)};
  }

  // What a snapshot of it holds: all of it.
  template <class D>
    requires std::same_as<std::remove_const_t<D>, duplex>
  friend auto snapshot_fields(D& d) {
    return std::tie(d.rcv_router_, d.rcv_id_, d.rcv_snd_id_, d.rcv_auth_, d.rcv_router_dh_, d.rcv_e2e_, d.rcv_server_dh_, d.rcv_their_e2e_,
                    d.snd_queue_, d.snd_their_dh_, d.snd_auth_, d.snd_e2e_, d.snd_key_, d.agent_version_, d.client_version_, d.ratchet_,
                    d.snd_message_id_, d.rcv_message_id_, d.actions_, d.snd_previous_hash_, d.rcv_previous_hash_, d.connected_,
                    d.flow_, d.awaiting_, d.got_hello_, d.next_snd_, d.next_rcv_);
  }

  // A receipt for messages received (A_RCVD): each by its id and hash, as
  // event::message gave them, with what the chat says of it (`info`, often
  // empty). The other side marks those messages delivered.
  template <crypto::random_source R>
  std::expected<output, std::string> send_receipt(std::span<const agent::receipt> receipts, R& random) {
    if (!ratchet_ || !snd_queue_ || !connected_) return std::unexpected("not connected");
    if (receipts.empty()) return std::unexpected("no receipt");
    const std::uint64_t id = ++snd_message_id_;
    bytes plain;
    agent::put_agent_message(plain, agent::agent_message::message{{id, snd_previous_hash_},
                                                                  agent::a_message::received{std::vector(receipts.begin(), receipts.end())}});
    output out;
    if (auto sent = send_agent_message(plain, random, out); !sent) return std::unexpected(sent.error());
    snd_previous_hash_ = agent::message_hash(plain);
    return out;
  }

 protected:
  action act(const smp::router& where, bytes entity, smp::command_t command, authorization_t auth) {
    return action{++actions_, where, std::move(entity), std::move(command), std::move(auth)};
  }
  static output& failed(output& out, std::string what) {
    out.events.push_back(event::failed{std::move(what)});
    return out;
  }
  template <crypto::random_source R>
  std::expected<void, std::string> send_agent_message(std::span<const byte> plain, R& random, output& out) {
    const auto encrypted = ratchet::encrypt(*ratchet_, plain, agent::agent_message_length(ratchet_->support_kem), random);
    if (!encrypted) return std::unexpected("the message could not be encrypted (too large?)");
    bytes envelope;
    agent::put_envelope(envelope, agent::envelope::message{agent_version_, *encrypted});
    const auto sealed = smp::e2e_message(snd_key_, client_version_, envelope, random);
    if (!sealed) return std::unexpected("the message could not be sealed");
    out.actions.push_back(act(snd_queue_->router, snd_queue_->sender_id, smp::command::send{true, *sealed}, authorization::signed_by{snd_auth_.priv}));
    return {};
  }
  // A delivery's two outer layers off, acknowledged: the sender's E2E
  // body (a confirmation's, or a message's).
  std::optional<smp::e2e_t> opened(const smp::response::message& got, output& out) {
    out.actions.push_back(act(rcv_router_, rcv_id_, smp::command::acknowledge{got.id}, authorization::signed_by{rcv_auth_.priv}));
    const auto router_key = crypto::box_key_of(rcv_server_dh_, rcv_router_dh_.priv);
    if (!router_key) return failed(out, "no router key"), std::nullopt;
    const auto received = smp::router_layer_off(*router_key, got);
    if (!received) return failed(out, "the router's layer did not come off"), std::nullopt;
    const auto* sent = received->template get_if<smp::received::sent>();
    if (!sent) return std::nullopt;  // a quota notice
    auto e2e = smp::e2e_open(sent->message, [&](const std::optional<public_key<curve::x25519>>& their_dh) {
      if (their_dh) rcv_their_e2e_ = *their_dh;
      if (!rcv_their_e2e_) return std::expected<crypto::box_key, crypto::crypto_error>(std::unexpected(crypto::errors::bad_key{}));
      return crypto::box_key_of(*rcv_their_e2e_, rcv_e2e_.priv);
    });
    if (!e2e) return failed(out, "the sender's layer did not come off"), std::nullopt;
    return std::move(e2e->second);
  }
  // An agent message through the ratchet: acted on, said as events.
  template <crypto::random_source R>
  void agent_message_in(std::span<const byte> encrypted, R& random, output& out) {
    const auto plain = ratchet::decrypt(*ratchet_, encrypted, random);
    if (!plain) return (void)failed(out, "a message the ratchet does not open");
    const auto message = agent::agent_message_of(*plain);
    if (!message) return (void)failed(out, "an agent message that does not read");
    spl::visit(spl::overloaded{
                   [&](const agent::agent_message::conn_info& ci) {
                     rcv_message_id_ = 1;
                     rcv_previous_hash_ = agent::message_hash(*plain);
                     out.events.push_back(event::confirmed{ci.info});
                     if (flow_ == flow::fast) {  // by the standard flow, HELLOs first
                       connected_ = true;
                       out.events.push_back(event::connected{});
                     }
                   },
                   [&](const agent::agent_message::message& m) {
                     const bool in_sequence = m.header.id == rcv_message_id_ + 1 && m.header.previous_hash == rcv_previous_hash_;
                     rcv_message_id_ = m.header.id;
                     rcv_previous_hash_ = agent::message_hash(*plain);
                     spl::visit(spl::overloaded{[&](const agent::a_message::msg& x) {
                                                  out.events.push_back(event::message{m.header.id, x.body, in_sequence, rcv_previous_hash_});
                                                },
                                                [&](const agent::a_message::received& x) {
                                                  for (const auto& r : x.receipts) out.events.push_back(event::received{r.message_id});
                                                },
                                                [&](const agent::a_message::hello&) { got_hello_ = true; },
                                                [&](const agent::a_message::add_queues& x) {
                                                  out.events.push_back(event::other{*message});
                                                  queues_added(x, random, out);
                                                },
                                                [&](const agent::a_message::use_queues& x) {
                                                  out.events.push_back(event::other{*message});
                                                  queues_used(x, random, out);
                                                },
                                                [&](const agent::a_message::queue_keys& x) {
                                                  out.events.push_back(event::other{*message});
                                                  queue_keys_in(x, out);
                                                },
                                                [&](const agent::a_message::test_queues&) {
                                                  out.events.push_back(event::other{*message});
                                                  if (next_rcv_ && next_rcv_->their_e2e) switch_done(out);
                                                },
                                                [&](const auto&) { out.events.push_back(event::other{*message}); }},
                                m.body);
                   },
                   [&](const auto&) { out.events.push_back(event::other{*message}); }},
               *message);
  }

  // The step's action awaited: its answer, and no other, moves the step on.
  action& expect(output& out, action a) {
    awaiting_ = a.id;
    out.actions.push_back(std::move(a));
    return out.actions.back();
  }
  // Our HELLO, the standard flow's: an agent message, numbered and hashed.
  template <crypto::random_source R>
  std::expected<void, std::string> send_hello(R& random, output& out) {
    const std::uint64_t id = ++snd_message_id_;
    bytes plain;
    agent::put_agent_message(plain, agent::agent_message::message{{id, snd_previous_hash_}, agent::a_message::hello{}});
    if (auto sent = send_agent_message(plain, random, out); !sent) return sent;
    snd_previous_hash_ = agent::message_hash(plain);
    return {};
  }

  // An agent message of ours sent: numbered and hashed in turn.
  template <crypto::random_source R>
  std::expected<void, std::string> send_a(agent::a_message_t body, R& random, output& out) {
    const std::uint64_t id = ++snd_message_id_;
    bytes plain;
    agent::put_agent_message(plain, agent::agent_message::message{{id, snd_previous_hash_}, std::move(body)});
    if (auto sent = send_agent_message(plain, random, out); !sent) return sent;
    snd_previous_hash_ = agent::message_hash(plain);
    return {};
  }
  // The other side moving the queue it receives on -- ours to send to --
  // to a new one, as simplexmq's agent switches queues: QADD gives the new
  // queue and the one it replaces; we answer QKEY on the old one -- our new
  // E2E key, and the key our SENDs to the new queue will be signed by, for
  // the other side to secure it with (KEY); QUSE says it is secured: from
  // then on we send to it, QTEST first.
  struct next_queue {
    agent::send_queue_address address;
    crypto::key_pair<curve::ed25519> auth;
    crypto::key_pair<curve::x25519> e2e;
    crypto::box_key key{};
    std::uint16_t client_version = agent::current_client_version;
  };
  template <crypto::random_source R>
  void queues_added(const agent::a_message::add_queues& x, R& random, output& out) {
    if (x.queues.empty() || !snd_queue_) return;
    const auto& [uri, replaced] = x.queues.front();
    if (!replaced || *replaced != *snd_queue_) return (void)failed(out, "QADD: not replacing the queue we send to");
    next_queue n{{uri.address.router, uri.address.sender_id},
                 crypto::generate<curve::ed25519>(random),
                 crypto::generate<curve::x25519>(random),
                 {},
                 std::min<std::uint16_t>(uri.client_versions.max, agent::current_client_version)};
    const auto key = crypto::box_key_of(uri.address.dh, n.e2e.priv);
    if (!key) return (void)failed(out, "QADD: the new queue's key refuses ours");
    n.key = *key;
    const agent::queue_info info{n.client_version, {n.address.router, n.address.sender_id, n.e2e.pub, uri.address.mode}};
    if (auto sent = send_a(agent::a_message::queue_keys{{{info, smp::auth_key(n.auth.pub)}}}, random, out); !sent) return (void)failed(out, sent.error());
    next_snd_ = std::move(n);
  }
  template <crypto::random_source R>
  void queues_used(const agent::a_message::use_queues& x, R& random, output& out) {
    if (x.queues.empty() || !next_snd_ || x.queues.front().first != next_snd_->address) return (void)failed(out, "QUSE: not the queue we were given");
    snd_queue_ = next_snd_->address;
    snd_auth_ = next_snd_->auth;
    snd_e2e_ = next_snd_->e2e;
    snd_key_ = next_snd_->key;
    client_version_ = next_snd_->client_version;
    next_snd_.reset();
    if (auto sent = send_a(agent::a_message::test_queues{{*snd_queue_}}, random, out); !sent) return (void)failed(out, sent.error());
  }
  std::optional<next_queue> next_snd_;

  // Our own queue moved to a new one, as simplexmq's agent switches: the new
  // queue made (NEW), QADD to the other side -- it and the queue it
  // replaces; its QKEY gives its new E2E key and the key its SENDs to the
  // new queue are signed by: the new queue secured with it (KEY), QUSE
  // sent; its QTEST on the new queue ends it: the old queue deleted.
  struct next_receive {
    smp::router router;
    bytes id, snd_id;
    crypto::key_pair<curve::ed25519> auth;
    crypto::key_pair<curve::x25519> router_dh, e2e;
    public_key<curve::x25519> server_dh;
    std::optional<public_key<curve::x25519>> their_e2e;
    std::uint64_t create_action = 0, secure_action = 0;
  };
  std::optional<next_receive> next_rcv_;
  // An answer to one of the switch's actions: taken here (true), or not one of them.
  template <crypto::random_source R>
  bool switch_answered(std::uint64_t action_id, const smp::response_t& response, R& random, output& out) {
    if (!next_rcv_) return false;
    if (action_id == next_rcv_->create_action) {
      const auto* ids = response.template get_if<smp::response::queue_ids>();
      if (!ids) return failed(out, "no queue ids for our new queue"), true;
      next_rcv_->id = ids->recipient_id, next_rcv_->snd_id = ids->sender_id, next_rcv_->server_dh = ids->server_dh;
      const agent::queue_uri uri{{1, agent::current_client_version}, {next_rcv_->router, next_rcv_->snd_id, next_rcv_->e2e.pub, std::nullopt}};
      if (auto sent = send_a(agent::a_message::add_queues{{{uri, agent::send_queue_address{rcv_router_, rcv_snd_id_}}}}, random, out); !sent)
        failed(out, sent.error());
      return true;
    }
    if (action_id == next_rcv_->secure_action) {
      if (auto sent = send_a(agent::a_message::use_queues{{{agent::send_queue_address{next_rcv_->router, next_rcv_->snd_id}, true}}}, random, out); !sent)
        failed(out, sent.error());
      return true;
    }
    return false;
  }
  void queue_keys_in(const agent::a_message::queue_keys& x, output& out) {
    if (!next_rcv_ || x.queues.empty()) return (void)failed(out, "QKEY: no switch of ours going on");
    const auto& [info, key] = x.queues.front();
    if (info.address.sender_id != next_rcv_->snd_id) return (void)failed(out, "QKEY: not our new queue");
    next_rcv_->their_e2e = info.address.dh;
    out.actions.push_back(act(next_rcv_->router, next_rcv_->id, smp::command::secure{key}, authorization::signed_by{next_rcv_->auth.priv}));
    next_rcv_->secure_action = out.actions.back().id;
  }
  // QTEST on the new queue: the old one deleted, the new one ours.
  void switch_done(output& out) {
    out.actions.push_back(act(rcv_router_, rcv_id_, smp::command::remove{}, authorization::signed_by{rcv_auth_.priv}));
    auto& n = *next_rcv_;
    rcv_router_ = n.router, rcv_id_ = n.id, rcv_snd_id_ = n.snd_id, rcv_auth_ = n.auth, rcv_router_dh_ = n.router_dh, rcv_e2e_ = n.e2e;
    rcv_server_dh_ = n.server_dh, rcv_their_e2e_ = n.their_e2e;
    next_rcv_.reset();
  }
  // A delivery on the new queue, before the switch is done.
  template <crypto::random_source R>
  output delivered_on_next(const smp::response::message& got, R& random) {
    output out;
    auto& n = *next_rcv_;
    out.actions.push_back(act(n.router, n.id, smp::command::acknowledge{got.id}, authorization::signed_by{n.auth.priv}));
    const auto router_key = crypto::box_key_of(n.server_dh, n.router_dh.priv);
    if (!router_key) return failed(out, "no router key for our new queue");
    const auto received = smp::router_layer_off(*router_key, got);
    if (!received) return failed(out, "the router's layer did not come off");
    const auto* sent = received->template get_if<smp::received::sent>();
    if (!sent) return out;
    const auto e2e = smp::e2e_open(sent->message, [&](const std::optional<public_key<curve::x25519>>&) {
      if (!n.their_e2e) return std::expected<crypto::box_key, crypto::crypto_error>(std::unexpected(crypto::errors::bad_key{}));
      return crypto::box_key_of(*n.their_e2e, n.e2e.priv);
    });
    if (!e2e) return failed(out, "the sender's layer did not come off");
    const auto* m = e2e->second.template get_if<smp::e2e::message>();
    if (!m) return failed(out, "not a message on our new queue");
    const auto envelope = agent::envelope_of(m->body);
    const auto* env = envelope ? envelope->template get_if<agent::envelope::message>() : nullptr;
    if (!env) return failed(out, "an envelope this side does not take");
    agent_message_in(env->encrypted, random, out);
    return out;
  }

  connection::flow flow_ = flow::fast;
  std::uint64_t awaiting_ = 0;
  bool got_hello_ = false;
  // The queue received on: where, its ids, our keys for it, the router's key.
  smp::router rcv_router_;
  bytes rcv_id_, rcv_snd_id_;
  crypto::key_pair<curve::ed25519> rcv_auth_;
  crypto::key_pair<curve::x25519> rcv_router_dh_, rcv_e2e_;
  public_key<curve::x25519> rcv_server_dh_;
  std::optional<public_key<curve::x25519>> rcv_their_e2e_;
  // The queue sent to: its address, our sender key, the E2E key with it.
  std::optional<agent::send_queue_address> snd_queue_;
  public_key<curve::x25519> snd_their_dh_;
  crypto::key_pair<curve::ed25519> snd_auth_;
  crypto::key_pair<curve::x25519> snd_e2e_;
  crypto::box_key snd_key_{};
  std::uint16_t agent_version_ = agent::current_agent_version, client_version_ = agent::current_client_version;
  std::optional<ratchet::state> ratchet_;
  std::uint64_t snd_message_id_ = 0, rcv_message_id_ = 0, actions_ = 0;
  bytes snd_previous_hash_, rcv_previous_hash_;
  bool connected_ = false;
};
}  // namespace detail

// The joining side of a connection.
class joining : public detail::duplex {
 public:
  // An invitation joined: its queue, its parameters; our reply queue to be
  // made on `reply_router`; `info` what the other side is told (a chat
  // profile). By the fast flow where the invitation's queue lets its sender
  // secure it, or by the standard one where asked to (or where it does not).
  template <crypto::random_source R>
  static std::expected<std::pair<joining, output>, std::string> join(const agent::link::invitation& invitation, smp::router reply_router,
                                                                     bytes info, R& random, connection::flow how = flow::fast) {
    joining c;
    const auto& theirs_q = invitation.queues.front();
    c.flow_ = agent::detail::sender_can_secure(theirs_q.address.mode) ? how : flow::standard;
    c.snd_queue_ = agent::send_queue_address{theirs_q.address.router, theirs_q.address.sender_id};
    c.snd_their_dh_ = theirs_q.address.dh;
    c.rcv_router_ = std::move(reply_router);
    c.info_ = std::move(info);
    c.agent_version_ = std::min<std::uint16_t>(invitation.agent_versions.max, agent::current_agent_version);
    c.client_version_ = std::min<std::uint16_t>(theirs_q.client_versions.max, agent::current_client_version);
    c.rcv_auth_ = crypto::generate<curve::ed25519>(random);
    c.rcv_router_dh_ = crypto::generate<curve::x25519>(random);
    c.rcv_e2e_ = crypto::generate<curve::x25519>(random);
    c.snd_auth_ = crypto::generate<curve::ed25519>(random);
    c.snd_e2e_ = crypto::generate<curve::x25519>(random);
    // The ratchet: our parameters, accepting its KEM key where it proposed one.
    const std::uint16_t e2e_version = std::min(invitation.e2e.versions.max, ratchet::current_version);
    auto [params, priv] = ratchet::make_params(e2e_version, invitation.e2e.kem_key.has_value(), invitation.e2e.kem_key, random);
    ratchet::e2e_params theirs{e2e_version, invitation.e2e.key1, invitation.e2e.key2, std::nullopt};
    if (invitation.e2e.kem_key) theirs.kem = ratchet::kem_params::proposed{*invitation.e2e.kem_key};
    const auto agreed = ratchet::x3dh_sending(priv, theirs);
    if (!agreed) return std::unexpected("no ratchet agreement with the invitation's keys");
    const auto own_dh = crypto::generate<curve::x448>(random);
    c.ratchet_.emplace(ratchet::sending_ratchet(e2e_version, ratchet::current_version, invitation.e2e.key2, own_dh.priv, agreed->first, agreed->second));
    c.params_ = params;
    output out;
    // Our reply queue: one its sender may secure, where the fast flow goes on.
    std::optional<smp::queue_request_t> request;
    if (c.flow_ == flow::fast) request = smp::queue_request_t(smp::queue_request::messaging{});
    c.expect(out, c.act(c.rcv_router_, {}, smp::command::create{c.rcv_auth_.pub, c.rcv_router_dh_.pub, std::nullopt, true, request, std::nullopt},
                        authorization::signed_by{c.rcv_auth_.priv}));
    c.step_ = step::creating_reply;
    return std::pair{std::move(c), std::move(out)};
  }

  // A router's answer to an action.
  template <crypto::random_source R>
  output answered(std::uint64_t action_id, const smp::response_t& response, R& random) {
    output out;
    if (response.template get_if<smp::response::failed>()) return failed(out, "the router refused action " + std::to_string(action_id));
    if (switch_answered(action_id, response, random, out)) return out;
    if (action_id != awaiting_) return out;  // an OK to a SEND or an ACK no step waits for
    switch (step_) {
      case step::creating_reply: {
        const auto* ids = response.template get_if<smp::response::queue_ids>();
        if (!ids) return failed(out, "no queue ids for the reply queue");
        rcv_id_ = ids->recipient_id, rcv_snd_id_ = ids->sender_id, rcv_server_dh_ = ids->server_dh;
        if (flow_ == flow::standard) return confirm(random, out);
        expect(out, act(snd_queue_->router, snd_queue_->sender_id, smp::command::sender_secure{snd_auth_.pub}, authorization::signed_by{snd_auth_.priv}));
        step_ = step::securing_theirs;
        return out;
      }
      case step::securing_theirs:
        return confirm(random, out);
      case step::securing_ours:
        // Our reply queue secured with the inviting side's key: our HELLO.
        if (auto sent = send_hello(random, out); !sent) return failed(out, sent.error());
        step_ = step::hello_sent;
        return out;
      default:
        return out;
    }
  }

  // A message the router delivered for `queue_id`: to the queue we are moving to, or ours.
  template <crypto::random_source R>
  output delivered(std::span<const byte> queue_id, const smp::response::message& got, R& random) {
    if (next_rcv_ && !next_rcv_->id.empty() && std::ranges::equal(queue_id, next_rcv_->id)) return delivered_on_next(got, random);
    return delivered(got, random);
  }
  // A message the router delivered to our reply queue.
  template <crypto::random_source R>
  output delivered(const smp::response::message& got, R& random) {
    output out;
    const auto e2e = opened(got, out);
    if (!e2e) return out;
    std::optional<smp::auth_key> their_sender_key;
    const auto body = spl::visit(spl::overloaded{[](const smp::e2e::message& m) { return m.body; },
                                                 [&](const smp::e2e::confirmation& c) {
                                                   their_sender_key = c.sender_key;
                                                   return c.body;
                                                 }},
                                 *e2e);
    const auto envelope = agent::envelope_of(body);
    if (!envelope) return failed(out, "an envelope that does not read");
    const auto encrypted = spl::visit(spl::overloaded{[](const agent::envelope::confirmation& c) { return std::optional(c.encrypted); },
                                                      [](const agent::envelope::message& m) { return std::optional(m.encrypted); },
                                                      [](const auto&) { return std::optional<bytes>(); }},
                                      *envelope);
    if (!encrypted) return failed(out, "an envelope this side does not take");
    agent_message_in(*encrypted, random, out);
    if (flow_ == flow::standard && step_ == step::confirming && their_sender_key) {
      // The inviting side's confirmation, with the key its SENDs will be
      // signed by: our reply queue secured with it (KEY).
      expect(out, act(rcv_router_, rcv_id_, smp::command::secure{*their_sender_key}, authorization::signed_by{rcv_auth_.priv}));
      step_ = step::securing_ours;
    } else if (flow_ == flow::standard && step_ == step::hello_sent && got_hello_) {
      connected_ = true;
      out.events.push_back(event::connected{});
      step_ = step::done;
    }
    return out;
  }

  [[nodiscard]] bytes saved() const { return quay::snapshot::of(*this); }
  template <std::ranges::input_range In>
  static std::expected<joining, quay::snapshot::error> restored(In&& from, std::uint64_t at_least = 0) {
    joining c;
    if (auto r = quay::snapshot::restore(std::forward<In>(from), c); !r) return std::unexpected(r.error());
    if (c.generation() < at_least) return std::unexpected(quay::snapshot::errors::stale{c.generation(), at_least});
    return c;
  }
  template <class D>
    requires std::same_as<std::remove_const_t<D>, joining>
  friend auto snapshot_fields(D& d) {
    using base = std::conditional_t<std::is_const_v<D>, const detail::duplex, detail::duplex>;
    return std::tuple_cat(snapshot_fields(static_cast<base&>(d)), std::tie(d.info_, d.params_, d.step_));
  }

 private:
  enum class step { creating_reply, securing_theirs, confirming, securing_ours, hello_sent, done };
  // The confirmation: our reply queue and our info, through the ratchet --
  // by the standard flow with our sender key beside it, the SEND unsigned.
  template <crypto::random_source R>
  output& confirm(R& random, output& out) {
    std::optional<agent::queue_mode_t> mode;
    if (flow_ == flow::fast) mode = agent::queue_mode_t(agent::queue_mode::messaging{});
    const agent::queue_info reply{agent::current_client_version, {rcv_router_, rcv_snd_id_, rcv_e2e_.pub, mode}};
    bytes conn_info;
    agent::put_agent_message(conn_info, agent::agent_message::conn_info_reply{{reply}, info_});
    const auto encrypted = ratchet::encrypt(*ratchet_, conn_info, agent::conn_info_length(ratchet_->support_kem), random);
    if (!encrypted) return failed(out, "the connection info could not be encrypted");
    bytes envelope;
    agent::put_envelope(envelope, agent::envelope::confirmation{agent_version_, params_, *encrypted});
    const auto key = crypto::box_key_of(snd_their_dh_, snd_e2e_.priv);
    if (!key) return failed(out, "the invitation's queue key refuses ours");
    snd_key_ = *key;
    std::optional<smp::auth_key> sender_key;
    if (flow_ == flow::standard) sender_key = smp::auth_key(snd_auth_.pub);
    const auto sealed = smp::e2e_confirmation(snd_key_, client_version_, snd_e2e_.pub, sender_key, envelope, random);
    if (!sealed) return failed(out, "the confirmation could not be sealed");
    // The connection info is our message 1, its hash what message 2 says came before.
    snd_message_id_ = 1;
    snd_previous_hash_ = agent::message_hash(conn_info);
    out.actions.push_back(act(snd_queue_->router, snd_queue_->sender_id, smp::command::send{true, *sealed},
                              flow_ == flow::fast ? authorization_t(authorization::signed_by{snd_auth_.priv}) : authorization_t(authorization::none{})));
    step_ = step::confirming;
    return out;
  }
  bytes info_;
  ratchet::e2e_params params_;
  step step_ = step::creating_reply;
};

// The inviting side of a connection.
class inviting : public detail::duplex {
 public:
  // An invitation made: our queue on `router` -- one the joining side may
  // secure itself by the fast flow, or that we secure by the standard one
  // -- our ratchet's parameters, a KEM key proposed where `post_quantum`,
  // and `info`, what the other side is told once it joins.
  template <crypto::random_source R>
  static std::pair<inviting, output> invite(smp::router router, bytes info, bool post_quantum, R& random, connection::flow how = flow::fast) {
    inviting c;
    c.flow_ = how;
    c.rcv_router_ = std::move(router);
    c.info_ = std::move(info);
    c.rcv_auth_ = crypto::generate<curve::ed25519>(random);
    c.rcv_router_dh_ = crypto::generate<curve::x25519>(random);
    c.rcv_e2e_ = crypto::generate<curve::x25519>(random);
    c.snd_auth_ = crypto::generate<curve::ed25519>(random);
    c.snd_e2e_ = crypto::generate<curve::x25519>(random);
    auto [params, priv] = ratchet::make_params(ratchet::current_version, post_quantum, std::nullopt, random);
    c.params_ = std::move(params);
    c.private_ = std::move(priv);
    c.post_quantum_ = post_quantum;
    output out;
    std::optional<smp::queue_request_t> request;
    if (how == flow::fast) request = smp::queue_request_t(smp::queue_request::messaging{});
    c.expect(out, c.act(c.rcv_router_, {}, smp::command::create{c.rcv_auth_.pub, c.rcv_router_dh_.pub, std::nullopt, true, request, std::nullopt},
                        authorization::signed_by{c.rcv_auth_.priv}));
    return {std::move(c), std::move(out)};
  }

  // An invitation made as invite() makes it, and sent to a contact address
  // (simplex:/contact) as a contact request -- `request_info` what it says
  // (a chat x.contact), `info` what our confirmation says once the address's
  // owner accepts and joins it (a chat x.info).
  template <crypto::random_source R>
  static std::expected<std::pair<inviting, output>, std::string> invite_through(const agent::link::contact& address, smp::router router,
                                                                                bytes request_info, bytes info, bool post_quantum, R& random,
                                                                                connection::flow how = flow::fast) {
    if (address.queues.empty()) return std::unexpected("an address without a queue");
    auto [c, out] = invite(std::move(router), std::move(info), post_quantum, random, how);
    c.through_ = address;
    c.request_info_ = std::move(request_info);
    return std::pair{std::move(c), std::move(out)};
  }

  // A router's answer to an action.
  template <crypto::random_source R>
  output answered(std::uint64_t action_id, const smp::response_t& response, R& random) {
    output out;
    if (response.template get_if<smp::response::failed>()) return failed(out, "the router refused action " + std::to_string(action_id));
    if (switch_answered(action_id, response, random, out)) return out;
    if (action_id != awaiting_) return out;  // an OK to a SEND or an ACK no step waits for
    switch (step_) {
      case step::creating: {
        const auto* ids = response.template get_if<smp::response::queue_ids>();
        if (!ids) return failed(out, "no queue ids for our queue");
        rcv_id_ = ids->recipient_id, rcv_snd_id_ = ids->sender_id, rcv_server_dh_ = ids->server_dh;
        std::optional<agent::queue_mode_t> mode;
        if (flow_ == flow::fast) mode = agent::queue_mode_t(agent::queue_mode::messaging{});
        agent::link::invitation link;
        link.queues.push_back(agent::queue_uri{{1, agent::current_client_version}, {rcv_router_, rcv_snd_id_, rcv_e2e_.pub, mode}});
        link.e2e = agent::e2e_params_uri{{ratchet::kdf_x3dh_version, ratchet::current_version}, params_.key1, params_.key2, std::nullopt};
        if (params_.kem) link.e2e.kem_key = params_.kem->template get_if<ratchet::kem_params::proposed>()->key;
        const auto text = agent::text_of(agent::link_t(link));
        out.events.push_back(event::invitation{text});
        step_ = step::invited;
        if (through_) {
          // The contact request: our link and what it says, sealed to the
          // address's queue under a key used once, the queue never secured.
          const auto& q = through_->queues.front();
          const auto once = crypto::generate<curve::x25519>(random);
          const auto key = crypto::box_key_of(q.address.dh, once.priv);
          if (!key) return failed(out, "the address's key refuses ours");
          bytes envelope;
          agent::put_envelope(envelope, agent::envelope::invitation{std::min<std::uint16_t>(through_->agent_versions.max, agent::current_agent_version),
                                                                    text, request_info_});
          const auto sealed = smp::e2e_confirmation(*key, std::min<std::uint16_t>(q.client_versions.max, agent::current_client_version), once.pub,
                                                    std::nullopt, envelope, random);
          if (!sealed) return failed(out, "the contact request could not be sealed");
          out.actions.push_back(act(q.address.router, q.address.sender_id, smp::command::send{true, *sealed}, authorization::none{}));
          through_.reset();
          request_info_.clear();
        }
        return out;
      }
      case step::securing: {
        // Our confirmation: our info, through the ratchet, to their reply
        // queue -- by the standard flow with our sender key, unsigned.
        bytes conn_info;
        agent::put_agent_message(conn_info, agent::agent_message::conn_info{info_});
        const auto encrypted = ratchet::encrypt(*ratchet_, conn_info, agent::conn_info_length(ratchet_->support_kem), random);
        if (!encrypted) return failed(out, "the connection info could not be encrypted");
        bytes envelope;
        agent::put_envelope(envelope, agent::envelope::confirmation{agent_version_, std::nullopt, *encrypted});
        std::optional<smp::auth_key> sender_key;
        if (flow_ == flow::standard) sender_key = smp::auth_key(snd_auth_.pub);
        const auto sealed = smp::e2e_confirmation(snd_key_, client_version_, snd_e2e_.pub, sender_key, envelope, random);
        if (!sealed) return failed(out, "the confirmation could not be sealed");
        snd_message_id_ = 1;
        snd_previous_hash_ = agent::message_hash(conn_info);
        expect(out, act(snd_queue_->router, snd_queue_->sender_id, smp::command::send{true, *sealed},
                        flow_ == flow::fast ? authorization_t(authorization::signed_by{snd_auth_.priv}) : authorization_t(authorization::none{})));
        step_ = step::confirming;
        return out;
      }
      case step::confirming:
        // Our confirmation taken by the router: by the fast flow, connected;
        // by the standard one, the joining side's HELLO awaited.
        if (flow_ == flow::standard) {
          step_ = step::awaiting_hello;
          return out;
        }
        [[fallthrough]];
      case step::hello_sent:
        connected_ = true;
        out.events.push_back(event::connected{});
        step_ = step::done;
        return out;
      default:
        return out;
    }
  }

  // A message the router delivered for `queue_id`: to the queue we are moving to, or ours.
  template <crypto::random_source R>
  output delivered(std::span<const byte> queue_id, const smp::response::message& got, R& random) {
    if (next_rcv_ && !next_rcv_->id.empty() && std::ranges::equal(queue_id, next_rcv_->id)) return delivered_on_next(got, random);
    return delivered(got, random);
  }
  // A message the router delivered to our queue: first the joining side's
  // confirmation, then its messages.
  template <crypto::random_source R>
  output delivered(const smp::response::message& got, R& random) {
    output out;
    const auto e2e = opened(got, out);
    if (!e2e) return out;
    if (const auto* conf = e2e->template get_if<smp::e2e::confirmation>(); conf && step_ == step::invited) {
      const auto envelope = agent::envelope_of(conf->body);
      const auto* c = envelope ? envelope->template get_if<agent::envelope::confirmation>() : nullptr;
      if (!c || !c->e2e) return failed(out, "a confirmation without the joining side's ratchet parameters");
      if (flow_ == flow::standard && !conf->sender_key) return failed(out, "a confirmation without the key to secure our queue with");
      their_sender_key_ = conf->sender_key;
      // The ratchet, on its parameters.
      const auto agreed = ratchet::x3dh_receiving(private_, *c->e2e);
      if (!agreed) return failed(out, "no ratchet agreement with the joining side's keys");
      const std::uint16_t version = std::min(c->e2e->version, ratchet::current_version);
      ratchet_.emplace(ratchet::receiving_ratchet(version, ratchet::current_version, private_.key2, agreed->first, agreed->second, post_quantum_));
      agent_version_ = std::min<std::uint16_t>(c->version, agent::current_agent_version);
      const auto plain = ratchet::decrypt(*ratchet_, c->encrypted, random);
      if (!plain) return failed(out, "its connection info does not open");
      const auto message = agent::agent_message_of(*plain);
      const auto* reply = message ? message->template get_if<agent::agent_message::conn_info_reply>() : nullptr;
      if (!reply || reply->queues.empty()) return failed(out, "a confirmation without a reply queue");
      // Its connection info is its message 1.
      rcv_message_id_ = 1;
      rcv_previous_hash_ = agent::message_hash(*plain);
      const auto& q = reply->queues.front();
      if (flow_ == flow::fast && !agent::detail::sender_can_secure(q.address.mode)) return failed(out, "its reply queue cannot be secured by us (no fast flow)");
      snd_queue_ = agent::send_queue_address{q.address.router, q.address.sender_id};
      snd_their_dh_ = q.address.dh;
      client_version_ = std::min<std::uint16_t>(q.client_version, agent::current_client_version);
      const auto key = crypto::box_key_of(snd_their_dh_, snd_e2e_.priv);
      if (!key) return failed(out, "its reply queue's key refuses ours");
      snd_key_ = *key;
      out.events.push_back(event::confirmed{reply->info});
      step_ = step::confirmed;
      return out;
    }
    const auto* m = e2e->template get_if<smp::e2e::message>();
    if (!m || !ratchet_) return failed(out, "a message before the connection");
    const auto envelope = agent::envelope_of(m->body);
    const auto* env = envelope ? envelope->template get_if<agent::envelope::message>() : nullptr;
    if (!env) return failed(out, "an envelope this side does not take");
    agent_message_in(env->encrypted, random, out);
    if (step_ == step::awaiting_hello && got_hello_) {
      // The joining side's HELLO: ours back, and connected once it is taken.
      if (auto sent = send_hello(random, out); !sent) return failed(out, sent.error());
      awaiting_ = out.actions.back().id;
      step_ = step::hello_sent;
    }
    return out;
  }

  // The joining side allowed: by the fast flow its reply queue secured
  // (SKEY), by the standard one our queue secured with its key (KEY); then
  // our confirmation sent (answered()).
  output allow() {
    output out;
    if (step_ != step::confirmed) return failed(out, "nothing to allow");
    if (flow_ == flow::fast)
      expect(out, act(snd_queue_->router, snd_queue_->sender_id, smp::command::sender_secure{snd_auth_.pub}, authorization::signed_by{snd_auth_.priv}));
    else
      expect(out, act(rcv_router_, rcv_id_, smp::command::secure{*their_sender_key_}, authorization::signed_by{rcv_auth_.priv}));
    step_ = step::securing;
    return out;
  }

  [[nodiscard]] bytes saved() const { return quay::snapshot::of(*this); }
  template <std::ranges::input_range In>
  static std::expected<inviting, quay::snapshot::error> restored(In&& from, std::uint64_t at_least = 0) {
    inviting c;
    if (auto r = quay::snapshot::restore(std::forward<In>(from), c); !r) return std::unexpected(r.error());
    if (c.generation() < at_least) return std::unexpected(quay::snapshot::errors::stale{c.generation(), at_least});
    return c;
  }
  template <class D>
    requires std::same_as<std::remove_const_t<D>, inviting>
  friend auto snapshot_fields(D& d) {
    using base = std::conditional_t<std::is_const_v<D>, const detail::duplex, detail::duplex>;
    return std::tuple_cat(snapshot_fields(static_cast<base&>(d)),
                          std::tie(d.info_, d.params_, d.private_, d.post_quantum_, d.their_sender_key_, d.step_));
  }

 private:
  enum class step { creating, invited, confirmed, securing, confirming, awaiting_hello, hello_sent, done };
  std::optional<agent::link::contact> through_;  // until the contact request is sent
  bytes request_info_;
  bytes info_;
  ratchet::e2e_params params_;
  ratchet::e2e_private private_;
  bool post_quantum_ = true;
  std::optional<smp::auth_key> their_sender_key_;  // the standard flow's: what our queue is secured with
  step step_ = step::creating;
};

// Our own contact address: a queue anyone may send a contact request to,
// never secured; each request accepted, where the program wants it, by
// joining the invitation it carries (joining::join).
class address : public detail::duplex {
 public:
  template <crypto::random_source R>
  static std::pair<address, output> create(smp::router router, R& random) {
    address a;
    a.rcv_router_ = std::move(router);
    a.rcv_auth_ = crypto::generate<curve::ed25519>(random);
    a.rcv_router_dh_ = crypto::generate<curve::x25519>(random);
    a.rcv_e2e_ = crypto::generate<curve::x25519>(random);
    output out;
    out.actions.push_back(a.act(a.rcv_router_, {},
                                smp::command::create{a.rcv_auth_.pub, a.rcv_router_dh_.pub, std::nullopt, true,
                                                     smp::queue_request_t(smp::queue_request::contact{}), std::nullopt},
                                authorization::signed_by{a.rcv_auth_.priv}));
    return {std::move(a), std::move(out)};
  }

  // A router's answer: the queue's ids, and with them the address.
  template <crypto::random_source R>
  output answered(std::uint64_t action_id, const smp::response_t& response, R&) {
    output out;
    if (response.template get_if<smp::response::failed>()) return failed(out, "the router refused action " + std::to_string(action_id));
    const auto* ids = response.template get_if<smp::response::queue_ids>();
    if (!ids || !rcv_id_.empty()) return out;  // an OK to an ACK
    rcv_id_ = ids->recipient_id, rcv_snd_id_ = ids->sender_id, rcv_server_dh_ = ids->server_dh;
    agent::link::contact link;
    link.queues.push_back(agent::queue_uri{{1, agent::current_client_version},
                                           {rcv_router_, rcv_snd_id_, rcv_e2e_.pub, agent::queue_mode_t(agent::queue_mode::contact{})}});
    out.events.push_back(event::address{agent::text_of(agent::link_t(link))});
    return out;
  }

  // A contact request delivered: its invitation and what it says.
  template <crypto::random_source R>
  output delivered(const smp::response::message& got, R&) {
    output out;
    const auto e2e = opened(got, out);
    if (!e2e) return out;
    const auto body = spl::visit(spl::overloaded{[](const smp::e2e::message& m) { return m.body; }, [](const smp::e2e::confirmation& c) { return c.body; }}, *e2e);
    const auto envelope = agent::envelope_of(body);
    const auto* request = envelope ? envelope->template get_if<agent::envelope::invitation>() : nullptr;
    if (!request) return failed(out, "not a contact request");
    const auto link = agent::link_of(request->connection_link);
    const auto* invitation = link ? link->template get_if<agent::link::invitation>() : nullptr;
    if (!invitation || invitation->queues.empty()) return failed(out, "a contact request without an invitation");
    out.events.push_back(event::contact_request{*invitation, request->info});
    return out;
  }

  [[nodiscard]] bytes saved() const { return quay::snapshot::of(*this); }
  template <std::ranges::input_range In>
  static std::expected<address, quay::snapshot::error> restored(In&& from, std::uint64_t at_least = 0) {
    address a;
    if (auto r = quay::snapshot::restore(std::forward<In>(from), a); !r) return std::unexpected(r.error());
    if (a.generation() < at_least) return std::unexpected(quay::snapshot::errors::stale{a.generation(), at_least});
    return a;
  }
  template <class D>
    requires std::same_as<std::remove_const_t<D>, address>
  friend auto snapshot_fields(D& d) {
    using base = std::conditional_t<std::is_const_v<D>, const detail::duplex, detail::duplex>;
    return snapshot_fields(static_cast<base&>(d));
  }
};

}  // namespace quay::connection

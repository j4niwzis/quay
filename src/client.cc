// SPDX-License-Identifier: AGPL-3.0-only
// quay.client -- one session with one router, sans-IO: the socket's bytes
// in, the socket's bytes out, and between them TLS (quay.tls), the
// router's authentication (quay.session), the hellos, and SMP's blocks.
// Actions of any number of connections (quay.connection) are submitted
// with a tag the program chooses -- which connection asked -- and what
// comes back is said with it: the answer to an action by its tag and id,
// a delivery by the queue it is for (connection::queue_id()).
//
// Actions for queues on other routers may go through this one as a proxy
// (submit_via_proxy: private message routing), the destination never
// seeing the program's address.
//
// What it does not do is the socket itself: the program connects to the
// router's host and port, writes take_outgoing(), and feeds what it reads
// to received() -- with whatever I/O it likes.
export module quay.client;

import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.smp;
import quay.session;
import quay.tls;
import quay.connection;

export namespace quay::client {

namespace incoming {
struct answered {  // a router's answer to an action submitted with `tag`
  std::uint64_t tag = 0, action_id = 0;
  smp::response_t response;
};
struct delivered {  // a message for the queue `queue_id`: to the connection whose queue it is
  bytes queue_id;
  smp::response::message message;
};
struct ready {};  // the router authenticated and the hellos done: actions go out from now
struct failed {   // the session is no good: TLS, the router's authentication, the router's framing
  std::string what;
};
}  // namespace incoming
using incoming_t = spl::variant<incoming::answered, incoming::delivered, incoming::ready, incoming::failed>;

class router_session {
 public:
  // A session begun with `router` (its first host and its port, 5223 where
  // it names none); what TLS first sends is in take_outgoing().
  explicit router_session(smp::router router)
      : router_(std::move(router)), tls_(router_.hosts.empty() ? std::string() : router_.hosts.front(), router_.port.value_or(5223)) {
    flush();
  }

  [[nodiscard]] const smp::router& router() const { return router_; }
  [[nodiscard]] bool ready() const { return verified_.has_value(); }

  // An action to send, for the connection `tag` -- held until the session is ready.
  template <crypto::random_source R>
  void submit(std::uint64_t tag, const connection::action& a, R& random) {
    smp::corr_id c{};
    random(std::span<byte>(c));
    pending_[c] = {tag, a.id};
    if (!verified_) {
      held_.push_back({c, a});
      return;
    }
    send(a, c);
  }
  template <crypto::random_source R>
  void submit(std::uint64_t tag, const connection::output& out, R& random) {
    for (const auto& a : out.actions) submit(tag, a, random);
  }

  // An action for a queue on `destination`, sent through this router as a
  // proxy (private message routing): the destination's session asked for
  // once (PRXY) and checked (session::verify_relayed), then each action
  // sealed for it (session::proxy_command) and forwarded (PFWD); its answer
  // comes back as any other, by tag and id.
  template <crypto::random_source R>
  void submit_via_proxy(std::uint64_t tag, const connection::action& a, const smp::router& destination, R& random) {
    auto& relay = relays_[destination.identity];
    relay.router = destination;
    relay.waiting.push_back({tag, a});
    if (!relay.asked) {
      relay.asked = true;
      submit_raw(smp::command::proxy_session{destination, std::nullopt}, {}, random, [this, id = destination.identity](const smp::corr_id& c) { prxy_[c] = id; });
    }
    flush_relay(relay, random);
  }

  // Bytes read from the socket.
  void received(std::span<const byte> data) {
    if (failed_) return;
    if (auto fed = tls_.received(data); !fed) return fail(fed.error());
    flush();
    const auto got = tls_.take_incoming();
    plain_.insert(plain_.end(), got.begin(), got.end());
    while (!failed_ && plain_.size() >= smp::block_size) {
      const bytes block(plain_.begin(), plain_.begin() + smp::block_size);
      plain_.erase(plain_.begin(), plain_.begin() + smp::block_size);
      if (!verified_) hello(block);
      else blocks(block);
    }
  }
  // What to write to the socket, and what came of what was read, drained.
  [[nodiscard]] bytes take_outgoing() { return std::exchange(outgoing_, {}); }
  [[nodiscard]] std::vector<incoming_t> take_incoming() { return std::exchange(incoming_, {}); }

 private:
  struct relay {
    smp::router router;
    bool asked = false;
    std::optional<session::verified> destination;
    bytes session_id;  // the proxy's session with it
    std::vector<std::pair<std::uint64_t, connection::action>> waiting;
  };
  struct in_flight {
    std::uint64_t tag = 0, action_id = 0;
    session::proxied sealed;
    std::uint16_t version = 0;
  };
  // A command of this session's own (no connection's action), its correlation id told.
  template <crypto::random_source R, class Told>
  void submit_raw(const smp::command_t& command, bytes entity, R& random, Told&& told) {
    smp::corr_id c{};
    random(std::span<byte>(c));
    told(c);
    bytes body;
    smp::put_command(body, command);
    raw_.push_back(smp::transmission{{}, c, std::move(entity), std::move(body)});
    send_raw();
  }
  void send_raw() {
    if (!verified_) return;
    for (const auto& t : std::exchange(raw_, {})) {
      const auto block = smp::block_of(std::span(&t, 1), verified_->version());
      if (!block) return fail("a command too large for a block");
      if (auto sent = tls_.send(*block); !sent) return fail(sent.error());
      flush();
    }
  }
  template <crypto::random_source R>
  void flush_relay(relay& r, R& random) {
    if (!r.destination) return;
    for (auto& [tag, a] : std::exchange(r.waiting, {})) {
      const auto key = spl::visit(spl::overloaded{[](const connection::authorization::none&) { return std::optional<crypto::private_key<curve::ed25519>>(); },
                                                  [](const connection::authorization::signed_by& s) { return std::optional(s.key); }},
                                  a.authorization);
      auto sealed = session::proxy_command(*r.destination, a.entity, a.command, key, random);
      if (!sealed) return fail(sealed.error());
      bytes body;
      smp::put_command(body, sealed->command);
      raw_.push_back(smp::transmission{{}, sealed->correlation, r.session_id, std::move(body)});
      forwarded_[sealed->correlation] = in_flight{tag, a.id, std::move(*sealed), r.destination->version()};
    }
    send_raw();
  }

 private:
  void flush() {
    const auto out = tls_.take_outgoing();
    outgoing_.insert(outgoing_.end(), out.begin(), out.end());
  }
  void fail(std::string what) {
    failed_ = true;
    incoming_.push_back(incoming::failed{std::move(what)});
  }
  void send(const connection::action& a, const smp::corr_id& c) {
    const auto t = connection::transmission_of(a, *verified_, c);
    const auto block = smp::block_of(std::span(&t, 1), verified_->version());
    if (!block) return fail("an action too large for a block");
    if (auto sent = tls_.send(*block); !sent) return fail(sent.error());
    flush();
  }
  // The router's hello: the router authenticated from it and from TLS, ours sent, what was held sent.
  void hello(const bytes& block) {
    const auto facts = tls_.facts();
    if (!facts) return fail("TLS gave no chain or Finished");
    const auto h = smp::router_hello_of(block);
    if (!h) return fail("not a router's hello");
    auto checked = session::verify(*h, router_.identity, *facts);
    if (!checked) return fail("the router is not the one its address pins (or not this TLS session's)");
    verified_ = std::move(*checked);
    const auto ours = smp::client_hello(verified_->version(), router_.identity);
    if (!ours) return fail("our hello could not be made");
    if (auto sent = tls_.send(*ours); !sent) return fail(sent.error());
    flush();
    incoming_.push_back(incoming::ready{});
    for (const auto& [c, a] : std::exchange(held_, {})) send(a, c);
    send_raw();
  }
  // Transmissions: answers by their correlation id, deliveries by their queue.
  void blocks(const bytes& block) {
    const auto all = smp::transmissions_of(block, verified_->version());
    if (!all) return fail("a block that does not read");
    for (const auto& t : *all) {
      const auto r = smp::response_of(t.body);
      if (!r) continue;
      if (t.correlation) {
        if (const auto asked = prxy_.find(*t.correlation); asked != prxy_.end()) {
          auto& relay = relays_[asked->second];
          prxy_.erase(asked);
          const auto* key = r->template get_if<smp::response::proxy_session_key>();
          if (!key) {
            for (const auto& [tag, a] : std::exchange(relay.waiting, {})) incoming_.push_back(incoming::answered{tag, a.id, *r});
            continue;
          }
          auto checked = session::verify_relayed(*key, relay.router.identity);
          if (!checked) return fail("the destination the proxy relays is not the one its address pins");
          relay.destination = std::move(*checked);
          relay.session_id = key->session_id;
          crypto::system_random random;
          flush_relay(relay, random);
          continue;
        }
        if (const auto f = forwarded_.find(*t.correlation); f != forwarded_.end()) {
          const auto flight = std::move(f->second);
          forwarded_.erase(f);
          const auto* pres = r->template get_if<smp::response::proxy_response>();
          if (!pres) {
            incoming_.push_back(incoming::answered{flight.tag, flight.action_id, *r});
            continue;
          }
          auto answer = session::proxied_response(flight.sealed, *pres, flight.version);
          if (!answer) return fail(answer.error());
          incoming_.push_back(incoming::answered{flight.tag, flight.action_id, std::move(*answer)});
          continue;
        }
      }
      const auto* m = r->template get_if<smp::response::message>();
      if (t.correlation) {
        if (const auto found = pending_.find(*t.correlation); found != pending_.end()) {
          const auto [tag, id] = found->second;
          pending_.erase(found);
          // A message as the answer to a SUB: delivered as well as answered.
          if (m) incoming_.push_back(incoming::delivered{t.entity, *m});
          incoming_.push_back(incoming::answered{tag, id, *r});
          continue;
        }
      }
      if (m) incoming_.push_back(incoming::delivered{t.entity, *m});
    }
  }

  smp::router router_;
  tls::client tls_;
  std::optional<session::verified> verified_;
  std::map<smp::corr_id, std::pair<std::uint64_t, std::uint64_t>> pending_;
  std::vector<std::pair<smp::corr_id, connection::action>> held_;
  std::map<bytes, relay> relays_;                // by the destination's identity
  std::map<smp::corr_id, bytes> prxy_;           // a PRXY's correlation id: whose session it asks for
  std::map<smp::corr_id, in_flight> forwarded_;  // a PFWD's
  std::vector<smp::transmission> raw_;
  bytes plain_, outgoing_;
  std::vector<incoming_t> incoming_;
  bool failed_ = false;
};

}  // namespace quay::client

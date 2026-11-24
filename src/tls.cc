// SPDX-License-Identifier: AGPL-3.0-only
// quay.tls -- TLS 1.3 to an SMP router, on Botan, sans-IO: bytes from the
// socket are fed in, bytes for the socket and the router's plaintext come
// out, and once the handshake is done, what quay.session needs to
// authenticate the router: its certificate chain as it sent it (leaf
// first, DER) and this client's Finished (tls-unique, the channel binding
// simplexmq takes for the session id). ALPN smp/1, as simplexmq's clients
// offer it.
//
// The chain is not checked against any trust store here: a router's
// certificates are its own, and quay.session::verify() pins them -- the CA
// certificate's fingerprint against the router's address, the leaf's
// signature over the session key, this session's Finished. Nothing is to
// be sent to the router before that verification passes.
module;
#include "botan_all.h"
export module quay.tls;

import std;
import quay.bytes;
import quay.session;

namespace quay::tls::detail {

// What Botan says, kept for the client to hand out: bytes for the socket,
// plaintext, the chain, the last Finished seen (ours: the server's comes first).
class callbacks final : public Botan::TLS::Callbacks {
 public:
  bytes outgoing, incoming;
  std::vector<bytes> chain;
  bytes finished;
  bool active = false, closed = false;
  std::optional<std::string> alert;

  void tls_emit_data(std::span<const std::uint8_t> data) override { outgoing.insert(outgoing.end(), data.begin(), data.end()); }
  void tls_record_received(std::uint64_t, std::span<const std::uint8_t> data) override { incoming.insert(incoming.end(), data.begin(), data.end()); }
  void tls_alert(Botan::TLS::Alert a) override {
    if (a.type() == Botan::TLS::Alert::CloseNotify) closed = true;
    else alert = a.type_string();
  }
  void tls_session_activated() override { active = true; }
  // Kept, not judged: quay.session pins it.
  void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain, const std::vector<std::optional<Botan::OCSP::Response>>&,
                             const std::vector<Botan::Certificate_Store*>&, Botan::Usage_Type, std::string_view, const Botan::TLS::Policy&) override {
    chain.clear();
    for (const auto& cert : cert_chain) {
      const auto der = cert.BER_encode();
      chain.emplace_back(der.begin(), der.end());
    }
  }
  void tls_inspect_handshake_msg(const Botan::TLS::Handshake_Message& message) override {
    if (message.type() != Botan::TLS::Handshake_Type::Finished) return;
    const auto body = message.serialize();  // a Finished's body is its verify_data
    finished.assign(body.begin(), body.end());
  }
};

// TLS 1.3 only, with the routers' signature algorithms and this build's curves.
class policy final : public Botan::TLS::Policy {
 public:
  bool allow_tls12() const override { return false; }
  bool allow_tls13() const override { return true; }
  std::vector<std::string> allowed_signature_methods() const override { return {"Ed25519", "Ed448", "ECDSA", "RSA"}; }
  // EdDSA's schemes name no hash -- Botan calls it "Pure" -- and are dropped
  // unless it is allowed: then nothing is offered a router's Ed25519 or
  // Ed448 certificate can sign with, and the router refuses the handshake.
  std::vector<std::string> allowed_signature_hashes() const override { return {"Pure", "SHA-512", "SHA-384", "SHA-256"}; }
  // The curves this build has.
  std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
    return {Botan::TLS::Group_Params::X25519, Botan::TLS::Group_Params::X448};
  }
  std::vector<Botan::TLS::Group_Params> key_exchange_groups_to_offer() const override { return {Botan::TLS::Group_Params::X25519}; }
};

// No client certificate, no trust store: the chain is pinned, not trusted.
class credentials final : public Botan::Credentials_Manager {};

}  // namespace quay::tls::detail

export namespace quay::tls {

class client {
 public:
  // A handshake begun with the router named `host` (its SNI) on `port`;
  // what it first sends is in take_outgoing().
  client(const std::string& host, std::uint16_t port)
      : callbacks_(std::make_shared<detail::callbacks>()),
        sessions_(std::make_shared<Botan::TLS::Session_Manager_Noop>()),
        credentials_(std::make_shared<detail::credentials>()),
        policy_(std::make_shared<detail::policy>()),
        random_(std::make_shared<Botan::System_RNG>()),
        channel_(std::make_unique<Botan::TLS::Client>(callbacks_, sessions_, credentials_, policy_, random_, Botan::TLS::Server_Information(host, port),
                                                      Botan::TLS::Protocol_Version(Botan::TLS::Version_Code::TLS_V13), std::vector<std::string>{"smp/1"})) {}
  client(client&&) = default;
  client& operator=(client&&) = default;

  // Bytes from the socket. A TLS failure -- a bad record, an alert -- is said.
  template <std::ranges::contiguous_range R>
    requires std::same_as<std::ranges::range_value_t<R>, byte>
  std::expected<void, std::string> received(const R& data) {
    try {
      channel_->received_data(std::span<const std::uint8_t>(std::ranges::data(data), std::ranges::size(data)));
    } catch (const std::exception& e) {
      return std::unexpected(std::string("TLS: ") + e.what());
    }
    if (callbacks_->alert) return std::unexpected("TLS alert: " + *callbacks_->alert);
    return {};
  }
  // Plaintext for the router (only once ready()).
  template <std::ranges::contiguous_range R>
    requires std::same_as<std::ranges::range_value_t<R>, byte>
  std::expected<void, std::string> send(const R& data) {
    if (!ready()) return std::unexpected("TLS: not ready");
    try {
      channel_->send(std::span<const std::uint8_t>(std::ranges::data(data), std::ranges::size(data)));
    } catch (const std::exception& e) {
      return std::unexpected(std::string("TLS: ") + e.what());
    }
    return {};
  }
  void close() { channel_->close(); }

  // What is to be written to the socket, and what the router said, drained.
  [[nodiscard]] bytes take_outgoing() { return std::exchange(callbacks_->outgoing, {}); }
  [[nodiscard]] bytes take_incoming() { return std::exchange(callbacks_->incoming, {}); }

  [[nodiscard]] bool ready() const { return callbacks_->active && channel_->is_active(); }
  [[nodiscard]] bool closed() const { return callbacks_->closed || channel_->is_closed(); }
  // The protocol ALPN settled on (smp/1, where the router speaks it).
  [[nodiscard]] std::string protocol() const { return channel_->application_protocol(); }
  // Once ready: the router's chain and our Finished, for session::verify().
  [[nodiscard]] std::optional<session::tls_facts> facts() const {
    if (!ready() || callbacks_->chain.empty() || callbacks_->finished.empty()) return std::nullopt;
    return session::tls_facts{callbacks_->chain, callbacks_->finished};
  }

 private:
  // Botan's client holds these by shared_ptr; they live as long as it.
  std::shared_ptr<detail::callbacks> callbacks_;
  std::shared_ptr<Botan::TLS::Session_Manager_Noop> sessions_;
  std::shared_ptr<detail::credentials> credentials_;
  std::shared_ptr<detail::policy> policy_;
  std::shared_ptr<Botan::RandomNumberGenerator> random_;
  std::unique_ptr<Botan::TLS::Client> channel_;
};

}  // namespace quay::tls

// SPDX-License-Identifier: AGPL-3.0-only
// A file from simplex-chat's CLI, as a chat sends one: quay joins the CLI's
// invitation; the CLI sends a file (/f) -- uploaded to its XFTP router, the
// file offered in an x.msg.new and its description in parts
// (x.msg.file.descr); quay puts the description together (quay.chat), reads
// it (quay.xfile), gets the chunks from the XFTP router (quay.xftp), opens
// the file and writes it out (tools/live_cli_file.sh compares it).
// Then quay sends a file back the same way, for the CLI to receive (/fr).
// Usage: live_chat_file <the CLI's invitation> <where to write its file> <where to write ours>
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
import quay.agent;
import quay.connection;
import quay.chat;
import quay.xftp;
import quay.xfile;

using namespace quay;

namespace {
int fd = -1;
#include "live_io.h"
std::uint16_t agreed = 0;
std::optional<session::verified> verified;
crypto::system_random rng;
std::map<smp::corr_id, std::uint64_t> pending;
chat::file_descriptions descriptions;
std::optional<std::pair<std::string, xfile::description>> received;  // the file's name and its description, once whole

void perform(const connection::output& out, bool& connected) {
  for (const auto& a : out.actions) {
    smp::corr_id c{};
    rng(std::span<byte>(c));
    pending[c] = a.id;
    const auto t = connection::transmission_of(a, *verified, c);
    send_all(*smp::block_of(std::span(&t, 1), agreed));
  }
  for (const auto& e : out.events)
    spl::visit(spl::overloaded{[&](const connection::event::connected&) {
                                 std::println("event: connected");
                                 connected = true;
                               },
                               [](const connection::event::message& m) {
                                 const auto chats = chat::messages_of(m.body);
                                 if (!chats) return;
                                 for (const auto& c : *chats)
                                   spl::visit(spl::overloaded{[&](const chat::event::message_new& n) {
                                                                if (!n.file) return;
                                                                std::println("a file offered: {} ({} bytes)", n.file->file_name, n.file->file_size);
                                                                if (auto whole = descriptions.offered(c.message_id, *n.file)) {
                                                                  auto d = xfile::description_of(*whole);
                                                                  if (d) received.emplace(n.file->file_name, std::move(*d));
                                                                }
                                                              },
                                                              [&](const chat::event::file_description& f) {
                                                                std::println("a part of its description: {}{}", f.description.part, f.description.complete ? ", the last" : "");
                                                                if (auto whole = descriptions.more(f)) {
                                                                  auto d = xfile::description_of(*whole);
                                                                  if (!d) std::println("its description does not read: {}", d.error());
                                                                  else received.emplace("", std::move(*d));
                                                                }
                                                              },
                                                              [&](const auto&) { std::println("chat: {}", c.event); }},
                                              c.params.data());
                               },
                               [](const connection::event::failed& f) { std::println("event: FAILED: {}", f.what); },
                               [](const auto&) {}},
               e);
}

// One session with an XFTP router over a blocking socket, a command at a time.
struct xlink {
  int xfd = -1;
  xftp::router_session s;
  std::deque<xftp::incoming::answered> answers;
  explicit xlink(const xftp::router& router) : s(router) {
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(router.port);
    inet_pton(AF_INET, router.host.c_str(), &where.sin_addr);
    xfd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval wait{20, 0};
    ::setsockopt(xfd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    if (::connect(xfd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection to the XFTP router");
  }
  ~xlink() { ::close(xfd); }
  xftp::incoming::answered ask(const xftp::command_t& c, bytes entity, const crypto::private_key<curve::ed25519>& key, bytes chunk = {}) {
    const auto id = s.submit(c, std::move(entity), key, std::move(chunk));
    while (answers.empty() || answers.front().id != id) {
      for (auto out = s.take_outgoing(); !out.empty();) {
        const auto n = ::send(xfd, out.data(), out.size(), 0);
        if (n <= 0) throw std::runtime_error("send failed");
        out.erase(out.begin(), out.begin() + n);
      }
      std::array<byte, 65536> buffer{};
      const auto n = ::recv(xfd, buffer.data(), buffer.size(), 0);
      if (n <= 0) throw std::runtime_error("the XFTP router closed or went quiet");
      s.received(std::span<const byte>(buffer.data(), static_cast<std::size_t>(n)));
      for (auto& in : s.take_incoming())
        spl::visit(spl::overloaded{[](const xftp::incoming::ready&) {}, [&](xftp::incoming::answered& a) { answers.push_back(std::move(a)); },
                                   [](const xftp::incoming::failed& f) { throw std::runtime_error(f.what); }},
                   in);
    }
    auto a = std::move(answers.front());
    answers.pop_front();
    return a;
  }
};

// The file got from the XFTP router its description names, chunk by chunk, and opened.
xfile::opened_file download(const xfile::description& d) {
  xlink l(d.chunks.front().replicas.front().router);
  bytes sealed;
  for (const auto& c : d.chunks) {
    const auto& r = c.replicas.front();
    const auto dh = crypto::generate<curve::x25519>(rng);
    const auto got = l.ask(xftp::command::get{dh.pub}, r.id, r.key);
    const auto* file = got.response.template get_if<xftp::response::file>();
    if (!file) throw std::runtime_error("FGET refused");
    const auto opened = xftp::open_chunk(*file, dh.priv, got.chunk);
    if (!opened || !std::ranges::equal(crypto::sha256(*opened), c.digest)) throw std::runtime_error("a chunk that does not open or match its digest");
    sealed.insert(sealed.end(), opened->begin(), opened->end());
    (void)l.ask(xftp::command::acknowledge{}, r.id, r.key);
    std::println("chunk {} of {}: got and opened", c.number, d.chunks.size());
  }
  if (!std::ranges::equal(crypto::sha512(sealed), d.digest)) throw std::runtime_error("the file's digest is not as described");
  auto file = xfile::open(sealed, d.key, d.nonce);
  if (!file) throw std::runtime_error(file.error());
  return std::move(*file);
}

// A file of ours uploaded to `router` -- sealed, cut, each chunk created
// and put -- and the recipient's description of it.
xfile::description upload(const xftp::router& router, const std::string& name, std::span<const byte> content) {
  xlink l(router);
  const auto s = xfile::seal({name, std::nullopt}, content, rng);
  const auto digest = crypto::sha512(s.data);
  xfile::description d{xfile::party::recipient{}, s.data.size(), bytes(digest.begin(), digest.end()), s.key, s.nonce, s.chunk_sizes.front(), {}};
  std::size_t at = 0;
  for (std::size_t i = 0; i < s.chunk_sizes.size(); ++i) {
    const bytes piece(s.data.begin() + static_cast<std::ptrdiff_t>(at), s.data.begin() + static_cast<std::ptrdiff_t>(at + s.chunk_sizes[i]));
    at += s.chunk_sizes[i];
    const auto sender = crypto::generate<curve::ed25519>(rng), recipient = crypto::generate<curve::ed25519>(rng);
    const auto chunk_digest = crypto::sha256(piece);
    const auto created = l.ask(xftp::command::create{{sender.pub, s.chunk_sizes[i], bytes(chunk_digest.begin(), chunk_digest.end())}, {recipient.pub}}, {}, sender.priv);
    const auto* ids = created.response.template get_if<xftp::response::sender_ids>();
    if (!ids) throw std::runtime_error("FNEW refused");
    if (!l.ask(xftp::command::put{}, ids->sender_id, sender.priv, piece).response.template get_if<xftp::response::ok>()) throw std::runtime_error("FPUT refused");
    d.chunks.push_back({static_cast<std::uint32_t>(i + 1), s.chunk_sizes[i], bytes(chunk_digest.begin(), chunk_digest.end()), {{router, ids->recipient_ids.front(), recipient.priv}}});
    std::println("our chunk {}: up ({} bytes)", i + 1, piece.size());
  }
  return d;
}
}  // namespace

int main(int, char** argv) {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  try {
    std::ifstream file(argv[1]);
    const std::string text((std::istreambuf_iterator<char>(file)), {});
    const auto link = agent::link_of(text);
    const auto& inv = *link->template get_if<agent::link::invitation>();
    const auto router = inv.queues.front().address.router;
    sockaddr_in where{};
    where.sin_family = AF_INET;
    where.sin_port = htons(router.port.value_or(5223));
    inet_pton(AF_INET, router.hosts.front().c_str(), &where.sin_addr);
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    timeval wait{30, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
    // The one place a C API asks for its own pointer type: sockaddr*.
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection");
    const auto facts = read_tls_facts();
    auto checked = session::verify(*smp::router_hello_of(read_block()), router.identity, facts);
    if (!checked) throw std::runtime_error("the router is not the one pinned");
    verified = std::move(*checked);
    agreed = verified->version();
    send_all(*smp::client_hello(agreed, router.identity));

    const std::string name = std::format("quay{}", ::getpid());
    std::println("our name: {}", name);
    const std::string profile = std::format(R"({{"v":"1-22","event":"x.info","params":{{"profile":{{"displayName":"{}","fullName":""}}}}}})", name);
    auto joined = connection::joining::join(inv, router, bytes(profile.begin(), profile.end()), rng);
    if (!joined) throw std::runtime_error(joined.error());
    auto& [conn, first] = *joined;
    bool connected = false;
    perform(first, connected);
    for (int i = 0; i < 80 && !received; ++i) {
      const auto block = read_block();
      for (const auto& t : *smp::transmissions_of(block, agreed)) {
        const auto r = smp::response_of(t.body);
        if (!r) continue;
        if (const auto* m = r->template get_if<smp::response::message>()) perform(conn.delivered(t.entity, *m, rng), connected);
        else if (t.correlation && pending.contains(*t.correlation)) perform(conn.answered(pending[*t.correlation], *r, rng), connected);
      }
    }
    if (!received) throw std::runtime_error("no file came");
    std::println("its description whole: {} chunk(s), {} bytes sealed", received->second.chunks.size(), received->second.size);
    const auto got = download(received->second);
    std::println("the file opened: {} ({} bytes)", got.head.file_name, got.content.size());
    std::ofstream(argv[2], std::ios::binary) << (got.content | std::views::transform([](byte b) { return static_cast<char>(b); }) | std::ranges::to<std::string>());
    // Ours, sent back as a chat sends a file: uploaded, offered (x.msg.new
    // with its invitation), its description given (x.msg.file.descr).
    bytes content(150000);
    rng(std::span<byte>(content));
    std::ofstream(argv[3], std::ios::binary) << (content | std::views::transform([](byte b) { return static_cast<char>(b); }) | std::ranges::to<std::string>());
    const auto ours = upload(received->second.chunks.front().replicas.front().router, "from-quay.bin", content);
    const std::string offer_id = "cXVheWZpbGUxMjM0";
    chat::event::message_new offer{chat::content{"file", "", {}, {}, {}, {}}};
    offer.file = chat::file_invitation{"from-quay.bin", static_cast<std::int64_t>(content.size()), chat::file_description_part{"", 0, false}, {}, {}, {}};
    for (const auto& body : {chat::body_of(chat::message_of(offer, offer_id)),
                             chat::body_of(chat::message_of(chat::event::file_description{offer_id, {xfile::text_of(ours), 1, true}}, "cXVheWRlc2NyMTIz"))}) {
      auto out = conn.send(body, rng);
      if (!out) throw std::runtime_error(out.error());
      perform(out->second, connected);
    }
    std::println("our file offered: from-quay.bin ({} bytes), its description given", content.size());
    // A while more, for the router to take them and the CLI to answer.
    for (int i = 0; i < 4; ++i) {
      try {
        const auto block = read_block();
        for (const auto& tr : *smp::transmissions_of(block, agreed)) {
          const auto r = smp::response_of(tr.body);
          if (!r) continue;
          if (const auto* m = r->template get_if<smp::response::message>()) perform(conn.delivered(tr.entity, *m, rng), connected);
          else if (tr.correlation && pending.contains(*tr.correlation)) perform(conn.answered(pending[*tr.correlation], *r, rng), connected);
        }
      } catch (const std::exception&) {
        break;
      }
    }
    std::println("live chat file: passed");
    return 0;
  } catch (const std::exception& failed) {
    std::println("live chat file: FAILED: {}", failed.what());
    return 1;
  }
}

// SPDX-License-Identifier: AGPL-3.0-only
// A file from simplex-chat's CLI, as a chat sends one: quay joins the CLI's
// invitation; the CLI sends a file (/f) -- uploaded to its XFTP router, the
// file offered in an x.msg.new and its description in parts
// (x.msg.file.descr); quay puts the description together (quay.chat), reads
// it (quay.xfile), gets the chunks from the XFTP router (quay.xftp), opens
// the file and writes it out (tools/live_cli_file.sh compares it).
// Usage: live_chat_file <the CLI's invitation> <where to write the file>
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

// The file got from the XFTP router its description names, chunk by chunk, and opened.
xfile::opened_file download(const xfile::description& d) {
  const auto& router = d.chunks.front().replicas.front().router;
  sockaddr_in where{};
  where.sin_family = AF_INET;
  where.sin_port = htons(router.port);
  inet_pton(AF_INET, router.host.c_str(), &where.sin_addr);
  const int xfd = ::socket(AF_INET, SOCK_STREAM, 0);
  timeval wait{20, 0};
  ::setsockopt(xfd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof wait);
  // The one place a C API asks for its own pointer type: sockaddr*.
  if (::connect(xfd, reinterpret_cast<const sockaddr*>(&where), sizeof where) != 0) throw std::runtime_error("no connection to the XFTP router");
  xftp::router_session s(router);
  std::deque<xftp::incoming::answered> answers;
  const auto ask = [&](const xftp::command_t& c, const xfile::replica& r) {
    const auto id = s.submit(c, r.id, r.key);
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
  };
  bytes sealed;
  for (const auto& c : d.chunks) {
    const auto dh = crypto::generate<curve::x25519>(rng);
    const auto got = ask(xftp::command::get{dh.pub}, c.replicas.front());
    const auto* file = got.response.template get_if<xftp::response::file>();
    if (!file) throw std::runtime_error("FGET refused");
    const auto opened = xftp::open_chunk(*file, dh.priv, got.chunk);
    if (!opened || !std::ranges::equal(crypto::sha256(*opened), c.digest)) throw std::runtime_error("a chunk that does not open or match its digest");
    sealed.insert(sealed.end(), opened->begin(), opened->end());
    (void)ask(xftp::command::acknowledge{}, c.replicas.front());
    std::println("chunk {} of {}: got and opened", c.number, d.chunks.size());
  }
  if (!std::ranges::equal(crypto::sha512(sealed), d.digest)) throw std::runtime_error("the file's digest is not as described");
  auto file = xfile::open(sealed, d.key, d.nonce);
  if (!file) throw std::runtime_error(file.error());
  ::close(xfd);
  return std::move(*file);
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
    std::println("live chat file: passed");
    return 0;
  } catch (const std::exception& failed) {
    std::println("live chat file: FAILED: {}", failed.what());
    return 1;
  }
}

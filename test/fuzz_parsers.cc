// SPDX-License-Identifier: AGPL-3.0-only
// Every parser quay puts between the network and its types, given bytes it
// did not expect: each must answer -- a value or an error -- and never crash,
// hang or throw. LLVMFuzzerTestOneInput is libFuzzer's entry (QUAY_FUZZ);
// without libFuzzer, test/fuzz_driver.cc feeds it random and mutated inputs.
#include <cstddef>
#include <cstdint>
import std;
import splice;
import quay.bytes;
import quay.crypto;
import quay.smp;
import quay.ratchet;
import quay.agent;
import quay.snapshot;
import quay.connection;
import quay.compression;
import quay.chat;
import quay.hpack;
import quay.http2;
import quay.xftp;
import quay.xfile;

using namespace quay;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const std::span<const byte> all(data, size);
  const auto rest = all.subspan(1);
  const std::string text(rest.begin(), rest.end());
  // The first byte chooses the parser; the rest is its input.
  switch (all[0] % 16) {
    case 0: (void)smp::response_of(rest); break;
    case 1: (void)smp::transmissions_of(rest, smp::max_version); break;
    case 2: (void)smp::router_hello_of(rest); break;
    case 3: (void)agent::envelope_of(rest); break;
    case 4: (void)agent::agent_message_of(rest); break;
    case 5: (void)agent::link_of(text); break;
    case 6: {
      const bytes copy(rest.begin(), rest.end());
      (void)chat::messages_of(copy);
      break;
    }
    case 7: {
      const bytes copy(rest.begin(), rest.end());
      (void)compression::bodies_of(copy);
      break;
    }
    case 8: {
      hpack::decoder d;
      (void)d.decode(rest);
      break;
    }
    case 9: {
      http2::client c("fuzz:443");
      (void)c.post("/", bytes{1, 2, 3});
      c.received(rest);
      (void)c.take_events();
      break;
    }
    case 10: (void)xfile::description_of(text); break;
    case 11: (void)xftp::response_of(rest); break;
    case 12: {
      ratchet::state s;
      (void)snapshot::restore(rest, s);
      break;
    }
    case 13: {
      connection::joining j;
      (void)snapshot::restore(rest, j);
      break;
    }
    case 14: {
      const auto e2e = smp::e2e_open(rest, [](const std::optional<public_key<curve::x25519>>&) {
        return std::expected<crypto::box_key, crypto::crypto_error>(crypto::box_key{});
      });
      (void)e2e;
      break;
    }
    default: {
      const bytes copy(rest.begin(), rest.end());
      (void)xfile::open(copy, crypto::box_key{}, crypto::box_nonce{});
      break;
    }
  }
  return 0;
}

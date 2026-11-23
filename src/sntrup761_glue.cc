// SPDX-License-Identifier: AGPL-3.0-only
// What the vendored sntrup761 (third_party/sntrup761, OpenSSH's public-domain
// implementation) calls on: SHA-512 and randombytes, both through Botan --
// the randomness the generator quay.crypto sets for the calls on this
// thread -- and the optimization blockers its constant-time code reads.
#include "botan_all.h"

#include <cstdint>

extern "C" {
volatile std::int16_t crypto_int16_optblocker = 0;
volatile std::int32_t crypto_int32_optblocker = 0;
volatile std::int64_t crypto_int64_optblocker = 0;
}

namespace {
thread_local Botan::RandomNumberGenerator* current = nullptr;
}  // namespace

extern "C" void quay_sntrup761_use(void* rng) { current = static_cast<Botan::RandomNumberGenerator*>(rng); }

extern "C" void quay_randombytes(unsigned char* out, unsigned long long n) {
  (current ? *current : Botan::system_rng()).randomize(std::span<std::uint8_t>(out, static_cast<std::size_t>(n)));
}

extern "C" int crypto_hash_sha512(unsigned char* out, const unsigned char* in, unsigned long long n) {
  auto hash = Botan::HashFunction::create_or_throw("SHA-512");
  hash->update(in, static_cast<std::size_t>(n));
  hash->final(out);
  return 0;
}

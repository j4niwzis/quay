// SPDX-License-Identifier: AGPL-3.0-only
// libFuzzer's part where there is no libFuzzer: inputs made at random and
// by mutating the seeds given as files -- bytes flipped, cut, repeated,
// spliced -- each fed to LLVMFuzzerTestOneInput under an alarm, the one
// that crashes or hangs written out. Usage: fuzz_driver <seconds> [seed files...]
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <unistd.h>
// Locally, one program: the parsers' entry compiled in.
#ifdef QUAY_FUZZ_LOCAL
#include "fuzz_parsers.cc"
#endif
import std;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

namespace {
std::vector<std::uint8_t> current;
void write_current(const char* why) {
  std::FILE* f = std::fopen("fuzz-crash.bin", "wb");
  if (f) {
    std::fwrite(current.data(), 1, current.size(), f);
    std::fclose(f);
  }
  std::fprintf(stderr, "%s on an input of %zu bytes (kept in fuzz-crash.bin)\n", why, current.size());
}
void on_signal(int s) {
  write_current(s == SIGALRM ? "a hang" : "a crash");
  std::_Exit(1);
}
}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGSEGV, on_signal), std::signal(SIGABRT, on_signal), std::signal(SIGALRM, on_signal), std::signal(SIGFPE, on_signal);
  const int seconds = argc > 1 ? std::atoi(argv[1]) : 10;
  std::vector<std::vector<std::uint8_t>> seeds;
  for (int i = 2; i < argc; ++i) {
    std::ifstream f(argv[i], std::ios::binary);
    std::vector<std::uint8_t> s;
    for (char c; f.get(c);) s.push_back(static_cast<std::uint8_t>(c));
    // Each seed tried under every parser.
    for (std::uint8_t which = 0; which < 16; ++which) {
      auto with = s;
      with.insert(with.begin(), which);
      seeds.push_back(std::move(with));
    }
  }
  std::mt19937_64 rng(12345);
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  std::uint64_t runs = 0;
  while (std::chrono::steady_clock::now() < until) {
    if (seeds.empty() || rng() % 4 == 0) {
      current.resize(rng() % 600);
      for (auto& b : current) b = static_cast<std::uint8_t>(rng());
    } else {
      current = seeds[rng() % seeds.size()];
      for (int m = 0, n = 1 + static_cast<int>(rng() % 8); m < n && !current.empty(); ++m) {
        const auto at = rng() % current.size();
        switch (rng() % 5) {
          case 0: current[at] ^= static_cast<std::uint8_t>(1u << (rng() % 8)); break;
          case 1: current[at] = static_cast<std::uint8_t>(rng()); break;
          case 2: current.resize(at + 1); break;
          case 3: current.insert(current.begin() + static_cast<std::ptrdiff_t>(at), current.begin(), current.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(at, 64))); break;
          default: {
            const auto& other = seeds[rng() % seeds.size()];
            current.insert(current.begin() + static_cast<std::ptrdiff_t>(at), other.begin() + 1, other.end());
          }
        }
      }
    }
    ::alarm(5);
    try {
      LLVMFuzzerTestOneInput(current.data(), current.size());
    } catch (const std::exception& e) {
      write_current((std::string("an exception: ") + e.what()).c_str());
      return 1;
    }
    ::alarm(0);
    ++runs;
  }
  std::printf("%llu inputs, no crash, hang or exception\n", static_cast<unsigned long long>(runs));
  return 0;
}

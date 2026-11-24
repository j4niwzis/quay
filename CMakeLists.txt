cmake_minimum_required(VERSION 4.3.4 FATAL_ERROR)

# quay: SimpleX -- its messaging protocol, agent and chat -- as C++26
# modules, sans-IO: over a transport of the caller's, with the control flow
# the caller's. Cryptography is Botan's, and sntrup761 OpenSSH's.
include(${CMAKE_CURRENT_LIST_DIR}/cmake/import-std.cmake)
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_EXTENSIONS OFF)

project(quay VERSION 0.1 LANGUAGES C CXX)

option(QUAY_TESTS "Build the tests" ${PROJECT_IS_TOP_LEVEL})

if(NOT COMMAND cme_find_package)
  set(CME_WITHOUT_PROVIDER ON)
  include(${CMAKE_CURRENT_LIST_DIR}/cmake/get_cme.cmake)
endif()

# splice: the variant quay's errors and messages are held in, and the
# visiting.
set(SPLICE_CONSTEXPR_STEPS 100000000 CACHE STRING
  "clang's -fconstexpr-steps for splice, as quay and its family set it")
cme_declare_port(NAME splice PROVIDES splice
  GITHUB_REPOSITORY j4niwzis/splice
  GIT_TAG 8a7755a335917daf3bbfc54ef8a3a160f8445d15
  LICENSE GPL-3.0-only
  TARGETS splice)
cme_options(splice "SPLICE_TESTS OFF")
cme_find_package(splice REQUIRED)

# knot: simplex-chat's JSON read straight into quay.chat's types, and written from them.
cme_declare_port(NAME knot PROVIDES knot
  GITHUB_REPOSITORY j4niwzis/knot
  GIT_TAG 54dd75281fc01014774196a96143d36155b26299
  LICENSE AGPL-3.0-only
  TARGETS knot)
cme_find_package(knot REQUIRED)

set(QUAY_CONSTEXPR_STEPS 100000000 CACHE STRING
  "clang's -fconstexpr-steps for quay and what imports it, as its family sets it")

# ---- Botan ------------------------------------------------------------------
# Botan 3, as one amalgamated unit of only the modules quay uses, made by
# Botan's own configure.py at configure time from its release, pinned by
# its hash -- the curves, NaCl's box (Botan's libsodium-compatible API), AES
# and GCM, the hashes, HMAC and HKDF, and TLS 1.3 -- and built as a static library.
set(QUAY_BOTAN_VERSION 3.14.1)
set(QUAY_BOTAN_SHA256 d1046b8f5b18b80197cd1d62cf66743edfc0a54ab91bf8e5d916a99212ffc5e0)
set(QUAY_BOTAN_MODULES
  x25519 ed25519 x448 ed448 salsa20 poly1305 sodium aes gcm sha2_32 sha2_64 sha3 keccak hkdf hmac system_rng x509
  tls13 chacha20poly1305)
set(botan_root "${CMAKE_BINARY_DIR}/_botan")
set(botan_source "${botan_root}/botan-${QUAY_BOTAN_VERSION}")
set(botan_made "${botan_root}/made")
string(REPLACE ";" "," botan_modules "${QUAY_BOTAN_MODULES}")
set(botan_stamp "${QUAY_BOTAN_VERSION};eddsa-1;${botan_modules};${CMAKE_CXX_COMPILER};${CMAKE_SYSTEM_NAME};${CMAKE_SYSTEM_PROCESSOR}")
if(NOT EXISTS "${botan_made}/botan_all.cpp" OR NOT "${QUAY_BOTAN_STAMP}" STREQUAL "${botan_stamp}")
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  if(NOT EXISTS "${botan_source}/configure.py")
    file(DOWNLOAD "https://github.com/randombit/botan/archive/refs/tags/${QUAY_BOTAN_VERSION}.tar.gz"
         "${botan_root}/botan.tar.gz" EXPECTED_HASH SHA256=${QUAY_BOTAN_SHA256} TLS_VERIFY ON)
    file(ARCHIVE_EXTRACT INPUT "${botan_root}/botan.tar.gz" DESTINATION "${botan_root}")
  endif()
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(botan_cc clang)
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(botan_cc gcc)
  elseif(MSVC)
    set(botan_cc msvc)
  endif()
  file(MAKE_DIRECTORY "${botan_made}")
  execute_process(
    COMMAND "${Python3_EXECUTABLE}" "${botan_source}/configure.py"
            --minimized-build --amalgamation --disable-shared --without-documentation
            --enable-modules=${botan_modules} --cc=${botan_cc} --cc-bin=${CMAKE_CXX_COMPILER}
            --with-build-dir=${botan_made}/build
    WORKING_DIRECTORY "${botan_made}"
    RESULT_VARIABLE botan_configured)
  if(NOT botan_configured EQUAL 0)
    message(FATAL_ERROR "Botan's configure.py failed (${botan_configured}).")
  endif()
  # Botan leaves EdDSA out of TLS 1.3's signature schemes (botan#2958);
  # SMP routers' certificates are Ed25519 or Ed448: put back (tools/botan_eddsa.py).
  execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/botan_eddsa.py" "${botan_made}/botan_all.cpp"
                  RESULT_VARIABLE botan_patched)
  if(NOT botan_patched EQUAL 0)
    message(FATAL_ERROR "Botan's amalgamation could not be patched for EdDSA (${botan_patched}).")
  endif()
  set(QUAY_BOTAN_STAMP "${botan_stamp}" CACHE INTERNAL "What Botan's amalgamation was made for")
endif()
add_library(quay_botan STATIC "${botan_made}/botan_all.cpp")
target_include_directories(quay_botan SYSTEM PUBLIC "$<BUILD_INTERFACE:${botan_made}>")
target_compile_features(quay_botan PUBLIC cxx_std_20)
set_target_properties(quay_botan PROPERTIES POSITION_INDEPENDENT_CODE ON CXX_SCAN_FOR_MODULES OFF)
find_package(Threads REQUIRED)
target_link_libraries(quay_botan PUBLIC Threads::Threads)

# ---- sntrup761 ----------------------------------------------------------------
# OpenSSH's public-domain sntrup761.c, as it is, over a header of quay's own
# (third_party/sntrup761/crypto_api.h) and its glue: SHA-512 and randomness
# through Botan.
add_library(quay_sntrup761 STATIC third_party/sntrup761/sntrup761.c src/sntrup761_glue.cc)
target_include_directories(quay_sntrup761 PRIVATE third_party/sntrup761)
target_compile_definitions(quay_sntrup761 PRIVATE USE_SNTRUP761X25519)
target_link_libraries(quay_sntrup761 PUBLIC quay_botan)
set_target_properties(quay_sntrup761 PROPERTIES POSITION_INDEPENDENT_CODE ON CXX_SCAN_FOR_MODULES OFF)

# ---- zstd ---------------------------------------------------------------------
# zstd's library from its release, pinned by its hash, built from its own
# sources: simplex-chat compresses message batches with it (quay.compression).
set(QUAY_ZSTD_VERSION 1.5.7)
set(QUAY_ZSTD_SHA256 eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3)
set(zstd_root "${CMAKE_BINARY_DIR}/_zstd")
set(zstd_lib "${zstd_root}/zstd-${QUAY_ZSTD_VERSION}/lib")
if(NOT EXISTS "${zstd_lib}/zstd.h")
  file(DOWNLOAD "https://github.com/facebook/zstd/releases/download/v${QUAY_ZSTD_VERSION}/zstd-${QUAY_ZSTD_VERSION}.tar.gz"
       "${zstd_root}/zstd.tar.gz" EXPECTED_HASH SHA256=${QUAY_ZSTD_SHA256} TLS_VERIFY ON)
  file(ARCHIVE_EXTRACT INPUT "${zstd_root}/zstd.tar.gz" DESTINATION "${zstd_root}")
endif()
file(GLOB zstd_sources "${zstd_lib}/common/*.c" "${zstd_lib}/compress/*.c" "${zstd_lib}/decompress/*.c")
add_library(quay_zstd STATIC ${zstd_sources})
target_include_directories(quay_zstd SYSTEM PUBLIC "$<BUILD_INTERFACE:${zstd_lib}>")
target_compile_definitions(quay_zstd PRIVATE ZSTD_DISABLE_ASM ZSTD_MULTITHREAD=0 XXH_NAMESPACE=ZSTD_)
set_target_properties(quay_zstd PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 11)

# ---- quay ---------------------------------------------------------------------
add_library(quay)
target_sources(quay PUBLIC FILE_SET CXX_MODULES BASE_DIRS src
  FILES src/bytes.cc src/snapshot.cc src/crypto.cc src/smp.cc src/ratchet.cc src/agent.cc src/session.cc src/tls.cc src/hpack.cc src/http2.cc src/xftp.cc src/xfile.cc src/connection.cc src/client.cc src/compression.cc src/chat.cc)
target_compile_features(quay PUBLIC cxx_std_26)
target_link_libraries(quay PUBLIC splice knot quay_botan quay_zstd PRIVATE quay_sntrup761)
target_compile_options(quay PUBLIC
  $<$<COMPILE_LANG_AND_ID:CXX,Clang,AppleClang>:-fconstexpr-steps=${QUAY_CONSTEXPR_STEPS}>)

if(QUAY_TESTS)
  enable_testing()
  cme_declare_port(NAME googletest-modules PROVIDES GTest
    GITHUB_REPOSITORY j4niwzis/googletest-modules
    GIT_TAG 706920f1d230f0316d271466d8885735be3e300e
    LICENSE BSD-3-Clause
    SYSTEM NEVER
    TARGETS gtest_main)
  cme_options(googletest-modules
    "BUILD_GMOCK OFF" "INSTALL_GTEST OFF" "gtest_build_modules ON"
    "gtest_build_tests OFF" "gtest_build_samples OFF")
  cme_find_package(GTest REQUIRED)
  foreach(target IN ITEMS gtest gtest_main)
    if(TARGET ${target})
      get_target_property(aliased ${target} ALIASED_TARGET)
      if(aliased)
        set(target ${aliased})
      endif()
      set_target_properties(${target} PROPERTIES CXX_STANDARD 26 CXX_STANDARD_REQUIRED ON)
    endif()
  endforeach()
  if(TARGET GTest::gtest_main)
    set(quay_gtest GTest::gtest_main)
  else()
    set(quay_gtest gtest_main)
  endif()
  foreach(name IN ITEMS bytes crypto sntrup761_kat smp ratchet agent compression chat hpack http2)
    add_executable(quay-${name}-test test/${name}_test.cc)
    target_include_directories(quay-${name}-test PRIVATE test)
    target_link_libraries(quay-${name}-test PRIVATE quay ${quay_gtest})
    add_test(NAME ${name} COMMAND quay-${name}-test)
  endforeach()
  # Against a real router (CI runs smp-server; the tests reach it by quay.tls):
  # QUAY_SMP_ADDRESS, QUAY_SMP_FINGERPRINT.
  option(QUAY_LIVE_TESTS "Test against a running smp-server" OFF)
  if(QUAY_LIVE_TESTS)
    foreach(live IN ITEMS live_smp live_pin live_tls live_xftp)
      add_executable(quay-${live} test/${live}.cc)
      target_link_libraries(quay-${live} PRIVATE quay)
      add_test(NAME ${live} COMMAND quay-${live})
    endforeach()
    # And against simplex-chat's CLI on that router (its WebSocket API on
    # 5225): its invitation joined, by hand and by quay.connection.
    foreach(live IN ITEMS live_join live_connection)
      add_executable(quay-${live} test/${live}.cc)
      target_link_libraries(quay-${live} PRIVATE quay)
      add_test(NAME ${live} COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli.sh $<TARGET_FILE:quay-${live}>)
    endforeach()
    # The inviting side: the CLI joins quay's invitation.
    add_executable(quay-live_invite test/live_invite.cc)
    target_link_libraries(quay-live_invite PRIVATE quay)
    add_test(NAME live_invite COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_invite.sh $<TARGET_FILE:quay-live_invite>)
    # The standard flow (KEY, HELLO both ways), both sides.
    add_test(NAME live_invite_standard COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_invite.sh $<TARGET_FILE:quay-live_invite>)
    add_test(NAME live_connection_standard COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli.sh $<TARGET_FILE:quay-live_connection>)
    set_tests_properties(live_invite_standard live_connection_standard PROPERTIES ENVIRONMENT QUAY_FLOW=standard)
    # The CLI speaks first once connected; quay's receipt marks its message delivered.
    set_tests_properties(live_connection PROPERTIES ENVIRONMENT "QUAY_CLI_SAYS=hello quay, a receipt please;QUAY_CLI_SWITCHES=1;QUAY_OWN_SWITCH=1")
    # Files with simplexmq's own xftp client: each side receives the other's.
    add_executable(quay-live_xfile test/live_xfile.cc)
    target_link_libraries(quay-live_xfile PRIVATE quay)
    add_test(NAME live_xfile COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_xftp_cli.sh $<TARGET_FILE:quay-live_xfile>)
    # A file from the CLI, as a chat sends one: offered, its description in parts, got over XFTP.
    add_executable(quay-live_chat_file test/live_chat_file.cc)
    target_link_libraries(quay-live_chat_file PRIVATE quay)
    add_test(NAME live_chat_file COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_file.sh $<TARGET_FILE:quay-live_chat_file>)
    # A group of the CLI's, joined: invited, our member connection made, messages both ways.
    add_executable(quay-live_group test/live_group.cc)
    target_link_libraries(quay-live_group PRIVATE quay)
    add_test(NAME live_group COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_group.sh $<TARGET_FILE:quay-live_group>)
    # Three in the group (a second CLI on 5226): introduced, our invitation answered, messages directly both ways.
    add_test(NAME live_group3 COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_group3.sh $<TARGET_FILE:quay-live_group>)
    # quay as a group's host: the CLI invited, its member connection allowed, messages both ways.
    add_executable(quay-live_group_host test/live_group_host.cc)
    target_link_libraries(quay-live_group_host PRIVATE quay)
    add_test(NAME live_group_host COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_group_host.sh $<TARGET_FILE:quay-live_group_host>)
    # quay hosting two CLIs: both invited, introduced to each other, talking directly.
    add_executable(quay-live_group_host3 test/live_group_host3.cc)
    target_link_libraries(quay-live_group_host3 PRIVATE quay)
    add_test(NAME live_group_host3 COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_group_host3.sh $<TARGET_FILE:quay-live_group_host3>)
    # A group joined through its link: the contact request, the host's x.grp.link.inv allowed, messages both ways.
    add_executable(quay-live_group_link test/live_group_link.cc)
    target_link_libraries(quay-live_group_link PRIVATE quay)
    add_test(NAME live_group_link COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_group_link.sh $<TARGET_FILE:quay-live_group_link>)
    # A bot's shape: one router session (quay.client) for an address and the contact it accepts.
    add_executable(quay-live_client test/live_client.cc)
    target_link_libraries(quay-live_client PRIVATE quay)
    add_test(NAME live_client COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_invite.sh $<TARGET_FILE:quay-live_client>)
    add_test(NAME live_client_proxied COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_invite.sh $<TARGET_FILE:quay-live_client>)
    set_tests_properties(live_client_proxied PROPERTIES ENVIRONMENT QUAY_PROXY=1)
    # quay's own address: the CLI's contact request, accepted.
    add_executable(quay-live_address test/live_address.cc)
    target_link_libraries(quay-live_address PRIVATE quay)
    add_test(NAME live_address COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_invite.sh $<TARGET_FILE:quay-live_address>)
    # And through the CLI's contact address: quay's contact request, accepted.
    add_test(NAME live_contact COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_cli_contact.sh $<TARGET_FILE:quay-live_invite>)
  endif()
endif()

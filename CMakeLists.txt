cmake_minimum_required(VERSION 3.20)
project(pqc_api CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Find dependencies ────────────────────────────────────────────────────────
find_package(OpenSSL   REQUIRED)
find_package(Drogon    REQUIRED)
find_package(CURL      REQUIRED)
find_package(nlohmann_json REQUIRED)

# libsodium — no CMake module, use pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# hiredis
find_path(HIREDIS_INCLUDE_DIR hiredis/hiredis.h)
find_library(HIREDIS_LIB hiredis)

# libpqxx
find_package(PostgreSQL REQUIRED)
find_path(PQXX_INCLUDE_DIR pqxx/pqxx)
find_library(PQXX_LIB pqxx)

# ─── Source files ─────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp

    # TLS layer
    src/tls/OQSProvider.cpp
    src/tls/OpenSSLContext.cpp

    # Crypto
    src/crypto/DilithiumSigner.cpp

    # PKI
    src/pki/Certificate.cpp
    src/pki/OCSPClient.cpp
    src/pki/RevocationChecker.cpp

    # Persistence
    src/persistence/RedisClient.cpp
    src/persistence/PostgreSQLClient.cpp
    src/persistence/UserRepository.cpp
    src/persistence/SessionRepository.cpp
    src/persistence/DocumentRepository.cpp

    # Auth
    src/auth/AuthManager.cpp

    # API
    src/api/Controllers.cpp
)

# ─── Build target ─────────────────────────────────────────────────────────────
add_executable(pqc_api ${SOURCES})

target_include_directories(pqc_api PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${HIREDIS_INCLUDE_DIR}
    ${PQXX_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIRS}
    ${PostgreSQL_INCLUDE_DIRS}
)

target_link_libraries(pqc_api PRIVATE
    Drogon::Drogon
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    nlohmann_json::nlohmann_json
    ${HIREDIS_LIB}
    ${PQXX_LIB}
    ${PostgreSQL_LIBRARIES}
    ${SODIUM_LIBRARIES}
)

# Compiler hardening flags
target_compile_options(pqc_api PRIVATE
    -Wall -Wextra -Wpedantic
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

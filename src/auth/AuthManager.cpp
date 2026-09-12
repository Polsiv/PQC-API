#include "auth/AuthManager.h"
#include <sodium.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <chrono>
#include <stdexcept>
#include <random>

using json = nlohmann::json;

// ─── Base64url helpers ────────────────────────────────────────────────────────

static std::string base64url_encode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input.data(), (int)input.size());
    BIO_flush(b64);

    char* data = nullptr;
    long  len  = BIO_get_mem_data(mem, &data);
    std::string result(data, len);
    BIO_free_all(b64);

    // Standard base64 → base64url
    for (char& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!result.empty() && result.back() == '=') result.pop_back();
    return result;
}

static std::string base64url_decode(const std::string& input) {
    std::string padded = input;
    for (char& c : padded) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (padded.size() % 4 != 0) padded += '=';

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(padded.data(), (int)padded.size());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    std::string result(padded.size(), '\0');
    int len = BIO_read(b64, result.data(), (int)result.size());
    BIO_free_all(b64);
    if (len > 0) result.resize(len);
    else result.clear();
    return result;
}

static std::string generate_session_id() {
    unsigned char buf[32];
    randombytes_buf(buf, sizeof(buf));                   // libsodium CSPRNG
    std::string result;
    result.reserve(64);
    for (auto b : buf) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", b);
        result += hex;
    }
    return result;
}

// ─── AuthManager ─────────────────────────────────────────────────────────────

AuthManager::AuthManager(const std::string& secret_key,
                         UserRepository&    user_repo,
                         SessionRepository& session_repo)
    : secret_key_(secret_key), user_repo_(user_repo), session_repo_(session_repo) {
    if (sodium_init() < 0) {
        throw std::runtime_error("[AuthManager] libsodium init failed");
    }
}

AuthResult AuthManager::registerUser(const std::string& username,
                                      const std::string& password) {
    if (username.empty() || password.size() < 8) {
        return { false, {}, {}, "Username empty or password too short" };
    }

    if (user_repo_.findByUsername(username)) {
        return { false, {}, {}, "Username already exists" };
    }

    std::string hash = hashPassword(password);
    if (!user_repo_.save(username, hash)) {
        return { false, {}, {}, "Failed to save user" };
    }

    return { true, username, {}, {} };
}

AuthResult AuthManager::login(const std::string& username,
                               const std::string& password) {
    auto user = user_repo_.findByUsername(username);
    if (!user) {
        return { false, {}, {}, "Invalid credentials" };
    }

    if (!verifyPassword(password, user->password_hash)) {
        return { false, {}, {}, "Invalid credentials" };
    }

    std::string session_id = generate_session_id();
    std::string token      = buildToken(std::to_string(user->id), session_id);

    // Store session in Redis with TTL
    session_repo_.storeKey(session_id, std::to_string(user->id));

    return { true, std::to_string(user->id), token, {} };
}

std::optional<std::string> AuthManager::verifyToken(const std::string& token) {
    std::string user_id, session_id;
    if (!parseToken(token, user_id, session_id)) {
        return std::nullopt;
    }

    // Confirm session still exists in Redis
    if (!session_repo_.getKey(session_id)) {
        return std::nullopt;
    }

    return user_id;
}

bool AuthManager::revokeToken(const std::string& session_id) {
    return session_repo_.invalidate(session_id);
}

bool AuthManager::logout(const std::string& token) {
    std::string user_id, session_id;
    if (!parseToken(token, user_id, session_id)) {
        return false;
    }
    // Best-effort revoke — deleting an already-expired session is a no-op,
    // so logout stays idempotent even if the session already lapsed.
    session_repo_.invalidate(session_id);
    return true;
}

// ─── Private helpers ──────────────────────────────────────────────────────────

std::string AuthManager::hashPassword(const std::string& password) const {
    char hash_buf[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash_buf, password.c_str(), password.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        throw std::runtime_error("[AuthManager] Argon2id hashing failed (OOM?)");
    }
    return std::string(hash_buf);
}

bool AuthManager::verifyPassword(const std::string& password,
                                  const std::string& hash) const {
    return crypto_pwhash_str_verify(
        hash.c_str(), password.c_str(), password.size()) == 0;
}

std::string AuthManager::buildToken(const std::string& user_id,
                                     const std::string& session_id) const {
    // Header
    json header = { {"alg", "HS256"}, {"typ", "JWT"} };
    std::string h = base64url_encode(header.dump());

    // Payload
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::seconds(TOKEN_TTL_SECONDS);

    json payload = {
        {"sub",  user_id},
        {"sid",  session_id},
        {"iat",  std::chrono::system_clock::to_time_t(now)},
        {"exp",  std::chrono::system_clock::to_time_t(exp)}
    };
    std::string p = base64url_encode(payload.dump());

    // Sign header.payload with HMAC-SHA256
    std::string signing_input = h + "." + p;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digest_len = 0;
    HMAC(EVP_sha256(),
         secret_key_.data(), static_cast<int>(secret_key_.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()),
         signing_input.size(), digest, &digest_len);

    std::string sig = base64url_encode(
        std::string(reinterpret_cast<char*>(digest), digest_len));

    return h + "." + p + "." + sig;
}

bool AuthManager::parseToken(const std::string& token,
                              std::string& out_user_id,
                              std::string& out_session_id) const {
    // Split into three parts
    auto p1 = token.find('.');
    if (p1 == std::string::npos) return false;
    auto p2 = token.find('.', p1 + 1);
    if (p2 == std::string::npos) return false;

    std::string h   = token.substr(0, p1);
    std::string p   = token.substr(p1 + 1, p2 - p1 - 1);
    std::string sig = token.substr(p2 + 1);

    // Verify HMAC-SHA256 signature
    std::string signing_input = h + "." + p;
    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned int  expected_len = 0;
    HMAC(EVP_sha256(),
         secret_key_.data(), static_cast<int>(secret_key_.size()),
         reinterpret_cast<const unsigned char*>(signing_input.data()),
         signing_input.size(), expected, &expected_len);

    std::string sig_decoded = base64url_decode(sig);
    if (sig_decoded.size() != expected_len ||
        CRYPTO_memcmp(sig_decoded.data(), expected, expected_len) != 0) {
        std::cerr << "[AuthManager] Token signature verification failed\n";
        return false;
    }

    // Parse payload
    try {
        json payload = json::parse(base64url_decode(p));

        // Check expiry
        auto now = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());
        if (payload["exp"].get<long>() < now) {
            std::cerr << "[AuthManager] Token expired\n";
            return false;
        }

        out_user_id   = payload["sub"].get<std::string>();
        out_session_id = payload["sid"].get<std::string>();
        return true;
    } catch (...) {
        return false;
    }
}

#pragma once

#include "crypto/DilithiumSigner.h"
#include "persistence/UserRepository.h"
#include "persistence/SessionRepository.h"
#include <string>
#include <optional>

struct AuthResult {
    bool        success  = false;
    std::string user_id;
    std::string token;
    std::string error;
};

/**
 * AuthManager
 * Handles registration, login, and token verification.
 *
 * Token format (Dilithium-signed JWT-style):
 *   Base64(header).Base64(payload).Base64(ML-DSA-65 signature)
 *
 * Password storage: Argon2id via libsodium (crypto_pwhash).
 * Token signing:    ML-DSA-65 via DilithiumSigner.
 */
class AuthManager {
public:
    AuthManager(DilithiumSigner&    signer,
                UserRepository&     user_repo,
                SessionRepository&  session_repo);

    // Register a new user — hashes password with Argon2id
    AuthResult registerUser(const std::string& username,
                            const std::string& password);

    // Login — verify password, issue signed token, store session
    AuthResult login(const std::string& username,
                     const std::string& password);

    // Verify a token — returns user_id on success
    std::optional<std::string> verifyToken(const std::string& token);

    // Revoke a session
    bool revokeToken(const std::string& session_id);

private:
    std::string hashPassword(const std::string& password) const;
    bool        verifyPassword(const std::string& password,
                               const std::string& hash) const;
    std::string buildToken(const std::string& user_id,
                           const std::string& session_id) const;
    bool        parseToken(const std::string& token,
                           std::string& out_user_id,
                           std::string& out_session_id) const;

    DilithiumSigner&   signer_;
    UserRepository&    user_repo_;
    SessionRepository& session_repo_;

    static constexpr int TOKEN_TTL_SECONDS = 3600;
};

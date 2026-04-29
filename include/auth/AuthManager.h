#pragma once

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

class AuthManager {
public:
    AuthManager(const std::string& secret_key,
                UserRepository&    user_repo,
                SessionRepository& session_repo);

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

    std::string        secret_key_;
    UserRepository&    user_repo_;
    SessionRepository& session_repo_;

    static constexpr int TOKEN_TTL_SECONDS = 3600;
};

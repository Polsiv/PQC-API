#pragma once

#include "persistence/PostgreSQLClient.h"
#include <string>
#include <optional>

struct User {
    int         id;
    std::string username;
    std::string password_hash;   // Argon2id via libsodium
    std::string created_at;
    int         role;            // 0 = normal user (default), 1 = admin
};

/**
 * UserRepository
 * Data access object for the users table.
 * All credential storage uses Argon2id hashes (via libsodium).
 */

class UserRepository {
public:
    explicit UserRepository(PostgreSQLClient& db);

    bool               save(const std::string& username, const std::string& password_hash);
    std::optional<User> findById(int id);
    std::optional<User> findByUsername(const std::string& username);
    bool               remove(int id);

    // Set a user's role (0 = user, 1 = admin). Idempotent.
    bool               setRole(const std::string& username, int role);

private:
    PostgreSQLClient& db_;
};

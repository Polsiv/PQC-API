#include "persistence/UserRepository.h"
#include <iostream>

UserRepository::UserRepository(PostgreSQLClient& db) : db_(db) {}

bool UserRepository::createTable() {
    const std::string sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      VARCHAR(64) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    )";
    return db_.execute(sql);
}

bool UserRepository::save(const std::string& username,
                           const std::string& password_hash) {
    return db_.execute(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) "
        "ON CONFLICT (username) DO NOTHING",
        { username, password_hash });
}

std::optional<User> UserRepository::findById(int id) {
    auto result = db_.query(
        "SELECT id, username, password_hash, created_at FROM users WHERE id = $1",
        { std::to_string(id) });

    if (result.empty()) return std::nullopt;

    const auto& row = result[0];
    return User{
        row["id"].as<int>(),
        row["username"].c_str(),
        row["password_hash"].c_str(),
        row["created_at"].c_str()
    };
}

std::optional<User> UserRepository::findByUsername(const std::string& username) {
    auto result = db_.query(
        "SELECT id, username, password_hash, created_at FROM users WHERE username = $1",
        { username });

    if (result.empty()) return std::nullopt;

    const auto& row = result[0];
    return User{
        row["id"].as<int>(),
        row["username"].c_str(),
        row["password_hash"].c_str(),
        row["created_at"].c_str()
    };
}

bool UserRepository::remove(int id) {
    return db_.execute("DELETE FROM users WHERE id = $1", { std::to_string(id) });
}

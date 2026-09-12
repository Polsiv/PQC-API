#include "persistence/UserRepository.h"
#include <iostream>

UserRepository::UserRepository(PostgreSQLClient& db) : db_(db) {}

bool UserRepository::save(const std::string& username,
                           const std::string& password_hash) {
    return db_.execute(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) "
        "ON CONFLICT (username) DO NOTHING",
        { username, password_hash });
}

std::optional<User> UserRepository::findById(int id) {
    auto result = db_.query(
        "SELECT id, username, password_hash, created_at, role FROM users WHERE id = $1",
        { std::to_string(id) });

    if (result.empty()) return std::nullopt;

    const auto& row = result[0];
    return User{
        row["id"].as<int>(),
        row["username"].c_str(),
        row["password_hash"].c_str(),
        row["created_at"].c_str(),
        row["role"].as<int>()
    };
}

std::optional<User> UserRepository::findByUsername(const std::string& username) {
    auto result = db_.query(
        "SELECT id, username, password_hash, created_at, role FROM users WHERE username = $1",
        { username });

    if (result.empty()) return std::nullopt;

    const auto& row = result[0];
    return User{
        row["id"].as<int>(),
        row["username"].c_str(),
        row["password_hash"].c_str(),
        row["created_at"].c_str(),
        row["role"].as<int>()
    };
}

bool UserRepository::remove(int id) {
    return db_.execute("DELETE FROM users WHERE id = $1", { std::to_string(id) });
}

bool UserRepository::setRole(const std::string& username, int role) {
    return db_.execute("UPDATE users SET role = $2 WHERE username = $1",
                       { username, std::to_string(role) });
}

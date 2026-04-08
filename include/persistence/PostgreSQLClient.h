#pragma once

#include <pqxx/pqxx>
#include <string>
#include <optional>
#include <functional>

/**
 * PostgreSQLClient
 * RAII wrapper around libpqxx for user and API data persistence.
 * Uses prepared statements for all queries to prevent SQL injection.
 */
class PostgreSQLClient {
public:
    explicit PostgreSQLClient(const std::string& connection_string);
    ~PostgreSQLClient() = default;

    bool isConnected() const;

    // Execute a query and return all rows
    pqxx::result query(const std::string& sql,
                       const std::vector<std::string>& params = {});

    // Execute a non-returning statement (INSERT, UPDATE, DELETE)
    bool execute(const std::string& sql,
                 const std::vector<std::string>& params = {});

    // Run a function inside a transaction — rolls back on exception
    bool withTransaction(const std::function<void(pqxx::work&)>& fn);

    // Non-copyable
    PostgreSQLClient(const PostgreSQLClient&)            = delete;
    PostgreSQLClient& operator=(const PostgreSQLClient&) = delete;

private:
    std::unique_ptr<pqxx::connection> conn_;
};

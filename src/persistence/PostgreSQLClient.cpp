#include "persistence/PostgreSQLClient.h"
#include <iostream>
#include <stdexcept>

PostgreSQLClient::PostgreSQLClient(const std::string& connection_string) {
    try {
        conn_ = std::make_unique<pqxx::connection>(connection_string);
        if (conn_->is_open()) {
            std::cout << "[PostgreSQLClient] Connected to: "
                      << conn_->dbname() << "\n";
        }
    } catch (const pqxx::broken_connection& e) {
        throw std::runtime_error(
            std::string("[PostgreSQLClient] Connection failed: ") + e.what());
    }
}

bool PostgreSQLClient::isConnected() const {
    return conn_ && conn_->is_open();
}

pqxx::result PostgreSQLClient::query(const std::string& sql,
                                      const std::vector<std::string>& params) {
    pqxx::work txn(*conn_);
    pqxx::result result;

    if (params.empty()) {
        result = txn.exec(sql);
    } else {
        // Build parameterized query using pqxx params
        pqxx::params p;
        for (const auto& param : params) p.append(param);
        result = txn.exec_params(sql, p);
    }

    txn.commit();
    return result;
}

bool PostgreSQLClient::execute(const std::string& sql,
                                const std::vector<std::string>& params) {
    try {
        pqxx::work txn(*conn_);
        if (params.empty()) {
            txn.exec(sql);
        } else {
            pqxx::params p;
            for (const auto& param : params) p.append(param);
            txn.exec_params(sql, p);
        }
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[PostgreSQLClient] Execute failed: " << e.what() << "\n";
        return false;
    }
}

bool PostgreSQLClient::withTransaction(const std::function<void(pqxx::work&)>& fn) {
    try {
        pqxx::work txn(*conn_);
        fn(txn);
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[PostgreSQLClient] Transaction rolled back: " << e.what() << "\n";
        return false;
    }
}

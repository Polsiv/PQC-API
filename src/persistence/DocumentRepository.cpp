#include "persistence/DocumentRepository.h"
#include <iostream>

DocumentRepository::DocumentRepository(PostgreSQLClient& db) : db_(db) {}

bool DocumentRepository::createTable() {
    return db_.execute(R"(
        CREATE TABLE IF NOT EXISTS documents (
            id          SERIAL PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            filename    VARCHAR(255) NOT NULL,
            pdf_data    TEXT NOT NULL,
            signature   TEXT NOT NULL,
            sha256_hash VARCHAR(64) NOT NULL,
            signed_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    )");
}

int DocumentRepository::save(int user_id, const std::string& filename,
                              const std::string& pdf_b64,
                              const std::string& signature_b64,
                              const std::string& sha256_hash) {
    try {
        auto result = db_.query(
            "INSERT INTO documents (user_id, filename, pdf_data, signature, sha256_hash) "
            "VALUES ($1, $2, $3, $4, $5) RETURNING id",
            { std::to_string(user_id), filename, pdf_b64, signature_b64, sha256_hash });
        if (result.empty()) return -1;
        return result[0]["id"].as<int>();
    } catch (const std::exception& e) {
        std::cerr << "[DocumentRepository] save failed: " << e.what() << "\n";
        return -1;
    }
}

std::optional<Document> DocumentRepository::findById(int id) {
    auto result = db_.query(
        "SELECT id, user_id, filename, sha256_hash, signature, signed_at "
        "FROM documents WHERE id = $1",
        { std::to_string(id) });

    if (result.empty()) return std::nullopt;
    const auto& row = result[0];
    return Document{
        row["id"].as<int>(),
        row["user_id"].as<int>(),
        row["filename"].c_str(),
        row["sha256_hash"].c_str(),
        row["signature"].c_str(),
        row["signed_at"].c_str()
    };
}

std::vector<Document> DocumentRepository::findByUserId(int user_id) {
    auto result = db_.query(
        "SELECT id, user_id, filename, sha256_hash, signature, signed_at "
        "FROM documents WHERE user_id = $1 ORDER BY signed_at DESC",
        { std::to_string(user_id) });

    std::vector<Document> docs;
    docs.reserve(result.size());
    for (const auto& row : result) {
        docs.push_back({
            row["id"].as<int>(),
            row["user_id"].as<int>(),
            row["filename"].c_str(),
            row["sha256_hash"].c_str(),
            row["signature"].c_str(),
            row["signed_at"].c_str()
        });
    }
    return docs;
}

std::optional<std::string> DocumentRepository::getPdfData(int id) {
    auto result = db_.query(
        "SELECT pdf_data FROM documents WHERE id = $1",
        { std::to_string(id) });
    if (result.empty()) return std::nullopt;
    return std::string(result[0]["pdf_data"].c_str());
}

bool DocumentRepository::ownedBy(int doc_id, int user_id) {
    auto result = db_.query(
        "SELECT 1 FROM documents WHERE id = $1 AND user_id = $2",
        { std::to_string(doc_id), std::to_string(user_id) });
    return !result.empty();
}

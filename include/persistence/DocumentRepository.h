#pragma once

#include "persistence/PostgreSQLClient.h"
#include <string>
#include <optional>
#include <vector>

struct Document {
    int         id;
    int         user_id;
    std::string filename;
    std::string sha256_hash;
    std::string signature_b64;
    std::string signed_at;
};

class DocumentRepository {
public:
    explicit DocumentRepository(PostgreSQLClient& db);

    int                        save(int user_id, const std::string& filename,
                                    const std::string& pdf_b64,
                                    const std::string& signature_b64,
                                    const std::string& sha256_hash);
    std::optional<Document>    findById(int id);
    std::vector<Document>      findByUserId(int user_id);
    std::optional<std::string> getPdfData(int id);
    bool                       ownedBy(int doc_id, int user_id);
    bool                       deleteById(int id);

private:
    PostgreSQLClient& db_;
};

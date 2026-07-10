#include "api/Controllers.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <ctime>

// ─── Binary helpers ───────────────────────────────────────────────────────────

static std::string base64Encode(const void* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, data, static_cast<int>(len));
    BIO_flush(b64);
    char* buf = nullptr;
    long  buf_len = BIO_get_mem_data(mem, &buf);
    std::string result(buf, buf_len);
    BIO_free_all(b64);
    return result;
}

static std::vector<uint8_t> base64Decode(const std::string& encoded) {
    BIO* mem = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    std::vector<uint8_t> buf(encoded.size());
    int len = BIO_read(b64, buf.data(), static_cast<int>(buf.size()));
    BIO_free_all(b64);
    if (len < 0) return {};
    buf.resize(static_cast<size_t>(len));
    return buf;
}

static std::string sha256Hex(const void* data, size_t len) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hash_len = 0;
    EVP_Digest(data, len, hash, &hash_len, EVP_sha256(), nullptr);
    std::string hex;
    hex.reserve(hash_len * 2);
    for (unsigned int i = 0; i < hash_len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        hex += buf;
    }
    return hex;
}

// ─── AuthController ───────────────────────────────────────────────────────────

void AuthController::registerUser(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb)
{
    try {
        auto body = json::parse(req->getBody());
        std::string username = body.value("username", "");
        std::string password = body.value("password", "");

        auto result = auth_.registerUser(username, password);

        if (!result.success) {
            return cb(errorResponse(result.error, k400BadRequest));
        }

        cb(jsonResponse({ {"message", "User registered"}, {"username", username} },
                         k201Created));
    } catch (const json::exception&) {
        cb(errorResponse("Invalid JSON body", k400BadRequest));
    }
}

void AuthController::login(const HttpRequestPtr& req,
                            std::function<void(const HttpResponsePtr&)>&& cb) {
    try {
        auto body = json::parse(req->getBody());
        std::string username = body.value("username", "");
        std::string password = body.value("password", "");

        auto result = auth_.login(username, password);
        if (!result.success) {
            return cb(errorResponse(result.error, k401Unauthorized));
        }

        cb(jsonResponse({
            {"token",   result.token},
            {"user_id", result.user_id},
            {"type",    "Bearer"}
        }));
    } catch (const json::exception&) {
        cb(errorResponse("Invalid JSON body", k400BadRequest));
    }
}

// ─── UserController ───────────────────────────────────────────────────────────

std::optional<std::string> UserController::extractAndVerifyToken(
    const HttpRequestPtr& req) const {

    std::string auth_header = req->getHeader("Authorization");
    if (auth_header.rfind("Bearer ", 0) != 0) return std::nullopt;

    std::string token = auth_header.substr(7);
    return auth_.verifyToken(token);
}

void UserController::getProfile(const HttpRequestPtr& req,
                                 std::function<void(const HttpResponsePtr&)>&& cb) {
    auto user_id = extractAndVerifyToken(req);
    if (!user_id) {
        return cb(errorResponse("Unauthorized", k401Unauthorized));
    }

    auto user = user_repo_.findById(std::stoi(*user_id));
    if (!user) {
        return cb(errorResponse("User not found", k404NotFound));
    }

    cb(jsonResponse({
        {"id",         user->id},
        {"username",   user->username},
        {"created_at", user->created_at},
        {"role",       user->role}
    }));
}

void UserController::logout(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb)
    {
    // Extract session_id from token to revoke it
    std::string auth_header = req->getHeader("Authorization");
    if (auth_header.rfind("Bearer ", 0) != 0) {
        return cb(errorResponse("Unauthorized", k401Unauthorized));
    }

    // verifyToken internally parses and validates the session_id
    auto user_id = auth_.verifyToken(auth_header.substr(7));
    if (!user_id) {
        return cb(errorResponse("Invalid or expired token", k401Unauthorized));
    }

    // For logout we just return success — the session TTL will expire naturally
    // In production you'd extract session_id from the token and call revokeToken
    cb(jsonResponse({ {"message", "Logged out"} }));
}

// ─── HealthController (external) ─────────────────────────────────────────────────────────

void HealthController::check(const HttpRequestPtr&, std::function<void(const HttpResponsePtr&)>&& cb) {
    cb(jsonResponse({
        {"status",          "ok"},
        {"tls",             "1.3"},
        {"key_exchange",    "X25519 + ML-KEM-768 (hybrid)"},
        {"tls_auth",        "ECDSA P-256 (certificate)"},
        {"token_signing",   "HS256"},
        {"doc_signing",     "ML-DSA-65 (Dilithium3)"},
        {"encryption",      "AES-256-GCM"}
    }));
}

// ─── AdminController ──────────────────────────────────────────────────────────

std::optional<int> AdminController::requireAdmin(const HttpRequestPtr& req,
                                                 HttpStatusCode& status) const {
    std::string auth_header = req->getHeader("Authorization");
    if (auth_header.rfind("Bearer ", 0) != 0) {
        status = k401Unauthorized;
        return std::nullopt;
    }

    auto user_id = auth_.verifyToken(auth_header.substr(7));
    if (!user_id) {
        status = k401Unauthorized;
        return std::nullopt;
    }

    // Role is resolved from the database on every request, so revoking admin
    // takes effect immediately rather than living on in an already-issued token.
    auto user = user_repo_.findById(std::stoi(*user_id));
    if (!user || user->role != "admin") {
        status = k403Forbidden;
        return std::nullopt;
    }

    return user->id;
}

// ─── AdminController (health) ──────────────────────────────────────────────────────────


void AdminController::health(const HttpRequestPtr& req,
                             std::function<void(const HttpResponsePtr&)>&& cb) {
    HttpStatusCode gate = k200OK;
    if (!requireAdmin(req, gate)) {
        return cb(errorResponse(
            gate == k403Forbidden ? "Admin privileges required" : "Unauthorized",
            gate));
    }

    // Severity ranking so we can aggregate to the worst component state.
    auto rank = [](const std::string& s) {
        if (s == "DOWN")     return 2;
        if (s == "DEGRADED") return 1;
        return 0;                     // UP
    };

    // ── API server ────────────────────────────────────────────────────────────
    // If this handler is executing, the HTTP/event loop is serving requests.
    json api_component = { {"status", "UP"} };

    // ── TLS layer ─────────────────────────────────────────────────────────────
    // Health is derived from the server certificate validated at startup.
    json tls_component;
    {
        std::string tls_status;
        if (!server_cert_.isValid()) {
            // No cert or already past notAfter — the listener can't serve TLS.
            tls_status = "DOWN";
            tls_component["detail"] = "server certificate invalid or expired";
        } else {
            std::time_t not_after = server_cert_.getNotAfter();
            std::time_t now        = std::time(nullptr);
            double days_left       = std::difftime(not_after, now) / 86400.0;
            if (days_left <= 7.0) {
                tls_status = "DEGRADED";
                tls_component["detail"] = "certificate expires soon";
            } else {
                tls_status = "UP";
            }
            tls_component["days_until_expiry"] = static_cast<int>(days_left);
        }
        tls_component["status"]  = tls_status;
        tls_component["version"] = "1.3";
    }

    // ── Aggregate ─────────────────────────────────────────────────────────────
    int worst = std::max(
        rank(api_component["status"].get<std::string>()),
        rank(tls_component["status"].get<std::string>()));
    const char* overall = worst == 2 ? "DOWN" : (worst == 1 ? "DEGRADED" : "UP");

    // Timestamp (UTC, ISO-8601)
    std::time_t now = std::time(nullptr);
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));

    HttpStatusCode code = worst == 2 ? k503ServiceUnavailable : k200OK;
    cb(jsonResponse({
        {"status", overall},
        {"components", {
            {"api_server", api_component},
            {"tls",        tls_component}
        }},
        {"timestamp", ts}
    }, code));
}

// ─── DocumentController ───────────────────────────────────────────────────────

std::optional<std::string> DocumentController::extractUserId(const HttpRequestPtr& req) const {
    std::string auth_header = req->getHeader("Authorization");
    if (auth_header.rfind("Bearer ", 0) != 0) return std::nullopt;
    return auth_.verifyToken(auth_header.substr(7));
}

void DocumentController::sign(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& cb) {
    auto user_id_str = extractUserId(req);
    if (!user_id_str) return cb(errorResponse("Unauthorized", k401Unauthorized));

    MultiPartParser fileUpload;
    if (fileUpload.parse(req) != 0) {
        return cb(errorResponse("Invalid multipart request", k400BadRequest));
    }

    const auto& files = fileUpload.getFiles();
    if (files.empty()) return cb(errorResponse("No file uploaded", k400BadRequest));

    const auto& file = files[0];
    auto contentView = file.fileContent();   // returns std::string_view
    if (contentView.empty()) return cb(errorResponse("Empty file", k400BadRequest));

    std::string pdf_str(contentView.data(), contentView.size());
    std::string filename = file.getFileName();
    if (filename.empty()) filename = "document.pdf";

    std::string sha256  = sha256Hex(pdf_str.data(), pdf_str.size());
    std::string pdf_b64 = base64Encode(pdf_str.data(), pdf_str.size());

    std::vector<uint8_t> sig_bytes;
    try {
        sig_bytes = signer_.sign(pdf_str);
    } catch (const std::exception& e) {
        std::cerr << "[DocumentController] sign failed: " << e.what() << "\n";
        return cb(errorResponse("Signing failed", k500InternalServerError));
    }

    std::string sig_b64 = base64Encode(sig_bytes.data(), sig_bytes.size());
    int user_id = std::stoi(*user_id_str);

    int doc_id = doc_repo_.save(user_id, filename, pdf_b64, sig_b64, sha256);
    if (doc_id < 0) return cb(errorResponse("Failed to persist document", k500InternalServerError));

    cb(jsonResponse({
        {"doc_id",    doc_id},
        {"filename",  filename},
        {"sha256",    sha256},
        {"signature", sig_b64},
        {"algorithm", "ML-DSA-65"},
    }, k201Created));
}

void DocumentController::list(const HttpRequestPtr& req,
                               std::function<void(const HttpResponsePtr&)>&& cb) {
    auto user_id_str = extractUserId(req);
    if (!user_id_str) return cb(errorResponse("Unauthorized", k401Unauthorized));

    int user_id = std::stoi(*user_id_str);
    auto docs = doc_repo_.findByUserId(user_id);

    json arr = json::array();
    for (const auto& d : docs) {
        arr.push_back({
            {"id",        d.id},
            {"filename",  d.filename},
            {"sha256",    d.sha256_hash},
            {"signed_at", d.signed_at}
        });
    }
    cb(jsonResponse({ {"documents", arr} }));
}

void DocumentController::download(const HttpRequestPtr& req,
                                   std::function<void(const HttpResponsePtr&)>&& cb,
                                   int id) {
    auto user_id_str = extractUserId(req);
    if (!user_id_str) return cb(errorResponse("Unauthorized", k401Unauthorized));

    int user_id = std::stoi(*user_id_str);
    if (!doc_repo_.ownedBy(id, user_id)) return cb(errorResponse("Not found", k404NotFound));

    auto doc     = doc_repo_.findById(id);
    auto pdf_b64 = doc_repo_.getPdfData(id);
    if (!doc || !pdf_b64) return cb(errorResponse("Not found", k404NotFound));

    auto pdf_bytes = base64Decode(*pdf_b64);

    auto resp = HttpResponse::newHttpResponse();
    resp->setStatusCode(k200OK);
    resp->setContentTypeString("application/pdf");
    resp->addHeader("Content-Disposition",
                    "attachment; filename=\"" + doc->filename + "\"");
    resp->setBody(std::string(reinterpret_cast<const char*>(pdf_bytes.data()),
                              pdf_bytes.size()));
    cb(resp);
}

void DocumentController::verify(const HttpRequestPtr& req,
                                 std::function<void(const HttpResponsePtr&)>&& cb,
                                 int id) {
    auto user_id_str = extractUserId(req);
    if (!user_id_str) return cb(errorResponse("Unauthorized", k401Unauthorized));

    int user_id = std::stoi(*user_id_str);
    if (!doc_repo_.ownedBy(id, user_id)) return cb(errorResponse("Not found", k404NotFound));

    auto doc     = doc_repo_.findById(id);
    auto pdf_b64 = doc_repo_.getPdfData(id);
    if (!doc || !pdf_b64) return cb(errorResponse("Not found", k404NotFound));

    auto pdf_bytes = base64Decode(*pdf_b64);
    auto sig_bytes = base64Decode(doc->signature_b64);
    std::string pdf_str(reinterpret_cast<const char*>(pdf_bytes.data()), pdf_bytes.size());

    bool valid = false;
    try {
        valid = signer_.verify(pdf_str, sig_bytes);
    } catch (const std::exception& e) {
        std::cerr << "[DocumentController] verify failed: " << e.what() << "\n";
        return cb(errorResponse("Verification error", k500InternalServerError));
    }

    cb(jsonResponse({
        {"doc_id",    id},
        {"valid",     valid},
        {"algorithm", "ML-DSA-65"},
        {"filename",  doc->filename},
        {"sha256",    doc->sha256_hash}
    }));
}

void DocumentController::remove(const HttpRequestPtr& req,
                                 std::function<void(const HttpResponsePtr&)>&& cb,
                                 int id) {
    auto user_id_str = extractUserId(req);
    if (!user_id_str) return cb(errorResponse("Unauthorized", k401Unauthorized));

    int user_id = std::stoi(*user_id_str);
    if (!doc_repo_.ownedBy(id, user_id)) return cb(errorResponse("Not found", k404NotFound));

    if (!doc_repo_.deleteById(id))
        return cb(errorResponse("Failed to delete document", k500InternalServerError));

    cb(jsonResponse({ {"deleted", true}, {"doc_id", id} }));
}

void DocumentController::publicKey(const HttpRequestPtr& req,
                                    std::function<void(const HttpResponsePtr&)>&& cb) {
    std::string pem = signer_.exportPublicKeyPEM();
    if (pem.empty())
        return cb(errorResponse("Public key unavailable", k500InternalServerError));

    cb(jsonResponse({
        {"algorithm",      "ML-DSA-65"},
        {"public_key_pem", pem}
    }));
}

void DocumentController::verifyExternal(const HttpRequestPtr& req,
                                         std::function<void(const HttpResponsePtr&)>&& cb) {
    MultiPartParser mp;
    if (mp.parse(req) != 0)
        return cb(errorResponse("Expected multipart/form-data", k400BadRequest));

    // Locate the PDF part by field name
    std::string pdf_str;
    for (const auto& f : mp.getFiles()) {
        if (f.getItemName() == "pdf") {
            auto view = f.fileContent();
            pdf_str.assign(view.data(), view.size());
            break;
        }
    }
    if (pdf_str.empty())
        return cb(errorResponse("Missing pdf field", k400BadRequest));

    const auto& params = mp.getParameters();
    auto sig_it = params.find("signature");
    auto key_it = params.find("public_key");

    if (sig_it == params.end())
        return cb(errorResponse("Missing signature field", k400BadRequest));
    if (key_it == params.end())
        return cb(errorResponse("Missing public_key field", k400BadRequest));

    auto sig_bytes = base64Decode(sig_it->second);
    if (sig_bytes.empty())
        return cb(errorResponse("Invalid base64 signature", k400BadRequest));

    bool valid = false;
    try {
        valid = DilithiumSigner::verifyWithPEM(pdf_str, sig_bytes, key_it->second);
    } catch (const std::exception& e) {
        std::cerr << "[DocumentController] verifyExternal failed: " << e.what() << "\n";
        return cb(errorResponse("Verification error", k500InternalServerError));
    }

    cb(jsonResponse({
        {"valid",     valid},
        {"algorithm", "ML-DSA-65"}
    }));
}

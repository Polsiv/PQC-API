#include "api/Controllers.h"
#include <iostream>

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
        {"created_at", user->created_at}
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

// ─── HealthController ─────────────────────────────────────────────────────────

void HealthController::check(const HttpRequestPtr&, std::function<void(const HttpResponsePtr&)>&& cb) {
    cb(jsonResponse({
        {"status",          "ok"},
        {"tls",             "1.3"},
        {"key_exchange",    "X25519 + ML-KEM-768 (hybrid)"},
        {"tls_auth",        "ECDSA P-256 (certificate)"},
        {"token_signing",   "ML-DSA-65 (application layer)"},
        {"encryption",      "AES-256-GCM"}
    }));
}
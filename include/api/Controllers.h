#pragma once

#include "auth/AuthManager.h"
#include "persistence/UserRepository.h"
#include <drogon/HttpController.h>
#include <nlohmann/json.hpp>

using namespace drogon;
using json = nlohmann::json;


// ─── Global app context ───────────────────────────────────────────────────────
// Drogon's registerController requires AutoCreation=false on the controller.
// Dependencies are passed at construction time (main.cpp creates the instances).
struct AppContext
{
    AuthManager*    auth      = nullptr;
    UserRepository* user_repo = nullptr;
};


// ─── Helper: build JSON responses ────────────────────────────────────────────

inline HttpResponsePtr jsonResponse(const json& body, HttpStatusCode code = k200OK)
{
    auto resp = HttpResponse::newHttpResponse();
    resp->setStatusCode(code);
    resp->setContentTypeCode(CT_APPLICATION_JSON);
    resp->setBody(body.dump());
    return resp;
}

inline HttpResponsePtr errorResponse(const std::string& message, HttpStatusCode code = k400BadRequest)
{
    return jsonResponse({ {"error", message} }, code);
}

// ─── AuthController ──────────────────────────────────────────────────────────
// Handles /api/auth/register and /api/auth/login — public endpoints.
// AutoCreation=false: instance is created manually and passed to registerController.

class AuthController : public HttpController<AuthController, false> {
public:
    METHOD_LIST_BEGIN
        ADD_METHOD_TO(AuthController::registerUser, "/api/auth/register", Post);
        ADD_METHOD_TO(AuthController::login,        "/api/auth/login",    Post);
    METHOD_LIST_END

    explicit AuthController(AuthManager& auth) : auth_(auth) {}

    void registerUser(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);
    void login(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback);

private:
    AuthManager& auth_;
};

// ─── UserController ───────────────────────────────────────────────────────────
// Handles /api/users/me and /api/users/logout — protected endpoints.
// AutoCreation=false: instance is created manually and passed to registerController.

class UserController : public HttpController<UserController, false> {
public:
    METHOD_LIST_BEGIN
        ADD_METHOD_TO(UserController::getProfile, "/api/users/me",    Get);
        ADD_METHOD_TO(UserController::logout,     "/api/users/logout", Post);
    METHOD_LIST_END

    UserController(AuthManager& auth, UserRepository& user_repo)
        : auth_(auth), user_repo_(user_repo) {}

    void getProfile(const HttpRequestPtr& req,
                    std::function<void(const HttpResponsePtr&)>&& callback);
    void logout(const HttpRequestPtr& req,
                std::function<void(const HttpResponsePtr&)>&& callback);

private:
    std::optional<std::string> extractAndVerifyToken(const HttpRequestPtr& req) const;

    AuthManager&    auth_;
    UserRepository& user_repo_;
};

// ─── HealthController ─────────────────────────────────────────────────────────
// GET /health — liveness probe, no auth required.
// AutoCreation=false: instance is created manually and passed to registerController.

class HealthController : public HttpController<HealthController, false> {
public:
    METHOD_LIST_BEGIN
        ADD_METHOD_TO(HealthController::check, "/health", Get);
    METHOD_LIST_END

    void check(const HttpRequestPtr& req,
               std::function<void(const HttpResponsePtr&)>&& callback);
};

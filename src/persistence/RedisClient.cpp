#include "persistence/RedisClient.h"
#include <iostream>
#include <stdexcept>

RedisClient::RedisClient(const std::string& host, int port, int timeout_ms) {
    timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    ctx_ = redisConnectWithTimeout(host.c_str(), port, tv);

    if (!ctx_) {
        throw std::runtime_error("[RedisClient] Failed to allocate context");
    }
    if (ctx_->err) {
        std::string err = ctx_->errstr;
        redisFree(ctx_);
        ctx_ = nullptr;
        throw std::runtime_error("[RedisClient] Connection failed: " + err);
    }
    std::cout << "[RedisClient] Connected to " << host << ":" << port << "\n";
}

RedisClient::~RedisClient() {
    if (ctx_) redisFree(ctx_);
}

bool RedisClient::set(const std::string& key, const std::string& value, int ttl_seconds) {
    redisReply* reply = static_cast<redisReply*>(
        redisCommand(ctx_, "SETEX %s %d %s",
                     key.c_str(), ttl_seconds, value.c_str()));
    if (!reply) return false;
    bool ok = (reply->type == REDIS_REPLY_STATUS);
    freeReplyObject(reply);
    return ok;
}

std::optional<std::string> RedisClient::get(const std::string& key) {
    redisReply* reply = static_cast<redisReply*>(
        redisCommand(ctx_, "GET %s", key.c_str()));
    if (!reply) return std::nullopt;

    std::optional<std::string> result;
    if (reply->type == REDIS_REPLY_STRING) {
        result = std::string(reply->str, reply->len);
    }
    freeReplyObject(reply);
    return result;
}

bool RedisClient::del(const std::string& key) {
    redisReply* reply = static_cast<redisReply*>(
        redisCommand(ctx_, "DEL %s", key.c_str()));
    if (!reply) return false;
    bool ok = (reply->integer > 0);
    freeReplyObject(reply);
    return ok;
}

bool RedisClient::expire(const std::string& key, int ttl_seconds) {
    redisReply* reply = static_cast<redisReply*>(
        redisCommand(ctx_, "EXPIRE %s %d", key.c_str(), ttl_seconds));
    if (!reply) return false;
    bool ok = (reply->integer == 1);
    freeReplyObject(reply);
    return ok;
}

bool RedisClient::exists(const std::string& key) {
    redisReply* reply = static_cast<redisReply*>(
        redisCommand(ctx_, "EXISTS %s", key.c_str()));
    if (!reply) return false;
    bool ok = (reply->integer == 1);
    freeReplyObject(reply);
    return ok;
}

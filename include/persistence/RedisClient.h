#pragma once

#include <hiredis/hiredis.h>
#include <string>
#include <optional>

/**
 * RedisClient
 * Thin RAII wrapper around hiredis for session key storage.
 * All session keys are stored with a TTL — they expire automatically.
 */
class RedisClient {
public:
    RedisClient(const std::string& host, int port, int timeout_ms = 2000);
    ~RedisClient();

    bool                     isConnected() const { return ctx_ && ctx_->err == 0; }
    bool                     set(const std::string& key, const std::string& value, int ttl_seconds);
    std::optional<std::string> get(const std::string& key);
    bool                     del(const std::string& key);
    bool                     expire(const std::string& key, int ttl_seconds);
    bool                     exists(const std::string& key);

    // Non-copyable
    RedisClient(const RedisClient&)            = delete;
    RedisClient& operator=(const RedisClient&) = delete;

private:
    redisContext* ctx_;
};

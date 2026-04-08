#pragma once

#include "persistence/RedisClient.h"
#include <string>
#include <optional>

/**
 * SessionRepository
 * Stores and retrieves session keys from Redis.
 * Keys are namespaced as "session:<session_id>" with automatic TTL.
 */
class SessionRepository {
public:
    SessionRepository(RedisClient& redis, int ttl_seconds = 3600);

    bool                     storeKey(const std::string& session_id,
                                      const std::string& key_data);
    std::optional<std::string> getKey(const std::string& session_id);
    bool                     invalidate(const std::string& session_id);
    bool                     refresh(const std::string& session_id);

private:
    std::string makeKey(const std::string& session_id) const;

    RedisClient& redis_;
    int          ttl_seconds_;
};

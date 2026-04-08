#include "persistence/SessionRepository.h"

SessionRepository::SessionRepository(RedisClient& redis, int ttl_seconds)
    : redis_(redis), ttl_seconds_(ttl_seconds) {}

std::string SessionRepository::makeKey(const std::string& session_id) const {
    return "session:" + session_id;
}

bool SessionRepository::storeKey(const std::string& session_id,
                                  const std::string& key_data) {
    return redis_.set(makeKey(session_id), key_data, ttl_seconds_);
}

std::optional<std::string> SessionRepository::getKey(const std::string& session_id) {
    return redis_.get(makeKey(session_id));
}

bool SessionRepository::invalidate(const std::string& session_id) {
    return redis_.del(makeKey(session_id));
}

bool SessionRepository::refresh(const std::string& session_id) {
    return redis_.expire(makeKey(session_id), ttl_seconds_);
}

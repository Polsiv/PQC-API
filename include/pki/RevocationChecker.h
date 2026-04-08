#pragma once

#include "pki/OCSPClient.h"
#include "pki/Certificate.h"
#include <unordered_map>
#include <chrono>
#include <string>
#include <mutex>

struct CachedStatus
{
    CertStatus                            status;
    std::chrono::steady_clock::time_point cached_at;
};

/**
 * RevocationChecker
 * Caches OCSP responses in memory to avoid a live round-trip on
 * every TLS connection. Called during handshake setup and periodically.
 */

class RevocationChecker
{
    public:
        explicit RevocationChecker(OCSPClient& ocsp_client, int cache_ttl_seconds = 300);

        CertStatus checkCert(const Certificate& cert, const Certificate& issuer);
        void       clearCache();

    private:
        bool isCacheValid(const std::string& serial) const;

        OCSPClient&                                   ocsp_;
        int                                           cache_ttl_seconds_;
        std::unordered_map<std::string, CachedStatus> cache_;
        mutable std::mutex                            cache_mutex_;
};
#include "pki/RevocationChecker.h"
#include <iostream>

RevocationChecker::RevocationChecker(OCSPClient& ocsp_client, int cache_ttl_seconds)
    : ocsp_(ocsp_client), cache_ttl_seconds_(cache_ttl_seconds) {}

CertStatus RevocationChecker::checkCert(const Certificate& cert,
                                         const Certificate& issuer) {
    std::string serial = cert.getSerialNumber();

    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        if (isCacheValid(serial)) {
            std::cout << "[RevocationChecker] Cache hit for serial: " << serial << "\n";
            return cache_.at(serial).status;
        }
    }

    // Cache miss — query OCSP responder
    std::cout << "[RevocationChecker] OCSP query for serial: " << serial << "\n";
    CertStatus status = ocsp_.checkStatus(cert, issuer);

    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        cache_[serial] = { status, std::chrono::steady_clock::now() };
    }

    return status;
}

bool RevocationChecker::isCacheValid(const std::string& serial) const {
    auto it = cache_.find(serial);
    if (it == cache_.end()) return false;

    auto age = std::chrono::steady_clock::now() - it->second.cached_at;
    return std::chrono::duration_cast<std::chrono::seconds>(age).count()
           < cache_ttl_seconds_;
}

void RevocationChecker::clearCache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
}

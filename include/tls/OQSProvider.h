#pragma once

#include <openssl/provider.h>
#include <mutex>

/**
 * OQSProvider — Singleton
 * Loads oqsprovider + default provider into OpenSSL's DEFAULT library context.
 * Must be initialized before any SSL_CTX or crypto calls.
 */
class OQSProvider {
public:
    static OQSProvider& getInstance();

    bool load();
    void unload();
    bool isLoaded() const { return loaded_; }

    OQSProvider(const OQSProvider&)            = delete;
    OQSProvider& operator=(const OQSProvider&) = delete;

private:
    OQSProvider()  = default;
    ~OQSProvider() { unload(); }

    OSSL_PROVIDER* oqs_provider_     = nullptr;
    OSSL_PROVIDER* default_provider_ = nullptr;
    bool           loaded_           = false;

    static std::once_flag init_flag_;
    static OQSProvider*   instance_;
};

#pragma once

#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <mutex>
#include <stdexcept>

/**
 * OQSProvider — Singleton
 * Loads the OQS provider into OpenSSL's global library context,
 * registering ML-KEM (Kyber) and ML-DSA (Dilithium) algorithms.
 * Must be initialized before any OpenSSL or Drogon TLS calls.
 */
class OQSProvider 
{
    public:

        static OQSProvider& getInstance();

        bool          load();
        void          unload();
        bool          isLoaded()  const { return loaded_; }
        OSSL_LIB_CTX* getLibCtx() const { return lib_ctx_; }

        // Non-copyable, non-movable
        OQSProvider(const OQSProvider&)            = delete;
        OQSProvider& operator=(const OQSProvider&) = delete;

    private:

        OQSProvider()  = default;
        ~OQSProvider() { unload(); }

        OSSL_PROVIDER* oqs_provider_     = nullptr;
        OSSL_PROVIDER* default_provider_ = nullptr;
        OSSL_LIB_CTX*  lib_ctx_          = nullptr;
        bool           loaded_            = false;

        static std::once_flag  init_flag_;
        static OQSProvider*    instance_;
};

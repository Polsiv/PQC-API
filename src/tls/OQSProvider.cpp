#include "tls/OQSProvider.h"
#include <stdexcept>
#include <iostream>

std::once_flag OQSProvider::init_flag_;
OQSProvider*   OQSProvider::instance_ = nullptr;

OQSProvider& OQSProvider::getInstance() 
{
    std::call_once(init_flag_, []()
    {
        instance_ = new OQSProvider();
    });
    return *instance_;
}

bool OQSProvider::load()
{
    if (loaded_) return true;

    // Create isolated library context so OQS doesn't pollute the default
    lib_ctx_ = OSSL_LIB_CTX_new();
    
    if (!lib_ctx_)
    {
        std::cerr << "[OQSProvider] Failed to create OSSL_LIB_CTX\n";
        return false;
    }

    // Load the default provider first (needed for AES-GCM, HKDF, SHA-2)
    default_provider_ = OSSL_PROVIDER_load(lib_ctx_, "default");

    if (!default_provider_)
    {
        std::cerr << "[OQSProvider] Failed to load default provider\n";
        OSSL_LIB_CTX_free(lib_ctx_);
        return false;
    }

    // Load OQS provider — must be built and on the provider search path
    oqs_provider_ = OSSL_PROVIDER_load(lib_ctx_, "oqsprovider");
    if (!oqs_provider_)
    {
        std::cerr << "[OQSProvider] Failed to load oqsprovider. "
                     "Ensure liboqs and oqs-provider are installed.\n";
        OSSL_PROVIDER_unload(default_provider_);
        OSSL_LIB_CTX_free(lib_ctx_);
        return false;
    }

    loaded_ = true;
    std::cout << "[OQSProvider] Loaded successfully. "
                 "ML-KEM and ML-DSA algorithms available.\n";
    return true;
}

void OQSProvider::unload() 
{
    if (!loaded_) return;
    if (oqs_provider_)     OSSL_PROVIDER_unload(oqs_provider_);
    if (default_provider_) OSSL_PROVIDER_unload(default_provider_);
    if (lib_ctx_)          OSSL_LIB_CTX_free(lib_ctx_);
    loaded_ = false;
}

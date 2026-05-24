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

    // Load both providers into the DEFAULT library context (nullptr).
    // Using an isolated context caused CTR-DRBG failures because SSL_CTX
    // and the RNG couldn't find the default provider algorithms.
    default_provider_ = OSSL_PROVIDER_load(nullptr, "default");

    if (!default_provider_)
    {
        std::cerr << "[OQSProvider] Failed to load default provider\n";
        return false;
    }

    oqs_provider_ = OSSL_PROVIDER_load(nullptr, "oqsprovider");
    if (!oqs_provider_)
    {
        std::cerr << "[OQSProvider] Failed to load oqsprovider. "
                     "Ensure liboqs and oqs-provider are installed.\n";
        OSSL_PROVIDER_unload(default_provider_);
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
    loaded_ = false;
}

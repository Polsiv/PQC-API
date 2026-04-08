#pragma once

#include <openssl/evp.h>
#include <string>
#include <vector>
#include <stdexcept>

/**
 * DilithiumSigner
 * Wraps ML-DSA-65 (Dilithium3) sign/verify via OpenSSL EVP API.
 * Used by AuthManager to sign and verify JWT tokens — keeping
 * PQC signatures at the application layer, not just TLS.
 */
class DilithiumSigner {
public:
    DilithiumSigner();
    ~DilithiumSigner();

    // Generate a new ML-DSA-65 key pair
    bool generateKeyPair();

    // Load keys from PEM files (use CA-generated keys for server identity)
    bool loadPrivateKey(const std::string& pem_path);
    bool loadPublicKey(const std::string& pem_path);

    // Sign arbitrary data — returns raw signature bytes
    std::vector<uint8_t> sign(const std::string& data) const;

    // Verify a signature against data using the loaded public key
    bool verify(const std::string& data,
                const std::vector<uint8_t>& signature) const;

    // Export keys to PEM string (for storage or distribution)
    std::string exportPrivateKeyPEM() const;
    std::string exportPublicKeyPEM()  const;

    // Non-copyable — owns EVP_PKEY* resources
    DilithiumSigner(const DilithiumSigner&)            = delete;
    DilithiumSigner& operator=(const DilithiumSigner&) = delete;

private:
    EVP_PKEY* private_key_ = nullptr;
    EVP_PKEY* public_key_  = nullptr;

    std::string exportKeyPEM(EVP_PKEY* key, bool is_private) const;
};

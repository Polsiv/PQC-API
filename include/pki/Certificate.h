#pragma once

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <string>
#include <ctime>

/**
 * Certificate
 * Wraps an X.509 certificate signed with ML-DSA-65 (Dilithium3).
 * Used by the server to load and validate its identity certificate
 * and by RevocationChecker to inspect cert metadata.
 */
class Certificate 
{
    public:
        Certificate()  = default;
        ~Certificate() { if (x509_) X509_free(x509_); }

        bool loadFromPEM(const std::string& pem_path);
        bool isExpired()  const;
        bool isValid()    const { return x509_ != nullptr && !isExpired(); }

        // Verify this cert was signed by the given issuer cert
        bool verifySignature(const Certificate& issuer) const;

        std::string getSubject()      const;
        std::string getSerialNumber() const;
        std::time_t getNotAfter()     const;
        EVP_PKEY*   getPublicKey()    const;
        X509*       getRawCert()      const { return x509_; }

        // Non-copyable
        Certificate(const Certificate&)            = delete;
        Certificate& operator=(const Certificate&) = delete;

    private:
        X509* x509_ = nullptr;
};

#pragma once

#include <openssl/ssl.h>
#include <string>

/**
 * OpenSSLContext
 * Wraps SSL_CTX configuration for the server.
 * Loads Dilithium (ML-DSA) certificates, sets TLS 1.3 cipher suites
 * with ML-KEM key exchange, and produces an SSL_CTX ready to hand to Drogon.
 */
class OpenSSLContext 
{
    public:
        enum class Mode { Server, Client };

        explicit OpenSSLContext(Mode mode = Mode::Server);
        ~OpenSSLContext();

        bool init();
        bool loadCertificate(const std::string& cert_path, const std::string& key_path);
        bool loadCAFile(const std::string& ca_path);
        bool setCipherSuites(const std::string& suites);
        bool setVerifyPeer(bool verify);

        SSL_CTX* getSSLCtx() const { return ssl_ctx_; }

        // Non-copyable
        OpenSSLContext(const OpenSSLContext&)            = delete;
        OpenSSLContext& operator=(const OpenSSLContext&) = delete;

    private:
        SSL_CTX* ssl_ctx_ = nullptr;
        Mode     mode_;
};

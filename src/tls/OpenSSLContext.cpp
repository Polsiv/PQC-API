#include "tls/OpenSSLContext.h"
#include "tls/OQSProvider.h"
#include <openssl/err.h>
#include <iostream>

OpenSSLContext::OpenSSLContext(Mode mode) : mode_(mode) {}

OpenSSLContext::~OpenSSLContext() {
    if (ssl_ctx_) SSL_CTX_free(ssl_ctx_);
}

bool OpenSSLContext::init() {
    if (!OQSProvider::getInstance().isLoaded()) {
        std::cerr << "[OpenSSLContext] OQSProvider not loaded.\n";
        return false;
    }

    const SSL_METHOD* method = (mode_ == Mode::Server)
        ? TLS_server_method()
        : TLS_client_method();

    // Use SSL_CTX_new (default context) — NOT SSL_CTX_new_ex with isolated ctx.
    // The isolated ctx caused CTR-DRBG failures on OpenSSL 3.0.
    ssl_ctx_ = SSL_CTX_new(method);
    if (!ssl_ctx_) {
        std::cerr << "[OpenSSLContext] SSL_CTX_new failed\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // TLS 1.3 only
    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION);

    // Lower security level to allow PQC + hybrid algorithms.
    // OpenSSL 3.0 ships with SECLEVEL=2 which blocks ML-DSA cert operations.
    SSL_CTX_set_security_level(ssl_ctx_, 0);

    // Hybrid key exchange: X25519 (classical) + ML-KEM-768 (PQC).
    // X25519MLKEM768 is the IETF hybrid group — supported by oqs-provider.
    // This gives quantum-safe forward secrecy while staying compatible
    // with the ECDSA certificate.
    if (SSL_CTX_set1_groups_list(ssl_ctx_, "X25519MLKEM768:x25519") != 1) {
        std::cerr << "[OpenSSLContext] Failed to set hybrid KEM group.\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    std::cout << "[OpenSSLContext] Initialized: TLS 1.3 + X25519/ML-KEM-768 hybrid\n";
    return true;
}

bool OpenSSLContext::loadCertificate(const std::string& cert_path,
                                      const std::string& key_path) {
    if (SSL_CTX_use_certificate_file(ssl_ctx_, cert_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        std::cerr << "[OpenSSLContext] Failed to load certificate: " << cert_path << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
        std::cerr << "[OpenSSLContext] Failed to load private key: " << key_path << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_check_private_key(ssl_ctx_) != 1) {
        std::cerr << "[OpenSSLContext] Certificate and private key do not match\n";
        return false;
    }

    std::cout << "[OpenSSLContext] Certificate loaded: " << cert_path << "\n";
    return true;
}

bool OpenSSLContext::loadCAFile(const std::string& ca_path) {
    if (SSL_CTX_load_verify_locations(ssl_ctx_, ca_path.c_str(), nullptr) != 1) {
        std::cerr << "[OpenSSLContext] Failed to load CA file: " << ca_path << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

bool OpenSSLContext::setCipherSuites(const std::string& suites) {
    if (SSL_CTX_set_ciphersuites(ssl_ctx_, suites.c_str()) != 1) {
        std::cerr << "[OpenSSLContext] Failed to set cipher suites: " << suites << "\n";
        return false;
    }
    return true;
}

bool OpenSSLContext::setVerifyPeer(bool verify) {
    int mode = verify ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
                      : SSL_VERIFY_NONE;
    SSL_CTX_set_verify(ssl_ctx_, mode, nullptr);
    return true;
}

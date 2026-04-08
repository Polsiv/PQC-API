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
        std::cerr << "[OpenSSLContext] OQSProvider not loaded. Call OQSProvider::load() first.\n";
        return false;
    }

    const SSL_METHOD* method = (mode_ == Mode::Server)
        ? TLS_server_method()
        : TLS_client_method();

    ssl_ctx_ = SSL_CTX_new_ex(OQSProvider::getInstance().getLibCtx(), nullptr, method);
    if (!ssl_ctx_) {
        std::cerr << "[OpenSSLContext] SSL_CTX_new_ex failed\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Enforce TLS 1.3 only
    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION);

    // ML-KEM-768 key exchange (Kyber768 NIST standard name)
    // Combined with X25519 for hybrid mode — remove X25519 for pure PQC
    if (SSL_CTX_set1_groups_list(ssl_ctx_, "mlkem768") != 1) {
        std::cerr << "[OpenSSLContext] Failed to set ML-KEM group. "
                     "Check OQS provider is loaded.\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    std::cout << "[OpenSSLContext] Initialized with TLS 1.3 + ML-KEM-768\n";
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
    // TLS 1.3 uses ciphersuites, not ciphers
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

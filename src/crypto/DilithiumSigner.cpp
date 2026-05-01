#include "crypto/DilithiumSigner.h"
#include "tls/OQSProvider.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <iostream>
#include <stdexcept>

DilithiumSigner::DilithiumSigner() {
    if (!OQSProvider::getInstance().isLoaded()) {
        throw std::runtime_error("OQSProvider must be loaded before DilithiumSigner");
    }
}

DilithiumSigner::~DilithiumSigner() {
    if (private_key_) EVP_PKEY_free(private_key_);
    if (public_key_)  EVP_PKEY_free(public_key_);
}

bool DilithiumSigner::generateKeyPair() {
    // nullptr = use default library context (same as OQSProvider)
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "mldsa65", nullptr);
    if (!ctx) {
        std::cerr << "[DilithiumSigner] Failed to create EVP_PKEY_CTX for mldsa65\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        std::cerr << "[DilithiumSigner] Key generation failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    private_key_ = pkey;
    public_key_  = EVP_PKEY_dup(pkey);

    std::cout << "[DilithiumSigner] ML-DSA-65 key pair generated\n";
    return true;
}

bool DilithiumSigner::loadPrivateKey(const std::string& pem_path) {
    FILE* f = fopen(pem_path.c_str(), "r");
    if (!f) {
        std::cerr << "[DilithiumSigner] Cannot open private key: " << pem_path << "\n";
        return false;
    }

    if (private_key_) EVP_PKEY_free(private_key_);
    if (public_key_)  EVP_PKEY_free(public_key_);

    private_key_ = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!private_key_) {
        std::cerr << "[DilithiumSigner] Failed to read private key\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Extract public key from the private key
    public_key_ = EVP_PKEY_dup(private_key_);
    if (!public_key_) {
        std::cerr << "[DilithiumSigner] Failed to extract public key\n";
        return false;
    }

    return true;
}

bool DilithiumSigner::loadPublicKey(const std::string& pem_path) {
    FILE* f = fopen(pem_path.c_str(), "r");
    if (!f) {
        std::cerr << "[DilithiumSigner] Cannot open public key: " << pem_path << "\n";
        return false;
    }

    if (public_key_) EVP_PKEY_free(public_key_);
    public_key_ = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!public_key_) {
        std::cerr << "[DilithiumSigner] Failed to read public key\n";
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}

std::vector<uint8_t> DilithiumSigner::sign(const std::string& data) const {
    if (!private_key_) {
        throw std::runtime_error("[DilithiumSigner] No private key loaded");
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) throw std::runtime_error("[DilithiumSigner] EVP_MD_CTX_new failed");

    // nullptr for lib_ctx = use default context
    if (EVP_DigestSignInit_ex(md_ctx, nullptr, nullptr,
                               nullptr, nullptr, private_key_, nullptr) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("[DilithiumSigner] DigestSignInit failed");
    }

    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx, nullptr, &sig_len,
                       reinterpret_cast<const uint8_t*>(data.data()),
                       data.size()) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("[DilithiumSigner] DigestSign size query failed");
    }

    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(md_ctx, signature.data(), &sig_len,
                       reinterpret_cast<const uint8_t*>(data.data()),
                       data.size()) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("[DilithiumSigner] Signing failed");
    }

    EVP_MD_CTX_free(md_ctx);
    signature.resize(sig_len);
    return signature;
}

bool DilithiumSigner::verify(const std::string& data,
                              const std::vector<uint8_t>& signature) const {
    if (!public_key_) {
        throw std::runtime_error("[DilithiumSigner] No public key loaded");
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return false;

    if (EVP_DigestVerifyInit_ex(md_ctx, nullptr, nullptr,
                                 nullptr, nullptr, public_key_, nullptr) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    int result = EVP_DigestVerify(
        md_ctx,
        signature.data(), signature.size(),
        reinterpret_cast<const uint8_t*>(data.data()), data.size());

    EVP_MD_CTX_free(md_ctx);
    return result == 1;
}

bool DilithiumSigner::verifyWithPEM(const std::string& data,
                                     const std::vector<uint8_t>& signature,
                                     const std::string& public_key_pem) {
    BIO* bio = BIO_new_mem_buf(public_key_pem.data(), static_cast<int>(public_key_pem.size()));
    if (!bio) return false;

    EVP_PKEY* pub_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pub_key) return false;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) { EVP_PKEY_free(pub_key); return false; }

    if (EVP_DigestVerifyInit_ex(md_ctx, nullptr, nullptr,
                                 nullptr, nullptr, pub_key, nullptr) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pub_key);
        return false;
    }

    int result = EVP_DigestVerify(
        md_ctx,
        signature.data(), signature.size(),
        reinterpret_cast<const uint8_t*>(data.data()), data.size());

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pub_key);
    return result == 1;
}

std::string DilithiumSigner::exportPrivateKeyPEM() const {
    return exportKeyPEM(private_key_, true);
}

std::string DilithiumSigner::exportPublicKeyPEM() const {
    return exportKeyPEM(public_key_, false);
}

std::string DilithiumSigner::exportKeyPEM(EVP_PKEY* key, bool is_private) const {
    if (!key) return {};
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return {};

    bool ok = is_private
        ? PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr)
        : PEM_write_bio_PUBKEY(bio, key);

    std::string result;
    if (ok) {
        char* data = nullptr;
        long  len  = BIO_get_mem_data(bio, &data);
        result.assign(data, len);
    }
    BIO_free(bio);
    return result;
}

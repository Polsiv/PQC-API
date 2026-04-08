#include "pki/Certificate.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <iostream>
#include <sstream>
#include <iomanip>

bool Certificate::loadFromPEM(const std::string& pem_path) {
    FILE* f = fopen(pem_path.c_str(), "r");
    if (!f) {
        std::cerr << "[Certificate] Cannot open: " << pem_path << "\n";
        return false;
    }

    if (x509_) X509_free(x509_);
    x509_ = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!x509_) {
        std::cerr << "[Certificate] Failed to parse PEM: " << pem_path << "\n";
        return false;
    }

    std::cout << "[Certificate] Loaded: " << getSubject() << "\n";
    return true;
}

bool Certificate::isExpired() const {
    if (!x509_) return true;
    return X509_cmp_current_time(X509_get0_notAfter(x509_)) < 0;
}

bool Certificate::verifySignature(const Certificate& issuer) const {
    if (!x509_ || !issuer.x509_) return false;

    EVP_PKEY* issuer_key = X509_get_pubkey(issuer.x509_);
    if (!issuer_key) return false;

    int result = X509_verify(x509_, issuer_key);
    EVP_PKEY_free(issuer_key);
    return result == 1;
}

std::string Certificate::getSubject() const {
    if (!x509_) return {};
    char buf[256];
    X509_NAME_oneline(X509_get_subject_name(x509_), buf, sizeof(buf));
    return std::string(buf);
}

std::string Certificate::getSerialNumber() const {
    if (!x509_) return {};
    const ASN1_INTEGER* serial = X509_get0_serialNumber(x509_);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char*   hex = BN_bn2hex(bn);
    std::string result(hex);
    OPENSSL_free(hex);
    BN_free(bn);
    return result;
}

std::time_t Certificate::getNotAfter() const {
    if (!x509_) return 0;
    const ASN1_TIME* asn1_time = X509_get0_notAfter(x509_);
    struct tm tm_val = {};
    ASN1_TIME_to_tm(asn1_time, &tm_val);
    return mktime(&tm_val);
}

EVP_PKEY* Certificate::getPublicKey() const {
    if (!x509_) return nullptr;
    return X509_get_pubkey(x509_); // caller must EVP_PKEY_free
}

#include "pki/OCSPClient.h"
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <stdexcept>

OCSPClient::OCSPClient(const std::string& responder_url, int timeout_ms)
    : responder_url_(responder_url), timeout_ms_(timeout_ms) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_handle_ = curl_easy_init();
    if (!curl_handle_) {
        throw std::runtime_error("[OCSPClient] Failed to init curl handle");
    }
}

OCSPClient::~OCSPClient() {
    if (curl_handle_) curl_easy_cleanup(curl_handle_);
    curl_global_cleanup();
}

size_t OCSPClient::curlWriteCallback(void* ptr, size_t size,
                                      size_t nmemb, void* userdata) {
    auto* buffer = static_cast<std::vector<uint8_t>*>(userdata);
    const uint8_t* data = static_cast<uint8_t*>(ptr);
    buffer->insert(buffer->end(), data, data + size * nmemb);
    return size * nmemb;
}

CertStatus OCSPClient::checkStatus(const Certificate& cert,
                                    const Certificate& issuer) {
    // Build the DER-encoded OCSP request
    std::string req_der = buildRequest(cert, issuer);
    if (req_der.empty()) return CertStatus::Error;

    std::vector<uint8_t> response_data;

    // Set up libcurl for POST to OCSP responder
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");

    curl_easy_setopt(curl_handle_, CURLOPT_URL, responder_url_.c_str());
    curl_easy_setopt(curl_handle_, CURLOPT_POST, 1L);
    curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDS, req_der.data());
    curl_easy_setopt(curl_handle_, CURLOPT_POSTFIELDSIZE, (long)req_der.size());
    curl_easy_setopt(curl_handle_, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle_, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl_handle_, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl_handle_, CURLOPT_TIMEOUT_MS, (long)timeout_ms_);

    CURLcode res = curl_easy_perform(curl_handle_);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        std::cerr << "[OCSPClient] curl failed: " << curl_easy_strerror(res) << "\n";
        return CertStatus::Error;
    }

    return parseResponse(response_data);
}

std::string OCSPClient::buildRequest(const Certificate& cert,
                                      const Certificate& issuer) {
    OCSP_REQUEST* req = OCSP_REQUEST_new();
    if (!req) return {};

    EVP_PKEY* issuer_key = issuer.getPublicKey();
    X509*     raw_cert   = cert.getRawCert();
    X509*     raw_issuer = issuer.getRawCert();

    OCSP_CERTID* cert_id = OCSP_cert_to_id(EVP_md5(), raw_cert, raw_issuer);
    if (!cert_id) {
        OCSP_REQUEST_free(req);
        if (issuer_key) EVP_PKEY_free(issuer_key);
        return {};
    }

    OCSP_request_add0_id(req, cert_id);
    if (issuer_key) EVP_PKEY_free(issuer_key);

    // Encode to DER
    unsigned char* der = nullptr;
    int der_len = i2d_OCSP_REQUEST(req, &der);
    OCSP_REQUEST_free(req);

    if (der_len <= 0) return {};

    std::string result(reinterpret_cast<char*>(der), der_len);
    OPENSSL_free(der);
    return result;
}

CertStatus OCSPClient::parseResponse(const std::vector<uint8_t>& response_data) {
    if (response_data.empty()) return CertStatus::Error;

    const uint8_t* p = response_data.data();
    OCSP_RESPONSE* resp = d2i_OCSP_RESPONSE(nullptr, &p, response_data.size());
    if (!resp) {
        std::cerr << "[OCSPClient] Failed to parse OCSP response\n";
        return CertStatus::Error;
    }

    int status = OCSP_response_status(resp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        std::cerr << "[OCSPClient] OCSP response status: " << status << "\n";
        OCSP_RESPONSE_free(resp);
        return CertStatus::Error;
    }

    OCSP_BASICRESP* basic = OCSP_response_get1_basic(resp);
    OCSP_RESPONSE_free(resp);
    if (!basic) return CertStatus::Error;

    // Check first certificate status in the response
    int cert_status = 0, reason = 0;
    ASN1_GENERALIZEDTIME *rev_time = nullptr, *this_update = nullptr, *next_update = nullptr;

    OCSP_SINGLERESP* single = OCSP_resp_get0(basic, 0);
    if (single) {
        cert_status = OCSP_single_get0_status(single, &reason,
                                               &rev_time, &this_update, &next_update);
    }

    OCSP_BASICRESP_free(basic);

    switch (cert_status) {
        case V_OCSP_CERTSTATUS_GOOD:    return CertStatus::Good;
        case V_OCSP_CERTSTATUS_REVOKED: return CertStatus::Revoked;
        default:                         return CertStatus::Unknown;
    }
}

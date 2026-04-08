#pragma once

#include "pki/Certificate.h"
#include <curl/curl.h>
#include <string>
#include <vector>

enum class CertStatus { Good, Revoked, Unknown, Error };

/**
 * OCSPClient
 * Sends OCSP requests to the OCSP responder container via libcurl.
 * This is the only place libcurl appears in the project — it's an
 * outbound HTTP client, exactly the right use case for libcurl.
 */
class OCSPClient {
public:
    explicit OCSPClient(const std::string& responder_url, int timeout_ms = 5000);
    ~OCSPClient();

    CertStatus checkStatus(const Certificate& cert, const Certificate& issuer);

    // Non-copyable
    OCSPClient(const OCSPClient&)            = delete;
    OCSPClient& operator=(const OCSPClient&) = delete;

private:
    std::string buildRequest(const Certificate& cert, const Certificate& issuer);
    CertStatus  parseResponse(const std::vector<uint8_t>& response_data);

    static size_t curlWriteCallback(void* ptr, size_t size,
                                     size_t nmemb, void* userdata);

    std::string responder_url_;
    int         timeout_ms_;
    CURL*       curl_handle_;
};

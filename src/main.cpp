#include "tls/OQSProvider.h"
#include "pki/Certificate.h"
#include "pki/OCSPClient.h"
#include "pki/RevocationChecker.h"
#include "persistence/PostgreSQLClient.h"
#include "persistence/RedisClient.h"
#include "persistence/UserRepository.h"
#include "persistence/SessionRepository.h"
#include "persistence/DocumentRepository.h"
#include "crypto/DilithiumSigner.h"
#include "auth/AuthManager.h"
#include "api/Controllers.h"

#include <drogon/drogon.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>



// Read env variable with fallback
static std::string env(const char* name, const char* fallback)
{
    const char* val = std::getenv(name);
    return val ? std::string(val) : std::string(fallback);
}

// Write a private key PEM to a new file readable only by its owner. Refuses to
// overwrite an existing file: replacing the ML-DSA key would invalidate every
// signature already issued.
static bool writePrivateKeyFile(const std::string& path, const std::string& pem)
{
    mode_t old_mask = umask(077);
    FILE* f = fopen(path.c_str(), "wx");
    umask(old_mask);
    if (!f) return false;
    bool ok = fwrite(pem.data(), 1, pem.size(), f) == pem.size();
    return fclose(f) == 0 && ok;
}

int main(int argc, char** argv)
{
    std::cout << "Hybrid TLS 1.3: X25519 + ML-KEM-768" << std::endl;

    // Load OQS provider into OpenSSL
    auto& oqs = OQSProvider::getInstance();

    if (!oqs.load()) {
        std::cerr << "[main] OQS provider failed to load. Aborting.\n";
        return 1;
    }

    // One-off key generation used by scripts/generate_certs.sh. It runs the same
    // OpenSSL + oqs-provider build as the server, so the key format always
    // matches what loadPrivateKey expects.
    if (argc == 3 && std::string(argv[1]) == "--generate-mldsa-key") {
        DilithiumSigner signer;
        if (!signer.generateKeyPair() ||
            !writePrivateKeyFile(argv[2], signer.exportPrivateKeyPEM())) {
            std::cerr << "[main] Could not generate ML-DSA-65 key at " << argv[2]
                      << " (does the file already exist?)\n";
            return 1;
        }
        std::cout << "[main] ML-DSA-65 key written to " << argv[2] << "\n";
        return 0;
    }

    // Resolve cert paths (Drogon will load them when the listener starts)

    std::string cert_path = env("TLS_CERT_PATH", "/certs/server.crt");
    std::string key_path  = env("TLS_KEY_PATH",  "/certs/server.key");
    std::string ca_path   = env("CA_CERT_PATH",  "/certs/ca.crt");

    // Validate server cert against CA (revocation check at startup)

    Certificate server_cert, ca_cert;

    if (!ca_cert.loadFromPEM(ca_path) || !server_cert.loadFromPEM(cert_path))
    {
        std::cerr << "[main] Failed to load certificates for validation.\n";
        return 1;
    }

    if (!server_cert.verifySignature(ca_cert)) {
        std::cerr << "[main] Server cert not signed by CA. Aborting.\n";
        return 1;
    }

    std::string ocsp_url = env("OCSP_URL", "http://ocsp:8080");
    OCSPClient ocsp_client(ocsp_url);
    RevocationChecker revocation(ocsp_client);

    auto cert_status = revocation.checkCert(server_cert, ca_cert);
    if (cert_status == CertStatus::Revoked) {
        std::cerr << "[main] Server certificate is REVOKED. Aborting.\n";
        return 1;
    }
    std::cout << "[main] Certificate revocation check: OK\n";

    // Connect to persistence layer
    std::string postgress_connection = env("DATABASE_URL", "host = postgres port = 5432 dbname = pqcapi user = pqcuser password = pqcpass");
    std::string redis_host = env("REDIS_HOST", "redis");
    int redis_port = std::stoi(env("REDIS_PORT", "6379"));

    PostgreSQLClient db(postgress_connection);
    RedisClient redis(redis_host, redis_port);

    UserRepository user_repo(db);
    SessionRepository session_repo(redis);

    // Schema and the seed admin account (paulsiv) are created by
    // scripts/init.sql on first container start.

    // Load JWT HMAC secret — no fallback: a known or short key lets anyone forge tokens
    const char* jwt_secret_env = std::getenv("JWT_SECRET");
    if (!jwt_secret_env) {
        std::cerr << "[main] JWT_SECRET is not set. Aborting.\n";
        return 1;
    }
    std::string jwt_secret(jwt_secret_env);
    if (jwt_secret.size() < 32 || jwt_secret == "change-me-in-production") {
        std::cerr << "[main] JWT_SECRET must be at least 32 bytes and not the placeholder. Aborting.\n";
        return 1;
    }

    // Build application layer
    AuthManager auth(jwt_secret, user_repo, session_repo);

    // Load or generate ML-DSA-65 keypair for document signing

    DilithiumSigner doc_signer;
    std::string mldsa_key_path = env("MLDSA_KEY_PATH", "/certs/mldsa_server.key");

    if (!doc_signer.loadPrivateKey(mldsa_key_path)) {
        std::cout << "[main] Generating new ML-DSA-65 document signing keypair...\n";
        if (!doc_signer.generateKeyPair()) {
            std::cerr << "[main] ML-DSA-65 keygen failed. Aborting.\n";
            return 1;
        }
        if (writePrivateKeyFile(mldsa_key_path, doc_signer.exportPrivateKeyPEM())) {
            std::cout << "[main] ML-DSA-65 key saved to " << mldsa_key_path << "\n";
        } else {
            std::cerr << "[main] Warning: could not persist ML-DSA-65 key to " << mldsa_key_path
                      << "; documents signed now will fail verification after a restart. "
                         "Run scripts/generate_certs.sh to create the key.\n";
        }
    }

    DocumentRepository doc_repo(db);

    // Register Drogon controllers
    auto auth_ctrl   = std::make_shared<AuthController>(auth);
    auto user_ctrl   = std::make_shared<UserController>(auth, user_repo);
    auto health_ctrl = std::make_shared<HealthController>();
    auto admin_ctrl  = std::make_shared<AdminController>(auth, user_repo, server_cert);
    auto doc_ctrl    = std::make_shared<DocumentController>(auth, doc_repo, doc_signer);

    drogon::app().registerController(auth_ctrl);
    drogon::app().registerController(user_ctrl);
    drogon::app().registerController(health_ctrl);
    drogon::app().registerController(admin_ctrl);
    drogon::app().registerController(doc_ctrl);

    // Configure Drogon's TLS listener with PQC-aware SSL_CONF commands

    int server_port = std::stoi(env("SERVER_PORT", "8443"));

    std::vector<std::pair<std::string, std::string>> ssl_conf_cmds = {
        {"Groups",       "X25519MLKEM768:x25519"},
        {"MinProtocol",  "TLSv1.3"},
        {"MaxProtocol",  "TLSv1.3"},
        {"CipherString", "DEFAULT:@SECLEVEL=0"},
    };

    // Security headers on every response, static files included. The CSP blocks
    // inline scripts and event handlers, so injected markup can't run code.
    // Inline styles stay allowed because the pages use style attributes.
    drogon::app().registerPreSendingAdvice(
        [](const drogon::HttpRequestPtr&, const drogon::HttpResponsePtr& resp) {
            resp->addHeader("Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
                "form-action 'self'; frame-ancestors 'none'");
            resp->addHeader("X-Content-Type-Options", "nosniff");
            resp->addHeader("X-Frame-Options", "DENY");
            resp->addHeader("Referrer-Policy", "no-referrer");
        });

    drogon::app()
        .setDocumentRoot("./static")
        .addListener("0.0.0.0", server_port, true,
                     cert_path, key_path,
                     false,
                     ssl_conf_cmds)
        .setThreadNum(4)
        .setClientMaxBodySize(50 * 1024 * 1024)   // <- this 50 MB
        .setLogLevel(trantor::Logger::kInfo);

    std::cout << "[main] Server starting on port " << server_port
              << " (HTTPS / TLS 1.3 + PQC)\n";

    drogon::app().run();
    return 0;
}

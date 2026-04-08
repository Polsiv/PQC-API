#include "tls/OQSProvider.h"
#include "tls/OpenSSLContext.h"
#include "pki/Certificate.h"
#include "pki/OCSPClient.h"
#include "pki/RevocationChecker.h"
#include "crypto/DilithiumSigner.h"
#include "persistence/PostgreSQLClient.h"
#include "persistence/RedisClient.h"
#include "persistence/UserRepository.h"
#include "persistence/SessionRepository.h"
#include "auth/AuthManager.h"
#include "api/Controllers.h"

#include <drogon/drogon.h>
#include <iostream>
#include <cstdlib>



// Read env variable with fallback 
static std::string env(const char* name, const char* fallback)
{
    const char* val = std::getenv(name);
    return val ? std::string(val) : std::string(fallback);
}

int main() 
{
    std::cout << "ML-KEM-768 + ML-DSA-65" << std::endl;

    // Load OQS provider into OpenSSL
    auto& oqs = OQSProvider::getInstance();

    if (!oqs.load()) {
        std::cerr << "[main] OQS provider failed to load. Aborting.\n";
        return 1;
    }

    // 2. Configure TLS context 

    OpenSSLContext tls_ctx(OpenSSLContext::Mode::Server);

    if (!tls_ctx.init())
    {
        std::cerr << "[main] TLS context init failed. Aborting.\n";
        return 1;
    }

    std::string cert_path = env("TLS_CERT_PATH", "/certs/server.crt");
    std::string key_path  = env("TLS_KEY_PATH",  "/certs/server.key");
    std::string ca_path   = env("CA_CERT_PATH",  "/certs/ca.crt");

    if (!tls_ctx.loadCertificate(cert_path, key_path))
    {  
        std::cerr << "[main] Failed to load TLS certificate. Aborting.\n";
        return 1;
    }

    tls_ctx.loadCAFile(ca_path);

    // 3. Validate server cert against CA (revocation check at startup) 

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

    // 4. Connect to persistence layer 
    std::string postgress_connection = env("DATABASE_URL", "host = postgres port = 5432 dbname = pqcapi user = pqcuser password = pqcpass");
    std::string redis_host = env("REDIS_HOST", "redis");
    int redis_port = std::stoi(env("REDIS_PORT", "6379"));

    PostgreSQLClient db(postgress_connection);
    RedisClient redis(redis_host, redis_port);

    UserRepository user_repo(db);
    SessionRepository session_repo(redis);

    // Ensure schema exists
    user_repo.createTable();

    // 5. Load signing key for application-layer JWT tokens
    DilithiumSigner signer;
    std::string signing_key_path = env("SIGNING_KEY_PATH", "/certs/server.key");
    if (!signer.loadPrivateKey(signing_key_path)) {
        // Fallback: generate ephemeral signing key (not recommended for production)
        std::cout << "[main] Generating ephemeral ML-DSA-65 signing key...\n";
        signer.generateKeyPair();
    }

    // ── 6. Build application layer ────────────────────────────────────────────
    AuthManager auth(signer, user_repo, session_repo);

    // ── 7. Register Drogon controllers ───────────────────────────────────────
    auto auth_ctrl   = std::make_shared<AuthController>(auth);
    auto user_ctrl   = std::make_shared<UserController>(auth, user_repo);
    auto health_ctrl = std::make_shared<HealthController>();

    drogon::app().registerController(auth_ctrl);
    drogon::app().registerController(user_ctrl);
    drogon::app().registerController(health_ctrl);

    // ── 8. Configure Drogon with our OQS-backed SSL_CTX ──────────────────────
    int server_port = std::stoi(env("SERVER_PORT", "8443"));

    drogon::app()
        .addListener("0.0.0.0", server_port, true,
                     cert_path, key_path)   // Drogon manages TLS internally
        .setThreadNum(4)
        .setLogLevel(trantor::Logger::kInfo);

    std::cout << "[main] Server starting on port " << server_port
              << " (HTTPS / TLS 1.3 + PQC)\n";

    drogon::app().run();
    return 0;
}

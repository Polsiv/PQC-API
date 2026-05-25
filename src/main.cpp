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
#include <cstdlib>



// Read env variable with fallback
static std::string env(const char* name, const char* fallback)
{
    const char* val = std::getenv(name);
    return val ? std::string(val) : std::string(fallback);
}

int main()
{
    std::cout << "Hybrid TLS 1.3: X25519 + ML-KEM-768" << std::endl;

    // Load OQS provider into OpenSSL
    auto& oqs = OQSProvider::getInstance();

    if (!oqs.load()) {
        std::cerr << "[main] OQS provider failed to load. Aborting.\n";
        return 1;
    }

    // 2. Resolve cert paths (Drogon will load them when the listener starts)

    std::string cert_path = env("TLS_CERT_PATH", "/certs/server.crt");
    std::string key_path  = env("TLS_KEY_PATH",  "/certs/server.key");
    std::string ca_path   = env("CA_CERT_PATH",  "/certs/ca.crt");

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

    // 5. Load JWT HMAC secret
    std::string jwt_secret = env("JWT_SECRET", "change-me-in-production");

    // 6. Build application layer
    AuthManager auth(jwt_secret, user_repo, session_repo);

    // 7. Load or generate ML-DSA-65 keypair for document signing
    DilithiumSigner doc_signer;
    std::string mldsa_key_path = env("MLDSA_KEY_PATH", "/certs/mldsa_server.key");

    if (!doc_signer.loadPrivateKey(mldsa_key_path)) {
        std::cout << "[main] Generating new ML-DSA-65 document signing keypair...\n";
        if (!doc_signer.generateKeyPair()) {
            std::cerr << "[main] ML-DSA-65 keygen failed. Aborting.\n";
            return 1;
        }
        std::string pem = doc_signer.exportPrivateKeyPEM();
        FILE* f = fopen(mldsa_key_path.c_str(), "w");
        if (f) {
            fwrite(pem.data(), 1, pem.size(), f);
            fclose(f);
            std::cout << "[main] ML-DSA-65 key saved to " << mldsa_key_path << "\n";
        } else {
            std::cerr << "[main] Warning: could not persist ML-DSA-65 key to " << mldsa_key_path << "\n";
        }
    }

    DocumentRepository doc_repo(db);
    doc_repo.createTable();

    // 8. Register Drogon controllers
    auto auth_ctrl   = std::make_shared<AuthController>(auth);
    auto user_ctrl   = std::make_shared<UserController>(auth, user_repo);
    auto health_ctrl = std::make_shared<HealthController>();
    auto doc_ctrl    = std::make_shared<DocumentController>(auth, doc_repo, doc_signer);

    drogon::app().registerController(auth_ctrl);
    drogon::app().registerController(user_ctrl);
    drogon::app().registerController(health_ctrl);
    drogon::app().registerController(doc_ctrl);

    // 8. Configure Drogon's TLS listener with PQC-aware SSL_CONF commands
    // OQSProvider is already registered in OpenSSL's default library context,
    // so Drogon's internal SSL_CTX inherits ML-KEM-768
    // We just need to tell that context to advertise the hybrid group and
    int server_port = std::stoi(env("SERVER_PORT", "8443"));

    std::vector<std::pair<std::string, std::string>> ssl_conf_cmds = {
        {"Groups",       "X25519MLKEM768:x25519"},
        {"MinProtocol",  "TLSv1.3"},
        {"MaxProtocol",  "TLSv1.3"},
        {"CipherString", "DEFAULT:@SECLEVEL=0"},
    };

    drogon::app()
        .setDocumentRoot("./static")
        .addListener("0.0.0.0", server_port, /*useSSL*/ true,
                     cert_path, key_path,
                     /*useOldTLS*/ false,
                     ssl_conf_cmds)
        .setThreadNum(4)
        .setClientMaxBodySize(50 * 1024 * 1024)   // <- this 50 MB
        .setLogLevel(trantor::Logger::kInfo);

    std::cout << "[main] Server starting on port " << server_port
              << " (HTTPS / TLS 1.3 + PQC)\n";

    drogon::app().run();
    return 0;
}

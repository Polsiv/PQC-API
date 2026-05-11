# PQC TLS 1.3 API

A C++ REST API secured end-to-end with post-quantum cryptography:

| Role            | Algorithm              | Library         |
|-----------------|------------------------|-----------------|
| Key Exchange    | ML-KEM-768 (Kyber768)  | liboqs + OpenSSL |
| Authentication  | ML-DSA-65 (Dilithium3) | liboqs + OpenSSL |
| Symmetric Enc.  | AES-256-GCM            | OpenSSL          |
| Token Signing   | ML-DSA-65              | liboqs + OpenSSL |
| Password Hash   | Argon2id               | libsodium        |

---

## Project Structure

```
pqc-api/
├── include/
│   ├── tls/         OQSProvider
│   ├── crypto/      DilithiumSigner
│   ├── pki/         Certificate, OCSPClient, RevocationChecker
│   ├── persistence/ RedisClient, PostgreSQLClient, UserRepository, SessionRepository
│   ├── auth/        AuthManager
│   └── api/         Controllers
├── src/             implementations
├── scripts/
│   ├── generate_certs.sh   one-time cert generation
│   └── init.sql            PostgreSQL schema
├── certs/           generated certificates (git-ignored except .crt)
├── CMakeLists.txt
├── Dockerfile
└── docker-compose.yml
```

---

## Quick Start

### Step 1 — Generate certificates (run once)

Requires OpenSSL 3.x + oqs-provider installed on your host:

```bash
chmod +x scripts/generate_certs.sh
./scripts/generate_certs.sh
```

This produces `certs/ca.crt`, `certs/server.crt`, `certs/server.key`,
and `certs/index.txt` (for the OCSP responder).

### Step 2 — Build and run

```bash
docker-compose up --build
```

Four containers start:
- `pqc_api`      → HTTPS on port 8443
- `pqc_ocsp`     → OCSP responder on port 8080
- `pqc_postgres` → PostgreSQL
- `pqc_redis`    → Redis

---

## API Endpoints

All endpoints are over HTTPS (TLS 1.3 + ML-KEM-768).

### Health check
```
GET /health
```
Returns TLS algorithm info — useful to confirm PQC is negotiated.

### Register
```
POST /api/auth/register
Content-Type: application/json

{ "username": "alice", "password": "supersecret123" }
```

### Login
```
POST /api/auth/login
Content-Type: application/json

{ "username": "alice", "password": "supersecret123" }
```
Returns a **ML-DSA-65 signed JWT** token.

### Get profile (protected)
```
GET /api/users/me
Authorization: Bearer <token>
```

### Logout
```
POST /api/users/logout
Authorization: Bearer <token>
```

---

## Testing with curl

Because the CA is self-signed, pass `--cacert`:

```bash
# Health check
curl --cacert certs/ca.crt https://localhost:8443/health

# Register
curl --cacert certs/ca.crt -X POST https://localhost:8443/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"supersecret123"}'

# Login — save the token
TOKEN=$(curl -s --cacert certs/ca.crt -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"supersecret123"}' | jq -r .token)

# Get profile
curl --cacert certs/ca.crt https://localhost:8443/api/users/me \
  -H "Authorization: Bearer $TOKEN"
```

---

## Architecture Notes

- **CA** is offline — `generate_certs.sh` runs once, produces cert files.
  `CertificateAuthority` in the code only loads and validates, never issues.

- **OCSP** responder is a single `openssl ocsp` process in a container.
  `OCSPClient` uses libcurl to POST requests to it. `RevocationChecker`
  caches responses for 5 minutes to avoid per-connection round trips.

- **Token format** is a custom JWT-style structure:
  `Base64url(header).Base64url(payload).Base64url(ML-DSA-65 signature)`
  Standard JWT libraries don't support ML-DSA — this is intentional.

- **DilithiumSigner** is used in two places:
  1. TLS layer — via the X.509 certificate (handled by OpenSSL + OQS)
  2. Application layer — signing/verifying JWT tokens in AuthManager

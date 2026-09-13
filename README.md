# PQC TLS 1.3 API



A C++ REST API (Drogon) for post-quantum document signing, served over hybrid post-quantum TLS 1.3.

| Role              | Algorithm                                         | Library                         |
|-------------------|---------------------------------------------------|---------------------------------|
| TLS key exchange  | X25519 + ML-KEM-768 hybrid (`X25519MLKEM768`)     | OpenSSL + oqs-provider (liboqs) |
| TLS server auth   | ECDSA P-256 certificate                           | OpenSSL                         |
| TLS encryption    | TLS 1.3 AEAD suites (AES-GCM, ChaCha20-Poly1305)  | OpenSSL                         |
| Document signing  | ML-DSA-65 (Dilithium3)                            | OpenSSL + oqs-provider (liboqs) |
| Token signing     | HMAC-SHA256 (HS256 JWT)                           | OpenSSL                         |
| Password hashing  | Argon2id                                          | libsodium                       |

---


---

## Quick Start

### Step 1 — Generate certificates and keys (run once)

Requires OpenSSL 3.x and Docker on your host (oqs-provider is not needed locally):

```bash
chmod +x scripts/generate_certs.sh
./scripts/generate_certs.sh
```

This creates the following in `certs/`:

| File | Purpose |
|------|---------|
| `ca.crt` / `ca.key` | ECDSA P-256 certificate authority. `ca.key` also signs the OCSP responder's responses |
| `server.crt` / `server.key` | ECDSA P-256 TLS certificate and key for the API |
| `index.txt` | Revocation database for the OCSP responder |
| `mldsa_server.key` | ML-DSA-65 private key used to sign uploaded PDFs |

`mldsa_server.key` is generated inside the API's Docker image, so it is created by the
same OpenSSL + oqs-provider build that loads it. Re-running the script keeps an existing
key, because replacing it makes every previously signed document fail verification.
`certs/` is mounted read-only into the containers, so the key must exist before the first start.

### Step 2 — Set the JWT secret

The API refuses to start without a `JWT_SECRET` of at least 32 bytes. Docker Compose
reads it from a `.env` file in the project root, which git ignores:

```bash
echo "JWT_SECRET=$(openssl rand -hex 32)" > .env
```

### Step 3 — Build and run

```bash
docker-compose up --build
```

Four containers start:
- `pqc_api`      → HTTPS on port 8443
- `pqc_ocsp`     → OCSP responder on port 8080
- `pqc_postgres` → PostgreSQL
- `pqc_redis`    → Redis

---

## Tests

The stack must be running (`docker compose up -d --build`).

### Benchmark harness: `tests/main.go`

Requires Go 1.24+ (`X25519MLKEM768` is built into `crypto/tls` from that version).

```bash
cd tests
go run main.go -ca ../certs/ca.crt
```

It registers and logs in a test user, then benchmarks:

1. TLS handshake, hybrid PQC vs classical X25519 (latency, bytes on the wire, server CPU and memory)
2. Login and logout
3. ML-DSA-65 PDF signing
4. ML-DSA-65 signature verification
5. Signed PDF download
6. Admin health endpoint

Results are written to `results_<timestamp>.csv`, `sizes_<timestamp>.csv` and `resources_<timestamp>.csv`.

| Flag              | Default                             | Purpose                                         |
|-------------------|-------------------------------------|-------------------------------------------------|
| `-base`           | `https://localhost:8443`            | API URL                                         |
| `-ca`             | `./certs/ca.crt`                    | CA certificate                                  |
| `-pdf`            | `./sample.pdf`                      | PDF used for the signing tests                  |
| `-n`              | `100`                               | Iterations per benchmark                        |
| `-user` / `-pass` | `testuser_harness` / `testpass123!` | Test account (registered automatically)         |
| `-concurrency`    | `1`                                 | Concurrent handshake workers                    |
| `-interleave`     | `true`                              | Alternate PQC and classical handshakes in blocks |
| `-block`          | `50`                                | Handshakes per block when interleaving          |
| `-container`      | `pqc_api`                           | Container sampled for CPU and memory            |
| `-docker`         | `docker`                            | Docker CLI used for sampling                    |

Notes:
- The admin health benchmark records failures (`403`) unless `-user`/`-pass` belong to an admin account.
- CPU and memory are sampled with `docker exec` against the API container. In WSL, either enable
  Docker Desktop's WSL integration for your distro or pass `-docker docker.exe`.

### Sign-and-verify script: `tests/pdf.sh`

An end-to-end check of signing and external verification using curl:

```bash
cd tests
./pdf.sh sample.pdf
```

It logs in with the `USERNAME`/`PASSWORD` set at the top of the script, signs the PDF, fetches the
server's public key and verifies the signature.


---

## API Endpoints

All endpoints are over HTTPS (TLS 1.3 + ML-KEM-768).

### Health check
```
GET /health
```
Returns a static summary of the configured algorithms. It does not report what a particular
connection negotiated; the benchmark harness in [Tests](#tests) measures the actual handshake.

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
Returns `{ "token": "...", "user_id": "...", "type": "Bearer" }`. The token is an HS256 JWT valid for one hour.

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
Revokes the token's session server-side, so the token stops working immediately.

### Documents (protected)

All require `Authorization: Bearer <token>`. Users can only access their own documents.

| Method   | Path                            | Description |
|----------|---------------------------------|-------------|
| `POST`   | `/api/documents/sign`           | Upload a PDF (multipart field `file`). Returns `doc_id`, `sha256` and the base64 ML-DSA-65 `signature` |
| `GET`    | `/api/documents`                | List your signed documents |
| `GET`    | `/api/documents/{id}/download`  | Download the stored PDF |
| `POST`   | `/api/documents/{id}/verify`    | Re-verify a stored document against the server key |
| `DELETE` | `/api/documents/{id}`           | Delete a document |

### Public verification (no account needed)

| Method | Path                         | Description |
|--------|------------------------------|-------------|
| `GET`  | `/api/documents/public-key`  | The server's ML-DSA-65 public key (PEM) |
| `POST` | `/api/documents/verify`      | Multipart fields `pdf`, `signature` (base64) and `public_key` (PEM). Only ML-DSA-65 keys are accepted. Returns `valid` and `server_key` (whether the key is this server's) |

### Admin health (admin only)
```
GET /api/admin/health
Authorization: Bearer <token>
```
Returns `UP`, `DEGRADED` or `DOWN` for the API server and the TLS layer (based on certificate expiry).
Users without the admin role get `403`.

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

- **Single service.** One Drogon binary serves the REST API and the static frontend (`static/`),
  backed by PostgreSQL (users and documents), Redis (sessions) and an OCSP responder.

- **TLS.** TLS 1.3 only. The server supports the hybrid `X25519MLKEM768` group and falls back to
  classical `x25519` for clients without post-quantum support. The certificate is classical
  ECDSA P-256, so post-quantum protection covers the key exchange, not server authentication.

- **Certificates.** `generate_certs.sh` creates the CA and server certificate; the API never issues
  certificates. At startup, `Certificate` checks that the server certificate is signed by the CA,
  and `RevocationChecker` queries the `openssl ocsp` responder through `OCSPClient` (libcurl).
  Startup aborts only if the certificate is reported revoked. Responses are cached for 5 minutes.

- **Tokens.** Standard HS256 JWTs, `base64url(header).base64url(payload).base64url(HMAC-SHA256)`,
  signed with `JWT_SECRET`. The payload holds `sub` (user ID), `sid` (session ID), `iat` and `exp`
  (1 hour). Each session is stored in Redis as `session:<sid>` → user ID. A token is accepted only
  if its session exists and belongs to `sub`, and logout deletes the session.

- **Document signing.** `DilithiumSigner` handles all ML-DSA-65 operations: signing uploaded PDFs
  with the key at `MLDSA_KEY_PATH`, re-verifying stored documents, and verifying externally
  submitted signatures (ML-DSA-65 keys only). PDFs and signatures are stored base64-encoded in PostgreSQL.

- **Frontend hardening.** Every response carries a Content Security Policy (`script-src 'self'`)
  plus `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy` headers. Pages contain no
  inline scripts or event handlers.

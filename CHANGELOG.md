# Changelog

## [Unreleased] — 2026-04-29

### Phase 1 — Replace Dilithium JWT signing with HS256

#### `include/auth/AuthManager.h`
- Removed `#include "crypto/DilithiumSigner.h"`
- Replaced `DilithiumSigner& signer_` member with `std::string secret_key_`
- Updated constructor signature from `AuthManager(DilithiumSigner&, ...)` to `AuthManager(const std::string& secret_key, ...)`
- Removed Dilithium-specific comments from class doc

#### `src/auth/AuthManager.cpp`
- Added `#include <openssl/hmac.h>` and `#include <openssl/crypto.h>`
- Updated constructor to accept and store `secret_key_`
- `buildToken()`: replaced `signer_.sign()` with `HMAC(EVP_sha256(), ...)` 
- `parseToken()`: replaced `signer_.verify()` with `HMAC(EVP_sha256(), ...)` + `CRYPTO_memcmp()` for constant-time comparison
- Changed JWT `"alg"` header value from `"ML-DSA-65"` to `"HS256"`

#### `src/main.cpp`
- Removed `#include "crypto/DilithiumSigner.h"`
- Removed `DilithiumSigner signer` instantiation and `SIGNING_KEY_PATH` key loading block
- Added `jwt_secret` read from `JWT_SECRET` env var (fallback: `"change-me-in-production"`)
- Updated `AuthManager` construction to pass `jwt_secret` instead of `signer`

#### `src/api/Controllers.cpp`
- Updated `/health` endpoint: `"token_signing"` field changed from `"ML-DSA-65 (application layer)"` to `"HS256"`

#### `scripts/generate_certs.sh`
- Removed ML-DSA-65 JWT signing key generation block (`openssl genpkey -algorithm mldsa65`)

---

### Phase 2 — ML-DSA-65 PDF document signing

#### `include/persistence/DocumentRepository.h` *(new)*
- `Document` struct: `id`, `user_id`, `filename`, `sha256_hash`, `signature_b64`, `signed_at`
- `DocumentRepository` class with `createTable`, `save`, `findById`, `findByUserId`, `getPdfData`, `ownedBy`

#### `src/persistence/DocumentRepository.cpp` *(new)*
- `documents` table schema: `id`, `user_id` (FK → users), `filename`, `pdf_data TEXT`, `signature TEXT`, `sha256_hash`, `signed_at`
- PDF and signature stored as standard base64 TEXT; compatible with existing `PostgreSQLClient` string-param API
- `save()` uses `INSERT ... RETURNING id` to return the new document ID
- `ownedBy()` enforces user-scoped access before download/verify

#### `include/api/Controllers.h`
- Added `#include "persistence/DocumentRepository.h"` and `#include "crypto/DilithiumSigner.h"`
- New `DocumentController` class (AutoCreation=false) with four endpoints:
  - `POST /api/documents/sign`
  - `GET  /api/documents`
  - `GET  /api/documents/{id}/download`
  - `POST /api/documents/{id}/verify`

#### `src/api/Controllers.cpp`
- Added `base64Encode` / `base64Decode` helpers (OpenSSL BIO, no newlines)
- Added `sha256Hex` helper (OpenSSL `EVP_Digest`)
- `DocumentController::sign`: receives multipart PDF, signs raw bytes with ML-DSA-65, persists base64 PDF + signature + SHA-256, returns `doc_id`, `sha256`, `signature`, `algorithm`
- `DocumentController::list`: returns metadata array (id, filename, sha256, signed_at) for the authenticated user
- `DocumentController::download`: decodes stored base64 PDF, returns raw bytes as `application/pdf` with `Content-Disposition: attachment`
- `DocumentController::verify`: reloads stored PDF + signature, calls `DilithiumSigner::verify()`, returns `{ valid, doc_id, algorithm, filename, sha256 }`
- Updated `/health` response: added `"doc_signing": "ML-DSA-65 (Dilithium3)"`

#### `src/main.cpp`
- Added `#include "persistence/DocumentRepository.h"` and `#include "crypto/DilithiumSigner.h"`
- On startup: attempts to load ML-DSA-65 private key from `MLDSA_KEY_PATH` (default `/certs/mldsa_server.key`); generates and persists a new keypair if not found
- Instantiates `DocumentRepository` and calls `createTable()`
- Registers `DocumentController` with Drogon

#### `CMakeLists.txt`
- Added `src/persistence/DocumentRepository.cpp` to `SOURCES`

---

### Phase 3 — Public key exposure and external verification

#### `include/api/Controllers.h`
- Added two new endpoints to `DocumentController`:
  - `GET  /api/documents/public-key`
  - `POST /api/documents/verify`

#### `src/api/Controllers.cpp`
- `DocumentController::publicKey`: exports the server's ML-DSA-65 public key as PEM via `DilithiumSigner::exportPublicKeyPEM()`; returns `{ algorithm, public_key_pem }`
- `DocumentController::verifyExternal`: stateless external verification endpoint; accepts multipart `pdf` (file), `signature` (base64), and `public_key` (PEM); calls `DilithiumSigner::verifyWithPEM()` without requiring authentication or database access; returns `{ valid, algorithm }`

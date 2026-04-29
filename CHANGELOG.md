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

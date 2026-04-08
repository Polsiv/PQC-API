#!/usr/bin/env bash
# generate_certs.sh
# ─────────────────────────────────────────────────────────────────────────────
# Generates a full ML-DSA-65 (Dilithium3) CA + server certificate chain
# using the OQS provider. Run this ONCE before docker-compose up.
#
# Prerequisites:
#   - OpenSSL 3.x installed
#   - oqs-provider built and on the provider path
#     (or set OPENSSL_MODULES to its directory)
#
# Usage:
#   ./scripts/generate_certs.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

CERTS_DIR="$(pwd)/certs"
ALGO="mldsa65"                    # ML-DSA-65 = Dilithium3 NIST standard name
DAYS=365
PROVIDER_FLAG="-provider oqsprovider -provider default"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "════════════════════════════════════════"
echo "  Generating ML-DSA-65 Certificate Chain"
echo "  Algorithm : $ALGO"
echo "  Output    : $CERTS_DIR"
echo "════════════════════════════════════════"

# ── 1. Generate CA key and self-signed root certificate ──────────────────────
echo ""
echo "[1/4] Generating CA key and root certificate..."
openssl req $PROVIDER_FLAG \
    -x509 -new \
    -newkey "$ALGO" \
    -keyout ca.key \
    -out    ca.crt \
    -nodes \
    -subj   "/CN=PQC-TLS CA/O=PQC API/C=US" \
    -days   "$DAYS"

echo "      ✓ ca.key and ca.crt generated"

# ── 2. Generate server private key ───────────────────────────────────────────
echo ""
echo "[2/4] Generating server private key..."
openssl genpkey $PROVIDER_FLAG \
    -algorithm "$ALGO" \
    -out server.key

echo "      ✓ server.key generated"

# ── 3. Generate certificate signing request ──────────────────────────────────
echo ""
echo "[3/4] Generating server CSR..."
openssl req $PROVIDER_FLAG \
    -new \
    -key    server.key \
    -out    server.csr \
    -subj   "/CN=localhost/O=PQC API Server/C=US"

echo "      ✓ server.csr generated"

# ── 4. Sign server cert with CA ───────────────────────────────────────────────
echo ""
echo "[4/4] Signing server certificate with CA..."
openssl x509 $PROVIDER_FLAG \
    -req \
    -in         server.csr \
    -CA         ca.crt \
    -CAkey      ca.key \
    -CAcreateserial \
    -out        server.crt \
    -days       "$DAYS"

echo "      ✓ server.crt signed by CA"

# ── Create OCSP index file (required by openssl ocsp responder) ───────────────
echo ""
echo "[+] Creating OCSP index file..."
# Format: V/R <tab> expiry <tab> serial <tab> unknown <tab> subject
SERIAL=$(openssl x509 -in server.crt -noout -serial | cut -d= -f2)
EXPIRY=$(openssl x509 -in server.crt -noout -enddate | cut -d= -f2 | \
         date -f - +"%y%m%d%H%M%SZ" 2>/dev/null || \
         openssl x509 -in server.crt -noout -enddate | cut -d= -f2)

printf "V\t%s\t\t%s\tunknown\t/CN=localhost/O=PQC API Server/C=US\n" \
       "$EXPIRY" "$SERIAL" > index.txt

echo "      ✓ index.txt created"

# ── Verify the chain ──────────────────────────────────────────────────────────
echo ""
echo "[+] Verifying certificate chain..."
openssl verify $PROVIDER_FLAG -CAfile ca.crt server.crt && \
    echo "      ✓ Chain verification PASSED" || \
    echo "      ✗ Chain verification FAILED"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════"
echo "  Generated files in $CERTS_DIR:"
echo ""
echo "  ca.key      ← CA private key   (KEEP SECRET — not needed at runtime)"
echo "  ca.crt      ← CA root cert     (loaded by server + OCSP responder)"
echo "  server.key  ← Server private key  (loaded by Drogon)"
echo "  server.crt  ← Server certificate  (loaded by Drogon)"
echo "  index.txt   ← OCSP revocation DB  (loaded by OCSP responder)"
echo "════════════════════════════════════════"
echo ""
echo "  Next step:  docker-compose up --build"
echo ""

# Cleanup CSR — not needed after signing
rm -f server.csr ca.srl

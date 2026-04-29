#!/usr/bin/env bash
# generate_certs.sh — Hybrid PQC TLS 1.3
# ─────────────────────────────────────────────────────────────────────────────
# Generates an ECDSA P-256 CA + server certificate chain.
# The certificate uses classical ECDSA (fully supported by OpenSSL 3.0).
# The PQC guarantee comes from X25519+ML-KEM-768 hybrid key exchange at
# runtime — the cert just needs to be valid, not PQC-signed.
#
# Usage (from project root):
#   chmod +x scripts/generate_certs.sh
#   ./scripts/generate_certs.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

CERTS_DIR="$(pwd)/certs"
DAYS=365

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "════════════════════════════════════════════"
echo "  Hybrid PQC TLS — Certificate Generation"
echo "  CA + Server: ECDSA P-256"
echo "  Key Exchange: X25519 + ML-KEM-768 (runtime)"
echo "════════════════════════════════════════════"

# ── 1. CA private key (ECDSA P-256) ──────────────────────────────────────────
echo ""
echo "[1/5] Generating CA private key (ECDSA P-256)..."
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
echo "      ✓ ca.key"

# ── 2. Self-signed CA certificate ────────────────────────────────────────────
echo ""
echo "[2/5] Generating CA certificate..."
openssl req -new -x509 \
    -key ca.key \
    -out ca.crt \
    -days "$DAYS" \
    -subj "/CN=PQC-TLS CA/O=PQC API/C=US"
echo "      ✓ ca.crt"

# ── 3. Server private key (ECDSA P-256) ──────────────────────────────────────
echo ""
echo "[3/5] Generating server private key..."
openssl ecparam -name prime256v1 -genkey -noout -out server.key
echo "      ✓ server.key"

# ── 4. Server CSR + sign ──────────────────────────────────────────────────────
echo ""
echo "[4/5] Generating and signing server certificate..."
openssl req -new \
    -key server.key \
    -out server.csr \
    -subj "/CN=localhost/O=PQC API Server/C=US"

# Create OCSP extension config
cat > ocsp_ext.cnf << EOF
authorityInfoAccess = OCSP;URI:http://localhost:8080
EOF

openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days "$DAYS" \
    -sha256 \
    -extfile ocsp_ext.cnf
echo "      ✓ server.crt"

# ── 5. OCSP index ─────────────────────────────────────────────────────────────
echo ""
echo "[5/5] Creating OCSP index..."
SERIAL=$(openssl x509 -in server.crt -noout -serial | cut -d= -f2)
EXPIRY=$(openssl x509 -in server.crt -noout -enddate | cut -d= -f2)
printf "V\t%s\t\t%s\tunknown\t/CN=localhost/O=PQC API Server/C=US\n" \
    "$EXPIRY" "$SERIAL" > index.txt
echo "      ✓ index.txt"

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo "[+] Verifying chain..."
openssl verify -CAfile ca.crt server.crt && echo "      ✓ Chain OK"

# Cleanup
rm -f server.csr ca.srl ocsp_ext.cnf

echo ""
echo "════════════════════════════════════════════"
echo "  Files in $CERTS_DIR:"
echo "  ca.key      ← keep secret, offline only"
echo "  ca.crt      ← loaded by server + OCSP"
echo "  server.key  ← loaded by Drogon"
echo "  server.crt  ← loaded by Drogon"
echo "  index.txt   ← OCSP revocation DB"
echo ""
echo "  Next: docker-compose up --build"
echo "════════════════════════════════════════════"

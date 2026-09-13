#!/usr/bin/env bash
# generate_certs.sh — Hybrid PQC TLS 1.3
# ─────────────────────────────────────────────────────────────────────────────
# Generates an ECDSA P-256 CA + server certificate chain.
# The certificate uses classical ECDSA (fully supported by OpenSSL 3.0).
# The PQC guarantee comes from X25519+ML-KEM-768 hybrid key exchange at
# runtime — the cert just needs to be valid, not PQC-signed.
#
# Also creates the ML-DSA-65 document signing key (once) by running the API
# image, so the key is produced by the same OpenSSL + oqs-provider build that
# loads it.
#
# Usage (from project root):
#   chmod +x scripts/generate_certs.sh
#   ./scripts/generate_certs.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

PROJECT_DIR="$(pwd)"
CERTS_DIR="$PROJECT_DIR/certs"
DAYS=365

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "════════════════════════════════════════════"
echo "  Hybrid PQC TLS — Certificate Generation"
echo "  CA + Server: ECDSA P-256"
echo "  Key Exchange: X25519 + ML-KEM-768 (runtime)"
echo "  Document signing: ML-DSA-65"
echo "════════════════════════════════════════════"

# ── 1. CA private key (ECDSA P-256) ──────────────────────────────────────────
echo ""
echo "[1/6] Generating CA private key (ECDSA P-256)..."
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
echo "      ✓ ca.key"

# ── 2. Self-signed CA certificate ────────────────────────────────────────────
echo ""
echo "[2/6] Generating CA certificate..."
openssl req -new -x509 \
    -key ca.key \
    -out ca.crt \
    -days "$DAYS" \
    -subj "/CN=PQC-TLS CA/O=PQC API/C=US"
echo "      ✓ ca.crt"

# ── 3. Server private key (ECDSA P-256) ──────────────────────────────────────
echo ""
echo "[3/6] Generating server private key..."
openssl ecparam -name prime256v1 -genkey -noout -out server.key
echo "      ✓ server.key"

# ── 4. Server CSR + sign ──────────────────────────────────────────────────────
echo ""
echo "[4/6] Generating and signing server certificate..."
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
echo "[5/6] Creating OCSP index..."
SERIAL=$(openssl x509 -in server.crt -noout -serial | cut -d= -f2)
EXPIRY=$(openssl x509 -in server.crt -noout -enddate | cut -d= -f2)
printf "V\t%s\t\t%s\tunknown\t/CN=localhost/O=PQC API Server/C=US\n" \
    "$EXPIRY" "$SERIAL" > index.txt
echo "      ✓ index.txt"

# ── 6. ML-DSA-65 document signing key ─────────────────────────────────────────
# Never overwritten: replacing it makes every stored signature fail verification.
echo ""
echo "[6/6] ML-DSA-65 document signing key..."
if [ -f mldsa_server.key ]; then
    echo "      ✓ mldsa_server.key already exists, keeping it"
else
    echo "      Building API image (the first build takes several minutes)..."
    docker build -t pqc_api_keygen "$PROJECT_DIR"

    # Git Bash needs a Windows-style path for the bind mount, and must not
    # rewrite the container-side paths
    HOST_CERTS_DIR="$(pwd -W 2>/dev/null || pwd)"
    MSYS_NO_PATHCONV=1 docker run --rm \
        --user "$(id -u):$(id -g)" \
        --mount "type=bind,source=$HOST_CERTS_DIR,target=/out" \
        pqc_api_keygen pqc_api --generate-mldsa-key /out/mldsa_server.key
    echo "      ✓ mldsa_server.key"
fi

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo "[+] Verifying chain..."
openssl verify -CAfile ca.crt server.crt && echo "      ✓ Chain OK"

# Cleanup
rm -f server.csr ca.srl ocsp_ext.cnf

echo ""
echo "════════════════════════════════════════════"
echo "  Files in $CERTS_DIR:"
echo "  ca.key            ← keep secret (also used by the OCSP responder)"
echo "  ca.crt            ← loaded by server + OCSP"
echo "  server.key        ← loaded by Drogon"
echo "  server.crt        ← loaded by Drogon"
echo "  index.txt         ← OCSP revocation DB"
echo "  mldsa_server.key  ← ML-DSA-65 document signing key"
echo ""
echo "  Next: set JWT_SECRET in .env, then docker compose up --build"
echo "════════════════════════════════════════════"

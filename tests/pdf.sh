#!/bin/bash
# Simple ML-DSA PDF sign & verify script

set -e

BASE="https://localhost:8443"
CA="../certs/ca.crt"
USERNAME="paulsiv"
PASSWORD="paulsiv123"
PDF="$1"

if [ ! -f "$PDF" ]; then
    echo "Error: PDF not found at $PDF"
    echo "Usage: ./sign_and_verify.sh <path-to-pdf>"
    exit 1
fi

echo "=== PQC Document Sign & Verify ==="
echo "PDF: $PDF"
echo ""

# ----- Login -----------------------------------------------------------
#
echo "[1/4] Logging in..."
TOKEN=$(curl -s --cacert "$CA" -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" \
    | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "[-] Error: Login failed"
    exit 1
fi
echo "[+] Token: ${TOKEN:0:20}..."

# ---- Sign the PDF ------------------------------------------------
echo ""
echo "[2/4] Signing PDF with ML-DSA"
SIGN_RESPONSE=$(curl -s --cacert "$CA" -X POST "$BASE/api/documents/sign" -H "Authorization: Bearer $TOKEN"  -F "file=@$PDF")

echo " [*]  Response: $SIGN_RESPONSE" | head -c 200
echo ""

SIGNATURE=$(echo "$SIGN_RESPONSE" | grep -o '"signature":"[^"]*"' | cut -d'"' -f4)
DOC_ID=$(echo "$SIGN_RESPONSE" | grep -o '"doc_id":[0-9]*' | cut -d':' -f2)

if [ -z "$SIGNATURE" ]; then
    echo "[-] Error: No signature in response"
    exit 1
fi
echo "[+] Doc ID:    $DOC_ID"
echo "[+] Signature: ${SIGNATURE:0:40}..."

# ------ PK --------------------------------------------------------------------
echo ""
echo "[3/4] Fetching ML-DSA public key"
PUBLIC_KEY=$(curl -s --cacert "$CA" "$BASE/api/documents/public-key" -H "Authorization: Bearer $TOKEN" \
    | grep -o '"public_key_pem":"[^"]*"' | cut -d'"' -f4 \
    | sed 's/\\n/\n/g')

if [ -z "$PUBLIC_KEY" ]; then
    echo "[-] Error: Could not fetch public key"
    exit 1
fi
echo "  $(echo "$PUBLIC_KEY" | head -3)"
echo "  ..."

# ------------ ver -------------------------------------------------
echo ""
echo "[4/4] Verifying signature"
VERIFY_RESPONSE=$(curl -s --cacert "$CA" -X POST "$BASE/api/documents/verify" \
    -H "Authorization: Bearer $TOKEN" \
    -F "pdf=@$PDF" \
    -F "signature=$SIGNATURE" \
    -F "public_key=$PUBLIC_KEY")

echo "[*]  Response: $VERIFY_RESPONSE"
echo ""

# Result ----------------------------------------------------------------------

if echo "$VERIFY_RESPONSE" | grep -q '"valid":true\|"status":"VALID"'; then
    echo "[+] Signature VALID — document is authentic"
else
    echo "[-] Signature INVALID or verification failed"
fi

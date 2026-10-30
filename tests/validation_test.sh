#!/usr/bin/env bash
# ------------------------------------------------------------------------------
#  Input-validation and error-handling test suite
#
#  Sends malformed, incomplete or out-of-range requests to the running API and
#  checks that each one is rejected with the documented error code instead of
#  being processed or crashing the server. Writes:
#     results/validation_tests.csv   (one row per test)
#     results/validation_tests.md    (table ready to paste into the thesis)
#
#  Usage (from the tests/ folder, with the stack running):
#     ./validation_tests.sh
#  Optional environment variables:
#     BASE=https://localhost:8443  CA=../certs/ca.crt  PDF=sample.pdf
#     CURVES=X25519MLKEM768   (default forces the hybrid group; needs curl built
#                              on OpenSSL 3.5+; set CURVES= to let curl choose)
# ------------------------------------------------------------------------------
set -u

BASE="${BASE:-https://localhost:8443}"
CA="${CA:-../certs/ca.crt}"
PDF="${PDF:-sample.pdf}"
CURVES="${CURVES-X25519MLKEM768}"
CURVE_ARGS=(); [ -n "$CURVES" ] && CURVE_ARGS=(--curves "$CURVES")

OUT_DIR="results"; mkdir -p "$OUT_DIR"
CSV="$OUT_DIR/validation_tests.csv"; MD="$OUT_DIR/validation_tests.md"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
RUN="$(date +%s)$RANDOM"
PASS_COUNT=0; FAIL_COUNT=0; ROWS=()

for f in "$CA" "$PDF"; do
    [ -f "$f" ] || { echo "Missing file: $f"; exit 1; }
done

# ── helpers ───────────────────────────────────────────────────────────────────
req() {  # req METHOD PATH [curl args...] -> sets $CODE and $BODY
    local method="$1" path="$2"; shift 2
    : > "$TMP/body"
    CODE=$(curl -s ${CURVE_ARGS[@]+"${CURVE_ARGS[@]}"} --cacert "$CA" -o "$TMP/body" \
           -w '%{http_code}' -X "$method" "$BASE$path" "$@")
    BODY=$(tr -d '\0' < "$TMP/body" 2>/dev/null)
}
json_field() { echo "$1" | grep -o "\"$2\": *\"[^\"]*\"" | head -1 | sed 's/^"[^"]*": *"//; s/"$//'; }
json_num()   { echo "$1" | grep -o "\"$2\": *[0-9]*" | head -1 | sed 's/.*: *//'; }
record() {  # ID CATEGORY REQ CASE EXPECTED OBSERVED PASS(0/1)
    local status="PASS"; [ "$7" = 1 ] || status="FAIL"
    [ "$status" = PASS ] && PASS_COUNT=$((PASS_COUNT+1)) || FAIL_COUNT=$((FAIL_COUNT+1))
    ROWS+=("$1|$2|$3|$4|$5|$6|$status")
    printf '%-4s %-4s %s\n' "$1" "$status" "$4"
}
expect_code() {  # ID CATEGORY REQ CASE EXPECTED_CODE
    local ok=0; [ "$CODE" = "$5" ] && ok=1
    local msg; msg=$(json_field "$BODY" error)
    record "$1" "$2" "$3" "$4" "HTTP $5" "HTTP $CODE${msg:+ (\"$msg\")}" "$ok"
}
JSON=(-H 'Content-Type: application/json')

echo "=== Input-validation and error-handling tests against $BASE ==="
echo "Key exchange: ${CURVES:-curl default}  ($(curl --version | head -1 | grep -o 'OpenSSL/[0-9.]*'))"

req GET /health
if [ "$CODE" = 000 ]; then
    echo "Cannot complete a TLS handshake with ${CURVES:-the default groups}."
    [ -n "$CURVES" ] && echo "Your curl/OpenSSL probably does not support $CURVES (needs OpenSSL 3.5+). Run the script in a newer container, or set CURVES= to let curl choose."
    exit 1
fi

# ── setup: one user with one signed document ─────────────────────────────────
U="val_$RUN"; PW="Passw0rd!$RUN"
req POST /api/auth/register "${JSON[@]}" -d "{\"username\":\"$U\",\"password\":\"$PW\"}"
[ "$CODE" = 201 ] || { echo "Setup failed: register (HTTP $CODE: $BODY)"; exit 1; }
req POST /api/auth/login "${JSON[@]}" -d "{\"username\":\"$U\",\"password\":\"$PW\"}"
TK=$(json_field "$BODY" token); [ -n "$TK" ] || { echo "Setup failed: login"; exit 1; }
AUTH=(-H "Authorization: Bearer $TK")
req POST /api/documents/sign "${AUTH[@]}" -F "file=@$PDF"
SIG=$(json_field "$BODY" signature); [ -n "$SIG" ] || { echo "Setup failed: signing"; exit 1; }
req GET /api/documents/public-key
json_field "$BODY" public_key_pem | sed 's/\\n/\n/g' > "$TMP/pk.pem"
grep -q "BEGIN PUBLIC KEY" "$TMP/pk.pem" || { echo "Setup failed: public key"; exit 1; }
MISSING_ID=999999999

# ── Registration and login input ─────────────────────────────────────────────
req POST /api/auth/register "${JSON[@]}" -d "{\"username\":\"short_$RUN\",\"password\":\"Abc123!\"}"
expect_code V01 "Input validation" FR-01 "Register with a 7-character password" 400

req POST /api/auth/register "${JSON[@]}" -d "{\"username\":\"edge_$RUN\",\"password\":\"Abc1234!\"}"
expect_code V02 "Input validation" FR-01 "Register with an 8-character password (boundary, control)" 201

req POST /api/auth/register "${JSON[@]}" -d "{\"username\":\"\",\"password\":\"$PW\"}"
expect_code V03 "Input validation" FR-01 "Register with an empty username" 400

req POST /api/auth/register "${JSON[@]}" -d '{"username":"broken", "password":'
expect_code V04 "Malformed request" FR-01 "Register with malformed JSON" 400

req POST /api/auth/login "${JSON[@]}" -d '{"username":"broken", "password":'
expect_code V05 "Malformed request" FR-02 "Log in with malformed JSON" 400

req POST /api/auth/login "${JSON[@]}" -d '{}'
expect_code V06 "Input validation" FR-04 "Log in with no username or password" 401

req POST /api/auth/login "${JSON[@]}" -d "{\"username\":\"$U\",\"password\":\"wrong-$RUN\"}"
expect_code V07 "Error handling" FR-04 "Log in with a wrong password" 401

# ── Document upload ──────────────────────────────────────────────────────────
req POST /api/documents/sign "${AUTH[@]}" "${JSON[@]}" -d '{"file":"not multipart"}'
expect_code V08 "Malformed request" FR-11 "Sign with a JSON body instead of multipart/form-data" 400

req POST /api/documents/sign "${AUTH[@]}" -F "note=no file attached"
expect_code V09 "Input validation" FR-11 "Sign with a multipart request that has no file" 400

: > "$TMP/empty.pdf"
req POST /api/documents/sign "${AUTH[@]}" -F "file=@$TMP/empty.pdf"
expect_code V10 "Input validation" FR-11 "Sign an empty (0-byte) file" 400

echo "This is a plain text file, not a PDF." > "$TMP/notes.txt"
req POST /api/documents/sign "${AUTH[@]}" -F "file=@$TMP/notes.txt;type=text/plain"
expect_code V11 "Input validation" FR-11 "Sign a non-PDF file (plain text)" 415

# ── Nonexistent resources ────────────────────────────────────────────────────
req GET "/api/documents/$MISSING_ID/download" "${AUTH[@]}"
expect_code V12 "Error handling" FR-13 "Download a document ID that does not exist" 404

req POST "/api/documents/$MISSING_ID/verify" "${AUTH[@]}"
expect_code V13 "Error handling" FR-14 "Verify a stored document ID that does not exist" 404

req DELETE "/api/documents/$MISSING_ID" "${AUTH[@]}"
expect_code V14 "Error handling" FR-13 "Delete a document ID that does not exist" 404

# ── External verification input ──────────────────────────────────────────────
req POST /api/documents/verify "${AUTH[@]}" -F "signature=$SIG" -F "public_key=<$TMP/pk.pem"
expect_code V15 "Input validation" FR-14 "Verify with the PDF field missing" 400

req POST /api/documents/verify "${AUTH[@]}" -F "pdf=@$PDF" -F "public_key=<$TMP/pk.pem"
expect_code V16 "Input validation" FR-14 "Verify with the signature field missing" 400

req POST /api/documents/verify "${AUTH[@]}" -F "pdf=@$PDF" -F "signature=$SIG"
expect_code V17 "Input validation" FR-14 "Verify with the public key field missing" 400

req POST /api/documents/verify "${AUTH[@]}" -F "pdf=@$PDF" -F "signature=!!!not-base64!!!" -F "public_key=<$TMP/pk.pem"
expect_code V18 "Input validation" FR-14 "Verify with a signature that is not valid base64" 400

req POST /api/documents/verify "${AUTH[@]}" -F "pdf=@$PDF" -F "signature=$SIG" -F "public_key=this is not a PEM key"
expect_code V19 "Input validation" FR-14 "Verify with a public key that is not valid PEM" 400

req POST /api/documents/verify "${AUTH[@]}" "${JSON[@]}" -d '{"pdf":"x"}'
expect_code V20 "Malformed request" FR-14 "Verify with a JSON body instead of multipart/form-data" 400

# ── Server still healthy after all malformed input ───────────────────────────
req GET /api/users/me "${AUTH[@]}"
expect_code V21 "Error handling" "—" "API still responds normally after the malformed requests (control)" 200

# ── output ───────────────────────────────────────────────────────────────────
{
    echo "ID,Category,Requirement,Case,Expected,Observed,Result"
    for r in "${ROWS[@]}"; do echo "$r" | awk -F'|' '{for(i=1;i<=NF;i++){gsub(/"/,"\"\"",$i); printf "\"%s\"%s",$i,(i<NF?",":"\n")}}'; done
} > "$CSV"
{
    echo "| ID | Category | Requirement | Case | Expected | Observed | Result |"
    echo "|---|---|---|---|---|---|---|"
    for r in "${ROWS[@]}"; do echo "| ${r//|/ | } |"; done
} > "$MD"

echo
echo "Passed: $PASS_COUNT  Failed: $FAIL_COUNT"
echo "Results written to $CSV and $MD"
[ "$FAIL_COUNT" = 0 ]

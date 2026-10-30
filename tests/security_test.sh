#!/usr/bin/env bash
# ------------------------------------------------------------------------------
#  Security controls test suite (OWASP Top 10:2025, Section 10.16)
#
#  Sends deliberately malicious or unauthorized requests to the running API and
#  checks that each control described in Section 10.16 rejects them. Every test
#  records the expected and the observed result, and the script writes:
#     results/security_tests.csv   (one row per test)
#     results/security_tests.md    (table ready to paste into the thesis)
#
#  Usage (from the tests/ folder, with the stack running):
#     ./security_tests.sh
#  Optional environment variables:
#     BASE=https://localhost:8443  CA=../certs/ca.crt
#     ADMIN_USER=paulsiv ADMIN_PASS=paulsiv123   (positive admin check)
#     PDF=sample.pdf
#     CURVES=X25519MLKEM768   (key-exchange group curl must use; default forces
#                              the hybrid group, needs curl built on OpenSSL 3.5+;
#                              set CURVES= to let curl choose)
# ------------------------------------------------------------------------------
set -u

BASE="${BASE:-https://localhost:8443}"
CA="${CA:-../certs/ca.crt}"
PDF="${PDF:-sample.pdf}"
ADMIN_USER="${ADMIN_USER:-paulsiv}"
ADMIN_PASS="${ADMIN_PASS:-paulsiv123}"
PG_CONTAINER="${PG_CONTAINER:-pqc_postgres}"
CURVES="${CURVES-X25519MLKEM768}"
CURVE_ARGS=(); [ -n "$CURVES" ] && CURVE_ARGS=(--curves "$CURVES")

OUT_DIR="results"; mkdir -p "$OUT_DIR"
CSV="$OUT_DIR/security_tests.csv"; MD="$OUT_DIR/security_tests.md"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
RUN="$(date +%s)$RANDOM"
PASS_COUNT=0; FAIL_COUNT=0; ROWS=()

for f in "$CA" "$PDF"; do
    [ -f "$f" ] || { echo "Missing file: $f"; exit 1; }
done

# ── helpers ───────────────────────────────────────────────────────────────────
# req METHOD PATH [curl args...] -> sets $CODE and $BODY
req() {
    local method="$1" path="$2"; shift 2
    : > "$TMP/body"
    CODE=$(curl -s ${CURVE_ARGS[@]+"${CURVE_ARGS[@]}"} --cacert "$CA" -o "$TMP/body" -w '%{http_code}' -X "$method" "$BASE$path" "$@")
    BODY=$(tr -d '\0' < "$TMP/body" 2>/dev/null)   # strip NULs (PDF downloads)
}
# tolerate optional whitespace after ':' so the parsing does not depend on the JSON formatter
json_field() { echo "$1" | grep -o "\"$2\": *\"[^\"]*\"" | head -1 | sed 's/^"[^"]*": *"//; s/"$//'; }
json_num()   { echo "$1" | grep -o "\"$2\": *[0-9]*" | head -1 | sed 's/.*: *//'; }
json_bool()  { echo "$1" | grep -o "\"$2\": *[a-z]*" | head -1 | sed 's/.*: *//'; }
b64url_enc() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
b64url_dec() {
    local s; s=$(echo -n "$1" | tr '_-' '/+')
    case $(( ${#s} % 4 )) in 2) s="$s==";; 3) s="$s=";; esac
    echo -n "$s" | openssl base64 -d -A
}
login() {  # login USER PASS -> sets $TOKEN, $CODE, $BODY (no subshell, so CODE/BODY survive)
    req POST /api/auth/login -H 'Content-Type: application/json' \
        -d "{\"username\":\"$1\",\"password\":\"$2\"}"
    TOKEN=$(json_field "$BODY" token)
}
# record ID OWASP CONTROL ATTACK EXPECTED OBSERVED PASS(0/1)
record() {
    local status="PASS"; [ "$7" = 1 ] || status="FAIL"
    [ "$status" = PASS ] && PASS_COUNT=$((PASS_COUNT+1)) || FAIL_COUNT=$((FAIL_COUNT+1))
    ROWS+=("$1|$2|$3|$4|$5|$6|$status")
    printf '%-4s %-5s %-4s %s\n' "$1" "$2" "$status" "$4"
}
expect_code() {  # ID OWASP CONTROL ATTACK EXPECTED_CODE
    local ok=0; [ "$CODE" = "$5" ] && ok=1
    record "$1" "$2" "$3" "$4" "HTTP $5" "HTTP $CODE" "$ok"
}

echo "=== Security controls test suite against $BASE ==="
echo "Key exchange: ${CURVES:-curl default}  ($(curl --version | head -1 | grep -o 'OpenSSL/[0-9.]*'))"

# ── preflight: the TLS handshake with the requested group must succeed ───────
req GET /health
if [ "$CODE" = 000 ]; then
    echo "Cannot complete a TLS handshake with ${CURVES:-the default groups}."
    [ -n "$CURVES" ] && echo "Your curl/OpenSSL probably does not support $CURVES (needs OpenSSL 3.5+). Run the script in a newer container, or set CURVES= to let curl choose."
    exit 1
fi

# ── setup: two ordinary users A and B ────────────────────────────────────────
UA="sec_a_$RUN"; UB="sec_b_$RUN"; PW="Passw0rd!$RUN"
for u in "$UA" "$UB"; do
    req POST /api/auth/register -H 'Content-Type: application/json' \
        -d "{\"username\":\"$u\",\"password\":\"$PW\"}"
    [ "$CODE" = 201 ] || { echo "Setup failed: could not register $u (HTTP $CODE: $BODY)"; exit 1; }
done
login "$UA" "$PW"; TA=$TOKEN; IDA=$(json_field "$BODY" user_id)
login "$UB" "$PW"; TB=$TOKEN; IDB=$(json_field "$BODY" user_id)
[ -n "$TA" ] && [ -n "$TB" ] || { echo "Setup failed: login"; exit 1; }

req POST /api/documents/sign -H "Authorization: Bearer $TA" -F "file=@$PDF"
DOC_A=$(json_num "$BODY" doc_id); SIG_A=$(json_field "$BODY" signature)
[ -n "$DOC_A" ] || { echo "Setup failed: signing (HTTP $CODE)"; exit 1; }
req GET /api/documents/public-key
json_field "$BODY" public_key_pem | sed 's/\\n/\n/g' > "$TMP/server_pk.pem"
grep -q "BEGIN PUBLIC KEY" "$TMP/server_pk.pem" || { echo "Setup failed: could not fetch the server public key"; exit 1; }

# ── A05 Injection ────────────────────────────────────────────────────────────
req POST /api/auth/login -H 'Content-Type: application/json' \
    -d "{\"username\":\"' OR '1'='1' --\",\"password\":\"x\"}"
expect_code T01 A05 "Parameterized SQL" "SQL injection in login username (' OR '1'='1' --)" 401

SQLI_USER="sqli_${RUN}'); DROP TABLE users; --"
req POST /api/auth/register -H 'Content-Type: application/json' \
    -d "{\"username\":\"$SQLI_USER\",\"password\":\"$PW\"}"
expect_code T02 A05 "Parameterized SQL" "Register username containing '); DROP TABLE users; --" 201

login "$SQLI_USER" "$PW"; T=$TOKEN
ok=0; [ "$CODE" = 200 ] && [ -n "$T" ] && ok=1
record T03 A05 "Parameterized SQL" "Log in with that username (stored as literal data)" "HTTP 200" "HTTP $CODE" "$ok"

login "$UA" "$PW"
ok=0; [ "$CODE" = 200 ] && ok=1
record T04 A05 "Parameterized SQL" "Users table intact after T02 (existing user logs in)" "HTTP 200" "HTTP $CODE" "$ok"

# ── A07 Token and session management ─────────────────────────────────────────
req GET /api/users/me
expect_code T05 A07 "Token required" "Protected endpoint without Authorization header" 401

H=$(echo "$TA" | cut -d. -f1); P=$(echo "$TA" | cut -d. -f2); S=$(echo "$TA" | cut -d. -f3)
NONE_H=$(echo -n '{"alg":"none","typ":"JWT"}' | b64url_enc)
req GET /api/users/me -H "Authorization: Bearer $NONE_H.$P."
expect_code T06 A07 "HS256 enforced" "Token with alg=none and no signature" 401

FORGED_P=$(b64url_dec "$P" | sed "s/\"sub\":\"$IDA\"/\"sub\":\"$IDB\"/" | b64url_enc)
req GET /api/users/me -H "Authorization: Bearer $H.$FORGED_P.$S"
expect_code T07 A07 "HMAC verification" "Payload changed to another user's id, original signature kept" 401

first=${S:0:1}; [ "$first" = A ] && repl=B || repl=A   # change the first char: it carries no padding bits
req GET /api/users/me -H "Authorization: Bearer $H.$P.$repl${S:1}"
expect_code T08 A07 "HMAC verification" "Signature altered by one character" 401

req GET /api/users/me -H "Authorization: Bearer $TA"
expect_code T09 A07 "Control" "Valid token accepted (control)" 200

login "$UA" "$PW"; TL=$TOKEN
req POST /api/users/logout -H "Authorization: Bearer $TL"
req GET /api/users/me -H "Authorization: Bearer $TL"
expect_code T10 A07 "Session revocation" "Token reused after logout" 401

# ── A01 Authorization and access control ──────────────────────────────────────
req GET "/api/documents/$DOC_A/download" -H "Authorization: Bearer $TB"
expect_code T11 A01 "Ownership check" "User B downloads user A's document" 404

req POST "/api/documents/$DOC_A/verify" -H "Authorization: Bearer $TB"
expect_code T12 A01 "Ownership check" "User B verifies user A's stored document" 404

req DELETE "/api/documents/$DOC_A" -H "Authorization: Bearer $TB"
expect_code T13 A01 "Ownership check" "User B deletes user A's document" 404

req GET /api/documents -H "Authorization: Bearer $TB"
ok=0; echo "$BODY" | grep -q "\"id\": *$DOC_A[,}]" || ok=1
record T14 A01 "Ownership check" "User B's document list excludes user A's document" "not listed" "$([ $ok = 1 ] && echo 'not listed' || echo 'listed')" "$ok"

req GET "/api/documents/$DOC_A/download" -H "Authorization: Bearer $TA"
expect_code T15 A01 "Control" "Owner downloads own document (control)" 200

req GET /api/admin/health -H "Authorization: Bearer $TB"
expect_code T16 A01 "Role from database" "Ordinary user calls admin endpoint" 403

req GET /api/admin/health
expect_code T17 A01 "Token required" "Admin endpoint without token" 401

login "$ADMIN_USER" "$ADMIN_PASS"; TADM=$TOKEN
if [ -n "$TADM" ]; then
    req GET /api/admin/health -H "Authorization: Bearer $TADM"
    ok=0; [ "$CODE" = 200 ] || [ "$CODE" = 503 ] && ok=1   # 503 = a component is down, still authorized
    record T18 A01 "Control" "Admin calls admin endpoint (control)" "HTTP 200/503" "HTTP $CODE" "$ok"
fi

# ── A06/A08 Signature verification and key handling ──────────────────────────
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null | openssl pkey -pubout > "$TMP/rsa_pk.pem"
req POST /api/documents/verify -H "Authorization: Bearer $TA" \
    -F "pdf=@$PDF" -F "signature=$SIG_A" -F "public_key=<$TMP/rsa_pk.pem"
expect_code T19 A08 "Key-type check" "External verification with an RSA public key" 400

cp "$PDF" "$TMP/tampered.pdf"; printf ' ' >> "$TMP/tampered.pdf"
req POST /api/documents/verify -H "Authorization: Bearer $TA" \
    -F "pdf=@$TMP/tampered.pdf" -F "signature=$SIG_A" -F "public_key=<$TMP/server_pk.pem"
V=$(json_bool "$BODY" valid); ok=0; [ "$V" = false ] && ok=1
record T20 A08 "ML-DSA verification" "Valid signature on a PDF with one byte appended" "valid=false" "HTTP $CODE, valid=$V" "$ok"

req POST /api/documents/verify -H "Authorization: Bearer $TA" \
    -F "pdf=@$PDF" -F "signature=$SIG_A" -F "public_key=<$TMP/server_pk.pem"
V=$(json_bool "$BODY" valid); K=$(json_bool "$BODY" server_key); ok=0; [ "$V" = true ] && [ "$K" = true ] && ok=1
record T21 A08 "Control" "Genuine PDF, signature and server key (control)" "valid=true, server_key=true" "HTTP $CODE, valid=$V, server_key=$K" "$ok"

# ── A06 Credential storage ───────────────────────────────────────────────────
if command -v docker >/dev/null 2>&1 && docker ps --format "{{.Names}}" 2>/dev/null | grep -q "^$PG_CONTAINER$"; then
    HASH=$(docker exec "$PG_CONTAINER" psql -U pqcuser -d pqcapi -tAc \
        "SELECT password_hash FROM users WHERE username='$UA'" 2>/dev/null)
    ok=0; [[ "$HASH" == \$argon2id\$* ]] && ok=1
    record T22 A06 "Argon2id storage" "Stored password is an Argon2id hash, not plaintext" "\$argon2id\$..." "${HASH:0:30}..." "$ok"
else
    echo "T22 skipped: container $PG_CONTAINER not reachable"
fi

# ── Known limitation (informational, not counted) ────────────────────────────
req POST /api/auth/register -H 'Content-Type: application/json' \
    -d "{\"username\":\"$UA\",\"password\":\"$PW\"}"
INFO_MSG="$(json_field "$BODY" error)"; [ -n "$INFO_MSG" ] || INFO_MSG="$BODY"

# ── output ───────────────────────────────────────────────────────────────────
{
    echo "ID,OWASP,Control,Attack,Expected,Observed,Result"
    for r in "${ROWS[@]}"; do echo "$r" | awk -F'|' '{for(i=1;i<=NF;i++){gsub(/"/,"\"\"",$i); printf "\"%s\"%s",$i,(i<NF?",":"\n")}}'; done
} > "$CSV"
{
    echo "| ID | OWASP | Control | Attack | Expected | Observed | Result |"
    echo "|---|---|---|---|---|---|---|"
    for r in "${ROWS[@]}"; do echo "| ${r//|/ | } |"; done
    echo
    echo "Known limitation (not counted): registering an existing username returns \"$INFO_MSG\" (HTTP $CODE), which reveals that the account exists. Listed in Future Work."
} > "$MD"

echo
echo "Passed: $PASS_COUNT  Failed: $FAIL_COUNT"
echo "Known limitation: duplicate registration returns \"$INFO_MSG\" (account enumeration)."
echo "Results written to $CSV and $MD"
[ "$FAIL_COUNT" = 0 ]

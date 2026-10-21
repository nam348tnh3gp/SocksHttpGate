#!/usr/bin/env bash
# test-doh.sh — Kiểm tra DoH server (RFC 8484)
#
#   ./test-doh.sh                              # dùng URL mặc định
#   ./test-doh.sh https://example.com/dns-query
#   ./test-doh.sh --blocked doubleclick.net     # đổi domain test blocklist
#
# Yêu cầu: curl, openssl (tùy chọn), base64 (có sẵn trên mọi Unix)
# Termux: pkg install curl openssl

set -euo pipefail

# ===== Cấu hình =====
DEFAULT_URL="https://sockshttpgate-dns.onrender.com/dns-query"
URL="${1:-$DEFAULT_URL}"
if [[ "$URL" == --* ]]; then
  URL="$DEFAULT_URL"
else
  shift || true
fi

BLOCKED_DOMAIN="${BLOCKED_DOMAIN:-doubleclick.net}"
NORMAL_DOMAIN="${NORMAL_DOMAIN:-example.com}"

# Colors (tắt nếu không phải terminal)
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
  CYAN=$'\033[0;36m'; NC=$'\033[0m'; BOLD=$'\033[1m'
else
  RED=""; GREEN=""; YELLOW=""; CYAN=""; NC=""; BOLD=""
fi

ok()   { echo "${GREEN}✓${NC} $*"; }
fail() { echo "${RED}✗${NC} $*"; }
info() { echo "${CYAN}ℹ${NC} $*"; }
warn() { echo "${YELLOW}⚠${NC} $*"; }

# ===== Helpers =====

# DNS wire format query (A record) — build với python3 hoặc perl (portable)
build_dns_query() {
  local domain="$1"
  local qname=""
  IFS='.' read -ra labels <<< "$domain"
  for label in "${labels[@]}"; do
    qname+=$(printf '\\x%02x' "${#label}")
    qname+="$label"
  done
  qname+='\x00'
  # Transaction ID: 0x1234, flags: 0x0100 (RD), QDCOUNT=1
  printf "\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00${qname}\\x00\\x01\\x00\\x01"
}

# Tạo file query tạm
make_query_file() {
  local domain="$1"
  local out="$2"
  build_dns_query "$domain" > "$out"
}

# Parse DNS response header (byte 3 = RCODE)
dns_rcode() {
  local file="$1"
  local b
  b=$(od -An -tu1 -j3 -N1 "$file" 2>/dev/null | tr -d ' ')
  if [[ -z "$b" ]]; then echo -1; return; fi
  echo $(( b & 0x0F ))
}

dns_rcode_name() {
  case "$1" in
    0) echo "NOERROR" ;;
    1) echo "FORMERR" ;;
    2) echo "SERVFAIL" ;;
    3) echo "NXDOMAIN" ;;
    4) echo "NOTIMP" ;;
    5) echo "REFUSED" ;;
    *) echo "RCODE=$1" ;;
  esac
}

# Kiểm tra HTTP status code và Content-Type
check_doh_response() {
  local method="$1"
  local domain="$2"
  local http_code="$3"
  local content_type="$4"
  local out_file="$5"

  if [[ "$http_code" != "200" ]]; then
    fail "$method $domain → HTTP $http_code"
    return 1
  fi

  if [[ ! "$content_type" =~ application/dns-message ]]; then
    fail "$method $domain → Content-Type sai: '$content_type'"
    return 1
  fi

  local size
  size=$(wc -c < "$out_file")
  if [[ "$size" -lt 12 ]]; then
    fail "$method $domain → response quá ngắn ($size bytes)"
    return 1
  fi

  local rcode
  rcode=$(dns_rcode "$out_file")
  local name
  name=$(dns_rcode_name "$rcode")

  if [[ "$rcode" -eq 0 ]]; then
    ok "$method $domain → $name ($size bytes)"
    return 0
  elif [[ "$rcode" -eq 3 ]]; then
    warn "$method $domain → $name (blocked hoặc không tồn tại)"
    return 0
  else
    fail "$method $domain → $name (rcode=$rcode)"
    return 1
  fi
}

# ===== Tests =====

test_health() {
  info "Test health endpoint (tùy chọn, có thể 404)..."
  local hc
  hc=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${URL%/dns-query}/health" 2>/dev/null || echo "000")
  if [[ "$hc" == "200" ]]; then
    ok "Health: HTTP 200"
  elif [[ "$hc" == "404" ]]; then
    info "Health: không có endpoint /healthz (bỏ qua)"
  else
    warn "Health: HTTP $hc (không bắt buộc)"
  fi
}

test_doh_post() {
  local domain="$1"
  info "Test POST DoH cho $domain..."

  local qfile
  qfile=$(mktemp)
  make_query_file "$domain" "$qfile"

  local resp_file
  resp_file=$(mktemp)

  local headers_file
  headers_file=$(mktemp)

  local http_code
  http_code=$(curl -sk --max-time 10 \
    -X POST \
    -H "Content-Type: application/dns-message" \
    -H "Accept: application/dns-message" \
    --data-binary "@$qfile" \
    -D "$headers_file" \
    -o "$resp_file" \
    -w "%{http_code}" \
    "$URL" 2>/dev/null || echo "000")

  local content_type
  content_type=$(grep -i '^content-type:' "$headers_file" 2>/dev/null | head -1 | sed 's/^[^:]*: *//I' | tr -d '\r\n' || echo "")

  local result=0
  check_doh_response "POST" "$domain" "$http_code" "$content_type" "$resp_file" || result=1

  rm -f "$qfile" "$resp_file" "$headers_file"
  return $result
}

test_doh_get() {
  local domain="$1"
  info "Test GET DoH cho $domain..."

  local qfile
  qfile=$(mktemp)
  make_query_file "$domain" "$qfile"

  local b64
  b64=$(base64 -w0 < "$qfile" | tr '+/' '-_' | tr -d '=')
  rm -f "$qfile"

  local resp_file
  resp_file=$(mktemp)

  local headers_file
  headers_file=$(mktemp)

  local http_code
  http_code=$(curl -sk --max-time 10 \
    -H "Accept: application/dns-message" \
    -D "$headers_file" \
    -o "$resp_file" \
    -w "%{http_code}" \
    "${URL}?dns=${b64}" 2>/dev/null || echo "000")

  local content_type
  content_type=$(grep -i '^content-type:' "$headers_file" 2>/dev/null | head -1 | sed 's/^[^:]*: *//I' | tr -d '\r\n' || echo "")

  local result=0
  check_doh_response "GET " "$domain" "$http_code" "$content_type" "$resp_file" || result=1

  rm -f "$resp_file" "$headers_file"
  return $result
}

test_blocked() {
  local domain="$1"
  info "Test blocklist cho $domain (kỳ vọng NXDOMAIN hoặc không có A record)..."

  local qfile
  qfile=$(mktemp)
  make_query_file "$domain" "$qfile"

  local resp_file
  resp_file=$(mktemp)

  local http_code
  http_code=$(curl -sk --max-time 10 \
    -X POST \
    -H "Content-Type: application/dns-message" \
    -H "Accept: application/dns-message" \
    --data-binary "@$qfile" \
    -o "$resp_file" \
    -w "%{http_code}" \
    "$URL" 2>/dev/null || echo "000")

  if [[ "$http_code" != "200" ]]; then
    fail "Blocked test $domain → HTTP $http_code"
    rm -f "$qfile" "$resp_file"
    return 1
  fi

  local rcode
  rcode=$(dns_rcode "$resp_file")
  local name
  name=$(dns_rcode_name "$rcode")

  # Đếm answer records (bytes 6-7 trong header)
  local ancount
  ancount=$(od -An -tu1 -j6 -N2 "$resp_file" 2>/dev/null | awk '{print $1*256+$2}')

  if [[ "$rcode" -eq 3 ]]; then
    ok "Blocked $domain → NXDOMAIN (blocklist hoạt động)"
  elif [[ "$ancount" -eq 0 ]]; then
    ok "Blocked $domain → $name với 0 answer (blocklist hoạt động)"
  else
    warn "Blocked $domain → $name với $ancount answer (có thể chưa chặn hoặc domain không có trong list)"
  fi

  rm -f "$qfile" "$resp_file"
  return 0
}

test_content_type_validation() {
  info "Test validation Content-Type (kỳ vọng 4xx khi gửi sai)..."

  local qfile
  qfile=$(mktemp)
  make_query_file "example.com" "$qfile"

  local http_code
  http_code=$(curl -sk --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    --data-binary "@$qfile" \
    -o /dev/null \
    -w "%{http_code}" \
    "$URL" 2>/dev/null || echo "000")

  if [[ "$http_code" == "4"* ]] || [[ "$http_code" == "5"* ]]; then
    ok "Sai Content-Type → HTTP $http_code (đúng behavior)"
  else
    warn "Sai Content-Type → HTTP $http_code (server không validate?)"
  fi

  rm -f "$qfile"
}

# ===== Main =====

echo ""
echo "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo "${BOLD}  DoH Test — $URL${NC}"
echo "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Kiểm tra dependencies
for cmd in curl base64 od; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    fail "Thiếu command: $cmd"
    exit 1
  fi
done

PASS=0
FAIL=0

# Chạy tests (không exit ngay nếu fail — tổng hợp cuối)
test_health || true

echo ""
if test_doh_post "$NORMAL_DOMAIN"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

echo ""
if test_doh_get "$NORMAL_DOMAIN"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

echo ""
if test_blocked "$BLOCKED_DOMAIN"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

echo ""
test_content_type_validation || true

echo ""
echo "${BOLD}═══════════════════════════════════════════════════════════${NC}"
if [[ "$FAIL" -eq 0 ]]; then
  echo "${GREEN}${BOLD}  ✓ PASS: $PASS/$((PASS+FAIL)) tests${NC}"
  exit 0
else
  echo "${RED}${BOLD}  ✗ FAIL: $FAIL/$((PASS+FAIL)) tests failed${NC}"
  exit 1
fi

#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

# Local-only ODoH interoperability test harness for Termux.
# Uses an archived Cloudflare reference implementation as an upstream test fixture.
# DO NOT expose this legacy test server to a network or use it in production.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$ROOT/.work"
SERVER="$WORK/odoh-server-go"
CLIENT="$WORK/odoh-client-go"
PORT="${PORT:-4567}"
DOMAIN="${DOMAIN:-example.com}"
TYPE="${TYPE:-A}"
LOG="$WORK/server.log"

say() { printf '\n[ODoH-Test] %s\n' "$*"; }
die() { printf '\n[ODoH-Test] ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Thiếu lệnh '$1'. Cài bằng: pkg install $2"; }

need pkg pkg
need git git
need go golang
need openssl openssl
need curl curl

if [[ "${ALLOW_LEGACY_REFERENCE:-}" != "YES" ]]; then
  die "Đây là server tham chiếu cũ có cảnh báo SSRF. Chỉ thử nghiệm local; đọc README.md rồi chạy với ALLOW_LEGACY_REFERENCE=YES nếu chấp nhận rủi ro."
fi

mkdir -p "$WORK"
cd "$WORK"

if [[ ! -d "$SERVER/.git" ]]; then
  say "Tải mã tham chiếu ODoH server..."
  git clone --depth 1 https://github.com/cloudflare/odoh-server-go.git "$SERVER"
fi
if [[ ! -d "$CLIENT/.git" ]]; then
  say "Tải client kiểm thử ODoH..."
  git clone --depth 1 https://github.com/cloudflare/odoh-client-go.git "$CLIENT"
fi

# This is only a weak source sanity check, NOT a listener-bind verification.
if ! grep -R -nE '127\.0\.0\.1|localhost' "$SERVER" --include='*.go' >/dev/null 2>&1; then
  say "CẢNH BÁO: không tìm thấy chuỗi loopback trong source server. Hãy kiểm tra listener thủ công; không chạy trên mạng không tin cậy."
fi

say "Build server (lần đầu có thể mất vài phút)..."
(
  cd "$SERVER"
  go mod download
  go build -o "$WORK/odoh-server" .
) || die "Build ODoH server thất bại. Xem lỗi Go ở phía trên."

say "Build client..."
(
  cd "$CLIENT"
  go mod download
  go build -o "$WORK/odoh-client" ./cmd/...
) || die "Build ODoH client thất bại. Xem lỗi Go ở phía trên."

cd "$WORK"
if [[ ! -s cert.pem || ! -s key.pem ]]; then
  say "Tạo chứng chỉ TLS tự ký chỉ dùng cho localhost..."
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout key.pem -out cert.pem \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
  chmod 600 key.pem
fi

export SSL_CERT_FILE="$WORK/cert.pem"
export CERT="$WORK/cert.pem"
export KEY="$WORK/key.pem"
export PORT

say "Khởi động ODoH server tham chiếu trên port $PORT..."
"$WORK/odoh-server" >"$LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

ready=0
for _ in $(seq 1 40); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat "$LOG" >&2
    die "Server thoát sớm. Xem log phía trên."
  fi
  if curl -ksS --max-time 1 "https://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.25
done

if [[ "$ready" != 1 ]]; then
  say "Chưa xác nhận được server qua HTTPS. Log server:"
  tail -n 60 "$LOG" >&2 || true
  die "Không tiếp tục vì server chưa sẵn sàng. Không tự tắt xác minh TLS."
fi

say "Chạy truy vấn ODoH kiểm thử: domain=$DOMAIN type=$TYPE"
say "Đang gọi client qua proxy cục bộ và target cục bộ..."
set +e
"$WORK/odoh-client" odoh \
  --proxy "localhost:${PORT}" \
  --target "localhost:${PORT}" \
  --domain "$DOMAIN" \
  --dnstype "$TYPE"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
  say "Client kết thúc thành công. Đây chỉ là smoke test, không phải kiểm toán bảo mật."
else
  say "Client trả mã lỗi $rc. Log server cuối:"
  tail -n 80 "$LOG" >&2 || true
  say "Nếu lỗi do TLS hoặc cờ CLI khác phiên bản, kiểm tra README và help của client."
fi

say "Server log (không được coi là log riêng tư):"
tail -n 30 "$LOG" || true
say "Đã dừng tiến trình khi thoát. Dữ liệu build nằm trong: $WORK"
exit "$rc"

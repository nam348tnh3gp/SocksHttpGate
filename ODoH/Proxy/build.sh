#!/usr/bin/env bash
# build.sh — Build ODoH proxy + lấy chứng chỉ Let's Encrypt qua DuckDNS
# Hỗ trợ: Termux (Android), Debian/Ubuntu, Fedora/RHEL, Arch, macOS
# Không build cryptography/cffi từ source — luôn dùng package manager của OS
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info()  { printf "${BLU}[*]${NC} %s\n" "$*"; }
ok()    { printf "${GRN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YEL}[!]${NC} %s\n" "$*"; }
err()   { printf "${RED}[-]${NC} %s\n" "$*" >&2; }
die()   { err "$*"; exit 1; }

VENV="$HOME/.odoh-venv"
CERTBOT_DIR="$HOME/.certbot"
ENVFILE="$HOME/.odoh-certbot.env"
DUCKDNS_INI="$CERTBOT_DIR/duckdns.ini"
RENEW_THRESHOLD_DAYS=30
RENEW_THRESHOLD_SECS=$((RENEW_THRESHOLD_DAYS * 86400))

# ============ 1. Detect platform ============
detect_platform() {
    if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX:-/nonexistent}" ] && command -v termux-info >/dev/null 2>&1; then
        PLATFORM=termux
    elif [ "$(uname -s)" = "Darwin" ]; then
        PLATFORM=macos
    elif [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
            ubuntu|debian|linuxmint|pop) PLATFORM=debian ;;
            fedora|rhel|centos|rocky|alma|ol) PLATFORM=fedora ;;
            arch|manjaro|endeavouros) PLATFORM=arch ;;
            *) PLATFORM=linux-unknown ;;
        esac
    else
        PLATFORM=unknown
    fi
    ok "Platform: $PLATFORM"
}

# ============ 2. Cài deps từ OS ============
install_deps() {
    local SUDO=""
    case "$PLATFORM" in
        termux)
            info "Cài gói Termux (python-cryptography, dnsutils, proot)..."
            pkg update -y >/dev/null 2>&1 || true
            # python-cryptography tự kéo cffi làm dependency.
            # dnspython KHÔNG có trong kho Termux → cài qua pip ở install_certbot().
            pkg install -y python python-cryptography dnsutils proot openssl
            ;;
        debian)
            command -v sudo >/dev/null && SUDO=sudo
            info "Cài gói apt (python3-cryptography, python3-cffi, python3-openssl)..."
            $SUDO apt-get update -y
            $SUDO apt-get install -y python3 python3-venv python3-pip \
                python3-cryptography python3-cffi python3-openssl python3-dnspython \
                dnsutils openssl
            ;;
        fedora)
            command -v sudo >/dev/null && SUDO=sudo
            info "Cài gói dnf (python3-cryptography, python3-cffi, python3-pyOpenSSL)..."
            $SUDO dnf install -y python3 python3-pip \
                python3-cryptography python3-cffi python3-pyOpenSSL python3-dns \
                bind-utils openssl
            ;;
        arch)
            command -v sudo >/dev/null && SUDO=sudo
            info "Cài gói pacman (python-cryptography, python-cffi, python-pyopenssl)..."
            $SUDO pacman -Sy --noconfirm python python-cryptography python-cffi \
                python-pyopenssl python-dnspython bind openssl
            ;;
        macos)
            info "macOS: cryptography + cffi + pyopenssl sẽ cài qua pip (wheel có sẵn)"
            command -v python3 >/dev/null || die "Cần Python3: brew install python"
            command -v openssl >/dev/null || die "Cần OpenSSL: brew install openssl"
            ;;
        *)
            warn "Platform không xác định — sẽ cài qua pip (có thể build từ source)"
            ;;
    esac
}

# ============ 3. Tạo venv (skip nếu đã có) ============
setup_venv() {
    if [ -x "$VENV/bin/python3" ]; then
        info "Venv đã tồn tại: $VENV (dùng lại)"
    else
        if [ "$PLATFORM" = "macos" ] || [ "$PLATFORM" = "linux-unknown" ] || [ "$PLATFORM" = "unknown" ]; then
            info "Tạo venv thường..."
            python3 -m venv "$VENV"
        else
            info "Tạo venv với --system-site-packages (dùng cryptography/cffi của OS)..."
            python3 -m venv "$VENV" --system-site-packages
        fi
    fi
    # shellcheck disable=SC1091
    source "$VENV/bin/activate"
    pip install --upgrade pip wheel >/dev/null 2>&1 || true
    ok "Venv: $VENV"
}

# ============ 4. Cài certbot không kéo cryptography/cffi từ source ============
install_certbot() {
    info "Cài certbot + plugin DuckDNS (deps có cryptography/cffi → --no-deps)..."

    # Packages CÓ dependency cryptography/cffi → cài --no-deps
    # (runtime lấy cryptography + cffi từ system qua --system-site-packages)
    pip install --no-deps --upgrade \
        certbot certbot-dns-duckdns acme josepy pyopenssl distro

    # Packages thuần Python → cài bình thường
    pip install --upgrade \
        configargparse configobj parsedatetime pyrfc3339 pytz requests setuptools dnspython

    # Verify tất cả import được (fail sớm nếu hệ thống thiếu gói)
    if ! python3 - <<'PY' 2>/dev/null
import sys
import cryptography, cffi, OpenSSL, josepy, acme, certbot, dns.resolver
PY
    then
        err "Một package không load được. Chạy để xem chi tiết:"
        err "  source $VENV/bin/activate && python3 -c 'import OpenSSL'"
        die "certbot dependency verification failed"
    fi

    local CV OV
    CV=$(python3 -c 'import cryptography; print(cryptography.__version__)')
    OV=$(python3 -c 'import OpenSSL; print(OpenSSL.__version__)')
    ok "cryptography=$CV, pyopenssl=$OV (cả 2 load OK)"
}

# ============ 5. Prompt token/domain/email ============
prompt_input() {
    if [ -f "$ENVFILE" ]; then
        info "Tìm thấy config cũ: $ENVFILE"
        # shellcheck disable=SC1090
        source "$ENVFILE"
        read -rp "Dùng lại domain=$DUCKDNS_DOMAIN ? [Y/n] " ans
        case "$ans" in
            n|N) ;;  # prompt lại
            *) return 0 ;;
        esac
    fi

    read -rp  "DuckDNS domain (vd: odohtermux.duckdns.org): " DUCKDNS_DOMAIN
    [ -n "${DUCKDNS_DOMAIN:-}" ] || die "Domain không được rỗng"

    read -rsp "DuckDNS token: " DUCKDNS_TOKEN; echo
    [ -n "${DUCKDNS_TOKEN:-}" ] || die "Token không được rỗng"

    read -rp  "Email (Let's Encrypt): " CERTBOT_EMAIL
    [ -n "${CERTBOT_EMAIL:-}" ] || die "Email không được rỗng"

    umask 077
    cat > "$ENVFILE" <<EOF
DUCKDNS_DOMAIN=$DUCKDNS_DOMAIN
DUCKDNS_TOKEN=$DUCKDNS_TOKEN
CERTBOT_EMAIL=$CERTBOT_EMAIL
EOF
    chmod 600 "$ENVFILE"
    ok "Lưu config: $ENVFILE (chmod 600)"
}

# ============ 6. Check cert hiện có ============
# Return: 0 = còn hạn (>30d), 1 = sắp hết (<30d), 2 = chưa có
check_cert() {
    local CERT="$CERTBOT_DIR/config/live/$DUCKDNS_DOMAIN/fullchain.pem"
    [ -f "$CERT" ] || return 2
    if openssl x509 -in "$CERT" -noout -checkend "$RENEW_THRESHOLD_SECS" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Tính số ngày còn lại bằng binary search qua -checkend (portable mọi OS)
days_left() {
    local CERT="$1"
    [ -f "$CERT" ] || { echo "?"; return; }
    local lo=0 hi=200
    while [ $((hi - lo)) -gt 1 ]; do
        local mid=$(( (lo + hi) / 2 ))
        if openssl x509 -in "$CERT" -noout -checkend $((mid * 86400)) >/dev/null 2>&1; then
            lo=$mid
        else
            hi=$mid
        fi
    done
    echo "$lo"
}

print_cert_info() {
    local CERT="$CERTBOT_DIR/config/live/$DUCKDNS_DOMAIN/fullchain.pem"
    [ -f "$CERT" ] || return 0

    local SUBJECT ISSUER NOTBEFORE NOTAFTER DAYS_LEFT
    SUBJECT=$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | sed 's/^subject=//')
    ISSUER=$(openssl x509 -in "$CERT" -noout -issuer  2>/dev/null | sed 's/^issuer=//')
    NOTBEFORE=$(openssl x509 -in "$CERT" -noout -startdate 2>/dev/null | sed 's/^notBefore=//')
    NOTAFTER=$(openssl x509 -in "$CERT" -noout -enddate   2>/dev/null | sed 's/^notAfter=//')
    DAYS_LEFT=$(days_left "$CERT")

    echo
    info "Thông tin chứng chỉ hiện tại:"
    echo "  Subject:    $SUBJECT"
    echo "  Issuer:     $ISSUER"
    echo "  Not before: $NOTBEFORE"
    echo "  Not after:  $NOTAFTER"
    echo "  Còn hạn:    ${DAYS_LEFT} ngày"
    echo
}

# ============ 7. Chạy certbot (chỉ khi cần) ============
run_certbot() {
    mkdir -p "$CERTBOT_DIR"
    umask 077
    printf 'dns_duckdns_token = %s\n' "$DUCKDNS_TOKEN" > "$DUCKDNS_INI"
    chmod 600 "$DUCKDNS_INI"

    local certbot_args=()

    set +e
    check_cert
    local rc=$?
    set -e

    case "$rc" in
        0)
            ok "Chứng chỉ còn hạn > ${RENEW_THRESHOLD_DAYS} ngày — bỏ qua certbot"
            print_cert_info
            return 0
            ;;
        1)
            warn "Chứng chỉ sắp hết hạn (< ${RENEW_THRESHOLD_DAYS} ngày) — gia hạn"
            print_cert_info
            # KHÔNG dùng --force-renewal — certbot renew tự renew khi <30 ngày,
            # tránh hit rate limit Let's Encrypt (5 cert/domain/tuần)
            certbot_args=(renew)
            ;;
        2)
            info "Chưa có chứng chỉ — cấp mới"
            certbot_args=(certonly)
            ;;
    esac

    local CMD=(
        "$VENV/bin/certbot" "${certbot_args[@]}"
        --config-dir "$CERTBOT_DIR/config"
        --work-dir   "$CERTBOT_DIR/work"
        --logs-dir   "$CERTBOT_DIR/logs"
        --authenticator dns-duckdns
        --dns-duckdns-credentials "$DUCKDNS_INI"
        --dns-duckdns-propagation-seconds 90
        -d "$DUCKDNS_DOMAIN"
        --non-interactive
        --agree-tos
        -m "$CERTBOT_EMAIL"
        --keep-until-expiring
    )

    info "Chạy certbot — chờ ~90s DNS propagate..."
    if [ "$PLATFORM" = "termux" ]; then
        local RESOLV="$PREFIX/etc/resolv.conf"
        if [ ! -f "$RESOLV" ]; then
            info "Tạo $RESOLV..."
            mkdir -p "$PREFIX/etc"
            printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' > "$RESOLV"
        fi
        proot -b "$RESOLV:/etc/resolv.conf" "${CMD[@]}"
    else
        "${CMD[@]}"
    fi

    print_cert_info
}

# ============ 8. Build proxy nếu có main.go ============
build_proxy() {
    if [ -f main.go ] && command -v go >/dev/null 2>&1; then
        info "Build proxy binary..."
        go build -trimpath -ldflags="-s -w" -o odoh-proxy .
        ok "Binary: $(pwd)/odoh-proxy"
    elif [ -f main.go ]; then
        warn "Có main.go nhưng không có Go — bỏ qua build"
    fi
}

# ============ 9. In kết quả ============
show_result() {
    local LIVE="$CERTBOT_DIR/config/live/$DUCKDNS_DOMAIN"
    local CERT="$LIVE/fullchain.pem"
    local KEY="$LIVE/privkey.pem"

    [ -f "$CERT" ] || die "Không tìm thấy cert: $CERT"
    [ -f "$KEY" ]  || die "Không tìm thấy key:  $KEY"

    ok "Chứng chỉ sẵn sàng!"
    echo
    info "Đường dẫn:"
    echo "  TLS_CERT=$CERT"
    echo "  TLS_KEY=$KEY"
    echo
    info "Chạy proxy:"
    cat <<CMD
    TLS_CERT="$CERT" \\
    TLS_KEY="$KEY" \\
    ODOH_TARGET_URL=http://127.0.0.1:8080 \\
    ALLOW_INSECURE_TARGET=YES \\
    PORT=8443 \\
    go run main.go
CMD
    echo
    info "Gia hạn tự động (thêm vào crontab -e):"
    if [ "$PLATFORM" = "termux" ]; then
        echo "  0 3 * * * proot -b $PREFIX/etc/resolv.conf:/etc/resolv.conf $VENV/bin/certbot renew --config-dir $CERTBOT_DIR/config --work-dir $CERTBOT_DIR/work --logs-dir $CERTBOT_DIR/logs --quiet"
    else
        echo "  0 3 * * * $VENV/bin/certbot renew --config-dir $CERTBOT_DIR/config --work-dir $CERTBOT_DIR/work --logs-dir $CERTBOT_DIR/logs --quiet"
    fi
}

# ============ main ============
main() {
    detect_platform
    install_deps
    setup_venv
    install_certbot
    prompt_input
    run_certbot
    build_proxy
    show_result
}

main "$@"

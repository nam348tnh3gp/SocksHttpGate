#!/usr/bin/env bash
# ============================================================================
# build.sh — Universal Proxy Pro (Kotlin/JDK21)
#
#   ./build.sh                Skip build nếu jar còn mới, in lệnh chạy
#   ./build.sh --run          Skip (hoặc build) rồi chạy luôn
#   ./build.sh --force        Force rebuild
#   ./build.sh --clean        Xoá jar trước khi build
#   ./build.sh --verify       Kiểm tra jar bằng java -cp (chậm ~3s, chắc chắn)
#   ./build.sh --help
# ============================================================================
set -euo pipefail

if [[ -t 1 ]]; then
    RED=$'\033[91m'; GRN=$'\033[92m'; YEL=$'\033[93m'
    BLU=$'\033[94m'; CYA=$'\033[96m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
    RED=''; GRN=''; YEL=''; BLU=''; CYA=''; BLD=''; RST=''
fi

ok()   { printf '%s[ OK ]%s %s\n'   "$GRN" "$RST" "$*"; }
warn() { printf '%s[WARN]%s %s\n'   "$YEL" "$RST" "$*"; }
err()  { printf '%s[FAIL]%s %s\n'   "$RED" "$RST" "$*" >&2; }
info() { printf '%s[INFO]%s %s\n'   "$BLU" "$RST" "$*"; }
hdr()  { printf '\n%s══ %s ══%s\n'  "$CYA$BLD" "$*" "$RST"; }

CLEAN=0; RUN=0; FORCE=0; VERIFY=0
for a in "$@"; do
    case "$a" in
        --clean)  CLEAN=1 ;;
        --run)    RUN=1 ;;
        --force)  FORCE=1 ;;
        --verify) VERIFY=1 ;;
        -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) err "Unknown arg: $a"; exit 2 ;;
    esac
done

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SRC="proxy.kt"
JAR="proxy.jar"
RUN_CMD_BASE="java -jar $JAR -p 1080 --dashboard-port 8081 --allow-private"

# ---------- mtime cross-platform ----------
get_mtime() {
    local f="$1"
    [[ ! -f "$f" ]] && { echo 0; return; }
    stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0
}

get_size() {
    local f="$1"
    [[ ! -f "$f" ]] && { echo 0; return; }
    wc -c < "$f" 2>/dev/null | tr -d ' ' || echo 0
}

# ---------- print run cmd ----------
print_run_cmd() {
    hdr "Chạy proxy"
    printf '  %s%s%s\n' "$CYA" "$RUN_CMD_BASE" "$RST"
    echo
    printf '  Hoặc: %s./build.sh --run%s\n' "$CYA" "$RST"
    echo
    printf '  Password dashboard in ra MỘT lần ở lần chạy đầu.\n'
    printf '  Login: http://127.0.0.1:8081\n'
}

# ============================================================================
# PLATFORM
# ============================================================================
hdr "Platform"
OS_RAW="$(uname -s 2>/dev/null || echo unknown)"
ARCH_RAW="$(uname -m 2>/dev/null || echo unknown)"
IS_TERMUX=0; IS_WSL=0; IS_MAC=0; IS_LINUX=0; IS_WINDOWS=0

case "$OS_RAW" in
    Linux)
        IS_LINUX=1
        [[ -n "${PREFIX:-}" && "$PREFIX" == *"com.termux"* ]] && IS_TERMUX=1
        grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null && IS_WSL=1
        ;;
    Darwin) IS_MAC=1 ;;
    MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
esac

case "$ARCH_RAW" in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    armv7l|armv8l) ARCH=armv7 ;;
    i686|i386)     ARCH=x86 ;;
    *)             ARCH="$ARCH_RAW" ;;
esac

PLATFORM="unknown"
[[ $IS_TERMUX  == 1 ]] && PLATFORM="termux"
[[ $IS_LINUX   == 1 && $IS_TERMUX == 0 ]] && PLATFORM="linux"
[[ $IS_WSL     == 1 ]] && PLATFORM="wsl"
[[ $IS_MAC     == 1 ]] && PLATFORM="macos"
[[ $IS_WINDOWS == 1 ]] && PLATFORM="windows"

ok "OS:       $OS_RAW"
ok "Arch:     $ARCH"
ok "Platform: $PLATFORM"

if [[ $IS_TERMUX == 1 ]]; then
    export JANSI_DISABLE=true
    case "${_JAVA_OPTIONS:-}" in
        *jansi.disable*) ;;
        *) export _JAVA_OPTIONS="-Djansi.disable=true ${_JAVA_OPTIONS:-}" ;;
    esac
    ok "JANSI_DISABLE=true (Termux)"
fi

# ============================================================================
# SKIP DECISION (mtime + size, không đọc nội dung jar)
# ============================================================================
JAR_MTIME=$(get_mtime "$JAR")
SRC_MTIME=$(get_mtime "$SRC")
JAR_SIZE=$(get_size "$JAR")

DO_BUILD=0
SKIP_REASON=""

if (( FORCE == 1 )); then
    DO_BUILD=1; SKIP_REASON="--force"
elif (( CLEAN == 1 )); then
    DO_BUILD=1; SKIP_REASON="--clean"
elif [[ ! -f "$JAR" ]]; then
    DO_BUILD=1; SKIP_REASON="chưa có $JAR"
elif [[ ! -f "$SRC" ]]; then
    DO_BUILD=0   # chỉ có jar, không có src → tin jar
elif (( JAR_SIZE < 50000 )); then
    DO_BUILD=1; SKIP_REASON="jar quá nhỏ ($JAR_SIZE bytes, có thể hỏng)"
elif (( JAR_MTIME < SRC_MTIME )); then
    DO_BUILD=1; SKIP_REASON="$SRC mới hơn jar"
fi

# --verify: kiểm tra sâu bằng java -cp (chậm ~3s nhưng chắc chắn)
if (( VERIFY == 1 && DO_BUILD == 0 )); then
    hdr "Deep Verify"
    info "Kiểm tra java -cp $JAR ... (có thể mất 2-3 giây)"
    _v_ok=0
    if timeout 8 java -cp "$JAR" ProxyKt --help >/dev/null 2>&1; then _v_ok=1
    elif timeout 8 java -cp "$JAR" Proxy --help >/dev/null 2>&1; then _v_ok=1
    fi
    if (( _v_ok == 1 )); then
        ok "Jar có thể load main class"
    else
        warn "Không load được main class → force build"
        DO_BUILD=1; SKIP_REASON="--verify fail"
    fi
fi

# ============================================================================
# SKIP PATH
# ============================================================================
if (( DO_BUILD == 0 )); then
    hdr "Skip Build"
    ok "$JAR còn mới — bỏ qua build"
    printf '     Jar:   %s\n' "$(pwd)/$JAR"
    printf '     Size:  %s bytes (%s MB)\n' "$JAR_SIZE" \
        "$(awk "BEGIN{printf \"%.1f\", $JAR_SIZE/1024/1024}")"
    printf '     Built: %s\n' "$(date -r "$JAR" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo '?')"
    [[ -f "$SRC" ]] && printf '     Src:   %s\n' "$(date -r "$SRC" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo '?')"
    echo
    info "Dùng --force để build lại, hoặc --verify để kiểm tra sâu."

    if (( RUN == 1 )); then
        hdr "Run"
        echo "→ Ctrl+C để dừng"; echo
        exec $RUN_CMD_BASE
    else
        print_run_cmd
        exit 0
    fi
fi

info "Lý do build: $SKIP_REASON"

# ============================================================================
# BUILD
# ============================================================================
hdr "JDK"
command -v java >/dev/null 2>&1 || {
    err "Không có 'java'. Cài:"
    case "$PLATFORM" in
        termux) echo "  pkg install openjdk-21" ;;
        macos)  echo "  brew install openjdk@21" ;;
        linux|wsl) echo "  sudo apt install openjdk-21-jdk" ;;
        windows) echo "  https://adoptium.net/" ;;
    esac
    exit 1
}

JAVA_FULL="$(java -version 2>&1)"
JAVA_LINE="$(printf '%s\n' "$JAVA_FULL" | grep -iE 'openjdk|java version' | head -1)"
[[ -z "$JAVA_LINE" ]] && JAVA_LINE="$(printf '%s\n' "$JAVA_FULL" | grep -v 'Picked up' | head -1)"
ok "java: $JAVA_LINE"

JAVA_MAJOR="$(printf '%s\n' "$JAVA_FULL" | awk -F'"' '/version/ {
    v=$2
    if (v ~ /^1\./) { split(v,a,"."); print a[2]; exit }
    split(v,a,"."); print a[1]; exit }')"

if [[ -z "$JAVA_MAJOR" || ! "$JAVA_MAJOR" =~ ^[0-9]+$ ]]; then
    warn "Không parse được version, bỏ qua"
elif (( JAVA_MAJOR < 17 )); then
    err "JDK $JAVA_MAJOR quá cũ (cần ≥ 17)"; exit 1
elif (( JAVA_MAJOR < 21 )); then
    warn "JDK $JAVA_MAJOR — không có virtual threads"
    USE_VT="disabled"
else
    ok "JDK $JAVA_MAJOR → virtual threads: enabled"
    USE_VT="enabled"
fi

hdr "Kotlin Compiler"
command -v kotlinc >/dev/null 2>&1 || {
    err "Không có 'kotlinc'. Cài:"
    case "$PLATFORM" in
        termux) echo "  pkg install kotlin" ;;
        macos)  echo "  brew install kotlin" ;;
        linux|wsl) echo "  sdk install kotlin" ;;
        windows) echo "  https://github.com/JetBrains/kotlin/releases" ;;
    esac
    exit 1
}
KOTLINC_RAW="$(kotlinc -version 2>&1 | grep -v 'Picked up' | head -1)"
ok "kotlinc: $KOTLINC_RAW"

hdr "Source"
[[ ! -f "$SRC" ]] && { err "Không tìm thấy $SRC"; exit 1; }
ok "$SRC ($(wc -l < "$SRC") dòng, $(get_size "$SRC") bytes)"

if head -5 "$SRC" | grep -q '^@file:JvmName'; then
    warn "Còn @file:JvmName → class sẽ KHÔNG phải ProxyKt.class"
fi
grep -q '^fun main' "$SRC" || { err "Không có 'fun main' ở cột 0"; exit 1; }
ok "fun main top-level: OK"

if (( CLEAN == 1 )); then
    hdr "Clean"
    rm -f "$JAR" proxy.kt.*.bak 2>/dev/null || true
    ok "Đã xoá $JAR + .bak"
fi

hdr "Build"
rm -f "$JAR"
KT_HEAP="${KT_HEAP:-1g}"
START_TS=$(date +%s)
info "kotlinc $SRC -include-runtime -d $JAR (heap=$KT_HEAP)..."
kotlinc -J-Xmx"$KT_HEAP" "$SRC" -include-runtime -d "$JAR" || { err "kotlinc thất bại"; exit 1; }
ELAPSED=$(( $(date +%s) - START_TS ))
ok "Build xong trong ${ELAPSED}s"

hdr "Verify"
[[ ! -f "$JAR" ]] && { err "$JAR không được tạo"; exit 1; }
JAR_SIZE_NEW=$(get_size "$JAR")
ok "Size: $JAR_SIZE_NEW bytes ($(awk "BEGIN{printf \"%.1f\", $JAR_SIZE_NEW/1024/1024}") MB)"

# Verify chắc chắn bằng java -cp (post-build, chấp nhận chậm)
info "Test load: java -cp $JAR ProxyKt --help"
if timeout 10 java -cp "$JAR" ProxyKt --help >/dev/null 2>&1; then
    MAIN_CLASS="ProxyKt"
    ok "Class entry: ProxyKt ✓"
elif timeout 10 java -cp "$JAR" Proxy --help >/dev/null 2>&1; then
    MAIN_CLASS="Proxy"
    ok "Class entry: Proxy ✓"
else
    err "Không load được cả ProxyKt lẫn Proxy — build thất bại"
    exit 1
fi

hdr "Done"
printf '%s✓ Jar: %s%s\n' "$GRN$BLD" "$(pwd)/$JAR" "$RST"
printf '  Class:  %s\n' "$MAIN_CLASS"
printf '  VT:     %s\n' "${USE_VT:-enabled}"

if (( RUN == 1 )); then
    hdr "Run"
    echo "→ Ctrl+C để dừng"; echo
    exec $RUN_CMD_BASE
else
    print_run_cmd
fi

exit 0

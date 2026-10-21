#!/usr/bin/env bash
# build.sh — All-in-one toolchain for proxy.kt
#
#   Build:   ./build.sh                    (auto setup + incremental build)
#   Run:     ./build.sh run                (foreground)
#   Run bg:  ./build.sh run-bg             (background + wake lock)
#   Stop:    ./build.sh stop
#   Status:  ./build.sh status
#   Log:     ./build.sh log
#   Help:    ./build.sh --help
#
# Platforms: Termux, Linux, macOS, WSL, Windows (Git Bash)
# Requires:  JDK 17+ (21+ recommended), kotlinc (auto-installed on Termux)

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# ============ Constants ============
SRC="proxy.kt"
OUT="proxy.jar"
PATCHED=".proxy.jdk17.kt"

CONFIG_DIR="${CONFIG_DIR:-$HOME/.config/socksgate}"
PIDFILE="$CONFIG_DIR/proxy.pid"
LOGFILE="$CONFIG_DIR/proxy.log"
mkdir -p "$CONFIG_DIR"

trap 'rm -f "$PATCHED"' EXIT

# Silence Termux "_JAVA_OPTIONS picked up" warnings for all JVM invocations below
unset _JAVA_OPTIONS JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS 2>/dev/null || true

# ============ Helpers ============

log() { echo "[*] $*"; }
ok()  { echo "[+] $*"; }
die() { echo "[x] $*" >&2; exit 1; }

detect_platform() {
    case "$(uname -s 2>/dev/null)" in
        Darwin) echo "macos" ;;
        Linux)
            if [[ -n "${TERMUX_VERSION:-}" ]] || { [[ -n "${PREFIX:-}" ]] && [[ "$PREFIX" == */com.termux/* ]]; }; then
                echo "termux"
            elif grep -qi microsoft /proc/version 2>/dev/null; then
                echo "wsl"
            else
                echo "linux"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) echo "unknown" ;;
    esac
}

# Robust java major extraction. Handles:
#   openjdk 21.0.12 ...              (--version, plain)
#   openjdk version "21.0.12" ...    (-version, quoted)
#   java version "1.8.0_392"         (JDK 8)
#   Picked up _JAVA_OPTIONS: ...     (Termux noise, filtered)
java_major() {
    command -v java >/dev/null 2>&1 || { echo 0; return; }
    local line v major
    line=$(_JAVA_OPTIONS= java --version 2>&1 | grep -v -i 'picked up' | head -1 || true)
    if [[ -z "$line" ]] || [[ "$line" == Unrecognized* ]]; then
        line=$(_JAVA_OPTIONS= java -version 2>&1 | grep -v -i 'picked up' | head -1 || true)
    fi
    v=$(echo "$line" | sed -nE 's/.*"([^"]+)".*/\1/p')
    [[ -z "$v" ]] && v=$(echo "$line" | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || true)
    [[ -z "$v" ]] && { echo 0; return; }
    major=$(echo "$v" | cut -d. -f1)
    [[ "$major" == "1" ]] && major=$(echo "$v" | cut -d. -f2)
    [[ "$major" =~ ^[0-9]+$ ]] || major=0
    echo "$major"
}

java_version_line() {
    command -v java >/dev/null 2>&1 || { echo "not found"; return; }
    local line
    line=$(_JAVA_OPTIONS= java --version 2>&1 | grep -v -i 'picked up' | head -1 || true)
    if [[ -z "$line" ]] || [[ "$line" == Unrecognized* ]]; then
        line=$(_JAVA_OPTIONS= java -version 2>&1 | grep -v -i 'picked up' | head -1 || true)
    fi
    echo "${line:-unknown}"
}

kotlinc_version() {
    command -v kotlinc >/dev/null 2>&1 || { echo "not installed"; return; }
    kotlinc -version 2>&1 | grep -v -i 'picked up' \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown"
}

find_any_jdk() {
    local cur
    cur=$(java_major)
    [[ "$cur" -ge 17 ]] && return 0

    local h d
    local paths=(
        "${PREFIX:-}/opt/openjdk-21"
        "${PREFIX:-}/opt/openjdk-17"
        "${PREFIX:-}/opt/openjdk"
        /data/data/com.termux/files/usr/opt/openjdk-21
        /data/data/com.termux/files/usr/opt/openjdk-17
        /data/data/com.termux/files/usr/opt/openjdk
        /data/data/com.termux/files/usr/lib/jvm/openjdk-21
        /data/data/com.termux/files/usr/lib/jvm/openjdk-17
        /usr/lib/jvm/java-21-openjdk-amd64
        /usr/lib/jvm/java-17-openjdk-amd64
        /usr/lib/jvm/java-21-openjdk
        /usr/lib/jvm/java-17-openjdk
        /usr/lib/jvm/temurin-21-jdk-amd64
        /usr/lib/jvm/temurin-17-jdk-amd64
        /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
        /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
        /Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home
        /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
    )
    for h in "${paths[@]}"; do
        [[ -x "$h/bin/java" ]] || continue
        export JAVA_HOME="$h"
        export PATH="$JAVA_HOME/bin:$PATH"
        hash -r 2>/dev/null || true
        return 0
    done

    if [[ -n "${PREFIX:-}" ]]; then
        for d in "$PREFIX"/opt/openjdk* "$PREFIX"/opt/*jdk*; do
            [[ -x "$d/bin/java" ]] || continue
            export JAVA_HOME="$d"
            export PATH="$JAVA_HOME/bin:$PATH"
            hash -r 2>/dev/null || true
            return 0
        done
    fi
    if [[ -d /usr/lib/jvm ]]; then
        for d in /usr/lib/jvm/*; do
            [[ -x "$d/bin/java" ]] || continue
            export JAVA_HOME="$d"
            export PATH="$JAVA_HOME/bin:$PATH"
            hash -r 2>/dev/null || true
            return 0
        done
    fi
    return 1
}

# ============ Termux setup ============

termux_setup() {
    log "Termux dependency check"
    local pkgs=()

    if [[ "$(java_major)" -lt 21 ]] && [[ ! -x "${PREFIX:-}/opt/openjdk-21/bin/java" ]]; then
        pkgs+=(openjdk-21)
    fi
    command -v kotlinc           >/dev/null 2>&1 || pkgs+=(kotlin)
    command -v openssl           >/dev/null 2>&1 || pkgs+=(openssl)
    command -v unzip             >/dev/null 2>&1 || pkgs+=(unzip)
    command -v termux-wake-lock  >/dev/null 2>&1 || pkgs+=(termux-api)
    if ! command -v fuser >/dev/null 2>&1 && ! command -v lsof >/dev/null 2>&1; then
        pkgs+=(psmisc)
    fi

    if [[ ${#pkgs[@]} -eq 0 ]]; then
        ok "All Termux deps present"
        return 0
    fi

    log "Installing: ${pkgs[*]}"
    pkg install -y "${pkgs[@]}" 2>&1 | tail -3 || true
    hash -r 2>/dev/null || true
}

persist_java_env() {
    [[ -z "${JAVA_HOME:-}" ]] && return 0
    local bashrc="$HOME/.bashrc"
    local begin="# >>> proxy.kt env >>>"
    local end="# <<< proxy.kt env <<<"
    if grep -q "$begin" "$bashrc" 2>/dev/null; then
        return 0
    fi
    {
        echo ""
        echo "$begin"
        echo "export JAVA_HOME=\"$JAVA_HOME\""
        echo 'export PATH="$JAVA_HOME/bin:$PATH"'
        echo 'unset _JAVA_OPTIONS JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS 2>/dev/null || true'
        echo "$end"
    } >> "$bashrc"
    log "Persisted JAVA_HOME to ~/.bashrc (source ~/.bashrc for new shells)"
}

# ============ Build ============

# Up-to-date means: jar exists AND proxy.kt is not strictly newer than jar.
# Editing build.sh or other files does NOT trigger a rebuild.
# If timestamps are equal, we consider it up-to-date (no rebuild).
up_to_date() {
    [[ -f "$OUT" ]] || return 1
    [[ -f "$SRC" ]] || return 1
    ! [[ "$SRC" -nt "$OUT" ]]
}

# Portable human mtime (works on GNU/BSD/BusyBox/macOS)
file_mtime() {
    local f="$1"
    [[ -f "$f" ]] || { echo "?"; return; }
    if stat -c '%y' "$f" >/dev/null 2>&1; then
        stat -c '%y' "$f" | cut -d. -f1
    elif stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$f" >/dev/null 2>&1; then
        stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$f"
    else
        date -r "$f" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "?"
    fi
}

do_build() {
    local force="${1:-0}"

    [[ -f "$SRC" ]] || die "Source not found: $SRC"

    if [[ "$force" == "1" ]]; then
        log "--force set — rebuilding regardless of timestamps"
    elif up_to_date; then
        log "  Source: $SRC ($(file_mtime "$SRC"))"
        log "  Output: $OUT ($(file_mtime "$OUT"))"
        ok "proxy.jar is up-to-date (proxy.kt not newer) — skipping build"
        echo "    Use --force to rebuild anyway"
        return 0
    else
        log "  Source: $SRC ($(file_mtime "$SRC"))"
        log "  Output: $OUT ($(file_mtime "$OUT"))"
        log "proxy.kt is newer — rebuilding"
    fi

    command -v kotlinc >/dev/null 2>&1 || die "kotlinc not found — install Kotlin compiler"

    local jv src="$SRC" target
    jv=$(java_major)
    [[ "$jv" =~ ^[0-9]+$ ]] || jv=0
    [[ "$jv" -lt 17 ]] && die "JDK not found (java_major=$jv) — need JDK 17+"

    target="$jv"
    if [[ "$jv" -lt 21 ]]; then
        log "JDK $jv — patching source (no virtual threads)"
        sed -E 's/Thread\.ofVirtual\(\)\.name\("vt"\)\.start\(block\)/thread(isDaemon = true, name = "vt", block = block)/g' \
            "$SRC" > "$PATCHED"
        src="$PATCHED"
        target="17"
    fi

    log "Compiling with jvm-target=$target..."
    rm -f "$OUT"
    local t0 dur sz
    t0=$(date +%s)
    if ! kotlinc "$src" -include-runtime -jvm-target "$target" -nowarn -d "$OUT"; then
        die "Compilation failed"
    fi
    dur=$(( $(date +%s) - t0 ))
    sz=$(wc -c < "$OUT" | tr -d ' ')
    ok "Built $OUT (${dur}s, $((sz / 1024))KB)"
}

# ============ Run flags builder ============

build_run_flags() {
    RUN_ARGS=()

    local listen="${LISTEN:-0.0.0.0}"
    local port="${PROXY_PORT:-1080}"
    local dbind="${DASHBOARD_BIND:-127.0.0.1}"
    local dport="${DASHBOARD_PORT:-8081}"

    RUN_ARGS+=(-l "$listen")
    RUN_ARGS+=(-p "$port")
    RUN_ARGS+=(--config "$CONFIG_DIR/proxy_config.json")
    RUN_ARGS+=(--usage-file "$CONFIG_DIR/proxy_usage.json")
    RUN_ARGS+=(--log-file "$LOGFILE")
    RUN_ARGS+=(--log-max-size-mb "${LOG_MAX_MB:-10}")
    RUN_ARGS+=(--log-max-backups "${LOG_MAX_BACKUPS:-3}")
    RUN_ARGS+=(--dashboard-bind "$dbind")
    RUN_ARGS+=(--dashboard-port "$dport")
    RUN_ARGS+=(--force-kill)

    if [[ -n "${PROXY_USER:-}" ]] && [[ -n "${PROXY_PASS:-}" ]]; then
        RUN_ARGS+=(-u "$PROXY_USER" -P "$PROXY_PASS")
    fi

    [[ "${ALLOW_PRIVATE:-1}" == "1" ]] && RUN_ARGS+=(--allow-private)
    [[ "${NO_UDP:-0}"         == "1" ]] && RUN_ARGS+=(--no-udp)

    if [[ -n "${UPSTREAM:-}" ]]; then
        RUN_ARGS+=(--upstream "$UPSTREAM")
        [[ "${UPSTREAM_FALLBACK:-0}" == "1" ]] && RUN_ARGS+=(--upstream-fallback)
    fi

    if [[ -n "${TLS_CERT:-}" ]] && [[ -n "${TLS_KEY:-}" ]]; then
        RUN_ARGS+=(--cert "$TLS_CERT" --key "$TLS_KEY")
    fi

    [[ -n "${ALLOW_CIDRS:-}" ]] && RUN_ARGS+=(--allow "$ALLOW_CIDRS")
    [[ -n "${DENY_CIDRS:-}"  ]] && RUN_ARGS+=(--deny  "$DENY_CIDRS")
}

print_run_info() {
    local listen="${LISTEN:-0.0.0.0}"
    local port="${PROXY_PORT:-1080}"
    local dbind="${DASHBOARD_BIND:-127.0.0.1}"
    local dport="${DASHBOARD_PORT:-8081}"

    echo "  Listen    : $listen:$port"
    echo "  Dashboard : http://$dbind:$dport"
    echo "  Config    : $CONFIG_DIR/proxy_config.json"
    echo "  Log       : $LOGFILE"
    echo ""
}

print_flags_only() {
    build_run_flags
    local jopts="${JAVA_OPTS:--Xmx512m -XX:+UseSerialGC}"
    echo "═══════════════════════════════════════════════════════════"
    echo "  Run command (executed by 'run' / 'run-bg')"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "  JAVA_OPTS=\"$jopts\""
    echo ""
    echo "  java \$JAVA_OPTS -jar $OUT \\"
    local i=0
    while [[ $i -lt ${#RUN_ARGS[@]} ]]; do
        local a="${RUN_ARGS[$i]}"
        local n="${RUN_ARGS[$((i+1))]:-}"
        if [[ "$a" == --* ]] && [[ -n "$n" ]] && [[ "$n" != -* ]]; then
            echo "      $a $n \\"
            i=$((i+2))
        else
            echo "      $a \\"
            i=$((i+1))
        fi
    done
    echo ""
    print_run_info
}

# ============ Run modes ============

do_run_fg() {
    do_build 0
    build_run_flags
    export JAVA_OPTS="${JAVA_OPTS:--Xmx512m -XX:+UseSerialGC -XX:MaxRAMPercentage=75}"
    echo "═══════════════════════════════════════════════════════════"
    echo "  Running proxy.jar (foreground)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    print_run_info
    exec java $JAVA_OPTS -jar "$OUT" "${RUN_ARGS[@]}"
}

do_run_bg() {
    do_build 0
    build_run_flags
    export JAVA_OPTS="${JAVA_OPTS:--Xmx512m -XX:+UseSerialGC -XX:MaxRAMPercentage=75}"

    if [[ -f "$PIDFILE" ]]; then
        local pid
        pid=$(cat "$PIDFILE" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            die "Already running (PID $pid). Use '$0 stop' first."
        fi
        rm -f "$PIDFILE"
    fi

    command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock && log "Wake lock acquired"

    echo "═══════════════════════════════════════════════════════════"
    echo "  Starting proxy.jar (background)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    print_run_info

    nohup java $JAVA_OPTS -jar "$OUT" "${RUN_ARGS[@]}" >> "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 2

    if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        ok "Started (PID $(cat "$PIDFILE"))"
        echo ""
        echo "  Status : $0 status"
        echo "  Log    : $0 log"
        echo "  Stop   : $0 stop"
    else
        rm -f "$PIDFILE"
        die "Failed to start — check $LOGFILE"
    fi
}

do_stop() {
    if [[ -f "$PIDFILE" ]]; then
        local pid
        pid=$(cat "$PIDFILE" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "Stopping PID $pid..."
            kill -TERM "$pid" 2>/dev/null || true
            sleep 2
            kill -KILL "$pid" 2>/dev/null || true
        fi
        rm -f "$PIDFILE"
    fi
    command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock || true
    ok "Stopped"
}

do_status() {
    if [[ -f "$PIDFILE" ]]; then
        local pid
        pid=$(cat "$PIDFILE" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            ok "Running (PID $pid)"
            local dport="${DASHBOARD_PORT:-8081}"
            if command -v curl >/dev/null 2>&1; then
                echo ""
                echo "  Health:"
                curl -sf --max-time 2 "http://127.0.0.1:$dport/healthz" 2>/dev/null \
                    | head -c 200 | sed 's/^/    /' || echo "    (unreachable)"
                echo ""
            fi
            return 0
        fi
        rm -f "$PIDFILE"
    fi
    log "Not running"
    return 1
}

do_log() {
    [[ -f "$LOGFILE" ]] || die "No log yet: $LOGFILE"
    exec tail -f "$LOGFILE"
}

# ============ Help ============

show_help() {
    cat <<'EOF'
Usage: ./build.sh <command> [options]

Commands:
  (none), build    Setup (if needed) + build proxy.jar (skip if up-to-date)
  run              Build if needed, then run foreground
  run-bg           Build if needed, then run in background (wake lock)
  stop             Stop background process
  status           Show if background process is running
  log              tail -f the log file

Build behavior:
  Rebuild only happens when proxy.kt is NEWER than proxy.jar.
  Editing build.sh or any other file does NOT trigger a rebuild.
  Use --force to rebuild regardless of timestamps.

Options:
  --force, -f      Force rebuild even if up-to-date
  --setup          Force re-run Termux dependency check
  --print-flags    Show run command + flags, don't execute
  -h, --help       Show this help

Environment (override defaults):
  LISTEN           Bind address           (default: 0.0.0.0)
  PROXY_PORT       Proxy port             (default: 1080)
  DASHBOARD_BIND   Dashboard bind         (default: 127.0.0.1)
  DASHBOARD_PORT   Dashboard port         (default: 8081)
  CONFIG_DIR       Config directory       (default: ~/.config/socksgate)

  PROXY_USER       SOCKS5/HTTP username   (empty = no auth)
  PROXY_PASS       SOCKS5/HTTP password
  ALLOW_PRIVATE    1 = allow LAN targets  (default: 1)
  NO_UDP           1 = disable SOCKS5 UDP (default: 0)
  UPSTREAM         Chain proxy: socks5://host:port | http://host:port
  UPSTREAM_FALLBACK 1 = direct if all upstreams fail
  TLS_CERT         PEM cert for TLS listener (with TLS_KEY)
  TLS_KEY          PEM key for TLS listener
  ALLOW_CIDRS      Whitelist IPs (comma-separated)
  DENY_CIDRS       Blacklist IPs (comma-separated)

  LOG_MAX_MB       Log rotation size MB   (default: 10)
  LOG_MAX_BACKUPS  Log rotation backups   (default: 3)
  JAVA_OPTS        JVM flags              (default: -Xmx512m -XX:+UseSerialGC)

Examples:
  ./build.sh                                       # build only (skip if up-to-date)
  ./build.sh --force                               # force rebuild
  ./build.sh run                                   # build if needed + run foreground
  ./build.sh run-bg                                # build if needed + run background
  ./build.sh --print-flags                         # inspect flags
  PROXY_USER=admin PROXY_PASS=secret ./build.sh run-bg
  PROXY_PORT=9090 DASHBOARD_PORT=8082 ./build.sh run
  UPSTREAM=socks5://1.2.3.4:1080 ./build.sh run-bg
EOF
}

# ============ Main ============

CMD="build"
FORCE=0
SETUP_FORCE=0
PRINT_FLAGS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        build|run|run-bg|stop|status|log) CMD="$1" ;;
        --force|-f)     FORCE=1 ;;
        --setup)        SETUP_FORCE=1 ;;
        --print-flags)  PRINT_FLAGS=1 ;;
        -h|--help)      show_help; exit 0 ;;
        *)              die "Unknown argument: $1 (try --help)" ;;
    esac
    shift
done

# Print flags is a dry run — no JDK or setup needed
if [[ "$PRINT_FLAGS" == "1" ]]; then
    print_flags_only
    exit 0
fi

PLATFORM=$(detect_platform)
log "Platform: $PLATFORM"

# Termux: dependency check (auto)
if [[ "$PLATFORM" == "termux" ]]; then
    export JAVA_OPTS="${JAVA_OPTS:--Xmx512m -XX:+UseSerialGC -XX:MaxRAMPercentage=75}"
    case "$CMD" in
        build|run|run-bg) termux_setup ;;
    esac
fi

# Locate JDK
if ! find_any_jdk; then
    cat >&2 <<'EOF'
[x] No JDK 17+ found.

    Install:
      Termux:        pkg install openjdk-21
                     export JAVA_HOME=$PREFIX/opt/openjdk-21
                     export PATH=$JAVA_HOME/bin:$PATH
      Debian/Ubuntu: sudo apt install openjdk-21-jdk
      Fedora/RHEL:   sudo dnf install java-21-openjdk-devel
      macOS:         brew install openjdk@21
      Windows (WSL): sudo apt install openjdk-21-jdk

EOF
    exit 1
fi

# Persist JAVA_HOME for new shells (Termux only, once)
if [[ "$PLATFORM" == "termux" ]]; then
    case "$CMD" in
        build|run|run-bg) persist_java_env ;;
    esac
fi

log "Java   : $(java_major)  ($(java_version_line))"
log "Kotlin : $(kotlinc_version)"
echo ""

case "$CMD" in
    build)  do_build "$FORCE" ;;
    run)    do_run_fg ;;
    run-bg) do_run_bg ;;
    stop)   do_stop ;;
    status) do_status || true ;;
    log)    do_log ;;
    *)      die "Unknown command: $CMD" ;;
esac

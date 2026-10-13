/**
 * Universal Proxy Pro v6.3 - C implementation
 * SOCKS5 (TCP/UDP), HTTP/HTTPS (CONNECT), upstream (HTTP CONNECT / SOCKS5),
 * dashboard giống bản Go: multi-user + giới hạn băng thông / số kết nối / quota tháng,
 * API token, whitelist/blacklist IP, hot-reload (SIGHUP), audit log, backup/restore, SSE real-time.
 *
 * Build: make            (hoặc: gcc -O2 -pthread -o proxy proxy.c)
 *
 * Config file (JSON, cùng định dạng với bản Go) mặc định: proxy_config.json
 * Usage file (quota theo tháng)                  mặc định: proxy_usage.json
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>

/* ========================== CONFIG ========================== */
#define VERSION_STR         "v6.3"
#define MAX_CONNECTIONS     4000
#define CONNECTION_TIMEOUT  25      /* tổng thời gian tối đa để kết nối tới đích (giây) */
#define HANDSHAKE_TIMEOUT   30      /* thời gian tối đa client gửi xong handshake/header */
#define IDLE_TIMEOUT        180
#define BUFFER_SIZE         32768
#define UDP_BUFFER_SIZE     65535
#define UDP_IDLE_TIMEOUT    120
#define DASHBOARD_PORT      8081
#define MAX_UPSTREAM        16
#define MAX_LINE            8192
#define MAX_HEADER_LINES    100
#define MAX_HEADER_BYTES    16384
#define THREAD_STACK_SIZE   (512 * 1024)
#define UDP_DEST_RING       64
#define AUTH_FAIL_THRESHOLD 5
#define DASH_AUTH_FAIL_THRESHOLD 30     /* dashboard: ngưỡng cao hơn vì 1 tab trình duyệt gọi nhiều endpoint cùng lúc */
#define AUTH_FAIL_WINDOW    300
#define AUTH_BLOCK_SECONDS  900
#define AUTH_TABLE_SIZE     512
#define NAME_LEN            64
#define DASH_MAX_THREADS    64
#define DASH_MAX_SSE        16

/* Colors (ANSI) */
#define COLOR_GREEN   "\033[92m"
#define COLOR_YELLOW  "\033[93m"
#define COLOR_RED     "\033[91m"
#define COLOR_CYAN    "\033[96m"
#define COLOR_PURPLE  "\033[95m"
#define COLOR_RESET   "\033[0m"

/* ========================== GLOBAL STATE ========================== */
typedef struct {
    long long total;
    long long current;
    long long socks5_tcp;
    long long socks5_udp;
    long long http;
    long long auth_fail;
    long long bytes_up;
    long long bytes_down;
    long long udp_up;
    long long udp_down;
    time_t start_time;
} Stats;

static Stats g_stats;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Một kết nối đang hoạt động (bảng cố định, truy cập qua active_mutex; bytes/rate dùng atomic) */
typedef struct {
    bool used;
    long long id;
    char ip[64];
    int port;
    char type[16];
    char target[256];
    char user[NAME_LEN];
    time_t start_time;
    long long bytes_up, bytes_down;     /* atomic */
    long long rate_bps;                 /* atomic; 0 = không giới hạn */
    int usage_idx;                      /* chỉ số bản ghi usage của user (-1 nếu không có user) */
    int client_fd, remote_fd;           /* dùng để kick; chỉ hợp lệ khi != -1, luôn thay đổi dưới active_mutex */
    int udp_relay_port;                 /* chỉ cho SOCKS5_UDP */
    long long udp_last;                 /* atomic */
    long long udp_dests;                /* atomic */
    char udp_client[80];                /* guarded by active_mutex */
} ActiveConn;

static ActiveConn g_active_conns[MAX_CONNECTIONS];
static pthread_mutex_t active_mutex = PTHREAD_MUTEX_INITIALIZER;
static long long g_conn_id_counter = 0;

typedef struct {
    char spec[300];         /* nguyên văn như trong config (vd "socks5://1.2.3.4:1080" hoặc "1.2.3.4:8080") */
    char host[256];
    int port;
    int type;               /* 0 = HTTP CONNECT, 1 = SOCKS5 */
    int alive;              /* health-check; chưa kiểm tra = coi là sống */
} Upstream;

static Upstream g_upstreams[MAX_UPSTREAM];
static int g_upstream_count = 0;
static int g_upstream_index = 0;
static pthread_mutex_t upstream_mutex = PTHREAD_MUTEX_INITIALIZER;

static char g_listen_addr[64] = "0.0.0.0";
static int g_listen_port = 1080;
static char g_username[256] = "";       /* chế độ 1 user cũ (-u/-P) */
static char g_password[256] = "";
static int g_auth_required = 0;
static int g_enable_udp = 1;
static char g_dashboard_bind[64] = "127.0.0.1";
static int g_dashboard_port = DASHBOARD_PORT;
static char g_init_dash_user[128] = "admin";    /* chỉ dùng lần chạy đầu (khi config file chưa tồn tại) */
static char g_init_dash_pass[256] = "";
static char g_seed_allow[2048] = "", g_seed_deny[2048] = "", g_seed_upstream[4096] = "";
static int g_force_kill = 0;
static int g_allow_private = 0;
static int g_upstream_fallback = 0;
static bool g_tty = false;

static int g_shutdown_raw = 0;      /* ghi trong signal handler, đọc từ nhiều luồng -> luôn truy cập atomic */
#define g_shutdown_flag __atomic_load_n(&g_shutdown_raw, __ATOMIC_RELAXED)
static int g_hup_raw = 0;           /* SIGHUP -> reload config */
static int g_thread_count = 0;      /* số luồng xử lý client (atomic) */
static int g_udp_assoc_count = 0;   /* atomic */

/* ========================== LOGGING ========================== */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void log_vmsg(FILE *out, const char *prefix, const char *fmt, va_list args) {
    char line[1024];
    vsnprintf(line, sizeof(line), fmt, args);
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    pthread_mutex_lock(&log_mutex);
    fprintf(out, "[%02d:%02d:%02d] %s%s\n", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, prefix, line);
    fflush(out);
    pthread_mutex_unlock(&log_mutex);
}

static void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_vmsg(stdout, "", fmt, args);
    va_end(args);
}

static void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_vmsg(stderr, "ERROR: ", fmt, args);
    va_end(args);
}

/* ========================== UTILITY ========================== */
static void format_bytes(long long bytes, char *buf, size_t bufsize) {
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int idx = 0;
    double val = (double)bytes;
    while (val >= 1024 && idx < 4) { val /= 1024; idx++; }
    snprintf(buf, bufsize, "%.1f %s", val, units[idx]);
}

static bool ct_equal(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    unsigned diff = (unsigned)(la ^ lb);
    size_t n = la > lb ? la : lb;
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = i < la ? (unsigned char)a[i] : 0;
        unsigned char cb = i < lb ? (unsigned char)b[i] : 0;
        diff |= (unsigned)(ca ^ cb);
    }
    return diff == 0;
}

static int b64_decode(const char *in, uint8_t *out, size_t outsz) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, bits = -8;
    size_t n = 0;
    for (; *in && *in != '=' && *in != '\r' && *in != '\n'; in++) {
        const char *p = strchr(tbl, *in);
        if (!p) return -1;
        val = ((val << 6) | (int)(p - tbl)) & 0xFFFFFF;
        bits += 6;
        if (bits >= 0) {
            if (n >= outsz) return -1;
            out[n++] = (uint8_t)((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return (int)n;
}

/* host chỉ gồm [A-Za-z0-9._:-] — chặn ký tự lạ (XSS/log injection) ngay từ nguồn */
static bool host_chars_ok(const char *h) {
    if (!*h) return false;
    for (; *h; h++) {
        unsigned char c = (unsigned char)*h;
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_' || c == ':')) return false;
    }
    return true;
}

static bool parse_port_str(const char *s, int *out) {
    if (!s || !*s) return false;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end || v < 1 || v > 65535) return false;
    *out = (int)v;
    return true;
}

/* "host", "host:port", "[v6]", "[v6]:port" */
static int parse_hostport(const char *s, char *host, size_t hostsz, int *port, int defport) {
    char tmp[300];
    if (strlen(s) >= sizeof(tmp)) return -1;
    snprintf(tmp, sizeof(tmp), "%s", s);
    char *h = tmp, *portstr = NULL;
    if (tmp[0] == '[') {
        char *rb = strchr(tmp, ']');
        if (!rb) return -1;
        *rb = '\0';
        h = tmp + 1;
        if (rb[1] == ':') portstr = rb + 2;
        else if (rb[1] != '\0') return -1;
    } else {
        char *c1 = strchr(tmp, ':');
        if (c1) {
            if (strchr(c1 + 1, ':')) return -1;     /* IPv6 trần không hợp lệ */
            *c1 = '\0';
            portstr = c1 + 1;
        }
    }
    if (strlen(h) >= hostsz || !host_chars_ok(h)) return -1;
    if (portstr) {
        if (!parse_port_str(portstr, port)) return -1;
    } else if (defport > 0) {
        *port = defport;
    } else {
        return -1;
    }
    snprintf(host, hostsz, "%s", h);
    return 0;
}

/* ---- địa chỉ: dạng chuẩn 16 byte (IPv4 -> ::ffff:a.b.c.d) ---- */
static void sa_canon(const struct sockaddr *sa, uint8_t ip[16], uint16_t *port) {
    memset(ip, 0, 16);
    *port = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
        ip[10] = 0xff; ip[11] = 0xff;
        memcpy(ip + 12, &in->sin_addr, 4);
        *port = ntohs(in->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
        memcpy(ip, &in6->sin6_addr, 16);
        *port = ntohs(in6->sin6_port);
    }
}

static bool canon_is_v4(const uint8_t ip[16]) {
    static const uint8_t pre[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    return memcmp(ip, pre, 12) == 0;
}

static void canon_to_str(const uint8_t ip[16], char *buf, size_t n) {
    if (canon_is_v4(ip)) inet_ntop(AF_INET, ip + 12, buf, (socklen_t)n);
    else inet_ntop(AF_INET6, ip, buf, (socklen_t)n);
}

static void sa_to_str(const struct sockaddr *sa, char *buf, size_t n, int *port) {
    uint8_t ip[16]; uint16_t p;
    sa_canon(sa, ip, &p);
    canon_to_str(ip, buf, n);
    if (port) *port = p;
}

/* Địa chỉ nội bộ / đặc biệt (chống SSRF) */
static bool is_blocked_v4(const uint8_t *p) {
    uint8_t a = p[0], b = p[1], c = p[2];
    if (a == 0 || a == 10 || a == 127) return true;
    if (a == 100 && (b & 0xC0) == 64) return true;          /* CGNAT 100.64/10 */
    if (a == 169 && b == 254) return true;                  /* link-local + metadata */
    if (a == 172 && (b & 0xF0) == 16) return true;
    if (a == 192 && b == 168) return true;
    if (a == 192 && b == 0 && c == 0) return true;
    if (a == 198 && (b & 0xFE) == 18) return true;          /* benchmark 198.18/15 */
    if (a >= 224) return true;                              /* multicast + reserved */
    return false;
}

static bool is_blocked_canon(const uint8_t ip[16]) {
    if (canon_is_v4(ip)) return is_blocked_v4(ip + 12);
    static const uint8_t zero12[12] = {0};
    if (memcmp(ip, zero12, 12) == 0) return true;           /* ::, ::1, ::/96 */
    if ((ip[0] & 0xFE) == 0xFC) return true;                /* fc00::/7 */
    if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) return true; /* fe80::/10 */
    if (ip[0] == 0xFF) return true;                         /* multicast */
    if (ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b) {
        static const uint8_t z8[8] = {0};
        if (memcmp(ip + 4, z8, 8) == 0) return is_blocked_v4(ip + 12); /* NAT64 */
    }
    return false;
}

static bool is_blocked_sa(const struct sockaddr *sa) {
    if (g_allow_private) return false;
    uint8_t ip[16]; uint16_t p;
    sa_canon(sa, ip, &p);
    return is_blocked_canon(ip);
}

static bool host_is_blocked_literal(const char *host) {
    if (g_allow_private) return false;
    uint8_t ip[16];
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, host, &a4) == 1) {
        memset(ip, 0, 16); ip[10] = 0xff; ip[11] = 0xff; memcpy(ip + 12, &a4, 4);
        return is_blocked_canon(ip);
    }
    if (inet_pton(AF_INET6, host, &a6) == 1) {
        memcpy(ip, &a6, 16);
        return is_blocked_canon(ip);
    }
    return false;
}

/* ========================== SHA-256 / HEX / RANDOM ========================== */
typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t blen;
} Sha256;

static const uint32_t SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t st[8], const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR32(w[i-2], 17) ^ ROR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

static void sha256_init(Sha256 *s) {
    static const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(s->h, iv, sizeof(iv));
    s->len = 0;
    s->blen = 0;
}

static void sha256_update(Sha256 *s, const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    s->len += n;
    if (s->blen) {
        size_t take = 64 - s->blen;
        if (take > n) take = n;
        memcpy(s->buf + s->blen, p, take);
        s->blen += take; p += take; n -= take;
        if (s->blen == 64) { sha256_block(s->h, s->buf); s->blen = 0; }
    }
    while (n >= 64) { sha256_block(s->h, p); p += 64; n -= 64; }
    if (n) { memcpy(s->buf, p, n); s->blen = n; }
}

static void sha256_final(Sha256 *s, uint8_t out[32]) {
    uint64_t bits = s->len * 8;
    uint8_t pad = 0x80;
    sha256_update(s, &pad, 1);
    uint8_t z = 0;
    while (s->blen != 56) sha256_update(s, &z, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(s, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4] = (uint8_t)(s->h[i] >> 24); out[i*4+1] = (uint8_t)(s->h[i] >> 16);
        out[i*4+2] = (uint8_t)(s->h[i] >> 8); out[i*4+3] = (uint8_t)s->h[i];
    }
}

static void sha256_buf(const void *data, size_t n, uint8_t out[32]) {
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, data, n);
    sha256_final(&s, out);
}

/* Nén 1 khối cho thông điệp 32 byte (dùng trong vòng lặp hash mật khẩu cho nhanh) */
static void sha256_32(const uint8_t in[32], uint8_t out[32]) {
    uint32_t st[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk[64];
    memcpy(blk, in, 32);
    blk[32] = 0x80;
    memset(blk + 33, 0, 64 - 33 - 2);
    blk[62] = 0x01; blk[63] = 0x00;     /* 256 bit = 0x0100 */
    sha256_block(st, blk);
    for (int i = 0; i < 8; i++) {
        out[i*4] = (uint8_t)(st[i] >> 24); out[i*4+1] = (uint8_t)(st[i] >> 16);
        out[i*4+2] = (uint8_t)(st[i] >> 8); out[i*4+3] = (uint8_t)st[i];
    }
}

static void hex_encode(const uint8_t *in, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[i*2] = hx[in[i] >> 4]; out[i*2+1] = hx[in[i] & 15]; }
    out[n*2] = '\0';
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *in, uint8_t *out, size_t maxn) {
    size_t l = strlen(in);
    if (l % 2 || l / 2 > maxn) return -1;
    for (size_t i = 0; i < l / 2; i++) {
        int a = hex_val(in[i*2]), b = hex_val(in[i*2+1]);
        if (a < 0 || b < 0) return -1;
        out[i] = (uint8_t)(a * 16 + b);
    }
    return (int)(l / 2);
}

static bool rand_bytes(uint8_t *out, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { close(fd); return false; }
        got += (size_t)r;
    }
    close(fd);
    return true;
}

/* ========================== HASH MẬT KHẨU (tương thích bản Go: "iterations:saltHex:hashHex") ========================== */
#define HASH_ITERATIONS     200000
#define HASH_MAX_ITERATIONS 5000000
#define PW_HASH_MAX         160

static void pw_digest(const char *password, const uint8_t *salt, size_t slen, int iterations, uint8_t out[32]) {
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, salt, slen);
    sha256_update(&s, password, strlen(password));
    uint8_t d[32];
    sha256_final(&s, d);
    for (int i = 1; i < iterations; i++) {
        uint8_t n[32];
        sha256_32(d, n);
        memcpy(d, n, 32);
    }
    memcpy(out, d, 32);
}

static bool hash_password(const char *password, char *out, size_t outsz) {
    uint8_t salt[16], dg[32];
    if (!rand_bytes(salt, sizeof(salt))) return false;
    pw_digest(password, salt, sizeof(salt), HASH_ITERATIONS, dg);
    char sh[33], dh[65];
    hex_encode(salt, sizeof(salt), sh);
    hex_encode(dg, sizeof(dg), dh);
    int n = snprintf(out, outsz, "%d:%s:%s", HASH_ITERATIONS, sh, dh);
    return n > 0 && (size_t)n < outsz;
}

static bool verify_password(const char *password, const char *stored) {
    char tmp[PW_HASH_MAX + 1];
    if (strlen(stored) > PW_HASH_MAX) return false;
    snprintf(tmp, sizeof(tmp), "%s", stored);
    char *c1 = strchr(tmp, ':');
    if (!c1) return false;
    *c1 = '\0';
    char *c2 = strchr(c1 + 1, ':');
    if (!c2) return false;
    *c2 = '\0';
    char *end = NULL;
    long iters = strtol(tmp, &end, 10);
    if (*end || iters <= 0 || iters > HASH_MAX_ITERATIONS) return false;
    uint8_t salt[64], want[32], got[32];
    int sl = hex_decode(c1 + 1, salt, sizeof(salt));
    int wl = hex_decode(c2 + 1, want, sizeof(want));
    if (sl < 0 || wl != 32) return false;
    pw_digest(password, salt, (size_t)sl, (int)iters, got);
    unsigned diff = 0;
    for (int i = 0; i < 32; i++) diff |= (unsigned)(got[i] ^ want[i]);
    return diff == 0;
}

/* Cache kết quả verify THÀNH CÔNG (key = SHA-256(hash đã lưu + mật khẩu)), TTL ngắn. */
#define PW_CACHE_SIZE 256
#define PW_CACHE_TTL  300
typedef struct { uint8_t key[32]; time_t exp; } PwCacheEnt;
static PwCacheEnt g_pwcache[PW_CACHE_SIZE];
static int g_pwcache_next = 0;
static pthread_mutex_t pwcache_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool verify_password_cached(const char *password, const char *stored) {
    uint8_t key[32];
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, stored, strlen(stored));
    uint8_t z = 0;
    sha256_update(&s, &z, 1);
    sha256_update(&s, password, strlen(password));
    sha256_final(&s, key);
    time_t now = time(NULL);
    pthread_mutex_lock(&pwcache_mutex);
    for (int i = 0; i < PW_CACHE_SIZE; i++) {
        if (g_pwcache[i].exp > now && memcmp(g_pwcache[i].key, key, 32) == 0) {
            pthread_mutex_unlock(&pwcache_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&pwcache_mutex);
    if (!verify_password(password, stored)) return false;
    pthread_mutex_lock(&pwcache_mutex);
    memcpy(g_pwcache[g_pwcache_next].key, key, 32);
    g_pwcache[g_pwcache_next].exp = now + PW_CACHE_TTL;
    g_pwcache_next = (g_pwcache_next + 1) % PW_CACHE_SIZE;
    pthread_mutex_unlock(&pwcache_mutex);
    return true;
}

static bool gen_token_hex(char *out, size_t outsz) {     /* 32 byte ngẫu nhiên -> 64 ký tự hex */
    uint8_t b[32];
    if (outsz < 65 || !rand_bytes(b, sizeof(b))) return false;
    hex_encode(b, sizeof(b), out);
    return true;
}

static void hash_api_token(const char *token, char out[65]) {
    uint8_t d[32];
    sha256_buf(token, strlen(token), d);
    hex_encode(d, 32, out);
}

/* ========================== JSON (parser DOM tối giản + helper) ========================== */
typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;
typedef struct JVal {
    JType t;
    bool b;
    double num;
    long long ll;
    bool is_int;
    char *s;
    struct JVal **items;     /* mảng giá trị (J_ARR) hoặc giá trị của object (J_OBJ) */
    char **keys;             /* khoá (J_OBJ) */
    int n, cap;
} JVal;

#define JSON_MAX_DEPTH 32
#define JSON_MAX_ITEMS 20000

typedef struct {
    const char *p, *end, *start;
    char err[96];
    int depth;
} JParser;

static void jfree(JVal *v) {
    if (!v) return;
    free(v->s);
    for (int i = 0; i < v->n; i++) {
        if (v->keys) free(v->keys[i]);
        jfree(v->items[i]);
    }
    free(v->items);
    free(v->keys);
    free(v);
}

static void jp_fail(JParser *jp, const char *msg) {
    if (!jp->err[0]) snprintf(jp->err, sizeof(jp->err), "%s (offset %ld)", msg, (long)(jp->p - jp->start));
}

static void jp_ws(JParser *jp) {
    while (jp->p < jp->end && (*jp->p == ' ' || *jp->p == '\t' || *jp->p == '\n' || *jp->p == '\r')) jp->p++;
}

static bool jv_push(JVal *v, char *key, JVal *item) {
    if (v->n >= JSON_MAX_ITEMS) return false;
    if (v->n == v->cap) {
        int nc = v->cap ? v->cap * 2 : 4;
        JVal **ni = realloc(v->items, sizeof(JVal *) * (size_t)nc);
        if (!ni) return false;
        v->items = ni;
        if (v->t == J_OBJ) {
            char **nk = realloc(v->keys, sizeof(char *) * (size_t)nc);
            if (!nk) return false;
            v->keys = nk;
        }
        v->cap = nc;
    }
    if (v->t == J_OBJ) v->keys[v->n] = key;
    v->items[v->n++] = item;
    return true;
}

static int utf8_put(char *o, uint32_t cp) {
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) { o[0] = (char)(0xC0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) { o[0] = (char)(0xE0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 0x3F)); o[2] = (char)(0x80 | (cp & 0x3F)); return 3; }
    o[0] = (char)(0xF0 | (cp >> 18)); o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

static int hex4(const char *p) {
    int v = 0;
    for (int i = 0; i < 4; i++) {
        int d = hex_val(p[i]);
        if (d < 0) return -1;
        v = v * 16 + d;
    }
    return v;
}

static char *jp_string(JParser *jp) {
    /* *p == '"' */
    jp->p++;
    size_t cap = 32, n = 0;
    char *out = malloc(cap);
    if (!out) { jp_fail(jp, "out of memory"); return NULL; }
    while (jp->p < jp->end) {
        unsigned char c = (unsigned char)*jp->p;
        if (c == '"') { jp->p++; out[n] = '\0'; return out; }
        if (c < 0x20) { jp_fail(jp, "control character in string"); break; }
        if (n + 8 >= cap) {
            cap *= 2;
            if (cap > (size_t)16 * 1024 * 1024) { jp_fail(jp, "string too long"); break; }
            char *no = realloc(out, cap);
            if (!no) { jp_fail(jp, "out of memory"); break; }
            out = no;
        }
        if (c != '\\') { out[n++] = (char)c; jp->p++; continue; }
        jp->p++;
        if (jp->p >= jp->end) break;
        char e = *jp->p++;
        switch (e) {
        case '"': out[n++] = '"'; break;
        case '\\': out[n++] = '\\'; break;
        case '/': out[n++] = '/'; break;
        case 'b': out[n++] = '\b'; break;
        case 'f': out[n++] = '\f'; break;
        case 'n': out[n++] = '\n'; break;
        case 'r': out[n++] = '\r'; break;
        case 't': out[n++] = '\t'; break;
        case 'u': {
            if (jp->end - jp->p < 4) { jp_fail(jp, "bad \\u escape"); goto bad; }
            int cp = hex4(jp->p);
            if (cp < 0) { jp_fail(jp, "bad \\u escape"); goto bad; }
            jp->p += 4;
            uint32_t u = (uint32_t)cp;
            if (u >= 0xD800 && u < 0xDC00) {
                if (jp->end - jp->p >= 6 && jp->p[0] == '\\' && jp->p[1] == 'u') {
                    int lo = hex4(jp->p + 2);
                    if (lo >= 0xDC00 && lo < 0xE000) {
                        u = 0x10000 + ((u - 0xD800) << 10) + ((uint32_t)lo - 0xDC00);
                        jp->p += 6;
                    } else u = 0xFFFD;
                } else u = 0xFFFD;
            } else if (u >= 0xDC00 && u < 0xE000) u = 0xFFFD;
            if (u == 0) { jp_fail(jp, "NUL in string"); goto bad; }
            n += (size_t)utf8_put(out + n, u);
            break;
        }
        default: jp_fail(jp, "bad escape"); goto bad;
        }
    }
    jp_fail(jp, "unterminated string");
bad:
    free(out);
    return NULL;
}

static JVal *jp_value(JParser *jp);

static JVal *jv_new(JType t) {
    JVal *v = calloc(1, sizeof(JVal));
    if (v) v->t = t;
    return v;
}

static JVal *jp_value(JParser *jp) {
    jp_ws(jp);
    if (jp->p >= jp->end) { jp_fail(jp, "unexpected end"); return NULL; }
    if (jp->depth > JSON_MAX_DEPTH) { jp_fail(jp, "nesting too deep"); return NULL; }
    char c = *jp->p;
    JVal *v = NULL;
    if (c == '{' || c == '[') {
        bool obj = (c == '{');
        char close = obj ? '}' : ']';
        v = jv_new(obj ? J_OBJ : J_ARR);
        if (!v) { jp_fail(jp, "out of memory"); return NULL; }
        jp->p++;
        jp->depth++;
        jp_ws(jp);
        if (jp->p < jp->end && *jp->p == close) { jp->p++; jp->depth--; return v; }
        for (;;) {
            char *key = NULL;
            jp_ws(jp);
            if (obj) {
                if (jp->p >= jp->end || *jp->p != '"') { jp_fail(jp, "expected object key"); goto fail; }
                key = jp_string(jp);
                if (!key) goto fail;
                jp_ws(jp);
                if (jp->p >= jp->end || *jp->p != ':') { free(key); jp_fail(jp, "expected ':'"); goto fail; }
                jp->p++;
            }
            JVal *item = jp_value(jp);
            if (!item) { free(key); goto fail; }
            if (!jv_push(v, key, item)) { free(key); jfree(item); jp_fail(jp, "too many items"); goto fail; }
            jp_ws(jp);
            if (jp->p >= jp->end) { jp_fail(jp, "unexpected end"); goto fail; }
            if (*jp->p == ',') { jp->p++; continue; }
            if (*jp->p == close) { jp->p++; break; }
            jp_fail(jp, "expected ',' or closing bracket");
            goto fail;
        }
        jp->depth--;
        return v;
    fail:
        jp->depth--;
        jfree(v);
        return NULL;
    }
    if (c == '"') {
        char *s = jp_string(jp);
        if (!s) return NULL;
        v = jv_new(J_STR);
        if (!v) { free(s); jp_fail(jp, "out of memory"); return NULL; }
        v->s = s;
        return v;
    }
    if (jp->end - jp->p >= 4 && strncmp(jp->p, "true", 4) == 0) { jp->p += 4; v = jv_new(J_BOOL); if (v) v->b = true; return v; }
    if (jp->end - jp->p >= 5 && strncmp(jp->p, "false", 5) == 0) { jp->p += 5; return jv_new(J_BOOL); }
    if (jp->end - jp->p >= 4 && strncmp(jp->p, "null", 4) == 0) { jp->p += 4; return jv_new(J_NULL); }
    if (c == '-' || (c >= '0' && c <= '9')) {
        const char *st = jp->p;
        const char *q = st;
        bool isint = true;
        if (*q == '-') q++;
        if (q >= jp->end || !(*q >= '0' && *q <= '9')) { jp_fail(jp, "bad number"); return NULL; }
        if (*q == '0' && q + 1 < jp->end && q[1] >= '0' && q[1] <= '9') { jp_fail(jp, "bad number"); return NULL; }
        while (q < jp->end && *q >= '0' && *q <= '9') q++;
        if (q < jp->end && *q == '.') {
            isint = false; q++;
            if (q >= jp->end || !(*q >= '0' && *q <= '9')) { jp_fail(jp, "bad number"); return NULL; }
            while (q < jp->end && *q >= '0' && *q <= '9') q++;
        }
        if (q < jp->end && (*q == 'e' || *q == 'E')) {
            isint = false; q++;
            if (q < jp->end && (*q == '+' || *q == '-')) q++;
            if (q >= jp->end || !(*q >= '0' && *q <= '9')) { jp_fail(jp, "bad number"); return NULL; }
            while (q < jp->end && *q >= '0' && *q <= '9') q++;
        }
        char tmp[64];
        size_t l = (size_t)(q - st);
        if (l >= sizeof(tmp)) { jp_fail(jp, "number too long"); return NULL; }
        memcpy(tmp, st, l);
        tmp[l] = '\0';
        v = jv_new(J_NUM);
        if (!v) return NULL;
        v->num = strtod(tmp, NULL);
        if (isint) {
            errno = 0;
            long long ll = strtoll(tmp, NULL, 10);
            if (errno == 0) { v->ll = ll; v->is_int = true; }
        }
        jp->p = q;
        return v;
    }
    jp_fail(jp, "unexpected character");
    return NULL;
}

/* Trả về NULL + message nếu lỗi. Từ chối dữ liệu thừa phía sau. */
static JVal *json_parse(const char *data, size_t len, char *err, size_t errsz) {
    JParser jp;
    memset(&jp, 0, sizeof(jp));
    jp.p = data; jp.end = data + len; jp.start = data;
    JVal *v = jp_value(&jp);
    if (v) {
        jp_ws(&jp);
        if (jp.p != jp.end) { jp_fail(&jp, "unexpected trailing data"); jfree(v); v = NULL; }
    }
    if (!v && err) snprintf(err, errsz, "%s", jp.err[0] ? jp.err : "invalid JSON");
    return v;
}

static JVal *jget(const JVal *o, const char *key) {
    if (!o || o->t != J_OBJ) return NULL;
    for (int i = 0; i < o->n; i++) if (strcmp(o->keys[i], key) == 0) return o->items[i];
    return NULL;
}

/* Truy cập kiểu: trả false nếu thiếu / sai kiểu (null được coi là thiếu, giống encoding/json của Go) */
static bool jstr(const JVal *o, const char *key, const char **out) {
    JVal *v = jget(o, key);
    if (!v || v->t == J_NULL) return true;
    if (v->t != J_STR) return false;
    *out = v->s;
    return true;
}

static bool jint(const JVal *o, const char *key, long long *out) {
    JVal *v = jget(o, key);
    if (!v || v->t == J_NULL) return true;
    if (v->t != J_NUM || !v->is_int) return false;
    *out = v->ll;
    return true;
}

static bool jbool(const JVal *o, const char *key, bool *out) {
    JVal *v = jget(o, key);
    if (!v || v->t == J_NULL) return true;
    if (v->t != J_BOOL) return false;
    *out = v->b;
    return true;
}

/* ---- builder ---- */
typedef struct {
    char *p;
    size_t len, cap;
} Buf;

static bool buf_reserve(Buf *b, size_t add) {
    if (b->len + add + 1 <= b->cap) return true;
    size_t ncap = b->cap ? b->cap : 1024;
    while (ncap < b->len + add + 1) ncap *= 2;
    if (ncap > (size_t)64 * 1024 * 1024) return false;
    char *np = realloc(b->p, ncap);
    if (!np) return false;
    b->p = np;
    b->cap = ncap;
    return true;
}

static void buf_printf(Buf *b, const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0 && buf_reserve(b, (size_t)n)) {
        vsnprintf(b->p + b->len, (size_t)n + 1, fmt, ap2);
        b->len += (size_t)n;
    }
    va_end(ap2);
}

static void buf_putc(Buf *b, char c) {
    if (buf_reserve(b, 1)) { b->p[b->len++] = c; b->p[b->len] = '\0'; }
}

static void buf_puts(Buf *b, const char *s) {
    size_t n = strlen(s);
    if (buf_reserve(b, n)) { memcpy(b->p + b->len, s, n + 1); b->len += n; }
}

/* JSON string: escape ", \, ký tự điều khiển và < > & (an toàn khi nhúng vào HTML) */
static void buf_json_str(Buf *b, const char *s) {
    buf_putc(b, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"') buf_puts(b, "\\\"");
        else if (c == '\\') buf_puts(b, "\\\\");
        else if (c == '\n') buf_puts(b, "\\n");
        else if (c == '\r') buf_puts(b, "\\r");
        else if (c == '\t') buf_puts(b, "\\t");
        else if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == 0x7f) buf_printf(b, "\\u%04x", c);
        else buf_putc(b, (char)c);
    }
    buf_putc(b, '"');
}

static void buf_free(Buf *b) { free(b->p); b->p = NULL; b->len = b->cap = 0; }

/* ========================== FILE HELPERS ========================== */
static char *read_file_all(const char *path, size_t maxlen, size_t *outlen, int *err) {
    FILE *f = fopen(path, "rb");
    if (!f) { if (err) *err = errno; return NULL; }
    size_t cap = 4096, n = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); if (err) *err = ENOMEM; return NULL; }
    for (;;) {
        if (n + 1 >= cap) {
            cap *= 2;
            if (cap > maxlen + 2) { free(buf); fclose(f); if (err) *err = EFBIG; return NULL; }
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); fclose(f); if (err) *err = ENOMEM; return NULL; }
            buf = nb;
        }
        size_t r = fread(buf + n, 1, cap - n - 1, f);
        if (r == 0) break;
        n += r;
        if (n > maxlen) { free(buf); fclose(f); if (err) *err = EFBIG; return NULL; }
    }
    fclose(f);
    buf[n] = '\0';
    if (outlen) *outlen = n;
    return buf;
}

/* Ghi file tạm rồi rename (atomic): crash giữa chừng không làm hỏng file hiện có. */
static int write_file_atomic(const char *path, const char *data, size_t len, mode_t mode) {
    char tmp[600];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return ENAMETOOLONG;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return errno;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; int e = errno; close(fd); unlink(tmp); return e; }
        off += (size_t)w;
    }
    if (fsync(fd) < 0) { /* không critical */ }
    close(fd);
    if (rename(tmp, path) < 0) { int e = errno; unlink(tmp); return e; }
    return 0;
}

/* ========================== CONFIG (JSON, cùng định dạng với bản Go) ========================== */
#define MAX_USERS     1000
#define MAX_TOKENS    100
#define MAX_LIST      1000
#define LIST_ITEM_LEN 256
#define CONFIG_MAX_BYTES (5 * 1024 * 1024)

typedef struct {
    char username[NAME_LEN];
    char hash[PW_HASH_MAX + 1];
    long long max_bw_bps;       /* 0 = không giới hạn */
    long long max_conns;        /* 0 = không giới hạn */
    long long quota_bytes;      /* 0 = không giới hạn */
} UserCfg;

typedef struct {
    char name[NAME_LEN];
    char token_hash[72];
    long long created_at;
} TokenCfg;

typedef struct {
    char dash_user[NAME_LEN * 2];
    char dash_hash[PW_HASH_MAX + 1];
    UserCfg *users; int nusers;
    char **allow; int nallow;
    char **deny; int ndeny;
    char **upstream; int nupstream;
    TokenCfg *tokens; int ntokens;
    bool require_proxy_auth;
} Config;

static Config g_cfg;
static pthread_mutex_t cfg_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_config_path[512] = "proxy_config.json";

static void strlist_free(char **v, int n) {
    for (int i = 0; i < n; i++) free(v[i]);
    free(v);
}

static bool strlist_add(char ***v, int *n, const char *s) {
    if (*n >= MAX_LIST) return false;
    char **nv = realloc(*v, sizeof(char *) * (size_t)(*n + 1));
    if (!nv) return false;
    *v = nv;
    char *d = strdup(s);
    if (!d) return false;
    (*v)[(*n)++] = d;
    return true;
}

static void cfg_free(Config *c) {
    free(c->users);
    strlist_free(c->allow, c->nallow);
    strlist_free(c->deny, c->ndeny);
    strlist_free(c->upstream, c->nupstream);
    free(c->tokens);
    memset(c, 0, sizeof(*c));
}

static bool cfg_str_array(const JVal *root, const char *key, char ***out, int *n, char *err, size_t errsz) {
    JVal *a = jget(root, key);
    if (!a || a->t == J_NULL) return true;
    if (a->t != J_ARR) { snprintf(err, errsz, "trường '%s' phải là mảng chuỗi", key); return false; }
    for (int i = 0; i < a->n; i++) {
        if (a->items[i]->t != J_STR) { snprintf(err, errsz, "trường '%s' phải là mảng chuỗi", key); return false; }
        if (strlen(a->items[i]->s) >= LIST_ITEM_LEN) { snprintf(err, errsz, "phần tử của '%s' quá dài", key); return false; }
        if (!strlist_add(out, n, a->items[i]->s)) { snprintf(err, errsz, "trường '%s' có quá nhiều phần tử (tối đa %d)", key, MAX_LIST); return false; }
    }
    return true;
}

static bool copy_checked(char *dst, size_t dsz, const char *src, const char *what, char *err, size_t errsz) {
    if (strlen(src) >= dsz) { snprintf(err, errsz, "%s quá dài", what); return false; }
    snprintf(dst, dsz, "%s", src);
    return true;
}

static long long clamp_ll(long long v, long long lo, long long hi) { return v < lo ? lo : (v > hi ? hi : v); }

/* Phân tích JSON -> Config. Không kiểm tra dashboard creds (người gọi tự quyết định). */
static bool cfg_from_json(const JVal *root, Config *out, char *err, size_t errsz) {
    memset(out, 0, sizeof(*out));
    if (!root || root->t != J_OBJ) { snprintf(err, errsz, "gốc của JSON phải là object"); return false; }
    const char *s;
    s = NULL; if (!jstr(root, "dashboard_user", &s)) { snprintf(err, errsz, "'dashboard_user' phải là chuỗi"); goto fail; }
    if (s && !copy_checked(out->dash_user, sizeof(out->dash_user), s, "dashboard_user", err, errsz)) goto fail;
    s = NULL; if (!jstr(root, "dashboard_password_hash", &s)) { snprintf(err, errsz, "'dashboard_password_hash' phải là chuỗi"); goto fail; }
    if (s && !copy_checked(out->dash_hash, sizeof(out->dash_hash), s, "dashboard_password_hash", err, errsz)) goto fail;
    if (!jbool(root, "require_proxy_auth", &out->require_proxy_auth)) { snprintf(err, errsz, "'require_proxy_auth' phải là true/false"); goto fail; }

    JVal *ua = jget(root, "users");
    if (ua && ua->t != J_NULL) {
        if (ua->t != J_ARR) { snprintf(err, errsz, "'users' phải là mảng"); goto fail; }
        if (ua->n > MAX_USERS) { snprintf(err, errsz, "quá nhiều user (tối đa %d)", MAX_USERS); goto fail; }
        out->users = calloc((size_t)(ua->n ? ua->n : 1), sizeof(UserCfg));
        if (!out->users) { snprintf(err, errsz, "hết bộ nhớ"); goto fail; }
        for (int i = 0; i < ua->n; i++) {
            JVal *u = ua->items[i];
            UserCfg *d = &out->users[out->nusers];
            if (u->t != J_OBJ) { snprintf(err, errsz, "phần tử của 'users' phải là object"); goto fail; }
            const char *name = NULL, *hash = NULL;
            long long bw = 0, mc = 0, q = 0;
            if (!jstr(u, "username", &name) || !jstr(u, "password_hash", &hash) ||
                !jint(u, "max_bandwidth_bps", &bw) || !jint(u, "max_connections", &mc) ||
                !jint(u, "quota_bytes_per_month", &q)) { snprintf(err, errsz, "user #%d sai kiểu dữ liệu", i + 1); goto fail; }
            if (!name || !*name || strlen(name) >= NAME_LEN) { snprintf(err, errsz, "user #%d có username rỗng hoặc dài quá %d ký tự", i + 1, NAME_LEN - 1); goto fail; }
            if (hash && !copy_checked(d->hash, sizeof(d->hash), hash, "password_hash", err, errsz)) goto fail;
            snprintf(d->username, sizeof(d->username), "%s", name);
            d->max_bw_bps = bw < 0 ? 0 : bw;
            d->max_conns = clamp_ll(mc, 0, 1000000000LL);
            d->quota_bytes = q < 0 ? 0 : q;
            out->nusers++;
        }
    }
    if (!cfg_str_array(root, "allow_list", &out->allow, &out->nallow, err, errsz)) goto fail;
    if (!cfg_str_array(root, "deny_list", &out->deny, &out->ndeny, err, errsz)) goto fail;
    if (!cfg_str_array(root, "upstream_proxies", &out->upstream, &out->nupstream, err, errsz)) goto fail;

    JVal *ta = jget(root, "api_tokens");
    if (ta && ta->t != J_NULL) {
        if (ta->t != J_ARR) { snprintf(err, errsz, "'api_tokens' phải là mảng"); goto fail; }
        if (ta->n > MAX_TOKENS) { snprintf(err, errsz, "quá nhiều token (tối đa %d)", MAX_TOKENS); goto fail; }
        out->tokens = calloc((size_t)(ta->n ? ta->n : 1), sizeof(TokenCfg));
        if (!out->tokens) { snprintf(err, errsz, "hết bộ nhớ"); goto fail; }
        for (int i = 0; i < ta->n; i++) {
            JVal *t = ta->items[i];
            if (t->t != J_OBJ) { snprintf(err, errsz, "phần tử của 'api_tokens' phải là object"); goto fail; }
            const char *name = NULL, *th = NULL;
            long long created = 0;
            if (!jstr(t, "name", &name) || !jstr(t, "token_hash", &th) || !jint(t, "created_at", &created)) {
                snprintf(err, errsz, "token #%d sai kiểu dữ liệu", i + 1); goto fail;
            }
            if (!name || !*name || strlen(name) >= NAME_LEN) { snprintf(err, errsz, "token #%d có tên rỗng hoặc dài quá %d ký tự", i + 1, NAME_LEN - 1); goto fail; }
            TokenCfg *d = &out->tokens[out->ntokens];
            snprintf(d->name, sizeof(d->name), "%s", name);
            if (th && !copy_checked(d->token_hash, sizeof(d->token_hash), th, "token_hash", err, errsz)) goto fail;
            d->created_at = created;
            out->ntokens++;
        }
    }
    return true;
fail:
    cfg_free(out);
    return false;
}

static void json_indent(Buf *b, int n) { for (int i = 0; i < n; i++) buf_puts(b, "  "); }

static void json_str_array(Buf *b, const char *key, char **v, int n, bool *first) {
    if (n == 0) return;
    buf_puts(b, *first ? "\n" : ",\n");
    *first = false;
    json_indent(b, 1);
    buf_json_str(b, key);
    buf_puts(b, ": [\n");
    for (int i = 0; i < n; i++) {
        json_indent(b, 2);
        buf_json_str(b, v[i]);
        buf_puts(b, i + 1 < n ? ",\n" : "\n");
    }
    json_indent(b, 1);
    buf_puts(b, "]");
}

/* Xuất Config ra JSON (thụt lề 2 space, thứ tự khoá và omitempty giống bản Go). */
static void cfg_to_json(const Config *c, Buf *b) {
    bool first = true;
    buf_puts(b, "{");
    buf_puts(b, "\n"); first = false;
    json_indent(b, 1); buf_puts(b, "\"dashboard_user\": "); buf_json_str(b, c->dash_user);
    buf_puts(b, ",\n"); json_indent(b, 1); buf_puts(b, "\"dashboard_password_hash\": "); buf_json_str(b, c->dash_hash);
    if (c->nusers > 0) {
        buf_puts(b, ",\n"); json_indent(b, 1); buf_puts(b, "\"users\": [\n");
        for (int i = 0; i < c->nusers; i++) {
            const UserCfg *u = &c->users[i];
            json_indent(b, 2); buf_puts(b, "{\n");
            json_indent(b, 3); buf_puts(b, "\"username\": "); buf_json_str(b, u->username); buf_puts(b, ",\n");
            json_indent(b, 3); buf_puts(b, "\"password_hash\": "); buf_json_str(b, u->hash); buf_puts(b, ",\n");
            json_indent(b, 3); buf_printf(b, "\"max_bandwidth_bps\": %lld,\n", u->max_bw_bps);
            json_indent(b, 3); buf_printf(b, "\"max_connections\": %lld,\n", u->max_conns);
            json_indent(b, 3); buf_printf(b, "\"quota_bytes_per_month\": %lld\n", u->quota_bytes);
            json_indent(b, 2); buf_puts(b, i + 1 < c->nusers ? "},\n" : "}\n");
        }
        json_indent(b, 1); buf_puts(b, "]");
    }
    json_str_array(b, "allow_list", c->allow, c->nallow, &first);
    json_str_array(b, "deny_list", c->deny, c->ndeny, &first);
    json_str_array(b, "upstream_proxies", c->upstream, c->nupstream, &first);
    if (c->ntokens > 0) {
        buf_puts(b, ",\n"); json_indent(b, 1); buf_puts(b, "\"api_tokens\": [\n");
        for (int i = 0; i < c->ntokens; i++) {
            const TokenCfg *t = &c->tokens[i];
            json_indent(b, 2); buf_puts(b, "{\n");
            json_indent(b, 3); buf_puts(b, "\"name\": "); buf_json_str(b, t->name); buf_puts(b, ",\n");
            json_indent(b, 3); buf_puts(b, "\"token_hash\": "); buf_json_str(b, t->token_hash); buf_puts(b, ",\n");
            json_indent(b, 3); buf_printf(b, "\"created_at\": %lld\n", t->created_at);
            json_indent(b, 2); buf_puts(b, i + 1 < c->ntokens ? "},\n" : "}\n");
        }
        json_indent(b, 1); buf_puts(b, "]");
    }
    if (c->require_proxy_auth) {
        buf_puts(b, ",\n"); json_indent(b, 1); buf_puts(b, "\"require_proxy_auth\": true");
    }
    buf_puts(b, "\n}");
}

/* Lưu g_cfg (người gọi PHẢI đang giữ cfg_mutex). Trả 0 nếu ok, errno nếu lỗi. */
static int cfg_save_locked(void) {
    Buf b = {0};
    cfg_to_json(&g_cfg, &b);
    if (!b.p) return ENOMEM;
    int rc = write_file_atomic(g_config_path, b.p, b.len, 0600);
    buf_free(&b);
    return rc;
}

static bool cfg_valid_creds(const Config *c) { return c->dash_user[0] && c->dash_hash[0]; }

/* ========================== CIDR allow / deny ========================== */
typedef struct { uint8_t addr[16]; int prefix; } Cidr;   /* prefix tính trong không gian 128 bit (IPv4 = 96 + n) */
typedef struct { Cidr *v; int n; } CidrList;

static CidrList g_allow_list, g_deny_list;
static pthread_mutex_t cidr_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool cidr_parse(const char *item, Cidr *out) {
    char tmp[LIST_ITEM_LEN + 8];
    if (strlen(item) >= LIST_ITEM_LEN) return false;
    snprintf(tmp, sizeof(tmp), "%s", item);
    char *slash = strchr(tmp, '/');
    bool v6 = strchr(tmp, ':') != NULL;
    int prefix;
    if (slash) {
        *slash = '\0';
        char *e = NULL;
        long p = strtol(slash + 1, &e, 10);
        if (!*(slash + 1) || *e || p < 0) return false;
        prefix = (int)p;
    } else {
        prefix = v6 ? 128 : 32;
    }
    if (v6) {
        struct in6_addr a6;
        if (prefix > 128 || inet_pton(AF_INET6, tmp, &a6) != 1) return false;
        memcpy(out->addr, &a6, 16);
        out->prefix = prefix;
    } else {
        struct in_addr a4;
        if (prefix > 32 || inet_pton(AF_INET, tmp, &a4) != 1) return false;
        memset(out->addr, 0, 16);
        out->addr[10] = 0xff; out->addr[11] = 0xff;
        memcpy(out->addr + 12, &a4, 4);
        out->prefix = 96 + prefix;
    }
    return true;
}

static bool cidr_contains(const Cidr *c, const uint8_t ip[16]) {
    int full = c->prefix / 8, rem = c->prefix % 8;
    if (full > 0 && memcmp(c->addr, ip, (size_t)full) != 0) return false;
    if (rem) {
        uint8_t mask = (uint8_t)(0xFF << (8 - rem));
        if ((c->addr[full] & mask) != (ip[full] & mask)) return false;
    }
    return true;
}

static void trim_inplace(char *s) {
    char *st = s;
    while (*st == ' ' || *st == '\t' || *st == '\r' || *st == '\n') st++;
    size_t l = strlen(st);
    while (l > 0 && (st[l-1] == ' ' || st[l-1] == '\t' || st[l-1] == '\r' || st[l-1] == '\n')) st[--l] = '\0';
    if (st != s) memmove(s, st, strlen(st) + 1);
}

/* Entry sai định dạng chỉ bị bỏ qua, nhưng được báo lại qua invalid[] (hiện trong lịch sử reload) */
static void cidr_build(char **items, int n, CidrList *out, char ***invalid, int *ninvalid) {
    out->v = calloc((size_t)(n ? n : 1), sizeof(Cidr));
    out->n = 0;
    for (int i = 0; i < n; i++) {
        char item[LIST_ITEM_LEN];
        snprintf(item, sizeof(item), "%s", items[i]);
        trim_inplace(item);
        if (!*item) continue;
        if (out->v && cidr_parse(item, &out->v[out->n])) out->n++;
        else {
            log_error("CIDR không hợp lệ, bỏ qua: %s", item);
            if (invalid) strlist_add(invalid, ninvalid, item);
        }
    }
}

static bool ip_allowed_canon(const uint8_t ip[16]) {
    bool ok = true;
    pthread_mutex_lock(&cidr_mutex);
    for (int i = 0; i < g_deny_list.n; i++)
        if (cidr_contains(&g_deny_list.v[i], ip)) { ok = false; break; }
    if (ok && g_allow_list.n > 0) {
        ok = false;
        for (int i = 0; i < g_allow_list.n; i++)
            if (cidr_contains(&g_allow_list.v[i], ip)) { ok = true; break; }
    }
    pthread_mutex_unlock(&cidr_mutex);
    return ok;
}

static void cidr_set_lists(CidrList *allow, CidrList *deny) {
    pthread_mutex_lock(&cidr_mutex);
    free(g_allow_list.v); free(g_deny_list.v);
    g_allow_list = *allow;
    g_deny_list = *deny;
    pthread_mutex_unlock(&cidr_mutex);
}

/* ========================== USAGE / QUOTA THEO THÁNG ========================== */
#define USAGE_SLOTS 1100
typedef struct {
    bool used;
    char user[NAME_LEN];
    char period[8];          /* "YYYY-MM" */
    long long bytes;
} UsageRec;

static UsageRec g_usage[USAGE_SLOTS];
static pthread_mutex_t usage_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_usage_path[512] = "proxy_usage.json";
static int g_usage_dirty = 0;      /* truy cập atomic */

static void current_period(char out[8]) {
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(out, 8, "%Y-%m", &tmv);
}

/* Trả về chỉ số bản ghi (tạo nếu chưa có), -1 nếu bảng đầy */
static int usage_index(const char *user) {
    if (!user || !*user) return -1;
    int idx = -1;
    pthread_mutex_lock(&usage_mutex);
    for (int i = 0; i < USAGE_SLOTS; i++) {
        if (g_usage[i].used && strcmp(g_usage[i].user, user) == 0) { idx = i; break; }
    }
    if (idx < 0) {
        for (int i = 0; i < USAGE_SLOTS; i++) {
            if (!g_usage[i].used) {
                g_usage[i].used = true;
                snprintf(g_usage[i].user, sizeof(g_usage[i].user), "%s", user);
                g_usage[i].period[0] = '\0';
                g_usage[i].bytes = 0;
                idx = i;
                break;
            }
        }
    }
    pthread_mutex_unlock(&usage_mutex);
    return idx;
}

static void usage_add_idx(int idx, long long n) {
    if (idx < 0 || idx >= USAGE_SLOTS || n <= 0) return;
    char per[8];
    current_period(per);
    pthread_mutex_lock(&usage_mutex);
    UsageRec *r = &g_usage[idx];
    if (strcmp(r->period, per) != 0) { snprintf(r->period, sizeof(r->period), "%s", per); r->bytes = 0; }
    r->bytes += n;
    pthread_mutex_unlock(&usage_mutex);
    __atomic_store_n(&g_usage_dirty, 1, __ATOMIC_RELAXED);
}

static long long usage_get(const char *user) {
    char per[8];
    current_period(per);
    long long v = 0;
    pthread_mutex_lock(&usage_mutex);
    for (int i = 0; i < USAGE_SLOTS; i++) {
        if (g_usage[i].used && strcmp(g_usage[i].user, user) == 0) {
            if (strcmp(g_usage[i].period, per) == 0) v = g_usage[i].bytes;
            break;
        }
    }
    pthread_mutex_unlock(&usage_mutex);
    return v;
}

static void usage_load(const char *path) {
    if (!path[0]) return;
    size_t len;
    char *data = read_file_all(path, CONFIG_MAX_BYTES, &len, NULL);
    if (!data) return;
    char err[96];
    JVal *root = json_parse(data, len, err, sizeof(err));
    free(data);
    if (!root || root->t != J_OBJ) { jfree(root); log_error("usage file %s lỗi định dạng, bỏ qua", path); return; }
    for (int i = 0; i < root->n; i++) {
        JVal *r = root->items[i];
        const char *per = NULL; long long bytes = 0;
        if (r->t != J_OBJ || !jstr(r, "period", &per) || !jint(r, "bytes_used", &bytes) || !per) continue;
        if (strlen(root->keys[i]) >= NAME_LEN || strlen(per) >= 8) continue;
        int idx = usage_index(root->keys[i]);
        if (idx < 0) continue;
        pthread_mutex_lock(&usage_mutex);
        snprintf(g_usage[idx].period, sizeof(g_usage[idx].period), "%s", per);
        g_usage[idx].bytes = bytes < 0 ? 0 : bytes;
        pthread_mutex_unlock(&usage_mutex);
    }
    jfree(root);
}

static int usage_save(const char *path) {
    if (!path[0]) return 0;
    Buf b = {0};
    buf_puts(&b, "{");
    pthread_mutex_lock(&usage_mutex);
    bool first = true;
    for (int i = 0; i < USAGE_SLOTS; i++) {
        if (!g_usage[i].used || !g_usage[i].period[0]) continue;
        buf_puts(&b, first ? "\n  " : ",\n  ");
        first = false;
        buf_json_str(&b, g_usage[i].user);
        buf_puts(&b, ": {\"period\": ");
        buf_json_str(&b, g_usage[i].period);
        buf_printf(&b, ", \"bytes_used\": %lld}", g_usage[i].bytes);
    }
    pthread_mutex_unlock(&usage_mutex);
    buf_puts(&b, "\n}\n");
    int rc = b.p ? write_file_atomic(path, b.p, b.len, 0644) : ENOMEM;
    buf_free(&b);
    return rc;
}

/* ========================== AUDIT LOG + LỊCH SỬ RELOAD ========================== */
#define AUDIT_MAX 200
#define RELOAD_MAX 30
#define RELOAD_INVALID_MAX 20

typedef struct { time_t t; char actor[96]; char action[48]; char details[400]; } AuditEv;
static AuditEv g_audit[AUDIT_MAX];
static int g_audit_count = 0, g_audit_next = 0;
static pthread_mutex_t audit_mutex = PTHREAD_MUTEX_INITIALIZER;

static void audit_record(const char *actor, const char *action, const char *details) {
    pthread_mutex_lock(&audit_mutex);
    AuditEv *e = &g_audit[g_audit_next];
    e->t = time(NULL);
    snprintf(e->actor, sizeof(e->actor), "%s", actor ? actor : "unknown");
    snprintf(e->action, sizeof(e->action), "%s", action);
    snprintf(e->details, sizeof(e->details), "%s", details ? details : "");
    g_audit_next = (g_audit_next + 1) % AUDIT_MAX;
    if (g_audit_count < AUDIT_MAX) g_audit_count++;
    pthread_mutex_unlock(&audit_mutex);
}

typedef struct {
    time_t t;
    char source[96];
    bool success;
    char error[256];
    int allow_count, deny_count, upstream_count, user_count;
    char invalid[RELOAD_INVALID_MAX][LIST_ITEM_LEN];
    int ninvalid;
} ReloadEv;
static ReloadEv g_reloads[RELOAD_MAX];
static int g_reload_count = 0, g_reload_next = 0;
static pthread_mutex_t reload_mutex = PTHREAD_MUTEX_INITIALIZER;

static void reload_record(const ReloadEv *ev) {
    pthread_mutex_lock(&reload_mutex);
    g_reloads[g_reload_next] = *ev;
    g_reload_next = (g_reload_next + 1) % RELOAD_MAX;
    if (g_reload_count < RELOAD_MAX) g_reload_count++;
    pthread_mutex_unlock(&reload_mutex);
}

/* Được định nghĩa ở phần proxy core */
static void upstreams_apply(char **items, int n);
static void apply_live_bandwidth(const char *username, long long new_limit);

/* Đọc lại config từ đĩa, VALIDATE trước, rồi áp dụng (không ngắt kết nối đang chạy).
   Mọi lần gọi đều được ghi vào lịch sử reload. Trả true nếu thành công. */
static bool reload_config(const char *source, char *errbuf, size_t errsz) {
    ReloadEv ev;
    memset(&ev, 0, sizeof(ev));
    ev.t = time(NULL);
    snprintf(ev.source, sizeof(ev.source), "%s", source);
    char err[256] = "";
    Config nc;
    bool have = false;
    int ferr = 0;
    size_t len = 0;
    char *data = read_file_all(g_config_path, CONFIG_MAX_BYTES, &len, &ferr);
    if (!data) {
        snprintf(err, sizeof(err), "không đọc được config file: %s", strerror(ferr));
    } else {
        char jerr[96];
        JVal *root = json_parse(data, len, jerr, sizeof(jerr));
        free(data);
        if (!root) snprintf(err, sizeof(err), "config file lỗi định dạng JSON: %s", jerr);
        else {
            char cerr[160] = "";
            if (!cfg_from_json(root, &nc, cerr, sizeof(cerr))) snprintf(err, sizeof(err), "config file không hợp lệ: %s", cerr);
            else if (!cfg_valid_creds(&nc)) { snprintf(err, sizeof(err), "config file thiếu dashboard_user/dashboard_password_hash"); cfg_free(&nc); }
            else have = true;
            jfree(root);
        }
    }
    if (!have) {
        ev.success = false;
        snprintf(ev.error, sizeof(ev.error), "%s", err);
        reload_record(&ev);
        if (errbuf) snprintf(errbuf, errsz, "%s", err);
        return false;
    }
    CidrList na, nd;
    char **invalid = NULL; int ninvalid = 0;
    cidr_build(nc.allow, nc.nallow, &na, &invalid, &ninvalid);
    cidr_build(nc.deny, nc.ndeny, &nd, &invalid, &ninvalid);
    ev.allow_count = na.n; ev.deny_count = nd.n;
    ev.upstream_count = nc.nupstream; ev.user_count = nc.nusers;
    for (int i = 0; i < ninvalid && i < RELOAD_INVALID_MAX; i++) {
        snprintf(ev.invalid[ev.ninvalid], LIST_ITEM_LEN, "%s", invalid[i]);
        ev.ninvalid++;
    }
    cidr_set_lists(&na, &nd);
    upstreams_apply(nc.upstream, nc.nupstream);

    /* snapshot user để đẩy giới hạn băng thông live mà không giữ lock */
    int nu = nc.nusers;
    UserCfg *snap = nu ? malloc(sizeof(UserCfg) * (size_t)nu) : NULL;
    if (snap) memcpy(snap, nc.users, sizeof(UserCfg) * (size_t)nu);
    pthread_mutex_lock(&cfg_mutex);
    cfg_free(&g_cfg);
    g_cfg = nc;
    pthread_mutex_unlock(&cfg_mutex);
    if (snap) {
        for (int i = 0; i < nu; i++) apply_live_bandwidth(snap[i].username, snap[i].max_bw_bps);
        free(snap);
    }
    log_info("Đã reload config (nguồn: %s): %d IP whitelist, %d IP blacklist, %d upstream, %d proxy user%s",
             source, ev.allow_count, ev.deny_count, ev.upstream_count, ev.user_count,
             ninvalid ? " (CẢNH BÁO: có CIDR không hợp lệ bị bỏ qua)" : "");
    ev.success = true;
    reload_record(&ev);
    strlist_free(invalid, ninvalid);
    return true;
}

/* ========================== STATS ========================== */
static void stats_increment(const char *type) {
    pthread_mutex_lock(&stats_mutex);
    g_stats.total++;
    g_stats.current++;
    if (strcmp(type, "SOCKS5_TCP") == 0) g_stats.socks5_tcp++;
    else if (strcmp(type, "SOCKS5_UDP") == 0) g_stats.socks5_udp++;
    else if (strcmp(type, "HTTP") == 0) g_stats.http++;
    pthread_mutex_unlock(&stats_mutex);
}

static void stats_decrement(void) {
    pthread_mutex_lock(&stats_mutex);
    if (g_stats.current > 0) g_stats.current--;
    pthread_mutex_unlock(&stats_mutex);
}

static void stats_auth_fail(void) {
    pthread_mutex_lock(&stats_mutex);
    g_stats.auth_fail++;
    pthread_mutex_unlock(&stats_mutex);
}

static void stats_add_bytes(int direction, long long bytes) {
    pthread_mutex_lock(&stats_mutex);
    if (direction == 0) g_stats.bytes_up += bytes;
    else g_stats.bytes_down += bytes;
    pthread_mutex_unlock(&stats_mutex);
}

/* ========================== ACTIVE CONNECTIONS ========================== */
/* Trả về slot (>=0) hoặc -1 nếu bảng đầy. Slot chỉ do luồng sở hữu giải phóng. */
static int active_add(const char *ip, int port, const char *type, const char *target,
                      const char *user, long long rate, int client_fd) {
    int slot = -1;
    pthread_mutex_lock(&active_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_active_conns[i].used) continue;
        ActiveConn *c = &g_active_conns[i];
        memset(c, 0, sizeof(*c));
        c->used = true;
        c->id = ++g_conn_id_counter;
        snprintf(c->ip, sizeof(c->ip), "%s", ip);
        c->port = port;
        snprintf(c->type, sizeof(c->type), "%s", type);
        snprintf(c->target, sizeof(c->target), "%s", target);
        if (user && *user) {
            snprintf(c->user, sizeof(c->user), "%s", user);
            c->usage_idx = usage_index(user);
        } else {
            c->usage_idx = -1;
        }
        c->start_time = time(NULL);
        c->rate_bps = rate > 0 ? rate : 0;
        c->client_fd = client_fd;
        c->remote_fd = -1;
        slot = i;
        break;
    }
    pthread_mutex_unlock(&active_mutex);
    return slot;
}

static void active_set_remote(int slot, int fd) {
    if (slot < 0) return;
    pthread_mutex_lock(&active_mutex);
    g_active_conns[slot].remote_fd = fd;
    pthread_mutex_unlock(&active_mutex);
}

/* Đóng fd remote SAU KHI gỡ khỏi bảng (dưới lock) — tránh kick nhầm vào fd đã được tái sử dụng. */
static void active_close_remote(int slot, int fd) {
    if (slot >= 0) {
        pthread_mutex_lock(&active_mutex);
        g_active_conns[slot].remote_fd = -1;
        pthread_mutex_unlock(&active_mutex);
    }
    close(fd);
}

static void active_remove(int slot) {
    if (slot < 0 || slot >= MAX_CONNECTIONS) return;
    pthread_mutex_lock(&active_mutex);
    g_active_conns[slot].used = false;
    g_active_conns[slot].client_fd = -1;
    g_active_conns[slot].remote_fd = -1;
    pthread_mutex_unlock(&active_mutex);
}

static long long conn_rate(int slot) {
    if (slot < 0) return 0;
    return __atomic_load_n(&g_active_conns[slot].rate_bps, __ATOMIC_RELAXED);
}

/* Kích thước đọc mỗi lần: nhỏ lại khi có giới hạn tốc độ để mỗi lần ngủ <= ~100ms (kick vẫn kịp tác dụng) */
static size_t chunk_for(int slot) {
    long long r = conn_rate(slot);
    if (r > 0 && r / 10 < BUFFER_SIZE) return r / 10 > 0 ? (size_t)(r / 10) : 1;
    return BUFFER_SIZE;
}

static void throttle(int slot, long long n) {
    long long r = conn_rate(slot);
    if (r <= 0 || n <= 0) return;
    long long ns = n * 1000000000LL / r;
    if (ns > 1500000000LL) ns = 1500000000LL;
    if (ns <= 0) return;
    struct timespec ts = { (time_t)(ns / 1000000000LL), (long)(ns % 1000000000LL) };
    nanosleep(&ts, NULL);
}

/* Ghi nhận n byte TCP: stats tổng (live) + bộ đếm của kết nối + quota của user. */
static void stats_add_bytes(int direction, long long bytes);
static void conn_acct(int slot, int dir, long long n) {
    if (n <= 0) return;
    stats_add_bytes(dir, n);
    if (slot < 0) return;
    ActiveConn *c = &g_active_conns[slot];
    __atomic_add_fetch(dir == 0 ? &c->bytes_up : &c->bytes_down, n, __ATOMIC_RELAXED);
    if (c->usage_idx >= 0) usage_add_idx(c->usage_idx, n);
}

/* Ghi nhận n byte UDP */
static void udp_acct(int slot, int dir, long long n) {
    if (n <= 0) return;
    pthread_mutex_lock(&stats_mutex);
    if (dir == 0) g_stats.udp_up += n; else g_stats.udp_down += n;
    pthread_mutex_unlock(&stats_mutex);
    if (slot < 0) return;
    ActiveConn *c = &g_active_conns[slot];
    __atomic_add_fetch(dir == 0 ? &c->bytes_up : &c->bytes_down, n, __ATOMIC_RELAXED);
    __atomic_store_n(&c->udp_last, (long long)time(NULL), __ATOMIC_RELAXED);
    if (c->usage_idx >= 0) usage_add_idx(c->usage_idx, n);
}

static int count_user_conns(const char *user) {
    int n = 0;
    pthread_mutex_lock(&active_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++)
        if (g_active_conns[i].used && strcmp(g_active_conns[i].user, user) == 0) n++;
    pthread_mutex_unlock(&active_mutex);
    return n;
}

static int count_active(void) {
    int n = 0;
    pthread_mutex_lock(&active_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) if (g_active_conns[i].used) n++;
    pthread_mutex_unlock(&active_mutex);
    return n;
}

/* Áp dụng giới hạn băng thông mới NGAY cho các connection đang mở của user (không cần kết nối lại). */
static void apply_live_bandwidth(const char *username, long long new_limit) {
    if (!username || !*username) return;
    int n = 0;
    pthread_mutex_lock(&active_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_active_conns[i].used && strcmp(g_active_conns[i].user, username) == 0) {
            __atomic_store_n(&g_active_conns[i].rate_bps, new_limit > 0 ? new_limit : 0, __ATOMIC_RELAXED);
            n++;
        }
    }
    pthread_mutex_unlock(&active_mutex);
    if (n) log_info("Áp dụng giới hạn băng thông mới (%lld bytes/s) cho %d connection đang mở của user '%s'", new_limit, n, username);
}

static void kick_slot_locked(ActiveConn *c) {
    if (c->client_fd >= 0) shutdown(c->client_fd, SHUT_RDWR);
    if (c->remote_fd >= 0) shutdown(c->remote_fd, SHUT_RDWR);
}

/* Kick theo id ("c123"). Trả true nếu tìm thấy; điền thông tin để ghi audit. */
static bool kick_by_id(const char *id, char *info, size_t infosz) {
    bool found = false;
    pthread_mutex_lock(&active_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ActiveConn *c = &g_active_conns[i];
        if (!c->used) continue;
        char idbuf[32];
        snprintf(idbuf, sizeof(idbuf), "c%lld", c->id);
        if (strcmp(idbuf, id) != 0) continue;
        kick_slot_locked(c);
        snprintf(info, infosz, "id=%s ip=%s target=%s user=%s", idbuf, c->ip, c->target, c->user);
        found = true;
        break;
    }
    pthread_mutex_unlock(&active_mutex);
    return found;
}

static int kick_user(const char *user) {
    int n = 0;
    pthread_mutex_lock(&active_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ActiveConn *c = &g_active_conns[i];
        if (c->used && strcmp(c->user, user) == 0) { kick_slot_locked(c); n++; }
    }
    pthread_mutex_unlock(&active_mutex);
    return n;
}

/* ========================== CHỐNG BRUTE-FORCE ========================== */
typedef struct {
    char ip[64];
    int count;
    time_t first, last;
    time_t blocked_until;
} AuthFail;

static AuthFail g_authfail[AUTH_TABLE_SIZE];
static pthread_mutex_t authfail_mutex = PTHREAD_MUTEX_INITIALIZER;


static AuthFail *authfail_find(const char *ip, bool create) {
    AuthFail *oldest = &g_authfail[0];
    for (int i = 0; i < AUTH_TABLE_SIZE; i++) {
        if (g_authfail[i].ip[0] && strcmp(g_authfail[i].ip, ip) == 0) return &g_authfail[i];
        if (!g_authfail[i].ip[0]) { oldest = &g_authfail[i]; break; }
        if (g_authfail[i].last < oldest->last) oldest = &g_authfail[i];
    }
    if (!create) return NULL;
    memset(oldest, 0, sizeof(*oldest));
    snprintf(oldest->ip, sizeof(oldest->ip), "%s", ip);
    oldest->first = oldest->last = time(NULL);
    return oldest;
}

static bool auth_is_blocked(const char *ip) {
    bool blocked = false;
    pthread_mutex_lock(&authfail_mutex);
    AuthFail *e = authfail_find(ip, false);
    if (e && e->blocked_until > time(NULL)) blocked = true;
    pthread_mutex_unlock(&authfail_mutex);
    return blocked;
}

static void auth_record_fail_t(const char *ip, int threshold) {
    pthread_mutex_lock(&authfail_mutex);
    AuthFail *e = authfail_find(ip, true);
    time_t now = time(NULL);
    if (e->blocked_until && e->blocked_until <= now) { e->count = 0; e->blocked_until = 0; }
    if (e->last && now - e->last > AUTH_FAIL_WINDOW) e->count = 0;     /* lần fail trước đã quá lâu -> đợt cũ đã qua */
    e->last = now;
    e->count++;
    if (e->count >= threshold) {
        e->blocked_until = now + AUTH_BLOCK_SECONDS;
        e->count = 0;
        log_error("Chặn %s trong %d giây do sai xác thực nhiều lần", ip, AUTH_BLOCK_SECONDS);
    }
    pthread_mutex_unlock(&authfail_mutex);
}

static void auth_record_fail(const char *ip) {       /* proxy (SOCKS5/HTTP) */
    stats_auth_fail();
    auth_record_fail_t(ip, AUTH_FAIL_THRESHOLD);
}

static void auth_reset(const char *ip) {
    pthread_mutex_lock(&authfail_mutex);
    AuthFail *e = authfail_find(ip, false);
    if (e) memset(e, 0, sizeof(*e));
    pthread_mutex_unlock(&authfail_mutex);
}

/* ========================== XÁC THỰC PROXY + GIỚI HẠN USER ========================== */
/* Bắt buộc xác thực khi: có -u/-P, HOẶC đã có user tạo trên dashboard (cờ require_proxy_auth giữ trạng thái
   kể cả khi xoá hết user, để proxy không tự mở lại). */
static bool proxy_auth_required(void) {
    if (g_auth_required) return true;
    pthread_mutex_lock(&cfg_mutex);
    bool r = g_cfg.require_proxy_auth || g_cfg.nusers > 0;
    pthread_mutex_unlock(&cfg_mutex);
    return r;
}

/* user_out: tên đã xác thực (NAME_LEN); bw: giới hạn băng thông (bytes/s, 0 = không) */
static bool proxy_authenticate(const char *user, const char *pass, char *user_out, long long *bw) {
    if (g_auth_required) {
        bool u = ct_equal(user, g_username);
        bool p = ct_equal(pass, g_password);
        if (u && p) {
            snprintf(user_out, NAME_LEN, "%.63s", g_username);
            *bw = 0;
            return true;
        }
    }
    char hash[PW_HASH_MAX + 1] = "";
    long long bw_l = 0;
    bool found = false;
    char uname[NAME_LEN] = "";
    pthread_mutex_lock(&cfg_mutex);
    for (int i = 0; i < g_cfg.nusers; i++) {
        if (strcmp(g_cfg.users[i].username, user) == 0) {
            snprintf(hash, sizeof(hash), "%s", g_cfg.users[i].hash);
            snprintf(uname, sizeof(uname), "%s", g_cfg.users[i].username);
            bw_l = g_cfg.users[i].max_bw_bps;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&cfg_mutex);
    if (found && verify_password_cached(pass, hash)) {
        snprintf(user_out, NAME_LEN, "%s", uname);
        *bw = bw_l;
        return true;
    }
    return false;
}

/* Đã vượt giới hạn số connection đồng thời / quota tháng chưa? */
static bool check_user_limits(const char *user, char *reason, size_t rsz) {
    long long max_conns = 0, quota = 0;
    bool found = false;
    pthread_mutex_lock(&cfg_mutex);
    for (int i = 0; i < g_cfg.nusers; i++) {
        if (strcmp(g_cfg.users[i].username, user) == 0) {
            max_conns = g_cfg.users[i].max_conns;
            quota = g_cfg.users[i].quota_bytes;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&cfg_mutex);
    if (!found) return true;            /* chế độ -u/-P cũ: không có entry config -> không giới hạn thêm */
    if (max_conns > 0 && count_user_conns(user) >= max_conns) {
        snprintf(reason, rsz, "đã đạt giới hạn %lld connection đồng thời", max_conns);
        return false;
    }
    if (quota > 0 && usage_get(user) >= quota) {
        snprintf(reason, rsz, "đã vượt quota dung lượng tháng này");
        return false;
    }
    return true;
}

/* Cắt các connection đang chạy của user đã vượt quota tháng (quota chỉ chặn connection MỚI ở bước auth). */
static void enforce_quota(void) {
    static char names[256][NAME_LEN];
    int nn = 0;
    pthread_mutex_lock(&active_mutex);
    for (int i = 0; i < MAX_CONNECTIONS && nn < 256; i++) {
        if (!g_active_conns[i].used || !g_active_conns[i].user[0]) continue;
        bool dup = false;
        for (int j = 0; j < nn; j++) if (strcmp(names[j], g_active_conns[i].user) == 0) { dup = true; break; }
        if (!dup) snprintf(names[nn++], NAME_LEN, "%s", g_active_conns[i].user);
    }
    pthread_mutex_unlock(&active_mutex);
    int kicked = 0;
    for (int j = 0; j < nn; j++) {
        long long quota = 0;
        pthread_mutex_lock(&cfg_mutex);
        for (int i = 0; i < g_cfg.nusers; i++)
            if (strcmp(g_cfg.users[i].username, names[j]) == 0) { quota = g_cfg.users[i].quota_bytes; break; }
        pthread_mutex_unlock(&cfg_mutex);
        if (quota > 0 && usage_get(names[j]) >= quota) kicked += kick_user(names[j]);
    }
    if (kicked) log_error("Đã ngắt %d connection do user vượt quota dung lượng tháng", kicked);
}

/* ========================== UPSTREAM (danh sách runtime, cập nhật được qua dashboard / SIGHUP) ========================== */
static bool parse_upstream_spec(const char *in, Upstream *u) {
    char s[300];
    if (strlen(in) >= sizeof(s)) return false;
    snprintf(s, sizeof(s), "%s", in);
    trim_inplace(s);
    if (!*s) return false;
    memset(u, 0, sizeof(*u));
    snprintf(u->spec, sizeof(u->spec), "%s", s);
    const char *hp = s;
    if (strncasecmp(s, "socks5://", 9) == 0) { u->type = 1; hp = s + 9; }
    else if (strncasecmp(s, "http://", 7) == 0) { hp = s + 7; }
    if (parse_hostport(hp, u->host, sizeof(u->host), &u->port, 0) < 0) return false;
    u->alive = 1;
    return true;
}

static void upstreams_apply(char **items, int n) {
    Upstream nu[MAX_UPSTREAM];
    int cnt = 0;
    for (int i = 0; i < n && cnt < MAX_UPSTREAM; i++) {
        if (parse_upstream_spec(items[i], &nu[cnt])) cnt++;
        else log_error("Upstream không hợp lệ, bỏ qua: %s (dạng [http://|socks5://]host:port)", items[i]);
    }
    pthread_mutex_lock(&upstream_mutex);
    for (int i = 0; i < cnt; i++)       /* giữ trạng thái sống/chết của upstream không đổi */
        for (int j = 0; j < g_upstream_count; j++)
            if (strcmp(nu[i].spec, g_upstreams[j].spec) == 0) { nu[i].alive = g_upstreams[j].alive; break; }
    memset(g_upstreams, 0, sizeof(g_upstreams));
    memcpy(g_upstreams, nu, sizeof(Upstream) * (size_t)cnt);
    g_upstream_count = cnt;
    if (g_upstream_index >= cnt) g_upstream_index = 0;
    pthread_mutex_unlock(&upstream_mutex);
}

static void upstream_set_health(const char *spec, bool alive) {
    bool changed = false;
    pthread_mutex_lock(&upstream_mutex);
    for (int i = 0; i < g_upstream_count; i++) {
        if (strcmp(g_upstreams[i].spec, spec) == 0) {
            changed = (g_upstreams[i].alive != 0) != alive;
            g_upstreams[i].alive = alive ? 1 : 0;
            break;
        }
    }
    pthread_mutex_unlock(&upstream_mutex);
    if (changed) {
        if (alive) log_info("Upstream %s đã SỐNG LẠI", spec);
        else log_error("Upstream %s CHẾT (không kết nối được)", spec);
    }
}

/* ========================== I/O HELPERS ========================== */
static void set_sock_opts(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct timeval tv = {IDLE_TIMEOUT, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void set_rcv_timeout(int fd, int seconds) {
    struct timeval tv = {seconds, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* Gửi đủ len byte (xử lý gửi một phần / EINTR / EAGAIN). 0 = ok, -1 = lỗi */
static int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = {fd, POLLOUT, 0};
                if (poll(&pfd, 1, IDLE_TIMEOUT * 1000) <= 0) return -1;
                continue;
            }
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Đọc đủ len byte trực tiếp từ fd (dùng cho handshake upstream) */
static int recv_exact_fd(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Reader có buffer: không mất byte khi chuyển sang chế độ tunnel */
typedef struct {
    int fd;
    uint8_t buf[8192];
    size_t pos, len;
} Reader;

static void rd_init(Reader *r, int fd) { r->fd = fd; r->pos = r->len = 0; }

static int rd_byte(Reader *r) {
    if (r->pos == r->len) {
        ssize_t n;
        do { n = recv(r->fd, r->buf, sizeof(r->buf), 0); } while (n < 0 && errno == EINTR);
        if (n <= 0) return -1;
        r->len = (size_t)n;
        r->pos = 0;
    }
    return r->buf[r->pos++];
}

static int rd_exact(Reader *r, void *out, size_t n) {
    uint8_t *p = (uint8_t *)out;
    for (size_t i = 0; i < n; i++) {
        int c = rd_byte(r);
        if (c < 0) return -1;
        p[i] = (uint8_t)c;
    }
    return 0;
}

/* Đọc tối đa max byte (ưu tiên phần đã buffer). >0 = số byte, <=0 = hết/lỗi */
static ssize_t rd_read(Reader *r, void *out, size_t max) {
    if (r->pos < r->len) {
        size_t avail = r->len - r->pos;
        size_t n = avail < max ? avail : max;
        memcpy(out, r->buf + r->pos, n);
        r->pos += n;
        return (ssize_t)n;
    }
    ssize_t n;
    do { n = recv(r->fd, out, max, 0); } while (n < 0 && errno == EINTR);
    return n;
}

/* Đọc 1 dòng (bỏ CRLF). trả về độ dài, -1 = lỗi/EOF/timeout, -2 = dòng quá dài */
static int rd_line(Reader *r, char *out, size_t max) {
    size_t n = 0;
    for (;;) {
        int c = rd_byte(r);
        if (c < 0) return -1;
        if (c == '\n') break;
        if (n + 1 >= max) return -2;
        out[n++] = (char)c;
    }
    if (n > 0 && out[n - 1] == '\r') n--;
    out[n] = '\0';
    return (int)n;
}

/* Chuyển hai chiều bằng poll() (không giới hạn fd 1024). Không đóng fd — người gọi đóng.
   Đếm byte theo kết nối/user (quota), áp dụng giới hạn tốc độ; kick = shutdown() fd nên poll() thấy EOF ngay. */
static void tunnel(int client, int remote, int slot) {
    uint8_t *buf = malloc(BUFFER_SIZE);
    if (!buf) return;
    bool c_open = true, r_open = true;
    int idle = 0;
    while ((c_open || r_open) && !g_shutdown_flag) {
        struct pollfd p[2];
        int nf = 0, ic = -1, ir = -1;
        if (c_open) { p[nf].fd = client; p[nf].events = POLLIN; p[nf].revents = 0; ic = nf++; }
        if (r_open) { p[nf].fd = remote; p[nf].events = POLLIN; p[nf].revents = 0; ir = nf++; }
        int ret = poll(p, nf, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) {
            if (++idle >= IDLE_TIMEOUT) break;      /* idle quá lâu */
            continue;
        }
        idle = 0;
        if (ic >= 0 && (p[ic].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(client, buf, chunk_for(slot), 0);
            if (n > 0) {
                if (send_all(remote, buf, (size_t)n) < 0) break;
                conn_acct(slot, 0, n);
                throttle(slot, n);
            } else if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                /* thử lại */
            } else {
                c_open = false;
                shutdown(remote, SHUT_WR);
            }
        }
        if (ir >= 0 && (p[ir].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(remote, buf, chunk_for(slot), 0);
            if (n > 0) {
                if (send_all(client, buf, (size_t)n) < 0) break;
                conn_acct(slot, 1, n);
                throttle(slot, n);
            } else if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                /* thử lại */
            } else {
                r_open = false;
                shutdown(client, SHUT_WR);
            }
        }
    }
    free(buf);
}

/* ========================== KẾT NỐI RA NGOÀI ========================== */
enum { CERR_OTHER = 0, CERR_BLOCKED, CERR_RESOLVE, CERR_REFUSED, CERR_TIMEOUT, CERR_UNREACH };

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* connect không chặn với timeout; trả về fd (chế độ blocking) hoặc -1 */
static int connect_fd_timeout(const struct sockaddr *sa, socklen_t len, int timeout_ms, int *err_kind) {
    int fd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (fd < 0) { *err_kind = CERR_OTHER; return -1; }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(fd, sa, len);
    int err = 0;
    if (rc < 0) {
        if (errno != EINPROGRESS) {
            err = errno;
        } else {
            struct pollfd pfd = {fd, POLLOUT, 0};
            int pr;
            do { pr = poll(&pfd, 1, timeout_ms); } while (pr < 0 && errno == EINTR);
            if (pr == 0) err = ETIMEDOUT;
            else if (pr < 0) err = errno;
            else {
                socklen_t el = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0) err = errno;
            }
        }
    }
    if (err) {
        close(fd);
        if (err == ECONNREFUSED) *err_kind = CERR_REFUSED;
        else if (err == ETIMEDOUT) *err_kind = CERR_TIMEOUT;
        else if (err == ENETUNREACH || err == EHOSTUNREACH) *err_kind = CERR_UNREACH;
        else *err_kind = CERR_OTHER;
        return -1;
    }
    fcntl(fd, F_SETFL, flags);          /* trả về blocking */
    set_sock_opts(fd);
    return fd;
}

/* Kết nối trực tiếp: resolve -> kiểm tra SSRF TẤT CẢ địa chỉ -> connect (dial đúng IP đã kiểm tra) */
static int connect_direct(const char *host, int port, int *err_kind) {
    struct addrinfo hints, *res = NULL;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0 || !res) {
        *err_kind = CERR_RESOLVE;
        return -1;
    }
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        if (is_blocked_sa(rp->ai_addr)) {
            freeaddrinfo(res);
            *err_kind = CERR_BLOCKED;
            return -1;
        }
    }
    long long deadline = mono_ms() + CONNECTION_TIMEOUT * 1000LL;
    int fd = -1;
    *err_kind = CERR_OTHER;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        long long left = deadline - mono_ms();
        if (left <= 0) { *err_kind = CERR_TIMEOUT; break; }
        int ek = CERR_OTHER;
        fd = connect_fd_timeout(rp->ai_addr, rp->ai_addrlen, (int)left, &ek);
        if (fd >= 0) break;
        *err_kind = ek;
    }
    freeaddrinfo(res);
    return fd;
}

/* --- handshake qua upstream --- */
static int upstream_handshake_http(int fd, const char *host, int port) {
    char req[700];
    bool v6 = strchr(host, ':') != NULL;
    int n = snprintf(req, sizeof(req),
                     "CONNECT %s%s%s:%d HTTP/1.1\r\nHost: %s%s%s:%d\r\n\r\n",
                     v6 ? "[" : "", host, v6 ? "]" : "", port,
                     v6 ? "[" : "", host, v6 ? "]" : "", port);
    if (n <= 0 || n >= (int)sizeof(req)) return -1;
    if (send_all(fd, req, (size_t)n) < 0) return -1;
    char resp[4096];
    size_t len = 0;
    while (len < sizeof(resp) - 1) {
        ssize_t r = recv(fd, resp + len, 1, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        len++;
        resp[len] = '\0';
        if (len >= 4 && memcmp(resp + len - 4, "\r\n\r\n", 4) == 0) break;
    }
    if (len < 12 || strncmp(resp, "HTTP/1.", 7) != 0) return -1;
    return (resp[9] == '2') ? 0 : -1;       /* 2xx = thành công */
}

static int upstream_handshake_socks5(int fd, const char *host, int port) {
    uint8_t greet[3] = {5, 1, 0};
    uint8_t rep[4];
    if (send_all(fd, greet, 3) < 0) return -1;
    if (recv_exact_fd(fd, rep, 2) < 0 || rep[0] != 5 || rep[1] != 0) return -1;
    uint8_t req[300];
    size_t n = 0;
    req[n++] = 5; req[n++] = 1; req[n++] = 0;
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, host, &a4) == 1) {
        req[n++] = 1; memcpy(req + n, &a4, 4); n += 4;
    } else if (inet_pton(AF_INET6, host, &a6) == 1) {
        req[n++] = 4; memcpy(req + n, &a6, 16); n += 16;
    } else {
        size_t hl = strlen(host);
        if (hl == 0 || hl > 255) return -1;
        req[n++] = 3; req[n++] = (uint8_t)hl; memcpy(req + n, host, hl); n += hl;
    }
    req[n++] = (uint8_t)((port >> 8) & 0xFF);
    req[n++] = (uint8_t)(port & 0xFF);
    if (send_all(fd, req, n) < 0) return -1;
    if (recv_exact_fd(fd, rep, 4) < 0 || rep[0] != 5 || rep[1] != 0) return -1;
    size_t skip;
    if (rep[3] == 1) skip = 4 + 2;
    else if (rep[3] == 4) skip = 16 + 2;
    else if (rep[3] == 3) {
        uint8_t l;
        if (recv_exact_fd(fd, &l, 1) < 0) return -1;
        skip = (size_t)l + 2;
    } else return -1;
    uint8_t junk[300];
    return recv_exact_fd(fd, junk, skip);
}

static int connect_via_upstreams(const char *host, int port, int *err_kind) {
    Upstream ups[MAX_UPSTREAM];
    int start, count;
    pthread_mutex_lock(&upstream_mutex);
    count = g_upstream_count;
    start = g_upstream_index;
    memcpy(ups, g_upstreams, sizeof(ups));
    pthread_mutex_unlock(&upstream_mutex);

    int alive_n = 0;
    for (int i = 0; i < count; i++) if (ups[i].alive) alive_n++;

    *err_kind = CERR_OTHER;
    for (int i = 0; i < count; i++) {
        int idx = (start + i) % count;
        Upstream *u = &ups[idx];
        /* Bỏ qua upstream đã biết chết, TRỪ KHI tất cả đều chết (thà thử còn hơn từ chối chắc chắn) */
        if (alive_n > 0 && !u->alive) continue;
        pthread_mutex_lock(&upstream_mutex);
        g_upstream_index = (idx + 1) % (g_upstream_count ? g_upstream_count : 1);      /* round-robin */
        pthread_mutex_unlock(&upstream_mutex);

        struct addrinfo hints, *res = NULL;
        char ps[8];
        snprintf(ps, sizeof(ps), "%d", u->port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(u->host, ps, &hints, &res) != 0 || !res) { upstream_set_health(u->spec, false); continue; }
        int fd = -1, ek = CERR_OTHER;
        long long deadline = mono_ms() + CONNECTION_TIMEOUT * 1000LL;
        for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
            long long left = deadline - mono_ms();
            if (left <= 0) break;
            fd = connect_fd_timeout(rp->ai_addr, rp->ai_addrlen, (int)left, &ek);
            if (fd >= 0) break;
        }
        freeaddrinfo(res);
        if (fd < 0) { upstream_set_health(u->spec, false); continue; }      /* upstream do operator cấu hình: tin cậy */
        set_rcv_timeout(fd, CONNECTION_TIMEOUT);
        int hs = (u->type == 1) ? upstream_handshake_socks5(fd, host, port)
                                : upstream_handshake_http(fd, host, port);
        set_rcv_timeout(fd, 0);
        if (hs == 0) return fd;
        close(fd);
    }
    return -1;
}

/* Điểm vào duy nhất để kết nối tới đích do client yêu cầu */
static int connect_target(const char *host, int port, int *err_kind) {
    *err_kind = CERR_OTHER;
    if (host_is_blocked_literal(host)) { *err_kind = CERR_BLOCKED; return -1; }
    int ucount;
    pthread_mutex_lock(&upstream_mutex);
    ucount = g_upstream_count;
    pthread_mutex_unlock(&upstream_mutex);
    if (ucount > 0) {
        int fd = connect_via_upstreams(host, port, err_kind);
        if (fd >= 0) return fd;
        if (!g_upstream_fallback) { *err_kind = CERR_UNREACH; return -1; }
        log_error("Mọi upstream đều lỗi -> fallback kết nối trực tiếp (có thể lộ IP thật)");
    }
    return connect_direct(host, port, err_kind);
}

/* Health check nền: định kỳ dial thử từng upstream để cập nhật sống/chết */
static void *upstream_health_thread(void *arg) {
    (void)arg;
    while (!g_shutdown_flag) {
        for (int s = 0; s < 15 && !g_shutdown_flag; s++) sleep(1);
        if (g_shutdown_flag) break;
        Upstream ups[MAX_UPSTREAM];
        int count;
        pthread_mutex_lock(&upstream_mutex);
        count = g_upstream_count;
        memcpy(ups, g_upstreams, sizeof(ups));
        pthread_mutex_unlock(&upstream_mutex);
        for (int i = 0; i < count; i++) {
            struct addrinfo hints, *res = NULL;
            char ps[8];
            snprintf(ps, sizeof(ps), "%d", ups[i].port);
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            bool ok = false;
            if (getaddrinfo(ups[i].host, ps, &hints, &res) == 0 && res) {
                int ek = 0;
                int fd = connect_fd_timeout(res->ai_addr, res->ai_addrlen, 3000, &ek);
                if (fd >= 0) { ok = true; close(fd); }
                freeaddrinfo(res);
            }
            upstream_set_health(ups[i].spec, ok);
        }
    }
    return NULL;
}

/* ========================== PROXY CLIENT HANDLER ========================== */
typedef struct {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    char ip[64];
    int port;
    uint8_t cip[16];            /* IP client dạng chuẩn 16 byte (cho whitelist/blacklist) */
    char user[NAME_LEN];        /* user đã xác thực ("" nếu không có auth) */
    long long bw;               /* giới hạn băng thông của user (bytes/s) */
    char udp_target[300];       /* đích UDP client yêu cầu (chỉ dùng cho SOCKS5_UDP) */
} ClientContext;

static void socks5_reply_sa(int fd, uint8_t rep, const struct sockaddr *sa) {
    uint8_t reply[32];
    size_t n = 0;
    uint8_t ip[16]; uint16_t port;
    sa_canon(sa, ip, &port);
    reply[n++] = 5; reply[n++] = rep; reply[n++] = 0;
    if (canon_is_v4(ip)) {
        reply[n++] = 1; memcpy(reply + n, ip + 12, 4); n += 4;
    } else {
        reply[n++] = 4; memcpy(reply + n, ip, 16); n += 16;
    }
    reply[n++] = (uint8_t)((port >> 8) & 0xFF);
    reply[n++] = (uint8_t)(port & 0xFF);
    send_all(fd, reply, n);
}

static void socks5_reply_zero(int fd, uint8_t rep) {
    uint8_t reply[10] = {5, rep, 0, 1, 0, 0, 0, 0, 0, 0};
    send_all(fd, reply, sizeof(reply));
}

static uint8_t socks5_rep_for(int err_kind) {
    switch (err_kind) {
    case CERR_BLOCKED: return 2;
    case CERR_RESOLVE: return 4;
    case CERR_UNREACH: return 4;
    case CERR_REFUSED: return 5;
    case CERR_TIMEOUT: return 6;
    default: return 1;
    }
}

static int socks5_auth(Reader *rd, ClientContext *ctx) {
    int fd = ctx->fd;
    uint8_t h[2];
    if (rd_exact(rd, h, 2) < 0 || h[0] != 1) return 0;
    char user[256], pass[256];
    size_t ulen = h[1];
    if (rd_exact(rd, user, ulen) < 0) return 0;
    user[ulen] = '\0';
    uint8_t pl;
    if (rd_exact(rd, &pl, 1) < 0) return 0;
    size_t plen = pl;
    if (rd_exact(rd, pass, plen) < 0) return 0;
    pass[plen] = '\0';

    if (proxy_authenticate(user, pass, ctx->user, &ctx->bw)) {
        uint8_t ok[] = {1, 0};
        send_all(fd, ok, 2);
        auth_reset(ctx->ip);
        return 1;
    }
    uint8_t fail[] = {1, 1};
    send_all(fd, fail, 2);
    auth_record_fail(ctx->ip);
    return 0;
}

/* Đọc địa chỉ đích (header 4 byte ĐÃ được đọc bởi người gọi; atyp truyền vào) */
static int read_socks5_addr(Reader *rd, uint8_t atyp, char *host, size_t hostsz, int *port) {
    uint8_t buf[256];
    if (atyp == 1) {
        if (rd_exact(rd, buf, 4) < 0) return -1;
        inet_ntop(AF_INET, buf, host, (socklen_t)hostsz);
    } else if (atyp == 3) {
        uint8_t len;
        if (rd_exact(rd, &len, 1) < 0) return -1;
        if (len == 0 || (size_t)len >= hostsz) return -1;
        if (rd_exact(rd, buf, len) < 0) return -1;
        memcpy(host, buf, len);
        host[len] = '\0';
        if (!host_chars_ok(host)) return -3;
    } else if (atyp == 4) {
        if (rd_exact(rd, buf, 16) < 0) return -1;
        inet_ntop(AF_INET6, buf, host, (socklen_t)hostsz);
    } else {
        return -2;
    }
    if (rd_exact(rd, buf, 2) < 0) return -1;
    *port = (buf[0] << 8) | buf[1];
    return 0;
}

/* ----- UDP ASSOCIATE: mỗi association một luồng (luồng handler) -> không còn deadlock/double-free ----- */
typedef struct {
    uint8_t ip[16];
    uint16_t port;
} UdpDest;

static bool udp_make_dest(int family, const uint8_t ip[16], uint16_t port,
                          struct sockaddr_storage *out, socklen_t *outlen) {
    memset(out, 0, sizeof(*out));
    if (family == AF_INET) {
        if (!canon_is_v4(ip)) return false;
        struct sockaddr_in *in = (struct sockaddr_in *)out;
        in->sin_family = AF_INET;
        memcpy(&in->sin_addr, ip + 12, 4);
        in->sin_port = htons(port);
        *outlen = sizeof(*in);
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)out;
        in6->sin6_family = AF_INET6;
        memcpy(&in6->sin6_addr, ip, 16);
        in6->sin6_port = htons(port);
        *outlen = sizeof(*in6);
    }
    return true;
}

static void handle_udp_associate(ClientContext *ctx) {
    int fd = ctx->fd;
    struct sockaddr_storage local;
    socklen_t ll = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &ll) < 0) { socks5_reply_zero(fd, 1); return; }
    int family = local.ss_family;
    int us = socket(family, SOCK_DGRAM, 0);
    if (us < 0) { socks5_reply_zero(fd, 1); return; }

    /* Relay bind vào chính IP mà client đã dùng để tới proxy (không mở rộng bề mặt phơi bày theo `-l`).
       NGOẠI LỆ khi đó là loopback: socket bind 127.0.0.1 không gửi được ra đích ngoài (sendto -> EINVAL) và không nhận
       được gói trả về từ Internet, nên client cùng máy cần bind wildcard. Gói vẫn chỉ được nhận từ đúng IP client
       (loopback) hoặc từ đích client đã gửi tới, nên không thành open relay. */
    bool loopback_local;
    {
        uint8_t lip[16]; uint16_t lp_unused;
        sa_canon((struct sockaddr *)&local, lip, &lp_unused);
        static const uint8_t v6lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        loopback_local = canon_is_v4(lip) ? (lip[12] == 127) : (memcmp(lip, v6lo, 16) == 0);
    }
    if (family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)&local;
        in->sin_port = 0;
        if (loopback_local) in->sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&local;
        in6->sin6_port = 0;
        if (loopback_local) in6->sin6_addr = in6addr_any;
    }
    if (bind(us, (struct sockaddr *)&local, ll) < 0) {
        log_error("UDP relay bind thất bại: %s", strerror(errno));
        close(us);
        socks5_reply_zero(fd, 1);
        return;
    }
    struct sockaddr_storage bound;
    socklen_t bl = sizeof(bound);
    getsockname(us, (struct sockaddr *)&bound, &bl);

    uint8_t *in = malloc(UDP_BUFFER_SIZE);
    uint8_t *out = malloc(UDP_BUFFER_SIZE + 32);
    if (!in || !out) { free(in); free(out); close(us); socks5_reply_zero(fd, 1); return; }

    char ip_str[64]; snprintf(ip_str, sizeof(ip_str), "%s", ctx->ip);
    const char *utgt = ctx->udp_target[0] ? ctx->udp_target : "UDP:any";
    int slot = active_add(ip_str, ctx->port, "SOCKS5_UDP", utgt, ctx->user, ctx->bw, fd);
    stats_increment("SOCKS5_UDP");
    if (slot >= 0) {
        pthread_mutex_lock(&active_mutex);
        g_active_conns[slot].udp_relay_port = ntohs(family == AF_INET ? ((struct sockaddr_in *)&bound)->sin_port
                                                                     : ((struct sockaddr_in6 *)&bound)->sin6_port);
        snprintf(g_active_conns[slot].udp_client, sizeof(g_active_conns[slot].udp_client), "%s", ctx->ip);
        pthread_mutex_unlock(&active_mutex);
        __atomic_store_n(&g_active_conns[slot].udp_last, (long long)time(NULL), __ATOMIC_RELAXED);
    }
    __atomic_add_fetch(&g_udp_assoc_count, 1, __ATOMIC_RELAXED);
    log_info(COLOR_PURPLE "UDP Associate → %s:%d (relay %d)" COLOR_RESET, ctx->ip, ctx->port,
             ntohs(family == AF_INET ? ((struct sockaddr_in *)&bound)->sin_port
                                     : ((struct sockaddr_in6 *)&bound)->sin6_port));

    /* RFC 1928 §7: BND.ADDR = IP relay (server), không phải client. ===
       Bug cũ dùng ctx->addr → chỉ chạy loopback. */
    {
        uint8_t pip[16];
        uint16_t pport_unused;
        struct sockaddr_storage tcp_local; socklen_t tl = sizeof(tcp_local);
        if (getsockname(fd, (struct sockaddr *)&tcp_local, &tl) < 0) memset(&tcp_local, 0, sizeof(tcp_local));
        sa_canon((struct sockaddr *)&tcp_local, pip, &pport_unused);
        struct sockaddr_storage replysa;
        memset(&replysa, 0, sizeof(replysa));
        if (canon_is_v4(pip)) {
            struct sockaddr_in *in2 = (struct sockaddr_in *)&replysa;
            in2->sin_family = AF_INET;
            memcpy(&in2->sin_addr, pip + 12, 4);
            in2->sin_port = ((struct sockaddr_in *)&bound)->sin_port;
        } else {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&replysa;
            in6->sin6_family = AF_INET6;
            memcpy(&in6->sin6_addr, pip, 16);
            in6->sin6_port = ((struct sockaddr_in6 *)&bound)->sin6_port;
        }
        socks5_reply_sa(fd, 0, (struct sockaddr *)&replysa);
    }

    uint8_t peer_ip[16]; uint16_t peer_port_unused;
    sa_canon((struct sockaddr *)&ctx->addr, peer_ip, &peer_port_unused);

    bool client_known = false;
    uint8_t client_ip[16]; uint16_t client_port = 0;
    struct sockaddr_storage client_sa; socklen_t client_len = 0;
    UdpDest ring[UDP_DEST_RING]; int ring_n = 0, ring_next = 0;
    time_t last_err_log = 0; unsigned err_suppressed = 0;       /* log lỗi sendto tối đa 1 dòng / 5 giây / association */
    time_t last = time(NULL);

    while (!g_shutdown_flag) {
        if (time(NULL) - last > UDP_IDLE_TIMEOUT) break;
        struct pollfd p[2] = {{fd, POLLIN, 0}, {us, POLLIN, 0}};
        int ret = poll(p, 2, 1000);
        if (ret < 0) { if (errno == EINTR) continue; break; }
        if (ret == 0) continue;
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            char d[256];
            ssize_t n = recv(fd, d, sizeof(d), MSG_DONTWAIT);
            if (n == 0) break;                                  /* TCP control đóng -> kết thúc association */
            if (n < 0 && errno != EAGAIN && errno != EINTR) break;
        }
        if (!(p[1].revents & POLLIN)) continue;

        struct sockaddr_storage from; socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(us, in, UDP_BUFFER_SIZE, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) continue;
        uint8_t fip[16]; uint16_t fport;
        sa_canon((struct sockaddr *)&from, fip, &fport);

        if (!client_known && memcmp(fip, peer_ip, 16) == 0) {
            /* gói đầu tiên từ đúng IP của client -> học cổng UDP thật */
            client_known = true;
            memcpy(client_ip, fip, 16);
            client_port = fport;
            memcpy(&client_sa, &from, fl);
            client_len = fl;
            if (slot >= 0) {
                char cs[64];
                canon_to_str(fip, cs, sizeof(cs));
                pthread_mutex_lock(&active_mutex);
                snprintf(g_active_conns[slot].udp_client, sizeof(g_active_conns[slot].udp_client), "%s:%u", cs, (unsigned)fport);
                pthread_mutex_unlock(&active_mutex);
            }
        }
        bool from_client = client_known && memcmp(fip, client_ip, 16) == 0 && fport == client_port;
        last = time(NULL);

        if (from_client) {
            if (n < 4 || in[2] != 0) continue;                  /* không hỗ trợ fragment */
            uint8_t atyp = in[3];
            size_t pos = 4;
            uint8_t dip[16]; uint16_t dport;
            if (atyp == 1) {
                if ((size_t)n < pos + 6) continue;
                memset(dip, 0, 16); dip[10] = 0xff; dip[11] = 0xff;
                memcpy(dip + 12, in + pos, 4); pos += 4;
            } else if (atyp == 4) {
                if ((size_t)n < pos + 18) continue;
                memcpy(dip, in + pos, 16); pos += 16;
            } else if (atyp == 3) {
                if ((size_t)n < pos + 1) continue;
                size_t dl = in[pos++];
                if ((size_t)n < pos + dl + 2 || dl == 0) continue;
                char host[256];
                memcpy(host, in + pos, dl); host[dl] = '\0';
                pos += dl;
                if (!host_chars_ok(host)) continue;
                uint16_t pp = (uint16_t)((in[pos] << 8) | in[pos + 1]);
                char ps[8]; snprintf(ps, sizeof(ps), "%u", pp);
                struct addrinfo hints, *res = NULL;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = (family == AF_INET) ? AF_INET : AF_UNSPEC;
                hints.ai_socktype = SOCK_DGRAM;
                if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) continue;
                bool bad = false;
                for (struct addrinfo *rp = res; rp; rp = rp->ai_next)
                    if (is_blocked_sa(rp->ai_addr)) { bad = true; break; }
                if (bad) { freeaddrinfo(res); continue; }
                uint16_t tmp;
                sa_canon(res->ai_addr, dip, &tmp);
                freeaddrinfo(res);
            } else {
                continue;
            }
            dport = (uint16_t)((in[pos] << 8) | in[pos + 1]);
            pos += 2;
            if (atyp != 3 && !g_allow_private && is_blocked_canon(dip)) continue;
            struct sockaddr_storage dest; socklen_t dlen;
            if (!udp_make_dest(family, dip, dport, &dest, &dlen)) continue;
            /* ghi nhớ đích để chỉ nhận gói trả về từ đích đã từng gửi tới */
            bool seen = false;
            for (int i = 0; i < ring_n; i++)
                if (memcmp(ring[i].ip, dip, 16) == 0 && ring[i].port == dport) { seen = true; break; }
            if (!seen) {
                memcpy(ring[ring_next].ip, dip, 16);
                ring[ring_next].port = dport;
                ring_next = (ring_next + 1) % UDP_DEST_RING;
                if (ring_n < UDP_DEST_RING) ring_n++;
                if (slot >= 0) __atomic_add_fetch(&g_active_conns[slot].udp_dests, 1, __ATOMIC_RELAXED);
            }
            ssize_t sent = sendto(us, in + pos, (size_t)n - pos, 0, (struct sockaddr *)&dest, dlen);
            if (sent > 0) {
                udp_acct(slot, 0, sent);
            } else {
                time_t nowt = time(NULL);
                if (nowt - last_err_log >= 5) {
                    char ds[64];
                    canon_to_str(dip, ds, sizeof(ds));
                    log_error("UDP relay sendto %s:%u thất bại: %s%s", ds, (unsigned)dport, strerror(errno),
                              err_suppressed ? " (còn nhiều lỗi tương tự bị ẩn)" : "");
                    last_err_log = nowt;
                    err_suppressed = 0;
                } else {
                    err_suppressed++;
                }
            }
        } else if (client_known) {
            bool allowed = false;
            for (int i = 0; i < ring_n; i++)
                if (memcmp(ring[i].ip, fip, 16) == 0 && ring[i].port == fport) { allowed = true; break; }
            if (!allowed) continue;
            /* MỘT datagram: header SOCKS5 mang địa chỉ NGUỒN của đích + payload */
            size_t o = 0;
            out[o++] = 0; out[o++] = 0; out[o++] = 0;
            if (canon_is_v4(fip)) { out[o++] = 1; memcpy(out + o, fip + 12, 4); o += 4; }
            else { out[o++] = 4; memcpy(out + o, fip, 16); o += 16; }
            out[o++] = (uint8_t)(fport >> 8);
            out[o++] = (uint8_t)(fport & 0xFF);
            memcpy(out + o, in, (size_t)n);
            ssize_t sent = sendto(us, out, o + (size_t)n, 0, (struct sockaddr *)&client_sa, client_len);
            if (sent > 0) {
                udp_acct(slot, 1, n);
            } else {
                time_t nowt = time(NULL);
                if (nowt - last_err_log >= 5) {
                    log_error("UDP relay reply→client thất bại: %s", strerror(errno));
                    last_err_log = nowt;
                } else {
                    err_suppressed++;
                }
            }
        }
        /* gói từ nguồn lạ khi chưa biết client: bỏ (không làm open relay) */
    }

    __atomic_sub_fetch(&g_udp_assoc_count, 1, __ATOMIC_RELAXED);
    active_remove(slot);
    stats_decrement();
    close(us);
    free(in);
    free(out);
}

static void handle_socks5(ClientContext *ctx) {
    int fd = ctx->fd;
    Reader rd;
    rd_init(&rd, fd);

    uint8_t hdr[2];
    if (rd_exact(&rd, hdr, 2) < 0 || hdr[0] != 5) return;
    int nmethods = hdr[1];
    uint8_t methods[256];
    if (nmethods > 0 && rd_exact(&rd, methods, (size_t)nmethods) < 0) return;

    bool need_auth = proxy_auth_required();
    uint8_t want = need_auth ? 0x02 : 0x00;
    bool found = false;
    for (int i = 0; i < nmethods; i++) if (methods[i] == want) { found = true; break; }
    if (!found) {
        uint8_t reply[] = {5, 0xFF};
        send_all(fd, reply, 2);
        return;
    }
    uint8_t reply[] = {5, want};
    if (send_all(fd, reply, 2) < 0) return;

    if (need_auth) {
        if (!socks5_auth(&rd, ctx)) return;
        char reason[96];
        if (ctx->user[0] && !check_user_limits(ctx->user, reason, sizeof(reason))) {
            log_error("SOCKS5 từ chối user '%s': %s", ctx->user, reason);
            socks5_reply_zero(fd, 2);
            return;
        }
    }

    /* Header yêu cầu: đọc MỘT lần (trước đây bị đọc hai lần nên SOCKS5 luôn lỗi) */
    uint8_t req[4];
    if (rd_exact(&rd, req, 4) < 0 || req[0] != 5) return;
    uint8_t cmd = req[1], atyp = req[3];

    char host[256];
    int port = 0;
    int rc = read_socks5_addr(&rd, atyp, host, sizeof(host), &port);
    if (rc != 0) {
        if (rc == -1) return;
        socks5_reply_zero(fd, rc == -2 ? 8 : 1);
        return;
    }
    if (cmd != 1 && cmd != 3) { socks5_reply_zero(fd, 7); return; }

    set_rcv_timeout(fd, 0);     /* hết giai đoạn handshake */

    if (cmd == 1) {
        char target[300];
        snprintf(target, sizeof(target), "%.255s:%d", host, port);
        log_info(COLOR_GREEN "SOCKS5 TCP → %s:%d → %s" COLOR_RESET, ctx->ip, ctx->port, target);
        int slot = active_add(ctx->ip, ctx->port, "SOCKS5_TCP", target, ctx->user, ctx->bw, fd);
        stats_increment("SOCKS5_TCP");

        int ek = CERR_OTHER;
        int remote = connect_target(host, port, &ek);
        if (remote < 0) {
            socks5_reply_zero(fd, socks5_rep_for(ek));
        } else {
            active_set_remote(slot, remote);
            struct sockaddr_storage la; socklen_t ll = sizeof(la);
            if (getsockname(remote, (struct sockaddr *)&la, &ll) < 0) memset(&la, 0, sizeof(la));
            if (la.ss_family == AF_INET || la.ss_family == AF_INET6)
                socks5_reply_sa(fd, 0, (struct sockaddr *)&la);
            else
                socks5_reply_zero(fd, 0);
            /* dữ liệu client gửi sớm (đã nằm trong buffer) phải được chuyển tiếp */
            bool ok = true;
            if (rd.pos < rd.len) {
                ok = send_all(remote, rd.buf + rd.pos, rd.len - rd.pos) == 0;
                if (ok) conn_acct(slot, 0, (long long)(rd.len - rd.pos));
            }
            if (ok) tunnel(fd, remote, slot);
            active_close_remote(slot, remote);
        }
        active_remove(slot);
        stats_decrement();
    } else if (g_enable_udp) {
        if (host[0]) {
            bool v6 = strchr(host, ':') != NULL;
            snprintf(ctx->udp_target, sizeof(ctx->udp_target),
                     "UDP:%s%.255s%s:%d", v6 ? "[" : "", host, v6 ? "]" : "", port);
        } else {
            snprintf(ctx->udp_target, sizeof(ctx->udp_target), "UDP:any");
        }
        handle_udp_associate(ctx);
    } else {
        socks5_reply_zero(fd, 7);
    }
}

/* ========================== HTTP ========================== */
static void send_status(int fd, int code, const char *text) {
    char b[256];
    int n = snprintf(b, sizeof(b), "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", code, text);
    send_all(fd, b, (size_t)n);
}

static bool hdr_name_is(const char *line, const char *name) {
    size_t n = strlen(name);
    return strncasecmp(line, name, n) == 0 && line[n] == ':';
}

static const char *hdr_value(const char *line) {
    const char *p = strchr(line, ':') + 1;
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static bool parse_ull_strict(const char *s, unsigned long long *out) {
    if (!*s) return false;
    for (const char *p = s; *p; p++) if (!isdigit((unsigned char)*p)) return false;
    errno = 0;
    unsigned long long v = strtoull(s, NULL, 10);
    if (errno || v > (unsigned long long)LLONG_MAX) return false;
    *out = v;
    return true;
}

static bool basic_decode(const char *value, char *user, size_t usz, char *pass, size_t psz) {
    if (!value || strncasecmp(value, "Basic ", 6) != 0) return false;
    value += 6;
    while (*value == ' ') value++;
    uint8_t dec[700];
    int n = b64_decode(value, dec, sizeof(dec) - 1);
    if (n < 0) return false;
    dec[n] = '\0';
    char *colon = strchr((char *)dec, ':');
    if (!colon) return false;
    *colon = '\0';
    if (strlen((char *)dec) >= usz || strlen(colon + 1) >= psz) return false;
    snprintf(user, usz, "%s", (char *)dec);
    snprintf(pass, psz, "%s", colon + 1);
    return true;
}

/* http://[user@]host[:port][/path][?query] -> host, port, path. https:// bị từ chối (dùng CONNECT). */
static int parse_http_url(const char *url, char *host, size_t hs, int *port, char *path, size_t ps) {
    const char *p = url;
    if (strncasecmp(p, "http://", 7) == 0) p += 7;
    else return -1;
    size_t alen = strcspn(p, "/?#");
    if (alen == 0 || alen >= 300) return -1;
    char auth[300];
    memcpy(auth, p, alen);
    auth[alen] = '\0';
    const char *end = p + alen;
    char *at = strrchr(auth, '@');
    const char *hp = at ? at + 1 : auth;
    if (parse_hostport(hp, host, hs, port, 80) < 0) return -1;
    char tmp[MAX_LINE + 2];
    if (*end == '\0') snprintf(tmp, sizeof(tmp), "/");
    else if (*end == '/') snprintf(tmp, sizeof(tmp), "%s", end);
    else snprintf(tmp, sizeof(tmp), "/%s", end);
    char *frag = strchr(tmp, '#');
    if (frag) *frag = '\0';
    size_t tl = strlen(tmp);
    if (tl >= ps) return -1;
    memcpy(path, tmp, tl + 1);
    return 0;
}

static void handle_http(ClientContext *ctx) {
    int fd = ctx->fd;
    Reader rd;
    rd_init(&rd, fd);

    char line[MAX_LINE + 1];
    char method[16], url[MAX_LINE], version[16];
    char *hdrs = malloc(MAX_HEADER_BYTES);
    char *req = malloc(MAX_HEADER_BYTES + 4 * 1024);
    uint8_t *buf = malloc(BUFFER_SIZE);
    size_t hlen = 0;
    char proxy_auth[512] = "";
    bool have_auth = false, chunked = false, have_cl = false;
    unsigned long long content_length = 0;
    int remote = -1, slot = -1;
    bool session = false;
    char host[256], path[MAX_LINE], target[300];
    int port = 0;

    if (!hdrs || !req || !buf) goto done;

    int rc = rd_line(&rd, line, sizeof(line));
    if (rc < 0) { if (rc == -2) send_status(fd, 414, "URI Too Long"); goto done; }
    if (sscanf(line, "%15s %8191s %15s", method, url, version) != 3 || strncmp(version, "HTTP/1.", 7) != 0) {
        send_status(fd, 400, "Bad Request");
        goto done;
    }

    for (int count = 0;; count++) {
        if (count > MAX_HEADER_LINES) { send_status(fd, 431, "Request Header Fields Too Large"); goto done; }
        rc = rd_line(&rd, line, sizeof(line));
        if (rc < 0) { if (rc == -2) send_status(fd, 431, "Request Header Fields Too Large"); goto done; }
        if (rc == 0) break;
        if (line[0] == ' ' || line[0] == '\t') { send_status(fd, 400, "Bad Request"); goto done; }   /* obs-fold */
        char *colon = strchr(line, ':');
        if (!colon || colon == line || colon[-1] == ' ' || colon[-1] == '\t') { send_status(fd, 400, "Bad Request"); goto done; }
        size_t ll = strlen(line);
        while (ll > 0 && (line[ll - 1] == ' ' || line[ll - 1] == '\t')) line[--ll] = '\0';

        if (hdr_name_is(line, "proxy-authorization")) {
            snprintf(proxy_auth, sizeof(proxy_auth), "%s", hdr_value(line));
            have_auth = true;
        } else if (hdr_name_is(line, "content-length")) {
            unsigned long long v;
            if (!parse_ull_strict(hdr_value(line), &v) || (have_cl && v != content_length)) {
                send_status(fd, 400, "Bad Request");
                goto done;
            }
            content_length = v;
            have_cl = true;
        } else if (hdr_name_is(line, "transfer-encoding")) {
            if (chunked || strcasecmp(hdr_value(line), "chunked") != 0) { send_status(fd, 400, "Bad Request"); goto done; }
            chunked = true;
        } else if (hdr_name_is(line, "host") || hdr_name_is(line, "proxy-connection") ||
                   hdr_name_is(line, "connection") || hdr_name_is(line, "keep-alive") ||
                   hdr_name_is(line, "expect") || hdr_name_is(line, "upgrade") ||
                   hdr_name_is(line, "te")) {
            /* bỏ: Host được tạo lại từ URL; các header hop-by-hop không chuyển tiếp */
        } else {
            if (hlen + ll + 2 > MAX_HEADER_BYTES) { send_status(fd, 431, "Request Header Fields Too Large"); goto done; }
            memcpy(hdrs + hlen, line, ll); hlen += ll;
            hdrs[hlen++] = '\r'; hdrs[hlen++] = '\n';
        }
    }
    if (chunked && have_cl) { send_status(fd, 400, "Bad Request"); goto done; }   /* chống request smuggling */
    set_rcv_timeout(fd, 0);

    /* Xác thực (trước đây HTTP proxy bỏ qua hoàn toàn -> open proxy) */
    if (proxy_auth_required()) {
        char au[256], ap[256];
        if (!have_auth || !basic_decode(proxy_auth, au, sizeof(au), ap, sizeof(ap)) ||
            !proxy_authenticate(au, ap, ctx->user, &ctx->bw)) {
            if (have_auth) auth_record_fail(ctx->ip);       /* thiếu credentials (lần thử đầu của trình duyệt) không bị tính */
            const char *r = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                            "Proxy-Authenticate: Basic realm=\"Proxy\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            send_all(fd, r, strlen(r));
            goto done;
        }
        auth_reset(ctx->ip);
        char reason[96];
        if (ctx->user[0] && !check_user_limits(ctx->user, reason, sizeof(reason))) {
            log_error("HTTP proxy từ chối user '%s': %s", ctx->user, reason);
            send_status(fd, 429, "Too Many Requests");
            goto done;
        }
    }

    bool is_connect = (strcmp(method, "CONNECT") == 0);
    if (is_connect) {
        if (parse_hostport(url, host, sizeof(host), &port, 0) < 0) { send_status(fd, 400, "Bad Request"); goto done; }
    } else {
        if (parse_http_url(url, host, sizeof(host), &port, path, sizeof(path)) < 0) {
            send_status(fd, 400, "Bad Request");
            goto done;
        }
    }

    {
        bool v6 = strchr(host, ':') != NULL;
        snprintf(target, sizeof(target), "%s%.255s%s:%d", v6 ? "[" : "", host, v6 ? "]" : "", port);
    }
    log_info(COLOR_GREEN "HTTP %s → %s:%d → %s" COLOR_RESET, method, ctx->ip, ctx->port, target);
    slot = active_add(ctx->ip, ctx->port, "HTTP", target, ctx->user, ctx->bw, fd);
    stats_increment("HTTP");
    session = true;

    int ek = CERR_OTHER;
    remote = connect_target(host, port, &ek);
    if (remote < 0) {
        if (ek == CERR_BLOCKED) send_status(fd, 403, "Forbidden");
        else if (ek == CERR_TIMEOUT) send_status(fd, 504, "Gateway Timeout");
        else send_status(fd, 502, "Bad Gateway");
        goto done;
    }
    active_set_remote(slot, remote);

    if (is_connect) {
        const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (send_all(fd, ok, strlen(ok)) < 0) goto done;
        if (rd.pos < rd.len) {      /* byte client gửi sớm nằm trong buffer */
            if (send_all(remote, rd.buf + rd.pos, rd.len - rd.pos) < 0) goto done;
            conn_acct(slot, 0, (long long)(rd.len - rd.pos));
        }
        tunnel(fd, remote, slot);
        goto done;
    }

    /* Yêu cầu thường: viết lại ở dạng origin-form, Connection: close */
    {
        bool v6 = strchr(host, ':') != NULL;
        int n = snprintf(req, MAX_HEADER_BYTES + 4 * 1024,
                         "%s %s HTTP/1.1\r\nHost: %s%s%s", method, path,
                         v6 ? "[" : "", host, v6 ? "]" : "");
        if (n < 0) goto done;
        size_t o = (size_t)n;
        if (port != 80) o += (size_t)snprintf(req + o, MAX_HEADER_BYTES + 4 * 1024 - o, ":%d", port);
        o += (size_t)snprintf(req + o, MAX_HEADER_BYTES + 4 * 1024 - o, "\r\n");
        if (o + hlen + 128 > MAX_HEADER_BYTES + 4 * 1024) { send_status(fd, 431, "Request Header Fields Too Large"); goto done; }
        memcpy(req + o, hdrs, hlen); o += hlen;
        if (chunked) o += (size_t)snprintf(req + o, MAX_HEADER_BYTES + 4 * 1024 - o, "Transfer-Encoding: chunked\r\n");
        else if (have_cl) o += (size_t)snprintf(req + o, MAX_HEADER_BYTES + 4 * 1024 - o, "Content-Length: %llu\r\n", content_length);
        o += (size_t)snprintf(req + o, MAX_HEADER_BYTES + 4 * 1024 - o, "Connection: close\r\n\r\n");
        if (send_all(remote, req, o) < 0) goto done;
        conn_acct(slot, 0, (long long)o);
    }

    /* Body: stream theo Content-Length hoặc chunked (không cấp phát theo giá trị client khai) */
    if (chunked) {
        for (;;) {
            rc = rd_line(&rd, line, sizeof(line));
            if (rc < 0) goto done;
            char *semi = strchr(line, ';');
            if (semi) *semi = '\0';
            char *e = NULL;
            errno = 0;
            unsigned long long csz = strtoull(line, &e, 16);
            if (errno || e == line || *e != '\0' || csz > (unsigned long long)LLONG_MAX) goto done;
            if (semi) *semi = ';';
            if (send_all(remote, line, strlen(line)) < 0 || send_all(remote, "\r\n", 2) < 0) goto done;
            if (csz == 0) {
                for (int t = 0; t <= MAX_HEADER_LINES; t++) {       /* trailer */
                    rc = rd_line(&rd, line, sizeof(line));
                    if (rc < 0) goto done;
                    if (send_all(remote, line, (size_t)rc) < 0 || send_all(remote, "\r\n", 2) < 0) goto done;
                    if (rc == 0) break;
                }
                break;
            }
            unsigned long long remaining = csz;
            while (remaining > 0) {
                size_t want = remaining < chunk_for(slot) ? (size_t)remaining : chunk_for(slot);
                ssize_t n = rd_read(&rd, buf, want);
                if (n <= 0) goto done;
                if (send_all(remote, buf, (size_t)n) < 0) goto done;
                conn_acct(slot, 0, n);
                throttle(slot, n);
                remaining -= (unsigned long long)n;
            }
            uint8_t crlf[2];
            if (rd_exact(&rd, crlf, 2) < 0 || crlf[0] != '\r' || crlf[1] != '\n') goto done;
            if (send_all(remote, crlf, 2) < 0) goto done;
        }
    } else if (have_cl && content_length > 0) {
        unsigned long long remaining = content_length;
        while (remaining > 0) {
            size_t want = remaining < chunk_for(slot) ? (size_t)remaining : chunk_for(slot);
            ssize_t n = rd_read(&rd, buf, want);
            if (n <= 0) goto done;
            if (send_all(remote, buf, (size_t)n) < 0) goto done;
            conn_acct(slot, 0, n);
                throttle(slot, n);
            remaining -= (unsigned long long)n;
        }
    }

    /* Response: remote -> client cho tới khi remote đóng (Connection: close) */
    for (;;) {
        struct pollfd pfd = {remote, POLLIN, 0};
        int pr = poll(&pfd, 1, IDLE_TIMEOUT * 1000);
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) break;
        ssize_t n = recv(remote, buf, chunk_for(slot), 0);
        if (n <= 0) break;
        if (send_all(fd, buf, (size_t)n) < 0) break;
        conn_acct(slot, 1, n);
        throttle(slot, n);
    }

done:
    if (remote >= 0) active_close_remote(session ? slot : -1, remote);
    if (session) { active_remove(slot); stats_decrement(); }
    free(hdrs);
    free(req);
    free(buf);
}

static void *client_handler(void *arg) {
    ClientContext *ctx = (ClientContext *)arg;
    int fd = ctx->fd;

    set_sock_opts(fd);
    set_rcv_timeout(fd, HANDSHAKE_TIMEOUT);     /* chống slowloris: handshake phải xong trong HANDSHAKE_TIMEOUT */

    if (!ip_allowed_canon(ctx->cip)) {
        log_error("Từ chối %s: không nằm trong whitelist hoặc nằm trong blacklist", ctx->ip);
    } else if (!auth_is_blocked(ctx->ip)) {
        uint8_t first;
        ssize_t n;
        do { n = recv(fd, &first, 1, MSG_PEEK); } while (n < 0 && errno == EINTR);
        if (n == 1) {
            if (first == 5) {
                handle_socks5(ctx);
            } else if (first == 'C' || first == 'G' || first == 'P' || first == 'D' ||
                       first == 'H' || first == 'O' || first == 'T') {
                handle_http(ctx);
            } else {
                log_error("Unknown protocol from %s", ctx->ip);
            }
        }
    }

    close(fd);      /* close duy nhất cho fd client (tunnel() không còn tự đóng -> hết double close) */
    free(ctx);
    __atomic_sub_fetch(&g_thread_count, 1, __ATOMIC_RELAXED);
    return NULL;
}

/* ========================== HTML DASHBOARD (nhúng từ bản Go) ========================== */
static const char DASH_HTML[] =
"<!DOCTYPE html>\n"
"<html>\n"
"<head>\n"
"<meta charset=\"UTF-8\">\n"
"<title>Proxy Dashboard</title>\n"
"<style>\n"
"* { margin:0; padding:0; box-sizing:border-box; }\n"
":root {\n"
"\t--bg: #0f0f1a;\n"
"\t--fg: #e0e0e0;\n"
"\t--container-bg: #14141f;\n"
"\t--box-bg: #1a1a2e;\n"
"\t--box-hover: #22223b;\n"
"\t--border: #2a2a3a;\n"
"\t--border2: #28283a;\n"
"\t--th-bg: #1e1e32;\n"
"\t--muted: #9999bb;\n"
"\t--muted2: #b4b4d4;\n"
"\t--accent: #f0c27a;\n"
"\t--accent-solid: #f0c27a;\n"
"\t--accent-contrast: #1a1a2e;\n"
"\t--btn-bg: #2a2a3a;\n"
"\t--btn-border: #3a3a52;\n"
"\t--btn-hover: #33334a;\n"
"\t--badge-bg: #2a2a4a; --badge-fg: #c0c0e0;\n"
"\t--badge-socks5tcp-bg: #1e3a5f; --badge-socks5tcp-fg: #7dd3fc;\n"
"\t--badge-socks5udp-bg: #3b1f4a; --badge-socks5udp-fg: #d8b4fe;\n"
"\t--badge-http-bg: #2d4a2d; --badge-http-fg: #86efac;\n"
"\t--danger-border: #7a3030; --danger-hover-bg: #4a1a1a; --danger-fg: #fca5a5;\n"
"}\n"
"html[data-theme=\"light\"] {\n"
"\t--bg: #f4f4f9;\n"
"\t--fg: #1c1c2a;\n"
"\t--container-bg: #ffffff;\n"
"\t--box-bg: #f0f0f7;\n"
"\t--box-hover: #e6e6f2;\n"
"\t--border: #dcdce8;\n"
"\t--border2: #e4e4f0;\n"
"\t--th-bg: #ececf5;\n"
"\t--muted: #52526a;\n"
"\t--muted2: #33334a;\n"
"\t--accent: #8a5010;\n"
"\t--accent-solid: #c67c1e;\n"
"\t--accent-contrast: #ffffff;\n"
"\t--btn-bg: #ececf5;\n"
"\t--btn-border: #c8c8dc;\n"
"\t--btn-hover: #e0e0ee;\n"
"\t--badge-bg: #e4e4f4; --badge-fg: #3f3f66;\n"
"\t--badge-socks5tcp-bg: #dbeafe; --badge-socks5tcp-fg: #1d4ed8;\n"
"\t--badge-socks5udp-bg: #f3e8ff; --badge-socks5udp-fg: #7e22ce;\n"
"\t--badge-http-bg: #dcfce7; --badge-http-fg: #15803d;\n"
"\t--danger-border: #e5a5a5; --danger-hover-bg: #fde2e2; --danger-fg: #b91c1c;\n"
"}\n"
"body {\n"
"\tbackground: var(--bg);\n"
"\tcolor: var(--fg);\n"
"\tfont-family: 'Segoe UI', 'Roboto', monospace;\n"
"\tpadding: 30px 20px;\n"
"\ttransition: background 0.2s, color 0.2s;\n"
"}\n"
".container {\n"
"\tmax-width: 1400px;\n"
"\tmargin: 0 auto;\n"
"}\n"
"h1 {\n"
"\tfont-size: 2.2rem;\n"
"\tfont-weight: 300;\n"
"\tletter-spacing: 1px;\n"
"\tcolor: var(--accent);\n"
"\tdisplay: flex;\n"
"\talign-items: center;\n"
"\tgap: 10px;\n"
"}\n"
"h1 span { background: var(--btn-bg); padding: 0 12px; border-radius: 30px; font-size: 0.8rem; color: var(--muted); }\n"
".stats-grid {\n"
"\tdisplay: grid;\n"
"\tgrid-template-columns: repeat(auto-fit, minmax(180px, 1fr));\n"
"\tgap: 15px;\n"
"\tmargin: 20px 0;\n"
"}\n"
".stat-box {\n"
"\tbackground: var(--box-bg);\n"
"\tpadding: 14px 16px;\n"
"\tborder-radius: 12px;\n"
"\tborder-left: 4px solid #6c6c9a;\n"
"\ttransition: 0.2s;\n"
"}\n"
".stat-box:hover { background: var(--box-hover); }\n"
".stat-label {\n"
"\tfont-size: 0.8rem;\n"
"\ttext-transform: uppercase;\n"
"\tletter-spacing: 0.5px;\n"
"\tcolor: var(--muted);\n"
"}\n"
".stat-value {\n"
"\tfont-size: 1.7rem;\n"
"\tfont-weight: 600;\n"
"\tmargin-top: 4px;\n"
"}\n"
".stat-value.cyan { color: #0891b2; }\n"
".stat-value.green { color: #16a34a; }\n"
".stat-value.yellow { color: #ca8a04; }\n"
".stat-value.pink { color: #db2777; }\n"
".stat-value.orange { color: #ea580c; }\n"
".stat-value.purple { color: #7c3aed; }\n"
".stat-value.red { color: #dc2626; }\n"
"html[data-theme=\"dark\"] .stat-value.cyan, html:not([data-theme]) .stat-value.cyan { color: #7dd3fc; }\n"
"html[data-theme=\"dark\"] .stat-value.green, html:not([data-theme]) .stat-value.green { color: #86efac; }\n"
"html[data-theme=\"dark\"] .stat-value.yellow, html:not([data-theme]) .stat-value.yellow { color: #fde047; }\n"
"html[data-theme=\"dark\"] .stat-value.pink, html:not([data-theme]) .stat-value.pink { color: #f9a8d4; }\n"
"html[data-theme=\"dark\"] .stat-value.orange, html:not([data-theme]) .stat-value.orange { color: #fdba74; }\n"
"html[data-theme=\"dark\"] .stat-value.purple, html:not([data-theme]) .stat-value.purple { color: #c4b5fd; }\n"
"html[data-theme=\"dark\"] .stat-value.red, html:not([data-theme]) .stat-value.red { color: #fca5a5; }\n"
".section {\n"
"\tmargin-top: 30px;\n"
"\tbackground: var(--container-bg);\n"
"\tborder-radius: 14px;\n"
"\tpadding: 20px 20px 10px 20px;\n"
"\tborder: 1px solid var(--border);\n"
"}\n"
".section-title-row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; }\n"
".section-title {\n"
"\tfont-size: 1.2rem;\n"
"\tfont-weight: 400;\n"
"\tcolor: var(--muted2);\n"
"\tletter-spacing: 0.3px;\n"
"}\n"
".toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }\n"
".toolbar input[type=text] { background: var(--box-bg); border: 1px solid var(--border); border-radius: 8px; padding: 6px 10px; color: var(--fg); font-size: 0.85rem; }\n"
"table {\n"
"\twidth: 100%;\n"
"\tborder-collapse: collapse;\n"
"\tfont-size: 0.9rem;\n"
"}\n"
"th {\n"
"\ttext-align: left;\n"
"\tpadding: 10px 8px;\n"
"\tbackground: var(--th-bg);\n"
"\tcolor: var(--muted);\n"
"\tfont-weight: 500;\n"
"\tcursor: pointer;\n"
"\tuser-select: none;\n"
"\twhite-space: nowrap;\n"
"}\n"
"th:hover { color: var(--accent); }\n"
"th.sorted-asc::after { content: ' \\25B2'; font-size: 0.7em; }\n"
"th.sorted-desc::after { content: ' \\25BC'; font-size: 0.7em; }\n"
"td {\n"
"\tpadding: 8px 8px;\n"
"\tborder-bottom: 1px solid var(--border2);\n"
"}\n"
"tr:hover td { background: var(--box-bg); }\n"
".badge {\n"
"\tdisplay: inline-block;\n"
"\tpadding: 2px 12px;\n"
"\tborder-radius: 20px;\n"
"\tfont-size: 0.7rem;\n"
"\tfont-weight: 600;\n"
"\tbackground: var(--badge-bg);\n"
"\tcolor: var(--badge-fg);\n"
"}\n"
".badge.socks5-tcp { background: var(--badge-socks5tcp-bg); color: var(--badge-socks5tcp-fg); }\n"
".badge.socks5-udp { background: var(--badge-socks5udp-bg); color: var(--badge-socks5udp-fg); }\n"
".badge.http { background: var(--badge-http-bg); color: var(--badge-http-fg); }\n"
".header-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 2px solid var(--border); padding-bottom: 15px; margin-bottom: 10px; flex-wrap: wrap; gap: 10px; }\n"
".header-actions { display: flex; gap: 8px; flex-wrap: wrap; }\n"
".btn { background: var(--btn-bg); color: var(--fg); border: 1px solid var(--btn-border); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; transition: 0.2s; }\n"
".btn:hover { background: var(--btn-hover); border-color: var(--accent); }\n"
".btn-sm { padding: 4px 10px; font-size: 0.75rem; }\n"
".btn-danger { border-color: var(--danger-border); color: var(--danger-fg); }\n"
".btn-danger:hover { background: var(--danger-hover-bg); border-color: var(--danger-fg); color: var(--danger-fg); }\n"
".modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); align-items: center; justify-content: center; z-index: 100; }\n"
".modal-overlay.open { display: flex; }\n"
".modal { background: var(--container-bg); border: 1px solid var(--border); border-radius: 14px; padding: 24px; width: 340px; max-width: 90vw; }\n"
".modal h2 { font-size: 1.1rem; font-weight: 500; color: var(--accent); margin-bottom: 16px; }\n"
".modal label { display: block; font-size: 0.8rem; color: var(--muted); margin: 12px 0 4px; }\n"
".modal input { width: 100%; background: var(--box-bg); border: 1px solid var(--border); border-radius: 8px; padding: 9px 10px; color: var(--fg); font-size: 0.9rem; }\n"
".modal input:focus { outline: none; border-color: var(--accent); }\n"
".modal-actions { display: flex; gap: 10px; margin-top: 20px; }\n"
".modal-actions .btn { flex: 1; }\n"
".btn-primary { background: var(--accent-solid); color: var(--accent-contrast); border-color: var(--accent-solid); font-weight: 600; }\n"
".btn-primary:hover { filter: brightness(1.1); }\n"
".modal-msg { margin-top: 12px; font-size: 0.82rem; min-height: 18px; }\n"
".modal-msg.error { color: #dc2626; }\n"
".modal-msg.success { color: #16a34a; }\n"
"</style>\n"
"</head>\n"
"<body>\n"
"<div class=\"container\">\n"
"\t<div class=\"header-bar\">\n"
"\t\t<h1>⚡ Proxy Pro <span>v6.3</span></h1>\n"
"\t\t<div class=\"header-actions\">\n"
"\t\t\t<button class=\"btn\" id=\"themeToggleBtn\" onclick=\"toggleTheme()\">🌙 Theme</button>\n"
"\t\t\t<button class=\"btn\" onclick=\"openPwModal()\">🔒 Change Password</button>\n"
"\t\t</div>\n"
"\t</div>\n"
"\t<div id=\"statsGrid\" class=\"stats-grid\">Loading stats...</div>\n"
"\t<div id=\"chartSection\" class=\"section\">\n"
"\t\t<div class=\"section-title-row\">\n"
"\t\t\t<div class=\"section-title\">📈 Real-time Traffic <span id=\"streamStatus\" style=\"font-size:0.75rem;color:var(--muted);\">(connecting...)</span></div>\n"
"\t\t</div>\n"
"\t\t<canvas id=\"trafficChart\" height=\"80\"></canvas>\n"
"\t</div>\n"
"\t<div id=\"connectionsSection\" class=\"section\">\n"
"\t\t<div class=\"section-title-row\">\n"
"\t\t\t<div class=\"section-title\">🔗 Active Connections</div>\n"
"\t\t\t<div class=\"toolbar\">\n"
"\t\t\t\t<input type=\"text\" id=\"connFilter\" placeholder=\"Filter by IP / target / type...\" oninput=\"renderConnections()\">\n"
"\t\t\t\t<button class=\"btn btn-sm\" onclick=\"exportConns('csv')\">⬇ CSV</button>\n"
"\t\t\t\t<button class=\"btn btn-sm\" onclick=\"exportConns('json')\">⬇ JSON</button>\n"
"\t\t\t</div>\n"
"\t\t</div>\n"
"\t\t<div id=\"connectionsTable\">Loading...</div>\n"
"\t</div>\n"
"\t<div id=\"upstreamSection\" class=\"section\">\n"
"\t\t<div class=\"section-title\">🌐 Upstream Proxies</div>\n"
"\t\t<div id=\"upstreamInfo\">Loading...</div>\n"
"\t</div>\n"
"\t<div id=\"usersSection\" class=\"section\">\n"
"\t\t<div class=\"section-title-row\">\n"
"\t\t\t<div class=\"section-title\">👤 Proxy Users (multi-user + bandwidth limit)</div>\n"
"\t\t\t<div class=\"toolbar\">\n"
"\t\t\t\t<button class=\"btn btn-sm\" onclick=\"openUserModal()\">+ Add / Update User</button>\n"
"\t\t\t</div>\n"
"\t\t</div>\n"
"\t\t<div id=\"usersTable\">Loading...</div>\n"
"\t</div>\n"
"\t<div id=\"networkSection\" class=\"section\">\n"
"\t\t<div class=\"section-title-row\">\n"
"\t\t\t<div class=\"section-title\">🌐 Network Rules (whitelist / blacklist / upstream)</div>\n"
"\t\t\t<div class=\"toolbar\">\n"
"\t\t\t\t<button class=\"btn btn-sm\" onclick=\"reloadFromDisk()\" title=\"Đọc lại config file từ đĩa và áp dụng ngay — dùng khi vừa tự sửa file bằng tay\">↻ Reload from disk</button>\n"
"\t\t\t</div>\n"
"\t\t</div>\n"
"\t\t<div style=\"font-size:0.78rem;color:var(--muted);margin-bottom:10px;\">Mỗi dòng 1 IP hoặc CIDR (vd. <code>1.2.3.4</code> hoặc <code>10.0.0.0/8</code>). Lưu sẽ tự động reload ngay, không cần restart.</div>\n"
"\t\t<div style=\"display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;\">\n"
"\t\t\t<div>\n"
"\t\t\t\t<label style=\"display:block;font-size:0.8rem;color:var(--muted);margin-bottom:4px;\">Whitelist IP/CIDR (để trống = cho phép tất cả)</label>\n"
"\t\t\t\t<textarea id=\"netAllow\" rows=\"5\" style=\"width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:0.82rem;font-family:monospace;\"></textarea>\n"
"\t\t\t</div>\n"
"\t\t\t<div>\n"
"\t\t\t\t<label style=\"display:block;font-size:0.8rem;color:var(--muted);margin-bottom:4px;\">Blacklist IP/CIDR</label>\n"
"\t\t\t\t<textarea id=\"netDeny\" rows=\"5\" style=\"width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:0.82rem;font-family:monospace;\"></textarea>\n"
"\t\t\t</div>\n"
"\t\t\t<div>\n"
"\t\t\t\t<label style=\"display:block;font-size:0.8rem;color:var(--muted);margin-bottom:4px;\">Upstream proxies (host:port)</label>\n"
"\t\t\t\t<textarea id=\"netUpstream\" rows=\"5\" style=\"width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:0.82rem;font-family:monospace;\"></textarea>\n"
"\t\t\t</div>\n"
"\t\t</div>\n"
"\t\t<div class=\"modal-msg\" id=\"netMsg\" style=\"margin-top:10px;\"></div>\n"
"\t\t<div style=\"margin-top:10px;\">\n"
"\t\t\t<button class=\"btn btn-primary\" onclick=\"saveNetworkConfig()\">Save & Apply Now</button>\n"
"\t\t</div>\n"
"\t</div>\n"
"\t<div id=\"reloadHistorySection\" class=\"section\">\n"
"\t\t<div class=\"section-title-row\">\n"
"\t\t\t<div class=\"section-title\">🕒 Reload History</div>\n"
"\t\t</div>\n"
"\t\t<div id=\"reloadHistoryTable\">Loading...</div>\n"
"\t</div>\n"
"\t<div id=\"tokensSection\" class=\"section\">\n"
"\t\t<div class=\"section-title-row\">\n"
"\t\t\t<div class=\"section-title\">🔑 API Tokens (cho script/monitoring)</div>\n"
"\t\t\t<div class=\"toolbar\">\n"
"\t\t\t\t<button class=\"btn btn-sm\" onclick=\"openTokenModal()\">+ Create Token</button>\n"
"\t\t\t</div>\n"
"\t\t</div>\n"
"\t\t<div style=\"font-size:0.78rem;color:var(--muted);margin-bottom:10px;\">Dùng <code>Authorization: Bearer &lt;token&gt;</code> thay cho Basic Auth khi gọi API từ script — token có thể thu hồi riêng, không ảnh hưởng mật khẩu đăng nhập web.</div>\n"
"\t\t<div id=\"tokensTable\">Loading...</div>\n"
"\t</div>\n"
"\t<div id=\"auditSection\" class=\"section\">\n"
"\t\t<div class=\"section-title-row\">\n"
"\t\t\t<div class=\"section-title\">📋 Audit Log</div>\n"
"\t\t</div>\n"
"\t\t<div id=\"auditTable\">Loading...</div>\n"
"\t</div>\n"
"\t<div id=\"backupSection\" class=\"section\">\n"
"\t\t<div class=\"section-title-row\">\n"
"\t\t\t<div class=\"section-title\">💾 Backup / Restore Config</div>\n"
"\t\t</div>\n"
"\t\t<div style=\"font-size:0.78rem;color:var(--muted);margin-bottom:10px;\">File backup chứa password/token đã hash (không phải plaintext) nhưng vẫn nên giữ bí mật.</div>\n"
"\t\t<div class=\"toolbar\">\n"
"\t\t\t<a class=\"btn btn-sm\" href=\"/api/config/export\" download>⬇ Download Backup</a>\n"
"\t\t\t<input type=\"file\" id=\"restoreFileInput\" accept=\"application/json\" style=\"display:none;\" onchange=\"restoreConfig(event)\">\n"
"\t\t\t<button class=\"btn btn-sm\" onclick=\"document.getElementById('restoreFileInput').click()\">⬆ Restore from File</button>\n"
"\t\t</div>\n"
"\t\t<div class=\"modal-msg\" id=\"backupMsg\" style=\"margin-top:10px;\"></div>\n"
"\t</div>\n"
"</div>\n"
"\n"
"<div class=\"modal-overlay\" id=\"tokenModalOverlay\">\n"
"\t<div class=\"modal\">\n"
"\t\t<h2>🔑 Create API Token</h2>\n"
"\t\t<form id=\"tokenForm\" onsubmit=\"return submitTokenForm(event)\">\n"
"\t\t\t<label for=\"tName\">Token name (gợi nhớ, vd \"monitoring-script\")</label>\n"
"\t\t\t<input type=\"text\" id=\"tName\" required>\n"
"\t\t\t<div class=\"modal-msg\" id=\"tokenMsg\"></div>\n"
"\t\t\t<div id=\"tokenResultBox\" style=\"display:none;margin-top:12px;padding:10px;background:var(--box-bg);border-radius:8px;border:1px solid var(--border);\">\n"
"\t\t\t\t<div style=\"font-size:0.78rem;color:var(--danger-fg);margin-bottom:6px;\">⚠️ Chỉ hiện MỘT LẦN — copy ngay, không xem lại được:</div>\n"
"\t\t\t\t<code id=\"tokenResultValue\" style=\"word-break:break-all;font-size:0.8rem;\"></code>\n"
"\t\t\t</div>\n"
"\t\t\t<div class=\"modal-actions\">\n"
"\t\t\t\t<button type=\"button\" class=\"btn\" onclick=\"closeTokenModal()\">Close</button>\n"
"\t\t\t\t<button type=\"submit\" class=\"btn btn-primary\" id=\"tokenSubmitBtn\">Create</button>\n"
"\t\t\t</div>\n"
"\t\t</form>\n"
"\t</div>\n"
"</div>\n"
"\n"
"<div class=\"modal-overlay\" id=\"userModalOverlay\">\n"
"\t<div class=\"modal\">\n"
"\t\t<h2>👤 Add / Update Proxy User</h2>\n"
"\t\t<form id=\"userForm\" onsubmit=\"return submitUserForm(event)\">\n"
"\t\t\t<label for=\"uUsername\">Username</label>\n"
"\t\t\t<input type=\"text\" id=\"uUsername\" required>\n"
"\t\t\t<label for=\"uPassword\">Password (min. 4 characters — leave blank to keep current password when editing an existing user)</label>\n"
"\t\t\t<input type=\"password\" id=\"uPassword\" minlength=\"4\">\n"
"\t\t\t<label for=\"uBandwidth\">Max bandwidth (KB/s, 0 = unlimited)</label>\n"
"\t\t\t<input type=\"number\" id=\"uBandwidth\" min=\"0\" value=\"0\">\n"
"\t\t\t<label for=\"uMaxConn\">Max concurrent connections (0 = unlimited)</label>\n"
"\t\t\t<input type=\"number\" id=\"uMaxConn\" min=\"0\" value=\"0\">\n"
"\t\t\t<label for=\"uQuota\">Monthly quota (MB, 0 = unlimited)</label>\n"
"\t\t\t<input type=\"number\" id=\"uQuota\" min=\"0\" value=\"0\">\n"
"\t\t\t<div class=\"modal-msg\" id=\"userMsg\"></div>\n"
"\t\t\t<div class=\"modal-actions\">\n"
"\t\t\t\t<button type=\"button\" class=\"btn\" onclick=\"closeUserModal()\">Cancel</button>\n"
"\t\t\t\t<button type=\"submit\" class=\"btn btn-primary\">Save</button>\n"
"\t\t\t</div>\n"
"\t\t</form>\n"
"\t</div>\n"
"</div>\n"
"\n"
"<div class=\"modal-overlay\" id=\"pwModalOverlay\">\n"
"\t<div class=\"modal\">\n"
"\t\t<h2>🔒 Change Dashboard Credentials</h2>\n"
"\t\t<form id=\"pwForm\" onsubmit=\"return submitPwChange(event)\">\n"
"\t\t\t<label for=\"curPass\">Current password</label>\n"
"\t\t\t<input type=\"password\" id=\"curPass\" autocomplete=\"current-password\" required>\n"
"\t\t\t<label for=\"newUser\">New username (leave blank to keep current)</label>\n"
"\t\t\t<input type=\"text\" id=\"newUser\" autocomplete=\"username\">\n"
"\t\t\t<label for=\"newPass\">New password (min. 8 characters)</label>\n"
"\t\t\t<input type=\"password\" id=\"newPass\" autocomplete=\"new-password\" minlength=\"8\" required>\n"
"\t\t\t<label for=\"newPass2\">Confirm new password</label>\n"
"\t\t\t<input type=\"password\" id=\"newPass2\" autocomplete=\"new-password\" minlength=\"8\" required>\n"
"\t\t\t<div class=\"modal-msg\" id=\"pwMsg\"></div>\n"
"\t\t\t<div class=\"modal-actions\">\n"
"\t\t\t\t<button type=\"button\" class=\"btn\" onclick=\"closePwModal()\">Cancel</button>\n"
"\t\t\t\t<button type=\"submit\" class=\"btn btn-primary\">Save changes</button>\n"
"\t\t\t</div>\n"
"\t\t</form>\n"
"\t</div>\n"
"</div>\n"
"\n"
"<script>\n"
"let lastConns = [];\n"
"let sortKey = 'start_time';\n"
"let sortDir = 'desc';\n"
"let trafficChart = null;\n"
"const CHART_MAX_POINTS = 150;\n"
"\n"
"function initChart() {\n"
"\tconst ctx = document.getElementById('trafficChart').getContext('2d');\n"
"\ttrafficChart = new Chart(ctx, {\n"
"\t\ttype: 'line',\n"
"\t\tdata: {\n"
"\t\t\tlabels: [],\n"
"\t\t\tdatasets: [\n"
"\t\t\t\t{ label: 'Upload (B/s)', data: [], borderColor: '#ea580c', backgroundColor: 'rgba(234,88,12,0.1)', tension: 0.3, pointRadius: 0, borderWidth: 2 },\n"
"\t\t\t\t{ label: 'Download (B/s)', data: [], borderColor: '#0891b2', backgroundColor: 'rgba(8,145,178,0.1)', tension: 0.3, pointRadius: 0, borderWidth: 2 }\n"
"\t\t\t]\n"
"\t\t},\n"
"\t\toptions: {\n"
"\t\t\tresponsive: true,\n"
"\t\t\tanimation: false,\n"
"\t\t\tinteraction: { mode: 'index', intersect: false },\n"
"\t\t\tscales: {\n"
"\t\t\t\tx: { ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--muted') }, grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border2') } },\n"
"\t\t\t\ty: { ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--muted'), callback: v => formatBytes(v) + '/s' }, grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border2') } }\n"
"\t\t\t},\n"
"\t\t\tplugins: { legend: { labels: { color: getComputedStyle(document.documentElement).getPropertyValue('--fg') } } }\n"
"\t\t}\n"
"\t});\n"
"}\n"
"function pushChartSample(sample) {\n"
"\tif (!trafficChart) return;\n"
"\tconst label = new Date(sample.t * 1000).toLocaleTimeString();\n"
"\ttrafficChart.data.labels.push(label);\n"
"\ttrafficChart.data.datasets[0].data.push(sample.up_bps);\n"
"\ttrafficChart.data.datasets[1].data.push(sample.down_bps);\n"
"\tif (trafficChart.data.labels.length > CHART_MAX_POINTS) {\n"
"\t\ttrafficChart.data.labels.shift();\n"
"\t\ttrafficChart.data.datasets[0].data.shift();\n"
"\t\ttrafficChart.data.datasets[1].data.shift();\n"
"\t}\n"
"\ttrafficChart.update('none');\n"
"}\n"
"function connectStream() {\n"
"\tconst statusEl = document.getElementById('streamStatus');\n"
"\tconst es = new EventSource('/api/stream');\n"
"\tes.addEventListener('history', (e) => {\n"
"\t\ttry {\n"
"\t\t\tconst hist = JSON.parse(e.data);\n"
"\t\t\thist.forEach(pushChartSample);\n"
"\t\t\tstatusEl.textContent = '(live)';\n"
"\t\t\tstatusEl.style.color = 'var(--badge-http-fg)';\n"
"\t\t} catch (err) { console.error(err); }\n"
"\t});\n"
"\tes.addEventListener('sample', (e) => {\n"
"\t\ttry { pushChartSample(JSON.parse(e.data)); } catch (err) { console.error(err); }\n"
"\t});\n"
"\tes.onerror = () => {\n"
"\t\tstatusEl.textContent = '(reconnecting...)';\n"
"\t\tstatusEl.style.color = 'var(--danger-fg)';\n"
"\t\t// EventSource tự động reconnect, không cần xử lý thủ công.\n"
"\t};\n"
"\tes.onopen = () => {\n"
"\t\tstatusEl.textContent = '(live)';\n"
"\t\tstatusEl.style.color = 'var(--badge-http-fg)';\n"
"\t};\n"
"}\n"
"\n"
"function applyTheme(theme) {\n"
"\tdocument.documentElement.setAttribute('data-theme', theme);\n"
"\tdocument.getElementById('themeToggleBtn').textContent = theme === 'light' ? '☀️ Theme' : '🌙 Theme';\n"
"\ttry { localStorage.setItem('dashboard-theme', theme); } catch (e) {}\n"
"}\n"
"function toggleTheme() {\n"
"\tconst cur = document.documentElement.getAttribute('data-theme') || 'dark';\n"
"\tapplyTheme(cur === 'light' ? 'dark' : 'light');\n"
"}\n"
"(function initTheme() {\n"
"\tlet saved = 'dark';\n"
"\ttry { saved = localStorage.getItem('dashboard-theme') || 'dark'; } catch (e) {}\n"
"\tapplyTheme(saved);\n"
"})();\n"
"\n"
"async function fetchAll() {\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/all');\n"
"\t\tif (!res.ok) throw new Error('HTTP '+res.status);\n"
"\t\tconst data = await res.json();\n"
"\t\trenderStats(data);\n"
"\t\tlastConns = data.active_connections || [];\n"
"\t\trenderConnections();\n"
"\t\trenderUpstream(data.upstream || {});\n"
"\t} catch(e) {\n"
"\t\tconsole.error('Fetch error:', e);\n"
"\t\tdocument.getElementById('statsGrid').innerHTML = '<div style=\"color:#dc2626;\">⚠️ Failed to load data. Retrying...</div>';\n"
"\t}\n"
"}\n"
"function renderStats(data) {\n"
"\tconst boxes = [\n"
"\t\t{ label: 'Total Connections', value: data.total, cls: 'cyan' },\n"
"\t\t{ label: 'Active', value: data.active, cls: 'green' },\n"
"\t\t{ label: 'SOCKS5 TCP', value: data.socks5_tcp, cls: 'cyan' },\n"
"\t\t{ label: 'SOCKS5 UDP', value: data.socks5_udp, cls: 'purple' },\n"
"\t\t{ label: 'HTTP Requests', value: data.http, cls: 'green' },\n"
"\t\t{ label: 'UDP Associations', value: data.udp_assocs || 0, cls: 'yellow' },\n"
"\t\t{ label: 'Bytes Up (TCP)', value: formatBytes(data.bytes_up), cls: 'orange' },\n"
"\t\t{ label: 'Bytes Down (TCP)', value: formatBytes(data.bytes_down), cls: 'pink' },\n"
"\t\t{ label: 'UDP Up', value: formatBytes(data.udp_up), cls: 'yellow' },\n"
"\t\t{ label: 'UDP Down', value: formatBytes(data.udp_down), cls: 'purple' },\n"
"\t\t{ label: 'Uptime', value: formatUptime(data.uptime), cls: 'cyan' },\n"
"\t];\n"
"\tlet html = '';\n"
"\tboxes.forEach(b => {\n"
"\t\thtml += '<div class=\"stat-box\"><div class=\"stat-label\">'+b.label+'</div><div class=\"stat-value '+b.cls+'\">'+b.value+'</div></div>';\n"
"\t});\n"
"\tdocument.getElementById('statsGrid').innerHTML = html;\n"
"}\n"
"function sortConns(key) {\n"
"\tif (sortKey === key) {\n"
"\t\tsortDir = sortDir === 'asc' ? 'desc' : 'asc';\n"
"\t} else {\n"
"\t\tsortKey = key;\n"
"\t\tsortDir = 'asc';\n"
"\t}\n"
"\trenderConnections();\n"
"}\n"
"function renderConnections() {\n"
"\tconst filterEl = document.getElementById('connFilter');\n"
"\tconst filter = (filterEl ? filterEl.value : '').toLowerCase().trim();\n"
"\n"
"\tlet conns = lastConns.slice();\n"
"\tif (filter) {\n"
"\t\tconns = conns.filter(c =>\n"
"\t\t\t(c.ip||'').toLowerCase().includes(filter) ||\n"
"\t\t\t(c.target||'').toLowerCase().includes(filter) ||\n"
"\t\t\t(c.type||'').toLowerCase().includes(filter)\n"
"\t\t);\n"
"\t}\n"
"\tconns.sort((a, b) => {\n"
"\t\tlet av = a[sortKey], bv = b[sortKey];\n"
"\t\tif (typeof av === 'string') { av = av.toLowerCase(); bv = (bv||'').toLowerCase(); }\n"
"\t\tif (av < bv) return sortDir === 'asc' ? -1 : 1;\n"
"\t\tif (av > bv) return sortDir === 'asc' ? 1 : -1;\n"
"\t\treturn 0;\n"
"\t});\n"
"\n"
"\tif (!conns.length) {\n"
"\t\tdocument.getElementById('connectionsTable').innerHTML = '<div style=\"padding:15px;color:var(--muted);\">No active connections</div>';\n"
"\t\treturn;\n"
"\t}\n"
"\n"
"\tconst cols = [\n"
"\t\t{ key: 'ip', label: 'IP' },\n"
"\t\t{ key: 'port', label: 'Port' },\n"
"\t\t{ key: 'type', label: 'Type' },\n"
"\t\t{ key: 'target', label: 'Target' },\n"
"\t\t{ key: 'duration', label: 'Duration' },\n"
"\t\t{ key: 'bytes_up', label: 'Bytes Up' },\n"
"\t\t{ key: 'bytes_down', label: 'Bytes Down' },\n"
"\t];\n"
"\tlet thead = '<tr>';\n"
"\tcols.forEach(col => {\n"
"\t\tlet cls = '';\n"
"\t\tif (sortKey === col.key) cls = sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc';\n"
"\t\tthead += '<th class=\"'+cls+'\" onclick=\"sortConns(\\''+col.key+'\\')\">'+col.label+'</th>';\n"
"\t});\n"
"\tthead += '<th>Action</th></tr>';\n"
"\n"
"\tlet html = '<table><thead>'+thead+'</thead><tbody>';\n"
"\tconns.forEach(c => {\n"
"\t\tlet badge = '<span class=\"badge\">'+esc(c.type)+'</span>';\n"
"\t\tif (c.type === 'SOCKS5_TCP') badge = '<span class=\"badge socks5-tcp\">SOCKS5 TCP</span>';\n"
"\t\telse if (c.type === 'SOCKS5_UDP') badge = '<span class=\"badge socks5-udp\">SOCKS5 UDP</span>';\n"
"\t\telse if (c.type === 'HTTP') badge = '<span class=\"badge http\">HTTP</span>';\n"
"\t\thtml += '<tr><td>'+esc(c.ip)+'</td><td>'+esc(c.port)+'</td><td>'+badge+'</td><td>'+esc(c.target||'N/A')+'</td><td>'+formatUptime(c.duration)+'</td><td>'+formatBytes(c.bytes_up)+'</td><td>'+formatBytes(c.bytes_down)+'</td><td><button class=\"btn btn-sm btn-danger\" data-id=\"'+esc(c.id)+'\" onclick=\"kickConn(this.dataset.id)\">Kick</button></td></tr>';\n"
"\t});\n"
"\thtml += '</tbody></table>';\n"
"\tdocument.getElementById('connectionsTable').innerHTML = html;\n"
"}\n"
"async function kickConn(id) {\n"
"\tif (!id) return;\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/kick', {\n"
"\t\t\tmethod: 'POST',\n"
"\t\t\theaders: { 'Content-Type': 'application/json' },\n"
"\t\t\tbody: JSON.stringify({ id: id })\n"
"\t\t});\n"
"\t\tif (res.ok) {\n"
"\t\t\tfetchAll();\n"
"\t\t} else {\n"
"\t\t\tconst data = await res.json().catch(() => ({}));\n"
"\t\t\talert('Kick failed: ' + (data.error || res.status));\n"
"\t\t}\n"
"\t} catch (err) {\n"
"\t\talert('Kick failed: ' + err.message);\n"
"\t}\n"
"}\n"
"function exportConns(format) {\n"
"\twindow.location.href = '/api/export?format=' + encodeURIComponent(format);\n"
"}\n"
"function renderUpstream(up) {\n"
"\tconst status = up.status || [];\n"
"\tlet html = '<div style=\"padding:8px 0;color:var(--muted2);\">';\n"
"\tif (status.length) {\n"
"\t\thtml += status.map(s => {\n"
"\t\t\tconst badge = s.alive\n"
"\t\t\t\t? '<span class=\"badge\" style=\"background:var(--badge-http-bg);color:var(--badge-http-fg);\">alive</span>'\n"
"\t\t\t\t: '<span class=\"badge\" style=\"background:var(--danger-hover-bg);color:var(--danger-fg);\">dead</span>';\n"
"\t\t\treturn esc(s.addr) + ' ' + badge;\n"
"\t\t}).join(' &nbsp;|&nbsp; ');\n"
"\t\thtml += '<br><span style=\"font-size:0.78rem;color:var(--muted);\">Round-robin index hiện tại: ' + up.current_index + '</span>';\n"
"\t} else {\n"
"\t\thtml += '<span style=\"color:var(--muted);\">No upstream proxies configured.</span>';\n"
"\t}\n"
"\thtml += '</div>';\n"
"\tdocument.getElementById('upstreamInfo').innerHTML = html;\n"
"}\n"
"async function fetchNetworkConfig() {\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/network-config');\n"
"\t\tif (!res.ok) throw new Error('HTTP ' + res.status);\n"
"\t\tconst data = await res.json();\n"
"\t\tdocument.getElementById('netAllow').value = (data.allow_list || []).join('\\n');\n"
"\t\tdocument.getElementById('netDeny').value = (data.deny_list || []).join('\\n');\n"
"\t\tdocument.getElementById('netUpstream').value = (data.upstream_proxies || []).join('\\n');\n"
"\t} catch (e) {\n"
"\t\tconsole.error('fetchNetworkConfig error:', e);\n"
"\t}\n"
"}\n"
"function linesToList(text) {\n"
"\treturn text.split('\\n').map(s => s.trim()).filter(s => s.length > 0);\n"
"}\n"
"async function saveNetworkConfig() {\n"
"\tconst msg = document.getElementById('netMsg');\n"
"\tmsg.textContent = 'Saving...';\n"
"\tmsg.className = 'modal-msg';\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/network-config', {\n"
"\t\t\tmethod: 'POST',\n"
"\t\t\theaders: { 'Content-Type': 'application/json' },\n"
"\t\t\tbody: JSON.stringify({\n"
"\t\t\t\tallow_list: linesToList(document.getElementById('netAllow').value),\n"
"\t\t\t\tdeny_list: linesToList(document.getElementById('netDeny').value),\n"
"\t\t\t\tupstream_proxies: linesToList(document.getElementById('netUpstream').value)\n"
"\t\t\t})\n"
"\t\t});\n"
"\t\tconst data = await res.json();\n"
"\t\tif (!res.ok) {\n"
"\t\t\tmsg.textContent = data.error || ('HTTP Error ' + res.status);\n"
"\t\t\tmsg.className = 'modal-msg error';\n"
"\t\t\treturn;\n"
"\t\t}\n"
"\t\tmsg.textContent = 'Saved & applied successfully.';\n"
"\t\tmsg.className = 'modal-msg success';\n"
"\t\tfetchReloadHistory();\n"
"\t} catch (err) {\n"
"\t\tmsg.textContent = 'Connection error: ' + err.message;\n"
"\t\tmsg.className = 'modal-msg error';\n"
"\t}\n"
"}\n"
"async function reloadFromDisk() {\n"
"\tconst msg = document.getElementById('netMsg');\n"
"\tmsg.textContent = 'Reloading...';\n"
"\tmsg.className = 'modal-msg';\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/reload', { method: 'POST', headers: { 'Content-Type': 'application/json' } });\n"
"\t\tconst data = await res.json();\n"
"\t\tif (!res.ok) {\n"
"\t\t\tmsg.textContent = data.error || ('HTTP Error ' + res.status);\n"
"\t\t\tmsg.className = 'modal-msg error';\n"
"\t\t\treturn;\n"
"\t\t}\n"
"\t\tmsg.textContent = 'Reloaded from disk successfully.';\n"
"\t\tmsg.className = 'modal-msg success';\n"
"\t\tfetchNetworkConfig();\n"
"\t\tfetchReloadHistory();\n"
"\t} catch (err) {\n"
"\t\tmsg.textContent = 'Connection error: ' + err.message;\n"
"\t\tmsg.className = 'modal-msg error';\n"
"\t}\n"
"}\n"
"async function fetchReloadHistory() {\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/reload-history');\n"
"\t\tif (!res.ok) throw new Error('HTTP ' + res.status);\n"
"\t\tconst data = await res.json();\n"
"\t\trenderReloadHistory(data.history || []);\n"
"\t} catch (e) {\n"
"\t\tdocument.getElementById('reloadHistoryTable').innerHTML = '<div style=\"padding:15px;color:var(--muted);\">Failed to load reload history</div>';\n"
"\t}\n"
"}\n"
"function renderReloadHistory(history) {\n"
"\tif (!history.length) {\n"
"\t\tdocument.getElementById('reloadHistoryTable').innerHTML = '<div style=\"padding:15px;color:var(--muted);\">No reload events yet.</div>';\n"
"\t\treturn;\n"
"\t}\n"
"\tlet html = '<table><thead><tr><th>Time</th><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody>';\n"
"\thistory.forEach(ev => {\n"
"\t\tconst time = new Date(ev.t * 1000).toLocaleString();\n"
"\t\tconst statusBadge = ev.success\n"
"\t\t\t? '<span class=\"badge\" style=\"background:var(--badge-http-bg);color:var(--badge-http-fg);\">OK</span>'\n"
"\t\t\t: '<span class=\"badge\" style=\"background:var(--danger-hover-bg);color:var(--danger-fg);\">FAILED</span>';\n"
"\t\tlet details = '';\n"
"\t\tif (ev.success) {\n"
"\t\t\tdetails = ev.allow_count + ' allow, ' + ev.deny_count + ' deny, ' + ev.upstream_count + ' upstream, ' + ev.user_count + ' users';\n"
"\t\t\tif (ev.invalid_cidrs && ev.invalid_cidrs.length) {\n"
"\t\t\t\tdetails += ' — <span style=\"color:var(--danger-fg);\">⚠️ invalid: ' + esc(ev.invalid_cidrs.join(', ')) + '</span>';\n"
"\t\t\t}\n"
"\t\t} else {\n"
"\t\t\tdetails = '<span style=\"color:var(--danger-fg);\">' + esc(ev.error || 'Unknown error') + '</span>';\n"
"\t\t}\n"
"\t\thtml += '<tr><td>' + time + '</td><td>' + esc(ev.source) + '</td><td>' + statusBadge + '</td><td>' + details + '</td></tr>';\n"
"\t});\n"
"\thtml += '</tbody></table>';\n"
"\tdocument.getElementById('reloadHistoryTable').innerHTML = html;\n"
"}\n"
"async function fetchTokens() {\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/tokens');\n"
"\t\tif (!res.ok) throw new Error('HTTP ' + res.status);\n"
"\t\tconst data = await res.json();\n"
"\t\trenderTokens(data.tokens || []);\n"
"\t} catch (e) {\n"
"\t\tdocument.getElementById('tokensTable').innerHTML = '<div style=\"padding:15px;color:var(--muted);\">Failed to load tokens</div>';\n"
"\t}\n"
"}\n"
"function renderTokens(tokens) {\n"
"\tif (!tokens.length) {\n"
"\t\tdocument.getElementById('tokensTable').innerHTML = '<div style=\"padding:15px;color:var(--muted);\">No API tokens yet.</div>';\n"
"\t\treturn;\n"
"\t}\n"
"\tlet html = '<table><thead><tr><th>Name</th><th>Created</th><th>Action</th></tr></thead><tbody>';\n"
"\ttokens.forEach(t => {\n"
"\t\tconst created = new Date(t.created_at * 1000).toLocaleString();\n"
"\t\thtml += '<tr><td>' + esc(t.name) + '</td><td>' + created + '</td><td><button class=\"btn btn-sm btn-danger\" data-name=\"' + esc(t.name) + '\" onclick=\"deleteToken(this.dataset.name)\">Revoke</button></td></tr>';\n"
"\t});\n"
"\thtml += '</tbody></table>';\n"
"\tdocument.getElementById('tokensTable').innerHTML = html;\n"
"}\n"
"function openTokenModal() {\n"
"\tdocument.getElementById('tokenMsg').textContent = '';\n"
"\tdocument.getElementById('tokenMsg').className = 'modal-msg';\n"
"\tdocument.getElementById('tokenResultBox').style.display = 'none';\n"
"\tdocument.getElementById('tokenForm').reset();\n"
"\tdocument.getElementById('tName').disabled = false;\n"
"\tdocument.getElementById('tokenSubmitBtn').style.display = 'inline-block';\n"
"\tdocument.getElementById('tokenModalOverlay').classList.add('open');\n"
"}\n"
"function closeTokenModal() {\n"
"\tdocument.getElementById('tokenModalOverlay').classList.remove('open');\n"
"\tfetchTokens();\n"
"}\n"
"async function submitTokenForm(e) {\n"
"\te.preventDefault();\n"
"\tconst msg = document.getElementById('tokenMsg');\n"
"\tconst name = document.getElementById('tName').value.trim();\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/tokens', {\n"
"\t\t\tmethod: 'POST',\n"
"\t\t\theaders: { 'Content-Type': 'application/json' },\n"
"\t\t\tbody: JSON.stringify({ name: name })\n"
"\t\t});\n"
"\t\tconst data = await res.json();\n"
"\t\tif (!res.ok) {\n"
"\t\t\tmsg.textContent = data.error || ('HTTP Error ' + res.status);\n"
"\t\t\tmsg.className = 'modal-msg error';\n"
"\t\t\treturn false;\n"
"\t\t}\n"
"\t\tdocument.getElementById('tokenResultValue').textContent = data.token;\n"
"\t\tdocument.getElementById('tokenResultBox').style.display = 'block';\n"
"\t\tdocument.getElementById('tName').disabled = true;\n"
"\t\tdocument.getElementById('tokenSubmitBtn').style.display = 'none';\n"
"\t\tmsg.textContent = '';\n"
"\t} catch (err) {\n"
"\t\tmsg.textContent = 'Connection error: ' + err.message;\n"
"\t\tmsg.className = 'modal-msg error';\n"
"\t}\n"
"\treturn false;\n"
"}\n"
"async function deleteToken(name) {\n"
"\tif (!confirm('Revoke API token \"' + name + '\"? Any script using it will stop working immediately.')) return;\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/tokens/delete', {\n"
"\t\t\tmethod: 'POST',\n"
"\t\t\theaders: { 'Content-Type': 'application/json' },\n"
"\t\t\tbody: JSON.stringify({ name: name })\n"
"\t\t});\n"
"\t\tif (res.ok) {\n"
"\t\t\tfetchTokens();\n"
"\t\t} else {\n"
"\t\t\tconst data = await res.json().catch(() => ({}));\n"
"\t\t\talert('Revoke failed: ' + (data.error || res.status));\n"
"\t\t}\n"
"\t} catch (err) {\n"
"\t\talert('Revoke failed: ' + err.message);\n"
"\t}\n"
"}\n"
"async function fetchAuditLog() {\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/audit-log');\n"
"\t\tif (!res.ok) throw new Error('HTTP ' + res.status);\n"
"\t\tconst data = await res.json();\n"
"\t\trenderAuditLog(data.events || []);\n"
"\t} catch (e) {\n"
"\t\tdocument.getElementById('auditTable').innerHTML = '<div style=\"padding:15px;color:var(--muted);\">Failed to load audit log</div>';\n"
"\t}\n"
"}\n"
"function renderAuditLog(events) {\n"
"\tif (!events.length) {\n"
"\t\tdocument.getElementById('auditTable').innerHTML = '<div style=\"padding:15px;color:var(--muted);\">No audit events yet.</div>';\n"
"\t\treturn;\n"
"\t}\n"
"\tlet html = '<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>';\n"
"\tevents.forEach(ev => {\n"
"\t\tconst time = new Date(ev.t * 1000).toLocaleString();\n"
"\t\thtml += '<tr><td>' + time + '</td><td>' + esc(ev.actor) + '</td><td>' + esc(ev.action) + '</td><td style=\"font-size:0.8rem;color:var(--muted2);\">' + esc(ev.details || '') + '</td></tr>';\n"
"\t});\n"
"\thtml += '</tbody></table>';\n"
"\tdocument.getElementById('auditTable').innerHTML = html;\n"
"}\n"
"async function restoreConfig(e) {\n"
"\tconst file = e.target.files[0];\n"
"\tif (!file) return;\n"
"\tconst msg = document.getElementById('backupMsg');\n"
"\tif (!confirm('Restore config from \"' + file.name + '\"? This will overwrite current settings (users, allow/deny lists, upstream, tokens) and apply immediately.')) {\n"
"\t\te.target.value = '';\n"
"\t\treturn;\n"
"\t}\n"
"\tmsg.textContent = 'Restoring...';\n"
"\tmsg.className = 'modal-msg';\n"
"\ttry {\n"
"\t\tconst text = await file.text();\n"
"\t\tconst res = await fetch('/api/config/import', {\n"
"\t\t\tmethod: 'POST',\n"
"\t\t\theaders: { 'Content-Type': 'application/json' },\n"
"\t\t\tbody: text\n"
"\t\t});\n"
"\t\tconst data = await res.json();\n"
"\t\tif (!res.ok) {\n"
"\t\t\tmsg.textContent = data.error || ('HTTP Error ' + res.status);\n"
"\t\t\tmsg.className = 'modal-msg error';\n"
"\t\t\treturn;\n"
"\t\t}\n"
"\t\tmsg.textContent = 'Restored successfully. Reloading dashboard...';\n"
"\t\tmsg.className = 'modal-msg success';\n"
"\t\tsetTimeout(() => window.location.reload(), 1500);\n"
"\t} catch (err) {\n"
"\t\tmsg.textContent = 'Connection error: ' + err.message;\n"
"\t\tmsg.className = 'modal-msg error';\n"
"\t} finally {\n"
"\t\te.target.value = '';\n"
"\t}\n"
"}\n"
"async function fetchUsers() {\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/users');\n"
"\t\tif (!res.ok) throw new Error('HTTP '+res.status);\n"
"\t\tconst data = await res.json();\n"
"\t\trenderUsers(data.users || []);\n"
"\t} catch (e) {\n"
"\t\tdocument.getElementById('usersTable').innerHTML = '<div style=\"padding:15px;color:var(--muted);\">Failed to load users</div>';\n"
"\t}\n"
"}\n"
"function renderUsers(users) {\n"
"\tif (!users.length) {\n"
"\t\tdocument.getElementById('usersTable').innerHTML = '<div style=\"padding:15px;color:var(--muted);\">No multi-user accounts configured yet — proxy still works via -u/-P if set.</div>';\n"
"\t\treturn;\n"
"\t}\n"
"\tlet html = '<table><thead><tr><th>Username</th><th>Max Bandwidth</th><th>Max Conns</th><th>Quota/Month</th><th>Used This Month</th><th>Action</th></tr></thead><tbody>';\n"
"\tusers.forEach(u => {\n"
"\t\tconst bw = u.max_bandwidth_bps > 0 ? formatBytes(u.max_bandwidth_bps)+'/s' : 'Unlimited';\n"
"\t\tconst maxConn = u.max_connections > 0 ? u.max_connections : 'Unlimited';\n"
"\t\tconst quota = u.quota_bytes_per_month > 0 ? formatBytes(u.quota_bytes_per_month) : 'Unlimited';\n"
"\t\tconst used = formatBytes(u.usage_bytes_this_month || 0);\n"
"\t\tconst overQuota = u.quota_bytes_per_month > 0 && (u.usage_bytes_this_month || 0) >= u.quota_bytes_per_month;\n"
"\t\tconst usedCell = overQuota ? '<span style=\"color:var(--danger-fg);\">' + used + ' ⚠️ OVER QUOTA</span>' : used;\n"
"\t\thtml += '<tr><td>'+esc(u.username)+'</td><td>'+bw+'</td><td>'+maxConn+'</td><td>'+quota+'</td><td>'+usedCell+'</td><td><button class=\"btn btn-sm btn-danger\" data-name=\"'+esc(u.username)+'\" onclick=\"deleteUser(this.dataset.name)\">Delete</button></td></tr>';\n"
"\t});\n"
"\thtml += '</tbody></table>';\n"
"\tdocument.getElementById('usersTable').innerHTML = html;\n"
"}\n"
"function openUserModal() {\n"
"\tdocument.getElementById('userMsg').textContent = '';\n"
"\tdocument.getElementById('userMsg').className = 'modal-msg';\n"
"\tdocument.getElementById('userForm').reset();\n"
"\tdocument.getElementById('userModalOverlay').classList.add('open');\n"
"}\n"
"function closeUserModal() {\n"
"\tdocument.getElementById('userModalOverlay').classList.remove('open');\n"
"}\n"
"async function submitUserForm(e) {\n"
"\te.preventDefault();\n"
"\tconst msg = document.getElementById('userMsg');\n"
"\tconst username = document.getElementById('uUsername').value.trim();\n"
"\tconst password = document.getElementById('uPassword').value;\n"
"\tconst bwKBs = parseFloat(document.getElementById('uBandwidth').value) || 0;\n"
"\tconst maxConn = parseInt(document.getElementById('uMaxConn').value) || 0;\n"
"\tconst quotaMB = parseFloat(document.getElementById('uQuota').value) || 0;\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/users', {\n"
"\t\t\tmethod: 'POST',\n"
"\t\t\theaders: { 'Content-Type': 'application/json' },\n"
"\t\t\tbody: JSON.stringify({\n"
"\t\t\t\tusername: username, password: password,\n"
"\t\t\t\tmax_bandwidth_bps: Math.round(bwKBs * 1024),\n"
"\t\t\t\tmax_connections: maxConn,\n"
"\t\t\t\tquota_bytes_per_month: Math.round(quotaMB * 1024 * 1024)\n"
"\t\t\t})\n"
"\t\t});\n"
"\t\tconst data = await res.json();\n"
"\t\tif (!res.ok) {\n"
"\t\t\tmsg.textContent = data.error || ('HTTP Error ' + res.status);\n"
"\t\t\tmsg.className = 'modal-msg error';\n"
"\t\t\treturn false;\n"
"\t\t}\n"
"\t\tcloseUserModal();\n"
"\t\tfetchUsers();\n"
"\t} catch (err) {\n"
"\t\tmsg.textContent = 'Connection error: ' + err.message;\n"
"\t\tmsg.className = 'modal-msg error';\n"
"\t}\n"
"\treturn false;\n"
"}\n"
"async function deleteUser(username) {\n"
"\tif (!confirm('Delete proxy user \"'+username+'\"?')) return;\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/users/delete', {\n"
"\t\t\tmethod: 'POST',\n"
"\t\t\theaders: { 'Content-Type': 'application/json' },\n"
"\t\t\tbody: JSON.stringify({ username: username })\n"
"\t\t});\n"
"\t\tif (res.ok) {\n"
"\t\t\tfetchUsers();\n"
"\t\t} else {\n"
"\t\t\tconst data = await res.json().catch(() => ({}));\n"
"\t\t\talert('Delete failed: ' + (data.error || res.status));\n"
"\t\t}\n"
"\t} catch (err) {\n"
"\t\talert('Delete failed: ' + err.message);\n"
"\t}\n"
"}\n"
"function esc(v) {\n"
"\treturn String(v === undefined || v === null ? '' : v)\n"
"\t\t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')\n"
"\t\t.replace(/\"/g, '&quot;').replace(/'/g, '&#39;');\n"
"}\n"
"function formatBytes(b) {\n"
"\tif (b === undefined || b === null) return '0 B';\n"
"\tconst units=['B','KiB','MiB','GiB','TiB'];\n"
"\tlet u=0;\n"
"\twhile(b>=1024 && u<units.length-1){ b/=1024; u++; }\n"
"\treturn b.toFixed(1)+' '+units[u];\n"
"}\n"
"function formatUptime(sec) {\n"
"\tif (!sec) return '00:00:00';\n"
"\tconst h=Math.floor(sec/3600), m=Math.floor((sec%3600)/60), s=Math.floor(sec%60);\n"
"\treturn String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');\n"
"}\n"
"function openPwModal() {\n"
"\tdocument.getElementById('pwMsg').textContent = '';\n"
"\tdocument.getElementById('pwMsg').className = 'modal-msg';\n"
"\tdocument.getElementById('pwForm').reset();\n"
"\tdocument.getElementById('pwModalOverlay').classList.add('open');\n"
"}\n"
"function closePwModal() {\n"
"\tdocument.getElementById('pwModalOverlay').classList.remove('open');\n"
"}\n"
"async function submitPwChange(e) {\n"
"\te.preventDefault();\n"
"\tconst msg = document.getElementById('pwMsg');\n"
"\tconst curPass = document.getElementById('curPass').value;\n"
"\tconst newUser = document.getElementById('newUser').value.trim();\n"
"\tconst newPass = document.getElementById('newPass').value;\n"
"\tconst newPass2 = document.getElementById('newPass2').value;\n"
"\n"
"\tif (newPass !== newPass2) {\n"
"\t\tmsg.textContent = 'Password confirmation does not match.';\n"
"\t\tmsg.className = 'modal-msg error';\n"
"\t\treturn false;\n"
"\t}\n"
"\tif (newPass.length < 8) {\n"
"\t\tmsg.textContent = 'New password must be at least 8 characters.';\n"
"\t\tmsg.className = 'modal-msg error';\n"
"\t\treturn false;\n"
"\t}\n"
"\n"
"\ttry {\n"
"\t\tconst res = await fetch('/api/change-password', {\n"
"\t\t\tmethod: 'POST',\n"
"\t\t\theaders: { 'Content-Type': 'application/json' },\n"
"\t\t\tbody: JSON.stringify({\n"
"\t\t\t\tcurrent_password: curPass,\n"
"\t\t\t\tnew_username: newUser,\n"
"\t\t\t\tnew_password: newPass\n"
"\t\t\t})\n"
"\t\t});\n"
"\t\tconst data = await res.json();\n"
"\t\tif (!res.ok) {\n"
"\t\t\tmsg.textContent = data.error || ('HTTP Error ' + res.status);\n"
"\t\t\tmsg.className = 'modal-msg error';\n"
"\t\t\treturn false;\n"
"\t\t}\n"
"\t\tmsg.textContent = 'Changed successfully! The browser will ask you to log in again with the new credentials.';\n"
"\t\tmsg.className = 'modal-msg success';\n"
"\t\tsetTimeout(() => { window.location.reload(); }, 1500);\n"
"\t} catch (err) {\n"
"\t\tmsg.textContent = 'Connection error: ' + err.message;\n"
"\t\tmsg.className = 'modal-msg error';\n"
"\t}\n"
"\treturn false;\n"
"}\n"
"// Dữ liệu cốt lõi của dashboard (stats, connections, users) chạy trước và độc lập\n"
"// với Chart.js — nếu CDN chart bị chặn/lỗi mạng, dashboard vẫn phải hoạt động bình thường.\n"
"fetchAll();\n"
"fetchUsers();\n"
"fetchNetworkConfig();\n"
"fetchReloadHistory();\n"
"fetchTokens();\n"
"fetchAuditLog();\n"
"setInterval(fetchAll, 5000);\n"
"setInterval(fetchUsers, 15000);\n"
"setInterval(fetchReloadHistory, 15000);\n"
"setInterval(fetchAuditLog, 15000);\n"
"\n"
"// Biểu đồ real-time (phụ thuộc CDN Chart.js) — bọc try/catch để một lỗi ở đây\n"
"// không làm dừng toàn bộ script phía trên (đã từng gây ra bug \"mọi thứ kẹt ở Loading...\").\n"
"// loadScript/loadChartJS: thử lần lượt vài CDN khác nhau, vì 1 CDN cụ thể (vd cdnjs) có\n"
"// thể bị chặn ở 1 số mạng/firewall dù máy vẫn có Internet bình thường.\n"
"function loadScript(src) {\n"
"\treturn new Promise((resolve, reject) => {\n"
"\t\tconst tag = document.createElement('script');\n"
"\t\ttag.src = src;\n"
"\t\ttag.onload = () => resolve();\n"
"\t\ttag.onerror = () => reject(new Error('Không tải được: ' + src));\n"
"\t\tdocument.head.appendChild(tag);\n"
"\t});\n"
"}\n"
"async function loadChartJS() {\n"
"\tconst urls = [\n"
"\t\t'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js',\n"
"\t\t'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js',\n"
"\t\t'https://unpkg.com/chart.js@4.4.4/dist/chart.umd.min.js'\n"
"\t];\n"
"\tfor (const url of urls) {\n"
"\t\ttry {\n"
"\t\t\tawait loadScript(url);\n"
"\t\t\tif (typeof Chart !== 'undefined') return true;\n"
"\t\t} catch (e) {\n"
"\t\t\tconsole.warn(e.message);\n"
"\t\t}\n"
"\t}\n"
"\treturn false;\n"
"}\n"
"(async function() {\n"
"try {\n"
"\tconst chartLoaded = await loadChartJS();\n"
"\tif (!chartLoaded) {\n"
"\t\tthrow new Error('Không tải được Chart.js từ bất kỳ CDN nào (cdnjs/jsdelivr/unpkg) — có thể mạng/firewall đang chặn các CDN này');\n"
"\t}\n"
"\tinitChart();\n"
"\tconnectStream();\n"
"} catch (err) {\n"
"\tconsole.error('Traffic chart disabled:', err);\n"
"\tconst statusEl = document.getElementById('streamStatus');\n"
"\tif (statusEl) { statusEl.textContent = '(unavailable)'; statusEl.style.color = 'var(--danger-fg)'; }\n"
"\tconst canvasEl = document.getElementById('trafficChart');\n"
"\tif (canvasEl) {\n"
"\t\tcanvasEl.outerHTML = '<div style=\"padding:20px;color:var(--danger-fg);font-size:0.85rem;\">'\n"
"\t\t\t+ '⚠️ Không tải được biểu đồ: ' + err.message + '<br>'\n"
"\t\t\t+ 'Các phần khác của dashboard (stats, connections, users) vẫn hoạt động bình thường.'\n"
"\t\t\t+ '</div>';\n"
"\t}\n"
"}\n"
"})();\n"
"</script>\n"
"</body></html>\n";

/* ========================== DASHBOARD ========================== */
static int create_listener(const char *addr, int port, int backlog) {
    struct addrinfo hints, *res = NULL;
    char ps[8];
    snprintf(ps, sizeof(ps), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
    if (getaddrinfo(addr, ps, &hints, &res) != 0 || !res) return -1;
    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (res->ai_family == AF_INET6) {
        int off = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
    }
    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0 || listen(fd, backlog) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static bool bind_is_loopback(const char *a) {
    return strncmp(a, "127.", 4) == 0 || strcmp(a, "::1") == 0;
}

/* ---- lịch sử mẫu thống kê (biểu đồ real-time) ---- */
typedef struct { long long t, up_bps, down_bps; int active, udp_assocs; } Sample;
#define HIST_MAX 300                    /* 300 mẫu * 2s = 10 phút gần nhất */
static Sample g_hist[HIST_MAX];
static int g_hist_count = 0, g_hist_next = 0;
static unsigned long g_sample_seq = 0;
static Sample g_latest;
static pthread_mutex_t hist_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hist_cond;        /* khởi tạo trong main (đồng hồ monotonic) */

static void sample_json(Buf *b, const Sample *s) {
    buf_printf(b, "{\"t\":%lld,\"up_bps\":%lld,\"down_bps\":%lld,\"active\":%d,\"udp_assocs\":%d}",
               s->t, s->up_bps, s->down_bps, s->active, s->udp_assocs);
}

static void hist_push(const Sample *s) {
    pthread_mutex_lock(&hist_mutex);
    g_hist[g_hist_next] = *s;
    g_hist_next = (g_hist_next + 1) % HIST_MAX;
    if (g_hist_count < HIST_MAX) g_hist_count++;
    g_latest = *s;
    g_sample_seq++;
    pthread_cond_broadcast(&hist_cond);
    pthread_mutex_unlock(&hist_mutex);
}

/* ---- request ---- */
typedef struct {
    char method[8];
    char path[512];
    char query[512];
    char authz[700];
    char ctype[100];
    char origin[256];
    char host[256];
    char sfs[40];
    long long clen;                 /* -1 = không có */
    char peer[64];
    char actor[NAME_LEN * 2 + 24];
    const uint8_t *pre; size_t pre_len;     /* byte của body đã đọc cùng header */
    char *body; size_t body_len;
    bool body_read;
} DReq;

static const char *status_text(int code) {
    switch (code) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 503: return "Service Unavailable";
    default: return code >= 500 ? "Internal Server Error" : "OK";
    }
}

static void dash_send(int fd, int code, const char *ctype, const char *body, size_t len, const char *extra) {
    char head[1200];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n"
                     "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n%s\r\n",
                     code, status_text(code), ctype, len, extra ? extra : "");
    if (n <= 0 || n >= (int)sizeof(head)) return;
    if (send_all(fd, head, (size_t)n) < 0) return;
    if (len) send_all(fd, body, len);
}

static void dash_json(int fd, int code, Buf *b) {
    if (b->p) dash_send(fd, code, "application/json", b->p, b->len, NULL);
    else dash_send(fd, 500, "application/json", "{\"error\":\"out of memory\"}", 25, NULL);
}

static void dash_error(int fd, int code, const char *msg) {
    Buf b = {0};
    buf_puts(&b, "{\"error\":");
    buf_json_str(&b, msg);
    buf_putc(&b, '}');
    dash_json(fd, code, &b);
    buf_free(&b);
}

static void dash_ok(int fd) { dash_send(fd, 200, "application/json", "{\"success\":true}", 16, NULL); }

static bool need_method(int fd, DReq *r, const char *m) {
    if (strcmp(r->method, m) == 0) return true;
    char msg[48];
    snprintf(msg, sizeof(msg), "Only %s is supported", m);
    dash_error(fd, 405, msg);
    return false;
}

/* Đọc body (tối đa limit byte). false = đã gửi lỗi. */
static bool dash_body(int fd, DReq *r, size_t limit) {
    if (r->body_read) return true;
    r->body_read = true;
    if (r->clen < 0) { r->body = calloc(1, 1); r->body_len = 0; return r->body != NULL; }
    if ((unsigned long long)r->clen > limit) { dash_error(fd, 413, "Request body too large"); return false; }
    size_t need = (size_t)r->clen;
    r->body = malloc(need + 1);
    if (!r->body) { dash_error(fd, 500, "out of memory"); return false; }
    size_t have = r->pre_len < need ? r->pre_len : need;
    memcpy(r->body, r->pre, have);
    while (have < need) {
        ssize_t n = recv(fd, r->body + have, need - have, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { dash_error(fd, 400, "Incomplete request body"); return false; }
        have += (size_t)n;
    }
    r->body[need] = '\0';
    r->body_len = need;
    return true;
}

static JVal *dash_json_body(int fd, DReq *r, size_t limit) {
    if (!dash_body(fd, r, limit)) return NULL;
    char err[96];
    JVal *j = json_parse(r->body, r->body_len, err, sizeof(err));
    if (!j || j->t != J_OBJ) {
        jfree(j);
        dash_error(fd, 400, "Invalid JSON body");
        return NULL;
    }
    return j;
}

static const char *hdr_skip_ws(const char *v) { while (*v == ' ' || *v == '\t') v++; return v; }

static void copy_hdr(char *dst, size_t dsz, const char *line_end_start, const char *line_end) {
    const char *v = hdr_skip_ws(line_end_start);
    size_t n = (size_t)(line_end - v);
    while (n > 0 && (v[n-1] == ' ' || v[n-1] == '\t')) n--;
    if (n >= dsz) n = dsz - 1;
    memcpy(dst, v, n);
    dst[n] = '\0';
}

/* Phân tích request line + header từ buf[0..hdr_end). false = request không hợp lệ. */
static bool dash_parse_head(char *buf, size_t hdr_end, DReq *r) {
    char *p = buf, *end = buf + hdr_end;
    char *eol = memchr(p, '\n', (size_t)(end - p));
    if (!eol) return false;
    char line[1100];
    size_t ll = (size_t)(eol - p);
    if (ll >= sizeof(line)) return false;
    memcpy(line, p, ll);
    line[ll] = '\0';
    if (ll && line[ll-1] == '\r') line[ll-1] = '\0';
    char target[1024], ver[16];
    if (sscanf(line, "%7s %1023s %15s", r->method, target, ver) != 3 || strncmp(ver, "HTTP/1.", 7) != 0) return false;
    char *q = strchr(target, '?');
    if (q) { *q = '\0'; snprintf(r->query, sizeof(r->query), "%s", q + 1); }
    if (strlen(target) >= sizeof(r->path)) return false;
    snprintf(r->path, sizeof(r->path), "%.511s", target);
    r->clen = -1;
    p = eol + 1;
    while (p < end) {
        eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol) break;
        const char *le = eol;
        if (le > p && le[-1] == '\r') le--;
        if (le == p) break;
        const char *colon = memchr(p, ':', (size_t)(le - p));
        if (colon) {
            size_t nl = (size_t)(colon - p);
            const char *v = colon + 1;
            if (nl == 13 && strncasecmp(p, "authorization", 13) == 0) copy_hdr(r->authz, sizeof(r->authz), v, le);
            else if (nl == 12 && strncasecmp(p, "content-type", 12) == 0) copy_hdr(r->ctype, sizeof(r->ctype), v, le);
            else if (nl == 6 && strncasecmp(p, "origin", 6) == 0) copy_hdr(r->origin, sizeof(r->origin), v, le);
            else if (nl == 4 && strncasecmp(p, "host", 4) == 0) copy_hdr(r->host, sizeof(r->host), v, le);
            else if (nl == 14 && strncasecmp(p, "sec-fetch-site", 14) == 0) copy_hdr(r->sfs, sizeof(r->sfs), v, le);
            else if (nl == 14 && strncasecmp(p, "content-length", 14) == 0) {
                char tmp[32];
                copy_hdr(tmp, sizeof(tmp), v, le);
                unsigned long long cl;
                if (!parse_ull_strict(tmp, &cl)) return false;
                r->clen = (long long)cl;
            }
        }
        p = eol + 1;
    }
    return true;
}

/* Chống CSRF: trình duyệt tự đính kèm Basic Auth đã cache vào request cross-site. */
static bool csrf_ok(const DReq *r) {
    if (strcmp(r->method, "GET") == 0 || strcmp(r->method, "HEAD") == 0 || strcmp(r->method, "OPTIONS") == 0) return true;
    if (r->sfs[0] && strcmp(r->sfs, "same-origin") != 0 && strcmp(r->sfs, "none") != 0) return false;
    if (r->origin[0]) {
        const char *o = r->origin;
        if (strncasecmp(o, "http://", 7) == 0) o += 7;
        else if (strncasecmp(o, "https://", 8) == 0) o += 8;
        else return false;
        if (strcasecmp(o, r->host) != 0) return false;
    }
    return strncasecmp(r->ctype, "application/json", 16) == 0;
}

/* Xác thực: Bearer token (script/monitoring) hoặc Basic (đăng nhập web). false = đã gửi lỗi. */
static bool dash_auth(int fd, DReq *r) {
    if (r->peer[0] && auth_is_blocked(r->peer)) {
        dash_send(fd, 429, "text/plain", "429 Too Many Requests - IP tạm thời bị chặn do đăng nhập sai nhiều lần\n", 0, NULL);
        return false;
    }
    if (strncmp(r->authz, "Bearer ", 7) == 0) {
        char h[65];
        hash_api_token(r->authz + 7, h);
        char name[NAME_LEN] = "";
        bool ok = false;
        pthread_mutex_lock(&cfg_mutex);
        for (int i = 0; i < g_cfg.ntokens; i++) {
            if (ct_equal(g_cfg.tokens[i].token_hash, h)) {
                snprintf(name, sizeof(name), "%s", g_cfg.tokens[i].name);
                ok = true;
            }
        }
        pthread_mutex_unlock(&cfg_mutex);
        if (ok) {
            if (r->peer[0]) auth_reset(r->peer);
            snprintf(r->actor, sizeof(r->actor), "token:%s", name);
            return true;
        }
        if (r->peer[0]) auth_record_fail_t(r->peer, DASH_AUTH_FAIL_THRESHOLD);
        dash_send(fd, 401, "text/plain", "401 Unauthorized (invalid token)\n", 33, NULL);
        return false;
    }
    char user[256], pass[256];
    char cuser[NAME_LEN * 2], chash[PW_HASH_MAX + 1];
    pthread_mutex_lock(&cfg_mutex);
    snprintf(cuser, sizeof(cuser), "%s", g_cfg.dash_user);
    snprintf(chash, sizeof(chash), "%s", g_cfg.dash_hash);
    pthread_mutex_unlock(&cfg_mutex);
    bool have = basic_decode(r->authz, user, sizeof(user), pass, sizeof(pass));
    if (!have) { user[0] = pass[0] = '\0'; }
    bool vu = ct_equal(user, cuser);
    bool vp = verify_password_cached(pass, chash);
    if (!have || !vu || !vp) {
        if (r->peer[0]) auth_record_fail_t(r->peer, DASH_AUTH_FAIL_THRESHOLD);
        dash_send(fd, 401, "text/plain", "401 Unauthorized\n", 17, "WWW-Authenticate: Basic realm=\"Dashboard\"\r\n");
        return false;
    }
    if (r->peer[0]) auth_reset(r->peer);
    if (!csrf_ok(r)) {
        dash_send(fd, 403, "text/plain", "403 Forbidden (CSRF check failed)\n", 34, NULL);
        return false;
    }
    snprintf(r->actor, sizeof(r->actor), "dashboard:%.127s", cuser);
    return true;
}

/* ================= HANDLERS ================= */
static void json_stats_fields(Buf *b) {
    Stats s;
    pthread_mutex_lock(&stats_mutex);
    s = g_stats;
    pthread_mutex_unlock(&stats_mutex);
    buf_printf(b, "\"total\":%lld,\"current\":%lld,\"active\":%d,\"socks5_tcp\":%lld,\"socks5_udp\":%lld,\"http\":%lld,"
                  "\"bytes_up\":%lld,\"bytes_down\":%lld,\"udp_up\":%lld,\"udp_down\":%lld,\"udp_assocs\":%d,\"uptime\":%.1f",
               s.total, s.current, count_active(), s.socks5_tcp, s.socks5_udp, s.http,
               s.bytes_up, s.bytes_down, s.udp_up, s.udp_down,
               __atomic_load_n(&g_udp_assoc_count, __ATOMIC_RELAXED), difftime(time(NULL), s.start_time));
}

static void h_stats(int fd, DReq *r) {
    (void)r;
    Buf b = {0};
    buf_putc(&b, '{');
    json_stats_fields(&b);
    buf_putc(&b, '}');
    dash_json(fd, 200, &b);
    buf_free(&b);
}

static void h_all(int fd, DReq *r) {
    (void)r;
    Buf b = {0};
    buf_putc(&b, '{');
    json_stats_fields(&b);
    time_t now = time(NULL);
    buf_puts(&b, ",\"active_connections\":[");
    pthread_mutex_lock(&active_mutex);
    bool first = true;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ActiveConn *c = &g_active_conns[i];
        if (!c->used) continue;
        if (!first) buf_putc(&b, ',');
        first = false;
        buf_printf(&b, "{\"id\":\"c%lld\",\"ip\":", c->id);
        buf_json_str(&b, c->ip);
        buf_printf(&b, ",\"port\":%d,\"type\":", c->port);
        buf_json_str(&b, c->type);
        buf_puts(&b, ",\"target\":");
        buf_json_str(&b, c->target);
        buf_printf(&b, ",\"start_time\":%lld,\"bytes_up\":%lld,\"bytes_down\":%lld,\"duration\":%.1f}",
                   (long long)c->start_time, __atomic_load_n(&c->bytes_up, __ATOMIC_RELAXED),
                   __atomic_load_n(&c->bytes_down, __ATOMIC_RELAXED), difftime(now, c->start_time));
    }
    buf_puts(&b, "],\"udp_associations\":{");
    first = true;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ActiveConn *c = &g_active_conns[i];
        if (!c->used || strcmp(c->type, "SOCKS5_UDP") != 0) continue;
        char key[96];
        snprintf(key, sizeof(key), "%s:%d", c->ip, c->port);
        if (!first) buf_putc(&b, ',');
        first = false;
        buf_json_str(&b, key);
        buf_puts(&b, ":{\"client_addr\":");
        buf_json_str(&b, c->udp_client);
        buf_printf(&b, ",\"relay_port\":%d,\"active\":true,\"last_activity\":%lld,\"dest_count\":%lld}",
                   c->udp_relay_port, __atomic_load_n(&c->udp_last, __ATOMIC_RELAXED),
                   __atomic_load_n(&c->udp_dests, __ATOMIC_RELAXED));
    }
    pthread_mutex_unlock(&active_mutex);
    buf_puts(&b, "},\"upstream\":{\"proxies\":[");
    pthread_mutex_lock(&upstream_mutex);
    for (int i = 0; i < g_upstream_count; i++) {
        if (i) buf_putc(&b, ',');
        buf_json_str(&b, g_upstreams[i].spec);
    }
    buf_printf(&b, "],\"current_index\":%d,\"status\":[", g_upstream_index);
    for (int i = 0; i < g_upstream_count; i++) {
        if (i) buf_putc(&b, ',');
        buf_puts(&b, "{\"addr\":");
        buf_json_str(&b, g_upstreams[i].spec);
        buf_printf(&b, ",\"alive\":%s}", g_upstreams[i].alive ? "true" : "false");
    }
    pthread_mutex_unlock(&upstream_mutex);
    struct rlimit rl;
    long long fdl = (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) ? (long long)rl.rlim_cur : 0;
    buf_printf(&b, "]},\"system\":{\"cpu_percent\":0.0,\"memory_percent\":0.0,\"fd_limit\":%lld}}", fdl);
    dash_json(fd, 200, &b);
    buf_free(&b);
}

static void h_kick(int fd, DReq *r) {
    if (!need_method(fd, r, "POST")) return;
    JVal *j = dash_json_body(fd, r, 2048);
    if (!j) return;
    const char *id = NULL;
    bool ok = jstr(j, "id", &id);
    if (!ok || !id || !*id) { jfree(j); dash_error(fd, 400, "Missing or invalid 'id'"); return; }
    char info[400];
    bool found = kick_by_id(id, info, sizeof(info));
    char idcopy[48];
    snprintf(idcopy, sizeof(idcopy), "%s", id);
    jfree(j);
    if (!found) { dash_error(fd, 404, "Connection not found (already closed?)"); return; }
    log_info("Dashboard kicked connection %s", info);
    audit_record(r->actor, "kick_connection", info);
    Buf b = {0};
    buf_puts(&b, "{\"success\":true,\"id\":");
    buf_json_str(&b, idcopy);
    buf_putc(&b, '}');
    dash_json(fd, 200, &b);
    buf_free(&b);
}

static void csv_field(Buf *b, const char *s) {
    bool q = strpbrk(s, ",\"\r\n") != NULL;
    if (q) buf_putc(b, '"');
    for (; *s; s++) { if (*s == '"') buf_putc(b, '"'); buf_putc(b, *s); }
    if (q) buf_putc(b, '"');
}

static void h_export(int fd, DReq *r) {
    bool csv = strstr(r->query, "format=csv") != NULL;
    Buf b = {0};
    time_t now = time(NULL);
    if (csv) buf_puts(&b, "id,ip,port,type,target,bytes_up,bytes_down,duration_seconds\n");
    else buf_putc(&b, '[');
    bool first = true;
    pthread_mutex_lock(&active_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        ActiveConn *c = &g_active_conns[i];
        if (!c->used) continue;
        long long up = __atomic_load_n(&c->bytes_up, __ATOMIC_RELAXED), dn = __atomic_load_n(&c->bytes_down, __ATOMIC_RELAXED);
        if (csv) {
            buf_printf(&b, "c%lld,", c->id);
            csv_field(&b, c->ip);
            buf_printf(&b, ",%d,", c->port);
            csv_field(&b, c->type); buf_putc(&b, ',');
            csv_field(&b, c->target);
            buf_printf(&b, ",%lld,%lld,%.1f\n", up, dn, difftime(now, c->start_time));
        } else {
            if (!first) buf_putc(&b, ',');
            first = false;
            buf_printf(&b, "{\"ID\":\"c%lld\",\"IP\":", c->id);
            buf_json_str(&b, c->ip);
            buf_printf(&b, ",\"Port\":%d,\"Type\":", c->port);
            buf_json_str(&b, c->type);
            buf_puts(&b, ",\"Target\":");
            buf_json_str(&b, c->target);
            buf_printf(&b, ",\"BytesUp\":%lld,\"BytesDn\":%lld,\"Duration\":%.1f}", up, dn, difftime(now, c->start_time));
        }
    }
    pthread_mutex_unlock(&active_mutex);
    if (!csv) buf_putc(&b, ']');
    if (!b.p) { dash_error(fd, 500, "out of memory"); return; }
    dash_send(fd, 200, csv ? "text/csv" : "application/json", b.p, b.len,
              csv ? "Content-Disposition: attachment; filename=connections.csv\r\n"
                  : "Content-Disposition: attachment; filename=connections.json\r\n");
    buf_free(&b);
}

static void h_change_password(int fd, DReq *r) {
    if (!need_method(fd, r, "POST")) return;
    JVal *j = dash_json_body(fd, r, 4096);
    if (!j) return;
    const char *cur = NULL, *nu = NULL, *np = NULL;
    if (!jstr(j, "current_password", &cur) || !jstr(j, "new_username", &nu) || !jstr(j, "new_password", &np)) {
        jfree(j); dash_error(fd, 400, "Invalid JSON body"); return;
    }
    char curp[256] = "", newu[128] = "", newp[256] = "";
    if ((cur && strlen(cur) >= sizeof(curp)) || (nu && strlen(nu) >= sizeof(newu)) || (np && strlen(np) >= sizeof(newp))) {
        jfree(j); dash_error(fd, 400, "Value too long"); return;
    }
    if (cur) snprintf(curp, sizeof(curp), "%s", cur);
    if (nu) snprintf(newu, sizeof(newu), "%s", nu);
    if (np) snprintf(newp, sizeof(newp), "%s", np);
    jfree(j);

    char chash[PW_HASH_MAX + 1], cuser[NAME_LEN * 2];
    pthread_mutex_lock(&cfg_mutex);
    snprintf(chash, sizeof(chash), "%s", g_cfg.dash_hash);
    snprintf(cuser, sizeof(cuser), "%s", g_cfg.dash_user);
    pthread_mutex_unlock(&cfg_mutex);

    /* Xác thực lại mật khẩu hiện tại (không chỉ dựa vào Basic Auth header đã qua middleware) */
    if (!verify_password(curp, chash)) { dash_error(fd, 403, "Current password is incorrect"); return; }
    if (strlen(newp) < 8) { dash_error(fd, 400, "New password must be at least 8 characters"); return; }
    if (strcmp(newp, curp) == 0) { dash_error(fd, 400, "New password must be different from the current password"); return; }
    trim_inplace(newu);
    char newhash[PW_HASH_MAX + 1];
    if (!hash_password(newp, newhash, sizeof(newhash))) { dash_error(fd, 500, "Failed to hash new password"); return; }

    char finaluser[NAME_LEN * 2];
    pthread_mutex_lock(&cfg_mutex);
    if (newu[0]) snprintf(g_cfg.dash_user, sizeof(g_cfg.dash_user), "%s", newu);
    snprintf(g_cfg.dash_hash, sizeof(g_cfg.dash_hash), "%s", newhash);
    snprintf(finaluser, sizeof(finaluser), "%s", g_cfg.dash_user);
    int rc = cfg_save_locked();
    pthread_mutex_unlock(&cfg_mutex);
    if (rc) log_error("Đổi mật khẩu thành công nhưng KHÔNG ghi được config file: %s (sẽ mất khi restart)", strerror(rc));
    log_info("Dashboard credentials đã được đổi (user: %s -> %s)", cuser, finaluser);
    char det[256];
    snprintf(det, sizeof(det), "user: %.100s -> %.100s", cuser, finaluser);
    audit_record(r->actor, "change_dashboard_password", det);
    Buf b = {0};
    buf_puts(&b, "{\"success\":true,\"username\":");
    buf_json_str(&b, finaluser);
    buf_putc(&b, '}');
    dash_json(fd, 200, &b);
    buf_free(&b);
}

static void h_users(int fd, DReq *r) {
    if (strcmp(r->method, "GET") == 0) {
        Buf b = {0};
        buf_puts(&b, "{\"users\":[");
        pthread_mutex_lock(&cfg_mutex);
        for (int i = 0; i < g_cfg.nusers; i++) {
            const UserCfg *u = &g_cfg.users[i];
            if (i) buf_putc(&b, ',');
            buf_puts(&b, "{\"username\":");
            buf_json_str(&b, u->username);
            buf_printf(&b, ",\"max_bandwidth_bps\":%lld,\"max_connections\":%lld,\"quota_bytes_per_month\":%lld,\"usage_bytes_this_month\":%lld}",
                       u->max_bw_bps, u->max_conns, u->quota_bytes, usage_get(u->username));
        }
        pthread_mutex_unlock(&cfg_mutex);
        buf_puts(&b, "]}");
        dash_json(fd, 200, &b);
        buf_free(&b);
        return;
    }
    if (!need_method(fd, r, "POST")) return;
    JVal *j = dash_json_body(fd, r, 4096);
    if (!j) return;
    const char *un = NULL, *pw = NULL;
    long long bw = 0, mc = 0, q = 0;
    if (!jstr(j, "username", &un) || !jstr(j, "password", &pw) || !jint(j, "max_bandwidth_bps", &bw) ||
        !jint(j, "max_connections", &mc) || !jint(j, "quota_bytes_per_month", &q)) {
        jfree(j); dash_error(fd, 400, "Invalid JSON body"); return;
    }
    char uname[NAME_LEN + 8] = "", pass[256] = "";
    if (un) {
        if (strlen(un) >= sizeof(uname)) { jfree(j); dash_error(fd, 400, "Username too long (max 63 characters)"); return; }
        snprintf(uname, sizeof(uname), "%s", un);
    }
    if (pw) {
        if (strlen(pw) >= sizeof(pass)) { jfree(j); dash_error(fd, 400, "Password too long"); return; }
        snprintf(pass, sizeof(pass), "%s", pw);
    }
    jfree(j);
    trim_inplace(uname);
    if (!uname[0]) { dash_error(fd, 400, "Username required"); return; }
    if (strlen(uname) >= NAME_LEN) { dash_error(fd, 400, "Username too long (max 63 characters)"); return; }
    if (pass[0] && strlen(pass) < 4) { dash_error(fd, 400, "Password must be at least 4 characters"); return; }
    if (bw < 0) bw = 0;
    mc = clamp_ll(mc, 0, 1000000000LL);
    if (q < 0) q = 0;
    char newhash[PW_HASH_MAX + 1] = "";
    if (pass[0] && !hash_password(pass, newhash, sizeof(newhash))) { dash_error(fd, 500, "Failed to hash password"); return; }

    pthread_mutex_lock(&cfg_mutex);
    int idx = -1;
    for (int i = 0; i < g_cfg.nusers; i++) if (strcmp(g_cfg.users[i].username, uname) == 0) { idx = i; break; }
    if (idx >= 0) {
        if (pass[0]) snprintf(g_cfg.users[idx].hash, sizeof(g_cfg.users[idx].hash), "%s", newhash);
        g_cfg.users[idx].max_bw_bps = bw;
        g_cfg.users[idx].max_conns = mc;
        g_cfg.users[idx].quota_bytes = q;
    } else {
        if (!pass[0]) { pthread_mutex_unlock(&cfg_mutex); dash_error(fd, 400, "Password is required when creating a new user"); return; }
        if (g_cfg.nusers >= MAX_USERS) { pthread_mutex_unlock(&cfg_mutex); dash_error(fd, 400, "Too many users"); return; }
        UserCfg *nu = realloc(g_cfg.users, sizeof(UserCfg) * (size_t)(g_cfg.nusers + 1));
        if (!nu) { pthread_mutex_unlock(&cfg_mutex); dash_error(fd, 500, "out of memory"); return; }
        g_cfg.users = nu;
        UserCfg *d = &g_cfg.users[g_cfg.nusers++];
        memset(d, 0, sizeof(*d));
        snprintf(d->username, sizeof(d->username), "%.63s", uname);
        snprintf(d->hash, sizeof(d->hash), "%s", newhash);
        d->max_bw_bps = bw; d->max_conns = mc; d->quota_bytes = q;
        g_cfg.require_proxy_auth = true;
    }
    int rc = cfg_save_locked();
    pthread_mutex_unlock(&cfg_mutex);
    if (rc) {
        char m[160];
        snprintf(m, sizeof(m), "Saved in memory but failed to write config file: %s", strerror(rc));
        dash_error(fd, 500, m);
        return;
    }
    apply_live_bandwidth(uname, bw);        /* áp dụng NGAY cho connection đang mở của user này */
    log_info("Dashboard: đã thêm/cập nhật proxy user '%s' (max_bandwidth_bps=%lld, max_connections=%lld, quota=%lld, đổi password=%s)",
             uname, bw, mc, q, pass[0] ? "true" : "false");
    char det[300];
    snprintf(det, sizeof(det), "username=%s max_bandwidth_bps=%lld max_connections=%lld quota_bytes_per_month=%lld password_changed=%s",
             uname, bw, mc, q, pass[0] ? "true" : "false");
    audit_record(r->actor, "upsert_user", det);
    dash_ok(fd);
}

static void h_users_delete(int fd, DReq *r) {
    if (!need_method(fd, r, "POST")) return;
    JVal *j = dash_json_body(fd, r, 2048);
    if (!j) return;
    const char *un = NULL;
    char uname[NAME_LEN + 8] = "";
    bool ok = jstr(j, "username", &un) && un && *un && strlen(un) < sizeof(uname);
    if (ok) snprintf(uname, sizeof(uname), "%s", un);
    jfree(j);
    if (!ok) { dash_error(fd, 400, "Missing or invalid 'username'"); return; }
    pthread_mutex_lock(&cfg_mutex);
    int idx = -1;
    for (int i = 0; i < g_cfg.nusers; i++) if (strcmp(g_cfg.users[i].username, uname) == 0) { idx = i; break; }
    int rc = 0;
    if (idx >= 0) {
        memmove(&g_cfg.users[idx], &g_cfg.users[idx + 1], sizeof(UserCfg) * (size_t)(g_cfg.nusers - idx - 1));
        g_cfg.nusers--;
        rc = cfg_save_locked();
    }
    pthread_mutex_unlock(&cfg_mutex);
    if (idx < 0) { dash_error(fd, 404, "User not found"); return; }
    if (rc) {
        char m[160];
        snprintf(m, sizeof(m), "Removed in memory but failed to write config file: %s", strerror(rc));
        dash_error(fd, 500, m);
        return;
    }
    log_info("Dashboard: đã xoá proxy user '%s'", uname);
    char det[96];
    snprintf(det, sizeof(det), "username=%s", uname);
    audit_record(r->actor, "delete_user", det);
    dash_ok(fd);
}

static void h_tokens(int fd, DReq *r) {
    if (strcmp(r->method, "GET") == 0) {
        Buf b = {0};
        buf_puts(&b, "{\"tokens\":[");
        pthread_mutex_lock(&cfg_mutex);
        for (int i = 0; i < g_cfg.ntokens; i++) {
            if (i) buf_putc(&b, ',');
            buf_puts(&b, "{\"name\":");
            buf_json_str(&b, g_cfg.tokens[i].name);
            buf_printf(&b, ",\"created_at\":%lld}", g_cfg.tokens[i].created_at);
        }
        pthread_mutex_unlock(&cfg_mutex);
        buf_puts(&b, "]}");
        dash_json(fd, 200, &b);
        buf_free(&b);
        return;
    }
    if (!need_method(fd, r, "POST")) return;
    JVal *j = dash_json_body(fd, r, 2048);
    if (!j) return;
    const char *nm = NULL;
    char name[NAME_LEN + 8] = "";
    bool ok = jstr(j, "name", &nm);
    if (ok && nm) {
        if (strlen(nm) >= sizeof(name)) ok = false;
        else snprintf(name, sizeof(name), "%s", nm);
    }
    jfree(j);
    if (!ok) { dash_error(fd, 400, "Invalid JSON body"); return; }
    trim_inplace(name);
    if (!name[0]) { dash_error(fd, 400, "Name required"); return; }
    if (strlen(name) >= NAME_LEN) { dash_error(fd, 400, "Name too long (max 63 characters)"); return; }
    char token[72], thash[72];
    if (!gen_token_hex(token, sizeof(token))) { dash_error(fd, 500, "Failed to generate token"); return; }
    hash_api_token(token, thash);

    pthread_mutex_lock(&cfg_mutex);
    for (int i = 0; i < g_cfg.ntokens; i++) {
        if (strcmp(g_cfg.tokens[i].name, name) == 0) {
            pthread_mutex_unlock(&cfg_mutex);
            dash_error(fd, 409, "A token with this name already exists — delete it first if you want to regenerate");
            return;
        }
    }
    if (g_cfg.ntokens >= MAX_TOKENS) { pthread_mutex_unlock(&cfg_mutex); dash_error(fd, 400, "Too many tokens"); return; }
    TokenCfg *nt = realloc(g_cfg.tokens, sizeof(TokenCfg) * (size_t)(g_cfg.ntokens + 1));
    if (!nt) { pthread_mutex_unlock(&cfg_mutex); dash_error(fd, 500, "out of memory"); return; }
    g_cfg.tokens = nt;
    TokenCfg *d = &g_cfg.tokens[g_cfg.ntokens++];
    memset(d, 0, sizeof(*d));
    snprintf(d->name, sizeof(d->name), "%.63s", name);
    snprintf(d->token_hash, sizeof(d->token_hash), "%s", thash);
    d->created_at = (long long)time(NULL);
    int rc = cfg_save_locked();
    pthread_mutex_unlock(&cfg_mutex);
    if (rc) {
        char m[160];
        snprintf(m, sizeof(m), "Saved in memory but failed to write config file: %s", strerror(rc));
        dash_error(fd, 500, m);
        return;
    }
    log_info("Dashboard: đã tạo API token mới '%s'", name);
    char det[96];
    snprintf(det, sizeof(det), "name=%s", name);
    audit_record(r->actor, "create_api_token", det);
    Buf b = {0};
    buf_puts(&b, "{\"success\":true,\"token\":");
    buf_json_str(&b, token);
    buf_puts(&b, ",\"name\":");
    buf_json_str(&b, name);
    buf_putc(&b, '}');
    dash_json(fd, 200, &b);
    buf_free(&b);
}

static void h_tokens_delete(int fd, DReq *r) {
    if (!need_method(fd, r, "POST")) return;
    JVal *j = dash_json_body(fd, r, 2048);
    if (!j) return;
    const char *nm = NULL;
    char name[NAME_LEN + 8] = "";
    bool ok = jstr(j, "name", &nm) && nm && *nm && strlen(nm) < sizeof(name);
    if (ok) snprintf(name, sizeof(name), "%s", nm);
    jfree(j);
    if (!ok) { dash_error(fd, 400, "Missing or invalid 'name'"); return; }
    pthread_mutex_lock(&cfg_mutex);
    int idx = -1;
    for (int i = 0; i < g_cfg.ntokens; i++) if (strcmp(g_cfg.tokens[i].name, name) == 0) { idx = i; break; }
    int rc = 0;
    if (idx >= 0) {
        memmove(&g_cfg.tokens[idx], &g_cfg.tokens[idx + 1], sizeof(TokenCfg) * (size_t)(g_cfg.ntokens - idx - 1));
        g_cfg.ntokens--;
        rc = cfg_save_locked();
    }
    pthread_mutex_unlock(&cfg_mutex);
    if (idx < 0) { dash_error(fd, 404, "Token not found"); return; }
    if (rc) {
        char m[160];
        snprintf(m, sizeof(m), "Removed in memory but failed to write config file: %s", strerror(rc));
        dash_error(fd, 500, m);
        return;
    }
    log_info("Dashboard: đã thu hồi API token '%s'", name);
    char det[96];
    snprintf(det, sizeof(det), "name=%s", name);
    audit_record(r->actor, "revoke_api_token", det);
    dash_ok(fd);
}

static void h_audit(int fd, DReq *r) {
    (void)r;
    Buf b = {0};
    buf_puts(&b, "{\"events\":[");
    pthread_mutex_lock(&audit_mutex);
    for (int k = 0; k < g_audit_count; k++) {       /* mới nhất trước */
        int idx = ((g_audit_next - 1 - k) % AUDIT_MAX + AUDIT_MAX) % AUDIT_MAX;
        const AuditEv *e = &g_audit[idx];
        if (k) buf_putc(&b, ',');
        buf_printf(&b, "{\"t\":%lld,\"actor\":", (long long)e->t);
        buf_json_str(&b, e->actor);
        buf_puts(&b, ",\"action\":");
        buf_json_str(&b, e->action);
        if (e->details[0]) { buf_puts(&b, ",\"details\":"); buf_json_str(&b, e->details); }
        buf_putc(&b, '}');
    }
    pthread_mutex_unlock(&audit_mutex);
    buf_puts(&b, "]}");
    dash_json(fd, 200, &b);
    buf_free(&b);
}

static void h_reload_history(int fd, DReq *r) {
    (void)r;
    Buf b = {0};
    buf_puts(&b, "{\"history\":[");
    pthread_mutex_lock(&reload_mutex);
    for (int k = 0; k < g_reload_count; k++) {
        int idx = ((g_reload_next - 1 - k) % RELOAD_MAX + RELOAD_MAX) % RELOAD_MAX;
        const ReloadEv *e = &g_reloads[idx];
        if (k) buf_putc(&b, ',');
        buf_printf(&b, "{\"t\":%lld,\"source\":", (long long)e->t);
        buf_json_str(&b, e->source);
        buf_printf(&b, ",\"success\":%s", e->success ? "true" : "false");
        if (e->error[0]) { buf_puts(&b, ",\"error\":"); buf_json_str(&b, e->error); }
        buf_printf(&b, ",\"allow_count\":%d,\"deny_count\":%d,\"upstream_count\":%d,\"user_count\":%d",
                   e->allow_count, e->deny_count, e->upstream_count, e->user_count);
        if (e->ninvalid) {
            buf_puts(&b, ",\"invalid_cidrs\":[");
            for (int i = 0; i < e->ninvalid; i++) { if (i) buf_putc(&b, ','); buf_json_str(&b, e->invalid[i]); }
            buf_putc(&b, ']');
        }
        buf_putc(&b, '}');
    }
    pthread_mutex_unlock(&reload_mutex);
    buf_puts(&b, "]}");
    dash_json(fd, 200, &b);
    buf_free(&b);
}

static void json_str_list(Buf *b, const char *key, char **v, int n) {
    buf_json_str(b, key);
    buf_puts(b, ":[");
    for (int i = 0; i < n; i++) { if (i) buf_putc(b, ','); buf_json_str(b, v[i]); }
    buf_putc(b, ']');
}

static void h_network_config(int fd, DReq *r) {
    if (strcmp(r->method, "GET") == 0) {
        Buf b = {0};
        buf_putc(&b, '{');
        pthread_mutex_lock(&cfg_mutex);
        json_str_list(&b, "allow_list", g_cfg.allow, g_cfg.nallow); buf_putc(&b, ',');
        json_str_list(&b, "deny_list", g_cfg.deny, g_cfg.ndeny); buf_putc(&b, ',');
        json_str_list(&b, "upstream_proxies", g_cfg.upstream, g_cfg.nupstream);
        pthread_mutex_unlock(&cfg_mutex);
        buf_putc(&b, '}');
        dash_json(fd, 200, &b);
        buf_free(&b);
        return;
    }
    if (!need_method(fd, r, "POST")) return;
    JVal *j = dash_json_body(fd, r, 65536);
    if (!j) return;
    char **na = NULL, **nd = NULL, **nup = NULL;
    int nna = 0, nnd = 0, nnup = 0;
    char err[160] = "";
    bool ok = cfg_str_array(j, "allow_list", &na, &nna, err, sizeof(err)) &&
              cfg_str_array(j, "deny_list", &nd, &nnd, err, sizeof(err)) &&
              cfg_str_array(j, "upstream_proxies", &nup, &nnup, err, sizeof(err));
    jfree(j);
    if (!ok) {
        strlist_free(na, nna); strlist_free(nd, nnd); strlist_free(nup, nnup);
        dash_error(fd, 400, "Invalid JSON body");
        return;
    }
    pthread_mutex_lock(&cfg_mutex);
    strlist_free(g_cfg.allow, g_cfg.nallow); g_cfg.allow = na; g_cfg.nallow = nna;
    strlist_free(g_cfg.deny, g_cfg.ndeny); g_cfg.deny = nd; g_cfg.ndeny = nnd;
    strlist_free(g_cfg.upstream, g_cfg.nupstream); g_cfg.upstream = nup; g_cfg.nupstream = nnup;
    int rc = cfg_save_locked();
    pthread_mutex_unlock(&cfg_mutex);
    if (rc) {
        char m[160];
        snprintf(m, sizeof(m), "Saved in memory but failed to write config file: %s", strerror(rc));
        dash_error(fd, 500, m);
        return;
    }
    char rerr[256];
    if (!reload_config(r->actor, rerr, sizeof(rerr))) {
        char det[300], m[300];
        snprintf(det, sizeof(det), "failed: %s", rerr);
        audit_record(r->actor, "update_network_config", det);
        snprintf(m, sizeof(m), "Đã lưu file nhưng reload thất bại: %s", rerr);
        dash_error(fd, 500, m);
        return;
    }
    char det[96];
    snprintf(det, sizeof(det), "%d allow, %d deny, %d upstream", nna, nnd, nnup);
    audit_record(r->actor, "update_network_config", det);
    dash_ok(fd);
}

static void h_reload(int fd, DReq *r) {
    if (!need_method(fd, r, "POST")) return;
    char rerr[256];
    if (!reload_config(r->actor, rerr, sizeof(rerr))) {
        char det[300];
        snprintf(det, sizeof(det), "failed: %s", rerr);
        audit_record(r->actor, "reload_config", det);
        dash_error(fd, 400, rerr);
        return;
    }
    audit_record(r->actor, "reload_config", "success (manual)");
    dash_ok(fd);
}

static void h_config_export(int fd, DReq *r) {
    Buf b = {0};
    pthread_mutex_lock(&cfg_mutex);
    cfg_to_json(&g_cfg, &b);
    pthread_mutex_unlock(&cfg_mutex);
    if (!b.p) { dash_error(fd, 500, "Failed to export config"); return; }
    audit_record(r->actor, "export_config_backup", "");
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char ts[32], extra[160];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tmv);
    snprintf(extra, sizeof(extra), "Content-Disposition: attachment; filename=proxy_config_backup_%s.json\r\n", ts);
    dash_send(fd, 200, "application/json", b.p, b.len, extra);
    buf_free(&b);
}

static void h_config_import(int fd, DReq *r) {
    if (!need_method(fd, r, "POST")) return;
    if (!dash_body(fd, r, CONFIG_MAX_BYTES)) return;
    char jerr[96];
    JVal *root = json_parse(r->body, r->body_len, jerr, sizeof(jerr));
    if (!root) {
        char m[160];
        snprintf(m, sizeof(m), "Invalid JSON: %s", jerr);
        dash_error(fd, 400, m);
        return;
    }
    Config nc;
    char cerr[160] = "";
    bool ok = cfg_from_json(root, &nc, cerr, sizeof(cerr));
    jfree(root);
    if (!ok) {
        char m[220];
        snprintf(m, sizeof(m), "File không hợp lệ: %s", cerr);
        dash_error(fd, 400, m);
        return;
    }
    if (!cfg_valid_creds(&nc)) {
        cfg_free(&nc);
        dash_error(fd, 400, "File thiếu dashboard_user/dashboard_password_hash — không phải file backup hợp lệ");
        return;
    }
    int nusers = nc.nusers, ntokens = nc.ntokens;
    /* Validate xong mới ghi: file lỗi không bao giờ ghi đè config đang chạy */
    Buf out = {0};
    cfg_to_json(&nc, &out);
    cfg_free(&nc);
    int rc = out.p ? write_file_atomic(g_config_path, out.p, out.len, 0600) : ENOMEM;
    buf_free(&out);
    if (rc) {
        char m[160];
        snprintf(m, sizeof(m), "Failed to write config file: %s", strerror(rc));
        dash_error(fd, 500, m);
        return;
    }
    char rerr[256];
    if (!reload_config(r->actor, rerr, sizeof(rerr))) {
        char det[300], m[300];
        snprintf(det, sizeof(det), "failed: %s", rerr);
        audit_record(r->actor, "import_config_backup", det);
        snprintf(m, sizeof(m), "Đã ghi file nhưng reload thất bại: %s", rerr);
        dash_error(fd, 500, m);
        return;
    }
    char det[64];
    snprintf(det, sizeof(det), "%d users, %d tokens", nusers, ntokens);
    audit_record(r->actor, "import_config_backup", det);
    log_info("Dashboard: đã restore config từ file backup upload");
    dash_ok(fd);
}

static void h_health(int fd) {
    if (g_shutdown_flag) dash_send(fd, 503, "application/json", "{\"status\":\"shutting_down\"}", 26, NULL);
    else dash_send(fd, 200, "application/json", "{\"status\":\"ok\"}", 15, NULL);
}

static void metric(Buf *b, const char *name, const char *help, const char *typ, const char *fmt, ...) {
    char val[64];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(val, sizeof(val), fmt, ap);
    va_end(ap);
    buf_printf(b, "# HELP proxy_%s %s\n# TYPE proxy_%s %s\nproxy_%s %s\n", name, help, name, typ, name, val);
}

static void h_metrics(int fd) {
    Stats s;
    pthread_mutex_lock(&stats_mutex);
    s = g_stats;
    pthread_mutex_unlock(&stats_mutex);
    Buf b = {0};
    metric(&b, "connections_total", "Tổng số kết nối đã nhận từ khi khởi động", "counter", "%lld", s.total);
    metric(&b, "connections_current", "Số kết nối đang mở (kể cả đang chờ auth)", "gauge", "%lld", s.current);
    metric(&b, "connections_active", "Số kết nối đang active trong bảng dashboard", "gauge", "%d", count_active());
    metric(&b, "socks5_tcp_total", "Tổng số kết nối SOCKS5 TCP", "counter", "%lld", s.socks5_tcp);
    metric(&b, "socks5_udp_total", "Tổng số kết nối SOCKS5 UDP", "counter", "%lld", s.socks5_udp);
    metric(&b, "http_requests_total", "Tổng số request HTTP proxy", "counter", "%lld", s.http);
    metric(&b, "bytes_up_total", "Tổng bytes gửi lên (client -> target) qua TCP", "counter", "%lld", s.bytes_up);
    metric(&b, "bytes_down_total", "Tổng bytes tải về (target -> client) qua TCP", "counter", "%lld", s.bytes_down);
    metric(&b, "udp_bytes_up_total", "Tổng bytes UDP gửi lên", "counter", "%lld", s.udp_up);
    metric(&b, "udp_bytes_down_total", "Tổng bytes UDP tải về", "counter", "%lld", s.udp_down);
    metric(&b, "udp_associations", "Số UDP association đang mở", "gauge", "%d", __atomic_load_n(&g_udp_assoc_count, __ATOMIC_RELAXED));
    metric(&b, "auth_fail_total", "Tổng số lần xác thực thất bại (SOCKS5 + HTTP)", "counter", "%lld", s.auth_fail);
    metric(&b, "uptime_seconds", "Thời gian server đã chạy (giây)", "gauge", "%.0f", difftime(time(NULL), s.start_time));
    if (b.p) dash_send(fd, 200, "text/plain; version=0.0.4; charset=utf-8", b.p, b.len, NULL);
    else dash_error(fd, 500, "out of memory");
    buf_free(&b);
}

/* SSE: đẩy mẫu real-time (khớp định dạng bản Go: event "history" rồi các event "sample") */
static int g_sse_count = 0;

static void h_stream(int fd, DReq *r) {
    (void)r;
    if (__atomic_add_fetch(&g_sse_count, 1, __ATOMIC_RELAXED) > DASH_MAX_SSE) {
        __atomic_sub_fetch(&g_sse_count, 1, __ATOMIC_RELAXED);
        dash_error(fd, 503, "Too many streaming clients");
        return;
    }
    const char *head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n"
                       "Connection: keep-alive\r\nX-Content-Type-Options: nosniff\r\nX-Accel-Buffering: no\r\n\r\n";
    bool alive = send_all(fd, head, strlen(head)) == 0;
    unsigned long last_seq = 0;
    if (alive) {
        Buf b = {0};
        buf_puts(&b, "event: history\ndata: [");
        pthread_mutex_lock(&hist_mutex);
        for (int k = 0; k < g_hist_count; k++) {
            int idx = (g_hist_next - g_hist_count + k + HIST_MAX) % HIST_MAX;
            if (k) buf_putc(&b, ',');
            sample_json(&b, &g_hist[idx]);
        }
        last_seq = g_sample_seq;
        pthread_mutex_unlock(&hist_mutex);
        buf_puts(&b, "]\n\n");
        alive = b.p && send_all(fd, b.p, b.len) == 0;
        buf_free(&b);
    }
    time_t last_io = time(NULL);
    while (alive && !g_shutdown_flag) {
        Sample s;
        bool have = false;
        pthread_mutex_lock(&hist_mutex);
        if (g_sample_seq == last_seq) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&hist_cond, &hist_mutex, &ts);
        }
        if (g_sample_seq != last_seq) { last_seq = g_sample_seq; s = g_latest; have = true; }
        pthread_mutex_unlock(&hist_mutex);
        if (have) {
            Buf b = {0};
            buf_puts(&b, "event: sample\ndata: ");
            sample_json(&b, &s);
            buf_puts(&b, "\n\n");
            alive = b.p && send_all(fd, b.p, b.len) == 0;
            buf_free(&b);
            last_io = time(NULL);
        } else if (time(NULL) - last_io >= 15) {
            alive = send_all(fd, ": keepalive\n\n", 13) == 0;
            last_io = time(NULL);
        }
    }
    __atomic_sub_fetch(&g_sse_count, 1, __ATOMIC_RELAXED);
}

static void h_index(int fd) {
    dash_send(fd, 200, "text/html; charset=utf-8", DASH_HTML, sizeof(DASH_HTML) - 1,
              "Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline' https://cdnjs.cloudflare.com "
              "https://cdn.jsdelivr.net https://unpkg.com; style-src 'unsafe-inline'; img-src 'self' data:; "
              "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n");
}

static int g_dash_threads = 0;

typedef struct { int fd; char peer[64]; } DashConn;

static void dash_route(int fd, DReq *r) {
    const char *p = r->path;
    if (strcmp(p, "/healthz") == 0) { h_health(fd); return; }
    if (strcmp(p, "/metrics") == 0) { h_metrics(fd); return; }
    if (!dash_auth(fd, r)) return;
    /* endpoint chỉ đọc: chỉ nhận GET (đặc biệt /api/stream là SSE kéo dài vô hạn) */
    static const char *const get_only[] = {"/stats", "/api/all", "/api/audit-log", "/api/reload-history",
                                           "/api/stream", "/api/export", "/api/config/export"};
    for (size_t i = 0; i < sizeof(get_only) / sizeof(get_only[0]); i++)
        if (strcmp(p, get_only[i]) == 0 && !need_method(fd, r, "GET")) return;
    if (strcmp(p, "/") == 0) {
        if (!need_method(fd, r, "GET")) return;
        h_index(fd);
    }
    else if (strcmp(p, "/stats") == 0) h_stats(fd, r);
    else if (strcmp(p, "/api/all") == 0) h_all(fd, r);
    else if (strcmp(p, "/api/change-password") == 0) h_change_password(fd, r);
    else if (strcmp(p, "/api/users") == 0) h_users(fd, r);
    else if (strcmp(p, "/api/users/delete") == 0) h_users_delete(fd, r);
    else if (strcmp(p, "/api/reload") == 0) h_reload(fd, r);
    else if (strcmp(p, "/api/network-config") == 0) h_network_config(fd, r);
    else if (strcmp(p, "/api/reload-history") == 0) h_reload_history(fd, r);
    else if (strcmp(p, "/api/stream") == 0) h_stream(fd, r);
    else if (strcmp(p, "/api/kick") == 0) h_kick(fd, r);
    else if (strcmp(p, "/api/export") == 0) h_export(fd, r);
    else if (strcmp(p, "/api/tokens") == 0) h_tokens(fd, r);
    else if (strcmp(p, "/api/tokens/delete") == 0) h_tokens_delete(fd, r);
    else if (strcmp(p, "/api/audit-log") == 0) h_audit(fd, r);
    else if (strcmp(p, "/api/config/export") == 0) h_config_export(fd, r);
    else if (strcmp(p, "/api/config/import") == 0) h_config_import(fd, r);
    else dash_send(fd, 404, "text/plain", "404 page not found\n", 19, NULL);
}

static void *dash_conn_thread(void *arg) {
    DashConn *dc = (DashConn *)arg;
    int fd = dc->fd;
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    char *hb = malloc(MAX_HEADER_BYTES + 1);
    DReq *r = calloc(1, sizeof(DReq));
    if (hb && r) {
        size_t len = 0;
        long hdr_end = -1;
        while (len < MAX_HEADER_BYTES) {
            ssize_t n = recv(fd, hb + len, MAX_HEADER_BYTES - len, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            size_t from = len >= 3 ? len - 3 : 0;
            len += (size_t)n;
            hb[len] = '\0';
            char *e = NULL;
            for (size_t i = from; i + 3 < len; i++) if (memcmp(hb + i, "\r\n\r\n", 4) == 0) { e = hb + i; break; }
            if (e) { hdr_end = (long)(e - hb) + 4; break; }
        }
        snprintf(r->peer, sizeof(r->peer), "%s", dc->peer);
        if (hdr_end < 0) {
            if (len >= MAX_HEADER_BYTES) dash_send(fd, 431, "text/plain", "Request header too large\n", 25, NULL);
        } else if (!dash_parse_head(hb, (size_t)hdr_end, r)) {
            dash_send(fd, 400, "text/plain", "Bad Request\n", 12, NULL);
        } else {
            r->pre = (const uint8_t *)hb + hdr_end;
            r->pre_len = len - (size_t)hdr_end;
            dash_route(fd, r);
        }
    }
    if (r) free(r->body);
    free(r);
    free(hb);
    close(fd);
    __atomic_sub_fetch(&g_dash_threads, 1, __ATOMIC_RELAXED);
    free(dc);
    return NULL;
}

static void *dashboard_thread(void *arg) {
    (void)arg;
    int lfd = create_listener(g_dashboard_bind, g_dashboard_port, 64);
    if (lfd < 0) {
        log_error("Dashboard bind failed on %s:%d (%s)", g_dashboard_bind, g_dashboard_port, strerror(errno));
        return NULL;
    }
    char duser[NAME_LEN * 2];
    pthread_mutex_lock(&cfg_mutex);
    snprintf(duser, sizeof(duser), "%s", g_cfg.dash_user);
    pthread_mutex_unlock(&cfg_mutex);
    log_info(COLOR_CYAN "Dashboard available at http://%s:%d (user: %s)" COLOR_RESET, g_dashboard_bind, g_dashboard_port, duser);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    while (!g_shutdown_flag) {
        struct pollfd pfd = {lfd, POLLIN, 0};
        int pr = poll(&pfd, 1, 1000);
        if (pr <= 0) continue;
        struct sockaddr_storage ca;
        socklen_t cl = sizeof(ca);
        int c = accept(lfd, (struct sockaddr *)&ca, &cl);
        if (c < 0) {
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) usleep(50000);
            continue;
        }
        if (__atomic_load_n(&g_dash_threads, __ATOMIC_RELAXED) >= DASH_MAX_THREADS) { close(c); continue; }
        DashConn *dc = calloc(1, sizeof(*dc));
        if (!dc) { close(c); continue; }
        dc->fd = c;
        sa_to_str((struct sockaddr *)&ca, dc->peer, sizeof(dc->peer), NULL);
        __atomic_add_fetch(&g_dash_threads, 1, __ATOMIC_RELAXED);
        pthread_t t;
        if (pthread_create(&t, &attr, dash_conn_thread, dc) != 0) {
            __atomic_sub_fetch(&g_dash_threads, 1, __ATOMIC_RELAXED);
            close(c);
            free(dc);
        }
    }
    close(lfd);
    return NULL;
}

/* ========================== STATS THREAD (mẫu cho biểu đồ, quota, lưu usage, hiển thị terminal) ========================== */
static void *stats_thread(void *arg) {
    (void)arg;
    const int interval = 2;
    long long last_up = 0, last_down = 0;
    bool first = true;
    int tick = 0;
    while (!g_shutdown_flag) {
        for (int i = 0; i < interval * 10 && !g_shutdown_flag; i++) usleep(100000);
        if (g_shutdown_flag) break;
        tick++;
        Stats st;
        pthread_mutex_lock(&stats_mutex);
        st = g_stats;
        pthread_mutex_unlock(&stats_mutex);

        int s5_tcp = 0, s5_udp = 0, http = 0;
        pthread_mutex_lock(&active_mutex);
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (!g_active_conns[i].used) continue;
            if (strcmp(g_active_conns[i].type, "SOCKS5_TCP") == 0) s5_tcp++;
            else if (strcmp(g_active_conns[i].type, "SOCKS5_UDP") == 0) s5_udp++;
            else if (strcmp(g_active_conns[i].type, "HTTP") == 0) http++;
        }
        pthread_mutex_unlock(&active_mutex);
        int udp_assoc = __atomic_load_n(&g_udp_assoc_count, __ATOMIC_RELAXED);

        Sample s;
        memset(&s, 0, sizeof(s));
        s.t = (long long)time(NULL);
        if (!first) {
            s.up_bps = (st.bytes_up - last_up) / interval;
            s.down_bps = (st.bytes_down - last_down) / interval;
        }
        last_up = st.bytes_up; last_down = st.bytes_down; first = false;
        s.active = (int)st.current;
        s.udp_assocs = udp_assoc;
        hist_push(&s);

        if (tick % 5 == 0) enforce_quota();                     /* ~10s: cắt connection của user vượt quota */
        if (tick % 15 == 0 && __atomic_exchange_n(&g_usage_dirty, 0, __ATOMIC_RELAXED)) {   /* ~30s: lưu usage */
            int rc = usage_save(g_usage_path);
            if (rc) log_error("Không lưu được usage file %s: %s", g_usage_path, strerror(rc));
        }

        if (g_tty) {
            time_t uptime = time(NULL) - st.start_time;
            int h = (int)(uptime / 3600), m = (int)((uptime % 3600) / 60), sec = (int)(uptime % 60);
            char up_buf[32], down_buf[32], udp_up_buf[32], udp_down_buf[32];
            format_bytes(st.bytes_up, up_buf, sizeof(up_buf));
            format_bytes(st.bytes_down, down_buf, sizeof(down_buf));
            format_bytes(st.udp_up, udp_up_buf, sizeof(udp_up_buf));
            format_bytes(st.udp_down, udp_down_buf, sizeof(udp_down_buf));
            pthread_mutex_lock(&log_mutex);
            printf("\033[2A\033[2K");
            printf(COLOR_YELLOW "↑TCP %9s ↓TCP %9s │ ↑UDP %7s ↓UDP %7s" COLOR_RESET "\n",
                   up_buf, down_buf, udp_up_buf, udp_down_buf);
            printf(COLOR_CYAN "Active: %4lld (TCP:%3d UDP:%3d HTTP:%3d) │ UDP Assoc: %3d │ Uptime %02d:%02d:%02d" COLOR_RESET "\n",
                   st.current, s5_tcp, s5_udp, http, udp_assoc, h, m, sec);
            fflush(stdout);
            pthread_mutex_unlock(&log_mutex);
        }
    }
    return NULL;
}

/* ========================== SIGNAL (async-signal-safe: chỉ đặt cờ) ========================== */
static void signal_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    __atomic_store_n(&g_shutdown_raw, 1, __ATOMIC_RELAXED);
    errno = saved_errno;
}

static void hup_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    __atomic_store_n(&g_hup_raw, 1, __ATOMIC_RELAXED);
    errno = saved_errno;
}

/* ========================== MAIN ========================== */
static void usage(void) {
    printf("Usage: proxy [-l addr] [-p port] [-u user] [-P pass] [--no-udp]\n"
           "             [--config file] [--usage-file file]\n"
           "             [--dashboard-port port] [--dashboard-bind addr]\n"
           "             [--dashboard-user user] [--dashboard-pass pass]   (chỉ dùng khi config file chưa tồn tại)\n"
           "             [--allow cidr,...] [--deny cidr,...] [--upstream [http://|socks5://]host:port,...]  (như trên: chỉ lần đầu)\n"
           "             [--upstream-fallback] [--allow-private] [--force-kill]\n"
           "\n"
           "Lần chạy đầu: tạo config file (mặc định proxy_config.json), nếu không đặt --dashboard-pass thì sinh mật khẩu ngẫu nhiên\n"
           "và in ra MỘT lần. Từ lần sau, mọi thay đổi (user, whitelist/blacklist, upstream, token...) làm qua dashboard hoặc sửa file\n"
           "rồi gửi SIGHUP. Dashboard mặc định chỉ nghe 127.0.0.1; chặn kết nối tới địa chỉ nội bộ (--allow-private để tắt).\n");
}

static void copy_arg(char *dst, size_t n, const char *src, const char *name) {
    if (strlen(src) >= n) {
        fprintf(stderr, "Giá trị của %s quá dài (tối đa %zu ký tự)\n", name, n - 1);
        exit(2);
    }
    snprintf(dst, n, "%s", src);
}

static int arg_port(const char *s, const char *name) {
    int p;
    if (!parse_port_str(s, &p)) {
        fprintf(stderr, "Giá trị của %s phải là số cổng 1-65535\n", name);
        exit(2);
    }
    return p;
}

/* "a, b ,c" -> thêm từng phần tử (đã trim) vào danh sách */
static void split_commas(const char *s, char ***v, int *n) {
    char tmp[4200];
    snprintf(tmp, sizeof(tmp), "%s", s);
    char *save = NULL;
    for (char *tok = strtok_r(tmp, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        trim_inplace(tok);
        if (*tok && strlen(tok) < LIST_ITEM_LEN) strlist_add(v, n, tok);
    }
}

/* Đọc config file nếu có; chưa có thì tạo mới (hash mật khẩu, seed allow/deny/upstream từ cờ). */
static bool config_bootstrap(void) {
    bool seeds = g_seed_allow[0] || g_seed_deny[0] || g_seed_upstream[0];
    if (access(g_config_path, F_OK) == 0) {
        int ferr = 0;
        size_t len;
        char *data = read_file_all(g_config_path, CONFIG_MAX_BYTES, &len, &ferr);
        if (!data) { fprintf(stderr, "Lỗi đọc config file %s: %s\n", g_config_path, strerror(ferr)); return false; }
        char jerr[96];
        JVal *root = json_parse(data, len, jerr, sizeof(jerr));
        free(data);
        if (!root) { fprintf(stderr, "config file %s bị lỗi định dạng JSON: %s\n", g_config_path, jerr); return false; }
        Config c;
        char cerr[160] = "";
        bool ok = cfg_from_json(root, &c, cerr, sizeof(cerr));
        jfree(root);
        if (!ok) { fprintf(stderr, "config file %s không hợp lệ: %s\n", g_config_path, cerr); return false; }
        if (!cfg_valid_creds(&c)) {
            fprintf(stderr, "config file %s thiếu dashboard_user/dashboard_password_hash\n", g_config_path);
            cfg_free(&c);
            return false;
        }
        g_cfg = c;
        if (seeds || g_init_dash_pass[0])
            log_error("Config file đã tồn tại -> bỏ qua --allow/--deny/--upstream/--dashboard-user/--dashboard-pass (hãy sửa qua dashboard hoặc config file + SIGHUP)");
        return true;
    }
    /* Chưa có config file -> khởi tạo */
    char generated[32] = "";
    char pass[256];
    if (g_init_dash_pass[0]) snprintf(pass, sizeof(pass), "%s", g_init_dash_pass);
    else {
        char tok[72];
        if (!gen_token_hex(tok, sizeof(tok))) { fprintf(stderr, "Không sinh được mật khẩu ngẫu nhiên\n"); return false; }
        memcpy(generated, tok, 16);
        generated[16] = '\0';
        snprintf(pass, sizeof(pass), "%s", generated);
    }
    Config c;
    memset(&c, 0, sizeof(c));
    snprintf(c.dash_user, sizeof(c.dash_user), "%s", g_init_dash_user[0] ? g_init_dash_user : "admin");
    if (!hash_password(pass, c.dash_hash, sizeof(c.dash_hash))) { fprintf(stderr, "Không hash được mật khẩu\n"); return false; }
    split_commas(g_seed_allow, &c.allow, &c.nallow);
    split_commas(g_seed_deny, &c.deny, &c.ndeny);
    split_commas(g_seed_upstream, &c.upstream, &c.nupstream);
    g_cfg = c;
    int rc = cfg_save_locked();
    if (rc) log_error("Không ghi được config file %s: %s (credentials sẽ không được lưu bền vững)", g_config_path, strerror(rc));
    else log_info("Đã tạo config file mới tại %s", g_config_path);
    if (generated[0])
        log_error("Dashboard lần đầu — user: %s | password: %s (chỉ hiện MỘT LẦN, hãy lưu lại/đổi ngay)", g_cfg.dash_user, generated);
    return true;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        bool has = i + 1 < argc;
        if (strcmp(a, "-l") == 0 && has) copy_arg(g_listen_addr, sizeof(g_listen_addr), argv[++i], "-l");
        else if (strcmp(a, "-p") == 0 && has) g_listen_port = arg_port(argv[++i], "-p");
        else if (strcmp(a, "-u") == 0 && has) copy_arg(g_username, sizeof(g_username), argv[++i], "-u");
        else if (strcmp(a, "-P") == 0 && has) copy_arg(g_password, sizeof(g_password), argv[++i], "-P");
        else if (strcmp(a, "--no-udp") == 0) g_enable_udp = 0;
        else if (strcmp(a, "--allow-private") == 0) g_allow_private = 1;
        else if (strcmp(a, "--upstream-fallback") == 0) g_upstream_fallback = 1;
        else if (strcmp(a, "--upstream") == 0 && has) copy_arg(g_seed_upstream, sizeof(g_seed_upstream), argv[++i], "--upstream");
        else if (strcmp(a, "--allow") == 0 && has) copy_arg(g_seed_allow, sizeof(g_seed_allow), argv[++i], "--allow");
        else if (strcmp(a, "--deny") == 0 && has) copy_arg(g_seed_deny, sizeof(g_seed_deny), argv[++i], "--deny");
        else if (strcmp(a, "--config") == 0 && has) copy_arg(g_config_path, sizeof(g_config_path) - 8, argv[++i], "--config");
        else if (strcmp(a, "--usage-file") == 0 && has) copy_arg(g_usage_path, sizeof(g_usage_path) - 8, argv[++i], "--usage-file");
        else if ((strcmp(a, "--cert") == 0 || strcmp(a, "--key") == 0) && has) {
            fprintf(stderr, "Bản C không hỗ trợ TLS (--cert/--key). Hãy dùng stunnel/nginx phía trước, hoặc bản Go.\n");
            return 2;
        }
        else if (strcmp(a, "--dashboard-port") == 0 && has) g_dashboard_port = arg_port(argv[++i], "--dashboard-port");
        else if (strcmp(a, "--dashboard-bind") == 0 && has) copy_arg(g_dashboard_bind, sizeof(g_dashboard_bind), argv[++i], "--dashboard-bind");
        else if (strcmp(a, "--dashboard-user") == 0 && has) copy_arg(g_init_dash_user, sizeof(g_init_dash_user), argv[++i], "--dashboard-user");
        else if (strcmp(a, "--dashboard-pass") == 0 && has) copy_arg(g_init_dash_pass, sizeof(g_init_dash_pass), argv[++i], "--dashboard-pass");
        else if (strcmp(a, "--force-kill") == 0) g_force_kill = 1;
        else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) { usage(); return 0; }
        else { fprintf(stderr, "Tham số không hợp lệ: %s\n", a); usage(); return 2; }
    }

    if (g_username[0] || g_password[0]) {
        if (!g_username[0] || !g_password[0]) {
            fprintf(stderr, "Cần đặt cả -u và -P để bật xác thực\n");
            return 2;
        }
        g_auth_required = 1;
    }

    if (g_force_kill) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "fuser -k %d/tcp 2>/dev/null", g_listen_port);   /* port đã validate 1..65535 */
        if (system(cmd) != 0) { /* không có tiến trình nào / không có fuser: bỏ qua */ }
        sleep(1);
    }

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rlim_t want = 65536;
        rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY || want < rl.rlim_max) ? want : rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;      /* không SA_RESTART: poll()/accept() trả EINTR để thoát vòng lặp */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = hup_handler;
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    g_stats.start_time = time(NULL);
    g_tty = isatty(STDOUT_FILENO);

    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&hist_cond, &ca);

    if (!config_bootstrap()) return 1;
    usage_load(g_usage_path);
    {
        CidrList na, nd;
        cidr_build(g_cfg.allow, g_cfg.nallow, &na, NULL, NULL);
        cidr_build(g_cfg.deny, g_cfg.ndeny, &nd, NULL, NULL);
        cidr_set_lists(&na, &nd);
        upstreams_apply(g_cfg.upstream, g_cfg.nupstream);
    }
    if (strcmp(g_cfg.dash_user, "admin") == 0 && verify_password("admin", g_cfg.dash_hash))
        log_error("Dashboard đang dùng tài khoản mặc định admin/admin — hãy đổi ngay trên dashboard (nút Change Password)");
    if (!bind_is_loopback(g_dashboard_bind))
        log_error("Dashboard nghe %s qua HTTP thường (không mã hoá) — nên đặt sau reverse proxy HTTPS hoặc giữ mặc định 127.0.0.1", g_dashboard_bind);

    int lfd = create_listener(g_listen_addr, g_listen_port, SOMAXCONN);
    if (lfd < 0) {
        log_error("Bind failed on %s:%d (%s)", g_listen_addr, g_listen_port, strerror(errno));
        return 1;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_t th;
    pthread_create(&th, &attr, dashboard_thread, NULL);
    pthread_create(&th, &attr, stats_thread, NULL);
    pthread_create(&th, &attr, upstream_health_thread, NULL);

    log_info(COLOR_GREEN "Proxy %s (C) STARTED → %s:%d" COLOR_RESET, VERSION_STR, g_listen_addr, g_listen_port);
    pthread_mutex_lock(&cfg_mutex);
    int nu = g_cfg.nusers;
    pthread_mutex_unlock(&cfg_mutex);
    log_info(COLOR_CYAN "Features: SOCKS5 TCP/UDP + HTTP/HTTPS | Auth: %s | Users: %d | Upstream: %d | Dashboard: %s:%d | Private targets: %s | Config: %s" COLOR_RESET,
             proxy_auth_required() ? "yes" : "no", nu, g_upstream_count, g_dashboard_bind, g_dashboard_port,
             g_allow_private ? "allowed" : "blocked", g_config_path);
    log_info("Gửi SIGHUP (kill -HUP %d) để reload allow/deny/upstream/users/dashboard-creds từ config file mà không cần restart", (int)getpid());
    if (!proxy_auth_required())
        log_error("Proxy KHÔNG có xác thực (chưa có user nào / không có -u/-P) — bất kỳ ai kết nối được tới cổng này đều dùng được");
    if (g_tty) printf("\n\n");

    while (!g_shutdown_flag) {
        if (__atomic_exchange_n(&g_hup_raw, 0, __ATOMIC_RELAXED)) {
            log_info("Nhận tín hiệu SIGHUP, đang reload config...");
            char rerr[256];
            if (!reload_config("SIGHUP", rerr, sizeof(rerr))) log_error("Reload config thất bại: %s", rerr);
        }
        struct pollfd pfd = {lfd, POLLIN, 0};
        int pr = poll(&pfd, 1, 1000);
        if (pr <= 0) continue;           /* timeout hoặc EINTR -> kiểm tra cờ shutdown / SIGHUP */

        struct sockaddr_storage caddr;
        socklen_t len = sizeof(caddr);
        int client = accept(lfd, (struct sockaddr *)&caddr, &len);
        if (client < 0) {
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) usleep(50000);
            continue;
        }
        /* Giới hạn số luồng (chống DoS bằng cách mở vô hạn kết nối) */
        if (__atomic_load_n(&g_thread_count, __ATOMIC_RELAXED) >= MAX_CONNECTIONS) {
            close(client);
            continue;
        }
        ClientContext *ctx = calloc(1, sizeof(ClientContext));
        if (!ctx) { close(client); continue; }
        ctx->fd = client;
        memcpy(&ctx->addr, &caddr, len);
        ctx->addrlen = len;
        sa_to_str((struct sockaddr *)&caddr, ctx->ip, sizeof(ctx->ip), &ctx->port);
        uint16_t pp;
        sa_canon((struct sockaddr *)&caddr, ctx->cip, &pp);

        __atomic_add_fetch(&g_thread_count, 1, __ATOMIC_RELAXED);
        pthread_t tid;
        if (pthread_create(&tid, &attr, client_handler, ctx) != 0) {
            __atomic_sub_fetch(&g_thread_count, 1, __ATOMIC_RELAXED);
            close(client);
            free(ctx);
        }
    }

    close(lfd);
    /* Chờ tối đa ~2s để các luồng xử lý (tunnel kiểm tra cờ shutdown mỗi giây) ghi nốt byte/quota trước khi lưu usage */
    for (int i = 0; i < 100 && __atomic_load_n(&g_thread_count, __ATOMIC_RELAXED) > 0; i++) usleep(20000);
    int rc = usage_save(g_usage_path);
    if (rc) log_error("Không lưu được usage file lúc thoát: %s", strerror(rc));
    time_t uptime = time(NULL) - g_stats.start_time;
    pthread_mutex_lock(&stats_mutex);
    long long total = g_stats.total;
    pthread_mutex_unlock(&stats_mutex);
    log_info(COLOR_RED "Proxy STOPPED │ Uptime %02d:%02d:%02d │ Total conn %lld" COLOR_RESET,
             (int)(uptime / 3600), (int)((uptime % 3600) / 60), (int)(uptime % 60), total);
    return 0;
}

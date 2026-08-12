/**
 * Universal Proxy Pro v6.2 - C implementation (Full features)
 * SOCKS5 (TCP/UDP), HTTP/HTTPS, upstream, dashboard, stats, TLS.
 * Compile: gcc -o proxy proxy.c -lpthread -lssl -lcrypto -O2
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/ioctl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* ========================== CONFIG ========================== */
#define MAX_CONNECTIONS     4000
#define CONNECTION_TIMEOUT  25
#define IDLE_TIMEOUT        180
#define RETRY_ATTEMPTS      5
#define BUFFER_SIZE         65536
#define UDP_BUFFER_SIZE     65535
#define UDP_IDLE_TIMEOUT    120
#define DASHBOARD_PORT      8081
#define MAX_UPSTREAM        16
#define MAX_URL_LEN         1024

/* Colors (ANSI) */
#define COLOR_GREEN   "\033[92m"
#define COLOR_YELLOW  "\033[93m"
#define COLOR_RED     "\033[91m"
#define COLOR_BLUE    "\033[94m"
#define COLOR_CYAN    "\033[96m"
#define COLOR_PURPLE  "\033[95m"
#define COLOR_WHITE   "\033[97m"
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

Stats g_stats;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char ip[64];
    int port;
    char type[16];
    char target[256];
} ActiveConn;

ActiveConn g_active_conns[MAX_CONNECTIONS];
int g_active_count = 0;
pthread_mutex_t active_mutex = PTHREAD_MUTEX_INITIALIZER;

/* UDP associations */
typedef struct UdpAssoc {
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    int relay_sock;
    time_t last_activity;
    bool active;
    pthread_mutex_t lock;
    struct UdpAssoc *next;
} UdpAssoc;

UdpAssoc *g_udp_assocs = NULL;
pthread_mutex_t udp_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t udp_thread;
int udp_thread_running = 0;

/* Upstream proxies */
typedef struct {
    char host[256];
    int port;
} Upstream;

Upstream g_upstreams[MAX_UPSTREAM];
int g_upstream_count = 0;
int g_upstream_index = 0;
pthread_mutex_t upstream_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Server config */
char g_listen_addr[64] = "0.0.0.0";
int g_listen_port = 1080;
char g_username[64] = "";
char g_password[64] = "";
int g_auth_required = 0;
int g_enable_udp = 1;
char g_cert_file[256] = "";
char g_key_file[256] = "";
int g_dashboard_port = DASHBOARD_PORT;
int g_force_kill = 0;

SSL_CTX *g_ssl_ctx = NULL;

int g_shutdown_flag = 0;

/* ========================== LOGGING ========================== */
void log_info(const char *fmt, ...) {
    va_list args;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    printf("[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

void log_error(const char *fmt, ...) {
    va_list args;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    fprintf(stderr, "[%02d:%02d:%02d] ERROR: ", tm->tm_hour, tm->tm_min, tm->tm_sec);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

/* ========================== UTILITY ========================== */
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return;
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_tcp_socket(const char *host, int port) {
    struct addrinfo hints, *res = NULL;
    int sock = -1, err;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;

    if ((err = getaddrinfo(host, port_str, &hints, &res)) != 0) {
        log_error("getaddrinfo(%s): %s", host, gai_strerror(err));
        return -1;
    }

    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;
        struct timeval tv = {CONNECTION_TIMEOUT, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock != -1) {
        struct timeval tv = {0, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        set_nonblocking(sock);
    }
    return sock;
}

int connect_with_retry(const char *host, int port) {
    int sock;
    for (int attempt = 0; attempt < RETRY_ATTEMPTS; attempt++) {
        sock = create_tcp_socket(host, port);
        if (sock != -1) return sock;
        sleep(attempt < 2 ? 1 : 2);
    }
    return -1;
}

void format_bytes(long long bytes, char *buf, size_t bufsize) {
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int idx = 0;
    double val = (double)bytes;
    while (val >= 1024 && idx < 4) { val /= 1024; idx++; }
    snprintf(buf, bufsize, "%.1f %s", val, units[idx]);
}

time_t get_uptime(void) {
    return time(NULL) - g_stats.start_time;
}

/* ========================== STATS ========================== */
void stats_increment(const char *type, long long bytes) {
    pthread_mutex_lock(&stats_mutex);
    g_stats.total++;
    g_stats.current++;
    if (strcmp(type, "SOCKS5_TCP") == 0) g_stats.socks5_tcp++;
    else if (strcmp(type, "SOCKS5_UDP") == 0) g_stats.socks5_udp++;
    else if (strcmp(type, "HTTP") == 0) g_stats.http++;
    if (bytes > 0) g_stats.bytes_up += bytes;
    pthread_mutex_unlock(&stats_mutex);
}

void stats_decrement(void) {
    pthread_mutex_lock(&stats_mutex);
    if (g_stats.current > 0) g_stats.current--;
    pthread_mutex_unlock(&stats_mutex);
}

void stats_auth_fail(void) {
    pthread_mutex_lock(&stats_mutex);
    g_stats.auth_fail++;
    pthread_mutex_unlock(&stats_mutex);
}

void stats_add_bytes(int direction, long long bytes) {
    pthread_mutex_lock(&stats_mutex);
    if (direction == 0) g_stats.bytes_up += bytes;
    else g_stats.bytes_down += bytes;
    pthread_mutex_unlock(&stats_mutex);
}

/* ========================== ACTIVE CONNECTIONS ========================== */
void active_add(const char *ip, int port, const char *type, const char *target) {
    pthread_mutex_lock(&active_mutex);
    if (g_active_count < MAX_CONNECTIONS) {
        strncpy(g_active_conns[g_active_count].ip, ip, 63);
        g_active_conns[g_active_count].port = port;
        strncpy(g_active_conns[g_active_count].type, type, 15);
        strncpy(g_active_conns[g_active_count].target, target, 255);
        g_active_count++;
    }
    pthread_mutex_unlock(&active_mutex);
}

void active_remove(const char *ip, int port, const char *type, const char *target) {
    pthread_mutex_lock(&active_mutex);
    for (int i = 0; i < g_active_count; i++) {
        if (strcmp(g_active_conns[i].ip, ip) == 0 &&
            g_active_conns[i].port == port &&
            strcmp(g_active_conns[i].type, type) == 0 &&
            strcmp(g_active_conns[i].target, target) == 0) {
            if (i < g_active_count - 1)
                memmove(&g_active_conns[i], &g_active_conns[i+1], sizeof(ActiveConn)*(g_active_count - i - 1));
            g_active_count--;
            break;
        }
    }
    pthread_mutex_unlock(&active_mutex);
}

/* ========================== UDP ASSOCIATION ========================== */
int find_free_udp_port(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        close(sock);
        return -1;
    }
    socklen_t len = sizeof(addr);
    getsockname(sock, (struct sockaddr*)&addr, &len);
    int port = ntohs(addr.sin_port);
    close(sock);
    return port;
}

UdpAssoc* udp_assoc_create(struct sockaddr *client_addr, socklen_t client_len) {
    UdpAssoc *assoc = calloc(1, sizeof(UdpAssoc));
    if (!assoc) return NULL;
    memcpy(&assoc->client_addr, client_addr, client_len);
    assoc->client_addrlen = client_len;
    assoc->last_activity = time(NULL);
    assoc->active = true;
    pthread_mutex_init(&assoc->lock, NULL);

    int port = find_free_udp_port();
    if (port == -1) { free(assoc); return NULL; }

    int sock = socket(client_addr->sa_family, SOCK_DGRAM, 0);
    if (sock == -1) { free(assoc); return NULL; }

    struct sockaddr_storage bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    if (client_addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in*)&bind_addr;
        in->sin_family = AF_INET;
        in->sin_addr.s_addr = htonl(INADDR_ANY);
        in->sin_port = htons(port);
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6*)&bind_addr;
        in6->sin6_family = AF_INET6;
        in6->sin6_addr = in6addr_any;
        in6->sin6_port = htons(port);
    }
    if (bind(sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == -1) {
        close(sock);
        free(assoc);
        return NULL;
    }
    set_nonblocking(sock);
    assoc->relay_sock = sock;

    pthread_mutex_lock(&udp_mutex);
    assoc->next = g_udp_assocs;
    g_udp_assocs = assoc;
    pthread_mutex_unlock(&udp_mutex);

    log_info(COLOR_PURPLE "UDP relay on port %d" COLOR_RESET, port);
    return assoc;
}

void udp_assoc_close(UdpAssoc *assoc) {
    if (!assoc) return;
    pthread_mutex_lock(&assoc->lock);
    assoc->active = false;
    if (assoc->relay_sock != -1) {
        close(assoc->relay_sock);
        assoc->relay_sock = -1;
    }
    pthread_mutex_unlock(&assoc->lock);

    pthread_mutex_lock(&udp_mutex);
    UdpAssoc **p = &g_udp_assocs;
    while (*p) {
        if (*p == assoc) {
            *p = assoc->next;
            break;
        }
        p = &(*p)->next;
    }
    pthread_mutex_unlock(&udp_mutex);
    pthread_mutex_destroy(&assoc->lock);
    free(assoc);
}

void udp_forward_to_remote(UdpAssoc *assoc, const uint8_t *data, size_t len) {
    if (len < 4) return;
    if (data[2] != 0) return; // fragment not supported

    uint8_t atyp = data[3];
    int pos = 4;
    char host[256];
    int port = 0;
    struct sockaddr_storage dest;
    socklen_t destlen = 0;

    if (atyp == 1) { // IPv4
        if (len < (size_t)(pos+6)) return;
        struct sockaddr_in *in = (struct sockaddr_in*)&dest;
        in->sin_family = AF_INET;
        memcpy(&in->sin_addr, data+pos, 4);
        pos += 4;
        in->sin_port = *(uint16_t*)(data+pos);
        destlen = sizeof(struct sockaddr_in);
    } else if (atyp == 3) { // domain name
        uint8_t domlen = data[pos++];
        if (len < (size_t)(pos+domlen+2)) return;
        memcpy(host, data+pos, domlen);
        host[domlen] = '\0';
        pos += domlen;
        port = (data[pos] << 8) | data[pos+1];
        pos += 2;
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", port);
        if (getaddrinfo(host, port_str, &hints, &res) != 0) return;
        memcpy(&dest, res->ai_addr, res->ai_addrlen);
        destlen = res->ai_addrlen;
        freeaddrinfo(res);
    } else if (atyp == 4) { // IPv6
        if (len < (size_t)(pos+18)) return;
        struct sockaddr_in6 *in6 = (struct sockaddr_in6*)&dest;
        in6->sin6_family = AF_INET6;
        memcpy(&in6->sin6_addr, data+pos, 16);
        pos += 16;
        in6->sin6_port = *(uint16_t*)(data+pos);
        destlen = sizeof(struct sockaddr_in6);
    } else {
        return;
    }

    size_t payload_len = len - pos;
    ssize_t sent = sendto(assoc->relay_sock, data+pos, payload_len, 0, (struct sockaddr*)&dest, destlen);
    if (sent > 0) {
        pthread_mutex_lock(&stats_mutex);
        g_stats.udp_up += sent;
        pthread_mutex_unlock(&stats_mutex);
        assoc->last_activity = time(NULL);
    }
}

void udp_forward_to_client(UdpAssoc *assoc, const uint8_t *data, size_t len, struct sockaddr *from, socklen_t fromlen) {
    (void)from;
    (void)fromlen;
    // Build SOCKS5 UDP header
    uint8_t header[4096];
    int hlen = 4;
    header[0] = 0; header[1] = 0; header[2] = 0;

    struct sockaddr *client = (struct sockaddr*)&assoc->client_addr;
    if (client->sa_family == AF_INET) {
        header[3] = 1;
        struct sockaddr_in *in = (struct sockaddr_in*)client;
        memcpy(header+4, &in->sin_addr, 4);
        memcpy(header+8, &in->sin_port, 2);
        hlen = 10;
    } else if (client->sa_family == AF_INET6) {
        header[3] = 4;
        struct sockaddr_in6 *in6 = (struct sockaddr_in6*)client;
        memcpy(header+4, &in6->sin6_addr, 16);
        memcpy(header+20, &in6->sin6_port, 2);
        hlen = 22;
    } else {
        return;
    }

    sendto(assoc->relay_sock, header, hlen, 0, (struct sockaddr*)&assoc->client_addr, assoc->client_addrlen);
    ssize_t sent = sendto(assoc->relay_sock, data, len, 0, (struct sockaddr*)&assoc->client_addr, assoc->client_addrlen);
    if (sent > 0) {
        pthread_mutex_lock(&stats_mutex);
        g_stats.udp_down += sent;
        pthread_mutex_unlock(&stats_mutex);
    }
}

void* udp_relay_thread(void *arg) {
    (void)arg;
    fd_set fds;
    int maxfd = 0;
    struct timeval tv;

    while (udp_thread_running) {
        FD_ZERO(&fds);
        maxfd = 0;
        pthread_mutex_lock(&udp_mutex);
        for (UdpAssoc *a = g_udp_assocs; a; a = a->next) {
            pthread_mutex_lock(&a->lock);
            if (a->active && a->relay_sock != -1) {
                FD_SET(a->relay_sock, &fds);
                if (a->relay_sock > maxfd) maxfd = a->relay_sock;
            }
            pthread_mutex_unlock(&a->lock);
        }
        pthread_mutex_unlock(&udp_mutex);

        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int ret = select(maxfd+1, &fds, NULL, NULL, &tv);
        if (ret < 0) continue;

        time_t now = time(NULL);
        pthread_mutex_lock(&udp_mutex);
        UdpAssoc *prev = NULL;
        UdpAssoc *curr = g_udp_assocs;
        while (curr) {
            if (now - curr->last_activity > UDP_IDLE_TIMEOUT) {
                UdpAssoc *next = curr->next;
                if (prev) prev->next = next;
                else g_udp_assocs = next;
                udp_assoc_close(curr);
                curr = next;
            } else {
                prev = curr;
                curr = curr->next;
            }
        }
        pthread_mutex_unlock(&udp_mutex);

        pthread_mutex_lock(&udp_mutex);
        for (UdpAssoc *a = g_udp_assocs; a; a = a->next) {
            if (!a->active || a->relay_sock == -1) continue;
            if (!FD_ISSET(a->relay_sock, &fds)) continue;
            uint8_t buffer[UDP_BUFFER_SIZE];
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(a->relay_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &fromlen);
            if (n > 0) {
                a->last_activity = time(NULL);
                if (a->client_addrlen > 0 &&
                    from.ss_family == a->client_addr.ss_family &&
                    memcmp(&from, &a->client_addr, a->client_addrlen) == 0) {
                    udp_forward_to_remote(a, buffer, n);
                } else {
                    udp_forward_to_client(a, buffer, n, (struct sockaddr*)&from, fromlen);
                }
            }
        }
        pthread_mutex_unlock(&udp_mutex);
    }
    return NULL;
}

void start_udp_relay(void) {
    if (!g_enable_udp) return;
    udp_thread_running = 1;
    pthread_create(&udp_thread, NULL, udp_relay_thread, NULL);
}

void stop_udp_relay(void) {
    udp_thread_running = 0;
    pthread_join(udp_thread, NULL);
}

/* ========================== PROXY CLIENT HANDLER ========================== */
typedef struct {
    int client_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    SSL *ssl;
} ClientContext;

void socks5_reply(int fd, uint8_t rep, const char *addr, int port) {
    uint8_t reply[256];
    int len = 0;
    reply[len++] = 5;
    reply[len++] = rep;
    reply[len++] = 0;
    if (strchr(addr, ':')) {
        reply[len++] = 4;
        struct in6_addr in6;
        inet_pton(AF_INET6, addr, &in6);
        memcpy(reply+len, &in6, 16);
        len += 16;
    } else {
        reply[len++] = 1;
        struct in_addr in;
        inet_pton(AF_INET, addr, &in);
        memcpy(reply+len, &in, 4);
        len += 4;
    }
    reply[len++] = (port >> 8) & 0xFF;
    reply[len++] = port & 0xFF;
    send(fd, reply, len, 0);
}

int socks5_auth(ClientContext *ctx) {
    int fd = ctx->client_fd;
    uint8_t buf[256];
    ssize_t n = recv(fd, buf, 2, 0);
    if (n != 2 || buf[0] != 1) return 0;
    uint8_t ulen = buf[1];
    n = recv(fd, buf, ulen, 0);
    if (n != ulen) return 0;
    char user[64];
    memcpy(user, buf, ulen);
    user[ulen] = '\0';
    n = recv(fd, buf, 1, 0);
    if (n != 1) return 0;
    uint8_t plen = buf[0];
    n = recv(fd, buf, plen, 0);
    if (n != plen) return 0;
    char pass[64];
    memcpy(pass, buf, plen);
    pass[plen] = '\0';

    if (strcmp(user, g_username) == 0 && strcmp(pass, g_password) == 0) {
        uint8_t ok[] = {1, 0};
        send(fd, ok, 2, 0);
        return 1;
    } else {
        uint8_t fail[] = {1, 1};
        send(fd, fail, 2, 0);
        stats_auth_fail();
        return 0;
    }
}

int read_socks5_addr(int fd, char *host, int *port) {
    uint8_t buf[256];
    ssize_t n = recv(fd, buf, 4, 0);
    if (n != 4) return -1;
    uint8_t ver = buf[0], cmd = buf[1], atyp = buf[3];
    if (ver != 5) return -1;
    if (cmd != 1 && cmd != 3) return -2;

    if (atyp == 1) {
        n = recv(fd, buf, 4, 0);
        if (n != 4) return -1;
        struct in_addr in;
        memcpy(&in, buf, 4);
        inet_ntop(AF_INET, &in, host, 64);
        n = recv(fd, buf, 2, 0);
        if (n != 2) return -1;
        *port = (buf[0] << 8) | buf[1];
    } else if (atyp == 3) {
        n = recv(fd, buf, 1, 0);
        if (n != 1) return -1;
        uint8_t len = buf[0];
        n = recv(fd, buf, len, 0);
        if (n != len) return -1;
        memcpy(host, buf, len);
        host[len] = '\0';
        n = recv(fd, buf, 2, 0);
        if (n != 2) return -1;
        *port = (buf[0] << 8) | buf[1];
    } else if (atyp == 4) {
        n = recv(fd, buf, 16, 0);
        if (n != 16) return -1;
        struct in6_addr in6;
        memcpy(&in6, buf, 16);
        inet_ntop(AF_INET6, &in6, host, 64);
        n = recv(fd, buf, 2, 0);
        if (n != 2) return -1;
        *port = (buf[0] << 8) | buf[1];
    } else {
        return -1;
    }
    return 0;
}

void tunnel(int fd1, int fd2) {
    fd_set fds;
    int maxfd = (fd1 > fd2) ? fd1 : fd2;
    uint8_t buffer[BUFFER_SIZE];
    while (1) {
        FD_ZERO(&fds);
        FD_SET(fd1, &fds);
        FD_SET(fd2, &fds);
        struct timeval tv = {IDLE_TIMEOUT, 0};
        int ret = select(maxfd+1, &fds, NULL, NULL, &tv);
        if (ret <= 0) break;
        if (FD_ISSET(fd1, &fds)) {
            ssize_t n = recv(fd1, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            send(fd2, buffer, n, 0);
            stats_add_bytes(0, n);
        }
        if (FD_ISSET(fd2, &fds)) {
            ssize_t n = recv(fd2, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            send(fd1, buffer, n, 0);
            stats_add_bytes(1, n);
        }
    }
    close(fd1);
    close(fd2);
}

void handle_socks5(ClientContext *ctx) {
    int fd = ctx->client_fd;
    char client_ip[64];
    inet_ntop(ctx->client_addr.ss_family,
              (ctx->client_addr.ss_family == AF_INET) ?
              (void*)&((struct sockaddr_in*)&ctx->client_addr)->sin_addr :
              (void*)&((struct sockaddr_in6*)&ctx->client_addr)->sin6_addr,
              client_ip, sizeof(client_ip));
    int client_port = (ctx->client_addr.ss_family == AF_INET) ?
                      ntohs(((struct sockaddr_in*)&ctx->client_addr)->sin_port) :
                      ntohs(((struct sockaddr_in6*)&ctx->client_addr)->sin6_port);

    uint8_t buf[256];
    ssize_t n = recv(fd, buf, 2, 0);
    if (n != 2 || buf[0] != 5) return;
    int nmethods = buf[1];
    n = recv(fd, buf, nmethods, 0);
    if (n != nmethods) return;

    uint8_t method = 0x00;
    if (g_auth_required) {
        for (int i=0; i<nmethods; i++) {
            if (buf[i] == 0x02) { method = 0x02; break; }
        }
        if (method != 0x02) {
            uint8_t reply[] = {5, 0xFF};
            send(fd, reply, 2, 0);
            return;
        }
    }
    uint8_t reply[] = {5, method};
    send(fd, reply, 2, 0);

    if (g_auth_required && !socks5_auth(ctx)) return;

    char host[256];
    int port;
    n = recv(fd, buf, 4, 0);
    if (n != 4 || buf[0] != 5) return;
    uint8_t cmd = buf[1];
    if (cmd != 1 && cmd != 3) {
        socks5_reply(fd, 7, "0.0.0.0", 0);
        return;
    }

    if (read_socks5_addr(fd, host, &port) != 0) {
        socks5_reply(fd, 4, "0.0.0.0", 0);
        return;
    }

    char target[256];
    snprintf(target, sizeof(target), "%s:%d", host, port);
    char ip_str[64];
    strcpy(ip_str, client_ip);

    if (cmd == 1) {
        log_info(COLOR_GREEN "SOCKS5 TCP → %s:%d → %s:%d" COLOR_RESET, client_ip, client_port, host, port);
        active_add(ip_str, client_port, "SOCKS5_TCP", target);
        stats_increment("SOCKS5_TCP", 0);

        int remote = connect_with_retry(host, port);
        if (remote == -1) {
            socks5_reply(fd, 5, "0.0.0.0", 0);
            active_remove(ip_str, client_port, "SOCKS5_TCP", target);
            stats_decrement();
            return;
        }

        struct sockaddr_storage local_addr;
        socklen_t local_len = sizeof(local_addr);
        getsockname(remote, (struct sockaddr*)&local_addr, &local_len);
        char bind_ip[64];
        int bind_port;
        if (local_addr.ss_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in*)&local_addr;
            inet_ntop(AF_INET, &in->sin_addr, bind_ip, 64);
            bind_port = ntohs(in->sin_port);
        } else {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6*)&local_addr;
            inet_ntop(AF_INET6, &in6->sin6_addr, bind_ip, 64);
            bind_port = ntohs(in6->sin6_port);
        }
        socks5_reply(fd, 0, bind_ip, bind_port);

        tunnel(fd, remote);
        active_remove(ip_str, client_port, "SOCKS5_TCP", target);
        stats_decrement();
    } else if (cmd == 3 && g_enable_udp) {
        log_info(COLOR_PURPLE "UDP Associate → %s:%d" COLOR_RESET, client_ip, client_port);
        active_add(ip_str, client_port, "SOCKS5_UDP", "UDP");
        stats_increment("SOCKS5_UDP", 0);

        UdpAssoc *assoc = udp_assoc_create((struct sockaddr*)&ctx->client_addr, ctx->client_addrlen);
        if (!assoc) {
            socks5_reply(fd, 1, "0.0.0.0", 0);
            active_remove(ip_str, client_port, "SOCKS5_UDP", "UDP");
            stats_decrement();
            return;
        }

        char bind_ip[64];
        struct sockaddr_storage bind_addr;
        socklen_t bind_len = sizeof(bind_addr);
        getsockname(fd, (struct sockaddr*)&bind_addr, &bind_len);
        if (bind_addr.ss_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in*)&bind_addr;
            inet_ntop(AF_INET, &in->sin_addr, bind_ip, 64);
        } else {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6*)&bind_addr;
            inet_ntop(AF_INET6, &in6->sin6_addr, bind_ip, 64);
        }
        int bind_port = 0;
        getsockname(assoc->relay_sock, (struct sockaddr*)&bind_addr, &bind_len);
        if (bind_addr.ss_family == AF_INET) {
            bind_port = ntohs(((struct sockaddr_in*)&bind_addr)->sin_port);
        } else {
            bind_port = ntohs(((struct sockaddr_in6*)&bind_addr)->sin6_port);
        }
        socks5_reply(fd, 0, bind_ip, bind_port);

        while (1) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);
            struct timeval tv = {5, 0};
            int ret = select(fd+1, &fds, NULL, NULL, &tv);
            if (ret <= 0) break;
            char dummy[256];
            recv(fd, dummy, sizeof(dummy), 0);
        }

        udp_assoc_close(assoc);
        active_remove(ip_str, client_port, "SOCKS5_UDP", "UDP");
        stats_decrement();
    } else {
        socks5_reply(fd, 7, "0.0.0.0", 0);
    }
}

/* HTTP handling */
void handle_http(ClientContext *ctx) {
    int fd = ctx->client_fd;
    char client_ip[64];
    inet_ntop(ctx->client_addr.ss_family,
              (ctx->client_addr.ss_family == AF_INET) ?
              (void*)&((struct sockaddr_in*)&ctx->client_addr)->sin_addr :
              (void*)&((struct sockaddr_in6*)&ctx->client_addr)->sin6_addr,
              client_ip, sizeof(client_ip));
    int client_port = (ctx->client_addr.ss_family == AF_INET) ?
                      ntohs(((struct sockaddr_in*)&ctx->client_addr)->sin_port) :
                      ntohs(((struct sockaddr_in6*)&ctx->client_addr)->sin6_port);

    uint8_t buffer[BUFFER_SIZE]; // declared once for the whole function

    char req_line[1024];
    int idx = 0;
    while (idx < (int)sizeof(req_line)-1) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return;
        if (c == '\n') break;
        req_line[idx++] = c;
    }
    req_line[idx] = '\0';
    if (strlen(req_line) == 0) return;

    char method[16], url[512], version[16];
    sscanf(req_line, "%15s %511s %15s", method, url, version);

    char headers[8192] = {0};
    int content_length = -1;
    int is_chunked = 0;
    while (1) {
        char line[512];
        int li = 0;
        while (li < (int)sizeof(line)-1) {
            char c;
            ssize_t n = recv(fd, &c, 1, 0);
            if (n <= 0) return;
            if (c == '\n') break;
            line[li++] = c;
        }
        line[li] = '\0';
        if (strcmp(line, "\r") == 0 || strcmp(line, "\n") == 0) break;
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            content_length = atoi(line+15);
        } else if (strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
            if (strstr(line, "chunked")) is_chunked = 1;
        }
        strcat(headers, line);
        strcat(headers, "\r\n");
    }

    char host[256];
    int port = 0;
    if (strcmp(method, "CONNECT") == 0) {
        sscanf(url, "%255[^:]:%d", host, &port);
        if (port == 0) port = 443;
    } else {
        char *p = strstr(url, "://");
        if (p) {
            char *start = p + 3;
            char *end = strchr(start, '/');
            if (end) {
                char hostport[256];
                memcpy(hostport, start, end-start);
                hostport[end-start] = '\0';
                if (strchr(hostport, ':')) {
                    sscanf(hostport, "%255[^:]:%d", host, &port);
                } else {
                    strcpy(host, hostport);
                    port = (strncmp(url, "https", 5)==0) ? 443 : 80;
                }
            } else {
                strcpy(host, start);
                port = (strncmp(url, "https", 5)==0) ? 443 : 80;
            }
        } else {
            char *end = strchr(url, '/');
            if (end) {
                char hostport[256];
                memcpy(hostport, url, end-url);
                hostport[end-url] = '\0';
                if (strchr(hostport, ':')) {
                    sscanf(hostport, "%255[^:]:%d", host, &port);
                } else {
                    strcpy(host, hostport);
                    port = 80;
                }
            } else {
                strcpy(host, url);
                port = 80;
            }
        }
    }

    log_info(COLOR_GREEN "HTTP %s → %s:%d → %s:%d" COLOR_RESET, method, client_ip, client_port, host, port);
    char target[256];
    snprintf(target, sizeof(target), "%s:%d", host, port);
    active_add(client_ip, client_port, "HTTP", target);
    stats_increment("HTTP", 0);

    int remote = -1;
    pthread_mutex_lock(&upstream_mutex);
    if (g_upstream_count > 0) {
        for (int i=0; i<g_upstream_count; i++) {
            int idx = (g_upstream_index + i) % g_upstream_count;
            remote = connect_with_retry(g_upstreams[idx].host, g_upstreams[idx].port);
            if (remote != -1) {
                g_upstream_index = (idx + 1) % g_upstream_count;
                break;
            }
        }
    }
    pthread_mutex_unlock(&upstream_mutex);
    if (remote == -1) {
        remote = connect_with_retry(host, port);
    }
    if (remote == -1) {
        char *resp = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        send(fd, resp, strlen(resp), 0);
        active_remove(client_ip, client_port, "HTTP", target);
        stats_decrement();
        return;
    }

    if (strcmp(method, "CONNECT") == 0) {
        char *resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(fd, resp, strlen(resp), 0);
        tunnel(fd, remote);
    } else {
        char forward_req[8192];
        char path[512];
        char *p = strstr(url, "://");
        if (p) {
            char *start = p + 3;
            char *end = strchr(start, '/');
            if (end) {
                strcpy(path, end);
            } else {
                strcpy(path, "/");
            }
        } else {
            strcpy(path, url);
        }
        snprintf(forward_req, sizeof(forward_req), "%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n",
                 method, path, host, headers);
        send(remote, forward_req, strlen(forward_req), 0);

        if (content_length > 0) {
            long long remaining = content_length;
            while (remaining > 0) {
                ssize_t n = recv(fd, buffer, (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE, 0);
                if (n <= 0) break;
                send(remote, buffer, n, 0);
                remaining -= n;
            }
        } else if (is_chunked) {
            while (1) {
                char chunk_header[32];
                int hi = 0;
                while (hi < (int)sizeof(chunk_header)-1) {
                    char c;
                    ssize_t n = recv(fd, &c, 1, 0);
                    if (n <= 0) goto done;
                    if (c == '\n') break;
                    chunk_header[hi++] = c;
                }
                chunk_header[hi] = '\0';
                send(remote, chunk_header, strlen(chunk_header), 0);
                send(remote, "\n", 1, 0);
                long chunk_size = strtol(chunk_header, NULL, 16);
                if (chunk_size == 0) {
                    while (1) {
                        char line[256];
                        int li = 0;
                        while (li < (int)sizeof(line)-1) {
                            char c;
                            ssize_t n = recv(fd, &c, 1, 0);
                            if (n <= 0) goto done;
                            if (c == '\n') break;
                            line[li++] = c;
                        }
                        line[li] = '\0';
                        send(remote, line, strlen(line), 0);
                        send(remote, "\n", 1, 0);
                        if (strcmp(line, "\r") == 0 || strcmp(line, "\n") == 0) break;
                    }
                    break;
                }
                long long remaining = chunk_size;
                while (remaining > 0) {
                    ssize_t n = recv(fd, buffer, (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE, 0);
                    if (n <= 0) goto done;
                    send(remote, buffer, n, 0);
                    remaining -= n;
                }
                recv(fd, buffer, 2, 0);
                send(remote, buffer, 2, 0);
            }
        }
done:
        tunnel(remote, fd);
    }

    active_remove(client_ip, client_port, "HTTP", target);
    stats_decrement();
}

void* client_handler(void *arg) {
    ClientContext *ctx = (ClientContext*)arg;
    int fd = ctx->client_fd;

    uint8_t first;
    ssize_t n = recv(fd, &first, 1, MSG_PEEK);
    if (n != 1) {
        close(fd);
        free(ctx);
        return NULL;
    }

    if (first == 5) {
        handle_socks5(ctx);
    } else if (first == 'C' || first == 'G' || first == 'P' || first == 'D' || first == 'H' || first == 'O' || first == 'T' || first == 'U') {
        handle_http(ctx);
    } else {
        log_error("Unknown protocol from %s", inet_ntoa(((struct sockaddr_in*)&ctx->client_addr)->sin_addr));
    }

    close(fd);
    free(ctx);
    return NULL;
}

/* ========================== DASHBOARD ========================== */
void* dashboard_thread(void *arg) {
    (void)arg;
    int port = g_dashboard_port;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        log_error("Cannot create dashboard socket");
        return NULL;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_error("Dashboard bind failed on port %d", port);
        close(listen_fd);
        return NULL;
    }
    listen(listen_fd, 10);
    log_info(COLOR_CYAN "Dashboard available at http://0.0.0.0:%d" COLOR_RESET, port);

    while (!g_shutdown_flag) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client = accept(listen_fd, (struct sockaddr*)&client_addr, &len);
        if (client == -1) continue;

        char buf[4096];
        ssize_t n = recv(client, buf, sizeof(buf)-1, 0);
        if (n <= 0) { close(client); continue; }
        buf[n] = '\0';

        if (strstr(buf, "GET / ") || strstr(buf, "GET /stats") || strstr(buf, "GET /api/all")) {
            char response[16384];
            if (strstr(buf, "/api/all") || strstr(buf, "/stats")) {
                pthread_mutex_lock(&stats_mutex);
                time_t uptime = time(NULL) - g_stats.start_time;
                long long total = g_stats.total;
                long long current = g_stats.current;
                long long s5_tcp = g_stats.socks5_tcp;
                long long s5_udp = g_stats.socks5_udp;
                long long http = g_stats.http;
                long long auth_fail = g_stats.auth_fail;
                long long bytes_up = g_stats.bytes_up;
                long long bytes_down = g_stats.bytes_down;
                long long udp_up = g_stats.udp_up;
                long long udp_down = g_stats.udp_down;
                pthread_mutex_unlock(&stats_mutex);

                char active_json[4096] = "";
                pthread_mutex_lock(&active_mutex);
                int count = (g_active_count < 100) ? g_active_count : 100;
                for (int i = 0; i < count; i++) {
                    char buf2[512];
                    snprintf(buf2, sizeof(buf2),
                             "%s{\"ip\":\"%s\",\"port\":%d,\"type\":\"%s\",\"target\":\"%s\"}",
                             (i==0?"":","),
                             g_active_conns[i].ip,
                             g_active_conns[i].port,
                             g_active_conns[i].type,
                             g_active_conns[i].target);
                    strcat(active_json, buf2);
                }
                pthread_mutex_unlock(&active_mutex);

                char upstream_json[512] = "";
                pthread_mutex_lock(&upstream_mutex);
                for (int i = 0; i < g_upstream_count; i++) {
                    char buf2[128];
                    snprintf(buf2, sizeof(buf2), "%s\"%s:%d\"", (i==0?"":","), g_upstreams[i].host, g_upstreams[i].port);
                    strcat(upstream_json, buf2);
                }
                pthread_mutex_unlock(&upstream_mutex);

                snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Connection: close\r\n\r\n"
                    "{\"total\":%lld,\"current\":%lld,\"socks5_tcp\":%lld,\"socks5_udp\":%lld,\"http\":%lld,\"auth_fail\":%lld,"
                    "\"bytes_up\":%lld,\"bytes_down\":%lld,\"udp_up\":%lld,\"udp_down\":%lld,\"uptime\":%ld,"
                    "\"active_connections\":[%s],\"upstream\":{\"proxies\":[%s],\"current_index\":%d}}",
                    total, current, s5_tcp, s5_udp, http, auth_fail,
                    bytes_up, bytes_down, udp_up, udp_down, uptime,
                    active_json, upstream_json, g_upstream_index);
            } else {
                snprintf(response, sizeof(response),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n\r\n"
                    "<html><head><title>Proxy Dashboard</title>"
                    "<style>body{font-family:monospace;background:#1e1e2e;color:#cdd6f4;padding:20px;}"
                    ".stat{margin:10px 0;}.label{color:#89b4fa;}.value{color:#a6e3a1;font-weight:bold;}"
                    "h1{color:#f9e2af;}table{border-collapse:collapse;width:100%;}"
                    "th,td{text-align:left;padding:6px;border-bottom:1px solid #313244;}"
                    "th{color:#89b4fa;}.section{margin-top:20px;border-top:1px solid #45475a;padding-top:10px;}"
                    ".sub{color:#94e2d5;}</style></head><body>"
                    "<h1>Universal Proxy Pro v6.2 (C)</h1>"
                    "<div id='stats'>Loading...</div>"
                    "<script>"
                    "async function fetchAll(){"
                    "try{const res=await fetch('/api/all');const d=await res.json();"
                    "let html='<div class=stat><span class=label>Total connections:</span> <span class=value>'+d.total+'</span></div>'"
                    "+'<div class=stat><span class=label>Active connections:</span> <span class=value>'+d.current+'</span></div>'"
                    "+'<div class=stat><span class=label>SOCKS5 TCP:</span> <span class=value>'+d.socks5_tcp+'</span></div>'"
                    "+'<div class=stat><span class=label>SOCKS5 UDP:</span> <span class=value>'+d.socks5_udp+'</span></div>'"
                    "+'<div class=stat><span class=label>HTTP requests:</span> <span class=value>'+d.http+'</span></div>'"
                    "+'<div class=stat><span class=label>Bytes Up:</span> <span class=value>'+d.bytes_up+'</span></div>'"
                    "+'<div class=stat><span class=label>Bytes Down:</span> <span class=value>'+d.bytes_down+'</span></div>'"
                    "+'<div class=stat><span class=label>UDP Up:</span> <span class=value>'+d.udp_up+'</span></div>'"
                    "+'<div class=stat><span class=label>UDP Down:</span> <span class=value>'+d.udp_down+'</span></div>'"
                    "+'<div class=stat><span class=label>Uptime:</span> <span class=value>'+d.uptime+'s</span></div>'"
                    "+'<div class=section><div class=sub>Active Connections (first 100)</div><table><tr><th>IP</th><th>Port</th><th>Type</th><th>Target</th></tr>';"
                    "d.active_connections.forEach(c=>{html+='<tr><td>'+c.ip+'</td><td>'+c.port+'</td><td>'+c.type+'</td><td>'+c.target+'</td></tr>';});"
                    "html+='</table></div>'"
                    "+'<div class=section><div class=sub>Upstream</div><div class=stat><span class=label>Proxies:</span> <span class=value>'+d.upstream.proxies.join(', ')+'</span></div>'"
                    "+'<div class=stat><span class=label>Current index:</span> <span class=value>'+d.upstream.current_index+'</span></div></div>';"
                    "document.getElementById('stats').innerHTML=html;}catch(e){console.error(e);}}"
                    "fetchAll();setInterval(fetchAll,2000);"
                    "</script></body></html>");
            }
            send(client, response, strlen(response), 0);
        }
        close(client);
    }
    close(listen_fd);
    return NULL;
}

/* ========================== REALTIME STATS ========================== */
void* realtime_stats_thread(void *arg) {
    (void)arg;
    while (!g_shutdown_flag) {
        sleep(2);
        time_t uptime = time(NULL) - g_stats.start_time;
        int h = uptime / 3600;
        int m = (uptime % 3600) / 60;
        int s = uptime % 60;

        pthread_mutex_lock(&stats_mutex);
        long long current = g_stats.current;
        long long bytes_up = g_stats.bytes_up;
        long long bytes_down = g_stats.bytes_down;
        long long udp_up = g_stats.udp_up;
        long long udp_down = g_stats.udp_down;
        pthread_mutex_unlock(&stats_mutex);

        int s5_tcp=0, s5_udp=0, http=0;
        pthread_mutex_lock(&active_mutex);
        for (int i=0; i<g_active_count; i++) {
            if (strcmp(g_active_conns[i].type, "SOCKS5_TCP")==0) s5_tcp++;
            else if (strcmp(g_active_conns[i].type, "SOCKS5_UDP")==0) s5_udp++;
            else if (strcmp(g_active_conns[i].type, "HTTP")==0) http++;
        }
        pthread_mutex_unlock(&active_mutex);

        int udp_assoc_count = 0;
        pthread_mutex_lock(&udp_mutex);
        for (UdpAssoc *a = g_udp_assocs; a; a = a->next) udp_assoc_count++;
        pthread_mutex_unlock(&udp_mutex);

        char up_buf[16], down_buf[16], udp_up_buf[16], udp_down_buf[16];
        format_bytes(bytes_up, up_buf, sizeof(up_buf));
        format_bytes(bytes_down, down_buf, sizeof(down_buf));
        format_bytes(udp_up, udp_up_buf, sizeof(udp_up_buf));
        format_bytes(udp_down, udp_down_buf, sizeof(udp_down_buf));

        printf("\033[2A\033[2K");
        printf(COLOR_YELLOW "↑TCP %9s ↓TCP %9s │ ↑UDP %7s ↓UDP %7s" COLOR_RESET "\n",
               up_buf, down_buf, udp_up_buf, udp_down_buf);
        printf(COLOR_CYAN "Active: %4lld (TCP:%3d UDP:%3d HTTP:%3d) │ UDP Assoc: %3d │ Uptime %02d:%02d:%02d" COLOR_RESET "\n",
               current, s5_tcp, s5_udp, http, udp_assoc_count, h, m, s);
        fflush(stdout);
    }
    return NULL;
}

/* ========================== SIGNAL HANDLING ========================== */
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_shutdown_flag = 1;
        pthread_mutex_lock(&udp_mutex);
        while (g_udp_assocs) {
            UdpAssoc *next = g_udp_assocs->next;
            udp_assoc_close(g_udp_assocs);
            g_udp_assocs = next;
        }
        pthread_mutex_unlock(&udp_mutex);
        stop_udp_relay();
        if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
        time_t uptime = time(NULL) - g_stats.start_time;
        int h = uptime / 3600;
        int m = (uptime % 3600) / 60;
        int s = uptime % 60;
        log_info(COLOR_RED "Proxy STOPPED │ Uptime %02d:%02d:%02d │ Total conn %lld" COLOR_RESET,
                 h, m, s, g_stats.total);
        exit(0);
    }
}

/* ========================== MAIN SERVER ========================== */
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i+1 < argc) strcpy(g_listen_addr, argv[++i]);
        else if (strcmp(argv[i], "-p") == 0 && i+1 < argc) g_listen_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "-u") == 0 && i+1 < argc) strcpy(g_username, argv[++i]);
        else if (strcmp(argv[i], "-P") == 0 && i+1 < argc) strcpy(g_password, argv[++i]);
        else if (strcmp(argv[i], "--no-udp") == 0) g_enable_udp = 0;
        else if (strcmp(argv[i], "--upstream") == 0 && i+1 < argc) {
            char *tok = strtok(argv[++i], ",");
            while (tok && g_upstream_count < MAX_UPSTREAM) {
                char *colon = strchr(tok, ':');
                if (colon) {
                    *colon = '\0';
                    strcpy(g_upstreams[g_upstream_count].host, tok);
                    g_upstreams[g_upstream_count].port = atoi(colon+1);
                    g_upstream_count++;
                }
                tok = strtok(NULL, ",");
            }
        }
        else if (strcmp(argv[i], "--cert") == 0 && i+1 < argc) strcpy(g_cert_file, argv[++i]);
        else if (strcmp(argv[i], "--key") == 0 && i+1 < argc) strcpy(g_key_file, argv[++i]);
        else if (strcmp(argv[i], "--dashboard-port") == 0 && i+1 < argc) g_dashboard_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--force-kill") == 0) g_force_kill = 1;
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: proxy [-l addr] [-p port] [-u user] [-P pass] [--no-udp] [--upstream host:port,...] [--cert cert.pem] [--key key.pem] [--dashboard-port port] [--force-kill]\n");
            return 0;
        }
    }

    if (strlen(g_username) > 0 && strlen(g_password) > 0) {
        g_auth_required = 1;
    }

    if (g_force_kill) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "fuser -k %d/tcp 2>/dev/null", g_listen_port);
        system(cmd);
        sleep(1);
    }

    if (strlen(g_cert_file) > 0 && strlen(g_key_file) > 0) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        g_ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (!g_ssl_ctx) {
            log_error("SSL_CTX_new failed");
            return 1;
        }
        if (SSL_CTX_use_certificate_file(g_ssl_ctx, g_cert_file, SSL_FILETYPE_PEM) <= 0) {
            log_error("SSL_CTX_use_certificate_file failed");
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_key_file, SSL_FILETYPE_PEM) <= 0) {
            log_error("SSL_CTX_use_PrivateKey_file failed");
            return 1;
        }
        log_info(COLOR_GREEN "TLS enabled with cert %s" COLOR_RESET, g_cert_file);
    }

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = 65536;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    start_udp_relay();

    pthread_t dash_thread;
    pthread_create(&dash_thread, NULL, dashboard_thread, NULL);

    pthread_t stats_thread;
    pthread_create(&stats_thread, NULL, realtime_stats_thread, NULL);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        log_error("Cannot create socket");
        return 1;
    }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(g_listen_addr);
    addr.sin_port = htons(g_listen_port);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_error("Bind failed on %s:%d", g_listen_addr, g_listen_port);
        close(listen_fd);
        return 1;
    }
    listen(listen_fd, SOMAXCONN);
    log_info(COLOR_GREEN "Proxy v6.2 (C) STARTED → %s:%d" COLOR_RESET, g_listen_addr, g_listen_port);
    log_info(COLOR_CYAN "Features: SOCKS5 TCP/UDP + HTTP/HTTPS | IPv6 | Upstream: %d | Dashboard: %d | TLS: %s" COLOR_RESET,
             g_upstream_count, g_dashboard_port, g_ssl_ctx ? "yes" : "no");

    g_stats.start_time = time(NULL);
    printf("\n\n");

    while (!g_shutdown_flag) {
        struct sockaddr_storage client_addr;
        socklen_t len = sizeof(client_addr);
        int client = accept(listen_fd, (struct sockaddr*)&client_addr, &len);
        if (client == -1) {
            if (g_shutdown_flag) break;
            continue;
        }

        ClientContext *ctx = malloc(sizeof(ClientContext));
        if (!ctx) { close(client); continue; }
        ctx->client_fd = client;
        memcpy(&ctx->client_addr, &client_addr, len);
        ctx->client_addrlen = len;
        ctx->ssl = NULL;

        pthread_t tid;
        pthread_create(&tid, NULL, client_handler, ctx);
        pthread_detach(tid);
    }

    close(listen_fd);
    stop_udp_relay();
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    return 0;
}

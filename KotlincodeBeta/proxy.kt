@file:Suppress("UNUSED", "NAME_SHADOWING")

import java.io.*
import java.net.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.*
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.math.min
import kotlin.system.exitProcess

// ============================================================================
// CONSTANTS
// ============================================================================
const val VERSION = "v6.3.6-kt"
const val MAX_CONNECTIONS = 4000
const val CONN_TIMEOUT_MS = 25_000
const val HANDSHAKE_TIMEOUT_MS = 30_000
const val IDLE_TIMEOUT_MS = 180_000
const val UDP_IDLE_MS = 120_000L
const val BUF_SIZE = 65536
const val UDP_BUF_SIZE = 65535
const val HASH_ITERATIONS = 200_000
const val MAX_LINE = 8192
const val MAX_HEADERS = 100
const val AUTH_FAIL_THRESHOLD = 5
const val DASH_AUTH_FAIL_THRESHOLD = 30
const val AUTH_FAIL_WINDOW_MS = 300_000L
const val AUTH_BLOCK_MS = 900_000L
const val DASH_MAX_SSE = 16
const val HISTORY_MAX = 300
const val AUDIT_MAX = 200
const val RELOAD_MAX = 30

val rng = SecureRandom()
val USE_VIRTUAL = Runtime.version().feature() >= 21

// ============================================================================
// GLOBAL STATE
// ============================================================================
object S {
    val startMs = System.currentTimeMillis()
    val statTotal = AtomicLong()
    val statCurrent = AtomicInteger()
    val statS5Tcp = AtomicLong()
    val statS5Udp = AtomicLong()
    val statHttp = AtomicLong()
    val statAuthFail = AtomicLong()
    val statBytesUp = AtomicLong()
    val statBytesDown = AtomicLong()
    val statUdpUp = AtomicLong()
    val statUdpDown = AtomicLong()

    val activeConns = ConcurrentHashMap<String, ConnInfo>()
    val connIdSeq = AtomicLong()
    val udpAssocs = ConcurrentHashMap<String, UdpAssoc>()

    val auditLog = ArrayDeque<AuditEvent>()
    val auditLock = ReentrantLock()

    val reloadHistory = ArrayDeque<ReloadEvent>()
    val reloadLock = ReentrantLock()

    val usage = ConcurrentHashMap<String, UsageRec>()

    @Volatile var allowCidrs: List<Cidr> = emptyList()
    @Volatile var denyCidrs: List<Cidr> = emptyList()

    val upstreams = CopyOnWriteArrayList<Upstream>()
    val upstreamIndex = AtomicInteger()
    val upstreamHealth = ConcurrentHashMap<String, Boolean>()

    val failCounts = ConcurrentHashMap<String, Int>()
    val failLast = ConcurrentHashMap<String, Long>()
    val blockedUntil = ConcurrentHashMap<String, Long>()

    @Volatile var cfg = AppConfig()

    val sseClients = CopyOnWriteArraySet<LinkedBlockingQueue<Sample>>()
    val histLock = ReentrantLock()
    val hist = ArrayDeque<Sample>()

    @Volatile var shuttingDown = false

    @Volatile var cliUser = ""
    @Volatile var cliPass = ""
    @Volatile var cliAuthRequired = false
    @Volatile var allowPrivate = false
    @Volatile var enableUdp = true
    @Volatile var upstreamFallback = false
    @Volatile var configPath = "proxy_config.json"
    @Volatile var usagePath = "proxy_usage.json"
}

// ============================================================================
// MINI JSON
// ============================================================================
sealed class J {
    object Nul : J()
    data class B(val v: Boolean) : J()
    data class Num(val d: Double, val l: Long, val isInt: Boolean) : J()
    data class Str(val v: String) : J()
    data class Arr(val v: MutableList<J> = mutableListOf()) : J()
    data class Obj(val v: LinkedHashMap<String, J> = LinkedHashMap()) : J()

    fun asStr(): String? = (this as? Str)?.v
    fun asLong(): Long? = (this as? Num)?.l
    fun asBool(): Boolean? = (this as? B)?.v
    fun asArr(): List<J>? = (this as? Arr)?.v
    operator fun get(k: String): J? = (this as? Obj)?.v?.get(k)
}

object Json {
    fun parse(src: String): J? {
        val p = P(src); p.ws()
        val v = p.value() ?: return null
        p.ws(); return if (p.i == src.length) v else null
    }

    private class P(val s: String) {
        var i = 0
        fun ws() { while (i < s.length && s[i] in " \t\n\r") i++ }
        fun value(): J? {
            ws(); if (i >= s.length) return null
            return when (s[i]) {
                '{' -> obj(); '[' -> arr()
                '"' -> J.Str(str() ?: return null)
                't' -> if (s.startsWith("true", i)) { i += 4; J.B(true) } else null
                'f' -> if (s.startsWith("false", i)) { i += 5; J.B(false) } else null
                'n' -> if (s.startsWith("null", i)) { i += 4; J.Nul } else null
                else -> num()
            }
        }
        fun str(): String? {
            if (i >= s.length || s[i] != '"') return null
            i++; val sb = StringBuilder()
            while (i < s.length) {
                val c = s[i]
                if (c == '"') { i++; return sb.toString() }
                if (c == '\\') {
                    i++; if (i >= s.length) return null
                    when (s[i]) {
                        '"' -> { sb.append('"'); i++ }
                        '\\' -> { sb.append('\\'); i++ }
                        '/' -> { sb.append('/'); i++ }
                        'b' -> { sb.append('\b'); i++ }
                        'f' -> { sb.append('\u000C'); i++ }
                        'n' -> { sb.append('\n'); i++ }
                        'r' -> { sb.append('\r'); i++ }
                        't' -> { sb.append('\t'); i++ }
                        'u' -> {
                            if (i + 4 >= s.length) return null
                            sb.append(s.substring(i + 1, i + 5).toInt(16).toChar()); i += 5
                        }
                        else -> return null
                    }
                } else { sb.append(c); i++ }
            }
            return null
        }
        fun num(): J? {
            val st = i
            if (i < s.length && s[i] == '-') i++
            while (i < s.length && s[i] in '0'..'9') i++
            var isInt = true
            if (i < s.length && s[i] == '.') { isInt = false; i++; while (i < s.length && s[i] in '0'..'9') i++ }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                isInt = false; i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (i == st) return null
            val tok = s.substring(st, i)
            return try {
                if (isInt) J.Num(tok.toDouble(), tok.toLong(), true)
                else J.Num(tok.toDouble(), tok.toDouble().toLong(), false)
            } catch (_: Exception) { null }
        }
        fun arr(): J? {
            if (s[i] != '[') return null
            i++; val a = J.Arr(); ws()
            if (i < s.length && s[i] == ']') { i++; return a }
            while (true) {
                val v = value() ?: return null
                a.v.add(v); ws()
                if (i >= s.length) return null
                when (s[i]) {
                    ',' -> { i++; ws() }
                    ']' -> { i++; return a }
                    else -> return null
                }
            }
        }
        fun obj(): J? {
            if (s[i] != '{') return null
            i++; val o = J.Obj(); ws()
            if (i < s.length && s[i] == '}') { i++; return o }
            while (true) {
                ws()
                val k = str() ?: return null
                ws()
                if (i >= s.length || s[i] != ':') return null
                i++
                val v = value() ?: return null
                o.v[k] = v; ws()
                if (i >= s.length) return null
                when (s[i]) {
                    ',' -> i++
                    '}' -> { i++; return o }
                    else -> return null
                }
            }
        }
    }

    fun encode(v: Any?): String = buildString { enc(v, this) }

    private fun enc(v: Any?, sb: StringBuilder) {
        when (v) {
            null -> sb.append("null")
            is String -> str(sb, v)
            is Boolean, is Int, is Long, is Short, is Byte, is Double, is Float -> sb.append(v.toString())
            is Map<*, *> -> {
                sb.append('{'); var first = true
                for ((k, vv) in v) {
                    if (!first) sb.append(','); first = false
                    str(sb, k.toString()); sb.append(':'); enc(vv, sb)
                }
                sb.append('}')
            }
            is Iterable<*> -> {
                sb.append('['); var first = true
                for (x in v) { if (!first) sb.append(','); first = false; enc(x, sb) }
                sb.append(']')
            }
            is Array<*> -> {
                sb.append('['); var first = true
                for (x in v) { if (!first) sb.append(','); first = false; enc(x, sb) }
                sb.append(']')
            }
            else -> str(sb, v.toString())
        }
    }

    private fun str(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) when {
            c == '"' -> sb.append("\\\"")
            c == '\\' -> sb.append("\\\\")
            c == '\n' -> sb.append("\\n")
            c == '\r' -> sb.append("\\r")
            c == '\t' -> sb.append("\\t")
            c.code < 0x20 || c == '<' || c == '>' || c == '&' -> sb.append("\\u%04x".format(c.code))
            else -> sb.append(c)
        }
        sb.append('"')
    }
}

// ============================================================================
// IP / CIDR / SSRF
// ============================================================================
data class Cidr(val bytes: ByteArray, val prefix: Int) {
    override fun equals(other: Any?) = other is Cidr && prefix == other.prefix && bytes.contentEquals(other.bytes)
    override fun hashCode() = bytes.contentHashCode() * 31 + prefix
}

object IP {
    fun parse(ip: String): ByteArray? = try { InetAddress.getByName(ip).address } catch (_: Exception) { null }
    fun format(b: ByteArray): String = try { InetAddress.getByAddress(b).hostAddress } catch (_: Exception) { "?" }

    fun isV4Mapped(b: ByteArray): Boolean {
        if (b.size != 16) return false
        for (i in 0..9) if (b[i] != 0.toByte()) return false
        return b[10] == 0xFF.toByte() && b[11] == 0xFF.toByte()
    }

    fun parseCidr(spec: String): Cidr? {
        val (ip, pfx) = if ('/' in spec) {
            val idx = spec.lastIndexOf('/')
            val p = spec.substring(idx + 1).toIntOrNull() ?: return null
            spec.substring(0, idx) to p
        } else spec to (if (':' in spec) 128 else 32)
        val addr = try { InetAddress.getByName(ip).address } catch (_: Exception) { return null } ?: return null
        val norm = when (addr.size) {
            4 -> ByteArray(16).also {
                it[10] = 0xFF.toByte(); it[11] = 0xFF.toByte()
                for (i in 0..3) it[12 + i] = addr[i]
            }
            16 -> addr
            else -> return null
        }
        val full = if (addr.size == 4) 96 + pfx else pfx
        if (full < 0 || full > 128) return null
        return Cidr(norm, full)
    }

    fun inCidr(ip: ByteArray, c: Cidr): Boolean {
        val full = c.prefix / 8; val rem = c.prefix % 8
        val cmp = minOf(full, ip.size, c.bytes.size)
        for (i in 0 until cmp) if (ip[i] != c.bytes[i]) return false
        if (rem > 0 && full < ip.size && full < c.bytes.size) {
            val mask = (0xFF shl (8 - rem)) and 0xFF
            if ((ip[full].toInt() and mask) != (c.bytes[full].toInt() and mask)) return false
        }
        return true
    }

    fun blocked(b: ByteArray): Boolean {
        if (S.allowPrivate) return false
        val v4 = if (b.size == 16 && isV4Mapped(b)) byteArrayOf(b[12], b[13], b[14], b[15]) else b
        if (v4.size == 4) {
            val a = v4[0].toInt() and 0xFF
            val bb = v4[1].toInt() and 0xFF
            val c = v4[2].toInt() and 0xFF
            if (a == 0 || a == 10 || a == 127) return true
            if (a == 100 && bb in 64..127) return true
            if (a == 169 && bb == 254) return true
            if (a == 172 && bb in 16..31) return true
            if (a == 192 && bb == 168) return true
            if (a == 192 && bb == 0 && c == 0) return true
            if (a == 198 && (bb == 18 || bb == 19)) return true
            if (a >= 224) return true
            return false
        }
        val a0 = b[0].toInt() and 0xFF
        if (a0 == 0) {
            var allZero = true
            for (i in 0 until 15) if (b[i] != 0.toByte()) { allZero = false; break }
            if (allZero) return true
        }
        if ((a0 and 0xFE) == 0xFC) return true
        if (a0 == 0xFE && (b[1].toInt() and 0xC0) == 0x80) return true
        if (a0 == 0xFF) return true
        return false
    }

    fun allowed(ip: String): Boolean {
        val a = parse(ip) ?: return false
        for (c in S.denyCidrs) if (inCidr(a, c)) return false
        if (S.allowCidrs.isEmpty()) return true
        for (c in S.allowCidrs) if (inCidr(a, c)) return true
        return false
    }
}

// ============================================================================
// HASH
// ============================================================================
object Hash {
    fun digest(pw: String, salt: ByteArray, iters: Int): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt); md.update(pw.toByteArray(StandardCharsets.UTF_8))
        var d = md.digest()
        val md2 = MessageDigest.getInstance("SHA-256")
        repeat(iters - 1) { md2.reset(); d = md2.digest(d) }
        return d
    }

    fun hashPassword(pw: String, iters: Int = HASH_ITERATIONS): String {
        val salt = ByteArray(16).also { rng.nextBytes(it) }
        return "$iters:${hex(salt)}:${hex(digest(pw, salt, iters))}"
    }

    fun verify(pw: String, stored: String?): Boolean {
        if (stored == null) return false
        val p = stored.split(':'); if (p.size != 3) return false
        val iters = p[0].toIntOrNull() ?: return false
        if (iters <= 0 || iters > 5_000_000) return false
        val salt = unhex(p[1]) ?: return false
        val want = unhex(p[2]) ?: return false
        if (want.size != 32) return false
        return MessageDigest.isEqual(digest(pw, salt, iters), want)
    }

    fun sha256Hex(s: String): String = hex(MessageDigest.getInstance("SHA-256").digest(s.toByteArray()))
    fun randomHex(n: Int): String = hex(ByteArray(n).also { rng.nextBytes(it) })

    private fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append("%02x".format(x.toInt() and 0xFF))
        return sb.toString()
    }

    private fun unhex(s: String): ByteArray? {
        if (s.length % 2 != 0) return null
        return try { ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() } } catch (_: Exception) { null }
    }
}

// ============================================================================
// DATA CLASSES
// ============================================================================
data class UserCfg(
    var username: String = "",
    var passwordHash: String = "",
    var maxBandwidthBps: Long = 0,
    var maxConnections: Long = 0,
    var quotaBytes: Long = 0,
)

data class TokenCfg(var name: String = "", var tokenHash: String = "", var createdAt: Long = 0)

data class AppConfig(
    var dashboardUser: String = "",
    var dashboardPasswordHash: String = "",
    var users: MutableList<UserCfg> = mutableListOf(),
    var allowList: MutableList<String> = mutableListOf(),
    var denyList: MutableList<String> = mutableListOf(),
    var upstreamProxies: MutableList<String> = mutableListOf(),
    var apiTokens: MutableList<TokenCfg> = mutableListOf(),
    var requireProxyAuth: Boolean = false,
) {
    fun toJson(): String {
        val m = LinkedHashMap<String, Any?>()
        m["dashboard_user"] = dashboardUser
        m["dashboard_password_hash"] = dashboardPasswordHash
        if (users.isNotEmpty()) m["users"] = users.map {
            linkedMapOf<String, Any?>(
                "username" to it.username, "password_hash" to it.passwordHash,
                "max_bandwidth_bps" to it.maxBandwidthBps,
                "max_connections" to it.maxConnections,
                "quota_bytes_per_month" to it.quotaBytes,
            )
        }
        if (allowList.isNotEmpty()) m["allow_list"] = allowList
        if (denyList.isNotEmpty()) m["deny_list"] = denyList
        if (upstreamProxies.isNotEmpty()) m["upstream_proxies"] = upstreamProxies
        if (apiTokens.isNotEmpty()) m["api_tokens"] = apiTokens.map {
            linkedMapOf<String, Any?>("name" to it.name, "token_hash" to it.tokenHash, "created_at" to it.createdAt)
        }
        if (requireProxyAuth) m["require_proxy_auth"] = true
        return Json.encode(m)
    }

    companion object {
        fun fromJson(j: J): AppConfig {
            val c = AppConfig()
            c.dashboardUser = j["dashboard_user"]?.asStr() ?: ""
            c.dashboardPasswordHash = j["dashboard_password_hash"]?.asStr() ?: ""
            j["users"]?.asArr()?.forEach { u ->
                c.users.add(UserCfg(
                    u["username"]?.asStr() ?: "",
                    u["password_hash"]?.asStr() ?: "",
                    u["max_bandwidth_bps"]?.asLong() ?: 0,
                    u["max_connections"]?.asLong() ?: 0,
                    u["quota_bytes_per_month"]?.asLong() ?: 0,
                ))
            }
            j["allow_list"]?.asArr()?.forEach { c.allowList.add(it.asStr() ?: "") }
            j["deny_list"]?.asArr()?.forEach { c.denyList.add(it.asStr() ?: "") }
            j["upstream_proxies"]?.asArr()?.forEach { c.upstreamProxies.add(it.asStr() ?: "") }
            j["api_tokens"]?.asArr()?.forEach { t ->
                c.apiTokens.add(TokenCfg(
                    t["name"]?.asStr() ?: "", t["token_hash"]?.asStr() ?: "",
                    t["created_at"]?.asLong() ?: 0,
                ))
            }
            c.requireProxyAuth = j["require_proxy_auth"]?.asBool() ?: false
            return c
        }
    }
}

class ConnInfo(
    val id: String, val ip: String, val port: Int, val type: String,
    val target: String, @Volatile var rateBps: Long, val user: String,
    @Volatile var socket: Socket?,
) {
    val startMs = System.currentTimeMillis()
    val bytesUp = AtomicLong(); val bytesDown = AtomicLong()
    fun snapshot(): Pair<Long, Long> = bytesUp.get() to bytesDown.get()
    fun addUp(n: Long) { if (n > 0) bytesUp.addAndGet(n) }
    fun addDown(n: Long) { if (n > 0) bytesDown.addAndGet(n) }
}

class UdpAssoc(
    val clientIp: String, val clientPort: Int, val relayPort: Int,
    val username: String, val controlSocket: Socket,
) {
    @Volatile var lastActivity = System.currentTimeMillis()
    @Volatile var destCount = 0
}

data class AuditEvent(val t: Long, val actor: String, val action: String, val details: String)
data class ReloadEvent(
    val t: Long, val source: String, val success: Boolean, val error: String?,
    val allow: Int, val deny: Int, val upstream: Int, val users: Int, val invalidCidrs: List<String>,
)
data class Sample(val t: Long, val upBps: Long, val downBps: Long, val active: Int, val udpAssocs: Int)
data class UsageRec(var period: String, var bytes: Long)
data class Upstream(val spec: String, val host: String, val port: Int, val type: Int)

// ============================================================================
// PASSWORD CACHE
// ============================================================================
object PwCache {
    private val map = ConcurrentHashMap<String, Long>()
    private const val TTL_MS = 300_000L
    fun hit(pw: String, stored: String): Boolean {
        val key = Hash.sha256Hex(stored + "\u0000" + pw)
        val now = System.currentTimeMillis()
        val exp = map[key]
        if (exp != null && exp > now) return true
        if (!Hash.verify(pw, stored)) return false
        if (map.size > 1024) map.clear()
        map[key] = now + TTL_MS
        return true
    }
}

// ============================================================================
// BRUTE FORCE
// ============================================================================
object Brute {
    fun recordFail(ip: String, threshold: Int) {
        val now = System.currentTimeMillis()
        val last = S.failLast[ip]
        if (last != null && now - last > AUTH_FAIL_WINDOW_MS) S.failCounts[ip] = 0
        S.failLast[ip] = now
        val c = (S.failCounts[ip] ?: 0) + 1
        if (c >= threshold) {
            S.blockedUntil[ip] = now + AUTH_BLOCK_MS
            S.failCounts[ip] = 0
            System.err.println("[WARN] Chặn $ip ${AUTH_BLOCK_MS / 1000}s do auth fail")
        } else S.failCounts[ip] = c
    }
    fun reset(ip: String) { S.failCounts.remove(ip); S.failLast.remove(ip); S.blockedUntil.remove(ip) }
    fun isBlocked(ip: String): Boolean {
        val until = S.blockedUntil[ip] ?: return false
        if (System.currentTimeMillis() > until) { S.blockedUntil.remove(ip); return false }
        return true
    }
}

// ============================================================================
// CONFIG
// ============================================================================
object Cfg {
    fun loadOrInit(path: String, fallbackUser: String, fallbackPass: String): Pair<AppConfig, Boolean> {
        val f = File(path)
        if (f.exists()) {
            val j = Json.parse(f.readText()) ?: throw RuntimeException("config file lỗi JSON")
            val c = AppConfig.fromJson(j)
            if (c.dashboardUser.isEmpty() || c.dashboardPasswordHash.isEmpty())
                throw RuntimeException("config thiếu dashboard_user/hash")
            return c to false
        }
        val pass = if (fallbackPass.isNotEmpty()) fallbackPass else Hash.randomHex(8)
        val c = AppConfig(
            dashboardUser = if (fallbackUser.isNotEmpty()) fallbackUser else "admin",
            dashboardPasswordHash = Hash.hashPassword(pass),
        )
        println("""═══════════════════════════════════════════════════════════════
Dashboard lần đầu — thông tin đăng nhập (chỉ hiện MỘT LẦN):
    URL:      http://127.0.0.1:8081
    User:     ${c.dashboardUser}
    Password: $pass
Config: $path
═══════════════════════════════════════════════════════════════""")
        save(path, c)
        return c to true
    }

    fun save(path: String, c: AppConfig) {
        val tmp = File("$path.tmp")
        tmp.writeText(c.toJson())
        try { tmp.setReadable(true, true); tmp.setWritable(true, true) } catch (_: Exception) {}
        tmp.renameTo(File(path))
    }

    fun reload(source: String): Pair<Boolean, String?> {
        try {
            val f = File(S.configPath)
            if (!f.exists()) { record(ReloadEvent(0, source, false, "no file", 0, 0, 0, 0, emptyList())); return false to "no file" }
            val j = Json.parse(f.readText()) ?: return false to "JSON invalid"
            val c = AppConfig.fromJson(j)
            if (c.dashboardUser.isEmpty() || c.dashboardPasswordHash.isEmpty())
                return false to "thiếu dashboard_user/hash"

            val newAllow = mutableListOf<Cidr>()
            val newDeny = mutableListOf<Cidr>()
            val invalid = mutableListOf<String>()
            for (s in c.allowList) { IP.parseCidr(s.trim())?.let { newAllow.add(it) } ?: invalid.add(s) }
            for (s in c.denyList) { IP.parseCidr(s.trim())?.let { newDeny.add(it) } ?: invalid.add(s) }
            S.allowCidrs = newAllow
            S.denyCidrs = newDeny

            val newUps = mutableListOf<Upstream>()
            for (spec in c.upstreamProxies) parseUpstream(spec)?.let { newUps.add(it) }
            S.upstreams.clear(); S.upstreams.addAll(newUps)
            S.upstreamIndex.set(0)

            S.cfg = c
            for (u in c.users) applyLiveBandwidthLimit(u.username, u.maxBandwidthBps)

            record(ReloadEvent(System.currentTimeMillis() / 1000, source, true, null,
                newAllow.size, newDeny.size, S.upstreams.size, c.users.size, invalid))
            println("[INFO] Reload ($source): ${newAllow.size} allow, ${newDeny.size} deny, ${S.upstreams.size} upstream, ${c.users.size} users")
            return true to null
        } catch (e: Exception) { return false to (e.message ?: "unknown") }
    }

    private fun record(ev: ReloadEvent) {
        S.reloadLock.lock()
        try { S.reloadHistory.addLast(ev); while (S.reloadHistory.size > RELOAD_MAX) S.reloadHistory.removeFirst() }
        finally { S.reloadLock.unlock() }
    }

    fun parseUpstream(spec: String): Upstream? {
        val s = spec.trim(); if (s.isEmpty()) return null
        var type = 0; var hp = s
        if (s.startsWith("socks5://", true)) { type = 1; hp = s.substring(9) }
        else if (s.startsWith("http://", true)) { hp = s.substring(7) }
        val (h, p) = parseHostPort(hp) ?: return null
        return Upstream(s, h, p, type)
    }

    fun parseHostPort(s: String): Pair<String, Int>? {
        if (s.startsWith("[")) {
            val end = s.indexOf(']'); if (end < 0) return null
            val h = s.substring(1, end); val rest = s.substring(end + 1)
            if (!rest.startsWith(":")) return null
            val p = rest.substring(1).toIntOrNull() ?: return null
            return h to p
        }
        val idx = s.lastIndexOf(':'); if (idx < 0) return null
        val h = s.substring(0, idx); val p = s.substring(idx + 1).toIntOrNull() ?: return null
        return h to p
    }
}

// ============================================================================
// AUDIT
// ============================================================================
object Audit {
    fun record(actor: String, action: String, details: String = "") {
        S.auditLock.lock()
        try {
            S.auditLog.addLast(AuditEvent(System.currentTimeMillis() / 1000, actor, action, details))
            while (S.auditLog.size > AUDIT_MAX) S.auditLog.removeFirst()
        } finally { S.auditLock.unlock() }
    }
}

// ============================================================================
// USAGE
// ============================================================================
object Usage {
    fun period(): String {
        val c = GregorianCalendar()
        return "%04d-%02d".format(c.get(Calendar.YEAR), c.get(Calendar.MONTH) + 1)
    }
    fun add(user: String, n: Long) {
        if (user.isEmpty() || n <= 0) return
        val p = period()
        S.usage.compute(user) { _, rec ->
            if (rec == null || rec.period != p) UsageRec(p, n) else { rec.bytes += n; rec }
        }
    }
    fun get(user: String): Long {
        if (user.isEmpty()) return 0
        val p = period(); val r = S.usage[user] ?: return 0
        return if (r.period == p) r.bytes else 0
    }
    fun load(path: String) {
        if (path.isEmpty()) return
        val f = File(path); if (!f.exists()) return
        try {
            val j = Json.parse(f.readText()) ?: return
            (j as? J.Obj)?.v?.forEach { (u, v) ->
                val per = v["period"]?.asStr() ?: return@forEach
                S.usage[u] = UsageRec(per, v["bytes_used"]?.asLong() ?: 0)
            }
        } catch (_: Exception) {}
    }
    fun save(path: String) {
        if (path.isEmpty()) return
        val m = LinkedHashMap<String, Any?>()
        for ((u, r) in S.usage) { if (r.period.isEmpty()) continue; m[u] = mapOf("period" to r.period, "bytes_used" to r.bytes) }
        val tmp = File("$path.tmp")
        try { tmp.writeText(Json.encode(m)); tmp.renameTo(File(path)) } catch (_: Exception) {}
    }
}

// ============================================================================
// AUTH
// ============================================================================
object Auth {
    fun required(): Boolean {
        if (S.cliAuthRequired) return true
        val c = S.cfg; return c.requireProxyAuth || c.users.isNotEmpty()
    }
    fun authenticate(user: String, pass: String): Triple<Boolean, Long, String> {
        if (S.cliUser.isNotEmpty() && user == S.cliUser && pass == S.cliPass) return Triple(true, 0L, user)
        for (u in S.cfg.users) {
            if (u.username == user && PwCache.hit(pass, u.passwordHash)) return Triple(true, u.maxBandwidthBps, u.username)
        }
        return Triple(false, 0L, "")
    }
    fun checkUserLimits(user: String): Pair<Boolean, String> {
        if (user.isEmpty()) return true to ""
        val u = S.cfg.users.find { it.username == user } ?: return true to ""
        if (u.maxConnections > 0 && S.activeConns.values.count { it.user == user } >= u.maxConnections)
            return false to "đã đạt ${u.maxConnections} conn"
        if (u.quotaBytes > 0 && Usage.get(user) >= u.quotaBytes)
            return false to "vượt quota"
        return true to ""
    }
    fun checkToken(token: String): String? {
        if (token.isEmpty()) return null
        val h = Hash.sha256Hex(token)
        return S.cfg.apiTokens.find { it.tokenHash == h }?.name
    }
}

// ============================================================================
// CONNECT (SSRF-safe)
// ============================================================================
object Connect {
    fun direct(host: String, port: Int): Socket? {
        val addrs = try { InetAddress.getAllByName(host) } catch (_: Exception) { return null }
        for (a in addrs) {
            if (IP.blocked(a.address)) continue
            try {
                val s = Socket()
                s.connect(InetSocketAddress(a, port), CONN_TIMEOUT_MS)
                s.tcpNoDelay = true
                return s
            } catch (_: Exception) {}
        }
        System.err.println("[WARN] SSRF/connect fail: $host:$port")
        return null
    }

    fun viaUpstream(host: String, targetPort: Int): Socket? {
        val ups = S.upstreams.toList()
        if (ups.isEmpty()) return null
        val start = S.upstreamIndex.get()
        for (i in ups.indices) {
            val idx = (start + i) % ups.size
            val u = ups[idx]
            val key = "${u.host}:${u.port}"
            if (S.upstreamHealth[key] == false) continue
            val s = try {
                val ss = Socket(); ss.connect(InetSocketAddress(u.host, u.port), CONN_TIMEOUT_MS)
                ss.tcpNoDelay = true; ss
            } catch (_: Exception) { S.upstreamHealth[key] = false; continue }
            val ok = if (u.type == 1) socks5Hs(s, host, targetPort) else httpConnectHs(s, host, targetPort)
            if (ok) { S.upstreamHealth[key] = true; S.upstreamIndex.set((idx + 1) % ups.size); return s }
            try { s.close() } catch (_: Exception) {}
        }
        return null
    }

    private fun httpConnectHs(s: Socket, host: String, port: Int): Boolean = try {
        val hdr = if (':' in host) "[$host]:$port" else "$host:$port"
        s.getOutputStream().write("CONNECT $hdr HTTP/1.1\r\nHost: $hdr\r\n\r\n".toByteArray()); s.getOutputStream().flush()
        val inp = s.getInputStream(); val buf = ByteArray(1024); var n = 0
        while (n < buf.size) {
            val r = inp.read(buf, n, 1); if (r < 0) return false
            n++
            if (n >= 4 && buf[n-4] == 13.toByte() && buf[n-3] == 10.toByte() && buf[n-2] == 13.toByte() && buf[n-1] == 10.toByte()) break
        }
        val r = String(buf, 0, n, StandardCharsets.ISO_8859_1)
        r.startsWith("HTTP/1.") && r.length >= 12 && r[9] == '2'
    } catch (_: Exception) { false }

    private fun socks5Hs(s: Socket, host: String, port: Int): Boolean = try {
        val out = s.getOutputStream(); val inp = s.getInputStream()
        out.write(byteArrayOf(5, 1, 0)); out.flush()
        val rep = ByteArray(2); if (inp.read(rep) != 2 || rep[0] != 5.toByte() || rep[1] != 0.toByte()) return false
        val hb = host.toByteArray(StandardCharsets.ISO_8859_1)
        val req = ByteArray(4 + hb.size + 2)
        req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3
        req[4] = hb.size.toByte(); System.arraycopy(hb, 0, req, 5, hb.size)
        req[5 + hb.size] = ((port ushr 8) and 0xFF).toByte(); req[6 + hb.size] = (port and 0xFF).toByte()
        out.write(req); out.flush()
        val hdr = ByteArray(4); if (inp.read(hdr) != 4 || hdr[0] != 5.toByte() || hdr[1] != 0.toByte()) return false
        val skip = when (hdr[3].toInt()) { 1 -> 6; 4 -> 18; 3 -> { val l = inp.read(); if (l < 0) return false; l + 2 }; else -> return false }
        val tmp = ByteArray(skip); var t = 0
        while (t < skip) { val r = inp.read(tmp, t, skip - t); if (r < 0) return false; t += r }
        true
    } catch (_: Exception) { false }

    fun target(host: String, port: Int): Socket? {
        if (S.upstreams.isNotEmpty()) {
            val s = viaUpstream(host, port)
            if (s != null) return s
            if (!S.upstreamFallback) return null
        }
        return direct(host, port)
    }
}

// ============================================================================
// REGISTRY
// ============================================================================
object Registry {
    fun nextId(): String = "c" + S.connIdSeq.incrementAndGet()
    fun add(ci: ConnInfo) { S.activeConns[ci.id] = ci }
    fun remove(id: String) { S.activeConns.remove(id) }
    fun kick(id: String): ConnInfo? {
        val ci = S.activeConns[id] ?: return null
        try { ci.socket?.shutdownInput(); ci.socket?.shutdownOutput() } catch (_: Exception) {}
        try { ci.socket?.close() } catch (_: Exception) {}
        return ci
    }
}

// ============================================================================
// THROTTLE / TUNNEL
// ============================================================================
fun throttle(ci: ConnInfo?, n: Long) {
    if (ci == null || n <= 0) return
    val r = ci.rateBps; if (r <= 0) return
    val ms = min((n * 1000L) / r, 1500L)
    if (ms > 0) try { Thread.sleep(ms) } catch (_: InterruptedException) {}
}

object Tunnel {
    fun relay(client: Socket, remote: Socket, ci: ConnInfo?, initial: ByteArray?) {
        if (initial != null && initial.isNotEmpty()) {
            try {
                remote.getOutputStream().write(initial); remote.getOutputStream().flush()
                S.statBytesUp.addAndGet(initial.size.toLong())
                ci?.addUp(initial.size.toLong()); Usage.add(ci?.user ?: "", initial.size.toLong())
            } catch (_: Exception) { closeAll(client, remote); return }
        }
        val t = thread(isDaemon = true, name = "tunnel") {
            pump(remote, client, ci, false)
            try { remote.close() } catch (_: Exception) {}
        }
        pump(client, remote, ci, true)
        try { client.close() } catch (_: Exception) {}
        try { t.join(2000) } catch (_: InterruptedException) {}
        try { remote.close() } catch (_: Exception) {}
    }

    private fun pump(from: Socket, to: Socket, ci: ConnInfo?, upstream: Boolean) {
        val buf = ByteArray(BUF_SIZE)
        try {
            from.soTimeout = IDLE_TIMEOUT_MS
            val fin = from.getInputStream(); val fout = to.getOutputStream()
            while (!S.shuttingDown) {
                val n = try { fin.read(buf) } catch (_: SocketTimeoutException) { break }
                if (n <= 0) break
                fout.write(buf, 0, n); fout.flush()
                if (upstream) { S.statBytesUp.addAndGet(n.toLong()); ci?.addUp(n.toLong()) }
                else { S.statBytesDown.addAndGet(n.toLong()); ci?.addDown(n.toLong()) }
                Usage.add(ci?.user ?: "", n.toLong())
                throttle(ci, n.toLong())
            }
        } catch (_: Exception) {}
    }

    fun closeAll(vararg sockets: Socket?) { for (s in sockets) try { s?.close() } catch (_: Exception) {} }
}

// ============================================================================
// BUFFERED READER
// ============================================================================
class BufReader(val input: InputStream) {
    private val buf = ByteArray(8192)
    private var pos = 0; private var len = 0

    fun fill(want: Int): Boolean {
        while (len - pos < want) {
            val n = try { input.read(buf) } catch (_: Exception) { return false }
            if (n <= 0) return false
            pos = 0; len = n
        }
        return true
    }

    fun readByte(): Int {
        if (!fill(1)) return -1
        return buf[pos++].toInt() and 0xFF
    }

    fun readExact(n: Int): ByteArray? {
        if (n <= 0) return ByteArray(0)
        if (!fill(n)) return null
        val out = buf.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    fun line(max: Int = MAX_LINE): String? {
        val sb = StringBuilder()
        while (true) {
            val c = readByte()
            if (c < 0) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) break
            if (sb.length >= max) return null
            sb.append(c.toChar())
        }
        if (sb.isNotEmpty() && sb.last() == '\r') sb.setLength(sb.length - 1)
        return sb.toString()
    }

    fun drain(): ByteArray {
        if (pos >= len) return ByteArray(0)
        val out = buf.copyOfRange(pos, len); pos = len; return out
    }
}

// ============================================================================
// SOCKS5
// ============================================================================
object Socks5 {
    fun handle(s: Socket, br: BufReader, clientIp: String, clientPort: Int, connId: String) {
        try {
            val hdr = br.readExact(2) ?: return
            if (hdr[0].toInt() != 5) return
            val nm = hdr[1].toInt() and 0xFF
            val methods = if (nm > 0) br.readExact(nm) ?: return else ByteArray(0)

            val need = Auth.required()
            val want = if (need) 0x02 else 0x00
            if (methods.none { (it.toInt() and 0xFF) == want }) {
                s.getOutputStream().write(byteArrayOf(5, 0xFF.toByte())); return
            }
            s.getOutputStream().write(byteArrayOf(5, want.toByte())); s.getOutputStream().flush()

            var username = ""; var rateBps = 0L
            if (need) {
                val r = doAuth(s, br) ?: return
                username = r.second; rateBps = r.first
                val (ok, reason) = Auth.checkUserLimits(username)
                if (!ok) { System.err.println("[WARN] SOCKS5 reject $username: $reason"); reply(s, 0x02); return }
            }

            val req = br.readExact(4) ?: return
            val cmd = req[1].toInt() and 0xFF
            val atyp = req[3].toInt() and 0xFF
            when (cmd) {
                0x01 -> doConnect(s, br, atyp, clientIp, clientPort, connId, username, rateBps)
                0x03 -> UDPRelay.start(s, br, atyp, clientIp, clientPort, username, rateBps)
                else -> reply(s, 0x07)
            }
        } catch (e: Exception) { System.err.println("[WARN] SOCKS5: ${e.message}") }
    }

    private fun doAuth(s: Socket, br: BufReader): Pair<Long, String>? {
        val ver = br.readExact(1) ?: return null
        if (ver[0].toInt() != 1) { s.getOutputStream().write(byteArrayOf(1, 0xFF.toByte())); return null }
        val ul = br.readExact(1)?.get(0)?.toInt()?.and(0xFF) ?: return null
        val ub = if (ul > 0) br.readExact(ul) ?: return null else ByteArray(0)
        val pl = br.readExact(1)?.get(0)?.toInt()?.and(0xFF) ?: return null
        val pb = if (pl > 0) br.readExact(pl) ?: return null else ByteArray(0)
        val (ok, rate, uname) = Auth.authenticate(String(ub, StandardCharsets.UTF_8), String(pb, StandardCharsets.UTF_8))
        if (ok) {
            s.getOutputStream().write(byteArrayOf(1, 0)); s.getOutputStream().flush()
            Brute.reset(s.inetAddress.hostAddress)
            return rate to uname
        }
        s.getOutputStream().write(byteArrayOf(1, 0xFF.toByte())); s.getOutputStream().flush()
        S.statAuthFail.incrementAndGet()
        Brute.recordFail(s.inetAddress.hostAddress, AUTH_FAIL_THRESHOLD)
        return null
    }

    private fun doConnect(s: Socket, br: BufReader, atyp: Int, clientIp: String, clientPort: Int,
                          connId: String, username: String, rateBps: Long) {
        val (host, port) = readAddr(br, atyp) ?: run { reply(s, 0x04); return }
        s.soTimeout = 0
        val remote = Connect.target(host, port) ?: run { reply(s, 0x05); return }
        reply(s, 0, remote.localAddress.hostAddress, remote.localPort)

        val ci = ConnInfo(connId, clientIp, clientPort, "SOCKS5_TCP", "$host:$port", rateBps, username, s)
        Registry.add(ci); S.statS5Tcp.incrementAndGet()
        try {
            val initial = br.drain()
            Tunnel.relay(s, remote, ci, initial)
        } finally {
            Registry.remove(connId)
            try { remote.close() } catch (_: Exception) {}
        }
    }

    fun readAddr(br: BufReader, atyp: Int): Pair<String, Int>? {
        val host = when (atyp) {
            1 -> { val b = br.readExact(4) ?: return null; InetAddress.getByAddress(b).hostAddress }
            4 -> { val b = br.readExact(16) ?: return null; InetAddress.getByAddress(b).hostAddress }
            3 -> {
                val n = br.readExact(1)?.get(0)?.toInt()?.and(0xFF) ?: return null
                if (n == 0) return null
                String(br.readExact(n) ?: return null, StandardCharsets.US_ASCII)
            }
            else -> return null
        }
        val pb = br.readExact(2) ?: return null
        return host to (((pb[0].toInt() and 0xFF) shl 8) or (pb[1].toInt() and 0xFF))
    }

    fun reply(s: Socket, rep: Int, ip: String = "0.0.0.0", port: Int = 0) {
        try {
            val bytes = InetAddress.getByName(ip).address
            val atyp = if (bytes.size == 4) 1 else 4
            val out = ByteArrayOutputStream()
            out.write(byteArrayOf(5, rep.toByte(), 0, atyp.toByte()))
            out.write(bytes)
            out.write((port ushr 8) and 0xFF); out.write(port and 0xFF)
            s.getOutputStream().write(out.toByteArray()); s.getOutputStream().flush()
        } catch (_: Exception) {}
    }
}

// ============================================================================
// UDP RELAY
// ============================================================================
object UDPRelay {
    fun start(tcp: Socket, br: BufReader, atyp: Int, clientIp: String, clientPort: Int,
              username: String, rateBps: Long) {
        if (!S.enableUdp) { Socks5.reply(tcp, 0x07); return }
        Socks5.readAddr(br, atyp) ?: return
        try {
            val relay = DatagramSocket(0)
            val relayPort = relay.localPort
            tcp.soTimeout = 0
            val bound = tcp.localAddress.hostAddress ?: "0.0.0.0"
            Socks5.reply(tcp, 0, bound, relayPort)
            println("[INFO] UDP relay $clientIp:$clientPort → :$relayPort")

            val ci = ConnInfo(Registry.nextId(), clientIp, clientPort, "SOCKS5_UDP", "UDP", rateBps, username, tcp)
            Registry.add(ci); S.statS5Udp.incrementAndGet()
            val key = "$clientIp:$clientPort:$relayPort"
            val assoc = UdpAssoc(clientIp, clientPort, relayPort, username, tcp)
            S.udpAssocs[key] = assoc

            val destMap = HashMap<Pair<String, Int>, Long>()
            var clientUdp: InetSocketAddress? = null
            relay.soTimeout = 1000
            val buf = ByteArray(UDP_BUF_SIZE)
            tcp.soTimeout = 100

            try {
                while (!S.shuttingDown) {
                    if (System.currentTimeMillis() - assoc.lastActivity > UDP_IDLE_MS) break
                    try {
                        val pkt = DatagramPacket(buf, buf.size)
                        relay.receive(pkt)
                        assoc.lastActivity = System.currentTimeMillis()
                        val fromAddr = pkt.socketAddress as InetSocketAddress
                        if (clientUdp == null) {
                            if (fromAddr.address.hostAddress != clientIp) continue
                            clientUdp = fromAddr
                        }
                        if (fromAddr == clientUdp) procClient(relay, pkt.data, pkt.length, destMap, ci, assoc)
                        else procRemote(relay, pkt.data, pkt.length, fromAddr, clientUdp!!, destMap, ci)
                    } catch (_: SocketTimeoutException) {}
                    try {
                        val av = tcp.getInputStream().available()
                        if (av > 0) {
                            val tmp = ByteArray(av); if (tcp.getInputStream().read(tmp) < 0) break
                        }
                    } catch (_: Exception) { break }
                }
            } finally {
                try { relay.close() } catch (_: Exception) {}
                S.udpAssocs.remove(key); Registry.remove(ci.id)
            }
        } catch (e: Exception) { System.err.println("[WARN] UDP: ${e.message}") }
    }

    private fun procClient(relay: DatagramSocket, data: ByteArray, n: Int,
                           destMap: HashMap<Pair<String, Int>, Long>, ci: ConnInfo, assoc: UdpAssoc) {
        if (n < 4 || data[2].toInt() != 0) return
        val atyp = data[3].toInt() and 0xFF
        var pos = 4
        val host: String
        when (atyp) {
            1 -> { if (n < pos + 6) return; host = InetAddress.getByAddress(data.copyOfRange(pos, pos + 4)).hostAddress; pos += 4 }
            4 -> { if (n < pos + 18) return; host = InetAddress.getByAddress(data.copyOfRange(pos, pos + 16)).hostAddress; pos += 16 }
            3 -> {
                if (n < pos + 1) return
                val ln = data[pos].toInt() and 0xFF; pos++
                if (ln == 0 || n < pos + ln + 2) return
                host = String(data, pos, ln, StandardCharsets.US_ASCII); pos += ln
            }
            else -> return
        }
        val port = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF); pos += 2
        val payload = data.copyOfRange(pos, n)
        val addrs = try { InetAddress.getAllByName(host) } catch (_: Exception) { return }
        val chosen = addrs.firstOrNull { !IP.blocked(it.address) } ?: return
        val dest = InetSocketAddress(chosen, port)
        try { relay.send(DatagramPacket(payload, payload.size, dest)) } catch (_: Exception) { return }
        val k = chosen.hostAddress to port
        if (!destMap.containsKey(k)) { destMap[k] = System.currentTimeMillis(); assoc.destCount = destMap.size }
        S.statUdpUp.addAndGet(payload.size.toLong()); Usage.add(ci.user, payload.size.toLong())
    }

    private fun procRemote(relay: DatagramSocket, data: ByteArray, n: Int, from: InetSocketAddress,
                           client: InetSocketAddress, destMap: HashMap<Pair<String, Int>, Long>, ci: ConnInfo) {
        if ((from.address.hostAddress to from.port) !in destMap) return
        val addr = from.address.address
        val atyp = if (addr.size == 4) 1 else 4
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0, 0, 0, atyp.toByte()))
        out.write(addr)
        out.write((from.port ushr 8) and 0xFF); out.write(from.port and 0xFF)
        out.write(data, 0, n)
        try { val pkt = out.toByteArray(); relay.send(DatagramPacket(pkt, pkt.size, client)) } catch (_: Exception) { return }
        S.statUdpDown.addAndGet(n.toLong()); Usage.add(ci.user, n.toLong())
    }
}

// ============================================================================
// HTTP PROXY
// ============================================================================
object HttpProxy {
    fun handle(s: Socket, br: BufReader, clientIp: String, clientPort: Int, connId: String) {
        try {
            val reqLine = br.line() ?: return
            val parts = reqLine.split(" ")
            if (parts.size < 2) return
            val method = parts[0].uppercase()
            val url = parts[1]
            val headers = HashMap<String, MutableList<String>>()
            var count = 0
            while (true) {
                count++; if (count > MAX_HEADERS) return
                val line = br.line() ?: return
                if (line.isEmpty()) break
                val idx = line.indexOf(':'); if (idx <= 0) continue
                val k = line.substring(0, idx).trim().lowercase()
                headers.getOrPut(k) { mutableListOf() }.add(line.substring(idx + 1).trim())
            }
            s.soTimeout = 0

            // Reject CL + TE (smuggling)
            if (headers.containsKey("content-length") && headers.containsKey("transfer-encoding")) {
                s.getOutputStream().write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".toByteArray()); return
            }

            var username = ""; var rateBps = 0L
            if (Auth.required()) {
                val auth = headers["proxy-authorization"]?.firstOrNull() ?: ""
                val (u, p) = decodeBasic(auth) ?: run {
                    s.getOutputStream().write("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nConnection: close\r\n\r\n".toByteArray()); return
                }
                val (ok, rate, uname) = Auth.authenticate(u, p)
                if (!ok) {
                    s.getOutputStream().write("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nConnection: close\r\n\r\n".toByteArray())
                    S.statAuthFail.incrementAndGet(); Brute.recordFail(clientIp, AUTH_FAIL_THRESHOLD); return
                }
                Brute.reset(clientIp)
                username = uname; rateBps = rate
                val (allowed, reason) = Auth.checkUserLimits(username)
                if (!allowed) { s.getOutputStream().write("HTTP/1.1 429\r\nConnection: close\r\n\r\n$reason".toByteArray()); return }
            }

            if (method == "CONNECT") {
                val (host, port) = parseConnect(url) ?: run { send400(s); return }
                doConnect(s, br, host, port, clientIp, clientPort, connId, username, rateBps)
            } else {
                val parsed = parseHttpUrl(url) ?: run { send400(s); return }
                doForward(s, br, method, headers, parsed, clientIp, clientPort, connId, username, rateBps)
            }
        } catch (e: Exception) { System.err.println("[WARN] HTTP: ${e.message}") }
    }

    private fun decodeBasic(auth: String): Pair<String, String>? {
        if (!auth.lowercase().startsWith("basic ")) return null
        return try {
            val dec = String(Base64.getDecoder().decode(auth.substring(6).trim()), StandardCharsets.UTF_8)
            val idx = dec.indexOf(':'); if (idx < 0) null else dec.substring(0, idx) to dec.substring(idx + 1)
        } catch (_: Exception) { null }
    }

    private fun parseConnect(url: String): Pair<String, Int>? {
        if (url.startsWith("[")) {
            val end = url.indexOf(']'); if (end < 0) return null
            val h = url.substring(1, end)
            if (end + 1 >= url.length || url[end + 1] != ':') return null
            val p = url.substring(end + 2).toIntOrNull() ?: return null
            return if (p in 1..65535) h to p else null
        }
        val idx = url.lastIndexOf(':'); if (idx < 0) return null
        val h = url.substring(0, idx); val p = url.substring(idx + 1).toIntOrNull() ?: return null
        return if (p in 1..65535) h to p else null
    }

    private fun parseHttpUrl(url: String): Triple<String, Int, String>? {
        val u = if (url.startsWith("http://")) url else "http://$url"
        val uri = try { URI(u) } catch (_: Exception) { return null }
        val host = uri.host ?: return null
        val port = if (uri.port > 0) uri.port else 80
        val path = (uri.rawPath ?: "/").let { if (it.isEmpty()) "/" else it } + (uri.rawQuery?.let { "?$it" } ?: "")
        return Triple(host, port, path)
    }

    private fun doConnect(s: Socket, br: BufReader, host: String, port: Int,
                          clientIp: String, clientPort: Int, connId: String, username: String, rateBps: Long) {
        val remote = Connect.target(host, port) ?: run {
            s.getOutputStream().write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray()); return
        }
        s.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
        s.getOutputStream().flush()
        val ci = ConnInfo(connId, clientIp, clientPort, "HTTP", "$host:$port", rateBps, username, s)
        Registry.add(ci); S.statHttp.incrementAndGet()
        try { Tunnel.relay(s, remote, ci, br.drain()) }
        finally {
            Registry.remove(connId)
            try { remote.close() } catch (_: Exception) {}
        }
    }

    private fun doForward(s: Socket, br: BufReader, method: String,
                          headers: Map<String, List<String>>, parsed: Triple<String, Int, String>,
                          clientIp: String, clientPort: Int, connId: String, username: String, rateBps: Long) {
        val (host, port, path) = parsed
        val remote = Connect.target(host, port) ?: run {
            s.getOutputStream().write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray()); return
        }
        val ci = ConnInfo(connId, clientIp, clientPort, "HTTP", "$host:$port", rateBps, username, s)
        Registry.add(ci); S.statHttp.incrementAndGet()
        try {
            val sb = StringBuilder()
            sb.append("$method $path HTTP/1.1\r\n")
            if (!headers.containsKey("host")) sb.append("Host: $host\r\n")
            for ((k, vs) in headers) {
                if (k in listOf("proxy-authorization", "proxy-connection", "connection")) continue
                for (v in vs) sb.append("${k.replaceFirstChar { it.uppercase() }}: $v\r\n")
            }
            sb.append("Connection: close\r\n\r\n")
            val reqBytes = sb.toString().toByteArray()
            remote.getOutputStream().write(reqBytes); remote.getOutputStream().flush()
            S.statBytesUp.addAndGet(reqBytes.size.toLong()); ci.addUp(reqBytes.size.toLong())
            Usage.add(username, reqBytes.size.toLong())

            val cl = headers["content-length"]?.lastOrNull()
            if (cl != null) {
                val n = cl.trim().toLongOrNull() ?: 0
                if (n > 0) forwardBody(br, remote, n, ci)
            } else if (headers["transfer-encoding"]?.lastOrNull()?.lowercase() == "chunked") {
                forwardChunked(br, remote, ci)
            }
            forwardResponse(remote, s, ci)
        } finally {
            try { remote.close() } catch (_: Exception) {}
            Registry.remove(connId)
        }
    }

    private fun forwardBody(br: BufReader, remote: Socket, n: Long, ci: ConnInfo) {
        var rem = n
        val out = remote.getOutputStream()
        while (rem > 0) {
            val want = min(rem, BUF_SIZE.toLong()).toInt()
            val data = br.readExact(want) ?: return
            out.write(data); out.flush()
            S.statBytesUp.addAndGet(data.size.toLong()); ci.addUp(data.size.toLong())
            Usage.add(ci.user, data.size.toLong()); throttle(ci, data.size.toLong())
            rem -= data.size
        }
    }

    private fun forwardChunked(br: BufReader, remote: Socket, ci: ConnInfo) {
        val out = remote.getOutputStream()
        while (true) {
            val line = br.line(1024) ?: return
            out.write((line + "\r\n").toByteArray())
            val sz = line.split(';')[0].trim().toIntOrNull(16) ?: return
            if (sz == 0) {
                while (true) { val t = br.line() ?: return; out.write((t + "\r\n").toByteArray()); if (t.isEmpty()) break }
                out.flush(); return
            }
            val data = br.readExact(sz) ?: return
            out.write(data)
            out.write(br.readExact(2) ?: return); out.flush()
            S.statBytesUp.addAndGet(sz.toLong()); ci.addUp(sz.toLong()); Usage.add(ci.user, sz.toLong())
        }
    }

    private fun forwardResponse(remote: Socket, client: Socket, ci: ConnInfo) {
        val buf = ByteArray(BUF_SIZE)
        try {
            remote.soTimeout = IDLE_TIMEOUT_MS
            val cin = remote.getInputStream(); val cout = client.getOutputStream()
            while (true) {
                val n = cin.read(buf); if (n <= 0) break
                cout.write(buf, 0, n); cout.flush()
                S.statBytesDown.addAndGet(n.toLong()); ci.addDown(n.toLong())
                Usage.add(ci.user, n.toLong()); throttle(ci, n.toLong())
            }
        } catch (_: Exception) {}
    }

    private fun send400(s: Socket) { try { s.getOutputStream().write("HTTP/1.1 400 Bad Request\r\n\r\n".toByteArray()) } catch (_: Exception) {} }
}

// ============================================================================
// LISTENER
// ============================================================================
object Listener {
    fun run(bind: String, port: Int, sslCtx: javax.net.ssl.SSLContext? = null) {
        try {
            val server: ServerSocket = if (sslCtx != null) {
                val ss = sslCtx.serverSocketFactory.createServerSocket() as javax.net.ssl.SSLServerSocket
                ss.reuseAddress = true
                ss.bind(InetSocketAddress(bind, port), 1024)
                ss
            } else {
                val ss = ServerSocket()
                ss.reuseAddress = true
                ss.bind(InetSocketAddress(bind, port), 1024)
                ss
            }
            val suffix = if (sslCtx != null) " (TLS)" else ""
            println("[INFO] Proxy STARTED → $bind:$port$suffix")
            while (!S.shuttingDown) {
                try {
                    val s = server.accept()
                    if (S.statCurrent.get() >= MAX_CONNECTIONS) { s.close(); continue }
                    S.statCurrent.incrementAndGet(); S.statTotal.incrementAndGet()
                    submit { handle(s) }
                } catch (_: Exception) { if (!S.shuttingDown) Thread.sleep(50) }
            }
        } catch (e: Exception) {
            System.err.println("[FATAL] Bind fail: ${e.message}"); exitProcess(1)
        }
    }

    private fun handle(s: Socket) {
        val clientIp = s.inetAddress.hostAddress
        val clientPort = s.port
        val connId = Registry.nextId()
        try {
            s.tcpNoDelay = true; s.soTimeout = HANDSHAKE_TIMEOUT_MS
            if (Brute.isBlocked(clientIp)) { s.close(); return }
            if (!IP.allowed(clientIp)) {
                System.err.println("[WARN] IP $clientIp bị từ chối")
                s.close(); return
            }
            val pb = PushbackInputStream(s.getInputStream(), 16)
            val first = try { pb.read() } catch (_: Exception) { -1 }
            if (first < 0) return
            pb.unread(first)
            val br = BufReader(pb)
            when {
                first == 5 -> Socks5.handle(s, br, clientIp, clientPort, connId)
                first.toChar() in "CGPDAHOT" -> HttpProxy.handle(s, br, clientIp, clientPort, connId)
            }
        } catch (_: Exception) {
        } finally {
            try { s.close() } catch (_: Exception) {}
            S.statCurrent.decrementAndGet()
        }
    }
}

// Virtual thread executor (JDK 21) or cached pool
fun submit(block: () -> Unit) {
    if (USE_VIRTUAL) {
        try {
            Thread.ofVirtual().name("vt").start(block)
            return
        } catch (_: Exception) {}
    }
    thread(isDaemon = true, block = block)
}

// ============================================================================
// DASHBOARD (raw socket)
// ============================================================================
object Dashboard {
    fun run(bind: String, port: Int) {
        try {
            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(InetSocketAddress(bind, port), 256)
            println("[INFO] Dashboard: http://$bind:$port")
            while (!S.shuttingDown) {
                try {
                    val s = server.accept()
                    submit { handle(s) }
                } catch (_: Exception) { if (!S.shuttingDown) Thread.sleep(50) }
            }
        } catch (e: Exception) { System.err.println("[WARN] Dashboard: ${e.message}") }
    }

    private fun handle(s: Socket) {
        val peer = s.inetAddress.hostAddress
        try {
            s.soTimeout = 30_000
            val br = BufReader(s.getInputStream())
            val reqLine = br.line() ?: return
            val parts = reqLine.split(" ")
            if (parts.size < 2) { respond(s, 400, "text/plain", "bad"); return }
            val method = parts[0]
            val rawTarget = parts[1]
            val qi = rawTarget.indexOf('?')
            val path = if (qi < 0) rawTarget else rawTarget.substring(0, qi)
            val query = if (qi < 0) emptyMap() else parseQuery(rawTarget.substring(qi + 1))
            val headers = HashMap<String, MutableList<String>>()
            var c = 0
            while (true) {
                c++; if (c > MAX_HEADERS) return
                val line = br.line() ?: return
                if (line.isEmpty()) break
                val idx = line.indexOf(':'); if (idx <= 0) continue
                val k = line.substring(0, idx).trim().lowercase()
                headers.getOrPut(k) { mutableListOf() }.add(line.substring(idx + 1).trim())
            }
            route(s, br, method, path, query, headers, peer)
        } catch (_: Exception) { try { s.close() } catch (_: Exception) {} }
    }

    private fun parseQuery(qs: String): Map<String, String> {
        val m = HashMap<String, String>()
        for (kv in qs.split("&")) {
            if (kv.isEmpty()) continue
            val eq = kv.indexOf('=')
            if (eq < 0) m[kv] = "" else m[kv.substring(0, eq)] = URLDecoder.decode(kv.substring(eq + 1), "UTF-8")
        }
        return m
    }

    private fun route(s: Socket, br: BufReader, method: String, path: String,
                      query: Map<String, String>, headers: Map<String, List<String>>, peer: String) {
        if (path == "/healthz") {
            if (S.shuttingDown) respond(s, 503, "application/json", """{"status":"shutting_down"}""")
            else respond(s, 200, "application/json", """{"status":"ok"}""")
            return
        }
        if (path == "/metrics") { respond(s, 200, "text/plain; version=0.0.4", metrics()); return }

        val actor = auth(s, headers, peer) ?: return
        if (method in listOf("POST", "PUT", "DELETE")) {
            val err = csrfCheck(method, headers)
            if (err != null) { respond(s, 403, "text/plain", "403 CSRF: $err"); return }
        }

        // Read body for POST
        var body = ""
        if (method == "POST") {
            val cl = headers["content-length"]?.firstOrNull()?.trim()?.toIntOrNull() ?: 0
            if (cl > 0 && cl <= 5_000_000) {
                body = String(br.readExact(cl) ?: ByteArray(0), StandardCharsets.UTF_8)
            }
        }

        when {
            method == "GET" && path == "/" -> respond(s, 200, "text/html; charset=utf-8", DASH_HTML)
            method == "GET" && path == "/stats" -> respondJson(s, 200, statsBasic())
            method == "GET" && path == "/api/all" -> respondJson(s, 200, statsAll())
            method == "GET" && path == "/api/users" -> respondJson(s, 200, apiUsers())
            method == "GET" && path == "/api/tokens" -> respondJson(s, 200, apiTokens())
            method == "GET" && path == "/api/network-config" -> respondJson(s, 200, apiNet())
            method == "GET" && path == "/api/audit-log" -> respondJson(s, 200, apiAudit())
            method == "GET" && path == "/api/reload-history" -> respondJson(s, 200, apiReload())
            method == "GET" && path == "/api/stream" -> sse(s)
            method == "GET" && path == "/api/export" -> exportConns(s, query)
            method == "GET" && path == "/api/config/export" -> exportConfig(s, actor)
            method == "POST" && path == "/api/reload" -> doReload(s, actor)
            method == "POST" && path == "/api/kick" -> doKick(s, body, actor)
            method == "POST" && path == "/api/users" -> doUser(s, body, actor)
            method == "POST" && path == "/api/users/delete" -> doDelUser(s, body, actor)
            method == "POST" && path == "/api/tokens" -> doToken(s, body, actor)
            method == "POST" && path == "/api/tokens/delete" -> doDelToken(s, body, actor)
            method == "POST" && path == "/api/network-config" -> doNet(s, body, actor)
            method == "POST" && path == "/api/change-password" -> doChangePw(s, body, actor)
            method == "POST" && path == "/api/config/import" -> importConfig(s, body, actor)
            else -> respond(s, 404, "text/plain", "404")
        }
    }

    private fun auth(s: Socket, headers: Map<String, List<String>>, peer: String): String? {
        if (Brute.isBlocked(peer)) { respond(s, 429, "text/plain", "429"); return null }
        val authz = headers["authorization"]?.firstOrNull() ?: ""
        if (authz.startsWith("Bearer ")) {
            val name = Auth.checkToken(authz.substring(7).trim())
            if (name != null) { Brute.reset(peer); return "token:$name" }
            Brute.recordFail(peer, DASH_AUTH_FAIL_THRESHOLD)
            respond(s, 401, "text/plain", "401 invalid token"); return null
        }
        if (!authz.lowercase().startsWith("basic ")) {
            Brute.recordFail(peer, DASH_AUTH_FAIL_THRESHOLD)
            respond(s, 401, "text/plain", "401", mapOf("WWW-Authenticate" to "Basic realm=\"Dashboard\""))
            return null
        }
        val dec = try { String(Base64.getDecoder().decode(authz.substring(6).trim()), StandardCharsets.UTF_8) } catch (_: Exception) { null }
        if (dec == null) { respond(s, 401, "text/plain", "401"); return null }
        val idx = dec.indexOf(':'); if (idx < 0) { respond(s, 401, "text/plain", "401"); return null }
        val u = dec.substring(0, idx); val p = dec.substring(idx + 1)
        val c = S.cfg
        if (u != c.dashboardUser || !PwCache.hit(p, c.dashboardPasswordHash)) {
            Brute.recordFail(peer, DASH_AUTH_FAIL_THRESHOLD)
            respond(s, 401, "text/plain", "401", mapOf("WWW-Authenticate" to "Basic realm=\"Dashboard\""))
            return null
        }
        Brute.reset(peer); return "dashboard:$u"
    }

    private fun csrfCheck(method: String, headers: Map<String, List<String>>): String? {
        if (method in listOf("GET", "HEAD", "OPTIONS")) return null
        val sfs = headers["sec-fetch-site"]?.firstOrNull() ?: ""
        if (sfs.isNotEmpty() && sfs !in listOf("same-origin", "none")) return "Sec-Fetch-Site=$sfs"
        val origin = headers["origin"]?.firstOrNull() ?: ""
        val host = headers["host"]?.firstOrNull() ?: ""
        if (origin.isNotEmpty()) {
            val u = try { URI(origin) } catch (_: Exception) { return "bad origin" }
            val oh = u.host ?: return "bad origin"
            if (oh != host.substringBefore(':')) return "Origin $oh != Host $host"
        }
        val ct = headers["content-type"]?.firstOrNull()?.lowercase() ?: ""
        if (!ct.startsWith("application/json")) return "Content-Type must be JSON"
        return null
    }

    private fun statsBasic(): Map<String, Any?> = linkedMapOf(
        "total" to S.statTotal.get(), "current" to S.statCurrent.get(),
        "active" to S.activeConns.size,
        "socks5_tcp" to S.statS5Tcp.get(), "socks5_udp" to S.statS5Udp.get(),
        "http" to S.statHttp.get(), "auth_fail" to S.statAuthFail.get(),
        "bytes_up" to S.statBytesUp.get(), "bytes_down" to S.statBytesDown.get(),
        "udp_up" to S.statUdpUp.get(), "udp_down" to S.statUdpDown.get(),
        "udp_assocs" to S.udpAssocs.size,
        "uptime" to (System.currentTimeMillis() - S.startMs) / 1000.0,
    )

    private fun statsAll(): Map<String, Any?> {
        val d = statsBasic().toMutableMap()
        val now = System.currentTimeMillis()
        d["active_connections"] = S.activeConns.values.map { c ->
            val (u, dn) = c.snapshot()
            linkedMapOf<String, Any?>(
                "id" to c.id, "ip" to c.ip, "port" to c.port, "type" to c.type,
                "target" to c.target, "user" to c.user,
                "start_time" to c.startMs / 1000, "bytes_up" to u, "bytes_down" to dn,
                "duration" to (now - c.startMs) / 1000.0,
            )
        }
        d["upstream"] = linkedMapOf<String, Any?>(
            "proxies" to S.upstreams.map { it.spec },
            "current_index" to S.upstreamIndex.get(),
            "status" to S.upstreams.map { mapOf("addr" to it.spec, "alive" to (S.upstreamHealth["${it.host}:${it.port}"] ?: true)) },
        )
        d["udp_associations"] = S.udpAssocs.map { (k, v) ->
            k to mapOf("client_addr" to "${v.clientIp}:${v.clientPort}", "relay_port" to v.relayPort,
                       "active" to true, "last_activity" to v.lastActivity / 1000, "dest_count" to v.destCount)
        }.toMap()
        return d
    }

    private fun apiUsers() = mapOf("users" to S.cfg.users.map { u ->
        mapOf(
            "username" to u.username, "max_bandwidth_bps" to u.maxBandwidthBps,
            "max_connections" to u.maxConnections, "quota_bytes_per_month" to u.quotaBytes,
            "usage_bytes_this_month" to Usage.get(u.username),
        )
    })

    private fun apiTokens() = mapOf("tokens" to S.cfg.apiTokens.map { mapOf("name" to it.name, "created_at" to it.createdAt) })

    private fun apiNet() = mapOf(
        "allow_list" to S.cfg.allowList, "deny_list" to S.cfg.denyList,
        "upstream_proxies" to S.cfg.upstreamProxies,
    )

    private fun apiAudit(): Map<String, Any?> {
        S.auditLock.lock()
        try { return mapOf("events" to S.auditLog.reversed().map {
            mapOf("t" to it.t, "actor" to it.actor, "action" to it.action, "details" to it.details)
        }) } finally { S.auditLock.unlock() }
    }

    private fun apiReload(): Map<String, Any?> {
        S.reloadLock.lock()
        try { return mapOf("history" to S.reloadHistory.reversed().map {
            val m = linkedMapOf<String, Any?>(
                "t" to it.t, "source" to it.source, "success" to it.success,
                "allow_count" to it.allow, "deny_count" to it.deny,
                "upstream_count" to it.upstream, "user_count" to it.users,
            )
            if (it.error != null) m["error"] = it.error
            if (it.invalidCidrs.isNotEmpty()) m["invalid_cidrs"] = it.invalidCidrs
            m
        }) } finally { S.reloadLock.unlock() }
    }

    private fun doReload(s: Socket, actor: String) {
        val (ok, err) = Cfg.reload(actor)
        if (ok) { Audit.record(actor, "reload_config", "success"); respondJson(s, 200, mapOf("success" to true)) }
        else respondJson(s, 400, mapOf("error" to err))
    }

    private fun doKick(s: Socket, body: String, actor: String) {
        val j = Json.parse(body) ?: run { respondJson(s, 400, mapOf("error" to "bad json")); return }
        val id = j["id"]?.asStr() ?: run { respondJson(s, 400, mapOf("error" to "missing id")); return }
        val ci = Registry.kick(id) ?: run { respondJson(s, 404, mapOf("error" to "not found")); return }
        Audit.record(actor, "kick_connection", "id=$id ip=${ci.ip} target=${ci.target} user=${ci.user}")
        respondJson(s, 200, mapOf("success" to true, "id" to id))
    }

    private fun doUser(s: Socket, body: String, actor: String) {
        val j = Json.parse(body) ?: run { respondJson(s, 400, mapOf("error" to "bad json")); return }
        val uname = (j["username"]?.asStr() ?: "").trim()
        if (uname.isEmpty()) { respondJson(s, 400, mapOf("error" to "username required")); return }
        if (uname.length >= 64) { respondJson(s, 400, mapOf("error" to "username too long")); return }
        val pwd = j["password"]?.asStr() ?: ""
        if (pwd.isNotEmpty() && pwd.length < 4) { respondJson(s, 400, mapOf("error" to "password >= 4")); return }
        val bw = maxOf(0L, j["max_bandwidth_bps"]?.asLong() ?: 0)
        val mc = maxOf(0L, j["max_connections"]?.asLong() ?: 0)
        val q = maxOf(0L, j["quota_bytes_per_month"]?.asLong() ?: 0)

        val c = S.cfg
        val existing = c.users.find { it.username == uname }
        if (existing != null) {
            if (pwd.isNotEmpty()) existing.passwordHash = Hash.hashPassword(pwd)
            existing.maxBandwidthBps = bw; existing.maxConnections = mc; existing.quotaBytes = q
        } else {
            if (pwd.isEmpty()) { respondJson(s, 400, mapOf("error" to "password required")); return }
            c.users.add(UserCfg(uname, Hash.hashPassword(pwd), bw, mc, q))
            c.requireProxyAuth = true
        }
        Cfg.save(S.configPath, c)
        applyLiveBandwidthLimit(uname, bw)
        Audit.record(actor, "upsert_user", "username=$uname bw=$bw mc=$mc q=$q")
        respondJson(s, 200, mapOf("success" to true))
    }

    private fun doDelUser(s: Socket, body: String, actor: String) {
        val j = Json.parse(body) ?: return
        val uname = j["username"]?.asStr() ?: run { respondJson(s, 400, mapOf("error" to "missing")); return }
        val c = S.cfg
        if (!c.users.removeIf { it.username == uname }) { respondJson(s, 404, mapOf("error" to "not found")); return }
        Cfg.save(S.configPath, c)
        Audit.record(actor, "delete_user", "username=$uname")
        respondJson(s, 200, mapOf("success" to true))
    }

    private fun doToken(s: Socket, body: String, actor: String) {
        val j = Json.parse(body) ?: run { respondJson(s, 400, mapOf("error" to "bad json")); return }
        val name = (j["name"]?.asStr() ?: "").trim()
        if (name.isEmpty()) { respondJson(s, 400, mapOf("error" to "name required")); return }
        if (name.length >= 64) { respondJson(s, 400, mapOf("error" to "name too long")); return }
        val c = S.cfg
        if (c.apiTokens.any { it.name == name }) { respondJson(s, 409, mapOf("error" to "name exists")); return }
        val token = Hash.randomHex(32)
        c.apiTokens.add(TokenCfg(name, Hash.sha256Hex(token), System.currentTimeMillis() / 1000))
        Cfg.save(S.configPath, c)
        Audit.record(actor, "create_api_token", "name=$name")
        respondJson(s, 200, linkedMapOf("success" to true, "token" to token, "name" to name))
    }

    private fun doDelToken(s: Socket, body: String, actor: String) {
        val j = Json.parse(body) ?: return
        val name = j["name"]?.asStr() ?: run { respondJson(s, 400, mapOf("error" to "missing")); return }
        val c = S.cfg
        if (!c.apiTokens.removeIf { it.name == name }) { respondJson(s, 404, mapOf("error" to "not found")); return }
        Cfg.save(S.configPath, c)
        Audit.record(actor, "revoke_api_token", "name=$name")
        respondJson(s, 200, mapOf("success" to true))
    }

    private fun doNet(s: Socket, body: String, actor: String) {
        val j = Json.parse(body) ?: run { respondJson(s, 400, mapOf("error" to "bad json")); return }
        val c = S.cfg
        c.allowList.clear(); j["allow_list"]?.asArr()?.forEach { c.allowList.add(it.asStr() ?: "") }
        c.denyList.clear(); j["deny_list"]?.asArr()?.forEach { c.denyList.add(it.asStr() ?: "") }
        c.upstreamProxies.clear(); j["upstream_proxies"]?.asArr()?.forEach { c.upstreamProxies.add(it.asStr() ?: "") }
        Cfg.save(S.configPath, c)
        val (ok, err) = Cfg.reload(actor)
        if (!ok) { respondJson(s, 500, mapOf("error" to "reload failed: $err")); return }
        Audit.record(actor, "update_network_config",
            "${c.allowList.size} allow, ${c.denyList.size} deny, ${c.upstreamProxies.size} upstream")
        respondJson(s, 200, mapOf("success" to true))
    }

    private fun doChangePw(s: Socket, body: String, actor: String) {
        val j = Json.parse(body) ?: run { respondJson(s, 400, mapOf("error" to "bad json")); return }
        val cur = j["current_password"]?.asStr() ?: ""
        val nu = (j["new_username"]?.asStr() ?: "").trim()
        val np = j["new_password"]?.asStr() ?: ""
        val c = S.cfg
        if (!Hash.verify(cur, c.dashboardPasswordHash)) { respondJson(s, 403, mapOf("error" to "current wrong")); return }
        if (np.length < 8) { respondJson(s, 400, mapOf("error" to "new >= 8")); return }
        if (np == cur) { respondJson(s, 400, mapOf("error" to "same")); return }
        c.dashboardPasswordHash = Hash.hashPassword(np)
        if (nu.isNotEmpty()) c.dashboardUser = nu
        Cfg.save(S.configPath, c)
        Audit.record(actor, "change_dashboard_password", c.dashboardUser)
        respondJson(s, 200, linkedMapOf("success" to true, "username" to c.dashboardUser))
    }

    private fun exportConns(s: Socket, query: Map<String, String>) {
        val fmt = query["format"] ?: "json"
        val now = System.currentTimeMillis()
        val rows = S.activeConns.values.map { c ->
            val (u, dn) = c.snapshot()
            mapOf(
                "id" to c.id, "ip" to c.ip, "port" to c.port, "type" to c.type, "target" to c.target,
                "user" to c.user, "bytes_up" to u, "bytes_down" to dn,
                "duration" to (now - c.startMs) / 1000.0,
            )
        }
        if (fmt == "csv") {
            val sb = StringBuilder()
            sb.append("id,ip,port,type,target,user,bytes_up,bytes_down,duration_seconds\n")
            for (r in rows) {
                val t = (r["target"] as String).replace("\"", "\"\"")
                sb.append("${r["id"]},${r["ip"]},${r["port"]},${r["type"]},\"$t\",${r["user"]},${r["bytes_up"]},${r["bytes_down"]},${r["duration"]}\n")
            }
            respond(s, 200, "text/csv", sb.toString(), mapOf("Content-Disposition" to "attachment; filename=connections.csv"))
        } else {
            respondJson(s, 200, rows, mapOf("Content-Disposition" to "attachment; filename=connections.json"))
        }
    }

    private fun exportConfig(s: Socket, actor: String) {
        Audit.record(actor, "export_config_backup", "")
        val ts = java.time.LocalDateTime.now().let { "%04d%02d%02d_%02d%02d%02d".format(it.year, it.monthValue, it.dayOfMonth, it.hour, it.minute, it.second) }
        respond(s, 200, "application/json", S.cfg.toJson(),
            mapOf("Content-Disposition" to "attachment; filename=proxy_config_backup_$ts.json"))
    }

    private fun importConfig(s: Socket, body: String, actor: String) {
        val j = Json.parse(body) ?: run { respondJson(s, 400, mapOf("error" to "bad json")); return }
        val c = AppConfig.fromJson(j)
        if (c.dashboardUser.isEmpty() || c.dashboardPasswordHash.isEmpty()) {
            respondJson(s, 400, mapOf("error" to "missing dashboard_user/hash")); return
        }
        Cfg.save(S.configPath, c)
        val (ok, err) = Cfg.reload(actor)
        if (!ok) { respondJson(s, 500, mapOf("error" to "reload fail: $err")); return }
        Audit.record(actor, "import_config_backup", "${c.users.size} users, ${c.apiTokens.size} tokens")
        respondJson(s, 200, mapOf("success" to true))
    }

    private fun sse(s: Socket) {
        if (S.sseClients.size >= DASH_MAX_SSE) { respond(s, 503, "text/plain", "503 too many SSE"); return }
        val q = LinkedBlockingQueue<Sample>(8)
        S.sseClients.add(q)
        try {
            s.soTimeout = 0
            val out = s.getOutputStream()
            out.write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\nX-Accel-Buffering: no\r\n\r\n".toByteArray()); out.flush()
            S.histLock.lock()
            val histJson = try { Json.encode(S.hist.map { mapOf("t" to it.t, "up_bps" to it.upBps, "down_bps" to it.downBps, "active" to it.active, "udp_assocs" to it.udpAssocs) }) }
                          finally { S.histLock.unlock() }
            out.write("event: history\ndata: $histJson\n\n".toByteArray()); out.flush()

            var lastKa = System.currentTimeMillis()
            while (!S.shuttingDown) {
                val sample = q.poll(1, TimeUnit.SECONDS)
                if (sample != null) {
                    val m = mapOf("t" to sample.t, "up_bps" to sample.upBps, "down_bps" to sample.downBps,
                                  "active" to sample.active, "udp_assocs" to sample.udpAssocs)
                    out.write("event: sample\ndata: ${Json.encode(m)}\n\n".toByteArray()); out.flush()
                    lastKa = System.currentTimeMillis()
                } else if (System.currentTimeMillis() - lastKa >= 15_000) {
                    out.write(": keepalive\n\n".toByteArray()); out.flush()
                    lastKa = System.currentTimeMillis()
                }
            }
        } catch (_: Exception) {
        } finally {
            S.sseClients.remove(q)
            try { s.close() } catch (_: Exception) {}
        }
    }

    private fun metrics(): String {
        val sb = StringBuilder()
        fun m(n: String, h: String, t: String, v: Any) { sb.append("# HELP proxy_$n $h\n# TYPE proxy_$n $t\nproxy_$n $v\n") }
        m("connections_total", "Tổng kết nối nhận", "counter", S.statTotal.get())
        m("connections_current", "Kết nối mở", "gauge", S.statCurrent.get())
        m("connections_active", "Kết nối active", "gauge", S.activeConns.size)
        m("socks5_tcp_total", "SOCKS5 TCP", "counter", S.statS5Tcp.get())
        m("socks5_udp_total", "SOCKS5 UDP", "counter", S.statS5Udp.get())
        m("http_requests_total", "HTTP req", "counter", S.statHttp.get())
        m("bytes_up_total", "TCP up", "counter", S.statBytesUp.get())
        m("bytes_down_total", "TCP down", "counter", S.statBytesDown.get())
        m("udp_bytes_up_total", "UDP up", "counter", S.statUdpUp.get())
        m("udp_bytes_down_total", "UDP down", "counter", S.statUdpDown.get())
        m("udp_associations", "UDP assoc", "gauge", S.udpAssocs.size)
        m("auth_fail_total", "Auth fail", "counter", S.statAuthFail.get())
        m("uptime_seconds", "Uptime", "gauge", (System.currentTimeMillis() - S.startMs) / 1000)
        return sb.toString()
    }

    private fun respondJson(s: Socket, code: Int, obj: Any?, extra: Map<String, String> = emptyMap()) {
        respond(s, code, "application/json", Json.encode(obj), extra)
    }

    private fun respond(s: Socket, code: Int, ctype: String, body: String, extra: Map<String, String> = emptyMap()) {
        val status = when (code) {
            200 -> "OK"; 400 -> "Bad Request"; 401 -> "Unauthorized"; 403 -> "Forbidden"
            404 -> "Not Found"; 405 -> "Method Not Allowed"; 409 -> "Conflict"
            413 -> "Payload Too Large"; 429 -> "Too Many Requests"; 500 -> "Internal Server Error"
            502 -> "Bad Gateway"; 503 -> "Service Unavailable"; else -> "OK"
        }
        val bb = body.toByteArray(StandardCharsets.UTF_8)
        val sb = StringBuilder()
        sb.append("HTTP/1.1 $code $status\r\n")
        sb.append("Content-Type: $ctype\r\n")
        sb.append("Content-Length: ${bb.size}\r\n")
        sb.append("Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n")
        sb.append("Pragma: no-cache\r\nExpires: 0\r\nConnection: close\r\n")
        for ((k, v) in extra) sb.append("$k: $v\r\n")
        sb.append("\r\n")
        try {
            s.getOutputStream().write(sb.toString().toByteArray())
            s.getOutputStream().write(bb)
            s.getOutputStream().flush()
        } catch (_: Exception) {}
        try { s.close() } catch (_: Exception) {}
    }
}

// ============================================================================
// DASHBOARD HTML (compact)
// ============================================================================
val DASH_HTML = """
<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Proxy Dashboard</title>
<style>
body{background:#0f0f1a;color:#e0e0e0;font-family:system-ui,monospace;padding:20px;margin:0}
h1{color:#f0c27a;font-weight:300}h1 small{color:#999;font-size:.7em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0}
.box{background:#1a1a2e;padding:14px;border-radius:10px;border-left:4px solid #6c6c9a}
.lbl{font-size:.75rem;color:#999;text-transform:uppercase}
.val{font-size:1.5rem;font-weight:600;margin-top:4px}
.sec{background:#14141f;border:1px solid #2a2a3a;border-radius:12px;padding:20px;margin-top:20px}
h3{color:#b4b4d4;font-weight:400}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{text-align:left;padding:8px;background:#1e1e32;color:#999}
td{padding:8px;border-bottom:1px solid #28283a}
tr:hover td{background:#1a1a2e}
button{background:#2a2a3a;color:#e0e0e0;border:1px solid #3a3a52;padding:6px 12px;border-radius:6px;cursor:pointer}
button:hover{background:#33334a}
.status{font-size:.75rem;color:#86efac;margin-left:8px}
canvas{width:100%;height:200px}
</style></head><body>
<h1>⚡ Proxy Pro <small>$VERSION (Kotlin/JDK21)</small><span class="status" id="streamStatus">(connecting...)</span></h1>
<div class="grid" id="stats">Loading...</div>
<div class="sec"><h3>🔗 Active <span id="connCount"></span></h3><div id="conns">Loading...</div></div>
<div class="sec"><h3>📈 Traffic</h3><canvas id="trafficChart"></canvas></div>
<div class="sec"><h3>👤 Users</h3><div id="users">Loading...</div></div>
<div class="sec"><h3>🔑 Tokens</h3><div id="tokens">Loading...</div></div>
<div class="sec"><h3>📋 Audit</h3><div id="audit">Loading...</div></div>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<script>
let lastConns=[],chart=null;
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function fmt(b){if(!b)return '0 B';const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(1)+' '+u[i]}
function fmtT(s){if(!s)return '00:00:00';const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),x=Math.floor(s%60);return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(x).padStart(2,'0')}
function initChart(){if(typeof Chart==='undefined')return;const c=document.getElementById('trafficChart').getContext('2d');chart=new Chart(c,{type:'line',data:{labels:[],datasets:[{label:'Up B/s',data:[],borderColor:'#ea580c',tension:.3,pointRadius:0},{label:'Down B/s',data:[],borderColor:'#0891b2',tension:.3,pointRadius:0}]},options:{animation:false,responsive:true,maintainAspectRatio:false,scales:{x:{ticks:{color:'#b4b4d4'},grid:{color:'#28283a'}},y:{ticks:{color:'#b4b4d4',callback:v=>fmt(v)+'/s'},grid:{color:'#28283a'}}},plugins:{legend:{labels:{color:'#b4b4d4'}}}}});}
function pushS(s){if(!chart)return;chart.data.labels.push(new Date(s.t*1000).toLocaleTimeString());chart.data.datasets[0].data.push(s.up_bps);chart.data.datasets[1].data.push(s.down_bps);if(chart.data.labels.length>150){chart.data.labels.shift();chart.data.datasets[0].data.shift();chart.data.datasets[1].data.shift();}chart.update('none');}
function connectStream(){const st=document.getElementById('streamStatus');const es=new EventSource('/api/stream');es.addEventListener('history',e=>{try{JSON.parse(e.data).forEach(pushS);st.textContent='(live)';st.style.color='#86efac';}catch(x){}});es.addEventListener('sample',e=>{try{pushS(JSON.parse(e.data));}catch(x){}});es.onerror=()=>{st.textContent='(reconnecting)';st.style.color='#fca5a5';};}
async function ref(){try{const d=await(await fetch('/api/all?_='+Date.now(),{cache:'no-store'})).json();document.getElementById('stats').innerHTML=[['Total',d.total],['Active',d.active],['S5 TCP',d.socks5_tcp],['S5 UDP',d.socks5_udp],['HTTP',d.http],['UDP Assoc',d.udp_assocs],['Up',fmt(d.bytes_up)],['Down',fmt(d.bytes_down)],['Uptime',fmtT(d.uptime)]].map(x=>'<div class="box"><div class="lbl">'+x[0]+'</div><div class="val">'+x[1]+'</div></div>').join('');lastConns=d.active_connections||[];renderConns();}catch(e){}}
function renderConns(){const c=lastConns;document.getElementById('connCount').textContent='('+c.length+')';if(!c.length){document.getElementById('conns').innerHTML='<p style="color:#999">None</p>';return;}
document.getElementById('conns').innerHTML='<table><thead><tr><th>IP</th><th>Type</th><th>Target</th><th>User</th><th>Up</th><th>Down</th><th>Time</th><th>Act</th></tr></thead><tbody>'+
c.map(x=>'<tr><td>'+esc(x.ip)+'</td><td>'+esc(x.type)+'</td><td>'+esc(x.target)+'</td><td>'+esc(x.user)+'</td><td>'+fmt(x.bytes_up)+'</td><td>'+fmt(x.bytes_down)+'</td><td>'+fmtT(x.duration)+'</td><td><button onclick="kick(\''+esc(x.id)+'\')">Kick</button></td></tr>').join('')+'</tbody></table>';}
async function kick(id){await fetch('/api/kick',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});ref();}
async function refU(){try{const d=await(await fetch('/api/users')).json();document.getElementById('users').innerHTML=!d.users.length?'<p style="color:#999">None</p>':'<table><thead><tr><th>User</th><th>BW</th><th>Conns</th><th>Quota</th><th>Used</th></tr></thead><tbody>'+d.users.map(u=>'<tr><td>'+esc(u.username)+'</td><td>'+(u.max_bandwidth_bps>0?fmt(u.max_bandwidth_bps)+'/s':'∞')+'</td><td>'+(u.max_connections||'∞')+'</td><td>'+(u.quota_bytes_per_month>0?fmt(u.quota_bytes_per_month):'∞')+'</td><td>'+fmt(u.usage_bytes_this_month)+'</td></tr>').join('')+'</tbody></table>';}catch(e){}}
async function refT(){try{const d=await(await fetch('/api/tokens')).json();document.getElementById('tokens').innerHTML=!d.tokens.length?'<p style="color:#999">None</p>':'<table><thead><tr><th>Name</th><th>Created</th></tr></thead><tbody>'+d.tokens.map(t=>'<tr><td>'+esc(t.name)+'</td><td>'+new Date(t.created_at*1000).toLocaleString()+'</td></tr>').join('')+'</tbody></table>';}catch(e){}}
async function refA(){try{const d=await(await fetch('/api/audit-log')).json();document.getElementById('audit').innerHTML=!d.events.length?'<p style="color:#999">None</p>':'<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>'+d.events.map(e=>'<tr><td>'+new Date(e.t*1000).toLocaleString()+'</td><td>'+esc(e.actor)+'</td><td>'+esc(e.action)+'</td><td>'+esc(e.details)+'</td></tr>').join('')+'</tbody></table>';}catch(e){}}
document.addEventListener('DOMContentLoaded',()=>{initChart();connectStream();});
ref();refU();refT();refA();setInterval(ref,3000);setInterval(refU,15000);setInterval(refT,30000);setInterval(refA,15000);
</script></body></html>
"""

// ============================================================================
// MAIN
// ============================================================================

// ============================================================================
// LOG ROTATION (Go: rotatingWriter)
// ============================================================================
class RotatingWriter(val path: String, val maxSizeMB: Int, val maxBackups: Int) {
    private var fos: java.io.FileOutputStream
    private var size: Long
    private val lock = Any()

    init {
        val f = File(path)
        fos = java.io.FileOutputStream(f, true)
        size = f.length()
    }

    fun write(s: String) {
        synchronized(lock) {
            try {
                val bytes = s.toByteArray(StandardCharsets.UTF_8)
                if (maxSizeMB > 0 && size + bytes.size > maxSizeMB.toLong() * 1024 * 1024) rotate()
                fos.write(bytes); fos.flush()
                size += bytes.size
            } catch (_: Exception) {}
        }
    }

    private fun rotate() {
        try { fos.close() } catch (_: Exception) {}
        for (i in (maxBackups - 1) downTo 1) {
            val old = File("$path.$i")
            if (old.exists()) old.renameTo(File("$path.${i + 1}"))
        }
        if (maxBackups > 0) File(path).renameTo(File("$path.1"))
        fos = java.io.FileOutputStream(File(path), false)
        size = 0
    }
}

fun setupLogging(path: String, maxMB: Int, maxBackups: Int) {
    if (path.isEmpty()) return
    val rw = RotatingWriter(path, maxMB, maxBackups)
    val tee = PrintStream(object : OutputStream() {
        override fun write(b: Int) {
            System.out.write(b)
            rw.write(b.toChar().toString())
        }
        override fun write(b: ByteArray, off: Int, len: Int) {
            System.out.write(b, off, len)
            rw.write(String(b, off, len, StandardCharsets.UTF_8))
        }
    }, true)
    System.setOut(tee)
    System.setErr(tee)
    println("[INFO] Logging to $path (max ${maxMB}MB, ${maxBackups} backups)")
}

// ============================================================================
// TLS LISTENER (Go: tls.NewListener) — convert PEM → PKCS12 via openssl
// ============================================================================
fun loadTlsContext(certFile: String, keyFile: String): javax.net.ssl.SSLContext? {
    return try {
        val tmpP12 = File.createTempFile("proxy-tls-", ".p12")
        tmpP12.deleteOnExit(); tmpP12.delete()
        val pass = "proxy-" + System.nanoTime()
        val proc = ProcessBuilder(
            "openssl", "pkcs12", "-export",
            "-in", certFile, "-inkey", keyFile,
            "-out", tmpP12.absolutePath, "-passout", "pass:$pass"
        ).redirectErrorStream(true).start()
        proc.inputStream.readBytes()
        if (proc.waitFor() != 0 || !tmpP12.exists()) {
            System.err.println("[WARN] openssl không convert được PEM → PKCS12")
            return null
        }
        val ks = java.security.KeyStore.getInstance("PKCS12")
        java.io.FileInputStream(tmpP12).use { ks.load(it, pass.toCharArray()) }
        tmpP12.delete()
        val kmf = javax.net.ssl.KeyManagerFactory.getInstance("SunX509")
        kmf.init(ks, pass.toCharArray())
        val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)
        println("[INFO] TLS loaded từ $certFile + $keyFile")
        ctx
    } catch (e: Exception) {
        System.err.println("[WARN] TLS load fail: ${e.message}")
        null
    }
}

// ============================================================================
// SIGHUP + FILE WATCH (Go: signal.Notify(hupCh, syscall.SIGHUP))
// ============================================================================
fun installHupHandler(onHup: () -> Unit) {
    try {
        val sigCls = Class.forName("sun.misc.Signal")
        val hdlCls = Class.forName("sun.misc.SignalHandler")
        val hup = sigCls.getConstructor(String::class.java).newInstance("HUP")
        val proxy = java.lang.reflect.Proxy.newProxyInstance(
            hdlCls.classLoader, arrayOf(hdlCls)
        ) { _, method, _ ->
            if (method.name == "handle") onHup()
            null
        }
        sigCls.getMethod("handle", sigCls, hdlCls).invoke(null, hup, proxy)
        println("[INFO] SIGHUP handler installed (kill -HUP <pid>)")
    } catch (_: Exception) {
        println("[INFO] SIGHUP fallback → file-watch (sửa config = reload)")
    }
}

fun watchConfigFile() {
    var lastMtime = File(S.configPath).lastModified()
    while (!S.shuttingDown) {
        try { Thread.sleep(2000) } catch (_: InterruptedException) { return }
        val f = File(S.configPath)
        if (f.exists()) {
            val mt = f.lastModified()
            if (mt != lastMtime && lastMtime != 0L) {
                lastMtime = mt
                println("[INFO] Config file changed → reload")
                Cfg.reload("file-watch")
            }
        }
    }
}

// ============================================================================
// FORCE KILL PORT (Go: -force-kill flag)
// ============================================================================
fun forceKillPort(port: Int) {
    for (cmd in listOf(
        arrayOf("fuser", "-k", "$port/tcp"),
        arrayOf("sh", "-c", "lsof -ti:$port | xargs -r kill -9 2>/dev/null")
    )) {
        try {
            val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
            p.inputStream.readBytes()
            p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)
            Thread.sleep(300)
            return
        } catch (_: Exception) {}
    }
}

// ============================================================================
// LIVE BANDWIDTH RAMP (Go: applyLiveBandwidthLimit + rampBandwidthLimit)
// ============================================================================
fun applyLiveBandwidthLimit(username: String, newLimit: Long) {
    if (username.isEmpty()) return
    val targets = S.activeConns.values.filter { it.user == username }
    if (targets.isEmpty()) return
    for (ci in targets) {
        val cur = ci.rateBps
        if (cur > 0 && newLimit > 0 && cur != newLimit) {
            thread(isDaemon = true, name = "ramp-${ci.id}") {
                for (i in 1..10) {
                    try { Thread.sleep(500) } catch (_: InterruptedException) { return@thread }
                    ci.rateBps = cur + (newLimit - cur) * i / 10
                }
            }
        } else {
            ci.rateBps = newLimit
        }
    }
    println("[INFO] BW=${newLimit} B/s → ${targets.size} conn user '$username'")
}

fun fmtBytes(b: Long): String {
    if (b < 1024) return "$b B"
    var v = b.toDouble()
    val u = listOf("B", "KiB", "MiB", "GiB", "TiB")
    var i = 0
    while (v >= 1024 && i < u.size - 1) { v /= 1024; i++ }
    return "%.1f %s".format(v, u[i])
}

fun printHelp() {
    println("""
Usage: proxy [-l addr] [-p port] [-u user] [-P pass] [--no-udp]
             [--config file] [--usage-file file]
             [--dashboard-port port] [--dashboard-bind addr]
             [--dashboard-user user] [--dashboard-pass pass]
             [--allow cidr,...] [--deny cidr,...]
             [--upstream [socks5://|http://]host:port,...]
             [--upstream-fallback] [--allow-private]
             [--cert FILE --key FILE]          TLS listener (PEM)
             [--log-file FILE]                 ghi log + rotate
             [--log-max-size-mb N]             (mặc định 20)
             [--log-max-backups N]             (mặc định 5)
             [--force-kill]                    kill process đang giữ port
             [-h]

Defaults: -l 0.0.0.0 -p 1080 --dashboard-bind 127.0.0.1 --dashboard-port 8081
Config:   proxy_config.json (lần đầu tạo mới, in password 1 lần)
Reload:   SIGHUP (kill -HUP PID), file-watch, hoặc POST /api/reload
""")
}

fun main(args: Array<String>) {
    var listen = "0.0.0.0"
    var port = 1080
    var username = ""
    var password = ""
    var noUdp = false
    var dashboardPort = 8081
    var dashboardBind = "127.0.0.1"
    var configPath = "proxy_config.json"
    var usagePath = "proxy_usage.json"
    var initUser = "admin"
    var initPass = ""
    var seedAllow = ""; var seedDeny = ""; var seedUpstream = ""
    var certFile = ""; var keyFile = ""
    var logPath = ""; var logMaxMB = 20; var logMaxBackups = 5
    var forceKill = false

    var i = 0
    while (i < args.size) {
        val a = args[i]
        fun next(): String { i++; return if (i < args.size) args[i] else "" }
        when (a) {
            "-l", "--listen" -> listen = next()
            "-p", "--port" -> port = next().toIntOrNull() ?: port
            "-u", "--username" -> username = next()
            "-P", "--password" -> password = next()
            "--no-udp" -> noUdp = true
            "--allow-private" -> S.allowPrivate = true
            "--upstream-fallback" -> S.upstreamFallback = true
            "--upstream" -> seedUpstream = next()
            "--allow" -> seedAllow = next()
            "--deny" -> seedDeny = next()
            "--config" -> configPath = next()
            "--usage-file" -> usagePath = next()
            "--dashboard-port" -> dashboardPort = next().toIntOrNull() ?: dashboardPort
            "--dashboard-bind" -> dashboardBind = next()
            "--dashboard-user" -> initUser = next()
            "--dashboard-pass" -> initPass = next()
            "--cert" -> certFile = next()
            "--key" -> keyFile = next()
            "--log-file" -> logPath = next()
            "--log-max-size-mb" -> logMaxMB = next().toIntOrNull() ?: 20
            "--log-max-backups" -> logMaxBackups = next().toIntOrNull() ?: 5
            "--force-kill" -> forceKill = true
            "-h", "--help" -> { printHelp(); return }
            else -> { System.err.println("Unknown: $a"); printHelp(); return }
        }
        i++
    }

    S.configPath = configPath
    S.usagePath = usagePath
    S.cliUser = username
    S.cliPass = password
    S.cliAuthRequired = username.isNotEmpty() && password.isNotEmpty()
    S.enableUdp = !noUdp

    Usage.load(usagePath)

    val (cfg, wasCreated) = try {
        Cfg.loadOrInit(configPath, initUser, initPass)
    } catch (e: Exception) {
        System.err.println("[FATAL] ${e.message}"); exitProcess(1)
    }
    S.cfg = cfg

    if (wasCreated) {
        if (seedAllow.isNotEmpty()) cfg.allowList.addAll(seedAllow.split(',').map { it.trim() }.filter { it.isNotEmpty() })
        if (seedDeny.isNotEmpty()) cfg.denyList.addAll(seedDeny.split(',').map { it.trim() }.filter { it.isNotEmpty() })
        if (seedUpstream.isNotEmpty()) cfg.upstreamProxies.addAll(seedUpstream.split(',').map { it.trim() }.filter { it.isNotEmpty() })
        Cfg.save(configPath, cfg)
    }

    // init CIDR + upstream
    val allow = mutableListOf<Cidr>(); val deny = mutableListOf<Cidr>()
    for (s in cfg.allowList) IP.parseCidr(s.trim())?.let { allow.add(it) }
    for (s in cfg.denyList) IP.parseCidr(s.trim())?.let { deny.add(it) }
    S.allowCidrs = allow
    S.denyCidrs = deny
    for (spec in cfg.upstreamProxies) Cfg.parseUpstream(spec)?.let { S.upstreams.add(it) }

    if (cfg.dashboardUser == "admin" && Hash.verify("admin", cfg.dashboardPasswordHash)) {
        System.err.println("[WARN] Dashboard đang dùng admin/admin — đổi ngay!")
    }

    // Shutdown hook
    Runtime.getRuntime().addShutdownHook(Thread {
        if (!S.shuttingDown) {
            S.shuttingDown = true
            Thread.sleep(500)
            Usage.save(usagePath)
        }
    })

    if (logPath.isNotEmpty()) setupLogging(logPath, logMaxMB, logMaxBackups)
    if (forceKill) forceKillPort(port)
    val sslCtx = if (certFile.isNotEmpty() && keyFile.isNotEmpty())
                    loadTlsContext(certFile, keyFile) else null

    println("[INFO] JDK ${Runtime.version()} | virtual threads: ${if (USE_VIRTUAL) "enabled" else "disabled"}")

    // Background threads
    thread(isDaemon = true, name = "sampler") { Sampler.loop() }
    thread(isDaemon = true, name = "usage-save") { UsageSaver.loop() }
    thread(isDaemon = true, name = "upstream-health") { UpHealth.loop() }
    thread(isDaemon = true, name = "quota-enforce") { QuotaEnforce.loop() }

    // SIGHUP / file-watch hot-reload
    installHupHandler { thread(isDaemon = true) { Cfg.reload("SIGHUP") } }
    thread(isDaemon = true, name = "cfg-watch") { watchConfigFile() }

    // Listeners
    thread(isDaemon = true, name = "dashboard") { Dashboard.run(dashboardBind, dashboardPort) }
    Listener.run(listen, port, sslCtx)
}


// ============================================================================
// BACKGROUND WORKERS (may be missing due to truncation)
// ============================================================================
object UpHealth {
    fun loop() {
        while (!S.shuttingDown) {
            try { Thread.sleep(15_000) } catch (_: InterruptedException) { return }
            for (u in S.upstreams) {
                val key = "${u.host}:${u.port}"
                try {
                    val s = java.net.Socket()
                    s.connect(java.net.InetSocketAddress(u.host, u.port), 3000)
                    s.close()
                    S.upstreamHealth[key] = true
                } catch (_: Exception) {
                    S.upstreamHealth[key] = false
                }
            }
        }
    }
}

object QuotaEnforce {
    fun loop() {
        while (!S.shuttingDown) {
            try { Thread.sleep(10_000) } catch (_: InterruptedException) { return }
            val users = S.cfg.users
            for (u in users) {
                if (u.quotaBytes <= 0) continue
                if (Usage.get(u.username) < u.quotaBytes) continue
                val toKick = S.activeConns.values.filter { it.user == u.username }
                for (c in toKick) try { c.socket?.close() } catch (_: Exception) {}
                if (toKick.isNotEmpty())
                    System.err.println("[WARN] Ngắt ${toKick.size} conn của ${u.username} do vượt quota")
            }
        }
    }
}

object Sampler {
    fun loop() {
        var lastUp = 0L
        var lastDown = 0L
        var first = true
        while (!S.shuttingDown) {
            try { Thread.sleep(2000) } catch (_: InterruptedException) { return }
            val up = S.statBytesUp.get()
            val down = S.statBytesDown.get()
            val upBps = if (first) 0L else (up - lastUp) / 2
            val downBps = if (first) 0L else (down - lastDown) / 2
            lastUp = up
            lastDown = down
            first = false
            val sample = Sample(System.currentTimeMillis() / 1000, upBps, downBps,
                                S.activeConns.size, S.udpAssocs.size)
            println("[STATS] Active:${S.activeConns.size} | UDP:${S.udpAssocs.size} | " +
                    "Up:${fmtBytes(up)} Down:${fmtBytes(down)} | " +
                    "${upBps} B/s ↑ ${downBps} B/s ↓")
            S.histLock.lock()
            try {
                S.hist.addLast(sample)
                while (S.hist.size > HISTORY_MAX) S.hist.removeFirst()
            } finally { S.histLock.unlock() }
            for (q in S.sseClients) try { q.offer(sample) } catch (_: Exception) {}
        }
    }
}

object UsageSaver {
    fun loop() {
        while (!S.shuttingDown) {
            try { Thread.sleep(30_000) } catch (_: InterruptedException) { return }
            Usage.save(S.usagePath)
        }
    }
}

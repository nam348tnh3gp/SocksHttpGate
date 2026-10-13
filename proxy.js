#!/usr/bin/env node
'use strict';

const net = require('net');
const tls = require('tls');
const dgram = require('dgram');
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const dns = require('dns');
const { URL } = require('url');

// ======================== CẤU HÌNH ========================
const MAX_CONNECTIONS = 4000;
const CONNECTION_TIMEOUT = 25_000;
const IDLE_TIMEOUT = 180_000;
const UDP_IDLE_TIMEOUT = 120_000;
const UDP_BUFFER_SIZE = 65535;
const HANDSHAKE_TIMEOUT = 30_000;
const MAX_HEADER_LINES = 100;
const MAX_LINE_BYTES = 8192;
const AUTH_FAIL_THRESHOLD = 5;
const AUTH_FAIL_WINDOW = 5 * 60 * 1000;
const AUTH_BLOCK_DURATION = 15 * 60 * 1000;
const DASHBOARD_AUTH_FAIL_THRESHOLD = 30;
const HASH_ITERATIONS = 200000;
const AUDIT_LOG_MAX = 200;
const RELOAD_HISTORY_MAX = 30;
const HISTORY_MAX_SAMPLES = 300;
const BANDWIDTH_RAMP_STEPS = 10;
const BANDWIDTH_RAMP_INTERVAL_MS = 500;
const PW_CACHE_TTL = 5 * 60 * 1000;
const UPSTREAM_HEALTH_CHECK_INTERVAL_MS = 15_000;
const UPSTREAM_HEALTH_CHECK_TIMEOUT_MS = 3_000;
const STATS_INTERVAL_MS = 2000;

// ======================== CLI ========================
const argv = process.argv.slice(2);
function getArg(names, def) {
  for (let i = 0; i < argv.length; i++) {
    for (const n of names) {
      if (argv[i] === n) return argv[i + 1];
      if (argv[i].startsWith(n + '=')) return argv[i].slice(n.length + 1);
    }
  }
  return def;
}
function hasFlag(names) { return argv.some(a => names.includes(a)); }

const cfgFlags = {
  listenAddr: getArg(['-l'], '0.0.0.0'),
  port: parseInt(getArg(['-p'], '1080'), 10),
  username: getArg(['-u'], ''),
  password: getArg(['-P'], ''),
  forceKill: hasFlag(['-force-kill']),
  noUDP: hasFlag(['-no-udp']),
  upstreamStr: getArg(['-upstream'], ''),
  certFile: getArg(['-cert'], ''),
  keyFile: getArg(['-key'], ''),
  dashboardPort: parseInt(getArg(['-dashboard-port'], '8081'), 10),
  dashboardBind: getArg(['-dashboard-bind'], '127.0.0.1'),
  configPath: getArg(['-config'], 'proxy_config.json'),
  initDashUser: getArg(['-dashboard-user'], 'admin'),
  initDashPass: getArg(['-dashboard-pass'], ''),
  allowStr: getArg(['-allow'], ''),
  denyStr: getArg(['-deny'], ''),
  usagePath: getArg(['-usage-file'], 'proxy_usage.json'),
  logFilePath: getArg(['-log-file'], ''),
  logMaxSizeMB: parseInt(getArg(['-log-max-size-mb'], '20'), 10),
  logMaxBackups: parseInt(getArg(['-log-max-backups'], '5'), 10),
};

// ======================== LOG ========================
const _err = console.error.bind(console);
function log(...a) {
  const line = `[${new Date().toISOString()}] ` + a.map(x => typeof x === 'string' ? x : (x instanceof Error ? x.message : String(x))).join(' ') + '\n';
  try { process.stdout.write(line); } catch {}
  if (logRotator) { try { logRotator.write(Buffer.from(line)); } catch {} }
}

class RotatingWriter {
  constructor(path, maxSizeMB, maxBackups) {
    this.path = path;
    this.maxSizeBytes = maxSizeMB * 1024 * 1024;
    this.maxBackups = maxBackups;
    this.fd = fs.openSync(path, 'a');
    try { this.size = fs.fstatSync(this.fd).size; } catch { this.size = 0; }
  }
  write(buf) {
    if (this.maxSizeBytes > 0 && this.size + buf.length > this.maxSizeBytes) this._rotate();
    try { fs.writeSync(this.fd, buf); this.size += buf.length; } catch {}
  }
  _rotate() {
    try { fs.closeSync(this.fd); } catch {}
    for (let i = this.maxBackups - 1; i >= 1; i--) {
      try { if (fs.existsSync(`${this.path}.${i}`)) fs.renameSync(`${this.path}.${i}`, `${this.path}.${i + 1}`); } catch {}
    }
    if (this.maxBackups > 0) { try { fs.renameSync(this.path, this.path + '.1'); } catch {} }
    this.fd = fs.openSync(this.path, 'w');
    this.size = 0;
  }
}

let logRotator = null;
function setupLogFile() {
  if (!cfgFlags.logFilePath) return;
  try {
    logRotator = new RotatingWriter(cfgFlags.logFilePath, cfgFlags.logMaxSizeMB, cfgFlags.logMaxBackups);
    log(`[INFO] Logging ra file ${cfgFlags.logFilePath} (max ${cfgFlags.logMaxSizeMB}MB, giữ ${cfgFlags.logMaxBackups} bản cũ)`);
  } catch (e) { _err(`[FATAL] Không mở được log file: ${e.message}`); process.exit(1); }
}

// ======================== BUFFERED READER ========================
class BufReader {
  constructor(socket, initial) {
    this.socket = socket;
    this.buf = initial || Buffer.alloc(0);
    this.eof = false;
    this.err = null;
    this.pending = [];
    this._onData = (c) => { this.buf = Buffer.concat([this.buf, c]); this._pump(); };
    this._onEnd = () => { this.eof = true; this._pump(); };
    this._onErr = (e) => { this.err = e; this._pump(); };
    socket.on('data', this._onData);
    socket.on('end', this._onEnd);
    socket.on('error', this._onErr);
  }
  readN(n) {
    if (this.buf.length >= n) {
      const r = this.buf.subarray(0, n);
      this.buf = this.buf.subarray(n);
      return Promise.resolve(r);
    }
    return new Promise((resolve, reject) => {
      this.pending.push({ type: 'n', n, resolve, reject });
      this._pump();
    });
  }
  readLine(max) {
    return new Promise((resolve, reject) => {
      this.pending.push({ type: 'line', max, resolve, reject });
      this._pump();
    });
  }
  // ★ Đặt lại byte vừa đọc trở về đầu buffer (giống io.MultiReader trong Go).
  unread(chunk) {
    if (!chunk || !chunk.length) return;
    this.buf = Buffer.concat([chunk, this.buf]);
  }
  _pump() {
    while (this.pending.length) {
      const req = this.pending[0];
      if (req.type === 'n') {
        if (this.buf.length >= req.n) {
          const r = this.buf.subarray(0, req.n);
          this.buf = this.buf.subarray(req.n);
          this.pending.shift();
          req.resolve(r);
          continue;
        }
        if (this.err) { this.pending.shift(); req.reject(this.err); continue; }
        if (this.eof) { this.pending.shift(); req.reject(new Error('EOF')); continue; }
        break;
      }
      if (req.type === 'line') {
        const idx = this.buf.indexOf(0x0a);
        if (idx >= 0) {
          let line = this.buf.subarray(0, idx);
          this.buf = this.buf.subarray(idx + 1);
          if (line.length && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
          this.pending.shift();
          req.resolve(line.toString('utf8'));
          continue;
        }
        if (this.buf.length > req.max) { this.pending.shift(); req.reject(new Error('line too long')); continue; }
        if (this.err) { this.pending.shift(); req.reject(this.err); continue; }
        if (this.eof) { this.pending.shift(); req.reject(new Error('EOF')); continue; }
        break;
      }
    }
  }
  detach() {
    this.socket.removeListener('data', this._onData);
    this.socket.removeListener('end', this._onEnd);
    this.socket.removeListener('error', this._onErr);
    const b = this.buf; this.buf = Buffer.alloc(0);
    return b;
  }
}

// ======================== PASSWORD HASH ========================
function pbkdf2SHA256(password, salt, iterations) {
  let digest = crypto.createHash('sha256').update(Buffer.concat([salt, Buffer.from(password)])).digest();
  for (let i = 1; i < iterations; i++) digest = crypto.createHash('sha256').update(digest).digest();
  return digest;
}
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const digest = pbkdf2SHA256(password, salt, HASH_ITERATIONS);
  return `${HASH_ITERATIONS}:${salt.toString('hex')}:${digest.toString('hex')}`;
}
function verifyPassword(password, stored) {
  const parts = String(stored || '').split(':');
  if (parts.length !== 3) return false;
  const iterations = parseInt(parts[0], 10);
  if (!iterations || iterations <= 0) return false;
  let salt, want;
  try { salt = Buffer.from(parts[1], 'hex'); want = Buffer.from(parts[2], 'hex'); }
  catch { return false; }
  const got = pbkdf2SHA256(password, salt, iterations);
  if (got.length !== want.length) return false;
  try { return crypto.timingSafeEqual(got, want); } catch { return false; }
}

const pwCache = new Map();
function verifyPasswordCached(password, stored) {
  const key = crypto.createHash('sha256').update(stored + '\x00' + password).digest('hex');
  const now = Date.now();
  const exp = pwCache.get(key);
  if (exp && now < exp) return true;
  if (!verifyPassword(password, stored)) return false;
  if (pwCache.size >= 1024) {
    for (const [k, v] of pwCache) if (now >= v) pwCache.delete(k);
    if (pwCache.size >= 1024) pwCache.clear();
  }
  pwCache.set(key, now + PW_CACHE_TTL);
  return true;
}

// ======================== API TOKEN ========================
function generateAPIToken() { return crypto.randomBytes(32).toString('hex'); }
function hashAPIToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function subtleCompare(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ba, bb); } catch { return false; }
}
function checkAPIToken(token) {
  if (!token) return [null, false];
  const h = hashAPIToken(token);
  for (const t of (appConfig.APITokens || [])) {
    if (subtleCompare(t.token_hash || '', h)) return [t.name, true];
  }
  return [null, false];
}

// ======================== SSRF ========================
function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(x => isNaN(x) || x < 0 || x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
function cidrToObj(cidr) {
  const [ip, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  if (ip.includes('.')) {
    const n = ipv4ToInt(ip);
    if (n === null || isNaN(bits)) return null;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return { kind: 'v4', net: (n & mask) >>> 0, mask };
  }
  return { kind: 'v6', ip: ip.toLowerCase(), bits };
}
function ipInCidr(ip, c) {
  if (c.kind === 'v4') {
    if (ip.includes(':')) {
      const m = ip.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/i);
      if (!m) return false;
      ip = m[1];
    }
    const n = ipv4ToInt(ip);
    if (n === null) return false;
    return ((n & c.mask) >>> 0) === c.net;
  }
  const a = ip.toLowerCase();
  const parts = c.ip.split(':').slice(0, Math.ceil(c.bits / 16));
  return a.startsWith(parts.join(':'));
}
const extraBlockedNets = ['0.0.0.0/8', '100.64.0.0/10', '192.0.0.0/24', '198.18.0.0/15']
  .map(cidrToObj).filter(Boolean);

function isBlockedIP(ip) {
  if (!ip) return true;
  for (const n of extraBlockedNets) if (ipInCidr(ip, n)) return true;
  if (ip === '::1' || ip.startsWith('127.')) return true;
  if (ip === '::' || ip === '0.0.0.0') return true;
  if (ip.startsWith('169.254.')) return true;
  if (ip === '169.254.169.254') return true;
  if (ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('ff')) return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m) { const n = parseInt(m[1], 10); if (n >= 16 && n <= 31) return true; }
  return false;
}
async function resolveAllAndCheck(host) {
  if (net.isIP(host)) {
    if (isBlockedIP(host)) throw new Error(`target IP ${host} bị chặn (địa chỉ nội bộ)`);
    return [host];
  }
  let addrs;
  try {
    addrs = await new Promise((resolve, reject) => {
      dns.lookup(host, { all: true }, (err, list) => err ? reject(err) : resolve(list || []));
    });
  } catch { throw new Error(`không phân giải được host ${host}`); }
  if (!addrs.length) throw new Error(`không phân giải được host ${host}`);
  for (const a of addrs) if (isBlockedIP(a.address)) throw new Error(`target host ${host} phân giải ra IP nội bộ (${a.address}), bị chặn`);
  return addrs.map(a => a.address);
}
async function resolveAndCheck(host) { return (await resolveAllAndCheck(host))[0]; }
async function dialChecked(host, portNum) {
  const ips = await resolveAllAndCheck(host);
  let lastErr;
  for (const ip of ips) {
    try {
      return await new Promise((resolve, reject) => {
        const s = net.createConnection({ host: ip, port: portNum, timeout: CONNECTION_TIMEOUT }, () => resolve(s));
        s.once('error', reject);
        s.once('timeout', () => { s.destroy(); reject(new Error('timeout')); });
      });
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('dial failed');
}

// ======================== GLOBAL STATE ========================
const activeConns = new Map();
const udpAssocs = new Map();
let upstreamProxies = [];
let upstreamIndex = 0;
let dashboardUser = 'admin';
let dashboardPassHash = '';
let appConfig = { DashboardUser: '', DashboardPasswordHash: '', Users: [], AllowList: [], DenyList: [], UpstreamProxies: [], APITokens: [], RequireProxyAuth: false };
let allowedCIDRs = [];
let deniedCIDRs = [];
let shuttingDown = false;

const stats = {
  StartTime: Date.now(),
  Total: 0, Current: 0, Socks5TCP: 0, Socks5UDP: 0, HTTP: 0, AuthFail: 0,
  BytesUp: 0, BytesDown: 0, UDPUp: 0, UDPDown: 0,
};

const failCounts = new Map(), failLastFail = new Map(), blockedUntil = new Map();
const usage = new Map();
const statHistory = [];
const sseClients = new Set();
const auditLog = [];
const reloadHistory = [];

let connIdCounter = 0;
function nextConnID() { return 'c' + (++connIdCounter); }

// ======================== AUTH FAIL / IP LISTS ========================
function recordAuthFail(ip, threshold) {
  const now = Date.now();
  const last = failLastFail.get(ip);
  if (last && now - last > AUTH_FAIL_WINDOW) failCounts.set(ip, 0);
  failLastFail.set(ip, now);
  const c = (failCounts.get(ip) || 0) + 1;
  failCounts.set(ip, c);
  if (c >= threshold) {
    blockedUntil.set(ip, now + AUTH_BLOCK_DURATION);
    log(`[WARN] IP ${ip} bị chặn ${AUTH_BLOCK_DURATION / 1000}s do auth fail quá ${threshold} lần`);
    failCounts.set(ip, 0);
  }
}
function resetAuthFail(ip) { failCounts.delete(ip); failLastFail.delete(ip); blockedUntil.delete(ip); }
function isAuthBlocked(ip) {
  const until = blockedUntil.get(ip);
  if (!until) return false;
  if (Date.now() > until) { blockedUntil.delete(ip); return false; }
  return true;
}
function isIPAllowed(ip) {
  if (net.isIP(ip) === 0) return false;
  for (const d of deniedCIDRs) if (ipInCidr(ip, d)) return false;
  if (allowedCIDRs.length === 0) return true;
  for (const a of allowedCIDRs) if (ipInCidr(ip, a)) return true;
  return false;
}
function parseCIDRSliceValidated(items) {
  const valid = [], invalid = [];
  for (let item of (items || [])) {
    item = String(item || '').trim();
    if (!item) continue;
    const orig = item;
    if (!item.includes('/')) item += item.includes(':') ? '/128' : '/32';
    const obj = cidrToObj(item);
    if (!obj) { log(`[WARN] CIDR không hợp lệ, bỏ qua: ${orig}`); invalid.push(orig); continue; }
    valid.push(obj);
  }
  return [valid, invalid];
}
function parseCIDRSlice(items) { return parseCIDRSliceValidated(items)[0]; }

// ======================== USER CONFIG / QUOTA ========================
function getUserConfig(username) {
  if (!username) return null;
  for (const u of (appConfig.Users || [])) if (u.username === username) return u;
  return null;
}
function countActiveConnsForUser(username) {
  if (!username) return 0;
  let n = 0;
  for (const ci of activeConns.values()) if (ci.Username === username) n++;
  return n;
}
function currentPeriod() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}
function loadUsage(path) {
  try {
    const data = JSON.parse(fs.readFileSync(path, 'utf8'));
    if (data && typeof data === 'object') for (const k of Object.keys(data)) usage.set(k, data[k]);
  } catch {}
}
function saveUsage(path) {
  if (!path) return;
  const obj = {};
  for (const [k, v] of usage) obj[k] = v;
  const tmp = path + '.tmp';
  try { fs.writeFileSync(tmp, JSON.stringify(obj, null, 2)); fs.renameSync(tmp, path); }
  catch (e) { log(`[WARN] Không lưu được usage file ${path}: ${e.message}`); try { fs.unlinkSync(tmp); } catch {} }
}
function addUsage(username, bytes) {
  if (!username || bytes <= 0) return;
  const period = currentPeriod();
  let rec = usage.get(username);
  if (!rec || rec.Period !== period) { rec = { Period: period, BytesUsed: 0 }; usage.set(username, rec); }
  rec.BytesUsed += bytes;
}
function getUsage(username) {
  const rec = usage.get(username);
  if (!rec || rec.Period !== currentPeriod()) return 0;
  return rec.BytesUsed;
}
function isOverQuota(username, quotaBytes) {
  if (!quotaBytes || quotaBytes <= 0) return false;
  return getUsage(username) >= quotaBytes;
}
function checkUserLimits(username) {
  if (!username) return [true, ''];
  const cfg = getUserConfig(username);
  if (!cfg) return [true, ''];
  if (cfg.max_connections > 0 && countActiveConnsForUser(username) >= cfg.max_connections) {
    return [false, `đã đạt giới hạn ${cfg.max_connections} connection đồng thời`];
  }
  if (isOverQuota(username, cfg.quota_bytes_per_month)) return [false, 'đã vượt quota dung lượng tháng này'];
  return [true, ''];
}

// ======================== BANDWIDTH RAMP ========================
function applyLiveBandwidthLimit(username, newLimitBps) {
  if (!username) return;
  const targets = [];
  for (const ci of activeConns.values()) if (ci.Username === username) targets.push(ci);
  if (!targets.length) return;
  for (const ci of targets) {
    const cur = ci.RateLimitBps || 0;
    if (cur > 0 && newLimitBps > 0 && cur !== newLimitBps) rampBandwidthLimit(ci, cur, newLimitBps);
    else ci.RateLimitBps = newLimitBps;
  }
  log(`[INFO] Áp dụng giới hạn băng thông mới (${newLimitBps} bytes/s) cho ${targets.length} connection đang mở của user '${username}'`);
}
function rampBandwidthLimit(ci, from, to) {
  (async () => {
    for (let i = 1; i <= BANDWIDTH_RAMP_STEPS; i++) {
      await new Promise(r => setTimeout(r, BANDWIDTH_RAMP_INTERVAL_MS));
      ci.RateLimitBps = from + Math.floor((to - from) * i / BANDWIDTH_RAMP_STEPS);
    }
  })();
}

// ======================== CONFIG FILE ========================
function loadOrInitConfig(path, fbUser, fbPass) {
  let data;
  try { data = fs.readFileSync(path, 'utf8'); }
  catch (e) {
    if (e.code !== 'ENOENT') throw e;
    const hash = hashPassword(fbPass);
    const cfg = { DashboardUser: fbUser, DashboardPasswordHash: hash };
    try { saveConfig(path, cfg); log(`[INFO] Đã tạo config file mới tại ${path}`); }
    catch (werr) { log(`[WARN] Không ghi được config file ${path}: ${werr.message}`); }
    return [cfg, true];
  }
  let cfg;
  try { cfg = JSON.parse(data); }
  catch (e) { throw new Error(`config file ${path} bị lỗi định dạng JSON: ${e.message}`); }
  if (!cfg.DashboardUser || !cfg.DashboardPasswordHash) throw new Error(`config file ${path} thiếu dashboard_user/dashboard_password_hash`);
  return [cfg, false];
}
function saveConfig(path, cfg) {
  const data = JSON.stringify(cfg, null, 2);
  const tmp = path + '.tmp';
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, path);
}

// ======================== AUDIT / RELOAD ========================
function recordAudit(actor, action, details) {
  auditLog.push({ t: Math.floor(Date.now() / 1000), actor, action, details: details || '' });
  while (auditLog.length > AUDIT_LOG_MAX) auditLog.shift();
}
function actorFromRequest(req) { return req.headers['x-actor'] || 'unknown'; }
function recordReloadEvent(ev) {
  reloadHistory.push(ev);
  while (reloadHistory.length > RELOAD_HISTORY_MAX) reloadHistory.shift();
}

function reloadConfig(source) {
  let data;
  try { data = fs.readFileSync(cfgFlags.configPath, 'utf8'); }
  catch (e) {
    const ev = { t: Math.floor(Date.now() / 1000), source, success: false, error: `không đọc được config file: ${e.message}` };
    recordReloadEvent(ev); return new Error(ev.error);
  }
  let cfg;
  try { cfg = JSON.parse(data); }
  catch (e) {
    const ev = { t: Math.floor(Date.now() / 1000), source, success: false, error: `config file lỗi định dạng JSON: ${e.message}` };
    recordReloadEvent(ev); return new Error(ev.error);
  }
  if (!cfg.DashboardUser || !cfg.DashboardPasswordHash) {
    const ev = { t: Math.floor(Date.now() / 1000), source, success: false, error: 'config file thiếu dashboard_user/dashboard_password_hash' };
    recordReloadEvent(ev); return new Error(ev.error);
  }
  const [newAllow, invalidAllow] = parseCIDRSliceValidated(cfg.AllowList);
  const [newDeny, invalidDeny] = parseCIDRSliceValidated(cfg.DenyList);
  const invalidCIDRs = [...invalidAllow, ...invalidDeny];

  allowedCIDRs = newAllow;
  deniedCIDRs = newDeny;
  upstreamProxies = (cfg.UpstreamProxies || []).slice();
  if (upstreamProxies.length === 0 || upstreamIndex >= upstreamProxies.length) upstreamIndex = 0;
  dashboardUser = cfg.DashboardUser;
  dashboardPassHash = cfg.DashboardPasswordHash;
  appConfig = cfg;

  for (const u of (cfg.Users || [])) applyLiveBandwidthLimit(u.username, u.max_bandwidth_bps);

  log(`[INFO] Đã reload config (nguồn: ${source}): ${newAllow.length} IP whitelist, ${newDeny.length} IP blacklist, ${upstreamProxies.length} upstream, ${(cfg.Users || []).length} proxy user${invalidCIDRs.length ? ` (CẢNH BÁO: ${invalidCIDRs.length} CIDR không hợp lệ bị bỏ qua)` : ''}`);
  recordReloadEvent({
    t: Math.floor(Date.now() / 1000), source, success: true,
    allow_count: newAllow.length, deny_count: newDeny.length,
    upstream_count: upstreamProxies.length, user_count: (cfg.Users || []).length,
    invalid_cidrs: invalidCIDRs,
  });
  return null;
}

// ======================== UPSTREAM HEALTH ========================
const upstreamHealth = new Map();
function isUpstreamAlive(addr) { const v = upstreamHealth.get(addr); return v === undefined ? true : v; }
function setUpstreamHealth(addr, alive) {
  const prev = upstreamHealth.get(addr);
  upstreamHealth.set(addr, alive);
  if (prev !== undefined && prev !== alive) {
    if (alive) log(`[INFO] Upstream ${addr} đã SỐNG LẠI`);
    else log(`[WARN] Upstream ${addr} CHẾT (không kết nối được)`);
  }
}
function upstreamHealthChecker() {
  setInterval(() => {
    const ups = upstreamProxies.slice();
    for (const addr of ups) {
      const [h, p] = addr.split(':');
      const s = net.createConnection({ host: h, port: parseInt(p, 10), timeout: UPSTREAM_HEALTH_CHECK_TIMEOUT_MS });
      s.once('connect', () => { s.destroy(); setUpstreamHealth(addr, true); });
      s.once('error', () => { s.destroy(); setUpstreamHealth(addr, false); });
      s.once('timeout', () => { s.destroy(); setUpstreamHealth(addr, false); });
    }
  }, UPSTREAM_HEALTH_CHECK_INTERVAL_MS);
}

// ======================== CONNECT TARGET ========================
async function connectTarget(host, portNum) {
  const ups = upstreamProxies.slice();
  if (ups.length > 0) {
    let aliveCount = 0;
    for (const u of ups) if (isUpstreamAlive(u)) aliveCount++;
    for (let i = 0; i < ups.length; i++) {
      const idx = (upstreamIndex + i) % ups.length;
      const upstream = ups[idx];
      if (aliveCount > 0 && !isUpstreamAlive(upstream)) continue;
      upstreamIndex = (idx + 1) % ups.length;
      try {
        const [uh, up] = upstream.split(':');
        return await new Promise((resolve, reject) => {
          const s = net.createConnection({ host: uh, port: parseInt(up, 10), timeout: CONNECTION_TIMEOUT }, () => resolve(s));
          s.once('error', reject);
          s.once('timeout', () => { s.destroy(); reject(new Error('timeout')); });
        });
      } catch { setUpstreamHealth(upstream, false); }
    }
  }
  return dialChecked(host, portNum);
}

// ======================== AUTH ========================
function authenticateProxyUser(user, pass) {
  if (cfgFlags.username && user === cfgFlags.username && pass === cfgFlags.password) return [true, 0, user];
  for (const u of (appConfig.Users || [])) {
    if (u.username === user && verifyPasswordCached(pass, u.password_hash)) return [true, u.max_bandwidth_bps || 0, u.username];
  }
  return [false, 0, ''];
}
function authRequired() {
  if (cfgFlags.username && cfgFlags.password) return true;
  return !!(appConfig.RequireProxyAuth || (appConfig.Users && appConfig.Users.length > 0));
}
function checkHTTPAuth(auth) {
  if (!auth || !/^basic /i.test(auth)) return [false, 0, ''];
  let decoded;
  try { decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8'); } catch { return [false, 0, '']; }
  const idx = decoded.indexOf(':');
  if (idx < 0) return [false, 0, ''];
  return authenticateProxyUser(decoded.slice(0, idx), decoded.slice(idx + 1));
}

// ======================== SOCKS5 ========================
function ipv4ToBuf(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(x => isNaN(x) || x < 0 || x > 255)) return null;
  return Buffer.from(p);
}
function ipv6ToBuf(ip) {
  const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (m) { const v4 = ipv4ToBuf(m[1]); if (!v4) return null; return Buffer.concat([Buffer.alloc(10, 0), Buffer.from([0xff, 0xff]), v4]); }
  let head, tail;
  if (ip.includes('::')) { const [h, t] = ip.split('::'); head = h ? h.split(':') : []; tail = t ? t.split(':') : []; }
  else { head = ip.split(':'); tail = []; }
  const groups = [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  const buf = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) { const n = parseInt(groups[i] || '0', 16); if (isNaN(n)) return null; buf.writeUInt16BE(n, i * 2); }
  return buf;
}
function sendSOCKS5Reply(socket, rep, bindIP, bindPort) {
  if (!bindIP) bindIP = '0.0.0.0';
  let atyp, ipBytes;
  if (!bindIP.includes(':')) { atyp = 0x01; ipBytes = ipv4ToBuf(bindIP) || Buffer.from([0, 0, 0, 0]); }
  else { atyp = 0x04; ipBytes = ipv6ToBuf(bindIP) || Buffer.alloc(16, 0); }
  const port = Buffer.alloc(2); port.writeUInt16BE(bindPort & 0xffff, 0);
  const out = Buffer.concat([Buffer.from([0x05, rep, 0x00, atyp]), ipBytes, port]);
  try { socket.write(out); } catch {}
}
async function readSOCKSAddr(atyp, reader) {
  try {
    if (atyp === 0x01) {
      const ip = await reader.readN(4);
      const p = (await reader.readN(2)).readUInt16BE(0);
      return [ip.join('.'), p];
    }
    if (atyp === 0x03) {
      const len = (await reader.readN(1))[0];
      const host = (await reader.readN(len)).toString('utf8');
      const p = (await reader.readN(2)).readUInt16BE(0);
      return [host, p];
    }
    if (atyp === 0x04) {
      const ip = await reader.readN(16);
      const p = (await reader.readN(2)).readUInt16BE(0);
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(ip.readUInt16BE(i).toString(16));
      return [parts.join(':'), p];
    }
  } catch {}
  return [null, 0];
}

async function handleSOCKS5(socket, reader, remoteIP) {
  let buf;
  try { buf = await reader.readN(2); } catch { return socket.destroy(); }
  if (buf[0] !== 0x05) {
    log(`[WARN] SOCKS5 bad version from ${socket.remoteAddress}: 0x${buf[0].toString(16)} (mong đợi 0x05)`);
    return socket.destroy();
  }
  let methods;
  try { methods = await reader.readN(buf[1]); } catch { return socket.destroy(); }

  const needAuth = authRequired();
  const authMethod = needAuth ? 0x02 : 0x00;
  let found = false;
  for (const m of methods) if (m === authMethod) { found = true; break; }
  if (!found) { try { socket.write(Buffer.from([0x05, 0xff])); } catch {} return socket.destroy(); }
  try { socket.write(Buffer.from([0x05, authMethod])); } catch {}

  let authLimitBps = 0, authUsername = '';
  if (needAuth) {
    let b;
    try { b = await reader.readN(1); } catch { return socket.destroy(); }
    if (b[0] !== 0x01) { try { socket.write(Buffer.from([0x01, 0xff])); } catch {} return socket.destroy(); }
    const ulen = (await reader.readN(1))[0];
    const user = (await reader.readN(ulen)).toString('utf8');
    const plen = (await reader.readN(1))[0];
    const pass = (await reader.readN(plen)).toString('utf8');
    const [ok, limit, uname] = authenticateProxyUser(user, pass);
    if (ok) {
      try { socket.write(Buffer.from([0x01, 0x00])); } catch {}
      resetAuthFail(remoteIP);
      authLimitBps = limit; authUsername = uname;
    } else {
      try { socket.write(Buffer.from([0x01, 0xff])); } catch {}
      log(`[WARN] SOCKS5 auth fail from ${socket.remoteAddress}:${socket.remotePort}`);
      stats.AuthFail++;
      recordAuthFail(remoteIP, AUTH_FAIL_THRESHOLD);
      return socket.destroy();
    }
  }
  if (authUsername) {
    const [ok, reason] = checkUserLimits(authUsername);
    if (!ok) {
      log(`[WARN] SOCKS5 từ chối user '${authUsername}': ${reason}`);
      sendSOCKS5Reply(socket, 0x02, null, 0);
      return socket.destroy();
    }
  }

  let req;
  try { req = await reader.readN(4); } catch { return socket.destroy(); }
  if (req[0] !== 0x05) return socket.destroy();
  const cmd = req[1], atyp = req[3];
  const [host, portNum] = await readSOCKSAddr(atyp, reader);
  if (host === null) return socket.destroy();

  if (cmd === 0x01) {
    socket.setTimeout(0);
    const target = `${host}:${portNum}`;
    log(`[SOCKS5 TCP] ${socket.remoteAddress}:${socket.remotePort} -> ${target}`);
    let remote;
    try { remote = await connectTarget(host, portNum); }
    catch { sendSOCKS5Reply(socket, 0x05, null, 0); return socket.destroy(); }

    const bindIP = remote.localAddress || '0.0.0.0';
    const bindPort = remote.localPort || 0;
    sendSOCKS5Reply(socket, 0x00, bindIP, bindPort);

    const ci = {
      ID: nextConnID(), IP: remoteIP, Port: socket.remotePort, Type: 'SOCKS5_TCP',
      Target: target, StartTime: Date.now(), Conn: socket,
      RateLimitBps: authLimitBps, Username: authUsername,
      BytesUp: 0, BytesDown: 0, flushedUp: 0, flushedDown: 0,
    };
    activeConns.set(ci.ID, ci);
    stats.Socks5TCP++;
    await tunnel(socket, remote, ci, reader.detach());
    activeConns.delete(ci.ID);
  } else if (cmd === 0x03) {
    if (cfgFlags.noUDP) { sendSOCKS5Reply(socket, 0x07, null, 0); return socket.destroy(); }
    const target = host ? `UDP:${host}:${portNum}` : 'UDP:any';
    socket.setTimeout(0);
    log(`[SOCKS5 UDP] ${socket.remoteAddress}:${socket.remotePort} -> ${target}`);

    const isV6 = !!(socket.localAddress && socket.localAddress.includes(':'));
    const udp = dgram.createSocket({ type: isV6 ? 'udp6' : 'udp4', ipv6Only: false });
    udp.on('error', (e) => log(`[WARN] UDP relay socket error: ${e.message}`));

    try {
      await new Promise((resolve, reject) => {
        const onErr = (e) => reject(e);
        udp.once('error', onErr);
        udp.bind(0, () => { udp.removeListener('error', onErr); resolve(); });
      });
    } catch (e) { sendSOCKS5Reply(socket, 0x01, null, 0); return socket.destroy(); }

    const localPort = udp.address().port;
    const tcpPort = socket.remotePort;
    const key = `${remoteIP}:${tcpPort}`;

    const assoc = {
      ClientAddr: { ip: remoteIP, port: 0 },
      RelayConn: udp,
      DestMap: new Map(),
      LastActivity: Date.now(),
      Active: true,
      ClientIP: remoteIP,
      ClientKnown: false,
      Username: authUsername,
    };
    udpAssocs.set(key, assoc);

    const ci = {
      ID: nextConnID(), IP: remoteIP, Port: tcpPort, Type: 'SOCKS5_UDP',
      Target: target, StartTime: Date.now(), Conn: socket, Username: authUsername,
      BytesUp: 0, BytesDown: 0, flushedUp: 0, flushedDown: 0, RateLimitBps: 0,
    };
    activeConns.set(ci.ID, ci);
    stats.Socks5UDP++;

    const replyIP = socket.localAddress || (isV6 ? '::' : '0.0.0.0');
    sendSOCKS5Reply(socket, 0x00, replyIP, localPort);

    reader.detach();
    udpRelay(assoc);

    // Giữ handleSOCKS5 cho tới khi TCP control connection đóng. Nếu return sớm,
    // khối finally trong handleConn sẽ destroy socket và giết association.
    await new Promise((resolve) => {
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        clearInterval(idleTimer);
        assoc.Active = false;
        try { udp.close(); } catch {}
        udpAssocs.delete(key);
        activeConns.delete(ci.ID);
        resolve();
      };
      socket.once('close', finish);
      socket.once('error', finish);
      socket.once('end', finish);
      const idleTimer = setInterval(() => {
        if (!assoc.Active || Date.now() - assoc.LastActivity > UDP_IDLE_TIMEOUT) {
          try { socket.destroy(); } catch {}
        }
      }, 5000);
    });
  } else {
    sendSOCKS5Reply(socket, 0x07, null, 0);
    socket.destroy();
  }
}

// ======================== UDP RELAY ========================
function normIP(ip) {
  if (!ip) return ip;
  const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return m ? m[1] : ip;
}
function udpRelay(assoc) {
  const socket = assoc.RelayConn;
  socket.on('message', (msg, from) => {
    if (!assoc.Active) return;
    assoc.LastActivity = Date.now();
    const fromIP = normIP(from.address);
    let isClient = false;
    if (assoc.ClientKnown) {
      isClient = fromIP === assoc.ClientAddr.ip && from.port === assoc.ClientAddr.port;
    } else if (fromIP === assoc.ClientIP) {
      assoc.ClientAddr = { ip: fromIP, port: from.port };
      assoc.ClientKnown = true;
      isClient = true;
    }
    if (isClient) udpClientToRemote(assoc, msg);
    else if (assoc.ClientKnown) udpRemoteToClient(assoc, { ip: fromIP, port: from.port }, msg);
  });
}
function udpClientToRemote(assoc, pkt) {
  const n = pkt.length;
  if (n < 4 || pkt[2] !== 0) return;
  const atyp = pkt[3];
  let pos = 4, host = '';
  if (atyp === 0x01) {
    if (pos + 6 > n) return;
    host = `${pkt[pos]}.${pkt[pos + 1]}.${pkt[pos + 2]}.${pkt[pos + 3]}`; pos += 4;
  } else if (atyp === 0x03) {
    if (pos + 1 > n) return;
    const length = pkt[pos]; pos++;
    if (pos + length + 2 > n) return;
    host = pkt.slice(pos, pos + length).toString('utf8'); pos += length;
  } else if (atyp === 0x04) {
    if (pos + 18 > n) return;
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(pkt.readUInt16BE(pos + i).toString(16));
    host = parts.join(':'); pos += 16;
  } else return;
  const portNum = pkt.readUInt16BE(pos); pos += 2;
  const payload = Buffer.from(pkt.slice(pos));

  (async () => {
    let ip;
    try { ip = await resolveAndCheck(host); }
    catch (e) { log(`[WARN] UDP relay bị chặn tới ${host}:${portNum}: ${e.message}`); return; }
    if (assoc.DestMap.size >= 4096) assoc.DestMap.clear();
    assoc.DestMap.set(`${ip}:${portNum}`, Date.now());
    try { assoc.RelayConn.send(payload, portNum, ip); } catch { return; }
    stats.UDPUp += payload.length;
    addUsage(assoc.Username, payload.length);
  })();
}
function udpRemoteToClient(assoc, from, data) {
  const key = `${from.ip}:${from.port}`;
  if (!assoc.DestMap.has(key)) return;
  const out = [0, 0, 0];
  let ipBytes;
  if (!from.ip.includes(':')) { out.push(0x01); ipBytes = ipv4ToBuf(from.ip); }
  else { out.push(0x04); ipBytes = ipv6ToBuf(from.ip); }
  if (!ipBytes) return;
  const header = Buffer.concat([Buffer.from(out), ipBytes, Buffer.from([from.port >> 8, from.port & 0xff])]);
  const full = Buffer.concat([header, data]);
  try { assoc.RelayConn.send(full, assoc.ClientAddr.port, assoc.ClientAddr.ip); } catch { return; }
  stats.UDPDown += data.length;
  addUsage(assoc.Username, data.length);
}

// ======================== HTTP PROXY ========================
async function handleHTTP(socket, reader, remoteIP) {
  let reqLine;
  try { reqLine = await reader.readLine(MAX_LINE_BYTES); } catch { return socket.destroy(); }
  const parts = reqLine.split(/\s+/).filter(Boolean);
  if (parts.length < 2) { log(`[WARN] HTTP bad request line from ${socket.remoteAddress}: "${reqLine}"`); return socket.destroy(); }
  const method = parts[0], rawURL = parts[1];
  const headers = {};
  for (let count = 0; ; count++) {
    if (count > MAX_HEADER_LINES) { try { socket.write('HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n'); } catch {} return socket.destroy(); }
    let line;
    try { line = await reader.readLine(MAX_LINE_BYTES); } catch { return socket.destroy(); }
    if (line === '') break;
    const idx = line.indexOf(':');
    if (idx > 0) {
      const k = line.slice(0, idx).trim().toLowerCase();
      const v = line.slice(idx + 1).trim();
      (headers[k] = headers[k] || []).push(v);
    }
  }
  socket.setTimeout(0);

  let authLimitBps = 0, authUsername = '';
  if (authRequired()) {
    const auth = (headers['proxy-authorization'] || [])[0] || '';
    const [ok, limit, uname] = checkHTTPAuth(auth);
    if (!ok) {
      try { socket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n'); } catch {}
      stats.AuthFail++;
      recordAuthFail(remoteIP, AUTH_FAIL_THRESHOLD);
      return socket.destroy();
    }
    resetAuthFail(remoteIP);
    authLimitBps = limit; authUsername = uname;
  }
  if (authUsername) {
    const [ok, reason] = checkUserLimits(authUsername);
    if (!ok) {
      log(`[WARN] HTTP proxy từ chối user '${authUsername}': ${reason}`);
      try { socket.write(`HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\n${reason}`); } catch {}
      return socket.destroy();
    }
  }

  const badRequest = () => { try { socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch {} socket.destroy(); };

  let host = '', portNum = 0, parsedURL = null;
  if (method === 'CONNECT') {
    const m = rawURL.match(/^\[([^\]]+)\]:(\d+)$/) || rawURL.match(/^([^:]+):(\d+)$/);
    if (!m) return badRequest();
    host = m[1]; portNum = parseInt(m[2], 10);
    if (!portNum || portNum < 1 || portNum > 65535) return badRequest();
  } else {
    let parsed;
    try { parsed = new URL(rawURL.includes('://') ? rawURL : 'http://' + rawURL); } catch { return badRequest(); }
    if (!parsed.hostname) return badRequest();
    host = parsed.hostname;
    portNum = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
    if (!portNum || portNum < 1 || portNum > 65535) return badRequest();
    parsedURL = parsed;
  }
  const target = `${host}:${portNum}`;
  log(`[HTTP ${method}] ${socket.remoteAddress}:${socket.remotePort} -> ${target}`);

  const ci = {
    ID: nextConnID(), IP: remoteIP, Port: socket.remotePort, Type: 'HTTP',
    Target: target, StartTime: Date.now(), Conn: socket,
    RateLimitBps: authLimitBps, Username: authUsername,
    BytesUp: 0, BytesDown: 0, flushedUp: 0, flushedDown: 0,
  };
  activeConns.set(ci.ID, ci);
  stats.HTTP++;

  let remote;
  try { remote = await connectTarget(host, portNum); }
  catch { try { socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch {} socket.destroy(); activeConns.delete(ci.ID); return; }

  try {
    if (method === 'CONNECT') {
      try { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); } catch {}
      await tunnel(socket, remote, ci, reader.detach());
    } else {
      await forwardHTTP(reader, method, parsedURL, headers, remote, socket, ci);
    }
  } finally {
    flushConnStats(ci);
    activeConns.delete(ci.ID);
  }
}
async function forwardHTTP(reader, method, parsedURL, headers, remote, client, ci) {
  let contentLength = -1, chunked = false;
  if (headers['content-length']) {
    for (const v of headers['content-length']) {
      const n = parseInt(v, 10);
      if (isNaN(n) || n < 0 || (contentLength >= 0 && n !== contentLength)) {
        try { client.write('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch {}
        remote.destroy(); return;
      }
      contentLength = n;
    }
  }
  if (headers['transfer-encoding']) {
    if (contentLength >= 0 || headers['transfer-encoding'].length !== 1 || headers['transfer-encoding'][0].toLowerCase() !== 'chunked') {
      try { client.write('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch {}
      remote.destroy(); return;
    }
    chunked = true;
  }
  let reqStr = `${method} ${parsedURL.pathname}${parsedURL.search} HTTP/1.1\r\n`;
  if (!headers['host']) reqStr += `Host: ${parsedURL.host}\r\n`;
  for (const k of Object.keys(headers)) {
    switch (k) {
      case 'proxy-authorization': case 'proxy-connection': case 'connection':
      case 'keep-alive': case 'expect': case 'upgrade': case 'te': continue;
    }
    for (const v of headers[k]) reqStr += `${k}: ${v}\r\n`;
  }
  reqStr += 'Connection: close\r\n\r\n';

  const upWriter = makeCountingWriter(remote, ci, 'BytesUp');
  try { upWriter.write(Buffer.from(reqStr)); } catch { remote.destroy(); return; }

  if (chunked) { try { await relayChunked(reader, upWriter); } catch { remote.destroy(); return; } }
  else if (contentLength > 0) { try { await pipeN(reader, upWriter, contentLength); } catch { remote.destroy(); return; } }

  await new Promise((resolve) => {
    remote.on('data', chunk => {
      ci.BytesDown += chunk.length;
      if (!client.writable) return;
      const ok = client.write(chunk);
      const limit = ci.RateLimitBps || 0;
      if (limit > 0) {
        const sleepMs = Math.ceil(chunk.length * 1000 / limit);
        remote.pause();
        setTimeout(() => { if (!remote.destroyed) remote.resume(); }, sleepMs);
      } else if (!ok) {
        remote.pause();
        client.once('drain', () => remote.resume());
      }
    });
    remote.on('end', () => { try { client.end(); } catch {} resolve(); });
    remote.on('error', () => { try { client.destroy(); } catch {} resolve(); });
    client.on('error', () => { remote.destroy(); resolve(); });
  });
}
function makeCountingWriter(socket, ci, field) {
  return {
    write(chunk) {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      ci[field] += b.length;
      return socket.write(b);
    },
  };
}
async function pipeN(reader, writer, n) {
  let remaining = n;
  while (remaining > 0) {
    const take = Math.min(remaining, 65536);
    const chunk = await reader.readN(take);
    writer.write(chunk);
    remaining -= chunk.length;
  }
}
async function relayChunked(reader, writer) {
  while (true) {
    let line;
    try { line = await reader.readLine(1024); } catch (e) { throw e; }
    let sizeStr = line;
    const i = sizeStr.indexOf(';');
    if (i >= 0) sizeStr = sizeStr.slice(0, i);
    const size = parseInt(sizeStr.trim(), 16);
    if (isNaN(size) || size < 0) throw new Error('chunk size không hợp lệ');
    writer.write(Buffer.from(line + '\r\n'));
    if (size === 0) {
      for (let i = 0; i <= MAX_HEADER_LINES; i++) {
        const t = await reader.readLine(MAX_LINE_BYTES);
        writer.write(Buffer.from(t + '\r\n'));
        if (t === '') return;
      }
      throw new Error('quá nhiều trailer');
    }
    await pipeN(reader, writer, size);
    const crlf = await reader.readN(2);
    if (crlf.toString('binary') !== '\r\n') throw new Error('thiếu CRLF sau chunk');
    writer.write(crlf);
  }
}

// ======================== TUNNEL ========================
async function tunnel(client, remote, ci, initialBuf) {
  if (initialBuf && initialBuf.length) {
    ci.BytesUp += initialBuf.length;
    if (!remote.destroyed) remote.write(initialBuf);
  }
  return new Promise((resolve) => {
    let done = 0;
    const finish = () => { if (++done === 2) resolve(); };
    const setup = (src, dst, field, onEnd) => {
      src.on('data', chunk => {
        ci[field] += chunk.length;
        if (!dst.writable) return;
        const ok = dst.write(chunk);
        const limit = ci.RateLimitBps || 0;
        if (limit > 0) {
          const sleepMs = Math.ceil(chunk.length * 1000 / limit);
          src.pause();
          setTimeout(() => { if (!src.destroyed && dst.writable) src.resume(); }, sleepMs);
        } else if (!ok) {
          src.pause();
          dst.once('drain', () => src.resume());
        }
      });
      src.once('end', () => { try { dst.end(); } catch {} onEnd(); });
      src.once('error', () => { try { dst.destroy(); } catch {} onEnd(); });
      src.once('close', () => { try { dst.destroy(); } catch {} });
      dst.once('error', () => { try { src.destroy(); } catch {} onEnd(); });
      dst.once('close', () => { try { src.destroy(); } catch {} });
    };
    setup(client, remote, 'BytesUp', finish);
    setup(remote, client, 'BytesDown', finish);
  });
}

// ======================== FLUSH CONN STATS ========================
function flushConnStats(ci) {
  const up = ci.BytesUp, down = ci.BytesDown;
  const dUp = up - (ci.flushedUp || 0);
  const dDown = down - (ci.flushedDown || 0);
  ci.flushedUp = up; ci.flushedDown = down;
  if (dUp <= 0 && dDown <= 0) return;
  stats.BytesUp += dUp;
  stats.BytesDown += dDown;
  addUsage(ci.Username, dUp + dDown);
}

// ======================== STATS REPORTER / SSE ========================
function broadcastSample(sample) {
  for (const ch of sseClients) ch.push(sample);
}
let statsReporterRunning = false;
function statsReporter() {
  if (statsReporterRunning) return;
  statsReporterRunning = true;
  let lastUp = 0, lastDown = 0, first = true, tick = 0;
  setInterval(() => {
    tick++;
    for (const ci of activeConns.values()) flushConnStats(ci);
    let s5TCP = 0, s5UDP = 0, httpCount = 0;
    for (const ci of activeConns.values()) {
      if (ci.Type === 'SOCKS5_TCP') s5TCP++;
      else if (ci.Type === 'SOCKS5_UDP') s5UDP++;
      else if (ci.Type === 'HTTP') httpCount++;
    }
    const udpAssoc = udpAssocs.size;
    const up = stats.BytesUp, down = stats.BytesDown;
    log(`[STATS] Active:${stats.Current} TCP:${s5TCP} UDP:${s5UDP} HTTP:${httpCount} | UDP Assoc:${udpAssoc} | Up:${formatBytes(up)} Down:${formatBytes(down)} | Uptime:${((Date.now() - stats.StartTime) / 1000).toFixed(0)}s`);

    let upBps = 0, downBps = 0;
    if (!first) {
      upBps = Math.floor((up - lastUp) / (STATS_INTERVAL_MS / 1000));
      downBps = Math.floor((down - lastDown) / (STATS_INTERVAL_MS / 1000));
    }
    lastUp = up; lastDown = down; first = false;

    const sample = { t: Math.floor(Date.now() / 1000), up_bps: upBps, down_bps: downBps, active: stats.Current, udp_assocs: udpAssoc };
    statHistory.push(sample);
    while (statHistory.length > HISTORY_MAX_SAMPLES) statHistory.shift();
    broadcastSample(sample);

    if (tick % 5 === 0) enforceQuotaOnActiveConns();
    if (tick % 15 === 0 && cfgFlags.usagePath) saveUsage(cfgFlags.usagePath);
  }, STATS_INTERVAL_MS);
}
function enforceQuotaOnActiveConns() {
  const seen = new Set();
  for (const ci of activeConns.values()) if (ci.Username) seen.add(ci.Username);
  const toKick = [];
  for (const username of seen) {
    const cfg = getUserConfig(username);
    if (!cfg || !cfg.quota_bytes_per_month) continue;
    if (!isOverQuota(username, cfg.quota_bytes_per_month)) continue;
    for (const ci of activeConns.values()) if (ci.Username === username) toKick.push(ci);
  }
  for (const ci of toKick) { if (ci.Conn) try { ci.Conn.destroy(); } catch {} }
  if (toKick.length) log(`[WARN] Đã ngắt ${toKick.length} connection do user vượt quota dung lượng tháng`);
}

// ======================== DASHBOARD ========================
function csrfOK(req) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return true;
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') return false;
  const origin = req.headers['origin'];
  if (origin) {
    try { const u = new URL(origin); if (u.host.toLowerCase() !== req.headers.host.toLowerCase()) return false; }
    catch { return false; }
  }
  return (req.headers['content-type'] || '').toLowerCase().startsWith('application/json');
}
function dashboardAuth(handler) {
  return async (req, res) => {
    const remoteIP = (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
    if (remoteIP && isAuthBlocked(remoteIP)) {
      res.writeHead(429, { 'Content-Type': 'text/plain' });
      res.end('429 Too Many Requests - IP tạm thời bị chặn do đăng nhập sai nhiều lần');
      return;
    }
    const authHeader = req.headers['authorization'] || '';
    if (authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      const [name, ok] = checkAPIToken(token);
      if (ok) {
        if (remoteIP) resetAuthFail(remoteIP);
        req.headers['x-actor'] = 'token:' + name;
        return handler(req, res);
      }
      if (remoteIP) recordAuthFail(remoteIP, DASHBOARD_AUTH_FAIL_THRESHOLD);
      res.writeHead(401); res.end('401 Unauthorized (invalid token)');
      return;
    }
    if (!authHeader.startsWith('Basic ')) {
      if (remoteIP) recordAuthFail(remoteIP, DASHBOARD_AUTH_FAIL_THRESHOLD);
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Dashboard"' });
      res.end('401 Unauthorized');
      return;
    }
    let decoded;
    try { decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8'); } catch { decoded = ''; }
    const idx = decoded.indexOf(':');
    if (idx < 0) {
      if (remoteIP) recordAuthFail(remoteIP, DASHBOARD_AUTH_FAIL_THRESHOLD);
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Dashboard"' });
      res.end('401 Unauthorized'); return;
    }
    const user = decoded.slice(0, idx), pass = decoded.slice(idx + 1);
    if (!subtleCompare(user, dashboardUser) || !verifyPasswordCached(pass, dashboardPassHash)) {
      if (remoteIP) recordAuthFail(remoteIP, DASHBOARD_AUTH_FAIL_THRESHOLD);
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Dashboard"' });
      res.end('401 Unauthorized'); return;
    }
    if (remoteIP) resetAuthFail(remoteIP);
    if (!csrfOK(req)) { res.writeHead(403); res.end('403 Forbidden (CSRF check failed)'); return; }
    req.headers['x-actor'] = 'dashboard:' + user;
    return handler(req, res);
  };
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { req.destroy(); reject(new Error('body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function sendJSON(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }

function dashboardIndex(req, res) {
  const u = new URL(req.url, 'http://x');
  if (u.pathname !== '/') { res.writeHead(404); res.end('Not Found'); return; }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(dashboardHTML);
}
function healthCheck(req, res) {
  if (shuttingDown) { res.writeHead(503); res.end('{"status":"shutting_down"}'); return; }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end('{"status":"ok"}');
}
function metricsHandler(req, res) {
  const activeCount = activeConns.size;
  const udpCount = udpAssocs.size;
  const uptime = (Date.now() - stats.StartTime) / 1000;
  const m = (name, help, typ, val) => `# HELP proxy_${name} ${help}\n# TYPE proxy_${name} ${typ}\nproxy_${name} ${val}\n`;
  let out = '';
  out += m('connections_total', 'Tổng số kết nối đã nhận từ khi khởi động', 'counter', stats.Total);
  out += m('connections_current', 'Số kết nối đang mở', 'gauge', stats.Current);
  out += m('connections_active', 'Số kết nối đang active', 'gauge', activeCount);
  out += m('socks5_tcp_total', 'Tổng số kết nối SOCKS5 TCP', 'counter', stats.Socks5TCP);
  out += m('socks5_udp_total', 'Tổng số kết nối SOCKS5 UDP', 'counter', stats.Socks5UDP);
  out += m('http_requests_total', 'Tổng số request HTTP proxy', 'counter', stats.HTTP);
  out += m('bytes_up_total', 'Tổng bytes gửi lên', 'counter', stats.BytesUp);
  out += m('bytes_down_total', 'Tổng bytes tải về', 'counter', stats.BytesDown);
  out += m('udp_bytes_up_total', 'Tổng bytes UDP gửi lên', 'counter', stats.UDPUp);
  out += m('udp_bytes_down_total', 'Tổng bytes UDP tải về', 'counter', stats.UDPDown);
  out += m('udp_associations', 'Số UDP association đang mở', 'gauge', udpCount);
  out += m('auth_fail_total', 'Tổng số lần xác thực thất bại', 'counter', stats.AuthFail);
  out += m('uptime_seconds', 'Thời gian server đã chạy (giây)', 'gauge', uptime);
  res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
  res.end(out);
}
async function dashboardAll(req, res) { sendJSON(res, 200, getAllStats()); }
async function dashboardKick(req, res) {
  if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Only POST is supported' });
  let body;
  try { body = JSON.parse((await readBody(req, 2048)).toString('utf8')); }
  catch { return sendJSON(res, 400, { error: "Missing or invalid 'id'" }); }
  if (!body || !body.id) return sendJSON(res, 400, { error: "Missing or invalid 'id'" });
  const target = activeConns.get(body.id);
  if (!target) return sendJSON(res, 404, { error: 'Connection not found (already closed?)' });
  if (target.Conn) try { target.Conn.destroy(); } catch {}
  log(`[INFO] Dashboard kicked connection ${target.ID} (${target.IP} -> ${target.Target})`);
  recordAudit(actorFromRequest(req), 'kick_connection', `id=${target.ID} ip=${target.IP} target=${target.Target} user=${target.Username}`);
  sendJSON(res, 200, { success: true, id: target.ID });
}
async function dashboardExport(req, res) {
  const u = new URL(req.url, 'http://x');
  const format = u.searchParams.get('format') || 'json';
  const rows = [];
  for (const ci of activeConns.values()) {
    rows.push({
      id: ci.ID, ip: ci.IP, port: ci.Port, type: ci.Type, target: ci.Target,
      bytes_up: ci.BytesUp, bytes_down: ci.BytesDown,
      duration_seconds: (Date.now() - ci.StartTime) / 1000,
    });
  }
  if (format === 'csv') {
    res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=connections.csv' });
    let out = 'id,ip,port,type,target,bytes_up,bytes_down,duration_seconds\n';
    for (const r of rows) {
      out += [r.id, r.ip, r.port, r.type, r.target, r.bytes_up, r.bytes_down, r.duration_seconds.toFixed(1)]
        .map(x => `"${String(x).replace(/"/g, '""')}"`).join(',') + '\n';
    }
    res.end(out); return;
  }
  res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename=connections.json' });
  res.end(JSON.stringify(rows));
}
async function dashboardChangePassword(req, res) {
  if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Only POST is supported' });
  let body;
  try { body = JSON.parse((await readBody(req, 4096)).toString('utf8')); }
  catch { return sendJSON(res, 400, { error: 'Invalid JSON body' }); }
  if (!verifyPassword(body.current_password, dashboardPassHash)) return sendJSON(res, 403, { error: 'Current password is incorrect' });
  if (!body.new_password || body.new_password.length < 8) return sendJSON(res, 400, { error: 'New password must be at least 8 characters' });
  if (body.new_password === body.current_password) return sendJSON(res, 400, { error: 'New password must be different from the current password' });
  const newHash = hashPassword(body.new_password);
  const oldUser = dashboardUser;
  dashboardPassHash = newHash;
  if (body.new_username) dashboardUser = body.new_username;
  appConfig.DashboardUser = dashboardUser;
  appConfig.DashboardPasswordHash = dashboardPassHash;
  try { saveConfig(cfgFlags.configPath, appConfig); }
  catch (e) { log(`[WARN] Đổi mật khẩu thành công nhưng KHÔNG ghi được config file: ${e.message}`); }
  log(`[INFO] Dashboard credentials đã được đổi (user: ${oldUser} -> ${dashboardUser})`);
  recordAudit(actorFromRequest(req), 'change_dashboard_password', `user: ${oldUser} -> ${dashboardUser}`);
  sendJSON(res, 200, { success: true, username: dashboardUser });
}
async function dashboardUsers(req, res) {
  if (req.method === 'GET') {
    const out = (appConfig.Users || []).map(u => ({
      username: u.username, max_bandwidth_bps: u.max_bandwidth_bps,
      max_connections: u.max_connections, quota_bytes_per_month: u.quota_bytes_per_month,
      usage_bytes_this_month: getUsage(u.username),
    }));
    return sendJSON(res, 200, { users: out });
  }
  if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Only GET/POST is supported' });
  let body;
  try { body = JSON.parse((await readBody(req, 4096)).toString('utf8')); }
  catch { return sendJSON(res, 400, { error: 'Invalid JSON body' }); }
  const uname = String(body.username || '').trim();
  if (!uname) return sendJSON(res, 400, { error: 'Username required' });
  if (body.password && body.password.length < 4) return sendJSON(res, 400, { error: 'Password must be at least 4 characters' });
  if (body.max_bandwidth_bps < 0) body.max_bandwidth_bps = 0;
  if (body.max_connections < 0) body.max_connections = 0;
  if (body.quota_bytes_per_month < 0) body.quota_bytes_per_month = 0;

  let found = false;
  for (const u of appConfig.Users) {
    if (u.username === uname) {
      if (body.password) u.password_hash = hashPassword(body.password);
      u.max_bandwidth_bps = body.max_bandwidth_bps;
      u.max_connections = body.max_connections;
      u.quota_bytes_per_month = body.quota_bytes_per_month;
      found = true; break;
    }
  }
  if (!found) {
    if (!body.password) return sendJSON(res, 400, { error: 'Password is required when creating a new user' });
    appConfig.RequireProxyAuth = true;
    appConfig.Users.push({
      username: uname, password_hash: hashPassword(body.password),
      max_bandwidth_bps: body.max_bandwidth_bps,
      max_connections: body.max_connections,
      quota_bytes_per_month: body.quota_bytes_per_month,
    });
  }
  try { saveConfig(cfgFlags.configPath, appConfig); }
  catch (e) { return sendJSON(res, 500, { error: 'Saved in memory but failed to write config file: ' + e.message }); }
  applyLiveBandwidthLimit(uname, body.max_bandwidth_bps);
  log(`[INFO] Dashboard: đã thêm/cập nhật proxy user '${uname}'`);
  recordAudit(actorFromRequest(req), 'upsert_user', `username=${uname}`);
  sendJSON(res, 200, { success: true });
}
async function dashboardDeleteUser(req, res) {
  if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Only POST is supported' });
  let body;
  try { body = JSON.parse((await readBody(req, 2048)).toString('utf8')); }
  catch { return sendJSON(res, 400, { error: "Missing or invalid 'username'" }); }
  if (!body || !body.username) return sendJSON(res, 400, { error: "Missing or invalid 'username'" });
  const before = appConfig.Users.length;
  appConfig.Users = appConfig.Users.filter(u => u.username !== body.username);
  if (appConfig.Users.length === before) return sendJSON(res, 404, { error: 'User not found' });
  try { saveConfig(cfgFlags.configPath, appConfig); }
  catch (e) { return sendJSON(res, 500, { error: 'Removed in memory but failed to write config file: ' + e.message }); }
  log(`[INFO] Dashboard: đã xoá proxy user '${body.username}'`);
  recordAudit(actorFromRequest(req), 'delete_user', 'username=' + body.username);
  sendJSON(res, 200, { success: true });
}
async function dashboardTokens(req, res) {
  if (req.method === 'GET') {
    const out = (appConfig.APITokens || []).map(t => ({ name: t.name, created_at: t.created_at }));
    return sendJSON(res, 200, { tokens: out });
  }
  if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Only GET/POST is supported' });
  let body;
  try { body = JSON.parse((await readBody(req, 2048)).toString('utf8')); }
  catch { return sendJSON(res, 400, { error: 'Invalid JSON body' }); }
  const name = String(body.name || '').trim();
  if (!name) return sendJSON(res, 400, { error: 'Name required' });
  const token = generateAPIToken();
  if ((appConfig.APITokens || []).some(t => t.name === name)) {
    return sendJSON(res, 409, { error: 'A token with this name already exists — delete it first if you want to regenerate' });
  }
  appConfig.APITokens = appConfig.APITokens || [];
  appConfig.APITokens.push({ name, token_hash: hashAPIToken(token), created_at: Math.floor(Date.now() / 1000) });
  try { saveConfig(cfgFlags.configPath, appConfig); }
  catch (e) { return sendJSON(res, 500, { error: 'Saved in memory but failed to write config file: ' + e.message }); }
  log(`[INFO] Dashboard: đã tạo API token mới '${name}'`);
  recordAudit(actorFromRequest(req), 'create_api_token', 'name=' + name);
  sendJSON(res, 200, { success: true, token, name });
}
async function dashboardDeleteToken(req, res) {
  if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Only POST is supported' });
  let body;
  try { body = JSON.parse((await readBody(req, 2048)).toString('utf8')); }
  catch { return sendJSON(res, 400, { error: "Missing or invalid 'name'" }); }
  if (!body || !body.name) return sendJSON(res, 400, { error: "Missing or invalid 'name'" });
  const before = (appConfig.APITokens || []).length;
  appConfig.APITokens = (appConfig.APITokens || []).filter(t => t.name !== body.name);
  if (appConfig.APITokens.length === before) return sendJSON(res, 404, { error: 'Token not found' });
  try { saveConfig(cfgFlags.configPath, appConfig); }
  catch (e) { return sendJSON(res, 500, { error: 'Removed in memory but failed to write config file: ' + e.message }); }
  log(`[INFO] Dashboard: đã thu hồi API token '${body.name}'`);
  recordAudit(actorFromRequest(req), 'revoke_api_token', 'name=' + body.name);
  sendJSON(res, 200, { success: true });
}
async function dashboardAuditLog(req, res) { sendJSON(res, 200, { events: auditLog.slice().reverse() }); }
async function dashboardConfigExport(req, res) {
  recordAudit(actorFromRequest(req), 'export_config_backup', '');
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Content-Disposition': `attachment; filename=proxy_config_backup_${new Date().toISOString().replace(/[-:T.]/g, '').slice(0, 15)}.json`,
  });
  res.end(JSON.stringify(appConfig, null, 2));
}
async function dashboardConfigImport(req, res) {
  if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Only POST is supported' });
  let data;
  try { data = await readBody(req, 5 * 1024 * 1024); }
  catch { return sendJSON(res, 400, { error: 'Failed to read uploaded file' }); }
  let cfg;
  try { cfg = JSON.parse(data.toString('utf8')); }
  catch (e) { return sendJSON(res, 400, { error: 'Invalid JSON: ' + e.message }); }
  if (!cfg.DashboardUser || !cfg.DashboardPasswordHash) return sendJSON(res, 400, { error: 'File thiếu dashboard_user/dashboard_password_hash — không phải file backup hợp lệ' });
  try { saveConfig(cfgFlags.configPath, cfg); }
  catch (e) { return sendJSON(res, 500, { error: 'Failed to write config file: ' + e.message }); }
  const actor = actorFromRequest(req);
  const err = reloadConfig(actor);
  if (err) { recordAudit(actor, 'import_config_backup', 'failed: ' + err.message); return sendJSON(res, 500, { error: 'Đã ghi file nhưng reload thất bại: ' + err.message }); }
  recordAudit(actor, 'import_config_backup', `${(cfg.Users || []).length} users, ${(cfg.APITokens || []).length} tokens`);
  log('[INFO] Dashboard: đã restore config từ file backup upload');
  sendJSON(res, 200, { success: true });
}
async function dashboardReload(req, res) {
  if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Only POST is supported' });
  const actor = actorFromRequest(req);
  const err = reloadConfig(actor);
  if (err) { recordAudit(actor, 'reload_config', 'failed: ' + err.message); return sendJSON(res, 400, { error: err.message }); }
  recordAudit(actor, 'reload_config', 'success (manual)');
  sendJSON(res, 200, { success: true });
}
async function dashboardNetworkConfig(req, res) {
  if (req.method === 'GET') {
    return sendJSON(res, 200, {
      allow_list: appConfig.AllowList || [],
      deny_list: appConfig.DenyList || [],
      upstream_proxies: appConfig.UpstreamProxies || [],
    });
  }
  if (req.method !== 'POST') return sendJSON(res, 405, { error: 'Only GET/POST is supported' });
  let body;
  try { body = JSON.parse((await readBody(req, 65536)).toString('utf8')); }
  catch { return sendJSON(res, 400, { error: 'Invalid JSON body' }); }
  appConfig.AllowList = body.allow_list || [];
  appConfig.DenyList = body.deny_list || [];
  appConfig.UpstreamProxies = body.upstream_proxies || [];
  try { saveConfig(cfgFlags.configPath, appConfig); }
  catch (e) { return sendJSON(res, 500, { error: 'Saved in memory but failed to write config file: ' + e.message }); }
  const actor = actorFromRequest(req);
  const err = reloadConfig(actor);
  if (err) { recordAudit(actor, 'update_network_config', 'failed: ' + err.message); return sendJSON(res, 500, { error: 'Đã lưu file nhưng reload thất bại: ' + err.message }); }
  recordAudit(actor, 'update_network_config', `${(body.allow_list || []).length} allow, ${(body.deny_list || []).length} deny, ${(body.upstream_proxies || []).length} upstream`);
  sendJSON(res, 200, { success: true });
}
async function dashboardReloadHistory(req, res) { sendJSON(res, 200, { history: reloadHistory.slice().reverse() }); }
function dashboardStream(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });
  res.write(`event: history\ndata: ${JSON.stringify(statHistory.slice())}\n\n`);
  const queue = [];
  let closed = false;
  const ch = {
    push(sample) {
      if (closed) return false;
      if (queue.length < 32) { queue.push(sample); flush(); return true; }
      return false;
    },
  };
  const flush = () => {
    while (queue.length) {
      const s = queue.shift();
      try { res.write(`event: sample\ndata: ${JSON.stringify(s)}\n\n`); } catch {}
    }
  };
  sseClients.add(ch);
  const ka = setInterval(() => { try { res.write(': keepalive\n\n'); } catch {} }, 15000);
  req.on('close', () => { closed = true; clearInterval(ka); sseClients.delete(ch); });
}

// ======================== STATS DATA ========================
function getStats() {
  return {
    total: stats.Total, current: stats.Current, active: activeConns.size,
    socks5_tcp: stats.Socks5TCP, socks5_udp: stats.Socks5UDP, http: stats.HTTP,
    bytes_up: stats.BytesUp, bytes_down: stats.BytesDown,
    udp_up: stats.UDPUp, udp_down: stats.UDPDown,
    udp_assocs: udpAssocs.size,
    uptime: (Date.now() - stats.StartTime) / 1000,
  };
}
function getAllStats() {
  const data = getStats();
  const conns = [];
  for (const ci of activeConns.values()) {
    conns.push({
      id: ci.ID, ip: ci.IP, port: ci.Port, type: ci.Type, target: ci.Target,
      start_time: Math.floor(ci.StartTime / 1000),
      bytes_up: ci.BytesUp, bytes_down: ci.BytesDown,
      duration: (Date.now() - ci.StartTime) / 1000,
    });
  }
  data.active_connections = conns;
  const proxies = upstreamProxies.slice();
  data.upstream = {
    proxies,
    current_index: upstreamIndex,
    status: proxies.map(p => ({ addr: p, alive: isUpstreamAlive(p) })),
  };
  data.system = { cpu_percent: 0.0, memory_percent: 0.0, fd_limit: 10000 };
  const udpInfo = {};
  for (const [k, a] of udpAssocs) {
    try {
      udpInfo[k] = {
        client_addr: `${a.ClientAddr.ip}:${a.ClientAddr.port}`,
        relay_port: a.RelayConn.address().port,
        active: a.Active,
        last_activity: Math.floor(a.LastActivity / 1000),
        dest_count: a.DestMap.size,
      };
    } catch {}
  }
  data.udp_associations = udpInfo;
  return data;
}

// ======================== FORMAT ========================
function formatBytes(b) {
  if (b === undefined || b === null) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let u = 0;
  while (b >= 1024 && u < units.length - 1) { b /= 1024; u++; }
  return b.toFixed(1) + ' ' + units[u];
}

// ======================== PROXY LISTENER ========================
let proxyListener = null;
async function handleConn(socket) {
  socket.on('error', () => {});
  stats.Current++;
  stats.Total++;
  if (stats.Current > MAX_CONNECTIONS) { socket.destroy(); stats.Current--; return; }
  const remoteIP = (socket.remoteAddress || '').replace(/^::ffff:/, '');

  if (remoteIP && !isIPAllowed(remoteIP)) {
    log(`[WARN] IP ${remoteIP} bị từ chối bởi whitelist/blacklist`);
    socket.destroy(); stats.Current--; return;
  }
  if (remoteIP && isAuthBlocked(remoteIP)) {
    log(`[WARN] IP ${remoteIP} đang bị chặn do auth fail quá nhiều lần`);
    socket.destroy(); stats.Current--; return;
  }

  socket.setTimeout(HANDSHAKE_TIMEOUT, () => { try { socket.destroy(); } catch {} });
  const reader = new BufReader(socket);
  let first;
  try { first = await reader.readN(1); } catch { socket.destroy(); stats.Current--; return; }
  const b = first[0];

  // ★ TRẢ LẠI byte vừa peeked — thiếu dòng này là bug khiến mọi kết nối
  // SOCKS5/HTTP bị chết ngay sau khi connect (giống io.MultiReader trong Go).
  reader.unread(first);

  try {
    if (b === 0x05) await handleSOCKS5(socket, reader, remoteIP);
    else if ('CGPDHOT'.includes(String.fromCharCode(b))) await handleHTTP(socket, reader, remoteIP);
    else { log(`[WARN] Unknown protocol from ${socket.remoteAddress} (first byte 0x${b.toString(16)})`); socket.destroy(); }
  } catch (e) {
    log(`[ERROR] handleConn: ${e.message}`);
    try { socket.destroy(); } catch {}
  } finally {
    stats.Current--;
    try { socket.destroy(); } catch {}
  }
}
async function runProxyServer() {
  let tlsOpts = null;
  if (cfgFlags.certFile && cfgFlags.keyFile) {
    try {
      tlsOpts = { cert: fs.readFileSync(cfgFlags.certFile), key: fs.readFileSync(cfgFlags.keyFile), minVersion: 'TLSv1.2' };
    } catch (e) { throw new Error(`không load được TLS cert/key: ${e.message}`); }
  }
  proxyListener = tlsOpts
    ? tls.createServer(tlsOpts, (s) => handleConn(s))
    : net.createServer((s) => handleConn(s));

  await new Promise((resolve, reject) => {
    proxyListener.once('error', reject);
    proxyListener.listen(cfgFlags.port, cfgFlags.listenAddr, () => { proxyListener.removeListener('error', reject); resolve(); });
  });
  if (tlsOpts) log('[INFO] TLS đã bật cho listener chính');
  log(`[INFO] Proxy started on ${cfgFlags.listenAddr}:${cfgFlags.port}`);
  proxyListener.on('error', (e) => log(`[ERROR] Listener: ${e.message}`));
}

// ======================== DASHBOARD SERVER ========================
let dashboardServer = null;
function startDashboardServer() {
  const routes = {
    '/': dashboardIndex,
    '/stats': (req, res) => sendJSON(res, 200, getStats()),
    '/api/all': dashboardAll,
    '/api/change-password': dashboardChangePassword,
    '/api/users': dashboardUsers,
    '/api/users/delete': dashboardDeleteUser,
    '/api/reload': dashboardReload,
    '/api/network-config': dashboardNetworkConfig,
    '/api/reload-history': dashboardReloadHistory,
    '/api/stream': dashboardStream,
    '/api/kick': dashboardKick,
    '/api/export': dashboardExport,
    '/api/tokens': dashboardTokens,
    '/api/tokens/delete': dashboardDeleteToken,
    '/api/audit-log': dashboardAuditLog,
    '/api/config/export': dashboardConfigExport,
    '/api/config/import': dashboardConfigImport,
  };
  dashboardServer = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const path = u.pathname;
    if (path === '/healthz') return healthCheck(req, res);
    if (path === '/metrics') return metricsHandler(req, res);
    const handler = routes[path];
    if (handler) {
      dashboardAuth(handler)(req, res).catch(e => {
        log(`[ERROR] dashboard: ${e.message}`);
        try { res.writeHead(500); res.end('Internal error'); } catch {}
      });
      return;
    }
    res.writeHead(404); res.end('Not Found');
  });
  dashboardServer.listen(cfgFlags.dashboardPort, cfgFlags.dashboardBind, () => {
    log(`[INFO] Dashboard available at http://${cfgFlags.dashboardBind}:${cfgFlags.dashboardPort} (user: ${dashboardUser})`);
  });
  dashboardServer.on('error', e => log(`[WARN] Dashboard error: ${e.message}`));
}

// ======================== DASHBOARD HTML ========================
const dashboardHTML = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Proxy Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
:root{--bg:#0f0f1a;--fg:#e0e0e0;--container-bg:#14141f;--box-bg:#1a1a2e;--box-hover:#22223b;--border:#2a2a3a;--border2:#28283a;--th-bg:#1e1e32;--muted:#9999bb;--muted2:#b4b4d4;--accent:#f0c27a;--accent-solid:#f0c27a;--accent-contrast:#1a1a2e;--btn-bg:#2a2a3a;--btn-border:#3a3a52;--btn-hover:#33334a;--badge-bg:#2a2a4a;--badge-fg:#c0c0e0;--badge-socks5tcp-bg:#1e3a5f;--badge-socks5tcp-fg:#7dd3fc;--badge-socks5udp-bg:#3b1f4a;--badge-socks5udp-fg:#d8b4fe;--badge-http-bg:#2d4a2d;--badge-http-fg:#86efac;--danger-border:#7a3030;--danger-hover-bg:#4a1a1a;--danger-fg:#fca5a5;}
html[data-theme="light"]{--bg:#f4f4f9;--fg:#1c1c2a;--container-bg:#fff;--box-bg:#f0f0f7;--box-hover:#e6e6f2;--border:#dcdce8;--border2:#e4e4f0;--th-bg:#ececf5;--muted:#52526a;--muted2:#33334a;--accent:#8a5010;--accent-solid:#c67c1e;--accent-contrast:#fff;--btn-bg:#ececf5;--btn-border:#c8c8dc;--btn-hover:#e0e0ee;--badge-bg:#e4e4f4;--badge-fg:#3f3f66;--badge-socks5tcp-bg:#dbeafe;--badge-socks5tcp-fg:#1d4ed8;--badge-socks5udp-bg:#f3e8ff;--badge-socks5udp-fg:#7e22ce;--badge-http-bg:#dcfce7;--badge-http-fg:#15803d;--danger-border:#e5a5a5;--danger-hover-bg:#fde2e2;--danger-fg:#b91c1c;}
body{background:var(--bg);color:var(--fg);font-family:'Segoe UI','Roboto',monospace;padding:30px 20px;transition:background .2s,color .2s;}
.container{max-width:1400px;margin:0 auto;}
h1{font-size:2.2rem;font-weight:300;letter-spacing:1px;color:var(--accent);display:flex;align-items:center;gap:10px;}
h1 span{background:var(--btn-bg);padding:0 12px;border-radius:30px;font-size:.8rem;color:var(--muted);}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;margin:20px 0;}
.stat-box{background:var(--box-bg);padding:14px 16px;border-radius:12px;border-left:4px solid #6c6c9a;transition:.2s;}
.stat-box:hover{background:var(--box-hover);}
.stat-label{font-size:.8rem;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);}
.stat-value{font-size:1.7rem;font-weight:600;margin-top:4px;}
.stat-value.cyan{color:#0891b2;}.stat-value.green{color:#16a34a;}.stat-value.yellow{color:#ca8a04;}.stat-value.pink{color:#db2777;}.stat-value.orange{color:#ea580c;}.stat-value.purple{color:#7c3aed;}.stat-value.red{color:#dc2626;}
html[data-theme="dark"] .stat-value.cyan,html:not([data-theme]) .stat-value.cyan{color:#7dd3fc;}
html[data-theme="dark"] .stat-value.green,html:not([data-theme]) .stat-value.green{color:#86efac;}
html[data-theme="dark"] .stat-value.yellow,html:not([data-theme]) .stat-value.yellow{color:#fde047;}
html[data-theme="dark"] .stat-value.pink,html:not([data-theme]) .stat-value.pink{color:#f9a8d4;}
html[data-theme="dark"] .stat-value.orange,html:not([data-theme]) .stat-value.orange{color:#fdba74;}
html[data-theme="dark"] .stat-value.purple,html:not([data-theme]) .stat-value.purple{color:#c4b5fd;}
html[data-theme="dark"] .stat-value.red,html:not([data-theme]) .stat-value.red{color:#fca5a5;}
.section{margin-top:30px;background:var(--container-bg);border-radius:14px;padding:20px 20px 10px 20px;border:1px solid var(--border);}
.section-title-row{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:15px;}
.section-title{font-size:1.2rem;font-weight:400;color:var(--muted2);letter-spacing:.3px;}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
.toolbar input[type=text]{background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:6px 10px;color:var(--fg);font-size:.85rem;}
table{width:100%;border-collapse:collapse;font-size:.9rem;}
th{text-align:left;padding:10px 8px;background:var(--th-bg);color:var(--muted);font-weight:500;cursor:pointer;user-select:none;white-space:nowrap;}
th:hover{color:var(--accent);}
td{padding:8px 8px;border-bottom:1px solid var(--border2);}tr:hover td{background:var(--box-bg);}
.badge{display:inline-block;padding:2px 12px;border-radius:20px;font-size:.7rem;font-weight:600;background:var(--badge-bg);color:var(--badge-fg);}
.badge.socks5-tcp{background:var(--badge-socks5tcp-bg);color:var(--badge-socks5tcp-fg);}
.badge.socks5-udp{background:var(--badge-socks5udp-bg);color:var(--badge-socks5udp-fg);}
.badge.http{background:var(--badge-http-bg);color:var(--badge-http-fg);}
.header-bar{display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid var(--border);padding-bottom:15px;margin-bottom:10px;flex-wrap:wrap;gap:10px;}
.header-actions{display:flex;gap:8px;flex-wrap:wrap;}
.btn{background:var(--btn-bg);color:var(--fg);border:1px solid var(--btn-border);padding:8px 16px;border-radius:8px;cursor:pointer;font-size:.85rem;transition:.2s;}
.btn:hover{background:var(--btn-hover);border-color:var(--accent);}
.btn-sm{padding:4px 10px;font-size:.75rem;}
.btn-danger{border-color:var(--danger-border);color:var(--danger-fg);}
.btn-danger:hover{background:var(--danger-hover-bg);border-color:var(--danger-fg);color:var(--danger-fg);}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);align-items:center;justify-content:center;z-index:100;}
.modal-overlay.open{display:flex;}
.modal{background:var(--container-bg);border:1px solid var(--border);border-radius:14px;padding:24px;width:340px;max-width:90vw;}
.modal h2{font-size:1.1rem;font-weight:500;color:var(--accent);margin-bottom:16px;}
.modal label{display:block;font-size:.8rem;color:var(--muted);margin:12px 0 4px;}
.modal input{width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:9px 10px;color:var(--fg);font-size:.9rem;}
.modal input:focus{outline:none;border-color:var(--accent);}
.modal-actions{display:flex;gap:10px;margin-top:20px;}.modal-actions .btn{flex:1;}
.btn-primary{background:var(--accent-solid);color:var(--accent-contrast);border-color:var(--accent-solid);font-weight:600;}
.btn-primary:hover{filter:brightness(1.1);}
.modal-msg{margin-top:12px;font-size:.82rem;min-height:18px;}
.modal-msg.error{color:#dc2626;}.modal-msg.success{color:#16a34a;}
</style>
</head><body>
<div class="container">
  <div class="header-bar">
    <h1>⚡ Proxy Pro <span>v6.3</span></h1>
    <div class="header-actions">
      <button class="btn" id="themeToggleBtn" onclick="toggleTheme()">🌙 Theme</button>
      <button class="btn" onclick="openPwModal()">🔒 Change Password</button>
    </div>
  </div>
  <div id="statsGrid" class="stats-grid">Loading stats...</div>
  <div id="chartSection" class="section"><div class="section-title-row"><div class="section-title">📈 Real-time Traffic <span id="streamStatus" style="font-size:.75rem;color:var(--muted);">(connecting...)</span></div></div><canvas id="trafficChart" height="80"></canvas></div>
  <div id="connectionsSection" class="section"><div class="section-title-row"><div class="section-title">🔗 Active Connections</div><div class="toolbar"><input type="text" id="connFilter" placeholder="Filter..." oninput="renderConnections()"><button class="btn btn-sm" onclick="exportConns('csv')">⬇ CSV</button><button class="btn btn-sm" onclick="exportConns('json')">⬇ JSON</button></div></div><div id="connectionsTable">Loading...</div></div>
  <div id="upstreamSection" class="section"><div class="section-title">🌐 Upstream Proxies</div><div id="upstreamInfo">Loading...</div></div>
  <div id="usersSection" class="section"><div class="section-title-row"><div class="section-title">👤 Proxy Users</div><div class="toolbar"><button class="btn btn-sm" onclick="openUserModal()">+ Add / Update User</button></div></div><div id="usersTable">Loading...</div></div>
  <div id="networkSection" class="section"><div class="section-title-row"><div class="section-title">🌐 Network Rules</div><div class="toolbar"><button class="btn btn-sm" onclick="reloadFromDisk()">↻ Reload from disk</button></div></div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;">
      <div><label style="display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px;">Whitelist</label><textarea id="netAllow" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:.82rem;font-family:monospace;"></textarea></div>
      <div><label style="display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px;">Blacklist</label><textarea id="netDeny" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:.82rem;font-family:monospace;"></textarea></div>
      <div><label style="display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px;">Upstream proxies</label><textarea id="netUpstream" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:.82rem;font-family:monospace;"></textarea></div>
    </div>
    <div class="modal-msg" id="netMsg" style="margin-top:10px;"></div>
    <div style="margin-top:10px;"><button class="btn btn-primary" onclick="saveNetworkConfig()">Save & Apply Now</button></div>
  </div>
  <div id="reloadHistorySection" class="section"><div class="section-title-row"><div class="section-title">🕒 Reload History</div></div><div id="reloadHistoryTable">Loading...</div></div>
  <div id="tokensSection" class="section"><div class="section-title-row"><div class="section-title">🔑 API Tokens</div><div class="toolbar"><button class="btn btn-sm" onclick="openTokenModal()">+ Create Token</button></div></div><div style="font-size:.78rem;color:var(--muted);margin-bottom:10px;">Dùng <code>Authorization: Bearer &lt;token&gt;</code></div><div id="tokensTable">Loading...</div></div>
  <div id="auditSection" class="section"><div class="section-title-row"><div class="section-title">📋 Audit Log</div></div><div id="auditTable">Loading...</div></div>
  <div id="backupSection" class="section"><div class="section-title-row"><div class="section-title">💾 Backup / Restore</div></div><div class="toolbar"><a class="btn btn-sm" href="/api/config/export" download>⬇ Download Backup</a><input type="file" id="restoreFileInput" accept="application/json" style="display:none;" onchange="restoreConfig(event)"><button class="btn btn-sm" onclick="document.getElementById('restoreFileInput').click()">⬆ Restore from File</button></div><div class="modal-msg" id="backupMsg" style="margin-top:10px;"></div></div>
</div>
<div class="modal-overlay" id="tokenModalOverlay"><div class="modal"><h2>🔑 Create API Token</h2><form id="tokenForm" onsubmit="return submitTokenForm(event)"><label for="tName">Token name</label><input type="text" id="tName" required><div class="modal-msg" id="tokenMsg"></div><div id="tokenResultBox" style="display:none;margin-top:12px;padding:10px;background:var(--box-bg);border-radius:8px;border:1px solid var(--border);"><div style="font-size:.78rem;color:var(--danger-fg);margin-bottom:6px;">⚠️ Chỉ hiện MỘT LẦN:</div><code id="tokenResultValue" style="word-break:break-all;font-size:.8rem;"></code></div><div class="modal-actions"><button type="button" class="btn" onclick="closeTokenModal()">Close</button><button type="submit" class="btn btn-primary" id="tokenSubmitBtn">Create</button></div></form></div></div>
<div class="modal-overlay" id="userModalOverlay"><div class="modal"><h2>👤 Add / Update User</h2><form id="userForm" onsubmit="return submitUserForm(event)"><label for="uUsername">Username</label><input type="text" id="uUsername" required><label for="uPassword">Password</label><input type="password" id="uPassword" minlength="4"><label for="uBandwidth">Max bandwidth (KB/s)</label><input type="number" id="uBandwidth" min="0" value="0"><label for="uMaxConn">Max connections</label><input type="number" id="uMaxConn" min="0" value="0"><label for="uQuota">Monthly quota (MB)</label><input type="number" id="uQuota" min="0" value="0"><div class="modal-msg" id="userMsg"></div><div class="modal-actions"><button type="button" class="btn" onclick="closeUserModal()">Cancel</button><button type="submit" class="btn btn-primary">Save</button></div></form></div></div>
<div class="modal-overlay" id="pwModalOverlay"><div class="modal"><h2>🔒 Change Credentials</h2><form id="pwForm" onsubmit="return submitPwChange(event)"><label for="curPass">Current password</label><input type="password" id="curPass" required><label for="newUser">New username</label><input type="text" id="newUser"><label for="newPass">New password (min 8)</label><input type="password" id="newPass" minlength="8" required><label for="newPass2">Confirm</label><input type="password" id="newPass2" minlength="8" required><div class="modal-msg" id="pwMsg"></div><div class="modal-actions"><button type="button" class="btn" onclick="closePwModal()">Cancel</button><button type="submit" class="btn btn-primary">Save</button></div></form></div></div>
<script>
let lastConns=[],sortKey='start_time',sortDir='desc',trafficChart=null;const CHART_MAX_POINTS=150;
function initChart(){const ctx=document.getElementById('trafficChart').getContext('2d');trafficChart=new Chart(ctx,{type:'line',data:{labels:[],datasets:[{label:'Upload',data:[],borderColor:'#ea580c',backgroundColor:'rgba(234,88,12,.1)',tension:.3,pointRadius:0,borderWidth:2},{label:'Download',data:[],borderColor:'#0891b2',backgroundColor:'rgba(8,145,178,.1)',tension:.3,pointRadius:0,borderWidth:2}]},options:{responsive:true,animation:false,interaction:{mode:'index',intersect:false},scales:{x:{ticks:{color:'#999'},grid:{color:'#333'}},y:{ticks:{color:'#999',callback:v=>formatBytes(v)+'/s'},grid:{color:'#333'}}},plugins:{legend:{labels:{color:'#e0e0e0'}}}}});}
function pushChartSample(s){if(!trafficChart)return;const l=new Date(s.t*1000).toLocaleTimeString();trafficChart.data.labels.push(l);trafficChart.data.datasets[0].data.push(s.up_bps);trafficChart.data.datasets[1].data.push(s.down_bps);if(trafficChart.data.labels.length>CHART_MAX_POINTS){trafficChart.data.labels.shift();trafficChart.data.datasets[0].data.shift();trafficChart.data.datasets[1].data.shift();}trafficChart.update('none');}
function connectStream(){const s=document.getElementById('streamStatus');const es=new EventSource('/api/stream');es.addEventListener('history',e=>{try{JSON.parse(e.data).forEach(pushChartSample);s.textContent='(live)';s.style.color='#86efac';}catch(e){}});es.addEventListener('sample',e=>{try{pushChartSample(JSON.parse(e.data));}catch(e){}});es.onerror=()=>{s.textContent='(reconnecting...)';s.style.color='#fca5a5';};es.onopen=()=>{s.textContent='(live)';s.style.color='#86efac';};}
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);document.getElementById('themeToggleBtn').textContent=t==='light'?'☀️ Theme':'🌙 Theme';try{localStorage.setItem('dashboard-theme',t);}catch(e){}}
function toggleTheme(){const c=document.documentElement.getAttribute('data-theme')||'dark';applyTheme(c==='light'?'dark':'light');}
(function(){let s='dark';try{s=localStorage.getItem('dashboard-theme')||'dark';}catch(e){}applyTheme(s);})();
async function fetchAll(){try{const r=await fetch('/api/all');if(!r.ok)throw new Error(r.status);const d=await r.json();renderStats(d);lastConns=d.active_connections||[];renderConnections();renderUpstream(d.upstream||{});}catch(e){document.getElementById('statsGrid').innerHTML='<div style="color:#dc2626;">⚠️ Load failed</div>';}}
function renderStats(d){const b=[['Total',d.total,'cyan'],['Active',d.active,'green'],['SOCKS5 TCP',d.socks5_tcp,'cyan'],['SOCKS5 UDP',d.socks5_udp,'purple'],['HTTP',d.http,'green'],['UDP Assocs',d.udp_assocs||0,'yellow'],['Bytes Up',formatBytes(d.bytes_up),'orange'],['Bytes Down',formatBytes(d.bytes_down),'pink'],['UDP Up',formatBytes(d.udp_up),'yellow'],['UDP Down',formatBytes(d.udp_down),'purple'],['Uptime',formatUptime(d.uptime),'cyan']];document.getElementById('statsGrid').innerHTML=b.map(x=>'<div class="stat-box"><div class="stat-label">'+x[0]+'</div><div class="stat-value '+x[2]+'">'+x[1]+'</div></div>').join('');}
function sortConns(k){if(sortKey===k)sortDir=sortDir==='asc'?'desc':'asc';else{sortKey=k;sortDir='asc';}renderConnections();}
function renderConnections(){const f=(document.getElementById('connFilter').value||'').toLowerCase().trim();let c=lastConns.slice();if(f)c=c.filter(x=>(x.ip||'').toLowerCase().includes(f)||(x.target||'').toLowerCase().includes(f)||(x.type||'').toLowerCase().includes(f));c.sort((a,b)=>{let av=a[sortKey],bv=b[sortKey];if(typeof av==='string'){av=av.toLowerCase();bv=(bv||'').toLowerCase();}if(av<bv)return sortDir==='asc'?-1:1;if(av>bv)return sortDir==='asc'?1:-1;return 0;});if(!c.length){document.getElementById('connectionsTable').innerHTML='<div style="padding:15px;color:#999;">No active connections</div>';return;}const cols=[['ip','IP'],['port','Port'],['type','Type'],['target','Target'],['duration','Duration'],['bytes_up','Bytes Up'],['bytes_down','Bytes Down']];let th='<tr>';cols.forEach(x=>{let cl=sortKey===x[0]?(sortDir==='asc'?'':' style="color:var(--accent)"'):'';th+='<th'+cl+' onclick="sortConns(\\''+x[0]+'\\')">'+x[1]+'</th>';});th+='<th>Action</th></tr>';let h='<table><thead>'+th+'</thead><tbody>';c.forEach(x=>{let b='<span class="badge">'+esc(x.type)+'</span>';if(x.type==='SOCKS5_TCP')b='<span class="badge socks5-tcp">SOCKS5 TCP</span>';else if(x.type==='SOCKS5_UDP')b='<span class="badge socks5-udp">SOCKS5 UDP</span>';else if(x.type==='HTTP')b='<span class="badge http">HTTP</span>';h+='<tr><td>'+esc(x.ip)+'</td><td>'+x.port+'</td><td>'+b+'</td><td>'+esc(x.target||'N/A')+'</td><td>'+formatUptime(x.duration)+'</td><td>'+formatBytes(x.bytes_up)+'</td><td>'+formatBytes(x.bytes_down)+'</td><td><button class="btn btn-sm btn-danger" data-id="'+esc(x.id)+'" onclick="kickConn(this.dataset.id)">Kick</button></td></tr>';});h+='</tbody></table>';document.getElementById('connectionsTable').innerHTML=h;}
async function kickConn(id){if(!id)return;try{const r=await fetch('/api/kick',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});if(r.ok)fetchAll();else{const d=await r.json().catch(()=>({}));alert('Kick failed: '+(d.error||r.status));}}catch(e){alert(e.message);}}
function exportConns(f){window.location.href='/api/export?format='+encodeURIComponent(f);}
function renderUpstream(up){const st=up.status||[];let h='<div style="padding:8px 0;">';if(st.length){h+=st.map(s=>esc(s.addr)+' '+(s.alive?'<span class="badge" style="background:var(--badge-http-bg);color:var(--badge-http-fg);">alive</span>':'<span class="badge" style="background:var(--danger-hover-bg);color:var(--danger-fg);">dead</span>')).join(' | ');h+='<br><span style="font-size:.78rem;color:#999;">Index: '+up.current_index+'</span>';}else h+='<span style="color:#999;">No upstream.</span>';h+='</div>';document.getElementById('upstreamInfo').innerHTML=h;}
async function fetchNetworkConfig(){try{const r=await fetch('/api/network-config');if(!r.ok)throw new Error(r.status);const d=await r.json();document.getElementById('netAllow').value=(d.allow_list||[]).join('\\n');document.getElementById('netDeny').value=(d.deny_list||[]).join('\\n');document.getElementById('netUpstream').value=(d.upstream_proxies||[]).join('\\n');}catch(e){}}
function linesToList(t){return t.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);}
async function saveNetworkConfig(){const m=document.getElementById('netMsg');m.textContent='Saving...';try{const r=await fetch('/api/network-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({allow_list:linesToList(document.getElementById('netAllow').value),deny_list:linesToList(document.getElementById('netDeny').value),upstream_proxies:linesToList(document.getElementById('netUpstream').value)})});const d=await r.json();if(!r.ok){m.textContent=d.error;m.className='modal-msg error';return;}m.textContent='Saved.';m.className='modal-msg success';fetchReloadHistory();}catch(e){m.textContent=e.message;m.className='modal-msg error';}}
async function reloadFromDisk(){const m=document.getElementById('netMsg');m.textContent='Reloading...';try{const r=await fetch('/api/reload',{method:'POST',headers:{'Content-Type':'application/json'}});const d=await r.json();if(!r.ok){m.textContent=d.error;m.className='modal-msg error';return;}m.textContent='Reloaded.';m.className='modal-msg success';fetchNetworkConfig();fetchReloadHistory();}catch(e){m.textContent=e.message;m.className='modal-msg error';}}
async function fetchReloadHistory(){try{const r=await fetch('/api/reload-history');const d=await r.json();renderReloadHistory(d.history||[]);}catch(e){document.getElementById('reloadHistoryTable').innerHTML='<div style="padding:15px;color:#999;">Failed</div>';}}
function renderReloadHistory(h){if(!h.length){document.getElementById('reloadHistoryTable').innerHTML='<div style="padding:15px;color:#999;">None.</div>';return;}let out='<table><thead><tr><th>Time</th><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody>';h.forEach(e=>{const sb=e.success?'OK':'FAILED';const d=e.success?(e.allow_count+'a '+e.deny_count+'d '+e.upstream_count+'u '+e.user_count+'users'):esc(e.error||'');out+='<tr><td>'+new Date(e.t*1000).toLocaleString()+'</td><td>'+esc(e.source)+'</td><td>'+sb+'</td><td>'+d+'</td></tr>';});out+='</tbody></table>';document.getElementById('reloadHistoryTable').innerHTML=out;}
async function fetchTokens(){try{const r=await fetch('/api/tokens');const d=await r.json();renderTokens(d.tokens||[]);}catch(e){document.getElementById('tokensTable').innerHTML='<div style="padding:15px;color:#999;">Failed</div>';}}
function renderTokens(ts){if(!ts.length){document.getElementById('tokensTable').innerHTML='<div style="padding:15px;color:#999;">No tokens.</div>';return;}let h='<table><thead><tr><th>Name</th><th>Created</th><th>Action</th></tr></thead><tbody>';ts.forEach(t=>{h+='<tr><td>'+esc(t.name)+'</td><td>'+new Date(t.created_at*1000).toLocaleString()+'</td><td><button class="btn btn-sm btn-danger" data-name="'+esc(t.name)+'" onclick="deleteToken(this.dataset.name)">Revoke</button></td></tr>';});h+='</tbody></table>';document.getElementById('tokensTable').innerHTML=h;}
function openTokenModal(){document.getElementById('tokenMsg').textContent='';document.getElementById('tokenResultBox').style.display='none';document.getElementById('tokenForm').reset();document.getElementById('tName').disabled=false;document.getElementById('tokenSubmitBtn').style.display='inline-block';document.getElementById('tokenModalOverlay').classList.add('open');}
function closeTokenModal(){document.getElementById('tokenModalOverlay').classList.remove('open');fetchTokens();}
async function submitTokenForm(e){e.preventDefault();const m=document.getElementById('tokenMsg');try{const r=await fetch('/api/tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:document.getElementById('tName').value.trim()})});const d=await r.json();if(!r.ok){m.textContent=d.error;m.className='modal-msg error';return false;}document.getElementById('tokenResultValue').textContent=d.token;document.getElementById('tokenResultBox').style.display='block';document.getElementById('tName').disabled=true;document.getElementById('tokenSubmitBtn').style.display='none';}catch(e){m.textContent=e.message;m.className='modal-msg error';}return false;}
async function deleteToken(n){if(!confirm('Revoke "'+n+'"?'))return;try{const r=await fetch('/api/tokens/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})});if(r.ok)fetchTokens();}catch(e){alert(e.message);}}
async function fetchAuditLog(){try{const r=await fetch('/api/audit-log');const d=await r.json();renderAuditLog(d.events||[]);}catch(e){document.getElementById('auditTable').innerHTML='<div style="padding:15px;color:#999;">Failed</div>';}}
function renderAuditLog(ev){if(!ev.length){document.getElementById('auditTable').innerHTML='<div style="padding:15px;color:#999;">None.</div>';return;}let h='<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>';ev.forEach(e=>{h+='<tr><td>'+new Date(e.t*1000).toLocaleString()+'</td><td>'+esc(e.actor)+'</td><td>'+esc(e.action)+'</td><td>'+esc(e.details||'')+'</td></tr>';});h+='</tbody></table>';document.getElementById('auditTable').innerHTML=h;}
async function restoreConfig(e){const f=e.target.files[0];if(!f)return;const m=document.getElementById('backupMsg');if(!confirm('Restore from "'+f.name+'"?')){e.target.value='';return;}m.textContent='Restoring...';try{const t=await f.text();const r=await fetch('/api/config/import',{method:'POST',headers:{'Content-Type':'application/json'},body:t});const d=await r.json();if(!r.ok){m.textContent=d.error;m.className='modal-msg error';return;}m.textContent='Restored.';m.className='modal-msg success';setTimeout(()=>location.reload(),1500);}catch(err){m.textContent=err.message;m.className='modal-msg error';}finally{e.target.value='';}}
async function fetchUsers(){try{const r=await fetch('/api/users');const d=await r.json();renderUsers(d.users||[]);}catch(e){document.getElementById('usersTable').innerHTML='<div style="padding:15px;color:#999;">Failed</div>';}}
function renderUsers(us){if(!us.length){document.getElementById('usersTable').innerHTML='<div style="padding:15px;color:#999;">No users.</div>';return;}let h='<table><thead><tr><th>Username</th><th>Bandwidth</th><th>MaxConns</th><th>Quota</th><th>Used</th><th>Action</th></tr></thead><tbody>';us.forEach(u=>{const bw=u.max_bandwidth_bps>0?formatBytes(u.max_bandwidth_bps)+'/s':'Unlimited';const mc=u.max_connections>0?u.max_connections:'∞';const q=u.quota_bytes_per_month>0?formatBytes(u.quota_bytes_per_month):'Unlimited';h+='<tr><td>'+esc(u.username)+'</td><td>'+bw+'</td><td>'+mc+'</td><td>'+q+'</td><td>'+formatBytes(u.usage_bytes_this_month||0)+'</td><td><button class="btn btn-sm btn-danger" data-name="'+esc(u.username)+'" onclick="deleteUser(this.dataset.name)">Delete</button></td></tr>';});h+='</tbody></table>';document.getElementById('usersTable').innerHTML=h;}
function openUserModal(){document.getElementById('userMsg').textContent='';document.getElementById('userForm').reset();document.getElementById('userModalOverlay').classList.add('open');}
function closeUserModal(){document.getElementById('userModalOverlay').classList.remove('open');}
async function submitUserForm(e){e.preventDefault();const m=document.getElementById('userMsg');const bw=parseFloat(document.getElementById('uBandwidth').value)||0;const mc=parseInt(document.getElementById('uMaxConn').value)||0;const qm=parseFloat(document.getElementById('uQuota').value)||0;try{const r=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('uUsername').value.trim(),password:document.getElementById('uPassword').value,max_bandwidth_bps:Math.round(bw*1024),max_connections:mc,quota_bytes_per_month:Math.round(qm*1024*1024)})});const d=await r.json();if(!r.ok){m.textContent=d.error;m.className='modal-msg error';return false;}closeUserModal();fetchUsers();}catch(err){m.textContent=err.message;m.className='modal-msg error';}return false;}
async function deleteUser(u){if(!confirm('Delete "'+u+'"?'))return;try{const r=await fetch('/api/users/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})});if(r.ok)fetchUsers();}catch(e){alert(e.message);}}
function esc(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function formatBytes(b){if(b==null)return '0 B';const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++;}return b.toFixed(1)+' '+u[i];}
function formatUptime(s){if(!s)return '00:00:00';const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),x=Math.floor(s%60);return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(x).padStart(2,'0');}
function openPwModal(){document.getElementById('pwMsg').textContent='';document.getElementById('pwForm').reset();document.getElementById('pwModalOverlay').classList.add('open');}
function closePwModal(){document.getElementById('pwModalOverlay').classList.remove('open');}
async function submitPwChange(e){e.preventDefault();const m=document.getElementById('pwMsg');const cp=document.getElementById('curPass').value,nu=document.getElementById('newUser').value.trim(),np=document.getElementById('newPass').value,np2=document.getElementById('newPass2').value;if(np!==np2){m.textContent='Mismatch.';m.className='modal-msg error';return false;}if(np.length<8){m.textContent='Min 8.';m.className='modal-msg error';return false;}try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cp,new_username:nu,new_password:np})});const d=await r.json();if(!r.ok){m.textContent=d.error;m.className='modal-msg error';return false;}m.textContent='Changed!';m.className='modal-msg success';setTimeout(()=>location.reload(),1500);}catch(err){m.textContent=err.message;m.className='modal-msg error';}return false;}
fetchAll();fetchUsers();fetchNetworkConfig();fetchReloadHistory();fetchTokens();fetchAuditLog();
setInterval(fetchAll,5000);setInterval(fetchUsers,15000);setInterval(fetchReloadHistory,15000);setInterval(fetchAuditLog,15000);
function loadScript(src){return new Promise((res,rej)=>{const t=document.createElement('script');t.src=src;t.onload=()=>res();t.onerror=()=>rej(new Error(src));document.head.appendChild(t);});}
async function loadChartJS(){const urls=['https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js','https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js','https://unpkg.com/chart.js@4.4.4/dist/chart.umd.min.js'];for(const u of urls){try{await loadScript(u);if(typeof Chart!=='undefined')return true;}catch(e){}}return false;}
(async function(){try{const ok=await loadChartJS();if(!ok)throw new Error('no CDN');initChart();connectStream();}catch(err){const s=document.getElementById('streamStatus');if(s){s.textContent='(unavailable)';s.style.color='#fca5a5';}const c=document.getElementById('trafficChart');if(c)c.outerHTML='<div style="padding:20px;color:#fca5a5;">⚠️ Chart unavailable: '+err.message+'</div>';}})();
</script></body></html>`;

// ======================== MAIN ========================
async function main() {
  setupLogFile();
  if (cfgFlags.usagePath) loadUsage(cfgFlags.usagePath);

  let generatedPass = '';
  if (!fs.existsSync(cfgFlags.configPath) && !cfgFlags.initDashPass) {
    cfgFlags.initDashPass = generateAPIToken().slice(0, 16);
    generatedPass = cfgFlags.initDashPass;
  }
  let cfg, wasCreated;
  try { [cfg, wasCreated] = loadOrInitConfig(cfgFlags.configPath, cfgFlags.initDashUser, cfgFlags.initDashPass); }
  catch (e) { log(`[FATAL] Lỗi đọc config file: ${e.message}`); process.exit(1); }

  if (wasCreated && generatedPass) log(`[WARN] Dashboard lần đầu — user: ${cfgFlags.initDashUser} | password: ${generatedPass} (chỉ hiện MỘT LẦN)`);
  if (wasCreated) {
    for (const item of (cfgFlags.allowStr || '').split(',')) if (item.trim()) (cfg.AllowList = cfg.AllowList || []).push(item.trim());
    for (const item of (cfgFlags.denyStr || '').split(',')) if (item.trim()) (cfg.DenyList = cfg.DenyList || []).push(item.trim());
    for (const item of (cfgFlags.upstreamStr || '').split(',')) if (item.trim()) (cfg.UpstreamProxies = cfg.UpstreamProxies || []).push(item.trim());
    try { saveConfig(cfgFlags.configPath, cfg); }
    catch (e) { log(`[WARN] Không ghi được allow/deny/upstream: ${e.message}`); }
  }
  appConfig = cfg;
  dashboardUser = cfg.DashboardUser;
  dashboardPassHash = cfg.DashboardPasswordHash;
  allowedCIDRs = parseCIDRSlice(cfg.AllowList || []);
  deniedCIDRs = parseCIDRSlice(cfg.DenyList || []);
  upstreamProxies = (cfg.UpstreamProxies || []).slice();

  if (dashboardUser === 'admin' && verifyPassword('admin', dashboardPassHash)) {
    log('[WARN] Dashboard đang dùng tài khoản mặc định admin/admin — hãy đổi ngay');
  }

  try { await runProxyServer(); }
  catch (e) { log(`[FATAL] ${e.message}`); process.exit(1); }

  log(`[INFO] Upstreams: [${upstreamProxies.join(', ')}]`);
  log(`[INFO] Whitelist: ${allowedCIDRs.length} entries | Blacklist: ${deniedCIDRs.length} entries (config: ${cfgFlags.configPath})`);
  log(`[INFO] Gửi SIGHUP (kill -HUP ${process.pid}) để reload config không cần restart`);

  startDashboardServer();
  statsReporter();
  upstreamHealthChecker();

  process.on('SIGHUP', () => {
    log('[INFO] Nhận SIGHUP, đang reload config...');
    const err = reloadConfig('SIGHUP');
    if (err) log(`[WARN] Reload config thất bại: ${err.message}`);
  });

  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    log('[INFO] Graceful shutdown...');
    try { proxyListener && proxyListener.close(); } catch {}
    try { dashboardServer && dashboardServer.close(); } catch {}
    const n = activeConns.size;
    for (const ci of activeConns.values()) { if (ci.Conn) try { ci.Conn.destroy(); } catch {} }
    for (const a of udpAssocs.values()) { a.Active = false; try { a.RelayConn.close(); } catch {} }
    log(`[INFO] Đã đóng ${n} connection đang active. Thoát.`);
    if (cfgFlags.usagePath) saveUsage(cfgFlags.usagePath);
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch(e => { _err('[FATAL]', e); process.exit(1); });

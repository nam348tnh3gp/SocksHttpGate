#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Universal Proxy Pro v6.3.6 — Ruby port (full parity Python/Go/C/JS)
#
# Ruby 2.7+ (tested 3.x). Stdlib only:
#   socket, openssl, digest, json, securerandom, base64, ipaddr, thread, set, uri, cgi, time.
#
# Chạy:
#   ruby proxy.rb -p 1080 --dashboard-port 8081
#   ruby proxy.rb --help
#
# Đã port các fix v6.3.6 từ Python:
#   * CONNECT IPv6 không crash (parse [v6]:port)
#   * SOCKS5 UDP BND.ADDR = IP proxy (không phải client)
#   * Từ chối smuggling (CL+TE, multi-CL, TE bất thường)
#   * Buffered reader + forward byte client gửi sớm vào tunnel
#
# Lưu ý GIL: MRI release GVL cho IO (recv/send/select), nên proxy IO-bound
# scale tốt. Thread-per-connection đủ cho vài trăm conn/process.

require 'socket'
require 'openssl'
require 'digest'
require 'json'
require 'securerandom'

begin
  require 'base64'
rescue LoadError
  module Base64
    module_function
    def decode64(str)
      str = str.to_s
      str = str.gsub(/\s+/, '')
      str += '=' * ((4 - str.length % 4) % 4)
      str.unpack1('m0')
    end
    def encode64(bin); [bin].pack('m'); end
    def strict_decode64(str); str.unpack1('m0'); end
    def strict_encode64(bin); [bin].pack('m0'); end
  end
end

require 'ipaddr'
require 'thread'
require 'set'
require 'uri'
require 'cgi'
require 'time'

# ══════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════
SOCKS5_VER           = 5
SOCKS5_CMD_CONNECT   = 0x01
SOCKS5_CMD_UDP       = 0x03
HTTP_FIRST_BYTES     = 'CGPDAHOT'.bytes.to_set

MAX_CONNECTIONS      = 4000
CONNECTION_TIMEOUT   = 25
IDLE_TIMEOUT         = 180
HANDSHAKE_TIMEOUT    = 30
RETRY_ATTEMPTS       = 5
BUFFER_SIZE          = 65536
UDP_BUFFER_SIZE      = 65535
UDP_IDLE_TIMEOUT     = 120
DASHBOARD_PORT       = 8081
UDP_DEST_MAX         = 4096
HIST_MAX             = 300
DASH_MAX_SSE         = 16
HASH_ITERATIONS      = 200_000
AUTH_FAIL_THRESHOLD  = 5
DASH_AUTH_FAIL_THRESHOLD = 30
AUTH_FAIL_WINDOW     = 300
AUTH_BLOCK_SECONDS   = 900

GREEN  = "\e[92m"; YELLOW = "\e[93m"; RED = "\e[91m"
BLUE   = "\e[94m"; CYAN   = "\e[96m"; PURPLE = "\e[95m"; RESET = "\e[0m"

# ══════════════════════════════════════════════════════════════════════
# UTIL
# ══════════════════════════════════════════════════════════════════════
module Util
  module_function

  def log(msg)
    ts = Time.now.strftime('%H:%M:%S')
    $stdout.puts "#{BLUE}#{ts}#{RESET} │ #{msg}"
    $stdout.flush
  rescue Errno::EPIPE
  end

  def log_warn(msg); log("#{YELLOW}#{msg}#{RESET}"); end
  def log_err(msg);  log("#{RED}#{msg}#{RESET}");    end

  def normalize_ip(ip)
    ip.to_s.sub(/\A::ffff:/, '')
  end

  def format_bytes(b)
    b = b.to_f
    return format('%.1f B', b) if b < 1024
    units = %w[B KiB MiB GiB TiB PiB]
    i = 0
    while b >= 1024 && i < units.length - 1
      b /= 1024.0
      i += 1
    end
    format('%.1f %s', b, units[i])
  end

  def ct_equal(a, b)
    a = a.to_s.b
    b = b.to_s.b
    return false unless a.bytesize == b.bytesize
    diff = 0
    a.bytes.each_with_index { |x, i| diff |= (x ^ b.getbyte(i)) }
    diff.zero?
  end

  # ---------- Password hash (tương thích format Python/Go/C) ----------
  def pw_digest(password, salt, iterations)
    d = Digest::SHA256.digest(salt + password.to_s)
    (iterations - 1).times { d = Digest::SHA256.digest(d) }
    d
  end

  def hash_password(password, iterations = HASH_ITERATIONS)
    salt = SecureRandom.random_bytes(16)
    dg = pw_digest(password, salt, iterations)
    "#{iterations}:#{salt.unpack1('H*')}:#{dg.unpack1('H*')}"
  end

  def verify_password(password, stored)
    parts = stored.to_s.split(':')
    return false unless parts.size == 3
    iters = parts[0].to_i
    return false if iters <= 0 || iters > 5_000_000
    salt = [parts[1]].pack('H*')
    want = [parts[2]].pack('H*')
    return false unless want.bytesize == 32
    got = pw_digest(password, salt, iters)
    ct_equal(got, want)
  rescue StandardError
    false
  end

  PW_CACHE_TTL = 300
  @pw_cache      = {}
  @pw_cache_lock = Mutex.new

  def verify_password_cached(password, stored)
    key = Digest::SHA256.digest(stored.to_s + "\x00" + password.to_s)
    now = Time.now.to_f
    @pw_cache_lock.synchronize do
      exp = @pw_cache[key]
      return true if exp && exp > now
    end
    return false unless verify_password(password, stored)
    @pw_cache_lock.synchronize do
      @pw_cache.clear if @pw_cache.size >= 1024
      @pw_cache[key] = now + PW_CACHE_TTL
    end
    true
  end
end

# ══════════════════════════════════════════════════════════════════════
# SSRF / CIDR
# ══════════════════════════════════════════════════════════════════════
module SSRF
  module_function

  EXTRA_BLOCKED = %w[0.0.0.0/8 100.64.0.0/10 192.0.0.0/24 198.18.0.0/15].freeze

  def parse_cidrs(items)
    valid = []
    invalid = []
    (items || []).each do |it|
      s = it.to_s.strip
      next if s.empty?
      begin
        if s.include?('/')
          net = IPAddr.new(s)
        elsif s.include?(':')
          net = IPAddr.new("#{s}/128")
        else
          net = IPAddr.new("#{s}/32")
        end
        valid << net
      rescue StandardError
        invalid << s
      end
    end
    [valid, invalid]
  end

  def ip_in_nets?(ip_str, nets)
    ip = IPAddr.new(ip_str)
    nets.any? { |n| n.include?(ip) }
  rescue StandardError
    false
  end

  def blocked?(ip_str)
    ip = IPAddr.new(ip_str)
    return true if ip.loopback? || ip.private? || ip.link_local?
    # multicast / unspecified / reserved
    if ip.ipv4?
      return true if ip.to_i.zero?
      return true if ip.to_i >= 0xE000_0000  # multicast + reserved
    else
      return true if ip.to_i.zero?
    end
    EXTRA_BLOCKED.any? do |cidr|
      IPAddr.new(cidr).include?(ip)
    rescue StandardError
      false
    end
  rescue StandardError
    true
  end
end

# ══════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════
module State
  @stats = {
    start: Time.now.to_f, total: 0, current: 0,
    socks5_tcp: 0, socks5_udp: 0, http: 0, auth_fail: 0,
    bytes_up: 0, bytes_down: 0, udp_up: 0, udp_down: 0,
    udp_assocs: 0
  }
  @stats_lock = Mutex.new

  @active_conns = {}
  @active_lock  = Mutex.new

  @udp_assocs  = {}
  @udp_lock    = Mutex.new

  @cfg         = nil
  @cfg_lock    = Mutex.new

  @allowed_cidrs = []
  @denied_cidrs  = []
  @cidr_lock     = Mutex.new

  @upstream_proxies = []
  @upstream_index   = 0
  @upstream_lock    = Mutex.new
  @upstream_health  = {}
  @upstream_health_lock = Mutex.new

  @audit_log    = []
  @audit_lock   = Mutex.new
  @reload_hist  = []
  @reload_lock  = Mutex.new

  @usage       = {}
  @usage_lock  = Mutex.new

  @fail_counts  = {}
  @fail_last    = {}
  @blocked_until= {}
  @fail_lock    = Mutex.new

  @hist_sample  = []
  @hist_lock    = Mutex.new
  @sse_clients  = Set.new
  @sse_lock     = Mutex.new

  @conn_id_counter = 0
  @conn_id_lock    = Mutex.new

  @shutdown_flag = false

  class << self
    attr_accessor :shutdown_flag
    attr_reader :stats_lock, :active_lock, :udp_lock, :cfg_lock,
                :cidr_lock, :upstream_lock, :upstream_health_lock,
                :audit_lock, :reload_lock, :usage_lock, :fail_lock,
                :hist_lock, :sse_lock, :conn_id_lock

    def stats;         @stats;         end
    def active_conns;  @active_conns;  end
    def udp_assocs;    @udp_assocs;    end
    def cfg;           @cfg;           end
    def cfg=(v);       @cfg = v;       end
    def allowed_cidrs; @allowed_cidrs; end
    def denied_cidrs;  @denied_cidrs;  end
    def allowed_cidrs=(v); @allowed_cidrs = v; end
    def denied_cidrs=(v);  @denied_cidrs  = v; end
    def upstream_proxies;  @upstream_proxies; end
    def upstream_proxies=(v); @upstream_proxies = v; end
    def upstream_index;    @upstream_index; end
    def upstream_index=(v); @upstream_index = v; end
    def upstream_health;   @upstream_health; end
    def audit_log;         @audit_log;      end
    def reload_hist;       @reload_hist;    end
    def usage;             @usage;          end
    def fail_counts;       @fail_counts;    end
    def fail_last;         @fail_last;      end
    def blocked_until;     @blocked_until;  end
    def hist_sample;       @hist_sample;    end
    def sse_clients;       @sse_clients;    end

    def next_conn_id
      @conn_id_lock.synchronize { "c#{@conn_id_counter += 1}" }
    end
  end
end

# ══════════════════════════════════════════════════════════════════════
# APP CONFIG
# ══════════════════════════════════════════════════════════════════════
class AppConfig
  attr_accessor :dashboard_user, :dashboard_password_hash,
                :users, :allow_list, :deny_list,
                :upstream_proxies, :api_tokens, :require_proxy_auth

  def initialize(data = {})
    data ||= {}
    @dashboard_user          = data['dashboard_user'] || data[:dashboard_user] || ''
    @dashboard_password_hash = data['dashboard_password_hash'] || data[:dashboard_password_hash] || ''
    @users                   = data['users'] || data[:users] || []
    @allow_list              = data['allow_list'] || data[:allow_list] || []
    @deny_list               = data['deny_list'] || data[:deny_list] || []
    @upstream_proxies        = data['upstream_proxies'] || data[:upstream_proxies] || []
    @api_tokens              = data['api_tokens'] || data[:api_tokens] || []
    @require_proxy_auth      = !!(data['require_proxy_auth'] || data[:require_proxy_auth])
  end

  def to_h
    h = {
      'dashboard_user' => @dashboard_user,
      'dashboard_password_hash' => @dashboard_password_hash
    }
    h['users']              = @users              if @users.any?
    h['allow_list']         = @allow_list         if @allow_list.any?
    h['deny_list']          = @deny_list          if @deny_list.any?
    h['upstream_proxies']   = @upstream_proxies   if @upstream_proxies.any?
    h['api_tokens']         = @api_tokens         if @api_tokens.any?
    h['require_proxy_auth'] = true                if @require_proxy_auth
    h
  end
end

# ══════════════════════════════════════════════════════════════════════
# CONFIG FILE I/O
# ══════════════════════════════════════════════════════════════════════
module ConfigFile
  module_function

  def save_locked(path, cfg)
    tmp = "#{path}.tmp"
    File.write(tmp, JSON.pretty_generate(cfg.to_h))
    File.chmod(0o600, tmp)
    File.rename(tmp, path)
    nil
  rescue StandardError => e
    e.message
  end

  def load_or_init(path, fb_user, fb_pass)
    if File.exist?(path)
      data = JSON.parse(File.read(path))
      c = AppConfig.new(data)
      raise "thiếu dashboard_user/dashboard_password_hash" if c.dashboard_user.empty? || c.dashboard_password_hash.empty?
      return [c, false]
    end
    c = AppConfig.new(
      'dashboard_user' => fb_user,
      'dashboard_password_hash' => Util.hash_password(fb_pass)
    )
    State.cfg_lock.synchronize { save_locked(path, c) }
    [c, true]
  end

  def reload!(path)
    ev = { 't' => Time.now.to_i, 'success' => false }
    data = JSON.parse(File.read(path))
    new_cfg = AppConfig.new(data)
    raise "thiếu dashboard_user/dashboard_password_hash" if new_cfg.dashboard_user.empty? || new_cfg.dashboard_password_hash.empty?

    na, ia = SSRF.parse_cidrs(new_cfg.allow_list)
    nd, id = SSRF.parse_cidrs(new_cfg.deny_list)

    State.cidr_lock.synchronize do
      State.allowed_cidrs = na
      State.denied_cidrs  = nd
    end

    State.upstream_lock.synchronize do
      ups = []
      new_cfg.upstream_proxies.each do |it|
        next unless it.include?(':')
        h, p = it.rsplit(':', 1) rescue it.rpartition(':').values_at(0, 2)
        h, p = it.rpartition(':').values_at(0, 2)
        begin
          ups << [h, Integer(p)]
        rescue ArgumentError
        end
      end
      State.upstream_proxies = ups
      State.upstream_index = 0 if State.upstream_index >= ups.size
    end

    State.cfg_lock.synchronize do
      State.cfg = new_cfg
      lim_map = new_cfg.users.each_with_object({}) do |u, h|
        h[u['username']] = (u['max_bandwidth_bps'] || 0).to_i
      end
      State.active_lock.synchronize do
        State.active_conns.each_value do |c|
          c.rate_bps = lim_map[c.username] if lim_map.key?(c.username)
        end
      end
    end

    ev['success'] = true
    ev['allow_count'] = na.size
    ev['deny_count']  = nd.size
    ev['upstream_count'] = State.upstream_proxies.size
    ev['user_count'] = new_cfg.users.size
    ev['invalid_cidrs'] = (ia + id) if (ia + id).any?
    State.reload_lock.synchronize do
      State.reload_hist << ev
      State.reload_hist.shift while State.reload_hist.size > 30
    end
    Util.log "Đã reload config: #{na.size} allow, #{nd.size} deny, " \
             "#{State.upstream_proxies.size} upstream, #{new_cfg.users.size} user"
    true
  rescue StandardError => e
    ev['error'] = e.message
    State.reload_lock.synchronize do
      State.reload_hist << ev
      State.reload_hist.shift while State.reload_hist.size > 30
    end
    Util.log_err "Reload config fail: #{e.message}"
    false
  end
end

# ══════════════════════════════════════════════════════════════════════
# USAGE (quota tháng)
# ══════════════════════════════════════════════════════════════════════
module Usage
  module_function

  def current_period; Time.now.strftime('%Y-%m'); end

  def get(username)
    return 0 if username.to_s.empty?
    per = current_period
    State.usage_lock.synchronize do
      r = State.usage[username]
      return 0 unless r && r['period'] == per
      r['bytes_used'].to_i
    end
  end

  def add(username, n)
    return if username.to_s.empty? || n.to_i <= 0
    per = current_period
    State.usage_lock.synchronize do
      r = State.usage[username]
      unless r && r['period'] == per
        r = { 'period' => per, 'bytes_used' => 0 }
        State.usage[username] = r
      end
      r['bytes_used'] = r['bytes_used'].to_i + n.to_i
    end
  end

  def load!(path)
    return unless path && File.exist?(path)
    data = JSON.parse(File.read(path))
    State.usage_lock.synchronize { State.usage = data } if data.is_a?(Hash)
  rescue StandardError => e
    Util.log_warn "Usage file lỗi, bỏ qua: #{e.message}"
  end

  def save!(path)
    return if path.to_s.empty?
    snap = State.usage_lock.synchronize { State.usage.dup }
    tmp = "#{path}.tmp"
    File.write(tmp, JSON.pretty_generate(snap))
    File.rename(tmp, path)
  rescue StandardError => e
    Util.log_warn "Không lưu được usage: #{e.message}"
  end
end

# ══════════════════════════════════════════════════════════════════════
# AUTH FAIL (brute-force)
# ══════════════════════════════════════════════════════════════════════
module AuthFail
  module_function

  def record(ip, threshold)
    now = Time.now.to_f
    State.fail_lock.synchronize do
      last = State.fail_last[ip]
      if last && now - last < 2.0
        return
      end
      State.fail_counts[ip] = 0 if last && now - last > AUTH_FAIL_WINDOW
      State.fail_last[ip] = now
      State.fail_counts[ip] = (State.fail_counts[ip] || 0) + 1
      if State.fail_counts[ip] >= threshold
        State.blocked_until[ip] = now + AUTH_BLOCK_SECONDS
        State.fail_counts[ip] = 0
        Util.log_warn "IP #{ip} bị chặn #{AUTH_BLOCK_SECONDS}s do sai xác thực nhiều lần"
      end
    end
  end

  def reset(ip)
    State.fail_lock.synchronize do
      State.fail_counts.delete(ip)
      State.fail_last.delete(ip)
      State.blocked_until.delete(ip)
    end
  end

  def blocked?(ip)
    State.fail_lock.synchronize do
      until_t = State.blocked_until[ip]
      return false unless until_t
      if Time.now.to_f > until_t
        State.blocked_until.delete(ip)
        return false
      end
      true
    end
  end
end

def ip_allowed?(ip_str)
  allow = State.allowed_cidrs
  deny  = State.denied_cidrs
  return false if SSRF.ip_in_nets?(ip_str, deny)
  return true  if allow.empty?
  SSRF.ip_in_nets?(ip_str, allow)
end

# ══════════════════════════════════════════════════════════════════════
# CONNECTION INFO
# ══════════════════════════════════════════════════════════════════════
class ConnectionInfo
  attr_accessor :id, :ip, :port, :conn_type, :target, :start_time,
                :rate_bps, :username, :conn, :sock_fd
  attr_reader   :bytes_up, :bytes_down

  def initialize(id, ip, port, conn_type, target, rate_bps = 0, username = '', conn = nil)
    @id = id; @ip = ip; @port = port
    @conn_type = conn_type; @target = target
    @start_time = Time.now.to_f
    @bytes_up = 0; @bytes_down = 0
    @rate_bps = rate_bps; @username = username; @conn = conn
    @lock = Mutex.new
  end

  def add_up(n);   return if n <= 0; @lock.synchronize { @bytes_up += n }; end
  def add_down(n); return if n <= 0; @lock.synchronize { @bytes_down += n }; end

  def snapshot
    @lock.synchronize { [@bytes_up, @bytes_down] }
  end
end

# ══════════════════════════════════════════════════════════════════════
# BUFFERED READER
# ══════════════════════════════════════════════════════════════════════
class BufReader
  def initialize(sock); @sock = sock; @buf = +''.b; end

  def has_data?; !@buf.empty?; end
  def peek_all;  @buf.dup; end
  def clear;     @buf.clear; end

  def fill(want = 1)
    while @buf.bytesize < want
      begin
        chunk = @sock.recv(4096)
      rescue IOError, SystemCallError
        return false
      end
      return false if chunk.nil? || chunk.empty?
      @buf << chunk
    end
    true
  end

  def read_exact(n)
    return ''.b if n <= 0
    return nil unless fill(n)
    out = @buf.byteslice(0, n)
    @buf = @buf.byteslice(n..-1) || +''.b
    out
  end

  def read_one
    return nil unless fill(1)
    b = @buf.getbyte(0)
    @buf = @buf.byteslice(1..-1) || +''.b
    b
  end

  def read_line(max = 8192)
    loop do
      idx = @buf.index("\n")
      if idx
        line = @buf.byteslice(0, idx)
        @buf = @buf.byteslice(idx + 1..-1) || +''.b
        line = line.byteslice(0, line.bytesize - 1) if line.end_with?("\r")
        return line
      end
      return nil if @buf.bytesize > max
      begin
        chunk = @sock.recv(4096)
      rescue IOError, SystemCallError
        return nil
      end
      return nil if chunk.nil? || chunk.empty?
      @buf << chunk
    end
  end
end

# ══════════════════════════════════════════════════════════════════════
# UPSTREAM (round-robin + health)
# ══════════════════════════════════════════════════════════════════════
module Upstream
  module_function

  def healthy?(addr)
    State.upstream_health_lock.synchronize do
      State.upstream_health.fetch(addr, true)
    end
  end

  def set_health(addr, alive)
    State.upstream_health_lock.synchronize { State.upstream_health[addr] = alive }
  end

  def try_connect(host, port)
    s = Socket.tcp(host, port, connect_timeout: CONNECTION_TIMEOUT)
    s.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, 1)
    s
  rescue StandardError
    nil
  end

  def connect_target(host, port)
    ups, start = State.upstream_lock.synchronize do
      [State.upstream_proxies.dup, State.upstream_index]
    end

    unless ups.empty?
      alive_n = ups.count { |u| healthy?("#{u[0]}:#{u[1]}") }
      ups.size.times do |i|
        idx = (start + i) % ups.size
        uh, up = ups[idx]
        key = "#{uh}:#{up}"
        next if alive_n > 0 && !healthy?(key)
        State.upstream_lock.synchronize do
          State.upstream_index = (idx + 1) % [State.upstream_proxies.size, 1].max
        end
        s = try_connect(uh, up)
        if s
          set_health(key, true)
          return s
        end
        set_health(key, false)
      end
    end

    resolved = resolve_target(host, port)
    return nil if resolved.nil?
    resolved.each do |ip, p|
      2.times do
        s = try_connect(ip, p)
        return s if s
        sleep 0.5
      end
    end
    nil
  end

  def resolve_target(host, port)
    begin
      ip = IPAddr.new(host)
      return nil if SSRF.blocked?(ip.to_s)
      return [[ip.to_s, port]]
    rescue IPAddr::InvalidAddressError
    end
    infos = Socket.getaddrinfo(host, port, nil, Socket::SOCK_STREAM)
    infos.map do |_, _, ip, _, sa|
      begin
        addr = IPAddr.new(ip)
        return nil if SSRF.blocked?(addr.to_s)
        [sa.ip_address, sa.ip_port]
      rescue StandardError
        nil
      end
    end.compact
  rescue SocketError
    nil
  end
end

# ══════════════════════════════════════════════════════════════════════
# PROXY HANDLER
# ══════════════════════════════════════════════════════════════════════
class ProxyHandler
  def initialize(sock, peer_addrinfo, server_opts)
    @sock = sock
    @cip  = Util.normalize_ip(peer_addrinfo.ip_address)
    @cport = peer_addrinfo.ip_port
    @opts = server_opts
    @reader = BufReader.new(sock)
    @ci = nil
  end

  def handle
    State.stats_lock.synchronize do
      return if State.stats[:current] >= MAX_CONNECTIONS
      State.stats[:total]   += 1
      State.stats[:current] += 1
    end

    unless ip_allowed?(@cip)
      Util.log_warn "IP #{@cip} bị từ chối (whitelist/blacklist)"
      return
    end
    if AuthFail.blocked?(@cip)
      Util.log_warn "IP #{@cip} đang bị chặn do auth fail"
      return
    end

    begin
      @sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO,
                       [HANDSHAKE_TIMEOUT, 0].pack('l_2'))
    rescue StandardError
    end

    return unless @reader.fill(1)
    fb = @reader.peek_all.getbyte(0)

    if fb == SOCKS5_VER
      handle_socks5
    elsif HTTP_FIRST_BYTES.include?(fb)
      State.stats_lock.synchronize { State.stats[:http] += 1 }
      handle_http
    else
      Util.log_warn "Unknown protocol từ #{@cip}:#{@cport} (byte=#{format('0x%02x', fb)})"
    end
  rescue StandardError => e
    Util.log_err "Handler error #{@cip}:#{@cport} → #{e.class}: #{e.message}"
  ensure
    State.stats_lock.synchronize { State.stats[:current] -= 1 }
    begin
      @sock.close unless @sock.closed?
    rescue StandardError
    end
  end

  # ────────────────────────────── SOCKS5 ──────────────────────────────
  def handle_socks5
    hdr = @reader.read_exact(2)
    return unless hdr
    ver, nm = hdr.getbyte(0), hdr.getbyte(1)
    return unless ver == 5
    methods = nm > 0 ? @reader.read_exact(nm) : ''.b
    return unless methods

    need_auth = auth_required?
    want = need_auth ? 0x02 : 0x00
    return @sock.write("\x05\xff".b) unless methods.bytes.include?(want)
    @sock.write([5, want].pack('CC'))

    username = ''
    rate_bps = 0
    if need_auth
      ok, rate_bps, username = socks5_auth
      return unless ok
      allowed, reason = check_user_limits(username)
      unless allowed
        Util.log_warn "SOCKS5 từ chối user '#{username}': #{reason}"
        socks5_reply(0x02)
        return
      end
    end

    req = @reader.read_exact(4)
    return unless req
    ver, cmd, _rsv, atyp = req.bytes
    return unless ver == 5

    if cmd == SOCKS5_CMD_CONNECT
      host, port = read_addr(atyp)
      return socks5_reply(0x04) unless host
      target = "#{host}:#{port}"
      Util.log "#{GREEN}SOCKS5 TCP → #{@cip}:#{@cport} → #{target}#{RESET}"

      clear_timeout
      remote = Upstream.connect_target(host, port)
      return socks5_reply(0x05) unless remote
      bnd = remote.addr
      socks5_reply(0x00, bnd[3], bnd[1])
      @ci = ConnectionInfo.new(State.next_conn_id, @cip, @cport, 'SOCKS5_TCP',
                               target, rate_bps, username, @sock)
      State.active_lock.synchronize { State.active_conns[@ci.id] = @ci }
      State.stats_lock.synchronize { State.stats[:socks5_tcp] += 1 }
      initial = @reader.peek_all
      @reader.clear
      tunnel(@sock, remote, @ci, initial)
    elsif cmd == SOCKS5_CMD_UDP
      return socks5_reply(0x07) unless @opts[:enable_udp]
      handle_udp_associate(username, rate_bps, atyp)
    else
      socks5_reply(0x07)
    end
  ensure
    State.active_lock.synchronize { State.active_conns.delete(@ci.id) } if @ci
  end

  # ─────────────────────── SOCKS5 UDP ASSOCIATE ───────────────────────
  def handle_udp_associate(username, rate_bps, atyp)
    host, port = read_addr(atyp)
    target = host ? "UDP:#{host}:#{port}" : 'UDP:any'
    Util.log "#{PURPLE}UDP Associate → #{@cip}:#{@cport} → #{target}#{RESET}"

    tcp_family = @sock.local_address.ipv6? ? Socket::AF_INET6 : Socket::AF_INET
    relay = UDPSocket.new(tcp_family)
    begin
      relay.bind(tcp_family == Socket::AF_INET6 ? '::' : '0.0.0.0', 0)
    rescue StandardError => e
      Util.log_err "UDP relay bind failed: #{e.message}"
      return socks5_reply(0x01)
    end
    relay_port = relay.addr[1]

    key = "#{@cip}:#{@cport}:#{relay_port}"
    ci = ConnectionInfo.new(State.next_conn_id, @cip, @cport, 'SOCKS5_UDP',
                            target, rate_bps, username, @sock)
    State.udp_lock.synchronize do
      State.udp_assocs[key] = {
        client_addr: [@cip, @cport],
        relay_port: relay_port,
        active: true,
        last_activity: Time.now.to_f,
        dest_count: 0,
        username: username
      }
    end
    State.active_lock.synchronize { State.active_conns[ci.id] = ci }
    State.stats_lock.synchronize do
      State.stats[:udp_assocs] += 1
      State.stats[:socks5_udp] += 1
    end

    # FIX v6.3.6: BND.ADDR là IP PROXY (local sock addr), không phải client IP.
    proxy_ip = @sock.addr[3]
    socks5_reply(0x00, proxy_ip, relay_port)
    Util.log "#{PURPLE}UDP reply sent → client dùng #{Util.normalize_ip(proxy_ip)}:#{relay_port}#{RESET}"

    clear_timeout
    udp_loop(relay, ci, key)
  ensure
    begin; relay.close if relay; rescue StandardError; end
    State.udp_lock.synchronize { State.udp_assocs.delete(key) } if key
    State.active_lock.synchronize { State.active_conns.delete(ci.id) } if ci
    State.stats_lock.synchronize do
      State.stats[:udp_assocs] -= 1 if State.stats[:udp_assocs] > 0
    end
  end

  def udp_loop(relay, ci, key)
    client_udp = nil
    dest_map = {}
    last_activity = Time.now.to_f

    while !State.shutdown_flag
      if Time.now.to_f - last_activity > UDP_IDLE_TIMEOUT
        Util.log "UDP association idle-expired (#{@cip}:#{@cport})"
        break
      end

      ready = IO.select([@sock, relay], nil, nil, 1.0)
      next unless ready

      if ready[0].include?(@sock)
        begin
          d = @sock.recv_nonblock(1024)
          if d.empty?
            Util.log "UDP control TCP closed (#{@cip}:#{@cport})"
            return
          end
        rescue IO::WaitReadable
        rescue StandardError
          return
        end
      end

      next unless ready[0].include?(relay)

      begin
        data, addr, _flags, _dest = relay.recvmsg(UDP_BUFFER_SIZE)
      rescue StandardError
        next
      end
      last_activity = Time.now.to_f
      State.udp_lock.synchronize do
        rec = State.udp_assocs[key]
        rec[:last_activity] = last_activity if rec
      end

      addr_ip = Util.normalize_ip(addr.ip_address)
      if client_udp.nil?
        next unless addr_ip == @cip
        client_udp = addr
        Util.log "#{PURPLE}UDP client learned: #{addr.ip_address}:#{addr.ip_port}#{RESET}"
      end

      if addr.ip_address == client_udp.ip_address && addr.ip_port == client_udp.ip_port
        udp_to_dest(relay, data, dest_map, ci, key)
      else
        udp_to_client(relay, data, addr, client_udp, dest_map, ci)
      end
    end
  end

  def udp_to_dest(relay, data, dest_map, ci, key)
    return if data.bytesize < 4 || data.getbyte(2) != 0
    atyp = data.getbyte(3)
    pos = 4
    case atyp
    when 1
      return if data.bytesize < pos + 6
      host = data.byteslice(pos, 4).bytes.join('.')
      pos += 4
    when 3
      return if data.bytesize < pos + 1
      ln = data.getbyte(pos); pos += 1
      return if ln.zero? || data.bytesize < pos + ln + 2
      host = data.byteslice(pos, ln)
      return unless host.ascii_only?
      host = host.force_encoding('ascii').encode('UTF-8')
      pos += ln
    when 4
      return if data.bytesize < pos + 18
      host = IPAddr.new_ntoh(data.byteslice(pos, 16)).to_s
      pos += 16
    else
      return
    end
    port = data.byteslice(pos, 2).unpack1('n'); pos += 2
    payload = data.byteslice(pos..-1)

    dest_ip = resolve_udp_target(host, port)
    return Util.log_warn("#{RED}UDP relay bỏ target bị chặn: #{host}:#{port}#{RESET}") unless dest_ip

    begin
      relay.send(payload, 0, dest_ip, port)
    rescue StandardError => e
      Util.log_warn "#{RED}UDP sendto #{dest_ip}:#{port} failed: #{e.message}#{RESET}"
      return
    end

    dest_map.clear if dest_map.size >= UDP_DEST_MAX
    is_new = !dest_map.key?([dest_ip, port])
    dest_map[[dest_ip, port]] = Time.now.to_f

    if is_new
      State.udp_lock.synchronize do
        rec = State.udp_assocs[key]
        rec[:dest_count] = dest_map.size if rec
      end
    end

    State.stats_lock.synchronize { State.stats[:udp_up] += payload.bytesize }
    Usage.add(ci.username, payload.bytesize)
  end

  def udp_to_client(relay, data, remote_addr, client_udp, dest_map, ci)
    remote_ip = Util.normalize_ip(remote_addr.ip_address)
    return unless dest_map.key?([remote_ip, remote_addr.ip_port])

    begin
      if remote_ip.include?(':')
        atyp = 4; bin_addr = IPAddr.new(remote_ip).hton
      else
        atyp = 1; bin_addr = remote_ip.split('.').map(&:to_i).pack('C4')
      end
      hdr = [0, 0, atyp].pack('CC C') + bin_addr + [remote_addr.ip_port].pack('n')
      relay.send(hdr + data, 0, client_udp.ip_address, client_udp.ip_port)
    rescue StandardError => e
      Util.log_warn "#{RED}UDP reply→client failed: #{e.message}#{RESET}"
      return
    end
    State.stats_lock.synchronize { State.stats[:udp_down] += data.bytesize }
    Usage.add(ci.username, data.bytesize)
  end

  def resolve_udp_target(host, port)
    begin
      ip = IPAddr.new(host)
      return nil if SSRF.blocked?(ip.to_s)
      return ip.to_s
    rescue IPAddr::InvalidAddressError
    end
    Socket.getaddrinfo(host, port, nil, Socket::SOCK_DGRAM).each do |_, _, addr, _, _|
      return nil if SSRF.blocked?(addr)
      return addr
    end
    nil
  rescue SocketError
    nil
  end

  # ─────────────────────── SOCKS5 auth / addr / reply ───────────────────────
  def socks5_auth
    ver = @reader.read_one
    return [false, 0, ''] unless ver == 1
    @sock.write("\x01\xff".b)
    return [false, 0, ''] unless ver == 1

    ulen = @reader.read_one
    return [false, 0, ''] unless ulen
    raw_u = ulen > 0 ? @reader.read_exact(ulen) : ''.b
    return [false, 0, ''] unless raw_u
    u = raw_u.force_encoding('UTF-8')

    plen = @reader.read_one
    return [false, 0, ''] unless plen
    raw_p = plen > 0 ? @reader.read_exact(plen) : ''.b
    return [false, 0, ''] unless raw_p
    p = raw_p.force_encoding('UTF-8')

    ok, rate, uname = authenticate_proxy_user(u, p)
    @sock.write(ok ? "\x01\x00".b : "\x01\xff".b)
    if ok
      AuthFail.reset(@cip)
      [true, rate, uname]
    else
      Util.log_warn "#{RED}SOCKS5 auth fail from #{@cip}#{RESET}"
      State.stats_lock.synchronize { State.stats[:auth_fail] += 1 }
      AuthFail.record(@cip, AUTH_FAIL_THRESHOLD)
      [false, 0, '']
    end
  rescue StandardError
    begin; @sock.write("\x01\xff".b); rescue; end
    [false, 0, '']
  end

  def read_addr(atyp)
    case atyp
    when 1
      raw = @reader.read_exact(4)
      return [nil, 0] unless raw
      host = raw.bytes.join('.')
    when 3
      ln = @reader.read_one
      return [nil, 0] unless ln && ln > 0
      raw = @reader.read_exact(ln)
      return [nil, 0] unless raw
      return [nil, 0] unless raw.ascii_only?
      host = raw.force_encoding('ascii')
    when 4
      raw = @reader.read_exact(16)
      return [nil, 0] unless raw
      host = IPAddr.new_ntoh(raw).to_s
    else
      return [nil, 0]
    end
    p_raw = @reader.read_exact(2)
    return [nil, 0] unless p_raw
    [host, p_raw.unpack1('n')]
  end

  def socks5_reply(rep, addr = '0.0.0.0', port = 0)
    addr = Util.normalize_ip(addr)
    if addr.include?(':')
      bin = IPAddr.new(addr).hton; atyp = 4
    else
      bin = addr.split('.').map(&:to_i).pack('C4'); atyp = 1
    end
    @sock.write([5, rep, 0, atyp].pack('C4') + bin + [port].pack('n'))
  rescue StandardError => e
    Util.log_warn "socks5_reply error: #{e.message}"
  end

  # ───────────────────────────── HTTP ─────────────────────────────
  def handle_http
    req_line, headers = read_http_headers
    return unless req_line
    parts = req_line.split
    return if parts.size < 2
    method = parts[0].upcase
    url = parts[1]

    # FIX v6.3.6: smuggling checks
    cl_vals = headers['content-length'] || []
    te_vals = headers['transfer-encoding'] || []
    if cl_vals.any? && te_vals.any?
      Util.log_warn "#{RED}HTTP smuggling: cả CL lẫn TE (#{@cip}:#{@cport})#{RESET}"
      return send_simple_response(400, 'Bad Request')
    end
    if cl_vals.size > 1
      uniq = cl_vals.map(&:strip).uniq
      if uniq.size != 1
        Util.log_warn "#{RED}HTTP smuggling: Content-Length xung đột#{RESET}"
        return send_simple_response(400, 'Bad Request')
      end
    end
    if te_vals.size > 1 || (te_vals.any? && te_vals.last.strip.downcase != 'chunked')
      Util.log_warn "#{RED}HTTP smuggling: Transfer-Encoding bất thường#{RESET}"
      return send_simple_response(400, 'Bad Request')
    end

    username = ''
    rate_bps = 0
    if auth_required?
      ok, rate_bps, username = http_auth(headers)
      unless ok
        @sock.write("HTTP/1.1 407 Proxy Authentication Required\r\n" \
                    "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n" \
                    "Connection: close\r\n\r\n")
        State.stats_lock.synchronize { State.stats[:auth_fail] += 1 }
        AuthFail.record(@cip, AUTH_FAIL_THRESHOLD)
        return
      end
      AuthFail.reset(@cip)
      allowed, reason = check_user_limits(username)
      unless allowed
        return @sock.write("HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n#{reason}")
      end
    end

    # FIX v6.3.6: CONNECT hỗ trợ [v6]:port
    if method == 'CONNECT'
      host, port = parse_connect_authority(url)
      unless host
        return send_simple_response(400, 'Bad Request')
      end
    else
      begin
        u = URI.parse(url.match?(%r{\Ahttps?://}) ? url : "http://#{url}")
        host = u.host
        port = u.port || (u.scheme == 'https' ? 443 : 80)
      rescue StandardError
        return send_simple_response(400, 'Bad Request')
      end
      return send_simple_response(400, 'Bad Request') unless host
    end

    target = "#{host}:#{port}"
    Util.log "#{GREEN}HTTP #{method} → #{@cip}:#{@cport} → #{target}#{RESET}"
    @ci = ConnectionInfo.new(State.next_conn_id, @cip, @cport, 'HTTP',
                             target, rate_bps, username, @sock)
    State.active_lock.synchronize { State.active_conns[@ci.id] = @ci }

    clear_timeout
    remote = Upstream.connect_target(host, port)
    return send_simple_response(502, 'Bad Gateway') unless remote

    begin
      if method == 'CONNECT'
        @sock.write("HTTP/1.1 200 Connection Established\r\n\r\n")
        initial = @reader.peek_all
        @reader.clear
        tunnel(@sock, remote, @ci, initial)
      else
        forward_http_request(method, url, headers, remote)
        forward_response(remote, @sock, @ci)
      end
    ensure
      begin; remote.close unless remote.closed?; rescue; end
    end
  ensure
    State.active_lock.synchronize { State.active_conns.delete(@ci.id) } if @ci
  end

  def parse_connect_authority(url)
    if url.start_with?('[')
      end_idx = url.index(']')
      return [nil, 0] unless end_idx
      host = url[1...end_idx]
      rest = url[(end_idx + 1)..-1] || ''
      return [nil, 0] unless rest.start_with?(':')
      port = rest[1..-1].to_i
      return [nil, 0] unless port.between?(1, 65535)
      [host, port]
    elsif url.include?(':')
      host, ps = url.rpartition(':').values_at(0, 2)
      port = ps.to_i
      return [nil, 0] unless port.between?(1, 65535)
      [host, port]
    else
      [url, 443]
    end
  end

  def read_http_headers
    line = @reader.read_line
    return nil unless line
    req_line = line.force_encoding('UTF-8').strip

    headers = Hash.new { |h, k| h[k] = [] }
    count = 0
    loop do
      count += 1
      return [nil, nil] if count > 200
      l = @reader.read_line
      return [nil, nil] unless l
      break if l.empty?
      s = l.force_encoding('UTF-8')
      next unless s.include?(':')
      k, v = s.split(':', 2)
      headers[k.strip.downcase] << v.strip
    end
    [req_line, headers]
  end

  def http_auth(headers)
    a = (headers['proxy-authorization'] || []).last || ''
    return [false, 0, ''] unless a.downcase.start_with?('basic ')
    begin
      cred = Base64.decode64(a[6..-1]).force_encoding('UTF-8')
      u, p = cred.split(':', 2)
      return [false, 0, ''] unless u && p
      authenticate_proxy_user(u, p)
    rescue StandardError
      [false, 0, '']
    end
  end

  def forward_http_request(method, url, headers, remote)
    u = URI.parse(url.match?(%r{\Ahttps?://}) ? url : "http://#{url}")
    path = u.path.empty? ? '/' : u.path
    path += "?#{u.query}" if u.query

    req = +"#{method} #{path} HTTP/1.1\r\n"
    req << "Host: #{u.host}\r\n" unless headers.key?('host')
    headers.each do |k, vs|
      next if %w[proxy-authorization proxy-connection connection].include?(k)
      vs.each { |v| req << "#{k.split('-').map(&:capitalize).join('-')}: #{v}\r\n" }
    end
    req << "Connection: close\r\n\r\n"
    remote.write(req)
    @ci&.add_up(req.bytesize)
    Usage.add(@ci&.username, req.bytesize)

    cl_vals = headers['content-length']
    te_vals = headers['transfer-encoding']
    if cl_vals
      rem = cl_vals.last.to_i
      while rem > 0
        chunk = @reader.read_exact([rem, BUFFER_SIZE].min)
        break unless chunk
        remote.write(chunk)
        @ci&.add_up(chunk.bytesize)
        Usage.add(@ci&.username, chunk.bytesize)
        rem -= chunk.bytesize
      end
    elsif te_vals && te_vals.last.strip.downcase == 'chunked'
      loop do
        line = @reader.read_line
        break unless line
        sz = line.split(';').first.strip.to_i(16) rescue 0
        if sz.zero?
          loop { t = @reader.read_line; break if t.nil? || t.empty? }
          break
        end
        break if sz > 64 * 1024 * 1024
        chunk = @reader.read_exact(sz)
        break unless chunk
        crlf = @reader.read_exact(2)
        break unless crlf == "\r\n"
        remote.write(chunk)
        @ci&.add_up(chunk.bytesize)
        Usage.add(@ci&.username, chunk.bytesize)
      end
    end
  end

  def forward_response(src, dst, ci)
    loop do
      ready = IO.select([src], nil, nil, IDLE_TIMEOUT)
      break unless ready
      begin
        chunk = src.recv(BUFFER_SIZE)
      rescue StandardError
        break
      end
      break if chunk.empty?
      dst.write(chunk)
      State.stats_lock.synchronize { State.stats[:bytes_down] += chunk.bytesize }
      ci.add_down(chunk.bytesize)
      Usage.add(ci.username, chunk.bytesize)
    end
  end

  def send_simple_response(code, text)
    body = "#{code} #{text}\n"
    @sock.write("HTTP/1.1 #{code} #{text}\r\nConnection: close\r\n" \
                "Content-Length: #{body.bytesize}\r\n\r\n#{body}")
  rescue StandardError
  end

  # ──────────────────────── TUNNEL ────────────────────────
  def tunnel(client, remote, ci, initial = ''.b)
    unless initial.empty?
      begin
        remote.write(initial)
        State.stats_lock.synchronize { State.stats[:bytes_up] += initial.bytesize }
        ci.add_up(initial.bytesize)
        Usage.add(ci.username, initial.bytesize)
      rescue StandardError
        return
      end
    end

    socks = [client, remote]
    begin
      loop do
        ready = IO.select(socks, nil, socks, IDLE_TIMEOUT)
        break unless ready
        ready[0].each do |s|
          begin
            chunk = s.recv(BUFFER_SIZE)
          rescue StandardError
            return
          end
          return if chunk.empty?
          if s.equal?(client)
            remote.write(chunk)
            State.stats_lock.synchronize { State.stats[:bytes_up] += chunk.bytesize }
            ci.add_up(chunk.bytesize)
            Usage.add(ci.username, chunk.bytesize)
          else
            client.write(chunk)
            State.stats_lock.synchronize { State.stats[:bytes_down] += chunk.bytesize }
            ci.add_down(chunk.bytesize)
            Usage.add(ci.username, chunk.bytesize)
          end
        end
      end
    ensure
      [client, remote].each { |s| s.close rescue nil }
    end
  end

  # ──────────────────────── MISC ────────────────────────
  def auth_required?
    return true if @opts[:auth_required]
    State.cfg_lock.synchronize do
      State.cfg&.require_proxy_auth || (State.cfg&.users&.any? == true)
    end
  end

  def authenticate_proxy_user(user, password)
    if @opts[:username] && user == @opts[:username] && password == @opts[:password]
      return [true, 0, user]
    end
    users = State.cfg_lock.synchronize { State.cfg ? State.cfg.users.dup : [] }
    users.each do |u|
      next unless u['username'] == user
      hash = u['password_hash'] || ''
      next unless Util.verify_password_cached(password, hash)
      return [true, (u['max_bandwidth_bps'] || 0).to_i, user]
    end
    [false, 0, '']
  end

  def check_user_limits(username)
    return [true, ''] if username.to_s.empty?
    u = nil
    State.cfg_lock.synchronize do
      u = State.cfg&.users&.find { |x| x['username'] == username }
    end
    return [true, ''] unless u
    maxc = (u['max_connections'] || 0).to_i
    quota = (u['quota_bytes_per_month'] || 0).to_i
    if maxc > 0
      n = State.active_lock.synchronize do
        State.active_conns.each_value.count { |c| c.username == username }
      end
      return [false, "đã đạt giới hạn #{maxc} connection đồng thời"] if n >= maxc
    end
    if quota > 0 && Usage.get(username) >= quota
      return [false, 'đã vượt quota dung lượng tháng']
    end
    [true, '']
  end

  def clear_timeout
    @sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [0, 0].pack('l_2'))
  rescue StandardError
  end
end

# ══════════════════════════════════════════════════════════════════════
# DASHBOARD (raw TCP HTTP server)
# ══════════════════════════════════════════════════════════════════════
class Dashboard
  DASH_MAX_BODY = 5 * 1024 * 1024
  DASH_MAX_HDR  = 16384
  DASH_MAX_THREADS = 64

  def initialize(bind, port)
    @bind = bind
    @port = port
    @threads = 0
    @threads_lock = Mutex.new
  end

  def start
    @server = TCPServer.new(@bind, @port)
    @server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
    Util.log "#{CYAN}Dashboard: http://#{@bind}:#{@port}#{RESET}"
    Thread.new do
      loop do
        break if State.shutdown_flag
        begin
          sock = @server.accept
        rescue IOError, Errno::EBADF
          break
        end
        next unless sock
        @threads_lock.synchronize do
          if @threads >= DASH_MAX_THREADS
            sock.close
            next
          end
          @threads += 1
        end
        Thread.new(sock) do |s|
          handle_client(s)
        ensure
          @threads_lock.synchronize { @threads -= 1 }
        end
      end
    end
  end

  def stop
    @server&.close rescue nil
  end

  def handle_client(sock)
    sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [30, 0].pack('l_2'))
    begin
      sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, [30, 0].pack('l_2'))
    rescue StandardError
    end
    peer = sock.peeraddr
    cip = Util.normalize_ip(peer[3])

    hdr_buf = +''.b
    hdr_end = nil
    while hdr_buf.bytesize < DASH_MAX_HDR
      begin
        chunk = sock.recv(4096)
      rescue StandardError
        break
      end
      break if chunk.nil? || chunk.empty?
      hdr_buf << chunk
      if (idx = hdr_buf.index("\r\n\r\n"))
        hdr_end = idx + 4
        break
      end
    end
    return sock.close unless hdr_end

    head = hdr_buf.byteslice(0, hdr_end)
    body_pre = hdr_buf.byteslice(hdr_end..-1) || ''.b

    method, path, _httpver = head.lines.first.to_s.split
    return sock.close unless method
    # FIX v3.0.1: tách query string khỏi path (/?foo=bar → /)
    path = path.to_s.split('?', 2).first || '/'
    path = '/' if path.empty?
    # Lưu method để write_resp biết skip body khi HEAD (thread-local, an toàn).
    Thread.current[:dash_req_method] = method

    headers = {}
    head.split("\r\n").drop(1).each do |l|
      next if l.empty?
      k, v = l.split(':', 2)
      headers[k.strip.downcase] = v.to_s.strip
    end

    clen = (headers['content-length'] || '0').to_i
    body = body_pre
    while body.bytesize < clen && body.bytesize <= DASH_MAX_BODY
      begin
        chunk = sock.recv([clen - body.bytesize, 4096].min)
      rescue StandardError
        break
      end
      break if chunk.nil? || chunk.empty?
      body << chunk
    end

    route(sock, cip, method, path, headers, body)
  rescue StandardError => e
    Util.log_err "Dashboard error: #{e.message}"
  ensure
    begin; sock.close unless sock.closed?; rescue; end
  end

  def write_resp(sock, code, ctype, body, extra = {})
    status_text = { 200 => 'OK', 400 => 'Bad Request', 401 => 'Unauthorized',
                    403 => 'Forbidden', 404 => 'Not Found', 405 => 'Method Not Allowed',
                    409 => 'Conflict', 413 => 'Payload Too Large',
                    429 => 'Too Many Requests', 500 => 'Internal Server Error',
                    503 => 'Service Unavailable' }.fetch(code, 'OK')
    body = body.to_s.b
    head = +"HTTP/1.1 #{code} #{status_text}\r\n"
    head << "Content-Type: #{ctype}\r\n"
    head << "Content-Length: #{body.bytesize}\r\n"
    head << "Cache-Control: no-store\r\n"
    head << "Connection: close\r\n"
    extra.each { |k, v| head << "#{k}: #{v}\r\n" }
    head << "\r\n"
    sock.write(head)
    # FIX v3.0.1: không dùng `method` — đó là Kernel#method (arity 1) gây ArgumentError
    # và bị rescue nuốt → body rỗng. Dùng @req_method set ở handle_client.
    unless Thread.current[:dash_req_method] == 'HEAD'
      sock.write(body)
    end
  rescue StandardError => e
    Util.log_err "write_resp error: #{e.message}"
  end

  def json_resp(sock, code, obj)
    write_resp(sock, code, 'application/json', JSON.dump(obj))
  end

  def check_auth(sock, cip, headers)
    if AuthFail.blocked?(cip)
      write_resp(sock, 429, 'text/plain', 'Too Many Requests')
      return nil
    end
    auth = headers['authorization'] || ''
    if auth.start_with?('Bearer ')
      name = check_token(auth[7..-1])
      if name
        AuthFail.reset(cip)
        return "token:#{name}"
      end
      AuthFail.record(cip, DASH_AUTH_FAIL_THRESHOLD)
      write_resp(sock, 401, 'text/plain', 'Unauthorized (invalid token)')
      return nil
    end
    unless auth.start_with?('Basic ')
      AuthFail.record(cip, DASH_AUTH_FAIL_THRESHOLD)
      write_resp(sock, 401, 'text/plain', 'Unauthorized',
                 'WWW-Authenticate' => 'Basic realm="Dashboard"')
      return nil
    end
    decoded = Base64.decode64(auth[6..-1]).force_encoding('UTF-8')
    u, p = decoded.split(':', 2)
    cu, ch = State.cfg_lock.synchronize do
      [State.cfg&.dashboard_user.to_s, State.cfg&.dashboard_password_hash.to_s]
    end
    unless Util.ct_equal(u.to_s, cu) && Util.verify_password_cached(p.to_s, ch)
      AuthFail.record(cip, DASH_AUTH_FAIL_THRESHOLD)
      write_resp(sock, 401, 'text/plain', 'Unauthorized',
                 'WWW-Authenticate' => 'Basic realm="Dashboard"')
      return nil
    end
    AuthFail.reset(cip)
    "dashboard:#{cu}"
  end

  def check_token(tok)
    h = Digest::SHA256.hexdigest(tok.to_s)
    State.cfg_lock.synchronize do
      t = State.cfg&.api_tokens&.find { |x| Util.ct_equal(x['token_hash'].to_s, h) }
      t && t['name']
    end
  end

  def csrf_ok?(method, headers)
    return true if %w[GET HEAD OPTIONS].include?(method)
    sfs = headers['sec-fetch-site'] || ''
    return false if !sfs.empty? && !%w[same-origin none].include?(sfs)
    if (origin = headers['origin']) && !origin.empty?
      begin
        u = URI.parse(origin)
        host = (headers['host'] || '').split(':').first
        return false if u.host && u.host != host
      rescue
        return false
      end
    end
    (headers['content-type'] || '').downcase.start_with?('application/json')
  end

  def route(sock, cip, method, path, headers, body)
    return health(sock) if path == '/healthz'
    return metrics(sock) if path == '/metrics'

    actor = check_auth(sock, cip, headers)
    return unless actor

    case [method, path]
    in ['GET', '/']  then write_resp(sock, 200, 'text/html; charset=utf-8', DASH_HTML)
    in ['GET', '/stats'] then json_resp(sock, 200, stats_basic)
    in ['GET', '/api/all'] then json_resp(sock, 200, stats_all)
    in ['GET', '/api/stream'] then stream(sock)
    in ['GET', '/api/audit-log']
      with_lock(State.audit_lock) { json_resp(sock, 200, events: State.audit_log.reverse) }
    in ['GET', '/api/reload-history']
      with_lock(State.reload_lock) { json_resp(sock, 200, history: State.reload_hist.reverse) }
    in ['GET', '/api/users'] then list_users(sock)
    in ['GET', '/api/tokens'] then list_tokens(sock)
    in ['GET', '/api/network-config'] then network_config(sock)
    in ['GET', '/api/export'] then export_conns(sock, path)
    in ['GET', '/api/config/export'] then export_config(sock, actor)
    in ['POST', '/api/kick']
      return write_resp(sock, 403, 'text/plain', 'CSRF') unless csrf_ok?(method, headers)
      kick(sock, actor, body)
    in ['POST', '/api/users']
      return write_resp(sock, 403, 'text/plain', 'CSRF') unless csrf_ok?(method, headers)
      upsert_user(sock, actor, body)
    in ['POST', '/api/users/delete']
      return write_resp(sock, 403, 'text/plain', 'CSRF') unless csrf_ok?(method, headers)
      delete_user(sock, actor, body)
    in ['POST', '/api/tokens']
      return write_resp(sock, 403, 'text/plain', 'CSRF') unless csrf_ok?(method, headers)
      create_token(sock, actor, body)
    in ['POST', '/api/tokens/delete']
      return write_resp(sock, 403, 'text/plain', 'CSRF') unless csrf_ok?(method, headers)
      delete_token(sock, actor, body)
    in ['POST', '/api/change-password']
      return write_resp(sock, 403, 'text/plain', 'CSRF') unless csrf_ok?(method, headers)
      change_password(sock, actor, body)
    in ['POST', '/api/reload']
      return write_resp(sock, 403, 'text/plain', 'CSRF') unless csrf_ok?(method, headers)
      do_reload(sock, actor)
    in ['POST', '/api/network-config']
      return write_resp(sock, 403, 'text/plain', 'CSRF') unless csrf_ok?(method, headers)
      save_network(sock, actor, body)
    in ['POST', '/api/config/import']
      return write_resp(sock, 403, 'text/plain', 'CSRF') unless csrf_ok?(method, headers)
      import_config(sock, actor, body)
    else
      write_resp(sock, 404, 'text/plain', '404')
    end
  end

  def with_lock(m); m.synchronize { yield }; end

  def health(sock)
    if State.shutdown_flag
      write_resp(sock, 503, 'application/json', '{"status":"shutting_down"}')
    else
      write_resp(sock, 200, 'application/json', '{"status":"ok"}')
    end
  end

  def metrics(sock)
    s = State.stats_lock.synchronize { State.stats.dup }
    ac = State.active_lock.synchronize { State.active_conns.size }
    ua = State.udp_lock.synchronize { State.udp_assocs.size }
    uptime = Time.now.to_f - s[:start]
    lines = []
    {
      'connections_total' => ['counter', s[:total]],
      'connections_current' => ['gauge', s[:current]],
      'connections_active' => ['gauge', ac],
      'socks5_tcp_total' => ['counter', s[:socks5_tcp]],
      'socks5_udp_total' => ['counter', s[:socks5_udp]],
      'http_requests_total' => ['counter', s[:http]],
      'bytes_up_total' => ['counter', s[:bytes_up]],
      'bytes_down_total' => ['counter', s[:bytes_down]],
      'udp_bytes_up_total' => ['counter', s[:udp_up]],
      'udp_bytes_down_total' => ['counter', s[:udp_down]],
      'udp_associations' => ['gauge', ua],
      'auth_fail_total' => ['counter', s[:auth_fail]],
      'uptime_seconds' => ['gauge', uptime.to_i]
    }.each { |k, (t, v)| lines << "# TYPE proxy_#{k} #{t}\nproxy_#{k} #{v}" }
    write_resp(sock, 200, 'text/plain; version=0.0.4', lines.join("\n") + "\n")
  end

  def stats_basic
    s = State.stats_lock.synchronize { State.stats.dup }
    s[:active] = State.active_lock.synchronize { State.active_conns.size }
    s[:uptime] = Time.now.to_f - s.delete(:start)
    s
  end

  def stats_all
    d = stats_basic
    conns = State.active_lock.synchronize do
      State.active_conns.values.map do |c|
        up, dn = c.snapshot
        { id: c.id, ip: c.ip, port: c.port, type: c.conn_type, target: c.target,
          user: c.username, start_time: c.start_time,
          bytes_up: up, bytes_down: dn, duration: Time.now.to_f - c.start_time }
      end
    end
    d[:active_connections] = conns
    ups = State.upstream_lock.synchronize do
      State.upstream_proxies.map { |h, p| "#{h}:#{p}" }
    end
    d[:upstream] = {
      proxies: ups,
      current_index: State.upstream_index,
      status: ups.map { |u| { addr: u, alive: State.upstream_health.fetch(u, true) } }
    }
    d[:system] = { cpu_percent: 0.0, memory_percent: 0.0, fd_limit: 65536 }
    d
  end

  def list_users(sock)
    u = State.cfg_lock.synchronize do
      (State.cfg&.users || []).map do |x|
        { username: x['username'],
          max_bandwidth_bps: x['max_bandwidth_bps'],
          max_connections: x['max_connections'],
          quota_bytes_per_month: x['quota_bytes_per_month'],
          usage_bytes_this_month: Usage.get(x['username']) }
      end
    end
    json_resp(sock, 200, users: u)
  end

  def list_tokens(sock)
    t = State.cfg_lock.synchronize do
      (State.cfg&.api_tokens || []).map { |x| { name: x['name'], created_at: x['created_at'] } }
    end
    json_resp(sock, 200, tokens: t)
  end

  def network_config(sock)
    c = State.cfg_lock.synchronize { State.cfg }
    json_resp(sock, 200,
              allow_list: c&.allow_list || [],
              deny_list: c&.deny_list || [],
              upstream_proxies: c&.upstream_proxies || [])
  end

  def export_conns(sock, path)
    fmt = (path.split('?', 2)[1] || '').split('&').map { |kv| kv.split('=', 2) }
               .to_h['format'] || 'json'
    rows = State.active_lock.synchronize do
      State.active_conns.values.map do |c|
        up, dn = c.snapshot
        { id: c.id, ip: c.ip, port: c.port, type: c.conn_type, target: c.target,
          user: c.username, bytes_up: up, bytes_down: dn,
          duration: Time.now.to_f - c.start_time }
      end
    end
    if fmt == 'csv'
      out = "id,ip,port,type,target,user,bytes_up,bytes_down,duration\n"
      rows.each { |r| out << r.values.join(',') + "\n" }
      write_resp(sock, 200, 'text/csv', out,
                 'Content-Disposition' => 'attachment; filename=connections.csv')
    else
      write_resp(sock, 200, 'application/json', JSON.dump(rows),
                 'Content-Disposition' => 'attachment; filename=connections.json')
    end
  end

  def export_config(sock, actor)
    c = State.cfg_lock.synchronize { State.cfg.to_h }
    State.audit_lock.synchronize do
      State.audit_log << { 't' => Time.now.to_i, 'actor' => actor,
                           'action' => 'export_config_backup', 'details' => '' }
      State.audit_log.shift while State.audit_log.size > 200
    end
    fn = "proxy_config_backup_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
    write_resp(sock, 200, 'application/json', JSON.pretty_generate(c),
               'Content-Disposition' => "attachment; filename=#{fn}")
  end

  def kick(sock, actor, body)
    j = JSON.parse(body) rescue nil
    return json_resp(sock, 400, error: "Missing 'id'") unless j && j['id']
    c = State.active_lock.synchronize { State.active_conns[j['id']] }
    return json_resp(sock, 404, error: 'Connection not found') unless c
    begin
      c.conn.shutdown(Socket::SHUT_RDWR) if c.conn
      c.conn.close if c.conn
    rescue StandardError
    end
    State.audit_lock.synchronize do
      State.audit_log << { 't' => Time.now.to_i, 'actor' => actor,
                           'action' => 'kick_connection',
                           'details' => "id=#{c.id} ip=#{c.ip} target=#{c.target}" }
      State.audit_log.shift while State.audit_log.size > 200
    end
    json_resp(sock, 200, success: true, id: c.id)
  end

  def upsert_user(sock, actor, body)
    j = JSON.parse(body) rescue nil
    return json_resp(sock, 400, error: 'Invalid JSON') unless j.is_a?(Hash)
    uname = (j['username'] || '').to_s.strip
    return json_resp(sock, 400, error: 'Username required') if uname.empty?
    return json_resp(sock, 400, error: 'Username too long') if uname.length >= 64
    pwd = (j['password'] || '').to_s
    return json_resp(sock, 400, error: 'Password must be >= 4 chars') if !pwd.empty? && pwd.length < 4

    bw = j['max_bandwidth_bps'].to_i
    mc = j['max_connections'].to_i
    q  = j['quota_bytes_per_month'].to_i
    bw = 0 if bw < 0; mc = 0 if mc < 0; q = 0 if q < 0
    pwd_hash = pwd.empty? ? nil : Util.hash_password(pwd)

    err = State.cfg_lock.synchronize do
      idx = State.cfg.users.index { |u| u['username'] == uname }
      if idx
        State.cfg.users[idx]['password_hash'] = pwd_hash if pwd_hash
        State.cfg.users[idx]['max_bandwidth_bps'] = bw
        State.cfg.users[idx]['max_connections'] = mc
        State.cfg.users[idx]['quota_bytes_per_month'] = q
      else
        return json_resp(sock, 400, error: 'Password required for new user') unless pwd_hash
        State.cfg.users << {
          'username' => uname, 'password_hash' => pwd_hash,
          'max_bandwidth_bps' => bw, 'max_connections' => mc,
          'quota_bytes_per_month' => q
        }
        State.cfg.require_proxy_auth = true
      end
      ConfigFile.save_locked($config_path, State.cfg)
    end
    return json_resp(sock, 500, error: "Write failed: #{err}") if err

    State.active_lock.synchronize do
      State.active_conns.each_value { |c| c.rate_bps = bw if c.username == uname }
    end
    State.audit_lock.synchronize do
      State.audit_log << { 't' => Time.now.to_i, 'actor' => actor,
                           'action' => 'upsert_user', 'details' => "username=#{uname}" }
      State.audit_log.shift while State.audit_log.size > 200
    end
    json_resp(sock, 200, success: true)
  end

  def delete_user(sock, actor, body)
    j = JSON.parse(body) rescue nil
    return json_resp(sock, 400, error: "Missing 'username'") unless j && j['username']
    uname = j['username']
    removed = false
    err = State.cfg_lock.synchronize do
      before = State.cfg.users.size
      State.cfg.users = State.cfg.users.reject { |u| u['username'] == uname }
      removed = State.cfg.users.size < before
      removed ? ConfigFile.save_locked($config_path, State.cfg) : nil
    end
    return json_resp(sock, 404, error: 'User not found') unless removed
    return json_resp(sock, 500, error: "Write failed: #{err}") if err
    State.audit_lock.synchronize do
      State.audit_log << { 't' => Time.now.to_i, 'actor' => actor,
                           'action' => 'delete_user', 'details' => "username=#{uname}" }
    end
    json_resp(sock, 200, success: true)
  end

  def create_token(sock, actor, body)
    j = JSON.parse(body) rescue nil
    name = (j && j['name'] || '').to_s.strip
    return json_resp(sock, 400, error: 'Name required') if name.empty?
    return json_resp(sock, 400, error: 'Name too long') if name.length >= 64
    token = SecureRandom.hex(32)
    err = State.cfg_lock.synchronize do
      if State.cfg.api_tokens.any? { |t| t['name'] == name }
        next '__EXISTS__'
      end
      State.cfg.api_tokens << {
        'name' => name,
        'token_hash' => Digest::SHA256.hexdigest(token),
        'created_at' => Time.now.to_i
      }
      ConfigFile.save_locked($config_path, State.cfg)
    end
    return json_resp(sock, 409, error: 'Token name exists') if err == '__EXISTS__'
    return json_resp(sock, 500, error: "Write failed: #{err}") if err
    State.audit_lock.synchronize do
      State.audit_log << { 't' => Time.now.to_i, 'actor' => actor,
                           'action' => 'create_api_token', 'details' => "name=#{name}" }
    end
    json_resp(sock, 200, success: true, token: token, name: name)
  end

  def delete_token(sock, actor, body)
    j = JSON.parse(body) rescue nil
    return json_resp(sock, 400, error: "Missing 'name'") unless j && j['name']
    name = j['name']
    removed = false
    err = State.cfg_lock.synchronize do
      before = State.cfg.api_tokens.size
      State.cfg.api_tokens = State.cfg.api_tokens.reject { |t| t['name'] == name }
      removed = State.cfg.api_tokens.size < before
      removed ? ConfigFile.save_locked($config_path, State.cfg) : nil
    end
    return json_resp(sock, 404, error: 'Token not found') unless removed
    return json_resp(sock, 500, error: "Write failed: #{err}") if err
    json_resp(sock, 200, success: true)
  end

  def change_password(sock, actor, body)
    j = JSON.parse(body) rescue nil
    return json_resp(sock, 400, error: 'Invalid JSON') unless j.is_a?(Hash)
    cur = j['current_password'].to_s
    nu  = (j['new_username'] || '').to_s.strip
    np  = j['new_password'].to_s
    cu, ch = State.cfg_lock.synchronize do
      [State.cfg.dashboard_user, State.cfg.dashboard_password_hash]
    end
    return json_resp(sock, 403, error: 'Current password incorrect') unless Util.verify_password(cur, ch)
    return json_resp(sock, 400, error: 'New password must be >= 8') if np.length < 8
    return json_resp(sock, 400, error: 'New password must differ') if np == cur
    new_hash = Util.hash_password(np)
    err = State.cfg_lock.synchronize do
      State.cfg.dashboard_user = nu unless nu.empty?
      State.cfg.dashboard_password_hash = new_hash
      ConfigFile.save_locked($config_path, State.cfg)
    end
    Util.log_warn "Đổi mật khẩu OK nhưng ghi file lỗi: #{err}" if err
    State.audit_lock.synchronize do
      State.audit_log << { 't' => Time.now.to_i, 'actor' => actor,
                           'action' => 'change_dashboard_password',
                           'details' => "user: #{cu} -> #{State.cfg.dashboard_user}" }
    end
    json_resp(sock, 200, success: true, username: State.cfg.dashboard_user)
  end

  def do_reload(sock, actor)
    ok = ConfigFile.reload!($config_path)
    unless ok
      ev = State.reload_lock.synchronize { State.reload_hist.last }
      return json_resp(sock, 400, error: ev && ev['error'] || 'reload failed')
    end
    json_resp(sock, 200, success: true)
  end

  def save_network(sock, actor, body)
    j = JSON.parse(body) rescue nil
    return json_resp(sock, 400, error: 'Invalid JSON') unless j.is_a?(Hash)
    err = State.cfg_lock.synchronize do
      State.cfg.allow_list = j['allow_list'] || []
      State.cfg.deny_list = j['deny_list'] || []
      State.cfg.upstream_proxies = j['upstream_proxies'] || []
      ConfigFile.save_locked($config_path, State.cfg)
    end
    return json_resp(sock, 500, error: "Write failed: #{err}") if err
    ConfigFile.reload!($config_path)
    json_resp(sock, 200, success: true)
  end

  def import_config(sock, actor, body)
    j = JSON.parse(body) rescue nil
    return json_resp(sock, 400, error: 'Invalid JSON') unless j.is_a?(Hash)
    return json_resp(sock, 400, error: 'Not a valid backup') unless j['dashboard_user'] && j['dashboard_password_hash']
    begin
      tmp = $config_path + '.tmp'
      File.write(tmp, JSON.pretty_generate(AppConfig.new(j).to_h))
      File.chmod(0o600, tmp)
      File.rename(tmp, $config_path)
    rescue StandardError => e
      return json_resp(sock, 500, error: "Write failed: #{e.message}")
    end
    ok = ConfigFile.reload!($config_path)
    unless ok
      return json_resp(sock, 500, error: 'Imported but reload failed')
    end
    json_resp(sock, 200, success: true)
  end

  def stream(sock)
    if State.sse_lock.synchronize { State.sse_clients.size } >= DASH_MAX_SSE
      return json_resp(sock, 503, error: 'Too many streaming clients')
    end

    sock.write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" \
               "Cache-Control: no-cache\r\nConnection: close\r\n" \
               "X-Accel-Buffering: no\r\n\r\n")

    hist = State.hist_lock.synchronize { State.hist_sample.dup }
    sock.write("event: history\ndata: #{JSON.dump(hist)}\n\n")

    q = Queue.new
    State.sse_lock.synchronize { State.sse_clients << q }
    last_ka = Time.now.to_f

    loop do
      break if State.shutdown_flag
      begin
        sample = q.pop(true)
        sock.write("event: sample\ndata: #{JSON.dump(sample)}\n\n")
        last_ka = Time.now.to_f
      rescue ThreadError
        sleep 0.5
        if Time.now.to_f - last_ka >= 15
          sock.write(": keepalive\n\n")
          last_ka = Time.now.to_f
        end
      rescue StandardError
        break
      end
    end
  ensure
    State.sse_lock.synchronize { State.sse_clients.delete(q) } if q
  end

  # Compact dashboard HTML — Python's DASH_HTML có thể thay thế nếu cần đầy đủ hơn.
  DASH_HTML = <<~'HTML'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Proxy Dashboard</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
:root {
	--bg: #0f0f1a;
	--fg: #e0e0e0;
	--container-bg: #14141f;
	--box-bg: #1a1a2e;
	--box-hover: #22223b;
	--border: #2a2a3a;
	--border2: #28283a;
	--th-bg: #1e1e32;
	--muted: #9999bb;
	--muted2: #b4b4d4;
	--accent: #f0c27a;
	--accent-solid: #f0c27a;
	--accent-contrast: #1a1a2e;
	--btn-bg: #2a2a3a;
	--btn-border: #3a3a52;
	--btn-hover: #33334a;
	--badge-bg: #2a2a4a; --badge-fg: #c0c0e0;
	--badge-socks5tcp-bg: #1e3a5f; --badge-socks5tcp-fg: #7dd3fc;
	--badge-socks5udp-bg: #3b1f4a; --badge-socks5udp-fg: #d8b4fe;
	--badge-http-bg: #2d4a2d; --badge-http-fg: #86efac;
	--danger-border: #7a3030; --danger-hover-bg: #4a1a1a; --danger-fg: #fca5a5;
}
html[data-theme="light"] {
	--bg: #f4f4f9;
	--fg: #1c1c2a;
	--container-bg: #ffffff;
	--box-bg: #f0f0f7;
	--box-hover: #e6e6f2;
	--border: #dcdce8;
	--border2: #e4e4f0;
	--th-bg: #ececf5;
	--muted: #52526a;
	--muted2: #33334a;
	--accent: #8a5010;
	--accent-solid: #c67c1e;
	--accent-contrast: #ffffff;
	--btn-bg: #ececf5;
	--btn-border: #c8c8dc;
	--btn-hover: #e0e0ee;
	--badge-bg: #e4e4f4; --badge-fg: #3f3f66;
	--badge-socks5tcp-bg: #dbeafe; --badge-socks5tcp-fg: #1d4ed8;
	--badge-socks5udp-bg: #f3e8ff; --badge-socks5udp-fg: #7e22ce;
	--badge-http-bg: #dcfce7; --badge-http-fg: #15803d;
	--danger-border: #e5a5a5; --danger-hover-bg: #fde2e2; --danger-fg: #b91c1c;
}
body {
	background: var(--bg);
	color: var(--fg);
	font-family: 'Segoe UI', 'Roboto', monospace;
	padding: 30px 20px;
	transition: background 0.2s, color 0.2s;
}
.container {
	max-width: 1400px;
	margin: 0 auto;
}
h1 {
	font-size: 2.2rem;
	font-weight: 300;
	letter-spacing: 1px;
	color: var(--accent);
	display: flex;
	align-items: center;
	gap: 10px;
}
h1 span { background: var(--btn-bg); padding: 0 12px; border-radius: 30px; font-size: 0.8rem; color: var(--muted); }
.stats-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
	gap: 15px;
	margin: 20px 0;
}
.stat-box {
	background: var(--box-bg);
	padding: 14px 16px;
	border-radius: 12px;
	border-left: 4px solid #6c6c9a;
	transition: 0.2s;
}
.stat-box:hover { background: var(--box-hover); }
.stat-label {
	font-size: 0.8rem;
	text-transform: uppercase;
	letter-spacing: 0.5px;
	color: var(--muted);
}
.stat-value {
	font-size: 1.7rem;
	font-weight: 600;
	margin-top: 4px;
}
.stat-value.cyan { color: #0891b2; }
.stat-value.green { color: #16a34a; }
.stat-value.yellow { color: #ca8a04; }
.stat-value.pink { color: #db2777; }
.stat-value.orange { color: #ea580c; }
.stat-value.purple { color: #7c3aed; }
.stat-value.red { color: #dc2626; }
html[data-theme="dark"] .stat-value.cyan, html:not([data-theme]) .stat-value.cyan { color: #7dd3fc; }
html[data-theme="dark"] .stat-value.green, html:not([data-theme]) .stat-value.green { color: #86efac; }
html[data-theme="dark"] .stat-value.yellow, html:not([data-theme]) .stat-value.yellow { color: #fde047; }
html[data-theme="dark"] .stat-value.pink, html:not([data-theme]) .stat-value.pink { color: #f9a8d4; }
html[data-theme="dark"] .stat-value.orange, html:not([data-theme]) .stat-value.orange { color: #fdba74; }
html[data-theme="dark"] .stat-value.purple, html:not([data-theme]) .stat-value.purple { color: #c4b5fd; }
html[data-theme="dark"] .stat-value.red, html:not([data-theme]) .stat-value.red { color: #fca5a5; }
.section {
	margin-top: 30px;
	background: var(--container-bg);
	border-radius: 14px;
	padding: 20px 20px 10px 20px;
	border: 1px solid var(--border);
}
.section-title-row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 15px; }
.section-title {
	font-size: 1.2rem;
	font-weight: 400;
	color: var(--muted2);
	letter-spacing: 0.3px;
}
.toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.toolbar input[type=text] { background: var(--box-bg); border: 1px solid var(--border); border-radius: 8px; padding: 6px 10px; color: var(--fg); font-size: 0.85rem; }
table {
	width: 100%;
	border-collapse: collapse;
	font-size: 0.9rem;
}
th {
	text-align: left;
	padding: 10px 8px;
	background: var(--th-bg);
	color: var(--muted);
	font-weight: 500;
	cursor: pointer;
	user-select: none;
	white-space: nowrap;
}
th:hover { color: var(--accent); }
th.sorted-asc::after { content: ' \25B2'; font-size: 0.7em; }
th.sorted-desc::after { content: ' \25BC'; font-size: 0.7em; }
td {
	padding: 8px 8px;
	border-bottom: 1px solid var(--border2);
}
tr:hover td { background: var(--box-bg); }
.badge {
	display: inline-block;
	padding: 2px 12px;
	border-radius: 20px;
	font-size: 0.7rem;
	font-weight: 600;
	background: var(--badge-bg);
	color: var(--badge-fg);
}
.badge.socks5-tcp { background: var(--badge-socks5tcp-bg); color: var(--badge-socks5tcp-fg); }
.badge.socks5-udp { background: var(--badge-socks5udp-bg); color: var(--badge-socks5udp-fg); }
.badge.http { background: var(--badge-http-bg); color: var(--badge-http-fg); }
.header-bar { display: flex; align-items: center; justify-content: space-between; border-bottom: 2px solid var(--border); padding-bottom: 15px; margin-bottom: 10px; flex-wrap: wrap; gap: 10px; }
.header-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.btn { background: var(--btn-bg); color: var(--fg); border: 1px solid var(--btn-border); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; transition: 0.2s; }
.btn:hover { background: var(--btn-hover); border-color: var(--accent); }
.btn-sm { padding: 4px 10px; font-size: 0.75rem; }
.btn-danger { border-color: var(--danger-border); color: var(--danger-fg); }
.btn-danger:hover { background: var(--danger-hover-bg); border-color: var(--danger-fg); color: var(--danger-fg); }
.modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); align-items: center; justify-content: center; z-index: 100; }
.modal-overlay.open { display: flex; }
.modal { background: var(--container-bg); border: 1px solid var(--border); border-radius: 14px; padding: 24px; width: 340px; max-width: 90vw; }
.modal h2 { font-size: 1.1rem; font-weight: 500; color: var(--accent); margin-bottom: 16px; }
.modal label { display: block; font-size: 0.8rem; color: var(--muted); margin: 12px 0 4px; }
.modal input { width: 100%; background: var(--box-bg); border: 1px solid var(--border); border-radius: 8px; padding: 9px 10px; color: var(--fg); font-size: 0.9rem; }
.modal input:focus { outline: none; border-color: var(--accent); }
.modal-actions { display: flex; gap: 10px; margin-top: 20px; }
.modal-actions .btn { flex: 1; }
.btn-primary { background: var(--accent-solid); color: var(--accent-contrast); border-color: var(--accent-solid); font-weight: 600; }
.btn-primary:hover { filter: brightness(1.1); }
.modal-msg { margin-top: 12px; font-size: 0.82rem; min-height: 18px; }
.modal-msg.error { color: #dc2626; }
.modal-msg.success { color: #16a34a; }
</style>
</head>
<body>
<div class="container">
	<div class="header-bar">
		<h1>⚡ Proxy Pro <span>v6.3</span></h1>
		<div class="header-actions">
			<button class="btn" id="themeToggleBtn" onclick="toggleTheme()">🌙 Theme</button>
			<button class="btn" onclick="openPwModal()">🔒 Change Password</button>
		</div>
	</div>
	<div id="statsGrid" class="stats-grid">Loading stats...</div>
	<div id="chartSection" class="section">
		<div class="section-title-row">
			<div class="section-title">📈 Real-time Traffic <span id="streamStatus" style="font-size:0.75rem;color:var(--muted);">(connecting...)</span></div>
		</div>
		<canvas id="trafficChart" height="80"></canvas>
	</div>
	<div id="connectionsSection" class="section">
		<div class="section-title-row">
			<div class="section-title">🔗 Active Connections</div>
			<div class="toolbar">
				<input type="text" id="connFilter" placeholder="Filter by IP / target / type..." oninput="renderConnections()">
				<button class="btn btn-sm" onclick="exportConns('csv')">⬇ CSV</button>
				<button class="btn btn-sm" onclick="exportConns('json')">⬇ JSON</button>
			</div>
		</div>
		<div id="connectionsTable">Loading...</div>
	</div>
	<div id="upstreamSection" class="section">
		<div class="section-title">🌐 Upstream Proxies</div>
		<div id="upstreamInfo">Loading...</div>
	</div>
	<div id="usersSection" class="section">
		<div class="section-title-row">
			<div class="section-title">👤 Proxy Users (multi-user + bandwidth limit)</div>
			<div class="toolbar">
				<button class="btn btn-sm" onclick="openUserModal()">+ Add / Update User</button>
			</div>
		</div>
		<div id="usersTable">Loading...</div>
	</div>
	<div id="networkSection" class="section">
		<div class="section-title-row">
			<div class="section-title">🌐 Network Rules (whitelist / blacklist / upstream)</div>
			<div class="toolbar">
				<button class="btn btn-sm" onclick="reloadFromDisk()" title="Đọc lại config file từ đĩa và áp dụng ngay — dùng khi vừa tự sửa file bằng tay">↻ Reload from disk</button>
			</div>
		</div>
		<div style="font-size:0.78rem;color:var(--muted);margin-bottom:10px;">Mỗi dòng 1 IP hoặc CIDR (vd. <code>1.2.3.4</code> hoặc <code>10.0.0.0/8</code>). Lưu sẽ tự động reload ngay, không cần restart.</div>
		<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;">
			<div>
				<label style="display:block;font-size:0.8rem;color:var(--muted);margin-bottom:4px;">Whitelist IP/CIDR (để trống = cho phép tất cả)</label>
				<textarea id="netAllow" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:0.82rem;font-family:monospace;"></textarea>
			</div>
			<div>
				<label style="display:block;font-size:0.8rem;color:var(--muted);margin-bottom:4px;">Blacklist IP/CIDR</label>
				<textarea id="netDeny" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:0.82rem;font-family:monospace;"></textarea>
			</div>
			<div>
				<label style="display:block;font-size:0.8rem;color:var(--muted);margin-bottom:4px;">Upstream proxies (host:port)</label>
				<textarea id="netUpstream" rows="5" style="width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:0.82rem;font-family:monospace;"></textarea>
			</div>
		</div>
		<div class="modal-msg" id="netMsg" style="margin-top:10px;"></div>
		<div style="margin-top:10px;">
			<button class="btn btn-primary" onclick="saveNetworkConfig()">Save & Apply Now</button>
		</div>
	</div>
	<div id="reloadHistorySection" class="section">
		<div class="section-title-row">
			<div class="section-title">🕒 Reload History</div>
		</div>
		<div id="reloadHistoryTable">Loading...</div>
	</div>
	<div id="tokensSection" class="section">
		<div class="section-title-row">
			<div class="section-title">🔑 API Tokens (cho script/monitoring)</div>
			<div class="toolbar">
				<button class="btn btn-sm" onclick="openTokenModal()">+ Create Token</button>
			</div>
		</div>
		<div style="font-size:0.78rem;color:var(--muted);margin-bottom:10px;">Dùng <code>Authorization: Bearer &lt;token&gt;</code> thay cho Basic Auth khi gọi API từ script — token có thể thu hồi riêng, không ảnh hưởng mật khẩu đăng nhập web.</div>
		<div id="tokensTable">Loading...</div>
	</div>
	<div id="auditSection" class="section">
		<div class="section-title-row">
			<div class="section-title">📋 Audit Log</div>
		</div>
		<div id="auditTable">Loading...</div>
	</div>
	<div id="backupSection" class="section">
		<div class="section-title-row">
			<div class="section-title">💾 Backup / Restore Config</div>
		</div>
		<div style="font-size:0.78rem;color:var(--muted);margin-bottom:10px;">File backup chứa password/token đã hash (không phải plaintext) nhưng vẫn nên giữ bí mật.</div>
		<div class="toolbar">
			<a class="btn btn-sm" href="/api/config/export" download>⬇ Download Backup</a>
			<input type="file" id="restoreFileInput" accept="application/json" style="display:none;" onchange="restoreConfig(event)">
			<button class="btn btn-sm" onclick="document.getElementById('restoreFileInput').click()">⬆ Restore from File</button>
		</div>
		<div class="modal-msg" id="backupMsg" style="margin-top:10px;"></div>
	</div>
</div>

<div class="modal-overlay" id="tokenModalOverlay">
	<div class="modal">
		<h2>🔑 Create API Token</h2>
		<form id="tokenForm" onsubmit="return submitTokenForm(event)">
			<label for="tName">Token name (gợi nhớ, vd "monitoring-script")</label>
			<input type="text" id="tName" required>
			<div class="modal-msg" id="tokenMsg"></div>
			<div id="tokenResultBox" style="display:none;margin-top:12px;padding:10px;background:var(--box-bg);border-radius:8px;border:1px solid var(--border);">
				<div style="font-size:0.78rem;color:var(--danger-fg);margin-bottom:6px;">⚠️ Chỉ hiện MỘT LẦN — copy ngay, không xem lại được:</div>
				<code id="tokenResultValue" style="word-break:break-all;font-size:0.8rem;"></code>
			</div>
			<div class="modal-actions">
				<button type="button" class="btn" onclick="closeTokenModal()">Close</button>
				<button type="submit" class="btn btn-primary" id="tokenSubmitBtn">Create</button>
			</div>
		</form>
	</div>
</div>

<div class="modal-overlay" id="userModalOverlay">
	<div class="modal">
		<h2>👤 Add / Update Proxy User</h2>
		<form id="userForm" onsubmit="return submitUserForm(event)">
			<label for="uUsername">Username</label>
			<input type="text" id="uUsername" required>
			<label for="uPassword">Password (min. 4 characters — leave blank to keep current password when editing an existing user)</label>
			<input type="password" id="uPassword" minlength="4">
			<label for="uBandwidth">Max bandwidth (KB/s, 0 = unlimited)</label>
			<input type="number" id="uBandwidth" min="0" value="0">
			<label for="uMaxConn">Max concurrent connections (0 = unlimited)</label>
			<input type="number" id="uMaxConn" min="0" value="0">
			<label for="uQuota">Monthly quota (MB, 0 = unlimited)</label>
			<input type="number" id="uQuota" min="0" value="0">
			<div class="modal-msg" id="userMsg"></div>
			<div class="modal-actions">
				<button type="button" class="btn" onclick="closeUserModal()">Cancel</button>
				<button type="submit" class="btn btn-primary">Save</button>
			</div>
		</form>
	</div>
</div>

<div class="modal-overlay" id="pwModalOverlay">
	<div class="modal">
		<h2>🔒 Change Dashboard Credentials</h2>
		<form id="pwForm" onsubmit="return submitPwChange(event)">
			<label for="curPass">Current password</label>
			<input type="password" id="curPass" autocomplete="current-password" required>
			<label for="newUser">New username (leave blank to keep current)</label>
			<input type="text" id="newUser" autocomplete="username">
			<label for="newPass">New password (min. 8 characters)</label>
			<input type="password" id="newPass" autocomplete="new-password" minlength="8" required>
			<label for="newPass2">Confirm new password</label>
			<input type="password" id="newPass2" autocomplete="new-password" minlength="8" required>
			<div class="modal-msg" id="pwMsg"></div>
			<div class="modal-actions">
				<button type="button" class="btn" onclick="closePwModal()">Cancel</button>
				<button type="submit" class="btn btn-primary">Save changes</button>
			</div>
		</form>
	</div>
</div>

<script>
let lastConns = [];
let sortKey = 'start_time';
let sortDir = 'desc';
let trafficChart = null;
const CHART_MAX_POINTS = 150;

function initChart() {
	const ctx = document.getElementById('trafficChart').getContext('2d');
	trafficChart = new Chart(ctx, {
		type: 'line',
		data: {
			labels: [],
			datasets: [
				{ label: 'Upload (B/s)', data: [], borderColor: '#ea580c', backgroundColor: 'rgba(234,88,12,0.1)', tension: 0.3, pointRadius: 0, borderWidth: 2 },
				{ label: 'Download (B/s)', data: [], borderColor: '#0891b2', backgroundColor: 'rgba(8,145,178,0.1)', tension: 0.3, pointRadius: 0, borderWidth: 2 }
			]
		},
		options: {
			responsive: true,
			animation: false,
			interaction: { mode: 'index', intersect: false },
			scales: {
				x: { ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--muted') }, grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border2') } },
				y: { ticks: { color: getComputedStyle(document.documentElement).getPropertyValue('--muted'), callback: v => formatBytes(v) + '/s' }, grid: { color: getComputedStyle(document.documentElement).getPropertyValue('--border2') } }
			},
			plugins: { legend: { labels: { color: getComputedStyle(document.documentElement).getPropertyValue('--fg') } } }
		}
	});
}
function pushChartSample(sample) {
	if (!trafficChart) return;
	const label = new Date(sample.t * 1000).toLocaleTimeString();
	trafficChart.data.labels.push(label);
	trafficChart.data.datasets[0].data.push(sample.up_bps);
	trafficChart.data.datasets[1].data.push(sample.down_bps);
	if (trafficChart.data.labels.length > CHART_MAX_POINTS) {
		trafficChart.data.labels.shift();
		trafficChart.data.datasets[0].data.shift();
		trafficChart.data.datasets[1].data.shift();
	}
	trafficChart.update('none');
}
function connectStream() {
	const statusEl = document.getElementById('streamStatus');
	const es = new EventSource('/api/stream');
	es.addEventListener('history', (e) => {
		try {
			const hist = JSON.parse(e.data);
			hist.forEach(pushChartSample);
			statusEl.textContent = '(live)';
			statusEl.style.color = 'var(--badge-http-fg)';
		} catch (err) { console.error(err); }
	});
	es.addEventListener('sample', (e) => {
		try { pushChartSample(JSON.parse(e.data)); } catch (err) { console.error(err); }
	});
	es.onerror = () => {
		statusEl.textContent = '(reconnecting...)';
		statusEl.style.color = 'var(--danger-fg)';
		// EventSource tự động reconnect, không cần xử lý thủ công.
	};
	es.onopen = () => {
		statusEl.textContent = '(live)';
		statusEl.style.color = 'var(--badge-http-fg)';
	};
}

function applyTheme(theme) {
	document.documentElement.setAttribute('data-theme', theme);
	document.getElementById('themeToggleBtn').textContent = theme === 'light' ? '☀️ Theme' : '🌙 Theme';
	try { localStorage.setItem('dashboard-theme', theme); } catch (e) {}
}
function toggleTheme() {
	const cur = document.documentElement.getAttribute('data-theme') || 'dark';
	applyTheme(cur === 'light' ? 'dark' : 'light');
}
(function initTheme() {
	let saved = 'dark';
	try { saved = localStorage.getItem('dashboard-theme') || 'dark'; } catch (e) {}
	applyTheme(saved);
})();

async function fetchAll() {
	try {
		const res = await fetch('/api/all');
		if (!res.ok) throw new Error('HTTP '+res.status);
		const data = await res.json();
		renderStats(data);
		lastConns = data.active_connections || [];
		renderConnections();
		renderUpstream(data.upstream || {});
	} catch(e) {
		console.error('Fetch error:', e);
		document.getElementById('statsGrid').innerHTML = '<div style="color:#dc2626;">⚠️ Failed to load data. Retrying...</div>';
	}
}
function renderStats(data) {
	const boxes = [
		{ label: 'Total Connections', value: data.total, cls: 'cyan' },
		{ label: 'Active', value: data.active, cls: 'green' },
		{ label: 'SOCKS5 TCP', value: data.socks5_tcp, cls: 'cyan' },
		{ label: 'SOCKS5 UDP', value: data.socks5_udp, cls: 'purple' },
		{ label: 'HTTP Requests', value: data.http, cls: 'green' },
		{ label: 'UDP Associations', value: data.udp_assocs || 0, cls: 'yellow' },
		{ label: 'Bytes Up (TCP)', value: formatBytes(data.bytes_up), cls: 'orange' },
		{ label: 'Bytes Down (TCP)', value: formatBytes(data.bytes_down), cls: 'pink' },
		{ label: 'UDP Up', value: formatBytes(data.udp_up), cls: 'yellow' },
		{ label: 'UDP Down', value: formatBytes(data.udp_down), cls: 'purple' },
		{ label: 'Uptime', value: formatUptime(data.uptime), cls: 'cyan' },
	];
	let html = '';
	boxes.forEach(b => {
		html += '<div class="stat-box"><div class="stat-label">'+b.label+'</div><div class="stat-value '+b.cls+'">'+b.value+'</div></div>';
	});
	document.getElementById('statsGrid').innerHTML = html;
}
function sortConns(key) {
	if (sortKey === key) {
		sortDir = sortDir === 'asc' ? 'desc' : 'asc';
	} else {
		sortKey = key;
		sortDir = 'asc';
	}
	renderConnections();
}
function renderConnections() {
	const filterEl = document.getElementById('connFilter');
	const filter = (filterEl ? filterEl.value : '').toLowerCase().trim();

	let conns = lastConns.slice();
	if (filter) {
		conns = conns.filter(c =>
			(c.ip||'').toLowerCase().includes(filter) ||
			(c.target||'').toLowerCase().includes(filter) ||
			(c.type||'').toLowerCase().includes(filter)
		);
	}
	conns.sort((a, b) => {
		let av = a[sortKey], bv = b[sortKey];
		if (typeof av === 'string') { av = av.toLowerCase(); bv = (bv||'').toLowerCase(); }
		if (av < bv) return sortDir === 'asc' ? -1 : 1;
		if (av > bv) return sortDir === 'asc' ? 1 : -1;
		return 0;
	});

	if (!conns.length) {
		document.getElementById('connectionsTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No active connections</div>';
		return;
	}

	const cols = [
		{ key: 'ip', label: 'IP' },
		{ key: 'port', label: 'Port' },
		{ key: 'type', label: 'Type' },
		{ key: 'target', label: 'Target' },
		{ key: 'duration', label: 'Duration' },
		{ key: 'bytes_up', label: 'Bytes Up' },
		{ key: 'bytes_down', label: 'Bytes Down' },
	];
	let thead = '<tr>';
	cols.forEach(col => {
		let cls = '';
		if (sortKey === col.key) cls = sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc';
		thead += '<th class="'+cls+'" onclick="sortConns(\''+col.key+'\')">'+col.label+'</th>';
	});
	thead += '<th>Action</th></tr>';

	let html = '<table><thead>'+thead+'</thead><tbody>';
	conns.forEach(c => {
		let badge = '<span class="badge">'+esc(c.type)+'</span>';
		if (c.type === 'SOCKS5_TCP') badge = '<span class="badge socks5-tcp">SOCKS5 TCP</span>';
		else if (c.type === 'SOCKS5_UDP') badge = '<span class="badge socks5-udp">SOCKS5 UDP</span>';
		else if (c.type === 'HTTP') badge = '<span class="badge http">HTTP</span>';
		html += '<tr><td>'+esc(c.ip)+'</td><td>'+esc(c.port)+'</td><td>'+badge+'</td><td>'+esc(c.target||'N/A')+'</td><td>'+formatUptime(c.duration)+'</td><td>'+formatBytes(c.bytes_up)+'</td><td>'+formatBytes(c.bytes_down)+'</td><td><button class="btn btn-sm btn-danger" data-id="'+esc(c.id)+'" onclick="kickConn(this.dataset.id)">Kick</button></td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('connectionsTable').innerHTML = html;
}
async function kickConn(id) {
	if (!id) return;
	try {
		const res = await fetch('/api/kick', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ id: id })
		});
		if (res.ok) {
			fetchAll();
		} else {
			const data = await res.json().catch(() => ({}));
			alert('Kick failed: ' + (data.error || res.status));
		}
	} catch (err) {
		alert('Kick failed: ' + err.message);
	}
}
function exportConns(format) {
	window.location.href = '/api/export?format=' + encodeURIComponent(format);
}
function renderUpstream(up) {
	const status = up.status || [];
	let html = '<div style="padding:8px 0;color:var(--muted2);">';
	if (status.length) {
		html += status.map(s => {
			const badge = s.alive
				? '<span class="badge" style="background:var(--badge-http-bg);color:var(--badge-http-fg);">alive</span>'
				: '<span class="badge" style="background:var(--danger-hover-bg);color:var(--danger-fg);">dead</span>';
			return esc(s.addr) + ' ' + badge;
		}).join(' &nbsp;|&nbsp; ');
		html += '<br><span style="font-size:0.78rem;color:var(--muted);">Round-robin index hiện tại: ' + up.current_index + '</span>';
	} else {
		html += '<span style="color:var(--muted);">No upstream proxies configured.</span>';
	}
	html += '</div>';
	document.getElementById('upstreamInfo').innerHTML = html;
}
async function fetchNetworkConfig() {
	try {
		const res = await fetch('/api/network-config');
		if (!res.ok) throw new Error('HTTP ' + res.status);
		const data = await res.json();
		document.getElementById('netAllow').value = (data.allow_list || []).join('\n');
		document.getElementById('netDeny').value = (data.deny_list || []).join('\n');
		document.getElementById('netUpstream').value = (data.upstream_proxies || []).join('\n');
	} catch (e) {
		console.error('fetchNetworkConfig error:', e);
	}
}
function linesToList(text) {
	return text.split('\n').map(s => s.trim()).filter(s => s.length > 0);
}
async function saveNetworkConfig() {
	const msg = document.getElementById('netMsg');
	msg.textContent = 'Saving...';
	msg.className = 'modal-msg';
	try {
		const res = await fetch('/api/network-config', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				allow_list: linesToList(document.getElementById('netAllow').value),
				deny_list: linesToList(document.getElementById('netDeny').value),
				upstream_proxies: linesToList(document.getElementById('netUpstream').value)
			})
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return;
		}
		msg.textContent = 'Saved & applied successfully.';
		msg.className = 'modal-msg success';
		fetchReloadHistory();
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
}
async function reloadFromDisk() {
	const msg = document.getElementById('netMsg');
	msg.textContent = 'Reloading...';
	msg.className = 'modal-msg';
	try {
		const res = await fetch('/api/reload', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return;
		}
		msg.textContent = 'Reloaded from disk successfully.';
		msg.className = 'modal-msg success';
		fetchNetworkConfig();
		fetchReloadHistory();
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
}
async function fetchReloadHistory() {
	try {
		const res = await fetch('/api/reload-history');
		if (!res.ok) throw new Error('HTTP ' + res.status);
		const data = await res.json();
		renderReloadHistory(data.history || []);
	} catch (e) {
		document.getElementById('reloadHistoryTable').innerHTML = '<div style="padding:15px;color:var(--muted);">Failed to load reload history</div>';
	}
}
function renderReloadHistory(history) {
	if (!history.length) {
		document.getElementById('reloadHistoryTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No reload events yet.</div>';
		return;
	}
	let html = '<table><thead><tr><th>Time</th><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody>';
	history.forEach(ev => {
		const time = new Date(ev.t * 1000).toLocaleString();
		const statusBadge = ev.success
			? '<span class="badge" style="background:var(--badge-http-bg);color:var(--badge-http-fg);">OK</span>'
			: '<span class="badge" style="background:var(--danger-hover-bg);color:var(--danger-fg);">FAILED</span>';
		let details = '';
		if (ev.success) {
			details = ev.allow_count + ' allow, ' + ev.deny_count + ' deny, ' + ev.upstream_count + ' upstream, ' + ev.user_count + ' users';
			if (ev.invalid_cidrs && ev.invalid_cidrs.length) {
				details += ' — <span style="color:var(--danger-fg);">⚠️ invalid: ' + esc(ev.invalid_cidrs.join(', ')) + '</span>';
			}
		} else {
			details = '<span style="color:var(--danger-fg);">' + esc(ev.error || 'Unknown error') + '</span>';
		}
		html += '<tr><td>' + time + '</td><td>' + esc(ev.source) + '</td><td>' + statusBadge + '</td><td>' + details + '</td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('reloadHistoryTable').innerHTML = html;
}
async function fetchTokens() {
	try {
		const res = await fetch('/api/tokens');
		if (!res.ok) throw new Error('HTTP ' + res.status);
		const data = await res.json();
		renderTokens(data.tokens || []);
	} catch (e) {
		document.getElementById('tokensTable').innerHTML = '<div style="padding:15px;color:var(--muted);">Failed to load tokens</div>';
	}
}
function renderTokens(tokens) {
	if (!tokens.length) {
		document.getElementById('tokensTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No API tokens yet.</div>';
		return;
	}
	let html = '<table><thead><tr><th>Name</th><th>Created</th><th>Action</th></tr></thead><tbody>';
	tokens.forEach(t => {
		const created = new Date(t.created_at * 1000).toLocaleString();
		html += '<tr><td>' + esc(t.name) + '</td><td>' + created + '</td><td><button class="btn btn-sm btn-danger" data-name="' + esc(t.name) + '" onclick="deleteToken(this.dataset.name)">Revoke</button></td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('tokensTable').innerHTML = html;
}
function openTokenModal() {
	document.getElementById('tokenMsg').textContent = '';
	document.getElementById('tokenMsg').className = 'modal-msg';
	document.getElementById('tokenResultBox').style.display = 'none';
	document.getElementById('tokenForm').reset();
	document.getElementById('tName').disabled = false;
	document.getElementById('tokenSubmitBtn').style.display = 'inline-block';
	document.getElementById('tokenModalOverlay').classList.add('open');
}
function closeTokenModal() {
	document.getElementById('tokenModalOverlay').classList.remove('open');
	fetchTokens();
}
async function submitTokenForm(e) {
	e.preventDefault();
	const msg = document.getElementById('tokenMsg');
	const name = document.getElementById('tName').value.trim();
	try {
		const res = await fetch('/api/tokens', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ name: name })
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return false;
		}
		document.getElementById('tokenResultValue').textContent = data.token;
		document.getElementById('tokenResultBox').style.display = 'block';
		document.getElementById('tName').disabled = true;
		document.getElementById('tokenSubmitBtn').style.display = 'none';
		msg.textContent = '';
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
	return false;
}
async function deleteToken(name) {
	if (!confirm('Revoke API token "' + name + '"? Any script using it will stop working immediately.')) return;
	try {
		const res = await fetch('/api/tokens/delete', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ name: name })
		});
		if (res.ok) {
			fetchTokens();
		} else {
			const data = await res.json().catch(() => ({}));
			alert('Revoke failed: ' + (data.error || res.status));
		}
	} catch (err) {
		alert('Revoke failed: ' + err.message);
	}
}
async function fetchAuditLog() {
	try {
		const res = await fetch('/api/audit-log');
		if (!res.ok) throw new Error('HTTP ' + res.status);
		const data = await res.json();
		renderAuditLog(data.events || []);
	} catch (e) {
		document.getElementById('auditTable').innerHTML = '<div style="padding:15px;color:var(--muted);">Failed to load audit log</div>';
	}
}
function renderAuditLog(events) {
	if (!events.length) {
		document.getElementById('auditTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No audit events yet.</div>';
		return;
	}
	let html = '<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>';
	events.forEach(ev => {
		const time = new Date(ev.t * 1000).toLocaleString();
		html += '<tr><td>' + time + '</td><td>' + esc(ev.actor) + '</td><td>' + esc(ev.action) + '</td><td style="font-size:0.8rem;color:var(--muted2);">' + esc(ev.details || '') + '</td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('auditTable').innerHTML = html;
}
async function restoreConfig(e) {
	const file = e.target.files[0];
	if (!file) return;
	const msg = document.getElementById('backupMsg');
	if (!confirm('Restore config from "' + file.name + '"? This will overwrite current settings (users, allow/deny lists, upstream, tokens) and apply immediately.')) {
		e.target.value = '';
		return;
	}
	msg.textContent = 'Restoring...';
	msg.className = 'modal-msg';
	try {
		const text = await file.text();
		const res = await fetch('/api/config/import', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: text
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return;
		}
		msg.textContent = 'Restored successfully. Reloading dashboard...';
		msg.className = 'modal-msg success';
		setTimeout(() => window.location.reload(), 1500);
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	} finally {
		e.target.value = '';
	}
}
async function fetchUsers() {
	try {
		const res = await fetch('/api/users');
		if (!res.ok) throw new Error('HTTP '+res.status);
		const data = await res.json();
		renderUsers(data.users || []);
	} catch (e) {
		document.getElementById('usersTable').innerHTML = '<div style="padding:15px;color:var(--muted);">Failed to load users</div>';
	}
}
function renderUsers(users) {
	if (!users.length) {
		document.getElementById('usersTable').innerHTML = '<div style="padding:15px;color:var(--muted);">No multi-user accounts configured yet — proxy still works via -u/-P if set.</div>';
		return;
	}
	let html = '<table><thead><tr><th>Username</th><th>Max Bandwidth</th><th>Max Conns</th><th>Quota/Month</th><th>Used This Month</th><th>Action</th></tr></thead><tbody>';
	users.forEach(u => {
		const bw = u.max_bandwidth_bps > 0 ? formatBytes(u.max_bandwidth_bps)+'/s' : 'Unlimited';
		const maxConn = u.max_connections > 0 ? u.max_connections : 'Unlimited';
		const quota = u.quota_bytes_per_month > 0 ? formatBytes(u.quota_bytes_per_month) : 'Unlimited';
		const used = formatBytes(u.usage_bytes_this_month || 0);
		const overQuota = u.quota_bytes_per_month > 0 && (u.usage_bytes_this_month || 0) >= u.quota_bytes_per_month;
		const usedCell = overQuota ? '<span style="color:var(--danger-fg);">' + used + ' ⚠️ OVER QUOTA</span>' : used;
		html += '<tr><td>'+esc(u.username)+'</td><td>'+bw+'</td><td>'+maxConn+'</td><td>'+quota+'</td><td>'+usedCell+'</td><td><button class="btn btn-sm btn-danger" data-name="'+esc(u.username)+'" onclick="deleteUser(this.dataset.name)">Delete</button></td></tr>';
	});
	html += '</tbody></table>';
	document.getElementById('usersTable').innerHTML = html;
}
function openUserModal() {
	document.getElementById('userMsg').textContent = '';
	document.getElementById('userMsg').className = 'modal-msg';
	document.getElementById('userForm').reset();
	document.getElementById('userModalOverlay').classList.add('open');
}
function closeUserModal() {
	document.getElementById('userModalOverlay').classList.remove('open');
}
async function submitUserForm(e) {
	e.preventDefault();
	const msg = document.getElementById('userMsg');
	const username = document.getElementById('uUsername').value.trim();
	const password = document.getElementById('uPassword').value;
	const bwKBs = parseFloat(document.getElementById('uBandwidth').value) || 0;
	const maxConn = parseInt(document.getElementById('uMaxConn').value) || 0;
	const quotaMB = parseFloat(document.getElementById('uQuota').value) || 0;
	try {
		const res = await fetch('/api/users', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				username: username, password: password,
				max_bandwidth_bps: Math.round(bwKBs * 1024),
				max_connections: maxConn,
				quota_bytes_per_month: Math.round(quotaMB * 1024 * 1024)
			})
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return false;
		}
		closeUserModal();
		fetchUsers();
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
	return false;
}
async function deleteUser(username) {
	if (!confirm('Delete proxy user "'+username+'"?')) return;
	try {
		const res = await fetch('/api/users/delete', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username: username })
		});
		if (res.ok) {
			fetchUsers();
		} else {
			const data = await res.json().catch(() => ({}));
			alert('Delete failed: ' + (data.error || res.status));
		}
	} catch (err) {
		alert('Delete failed: ' + err.message);
	}
}
function esc(v) {
	return String(v === undefined || v === null ? '' : v)
		.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function formatBytes(b) {
	if (b === undefined || b === null) return '0 B';
	const units=['B','KiB','MiB','GiB','TiB'];
	let u=0;
	while(b>=1024 && u<units.length-1){ b/=1024; u++; }
	return b.toFixed(1)+' '+units[u];
}
function formatUptime(sec) {
	if (!sec) return '00:00:00';
	const h=Math.floor(sec/3600), m=Math.floor((sec%3600)/60), s=Math.floor(sec%60);
	return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
}
function openPwModal() {
	document.getElementById('pwMsg').textContent = '';
	document.getElementById('pwMsg').className = 'modal-msg';
	document.getElementById('pwForm').reset();
	document.getElementById('pwModalOverlay').classList.add('open');
}
function closePwModal() {
	document.getElementById('pwModalOverlay').classList.remove('open');
}
async function submitPwChange(e) {
	e.preventDefault();
	const msg = document.getElementById('pwMsg');
	const curPass = document.getElementById('curPass').value;
	const newUser = document.getElementById('newUser').value.trim();
	const newPass = document.getElementById('newPass').value;
	const newPass2 = document.getElementById('newPass2').value;

	if (newPass !== newPass2) {
		msg.textContent = 'Password confirmation does not match.';
		msg.className = 'modal-msg error';
		return false;
	}
	if (newPass.length < 8) {
		msg.textContent = 'New password must be at least 8 characters.';
		msg.className = 'modal-msg error';
		return false;
	}

	try {
		const res = await fetch('/api/change-password', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				current_password: curPass,
				new_username: newUser,
				new_password: newPass
			})
		});
		const data = await res.json();
		if (!res.ok) {
			msg.textContent = data.error || ('HTTP Error ' + res.status);
			msg.className = 'modal-msg error';
			return false;
		}
		msg.textContent = 'Changed successfully! The browser will ask you to log in again with the new credentials.';
		msg.className = 'modal-msg success';
		setTimeout(() => { window.location.reload(); }, 1500);
	} catch (err) {
		msg.textContent = 'Connection error: ' + err.message;
		msg.className = 'modal-msg error';
	}
	return false;
}
// Dữ liệu cốt lõi của dashboard (stats, connections, users) chạy trước và độc lập
// với Chart.js — nếu CDN chart bị chặn/lỗi mạng, dashboard vẫn phải hoạt động bình thường.
fetchAll();
fetchUsers();
fetchNetworkConfig();
fetchReloadHistory();
fetchTokens();
fetchAuditLog();
setInterval(fetchAll, 5000);
setInterval(fetchUsers, 15000);
setInterval(fetchReloadHistory, 15000);
setInterval(fetchAuditLog, 15000);

// Biểu đồ real-time (phụ thuộc CDN Chart.js) — bọc try/catch để một lỗi ở đây
// không làm dừng toàn bộ script phía trên (đã từng gây ra bug "mọi thứ kẹt ở Loading...").
// loadScript/loadChartJS: thử lần lượt vài CDN khác nhau, vì 1 CDN cụ thể (vd cdnjs) có
// thể bị chặn ở 1 số mạng/firewall dù máy vẫn có Internet bình thường.
function loadScript(src) {
	return new Promise((resolve, reject) => {
		const tag = document.createElement('script');
		tag.src = src;
		tag.onload = () => resolve();
		tag.onerror = () => reject(new Error('Không tải được: ' + src));
		document.head.appendChild(tag);
	});
}
async function loadChartJS() {
	const urls = [
		'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js',
		'https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js',
		'https://unpkg.com/chart.js@4.4.4/dist/chart.umd.min.js'
	];
	for (const url of urls) {
		try {
			await loadScript(url);
			if (typeof Chart !== 'undefined') return true;
		} catch (e) {
			console.warn(e.message);
		}
	}
	return false;
}
(async function() {
try {
	const chartLoaded = await loadChartJS();
	if (!chartLoaded) {
		throw new Error('Không tải được Chart.js từ bất kỳ CDN nào (cdnjs/jsdelivr/unpkg) — có thể mạng/firewall đang chặn các CDN này');
	}
	initChart();
	connectStream();
} catch (err) {
	console.error('Traffic chart disabled:', err);
	const statusEl = document.getElementById('streamStatus');
	if (statusEl) { statusEl.textContent = '(unavailable)'; statusEl.style.color = 'var(--danger-fg)'; }
	const canvasEl = document.getElementById('trafficChart');
	if (canvasEl) {
		canvasEl.outerHTML = '<div style="padding:20px;color:var(--danger-fg);font-size:0.85rem;">'
			+ '⚠️ Không tải được biểu đồ: ' + err.message + '<br>'
			+ 'Các phần khác của dashboard (stats, connections, users) vẫn hoạt động bình thường.'
			+ '</div>';
	}
}
})();
</script>
</body></html>
  HTML
end

# ══════════════════════════════════════════════════════════════════════
# BACKGROUND LOOPS
# ══════════════════════════════════════════════════════════════════════
def start_background_threads
  # Stats reporter / SSE sampler
  Thread.new do
    last_up = last_down = 0
    first = true
    interval = 2.0
    until State.shutdown_flag
      sleep interval
      next if State.shutdown_flag
      s = State.stats_lock.synchronize { State.stats.dup }
      up_bps   = first ? 0 : ((s[:bytes_up] - last_up) / interval).to_i
      down_bps = first ? 0 : ((s[:bytes_down] - last_down) / interval).to_i
      last_up = s[:bytes_up]; last_down = s[:bytes_down]; first = false
      sample = { t: Time.now.to_i, up_bps: up_bps, down_bps: down_bps,
                 active: State.active_lock.synchronize { State.active_conns.size },
                 udp_assocs: State.udp_lock.synchronize { State.udp_assocs.size } }
      State.hist_lock.synchronize do
        State.hist_sample << sample
        State.hist_sample.shift while State.hist_sample.size > HIST_MAX
      end
      State.sse_lock.synchronize do
        State.sse_clients.each { |q| begin; q.push(sample); rescue; end }
      end
    end
  rescue StandardError
  end

  # Upstream health checker
  Thread.new do
    until State.shutdown_flag
      sleep 15
      next if State.shutdown_flag
      ups = State.upstream_lock.synchronize { State.upstream_proxies.dup }
      ups.each do |h, p|
        begin
          s = Socket.tcp(h, p, connect_timeout: 3)
          s.close
          Upstream.set_health("#{h}:#{p}", true)
        rescue StandardError
          Upstream.set_health("#{h}:#{p}", false)
        end
      end
    end
  rescue StandardError
  end

  # Quota enforcement
  Thread.new do
    until State.shutdown_flag
      sleep 10
      next if State.shutdown_flag
      quotas = State.cfg_lock.synchronize do
        (State.cfg&.users || []).each_with_object({}) do |u, h|
          h[u['username']] = (u['quota_bytes_per_month'] || 0).to_i
        end
      end
      quotas.each do |uname, q|
        next if q <= 0 || Usage.get(uname) < q
        victims = State.active_lock.synchronize do
          State.active_conns.values.select { |c| c.username == uname }
        end
        victims.each { |c| begin; c.conn.close; rescue; end }
        Util.log_warn "Ngắt #{victims.size} conn của user #{uname} do vượt quota" if victims.any?
      end
    end
  rescue StandardError
  end

  # Usage save
  Thread.new do
    until State.shutdown_flag
      sleep 30
      next if State.shutdown_flag
      Usage.save!($usage_path)
    end
  rescue StandardError
  end
end

# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════
$config_path = 'proxy_config.json'
$usage_path  = 'proxy_usage.json'

def parse_args(argv)
  opts = {
    listen: '0.0.0.0', port: 1080,
    username: '', password: '',
    no_udp: false, upstream: '',
    cert: nil, key: nil,
    dashboard_port: DASHBOARD_PORT,
    dashboard_bind: '0.0.0.0',
    config: 'proxy_config.json',
    usage_file: 'proxy_usage.json',
    dashboard_user: 'admin',
    dashboard_pass: '',
    allow: '', deny: ''
  }
  i = 0
  while i < argv.size
    a = argv[i]
    case a
    when '-l', '--listen'      then opts[:listen] = argv[i += 1]
    when '-p', '--port'        then opts[:port] = argv[i += 1].to_i
    when '-u', '--username'    then opts[:username] = argv[i += 1]
    when '-P', '--password'    then opts[:password] = argv[i += 1]
    when '--no-udp'            then opts[:no_udp] = true
    when '--upstream'          then opts[:upstream] = argv[i += 1]
    when '--cert'              then opts[:cert] = argv[i += 1]
    when '--key'               then opts[:key] = argv[i += 1]
    when '--dashboard-port'    then opts[:dashboard_port] = argv[i += 1].to_i
    when '--dashboard-bind'    then opts[:dashboard_bind] = argv[i += 1]
    when '--config'            then opts[:config] = argv[i += 1]
    when '--usage-file'        then opts[:usage_file] = argv[i += 1]
    when '--dashboard-user'    then opts[:dashboard_user] = argv[i += 1]
    when '--dashboard-pass'    then opts[:dashboard_pass] = argv[i += 1]
    when '--allow'             then opts[:allow] = argv[i += 1]
    when '--deny'              then opts[:deny] = argv[i += 1]
    when '-h', '--help'
      puts <<~HELP
        Universal Proxy Pro v6.3.6 (Ruby)
        Usage: ruby proxy.rb [options]
          -l, --listen ADDR          Bind address (default 0.0.0.0)
          -p, --port PORT            Proxy port (default 1080)
          -u, --username USER        Legacy auth user
          -P, --password PASS        Legacy auth pass
              --no-udp               Disable SOCKS5 UDP ASSOCIATE
              --upstream LIST        Upstream proxies (host:port,...)
              --cert FILE            TLS cert (PEM)
              --key FILE             TLS key (PEM)
              --dashboard-port PORT  (default 8081)
              --dashboard-bind ADDR  (default 0.0.0.0)
              --config FILE          Config JSON (default proxy_config.json)
              --usage-file FILE      Usage JSON (default proxy_usage.json)
              --dashboard-user USER  Only first run
              --dashboard-pass PASS  Only first run
              --allow CIDRS          IP whitelist (comma-separated, first run)
              --deny CIDRS           IP blacklist (first run)
          -h, --help                 Show this help
      HELP
      exit 0
    end
    i += 1
  end
  opts
end

def main
  opts = parse_args(ARGV)
  $config_path = opts[:config]
  $usage_path  = opts[:usage_file]

  begin
    rl = Process.getrlimit(:NOFILE)
    Process.setrlimit(:NOFILE, 65536, rl[1]) if rl[0] < 65536
  rescue StandardError
  end

  Usage.load!($usage_path)

  init_pass = opts[:dashboard_pass]
  generated = nil
  if !File.exist?($config_path) && init_pass.to_s.empty?
    init_pass = SecureRandom.hex(8)
    generated = init_pass
  end

  cfg, was_created = begin
    ConfigFile.load_or_init($config_path, opts[:dashboard_user], init_pass.empty? ? 'changeme' : init_pass)
  rescue StandardError => e
    Util.log_err e.message
    exit 1
  end
  State.cfg = cfg

  if was_created && generated
    Util.log_warn "Dashboard lần đầu — user: #{opts[:dashboard_user]} | password: #{generated}"
    Util.log_warn "(chỉ hiện MỘT LẦN — đổi ngay trên dashboard)"
  end

  if was_created
    State.cfg_lock.synchronize do
      State.cfg.allow_list = opts[:allow].split(',').map(&:strip).reject(&:empty?)
      State.cfg.deny_list  = opts[:deny].split(',').map(&:strip).reject(&:empty?)
      State.cfg.upstream_proxies = opts[:upstream].split(',').map(&:strip).reject(&:empty?)
      ConfigFile.save_locked($config_path, State.cfg)
    end
  end

  na, _ = SSRF.parse_cidrs(State.cfg.allow_list)
  nd, _ = SSRF.parse_cidrs(State.cfg.deny_list)
  State.allowed_cidrs = na
  State.denied_cidrs  = nd

  State.upstream_proxies = State.cfg.upstream_proxies.map do |it|
    next nil unless it.include?(':')
    h, _, p = it.rpartition(':')
    next nil if h.empty?
    begin; [h, Integer(p)]; rescue ArgumentError; nil; end
  end.compact

  if State.cfg.dashboard_user == 'admin' && Util.verify_password('admin', State.cfg.dashboard_password_hash)
    Util.log_warn 'Dashboard đang dùng admin/admin — đổi ngay!'
  end

  proxy_listener = TCPServer.new(opts[:listen], opts[:port])
  proxy_listener.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)

  if opts[:cert] && opts[:key]
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.cert = OpenSSL::X509::Certificate.new(File.read(opts[:cert]))
    ctx.key = OpenSSL::PKey::RSA.new(File.read(opts[:key]))
    ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
    proxy_listener = OpenSSL::SSL::SSLServer.new(proxy_listener, ctx)
    Util.log 'TLS đã bật cho listener chính'
  end

  dash = Dashboard.new(opts[:dashboard_bind], opts[:dashboard_port])
  dash.start

  Util.log "#{GREEN}Proxy v6.3.6 (Ruby) STARTED → #{opts[:listen]}:#{opts[:port]}#{RESET}"
  Util.log "#{CYAN}Users: #{State.cfg.users.size} | Upstream: #{State.upstream_proxies.size} | Config: #{$config_path}#{RESET}"

  start_background_threads

  Signal.trap('INT')  { State.shutdown_flag = true }
  Signal.trap('TERM') { State.shutdown_flag = true }
  Signal.trap('HUP')  { Thread.new { ConfigFile.reload!($config_path) } }

  at_exit do
    Usage.save!($usage_path)
    dash.stop
    begin; proxy_listener.close; rescue; end
  end

  threads = []
  threads_lock = Mutex.new
  conn_count = 0
  count_lock = Mutex.new

  loop do
    break if State.shutdown_flag
    begin
      ready = IO.select([proxy_listener], nil, nil, 1.0)
      next unless ready
      sock = proxy_listener.accept
    rescue IOError, Errno::EBADF
      break
    rescue StandardError => e
      Util.log_err "Accept error: #{e.message}"
      sleep 0.5
      next
    end

    count_lock.synchronize { conn_count += 1 }
    peer = begin; sock.peeraddr; rescue; nil; end
    next (sock.close rescue nil) unless peer

    t = Thread.new do
      begin
        ProxyHandler.new(sock, Addrinfo.tcp(peer[3], peer[1]), {
          username: opts[:username], password: opts[:password],
          auth_required: !opts[:username].empty? && !opts[:password].empty?,
          enable_udp: !opts[:no_udp]
        }).handle
      rescue StandardError => e
        Util.log_err "Handler thread: #{e.message}"
        begin; sock.close; rescue; end
      ensure
        count_lock.synchronize { conn_count -= 1 }
      end
    end
    t.abort_on_exception = false

    # Periodic cleanup of dead threads
    if count_lock.synchronize { conn_count } > 100
      threads.reject! { |x| !x.alive? }
    end
    threads << t
  end

  Util.log "#{RED}Proxy STOPPED#{RESET}"
end

if __FILE__ == $PROGRAM_NAME
  main
end

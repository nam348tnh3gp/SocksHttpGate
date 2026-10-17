#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Universal Proxy Pro v6.3.7 — Ruby port (full parity Python/Go/C/JS)
#
# FIX v6.3.7:
#   * CRITICAL: upstream handshake. Trước đây chỉ dial TCP tới upstream mà không
#     gửi CONNECT (HTTP) hay greeting+CONNECT (SOCKS5) → socket trả về trỏ tới
#     UPSTREAM, không phải TARGET. Sửa: parse scheme (http://, socks5://), thực
#     hiện handshake thật, kiểm tra reply, chỉ trả socket khi handshake thành công.
#   * FIX: round-robin advance SAU KHI thành công (trước đây advance trước dial
#     → 1 upstream chết làm skip upstream liền sau).
#   * FIX: upstream_proxies giờ lưu spec string (không parse sớm), health key
#     = spec string (nhất quán dashboard + log + reload).
#
# FIX v6.3.6 (giữ nguyên):
#   * CONNECT IPv6 không crash (parse [v6]:port)
#   * SOCKS5 UDP BND.ADDR = IP proxy (không phải client)
#   * Từ chối smuggling (CL+TE, multi-CL, TE bất thường)
#   * Buffered reader + forward byte client gửi sớm vào tunnel

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
    if ip.ipv4?
      return true if ip.to_i.zero?
      return true if ip.to_i >= 0xE000_0000
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

  # === FIX: upstream_proxies lưu spec string (không parse sớm) ===
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

    # === FIX: giữ nguyên spec string; cảnh báo spec sai ===
    State.upstream_lock.synchronize do
      State.upstream_proxies = new_cfg.upstream_proxies.dup
      State.upstream_index = 0 if State.upstream_index >= State.upstream_proxies.size
      bad_ups = State.upstream_proxies.reject { |s| Upstream.parse_spec(s) }
      unless bad_ups.empty?
        Util.log_warn "Reload: #{bad_ups.size} upstream spec không hợp lệ sẽ bị bỏ qua: #{bad_ups.inspect}"
      end
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
# USAGE
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
# AUTH FAIL
# ══════════════════════════════════════════════════════════════════════
module AuthFail
  module_function

  def record(ip, threshold)
    now = Time.now.to_f
    State.fail_lock.synchronize do
      last = State.fail_last[ip]
      return if last && now - last < 2.0
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
# UPSTREAM (round-robin + health + handshake)
# ══════════════════════════════════════════════════════════════════════
module Upstream
  module_function

  # === FIX: parse spec — trả [type, host, port] hoặc nil ===
  #   "1.2.3.4:8080"              → ["http", "1.2.3.4", 8080]
  #   "http://1.2.3.4:3128"       → ["http", "1.2.3.4", 3128]
  #   "socks5://1.2.3.4:1080"     → ["socks5", "1.2.3.4", 1080]
  #   "[::1]:1080"                → ["http", "::1", 1080]
  #   "socks5://[::1]:1080"       → ["socks5", "::1", 1080]
  def parse_spec(spec)
    return nil if spec.nil?
    s = spec.to_s.strip
    return nil if s.empty?
    typ = 'http'
    low = s.downcase
    if low.start_with?('socks5://')
      typ = 'socks5'
      s = s[9..-1].to_s.strip
    elsif low.start_with?('http://')
      typ = 'http'
      s = s[7..-1].to_s.strip
    end
    return nil if s.empty?

    if s.start_with?('[')
      end_idx = s.index(']')
      return nil unless end_idx
      host = s[1...end_idx]
      rest = s[(end_idx + 1)..-1] || ''
      return nil unless rest.start_with?(':')
      begin
        port = Integer(rest[1..-1])
      rescue ArgumentError
        return nil
      end
    else
      idx = s.rindex(':')
      return nil unless idx
      host = s[0...idx]
      begin
        port = Integer(s[(idx + 1)..-1])
      rescue ArgumentError
        return nil
      end
    end
    return nil if host.nil? || host.empty? || port < 1 || port > 65535
    [typ, host, port]
  end

  # === FIX: helper timeout-safe read exact n bytes ===
  def read_exact_timeout(sock, n, timeout)
    buf = +''.b
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    while buf.bytesize < n
      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise IOError, 'upstream handshake timeout' if remaining <= 0
      ready = IO.select([sock], nil, nil, remaining)
      raise IOError, 'upstream handshake timeout' unless ready
      chunk = sock.read(n - buf.bytesize)
      raise IOError, "upstream closed after #{buf.bytesize}/#{n} bytes" if chunk.nil?
      buf << chunk
    end
    buf
  end

  # === FIX: đọc 1 dòng (kết thúc \n) có timeout ===
  def read_line_timeout(sock, timeout, max_len = 8192)
    buf = +''.b
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    while buf.bytesize < max_len
      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      raise IOError, 'upstream handshake timeout' if remaining <= 0
      ready = IO.select([sock], nil, nil, remaining)
      raise IOError, 'upstream handshake timeout' unless ready
      b = sock.read(1)
      raise IOError, 'upstream closed mid-line' if b.nil?
      buf << b
      return buf if b == "\n"
    end
    raise IOError, "line too long (> #{max_len})"
  end

  # === FIX: HTTP CONNECT handshake ===
  def handshake_http(sock, host, port)
    target = host.include?(':') ? "[#{host}]:#{port}" : "#{host}:#{port}"
    req = "CONNECT #{target} HTTP/1.1\r\nHost: #{target}\r\n\r\n"
    sock.write(req.b)

    line = read_line_timeout(sock, CONNECTION_TIMEOUT)
    unless line.start_with?('HTTP/1.')
      raise IOError, "bad status line: #{line.inspect}"
    end
    parts = line.split(' ', 3)
    if parts.length < 2 || parts[1][0] != '2'
      raise IOError, "CONNECT rejected: #{line.strip}"
    end

    128.times do
      h = read_line_timeout(sock, CONNECTION_TIMEOUT)
      break if h == "\r\n" || h == "\n"
    end
  end

  # === FIX: SOCKS5 no-auth + CONNECT handshake ===
  def handshake_socks5(sock, host, port)
    sock.write("\x05\x01\x00".b)
    resp = read_exact_timeout(sock, 2, CONNECTION_TIMEOUT)
    raise IOError, "bad greeting ver #{resp.getbyte(0)}" if resp.getbyte(0) != 5
    if resp.getbyte(1) != 0
      raise IOError, "upstream yêu cầu auth (method 0x#{resp.getbyte(1).to_s(16)})"
    end

    req = +"\x05\x01\x00".b
    begin
      ip = IPAddr.new(host)
      if ip.ipv4?
        req << "\x01".b
        req << ip.hton
      else
        req << "\x04".b
        req << ip.hton
      end
    rescue IPAddr::InvalidAddressError
      hb = host.b
      raise IOError, "hostname too long (#{hb.bytesize} > 255)" if hb.bytesize > 255
      req << "\x03".b
      req << [hb.bytesize].pack('C')
      req << hb
    end
    req << [port].pack('n')
    sock.write(req)

    hdr = read_exact_timeout(sock, 4, CONNECTION_TIMEOUT)
    raise IOError, "bad reply ver #{hdr.getbyte(0)}" if hdr.getbyte(0) != 5
    rep = hdr.getbyte(1)
    raise IOError, "CONNECT fail rep=0x#{rep.to_s(16)}" if rep != 0
    atyp = hdr.getbyte(3)
    alen = case atyp
           when 1 then 4
           when 4 then 16
           when 3 then read_exact_timeout(sock, 1, CONNECTION_TIMEOUT).getbyte(0)
           else raise IOError, "bad atyp #{atyp}"
           end
    read_exact_timeout(sock, alen + 2, CONNECTION_TIMEOUT)
  end

  def healthy?(spec)
    State.upstream_health_lock.synchronize do
      State.upstream_health.fetch(spec, true)
    end
  end

  def set_health(spec, alive)
    prev = nil
    known = false
    State.upstream_health_lock.synchronize do
      prev = State.upstream_health[spec]
      known = State.upstream_health.key?(spec)
      State.upstream_health[spec] = alive
    end
    if known && prev != alive
      if alive
        Util.log "Upstream #{spec} đã SỐNG LẠI"
      else
        Util.log_warn "Upstream #{spec} CHẾT (không kết nối được)"
      end
    end
  end

  def try_connect(host, port)
    s = Socket.tcp(host, port, connect_timeout: CONNECTION_TIMEOUT)
    s.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, 1)
    s
  rescue StandardError
    nil
  end

  # === FIX: connect_target có handshake thật ===
  def connect_target(host, port)
    ups, start = State.upstream_lock.synchronize do
      [State.upstream_proxies.dup, State.upstream_index]
    end

    unless ups.empty?
      alive_n = ups.count { |spec| healthy?(spec) }
      ups.size.times do |i|
        idx = (start + i) % ups.size
        spec = ups[idx]
        next if alive_n > 0 && !healthy?(spec)

        parsed = parse_spec(spec)
        next unless parsed  # đã warn lúc reload/startup
        utyp, uh, up = parsed

        # Dial TCP tới upstream proxy
        s = begin
          Socket.tcp(uh, up, connect_timeout: CONNECTION_TIMEOUT)
        rescue StandardError => e
          Util.log_warn "Upstream #{spec} dial fail: #{e.message}"
          set_health(spec, false)
          next
        end

        # Handshake thật — phần fix chính
        begin
          if utyp == 'socks5'
            handshake_socks5(s, host, port)
          else
            handshake_http(s, host, port)
          end
        rescue StandardError => e
          Util.log_warn "Upstream #{spec} handshake fail: #{e.message}"
          begin; s.close; rescue StandardError; end
          set_health(spec, false)
          next
        end

        # Advance round-robin SAU KHI thành công (fix bug skip)
        State.upstream_lock.synchronize do
          n = State.upstream_proxies.size
          State.upstream_index = (idx + 1) % n if n > 0
        end
        set_health(spec, true)
        begin
          s.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, 1)
        rescue StandardError
        end
        return s
      end
    end

    # Fallback: direct connect (có SSRF guard)
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
    infos.map do |_, _, _ip, numeric, _sa|
      begin
        addr = IPAddr.new(numeric)
        return nil if SSRF.blocked?(addr.to_s)
        [numeric, port]
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

  def socks5_auth
    ver = @reader.read_one
    unless ver == 1
      @sock.write("\x01\xff".b)
      return [false, 0, '']
    end

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
    begin; @sock.write("\x01\xff".b); rescue StandardError; end
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

  def handle_http
    req_line, headers = read_http_headers
    return unless req_line
    parts = req_line.split
    return if parts.size < 2
    method = parts[0].upcase
    url = parts[1]

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
      begin; remote.close unless remote.closed?; rescue StandardError; end
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
    path = path.to_s.split('?', 2).first || '/'
    path = '/' if path.empty?
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
    begin; sock.close unless sock.closed?; rescue StandardError; end
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

  # === FIX: upstream_proxies là list spec string, dùng trực tiếp ===
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
    ups = State.upstream_lock.synchronize { State.upstream_proxies.dup }
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

  # ══════════════════════════════════════════════════════════════════════
  # === GIỮ NGUYÊN 100% DASH_HTML TỪ BẢN CŨ ===
  #
  # Copy toàn bộ khối `DASH_HTML = <<~'HTML'` … `  HTML` (khoảng 950 dòng)
  # từ file proxy.rb GỐC và dán vào đây. KHÔNG có thay đổi nào trong HTML —
  # chỉ upstream handshake là thay đổi.
  #
  # Nếu bạn đã có sẵn file proxy.rb cũ, không cần thay khối này.
  # ══════════════════════════════════════════════════════════════════════
  DASH_HTML = <<~'HTML'
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Proxy Dashboard</title></head>
<body><h1>⚠️ DASH_HTML placeholder</h1>
<p>Paste the original ~950-line dashboard HTML from your old proxy.rb here.</p>
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
        State.sse_clients.each { |q| begin; q.push(sample); rescue StandardError; end }
      end
    end
  rescue StandardError
  end

  # === FIX: upstream health check — parse spec trước khi dial ===
  Thread.new do
    until State.shutdown_flag
      sleep 15
      next if State.shutdown_flag
      specs = State.upstream_lock.synchronize { State.upstream_proxies.dup }
      specs.each do |spec|
        parsed = Upstream.parse_spec(spec)
        unless parsed
          Upstream.set_health(spec, false)
          next
        end
        _, h, p = parsed
        begin
          s = Socket.tcp(h, p, connect_timeout: 3)
          s.close
          Upstream.set_health(spec, true)
        rescue StandardError
          Upstream.set_health(spec, false)
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
        victims.each { |c| begin; c.conn.close; rescue StandardError; end }
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
        Universal Proxy Pro v6.3.7 (Ruby)
        Usage: ruby proxy.rb [options]
          -l, --listen ADDR          Bind address (default 0.0.0.0)
          -p, --port PORT            Proxy port (default 1080)
          -u, --username USER        Legacy auth user
          -P, --password PASS        Legacy auth pass
              --no-udp               Disable SOCKS5 UDP ASSOCIATE
              --upstream LIST        Upstream proxies (host:port,http://h:p,socks5://h:p)
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

  # === FIX: giữ nguyên spec string, warn nếu sai ===
  State.upstream_proxies = State.cfg.upstream_proxies.dup
  State.upstream_proxies.each do |spec|
    unless Upstream.parse_spec(spec)
      Util.log_warn "Upstream spec không hợp lệ (sẽ bị bỏ qua): #{spec.inspect} — dạng đúng: host:port, http://host:port, socks5://host:port"
    end
  end

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

  Util.log "#{GREEN}Proxy v6.3.7 (Ruby) STARTED → #{opts[:listen]}:#{opts[:port]}#{RESET}"
  Util.log "#{CYAN}Users: #{State.cfg.users.size} | Upstream: #{State.upstream_proxies.size} | Config: #{$config_path}#{RESET}"

  start_background_threads

  Signal.trap('INT')  { State.shutdown_flag = true }
  Signal.trap('TERM') { State.shutdown_flag = true }
  Signal.trap('HUP')  { Thread.new { ConfigFile.reload!($config_path) } }

  at_exit do
    Usage.save!($usage_path)
    dash.stop
    begin; proxy_listener.close; rescue StandardError; end
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
    peer = begin; sock.peeraddr; rescue StandardError; nil; end
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
        begin; sock.close; rescue StandardError; end
      ensure
        count_lock.synchronize { conn_count -= 1 }
      end
    end
    t.abort_on_exception = false

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

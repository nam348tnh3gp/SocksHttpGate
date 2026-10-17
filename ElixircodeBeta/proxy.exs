#!/usr/bin/env elixir
# ============================================================================
# Universal Proxy Pro v6.3.6 — Elixir single-file port
# ============================================================================
# Chạy:    elixir proxy.exs -p 1080 --dashboard-port 8081
# Multi-core: elixir --erl "+K true" proxy.exs -p 1080
# Termux:  pkg install elixir && elixir proxy.exs
# ============================================================================

:application.ensure_all_started(:crypto)

# ============================================================================
# JSON
# ============================================================================
defmodule P.JSON do
  def encode(term), do: IO.iodata_to_binary(enc(term))

  defp enc(nil), do: "null"
  defp enc(true), do: "true"
  defp enc(false), do: "false"
  defp enc(n) when is_integer(n), do: Integer.to_string(n)
  defp enc(n) when is_float(n), do: Float.to_string(n)
  defp enc(s) when is_binary(s), do: [?", esc(s), ?"]
  defp enc(a) when is_list(a), do: [?[, Enum.intersperse(Enum.map(a, &enc/1), ?,), ?]]
  defp enc(m) when is_map(m) do
    pairs = Enum.map(m, fn {k, v} -> [enc(to_string(k)), ?:, enc(v)] end)
    [?{, Enum.intersperse(pairs, ?,), ?}]
  end

  defp esc(s) do
    for <<c <- s>>, into: "" do
      case c do
        ?" -> "\\\""
        ?\\ -> "\\\\"
        ?\n -> "\\n"
        ?\r -> "\\r"
        ?\t -> "\\t"
        c when c < 32 -> "\\u" <> String.pad_leading(Integer.to_string(c, 16), 4, "0")
        c -> <<c>>
      end
    end
  end

  def decode(bin) when is_binary(bin) do
    try do
      {v, rest} = parse(skip_ws(bin))
      case skip_ws(rest) do
        "" -> {:ok, v}
        _ -> {:error, :trailing}
      end
    catch
      {:json_err, m} -> {:error, m}
    end
  end

  defp skip_ws(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: skip_ws(rest)
  defp skip_ws(b), do: b

  defp parse(<<"null", r::binary>>), do: {nil, r}
  defp parse(<<"true", r::binary>>), do: {true, r}
  defp parse(<<"false", r::binary>>), do: {false, r}
  defp parse(<<?", r::binary>>), do: parse_str(r, "")
  defp parse(<<?{, r::binary>>), do: parse_obj(skip_ws(r), %{})
  defp parse(<<?[, r::binary>>), do: parse_arr(skip_ws(r), [])
  defp parse(b) when is_binary(b), do: parse_num(b)
  defp parse(_), do: throw({:json_err, :bad_char})

  defp parse_str(<<?\\, c, r::binary>>, acc) do
    case c do
      ?" -> parse_str(r, acc <> "\"")
      ?\\ -> parse_str(r, acc <> "\\")
      ?/ -> parse_str(r, acc <> "/")
      ?b -> parse_str(r, acc <> "\b")
      ?f -> parse_str(r, acc <> "\f")
      ?n -> parse_str(r, acc <> "\n")
      ?r -> parse_str(r, acc <> "\r")
      ?t -> parse_str(r, acc <> "\t")
      ?u ->
        <<h::binary-size(4), r2::binary>> = r
        cp = String.to_integer(h, 16)
        parse_str(r2, acc <> <<cp::utf8>>)
    end
  end
  defp parse_str(<<?", r::binary>>, acc), do: {acc, r}
  defp parse_str(<<c, r::binary>>, acc), do: parse_str(r, acc <> <<c>>)
  defp parse_str(_, _), do: throw({:json_err, :unterminated_string})

  defp parse_obj(<<?}, r::binary>>, m), do: {m, r}
  defp parse_obj(<<?", r::binary>>, m) do
    {k, r2} = parse_str(r, "")
    case skip_ws(r2) do
      <<?:, r3::binary>> ->
        {v, r4} = parse(skip_ws(r3))
        case skip_ws(r4) do
          <<?,, r5::binary>> -> parse_obj(skip_ws(r5), Map.put(m, k, v))
          <<?}, r5::binary>> -> {Map.put(m, k, v), r5}
          _ -> throw({:json_err, :expected_comma})
        end
      _ -> throw({:json_err, :expected_colon})
    end
  end
  defp parse_obj(_, _), do: throw({:json_err, :expected_key})

  defp parse_arr(<<?], r::binary>>, a), do: {Enum.reverse(a), r}
  defp parse_arr(b, a) do
    {v, r} = parse(b)
    case skip_ws(r) do
      <<?,, r2::binary>> -> parse_arr(skip_ws(r2), [v | a])
      <<?], r2::binary>> -> {Enum.reverse([v | a]), r2}
      _ -> throw({:json_err, :expected_comma_arr})
    end
  end

  defp parse_num(b) do
    {int_part, r1} = take_int(b)
    {full, r} = case r1 do
      <<?., r2::binary>> ->
        {frac, r3} = take_digits(r2)
        {int_part <> "." <> frac, r3}
      _ -> {int_part, r1}
    end
    case Integer.parse(full) do
      {i, ""} -> {i, r}
      _ -> case Float.parse(full) do
        {f, ""} -> {f, r}
        _ -> throw({:json_err, :bad_number})
      end
    end
  end
  defp take_int(<<?-, r::binary>>) do
    {d, r2} = take_digits(r)
    {"-" <> d, r2}
  end
  defp take_int(b), do: take_digits(b)
  defp take_digits(b), do: take_digits(b, "")
  defp take_digits(<<c, r::binary>>, acc) when c in ?0..?9, do: take_digits(r, acc <> <<c>>)
  defp take_digits(r, acc), do: {acc, r}
end

# ============================================================================
# HASH
# ============================================================================
defmodule P.Hash do
  def hash_password(pw, iters \\ nil) do
    iters = iters || Application.get_env(:proxy, :hash_iters, 200_000)
    salt = :crypto.strong_rand_bytes(16)
    dg = digest(pw, salt, iters)
    "#{iters}:#{Base.encode16(salt, case: :lower)}:#{Base.encode16(dg, case: :lower)}"
  end

  def verify(pw, stored) when is_binary(stored) do
    with [it_s, salt_h, want_h] <- String.split(stored, ":"),
         {iters, ""} <- Integer.parse(it_s),
         true <- iters > 0 and iters <= 5_000_000,
         {:ok, salt} <- dec(salt_h),
         {:ok, want} <- dec(want_h),
         true <- byte_size(want) == 32 do
      got = digest(pw, salt, iters)
      :crypto.hash_equals(got, want)
    else
      _ -> false
    end
  end
  def verify(_, _), do: false

  defp digest(pw, salt, iters) do
    initial = :crypto.hash(:sha256, salt <> pw)
    loop(initial, iters - 1)
  end
  defp loop(d, 0), do: d
  defp loop(d, n), do: loop(:crypto.hash(:sha256, d), n - 1)

  defp dec(h) do
    try do
      {:ok, Base.decode16!(h, case: :mixed)}
    rescue
      _ -> :error
    end
  end

  def random_hex(n), do: :crypto.strong_rand_bytes(n) |> Base.encode16(case: :lower)
  def sha256_hex(s), do: :crypto.hash(:sha256, s) |> Base.encode16(case: :lower)
end

# ============================================================================
# IP / CIDR / SSRF
# ============================================================================
defmodule P.IP do
  import Bitwise

  def normalize(ip) when is_binary(ip) do
    cond do
      String.starts_with?(ip, "/") -> normalize(String.slice(ip, 1..-1//1))
      String.starts_with?(ip, "::ffff:") -> String.slice(ip, 7..-1//1)
      String.contains?(ip, ":ffff:") and String.contains?(ip, ".") ->
        case String.split(ip, ":ffff:") do
          [_, tail] -> if String.contains?(tail, "."), do: tail, else: ip
          _ -> ip
        end
      true -> ip
    end
  end
  def normalize(ip), do: ip

  def parse_cidr(spec) do
    case String.split(spec, "/", parts: 2) do
      [ip] -> build_cidr(ip, if(String.contains?(ip, ":"), do: 128, else: 32))
      [ip, pfx] ->
        case Integer.parse(pfx) do
          {p, ""} -> build_cidr(ip, p)
          _ -> nil
        end
      _ -> nil
    end
  end

  defp build_cidr(ip, pfx) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, t} when tuple_size(t) == 4 and pfx >= 0 and pfx <= 32 -> {t, pfx, :v4}
      {:ok, t} when tuple_size(t) == 8 and pfx >= 0 and pfx <= 128 -> {t, pfx, :v6}
      _ -> nil
    end
  end

  def in_cidr?(ip, {net, pfx, fam}) do
    case {fam, tuple_size(ip)} do
      {:v4, 4} -> v4_in?(ip, net, pfx)
      {:v6, 8} -> v6_in?(ip, net, pfx)
      {:v4, 8} ->
        case ip do
          {0, 0, 0, 0, 0, 0xffff, hi, lo} ->
            v4_in?({hi >>> 8, hi &&& 0xff, lo >>> 8, lo &&& 0xff}, net, pfx)
          _ -> false
        end
      _ -> false
    end
  end

  defp v4_in?({a, b, c, d}, {na, nb, nc, nd}, pfx) do
    n = (a <<< 24) ||| (b <<< 16) ||| (c <<< 8) ||| d
    nn = (na <<< 24) ||| (nb <<< 16) ||| (nc <<< 8) ||| nd
    mask = if pfx == 0, do: 0, else: (0xFFFFFFFF <<< (32 - pfx)) &&& 0xFFFFFFFF
    (n &&& mask) == (nn &&& mask)
  end

  defp v6_in?(ip, net, pfx) do
    full = div(pfx, 16)
    rem = rem(pfx, 16)
    ip_l = Tuple.to_list(ip)
    net_l = Tuple.to_list(net)
    if Enum.take(ip_l, full) == Enum.take(net_l, full) do
      if rem == 0 do
        true
      else
        mask = (0xFFFF <<< (16 - rem)) &&& 0xFFFF
        (Enum.at(ip_l, full) &&& mask) == (Enum.at(net_l, full) &&& mask)
      end
    else
      false
    end
  end

  # IPv4: {a,b,c,d}
  def blocked?({a, b, c, d}) when is_integer(a) and is_integer(d) do
    cond do
      a == 0 -> true
      a == 10 -> true
      a == 127 -> true
      a == 100 and b >= 64 and b <= 127 -> true
      a == 169 and b == 254 -> true
      a == 172 and b >= 16 and b <= 31 -> true
      a == 192 and b == 168 -> true
      a == 192 and b == 0 and c == 0 -> true
      a == 198 and (b == 18 or b == 19) -> true
      a >= 224 -> true
      true -> false
    end
  end

  # IPv6 loopback / unspecified
  def blocked?({0, 0, 0, 0, 0, 0, 0, 0}), do: true
  def blocked?({0, 0, 0, 0, 0, 0, 0, 1}), do: true

  # IPv4-mapped IPv6 ::ffff:a.b.c.d
  def blocked?({0, 0, 0, 0, 0, 0xffff, hi, lo}) do
    blocked?({hi >>> 8, hi &&& 0xff, lo >>> 8, lo &&& 0xff})
  end

  # IPv6 general: link-local, ULA, multicast
  def blocked?({a, _b, _c, _d, _e, _f, _g, _h}) when is_integer(a) do
    cond do
      (a &&& 0xffc0) == 0xfe80 -> true
      (a &&& 0xfe00) == 0xfc00 -> true
      (a &&& 0xff00) == 0xff00 -> true
      true -> false
    end
  end

  def blocked?(_), do: true

  def blocked_str?(ip_str) do
    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, t} -> blocked?(t)
      _ -> true
    end
  end

  def format(t) do
    try do
      case :inet.ntoa(t) do
        chars when is_list(chars) -> List.to_string(chars)
        _ -> "?"
      end
    rescue
      _ -> "?"
    end
  end

  def in_any?(ip, cidrs), do: Enum.any?(cidrs, &in_cidr?(ip, &1))

  def ip_allowed?(ip_str, allow, deny) do
    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, t} ->
        cond do
          in_any?(t, deny) -> false
          allow == [] -> true
          in_any?(t, allow) -> true
          true -> false
        end
      _ -> false
    end
  end
end

# ============================================================================
# CONFIG (GenServer)
# ============================================================================
defmodule P.Cfg do
  use GenServer
  require Logger

  def start_link(_), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  def get, do: GenServer.call(__MODULE__, :get)
  def users, do: Map.get(get(), "users", [])
  def tokens, do: Map.get(get(), "api_tokens", [])
  def creds, do: {get()["dashboard_user"], get()["dashboard_password_hash"]}
  def allow_cidrs, do: parse_list(get()["allow_list"])
  def deny_cidrs, do: parse_list(get()["deny_list"])
  def upstreams, do: Map.get(get(), "upstream_proxies", [])

  defp parse_list(nil), do: []
  defp parse_list(l) when is_list(l), do: l |> Enum.map(&P.IP.parse_cidr/1) |> Enum.reject(&is_nil/1)

  def set_creds(u, h), do: GenServer.call(__MODULE__, {:set_creds, u, h})
  def upsert_user(m), do: GenServer.call(__MODULE__, {:upsert_user, m})
  def delete_user(u), do: GenServer.call(__MODULE__, {:delete_user, u})
  def add_token(n), do: GenServer.call(__MODULE__, {:add_token, n})
  def del_token(n), do: GenServer.call(__MODULE__, {:del_token, n})
  def save_network(a, d, u), do: GenServer.call(__MODULE__, {:save_net, a, d, u})
  def reload, do: GenServer.call(__MODULE__, :reload)

  @impl true
  def init(_) do
    path = Application.get_env(:proxy, :config_path, "proxy_config.json")
    cfg = load_or_init(path)
    {:ok, %{path: path, cfg: cfg}}
  end

  @impl true
  def handle_call(:get, _, s), do: {:reply, s.cfg, s}

  def handle_call({:set_creds, u, h}, _, s) do
    cfg = s.cfg |> Map.put("dashboard_user", u) |> Map.put("dashboard_password_hash", h)
    case save(s.path, cfg) do
      :ok -> {:reply, :ok, %{s | cfg: cfg}}
      {:error, e} -> {:reply, {:error, e}, %{s | cfg: cfg}}
    end
  end

  def handle_call({:upsert_user, m}, _, s) do
    uname = m["username"]
    users = Map.get(s.cfg, "users", [])
    exists = Enum.find_index(users, &(&1["username"] == uname))
    new_users =
      if exists do
        List.update_at(users, exists, fn u ->
          u
          |> put_unless_nil("password_hash", m["password_hash"])
          |> Map.put("max_bandwidth_bps", m["max_bandwidth_bps"] || 0)
          |> Map.put("max_connections", m["max_connections"] || 0)
          |> Map.put("quota_bytes_per_month", m["quota_bytes_per_month"] || 0)
        end)
      else
        users ++ [%{
          "username" => uname,
          "password_hash" => m["password_hash"],
          "max_bandwidth_bps" => m["max_bandwidth_bps"] || 0,
          "max_connections" => m["max_connections"] || 0,
          "quota_bytes_per_month" => m["quota_bytes_per_month"] || 0
        }]
      end
    cfg =
      if exists do
        # Sửa user cũ: giữ nguyên require_proxy_auth
        Map.put(s.cfg, "users", new_users)
      else
        # Tạo user mới: bật require_proxy_auth (giống Go)
        s.cfg
        |> Map.put("users", new_users)
        |> Map.put("require_proxy_auth", true)
      end
    save(s.path, cfg)
    {:reply, :ok, %{s | cfg: cfg}}
  end

  def handle_call({:delete_user, u}, _, s) do
    users = Map.get(s.cfg, "users", []) |> Enum.reject(&(&1["username"] == u))
    cli_user = Application.get_env(:proxy, :username, "")
    require_auth = users != [] or cli_user != ""
    cfg = s.cfg
          |> Map.put("users", users)
          |> Map.put("require_proxy_auth", require_auth)
    save(s.path, cfg)
    {:reply, :ok, %{s | cfg: cfg}}
  end

  def handle_call({:add_token, name}, _, s) do
    tokens = Map.get(s.cfg, "api_tokens", [])
    if Enum.any?(tokens, &(&1["name"] == name)) do
      {:reply, {:error, "Token name exists"}, s}
    else
      token = P.Hash.random_hex(32)
      h = P.Hash.sha256_hex(token)
      t = %{"name" => name, "token_hash" => h, "created_at" => System.system_time(:second)}
      cfg = Map.put(s.cfg, "api_tokens", tokens ++ [t])
      save(s.path, cfg)
      {:reply, {:ok, token}, %{s | cfg: cfg}}
    end
  end

  def handle_call({:del_token, n}, _, s) do
    tokens = Map.get(s.cfg, "api_tokens", []) |> Enum.reject(&(&1["name"] == n))
    cfg = Map.put(s.cfg, "api_tokens", tokens)
    save(s.path, cfg)
    {:reply, :ok, %{s | cfg: cfg}}
  end

  def handle_call({:save_net, a, d, u}, _, s) do
    cfg = s.cfg |> Map.put("allow_list", a) |> Map.put("deny_list", d) |> Map.put("upstream_proxies", u)
    save(s.path, cfg)
    {:reply, :ok, %{s | cfg: cfg}}
  end

  def handle_call(:reload, _, s) do
    case File.read(s.path) do
      {:ok, data} ->
        case P.JSON.decode(data) do
          {:ok, cfg} when is_map(cfg) ->
            if cfg["dashboard_user"] && cfg["dashboard_password_hash"] do
              {:reply, {:ok, cfg}, %{s | cfg: cfg}}
            else
              {:reply, {:error, "thiếu dashboard_user/hash"}, s}
            end
          _ -> {:reply, {:error, "JSON invalid"}, s}
        end
      {:error, e} -> {:reply, {:error, "read: #{e}"}, s}
    end
  end

  defp put_unless_nil(m, _, nil), do: m
  defp put_unless_nil(m, k, v), do: Map.put(m, k, v)

  defp load_or_init(path) do
    abs = Path.expand(path)

    case File.read(abs) do
      {:ok, data} ->
        case P.JSON.decode(data) do
          {:ok, cfg} when is_map(cfg) ->
            if cfg["dashboard_user"] && cfg["dashboard_password_hash"] do
              Logger.info("Loaded config từ #{abs} | user=#{cfg["dashboard_user"]} | users=#{length(Map.get(cfg, "users", []))} | tokens=#{length(Map.get(cfg, "api_tokens", []))}")
              cfg
            else
              Logger.warning("Config #{abs} thiếu dashboard_user/hash — backup và tạo mới (KHÔNG ghi đè trực tiếp)")
              backup_corrupt(abs)
              init_new(abs)
            end
          {:error, reason} ->
            Logger.error("Config #{abs} JSON invalid (#{inspect(reason)}) — backup và tạo mới")
            backup_corrupt(abs)
            init_new(abs)
        end
      {:error, :enoent} ->
        Logger.info("Config #{abs} chưa tồn tại — tạo mới")
        init_new(abs)
      {:error, e} ->
        Logger.error("Không đọc được config #{abs}: #{inspect(e)} — dùng volatile")
        init_new_volatile()
    end
  end

  defp backup_corrupt(path) do
    ts = System.system_time(:second)
    bak = "#{path}.corrupt.#{ts}"
    case File.rename(path, bak) do
      :ok -> Logger.info("Backup file hỏng → #{bak}")
      {:error, e} -> Logger.warning("Không rename được #{path}: #{inspect(e)}")
    end
    :ok
  end

  # Config volatile: giữ trong :persistent_term để restart trong cùng BEAM
  # không sinh password mới.
  defp init_new_volatile do
    case :persistent_term.get({:proxy, :volatile_cfg}, nil) do
      %{} = cfg ->
        Logger.info("Dùng lại config volatile (user=#{cfg["dashboard_user"]})")
        cfg
      _ ->
        pw = P.Hash.random_hex(8)
        hash = P.Hash.hash_password(pw)
        cfg = %{"dashboard_user" => "admin", "dashboard_password_hash" => hash}
        :persistent_term.put({:proxy, :volatile_cfg}, cfg)
        Logger.warning("""
        ═══════════════════════════════════════════════════════════════
        Không ghi được file config — dùng VOLATILE config.
        Mất khi tắt BEAM!
            URL:      http://<host>:8081
            User:     admin
            Password: #{pw}
        ═══════════════════════════════════════════════════════════════
        """)
        cfg
    end
  end

  defp init_new(path) do
    pw = P.Hash.random_hex(8)
    hash = P.Hash.hash_password(pw)
    cfg = %{"dashboard_user" => "admin", "dashboard_password_hash" => hash}

    Logger.warning("""
    ═══════════════════════════════════════════════════════════════
    Dashboard lần đầu — thông tin đăng nhập (chỉ hiện MỘT LẦN):
        URL:      http://<host>:8081
        User:     admin
        Password: #{pw}
    Config: #{path}
    ═══════════════════════════════════════════════════════════════
    """)

    case save(path, cfg) do
      :ok ->
        creds = path <> ".credentials.txt"
        try do
          File.write!(creds, "user=admin\npassword=#{pw}\ncreated=#{DateTime.utc_now()}\nconfig=#{path}\n")
          File.chmod!(creds, 0o600)
          Logger.info("Credentials lưu tại #{creds}")
        rescue
          e -> Logger.warning("Không ghi được credentials file: #{inspect(e)}")
        end
        cfg

      {:error, e} ->
        Logger.error("Không ghi được #{path}: #{inspect(e)} — chuyển sang volatile")
        :persistent_term.put({:proxy, :volatile_cfg}, cfg)
        cfg
    end
  end

  defp save(path, cfg) do
    abs = Path.expand(path)
    tmp = abs <> ".tmp"
    try do
      File.write!(tmp, P.JSON.encode(cfg))
      File.chmod!(tmp, 0o600)
      File.rename!(tmp, abs)
      # Cập nhật volatile nếu đang dùng (giữ password khi file ghi được muộn)
      :persistent_term.put({:proxy, :volatile_cfg}, cfg)
      :ok
    rescue
      e ->
        Logger.error("save #{abs} fail: #{inspect(e)}")
        {:error, e}
    end
  end
end

# ============================================================================
# STATE (GenServer + ETS)
# ============================================================================
defmodule P.State do
  use GenServer
  @hist_max 300

  def start_link(_), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  def stats_all do
    %{
      "start" => :ets.lookup_element(:p_stats, :start, 2),
      "total" => counter(:total),
      "current" => counter(:current),
      "socks5_tcp" => counter(:socks5_tcp),
      "socks5_udp" => counter(:socks5_udp),
      "http" => counter(:http),
      "auth_fail" => counter(:auth_fail),
      "bytes_up" => counter(:bytes_up),
      "bytes_down" => counter(:bytes_down),
      "udp_up" => counter(:udp_up),
      "udp_down" => counter(:udp_down),
      "udp_assocs" => :ets.info(:p_udp, :size),
      "active" => :ets.info(:p_conns, :size),
      "uptime" => System.system_time(:second) - :ets.lookup_element(:p_stats, :start, 2)
    }
  end

  def inc(key, n \\ 1), do: :ets.update_counter(:p_stats, key, n, {key, 0})
  def counter(key), do: :ets.lookup_element(:p_stats, key, 2, 0)

  def add_conn(id, info) do
    :ets.insert(:p_conns, {id, info})
    :ets.insert(:p_conn_bytes, {id, 0, 0})
    # Theo dõi pid: khi process chết (bất kể lý do) → dọn ETS
    case Map.get(info, :pid) do
      pid when is_pid(pid) ->
        GenServer.cast(__MODULE__, {:watch_conn, id, pid})
      _ -> :ok
    end
    :ok
  end

  def remove_conn(id) do
    :ets.delete(:p_conns, id)
    :ets.delete(:p_conn_bytes, id)
    :ok
  end

  def get_conn(id) do
    case :ets.lookup(:p_conns, id) do
      [{^id, i}] ->
        {u, d} = case :ets.lookup(:p_conn_bytes, id) do
          [{^id, uu, dd}] -> {uu, dd}
          [] -> {0, 0}
        end
        i |> Map.put(:bytes_up, u) |> Map.put(:bytes_down, d)
      [] -> nil
    end
  end

  def all_conns do
    :ets.tab2list(:p_conns)
    |> Enum.map(fn {id, info} ->
      {u, d} = case :ets.lookup(:p_conn_bytes, id) do
        [{^id, uu, dd}] -> {uu, dd}
        [] -> {0, 0}
      end
      info
      |> Map.put(:bytes_up, u)
      |> Map.put(:bytes_down, d)
      |> Map.put_new(:start, System.system_time(:second))
      |> Map.put_new(:user, "")
      |> Map.put_new(:target, "N/A")
    end)
  end

  # Chỉ update counter nếu key còn tồn tại — tránh tái tạo ETS sau khi remove
  def inc_conn(id, dir, n) when n > 0 and dir in [:up, :down] do
    case :ets.lookup(:p_conn_bytes, id) do
      [{^id, _, _}] ->
        pos = if dir == :up, do: 2, else: 3
        :ets.update_counter(:p_conn_bytes, id, {pos, n})
      _ ->
        0
    end
  rescue
    _ -> 0
  end
  def inc_conn(_, _, _), do: :ok

  # Đóng connection: close các socket để handler tự nhiên return,
  # KHÔNG dùng Process.exit(:kill) vì kill không chạy after → không cleanup.
  def close_conn(id) do
    case :ets.lookup(:p_conns, id) do
      [{^id, info}] ->
        close_sock(Map.get(info, :client_sock))
        close_sock(Map.get(info, :remote_sock))
        close_sock(Map.get(info, :udp_sock))

        pid = Map.get(info, :pid)
        # Watchdog: nếu sau 500ms vẫn còn entry, force kill + xoá ETS
        spawn(fn ->
          Process.sleep(500)
          case :ets.lookup(:p_conns, id) do
            [{^id, _}] ->
              if is_pid(pid) and Process.alive?(pid), do: Process.exit(pid, :kill)
              :ets.delete(:p_conns, id)
              :ets.delete(:p_conn_bytes, id)
            _ -> :ok
          end
        end)
        :ok
      _ -> :ok
    end
  end

  defp close_sock(nil), do: :ok
  defp close_sock({:tcp, s}) do
    try do
      :gen_tcp.close(s)
    rescue
      _ -> :ok
    catch
      _, _ -> :ok
    end
  end
  defp close_sock({:udp, s}) do
    try do
      :gen_udp.close(s)
    rescue
      _ -> :ok
    catch
      _, _ -> :ok
    end
  end
  defp close_sock(_), do: :ok

  def add_udp(k, i), do: :ets.insert(:p_udp, {k, i})
  def remove_udp(k), do: :ets.delete(:p_udp, k)
  def all_udp, do: Enum.map(:ets.tab2list(:p_udp), &elem(&1, 1))

  def usage_get(u) do
    p = period()
    case :ets.lookup(:p_usage, u) do
      [{^u, ^p, n}] -> n
      _ -> 0
    end
  end

  def usage_add(u, n) when n > 0 do
    p = period()
    case :ets.lookup(:p_usage, u) do
      [{^u, ^p, prev}] -> :ets.insert(:p_usage, {u, p, prev + n})
      _ -> :ets.insert(:p_usage, {u, p, n})
    end
  end
  def usage_add(_, _), do: :ok

  defp period, do: Calendar.strftime(DateTime.utc_now(), "%Y-%m")

  def push_sample(s) do
    h = :ets.lookup_element(:p_hist, :h, 2, [])
    new = Enum.take(h ++ [s], -@hist_max)
    :ets.insert(:p_hist, {:h, new})
    GenServer.cast(__MODULE__, {:bcast, s})
  end
  def history, do: :ets.lookup_element(:p_hist, :h, 2, [])
  def subscribe do
    ref = make_ref()
    GenServer.cast(__MODULE__, {:sub, ref, self()})
    ref
  end

  def up_alive?(addr) do
    case :ets.lookup(:p_up, addr) do
      [{^addr, a}] -> a
      [] -> true
    end
  end
  def set_up(addr, a), do: :ets.insert(:p_up, {addr, a})

  @impl true
  def init(_) do
    safe_ets(:p_stats, [:named_table, :public, :set, {:write_concurrency, true}])
    safe_ets(:p_conns, [:named_table, :public, :set, {:write_concurrency, true}])
    safe_ets(:p_conn_bytes, [:named_table, :public, :set, {:write_concurrency, true}])
    safe_ets(:p_conn_watch, [:named_table, :public, :set])
    safe_ets(:p_udp, [:named_table, :public, :set, {:write_concurrency, true}])
    safe_ets(:p_usage, [:named_table, :public, :set, {:write_concurrency, true}])
    safe_ets(:p_hist, [:named_table, :public, :set])
    safe_ets(:p_up, [:named_table, :public, :set, {:read_concurrency, true}])
    safe_ets(:p_last, [:named_table, :public, :set])
    safe_ets(:p_fail, [:named_table, :public, :set])
    safe_ets(:p_blocked, [:named_table, :public, :set])
    :ets.insert(:p_stats, {:start, System.system_time(:second)})
    :ets.insert(:p_hist, {:h, []})
    load_usage()
    Process.send_after(self(), :flush, 30_000)
    Process.send_after(self(), :sample, 2000)
    Process.send_after(self(), :quota_check, 10_000)
    {:ok, %{subs: %{}}}
  end

  @impl true
  def handle_cast({:watch_conn, id, pid}, s) do
    ref = Process.monitor(pid)
    :ets.insert(:p_conn_watch, {ref, id})
    {:noreply, s}
  end

  def handle_cast({:sub, ref, pid}, s), do: {:noreply, %{s | subs: Map.put(s.subs, ref, pid)}}
  def handle_cast({:bcast, sample}, s) do
    Enum.each(s.subs, fn {_, pid} -> send(pid, {:sample, sample}) end)
    {:noreply, s}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, s) do
    case :ets.lookup(:p_conn_watch, ref) do
      [{^ref, id}] ->
        :ets.delete(:p_conn_watch, ref)
        :ets.delete(:p_conns, id)
        :ets.delete(:p_conn_bytes, id)
      _ -> :ok
    end
    {:noreply, s}
  end

  def handle_info(:flush, s) do
    flush_usage()
    Process.send_after(self(), :flush, 30_000)
    {:noreply, s}
  end

  def handle_info(:quota_check, s) do
    kick_over_quota_users()
    Process.send_after(self(), :quota_check, 10_000)
    {:noreply, s}
  end

  def handle_info(:sample, s) do
    now = System.monotonic_time(:millisecond)
    up = counter(:bytes_up)
    down = counter(:bytes_down)
    {up_bps, down_bps} =
      case :ets.lookup(:p_last, :last) do
        [{:last, pt, pu, pd}] ->
          dt = max(now - pt, 1) / 1000.0
          {round((up - pu) / dt), round((down - pd) / dt)}
        [] -> {0, 0}
      end
    :ets.insert(:p_last, {:last, now, up, down})
    sample = %{
      "t" => System.system_time(:second),
      "up_bps" => up_bps, "down_bps" => down_bps,
      "active" => :ets.info(:p_conns, :size),
      "udp_assocs" => :ets.info(:p_udp, :size)
    }
    push_sample(sample)
    Process.send_after(self(), :sample, 2000)
    {:noreply, s}
  end

  defp kick_over_quota_users do
    users = P.Cfg.users()
    Enum.each(users, fn u ->
      uname = u["username"]
      quota = u["quota_bytes_per_month"] || 0
      if uname && quota > 0 do
        used = usage_get(uname)
        if used >= quota do
          Enum.each(all_conns(), fn c ->
            if c[:user] == uname, do: close_conn(c.id)
          end)
        end
      end
    end)
  end

  # An toàn: chỉ tạo table nếu chưa tồn tại (tránh :badsig khi chạy lại trong cùng BEAM)
  defp safe_ets(name, opts) do
    case :ets.whereis(name) do
      :undefined ->
        try do
          :ets.new(name, opts)
        rescue
          ArgumentError -> :ok
        end
      _ -> :ok
    end
  end

  defp load_usage do
    path = Application.get_env(:proxy, :usage_path, "proxy_usage.json")
    case File.read(path) do
      {:ok, data} ->
        case P.JSON.decode(data) do
          {:ok, m} when is_map(m) ->
            Enum.each(m, fn {u, r} ->
              :ets.insert(:p_usage, {u, r["period"], r["bytes_used"] || 0})
            end)
          _ -> :ok
        end
      _ -> :ok
    end
  end

  def flush_usage do
    path = Application.get_env(:proxy, :usage_path, "proxy_usage.json")
    if path do
      obj = :ets.tab2list(:p_usage)
            |> Map.new(fn {u, p, n} -> {u, %{"period" => p, "bytes_used" => n}} end)
      tmp = path <> ".tmp"
      File.write!(tmp, P.JSON.encode(obj))
      File.rename!(tmp, path)
    end
  end
end

# ============================================================================
# BUFFERED READER
# ============================================================================
defmodule P.Buf do
  defstruct sock: nil, buf: <<>>

  def new(sock), do: %__MODULE__{sock: sock}

  def read_n(%__MODULE__{buf: b} = r, n) when byte_size(b) >= n do
    <<take::binary-size(^n), rest::binary>> = b
    {:ok, take, %{r | buf: rest}}
  end
  def read_n(%__MODULE__{sock: s} = r, n) do
    case :gen_tcp.recv(s, 0, 30_000) do
      {:ok, data} -> read_n(%{r | buf: r.buf <> data}, n)
      {:error, e} -> {:error, e}
    end
  end

  @max_line 8192

  def read_line(r), do: read_line(r, @max_line)

  def read_line(%__MODULE__{buf: b} = r, max) do
    case :binary.match(b, "\n") do
      {i, 1} when i <= max ->
        line = :binary.part(b, 0, i)
        rest = :binary.part(b, i + 1, byte_size(b) - i - 1)
        line = if byte_size(line) > 0 and :binary.last(line) == ?\r,
          do: :binary.part(line, 0, byte_size(line) - 1), else: line
        {:ok, line, %{r | buf: rest}}
      {i, 1} ->
        _ = i
        {:error, :line_too_long}
      :nomatch when byte_size(b) > max ->
        {:error, :line_too_long}
      :nomatch ->
        case :gen_tcp.recv(r.sock, 0, 30_000) do
          {:ok, data} -> read_line(%{r | buf: r.buf <> data}, max)
          {:error, e} -> {:error, e}
        end
    end
  end

  def drain(%__MODULE__{buf: b}), do: b
end

# ============================================================================
# UPSTREAM
# ============================================================================
defmodule P.Up do
  require Logger

  def connect(host, port) do
    ups = P.Cfg.upstreams()
    if ups != [] do
      case try_upstreams(ups, host, port) do
        {:ok, s} -> {:ok, s}
        :error -> connect_direct(host, port)
      end
    else
      connect_direct(host, port)
    end
  end

  defp try_upstreams(ups, host, port) do
    Enum.find_value(ups, :error, fn up ->
      case String.split(up, ":", parts: 2) do
        [h, p] ->
          case Integer.parse(p) do
            {uport, ""} ->
              if P.State.up_alive?(up) do
                case socks5_connect(h, uport, host, port) do
                  {:ok, s} -> {:ok, s}
                  _ -> P.State.set_up(up, false); nil
                end
              else
                nil
              end
            _ -> nil
          end
        _ -> nil
      end
    end)
  end

  # SOCKS5 CONNECT thực sự tới upstream
  defp socks5_connect(u_host, u_port, target_host, target_port) do
    case :gen_tcp.connect(String.to_charlist(u_host), u_port, [:binary, active: false], 25_000) do
      {:ok, s} ->
        with :ok <- :gen_tcp.send(s, <<5, 1, 0>>),
             {:ok, <<5, 0>>} <- :gen_tcp.recv(s, 2, 10_000),
             :ok <- :gen_tcp.send(s, build_socks5_connect(target_host, target_port)),
             {:ok, <<5, 0, _rsv, atyp>>} <- :gen_tcp.recv(s, 4, 15_000),
             :ok <- consume_socks5_reply(s, atyp) do
          {:ok, s}
        else
          _ -> :gen_tcp.close(s); :error
        end
      _ -> :error
    end
  end

  defp build_socks5_connect(host, port) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, {a, b, c, d}} -> <<5, 1, 0, 1, a, b, c, d, port::16>>
      _ ->
        hb = host
        <<5, 1, 0, 3, byte_size(hb), hb::binary, port::16>>
    end
  end

  defp consume_socks5_reply(s, 1) do
    case :gen_tcp.recv(s, 6, 5_000) do
      {:ok, _} -> :ok
      _ -> :error
    end
  end
  defp consume_socks5_reply(s, 3) do
    case :gen_tcp.recv(s, 1, 5_000) do
      {:ok, <<n>>} ->
        case :gen_tcp.recv(s, n + 2, 5_000) do
          {:ok, _} -> :ok
          _ -> :error
        end
      _ -> :error
    end
  end
  defp consume_socks5_reply(s, 4) do
    case :gen_tcp.recv(s, 18, 5_000) do
      {:ok, _} -> :ok
      _ -> :error
    end
  end
  defp consume_socks5_reply(_, _), do: :error

  defp connect_direct(host, port) do
    case resolve(host) do
      {:ok, ips} ->
        Enum.find_value(ips, {:error, :unreachable}, fn ip_t ->
          if not Application.get_env(:proxy, :allow_private, false) and P.IP.blocked?(ip_t) do
            Logger.warning("Chặn SSRF #{host} → #{P.IP.format(ip_t)}")
            nil
          else
            case :gen_tcp.connect(ip_t, port, [:binary, active: false], 25_000) do
              {:ok, s} -> {:ok, s}
              _ -> nil
            end
          end
        end)
      _ -> {:error, :resolve}
    end
  end

  defp resolve(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, t} -> {:ok, [t]}
      _ ->
        case :inet.getaddrs(String.to_charlist(host), :inet) do
          {:ok, ips} -> {:ok, ips}
          _ ->
            case :inet.getaddrs(String.to_charlist(host), :inet6) do
              {:ok, ips} -> {:ok, ips}
              _ -> {:error, :dns}
            end
        end
    end
  end

  def health_loop do
    spawn(fn -> loop() end)
  end

  defp loop do
    Process.sleep(15_000)
    Enum.each(P.Cfg.upstreams(), fn up ->
      case String.split(up, ":", parts: 2) do
        [h, p] ->
          case Integer.parse(p) do
            {port, ""} ->
              case :gen_tcp.connect(String.to_charlist(h), port, [:binary, active: false], 3_000) do
                {:ok, s} -> :gen_tcp.close(s); P.State.set_up(up, true)
                _ -> P.State.set_up(up, false)
              end
            _ -> :ok
          end
        _ -> :ok
      end
    end)
    loop()
  end
end

# ============================================================================
# TUNNEL
# ============================================================================
defmodule P.Tunnel do

  def relay(client, remote, conn_id, user, rate_bps, initial \\ <<>>) do
    if byte_size(initial) > 0 do
      try do
        :gen_tcp.send(remote, initial)
        P.State.inc(:bytes_up, byte_size(initial))
        P.State.inc_conn(conn_id, :up, byte_size(initial))
        P.State.usage_add(user, byte_size(initial))
      rescue
        _ -> :ok
      end
    end
    parent = self()
    pid = spawn(fn ->
      receive do
        :go -> pump(remote, client, conn_id, user, rate_bps, true, parent)
      end
    end)
    # Child cần OWN remote để :gen_tcp.recv(remote, ...) hoạt động
    case :gen_tcp.controlling_process(remote, pid) do
      :ok -> send(pid, :go)
      _ -> send(pid, :go)
    end
    try do
      pump(client, remote, conn_id, user, rate_bps, false, parent)
    after
      if Process.alive?(pid), do: Process.exit(pid, :kill)
    end
  end

  defp pump(from, to, conn_id, user, rate_bps, downstream, _parent) do
    # recv(_, 0) = lấy tất cả bytes đang có (streaming).
    # recv(_, N>0) = đợi ĐỦ N bytes ⇒ sẽ treo TLS handshake.
    case :gen_tcp.recv(from, 0, 180_000) do
      {:ok, data} ->
        if rate_bps > 0, do: throttle(byte_size(data), rate_bps)
        case :gen_tcp.send(to, data) do
          :ok ->
            n = byte_size(data)
            if downstream do
              P.State.inc(:bytes_down, n)
              P.State.inc_conn(conn_id, :down, n)
            else
              P.State.inc(:bytes_up, n)
              P.State.inc_conn(conn_id, :up, n)
            end
            P.State.usage_add(user, n)
            pump(from, to, conn_id, user, rate_bps, downstream, nil)
          _ -> :ok
        end
      {:error, _} -> :ok
    end
  end

  defp throttle(n, bps) do
    ms = trunc(n * 1000 / bps)
    if ms > 0 and ms < 1500, do: Process.sleep(ms)
  end
end

# ============================================================================
# SOCKS5
# ============================================================================
defmodule P.Socks5 do
  require Logger
  import Bitwise

  def auth_required? do
    cfg = P.Cfg.get()
    Map.get(cfg, "require_proxy_auth", false) or
      length(Map.get(cfg, "users", [])) > 0 or
      Application.get_env(:proxy, :username, "") != ""
  end

  def authenticate(user, pass) do
    cfg_user = Application.get_env(:proxy, :username, "")
    cfg_pass = Application.get_env(:proxy, :password, "")
    cond do
      cfg_user != "" and user == cfg_user and pass == cfg_pass -> {:ok, user, 0}
      true ->
        Enum.find_value(P.Cfg.users(), :error, fn u ->
          if u["username"] == user and P.Hash.verify(pass, u["password_hash"] || "") do
            {:ok, user, u["max_bandwidth_bps"] || 0}
          else
            nil
          end
        end)
    end
  end

  def peer_ip(sock) do
    case :inet.peername(sock) do
      {:ok, {ip, _}} -> P.IP.format(ip)
      _ -> ""
    end
  end

  def peer_port(sock) do
    case :inet.peername(sock) do
      {:ok, {_, p}} -> p
      _ -> 0
    end
  end

  def record_fail(ip, threshold) do
    if loopback?(ip) do
      :ok
    else
      do_record_fail(ip, threshold)
    end
  end

  defp loopback?(ip) when is_binary(ip) do
    ip == "::1" or ip == "localhost" or
      ip == "127.0.0.1" or String.starts_with?(ip, "127.")
  end
  defp loopback?(_), do: false

  defp do_record_fail(ip, threshold) do
    now = System.monotonic_time(:second)
    key = {:fail, ip}
    case :ets.lookup(:p_fail, key) do
      [{^key, count, last}] ->
        if now - last > 300 do
          :ets.insert(:p_fail, {key, 1, now})
        else
          c = count + 1
          if c >= threshold do
            :ets.insert(:p_fail, {key, 0, now})
            :ets.insert(:p_blocked, {ip, now + 900})
            Logger.warning("Chặn IP #{ip} 900s do auth fail")
          else
            :ets.insert(:p_fail, {key, c, now})
          end
        end
      [] -> :ets.insert(:p_fail, {key, 1, now})
    end
  end

  def reset_fail(ip) do
    :ets.delete(:p_fail, {:fail, ip})
    :ets.delete(:p_blocked, ip)
  end

  def blocked?(ip) do
    now = System.monotonic_time(:second)
    case :ets.lookup(:p_blocked, ip) do
      [{^ip, u}] when u > now -> true
      [{^ip, _}] -> :ets.delete(:p_blocked, ip); false
      [] -> false
    end
  end

  def handle(sock, reader, peer_ip, conn_id) do
    case handshake(sock, reader) do
      {:ok, user, bps, r} -> after_auth(sock, r, peer_ip, conn_id, user, bps)
      _ -> :close
    end
  end

  defp handshake(sock, reader) do
    with {:ok, <<5, nm>>, r1} <- P.Buf.read_n(reader, 2),
         {:ok, methods, r2} <- P.Buf.read_n(r1, nm) do
      need = auth_required?()
      want = if need, do: 0x02, else: 0x00
      if :binary.match(methods, <<want>>) == :nomatch do
        :gen_tcp.send(sock, <<5, 0xff>>)
        {:error, :no_method}
      else
        :gen_tcp.send(sock, <<5, want>>)
        if need, do: do_auth(sock, r2), else: {:ok, "", 0, r2}
      end
    else
      _ -> {:error, :handshake}
    end
  end

  defp do_auth(sock, reader) do
    with {:ok, <<1>>, r1} <- P.Buf.read_n(reader, 1),
         {:ok, <<ulen>>, r2} <- P.Buf.read_n(r1, 1),
         {:ok, u, r3} <- P.Buf.read_n(r2, ulen),
         {:ok, <<plen>>, r4} <- P.Buf.read_n(r3, 1),
         {:ok, p, r5} <- P.Buf.read_n(r4, plen) do
      user = u
      pass = p
      case authenticate(user, pass) do
        {:ok, uname, bps} ->
          :gen_tcp.send(sock, <<1, 0>>)
          reset_fail(peer_ip(sock))
          {:ok, uname, bps, r5}
        :error ->
          :gen_tcp.send(sock, <<1, 0xff>>)
          record_fail(peer_ip(sock), 5)
          P.State.inc(:auth_fail)
          {:error, :auth}
      end
    else
      _ -> {:error, :auth}
    end
  end

  defp after_auth(sock, reader, peer_ip, conn_id, user, bps) do
    with {:ok, <<5, cmd, _, atyp>>, r1} <- P.Buf.read_n(reader, 4),
         {:ok, host, port, r2} <- read_addr(r1, atyp) do
      case cmd do
        0x01 -> do_connect(sock, r2, host, port, peer_ip, conn_id, user, bps)
        0x03 -> P.UDPRelay.start(sock, r2, host, port, peer_ip, user)
        _ -> :gen_tcp.send(sock, <<5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0>>); :close
      end
    else
      _ -> :close
    end
  end

  defp do_connect(sock, reader, host, port, peer_ip, conn_id, user, bps) do
    case P.Up.connect(host, port) do
      {:ok, remote} ->
        {:ok, {lip, lport}} = :inet.sockname(remote)
        :gen_tcp.send(sock, reply_ok(lip, lport))
        info = %{
          id: conn_id, ip: peer_ip, port: peer_port(sock),
          type: "SOCKS5_TCP", target: "#{host}:#{port}",
          user: user, rate_bps: bps,
          bytes_up: 0, bytes_down: 0, pid: self(),
          client_sock: {:tcp, sock}, remote_sock: {:tcp, remote},
          start: System.system_time(:second)
        }
        P.State.add_conn(conn_id, info)
        P.State.inc(:socks5_tcp)
        initial = P.Buf.drain(reader)
        try do
          P.Tunnel.relay(sock, remote, conn_id, user, bps, initial)
        after
          P.State.remove_conn(conn_id)
        end
      _ ->
        :gen_tcp.send(sock, <<5, 0x05, 0, 1, 0, 0, 0, 0, 0, 0>>)
    end
  end

  defp read_addr(reader, 1) do
    with {:ok, ip, r1} <- P.Buf.read_n(reader, 4),
         {:ok, <<port::16>>, r2} <- P.Buf.read_n(r1, 2) do
      a = :binary.at(ip, 0); b = :binary.at(ip, 1); c = :binary.at(ip, 2); d = :binary.at(ip, 3)
      {:ok, "#{a}.#{b}.#{c}.#{d}", port, r2}
    end
  end
  defp read_addr(reader, 3) do
    with {:ok, <<ln>>, r1} <- P.Buf.read_n(reader, 1),
         {:ok, h, r2} <- P.Buf.read_n(r1, ln),
         {:ok, <<port::16>>, r3} <- P.Buf.read_n(r2, 2) do
      {:ok, h, port, r3}
    end
  end
  defp read_addr(reader, 4) do
    with {:ok, ip, r1} <- P.Buf.read_n(reader, 16),
         {:ok, <<port::16>>, r2} <- P.Buf.read_n(r1, 2) do
      {:ok, :inet.ntoa(ip) |> to_string(), port, r2}
    end
  end
  defp read_addr(_, _), do: {:error, :atyp}

  defp reply_ok(ip, port) do
    bin = case ip do
      {a, b, c, d} -> <<1, a, b, c, d>>
      {a, b, c, d, e, f, g, h} -> <<4, a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    end
    <<5, 0, 0>> <> bin <> <<port::16>>
  end
end

# ============================================================================
# HTTP PROXY
# ============================================================================
defmodule P.HTTPProxy do
  def handle(sock, reader, peer_ip, conn_id) do
    case P.Buf.read_line(reader) do
      {:ok, line, r2} ->
        case String.split(line, " ", parts: 3) do
          [method, url, _] -> dispatch(sock, r2, method, url, peer_ip, conn_id)
          _ -> :close
        end
      _ -> :close
    end
  end

  defp dispatch(sock, reader, method, url, peer_ip, conn_id) do
    case read_headers(reader, %{}) do
      {:ok, headers, r2} ->
        case auth_check(headers) do
          {:ok, user, bps} ->
            case parse_target(method, url, headers) do
              {:ok, host, port} ->
                do_request(sock, r2, method, url, headers, host, port, peer_ip, conn_id, user, bps)
              _ -> send_simple(sock, 400, "Bad Request")
            end
          :error ->
            :gen_tcp.send(sock, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nConnection: close\r\n\r\n")
            P.State.inc(:auth_fail)
            P.Socks5.record_fail(peer_ip, 5)
        end
      _ -> :close
    end
  end

  @max_headers 100

  defp read_headers(reader, acc), do: read_headers(reader, acc, 0)

  defp read_headers(_reader, _acc, n) when n > @max_headers, do: {:error, :too_many_headers}

  defp read_headers(reader, acc, n) do
    case P.Buf.read_line(reader) do
      {:ok, "", r} -> {:ok, acc, r}
      {:ok, line, r} ->
        case String.split(line, ":", parts: 2) do
          [k, v] ->
            key = String.downcase(String.trim(k))
            val = String.trim(v)
            read_headers(r, Map.update(acc, key, val, &(&1 <> ", " <> val)), n + 1)
          _ -> read_headers(r, acc, n + 1)
        end
      {:error, :line_too_long} -> {:error, :line_too_long}
      _ -> {:error, :eof}
    end
  end

  defp auth_check(headers) do
    if P.Socks5.auth_required?() do
      case headers["proxy-authorization"] do
        "Basic " <> b64 ->
          case Base.decode64(b64) do
            {:ok, dec} ->
              case String.split(dec, ":", parts: 2) do
                [u, p] -> case P.Socks5.authenticate(u, p) do
                  {:ok, un, bps} -> {:ok, un, bps}
                  _ -> :error
                end
                _ -> :error
              end
            _ -> :error
          end
        _ -> :error
      end
    else
      {:ok, "", 0}
    end
  end

  defp parse_target("CONNECT", url, _headers) do
    case String.split(url, ":", parts: 2) do
      [h, p] -> case Integer.parse(p) do
        {port, ""} -> {:ok, h, port}
        _ -> :error
      end
      _ -> :error
    end
  end

  defp parse_target(_m, url, headers) do
    cond do
      String.starts_with?(url, ["http://", "https://"]) ->
        case URI.parse(url) do
          %URI{host: h, port: p} when is_binary(h) and h != "" -> {:ok, h, p || 80}
          _ -> :error
        end

      # origin-form: GET /path HTTP/1.1  → dùng Host header
      String.starts_with?(url, "/") ->
        case headers["host"] do
          nil -> :error
          host ->
            case String.split(host, ":", parts: 2) do
              [h] -> {:ok, h, 80}
              [h, p] -> case Integer.parse(p) do
                {port, ""} -> {:ok, h, port}
                _ -> {:ok, h, 80}
              end
            end
        end

      true ->
        url2 = "http://" <> url
        case URI.parse(url2) do
          %URI{host: h, port: p} when is_binary(h) and h != "" -> {:ok, h, p || 80}
          _ -> :error
        end
    end
  end

  defp do_request(sock, reader, "CONNECT", _url, _headers, host, port, peer_ip, conn_id, user, bps) do
    case P.Up.connect(host, port) do
      {:ok, remote} ->
        :gen_tcp.send(sock, "HTTP/1.1 200 Connection Established\r\n\r\n")
        info = %{
          id: conn_id, ip: peer_ip, port: peer_port(sock),
          type: "HTTP", target: "#{host}:#{port}", user: user, rate_bps: bps,
          bytes_up: 0, bytes_down: 0, pid: self(),
          client_sock: {:tcp, sock}, remote_sock: {:tcp, remote},
          start: System.system_time(:second)
        }
        P.State.add_conn(conn_id, info)
        P.State.inc(:http)
        initial = P.Buf.drain(reader)
        try do
          P.Tunnel.relay(sock, remote, conn_id, user, bps, initial)
        after
          P.State.remove_conn(conn_id)
        end
      _ -> :gen_tcp.send(sock, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
    end
  end

  defp do_request(sock, reader, method, url, headers, host, port, peer_ip, conn_id, user, bps) do
    case P.Up.connect(host, port) do
      {:ok, remote} ->
        info = %{
          id: conn_id, ip: peer_ip, port: peer_port(sock),
          type: "HTTP", target: "#{host}:#{port}", user: user, rate_bps: bps,
          bytes_up: 0, bytes_down: 0, pid: self(),
          client_sock: {:tcp, sock}, remote_sock: {:tcp, remote},
          start: System.system_time(:second)
        }
        P.State.add_conn(conn_id, info)
        P.State.inc(:http)
        url2 = if String.starts_with?(url, ["http://", "https://"]), do: url, else: "http://" <> url
        uri = URI.parse(url2)
        path = (uri.path || "/") <> if(uri.query, do: "?" <> uri.query, else: "")
        req = "#{method} #{path} HTTP/1.1\r\nHost: #{host}\r\n" <>
              Enum.reduce(headers, "", fn {k, v}, acc ->
                if k in ["proxy-authorization", "proxy-connection", "connection"],
                  do: acc, else: acc <> "#{k}: #{v}\r\n"
              end) <> "Connection: close\r\n\r\n"
        try do
          :gen_tcp.send(remote, req)
          P.State.inc(:bytes_up, byte_size(req))
          P.State.inc_conn(conn_id, :up, byte_size(req))

          # Request smuggling protection: CL + TE cùng lúc = reject
          cl_hdr = headers["content-length"]
          te_hdr = headers["transfer-encoding"]
          chunked = te_hdr && String.contains?(String.downcase(te_hdr), "chunked")

          cond do
            cl_hdr != nil and chunked ->
              Logger.warning("Reject: cả Content-Length và Transfer-Encoding cùng lúc")
              :gen_tcp.send(sock, "HTTP/1.1 400 Bad Request\r\n\r\n")
            chunked ->
              relay_chunked(reader, remote, conn_id, user)
            cl_hdr ->
              case Integer.parse(cl_hdr) do
                {n, ""} when n > 0 -> forward_body(reader, remote, conn_id, n, user)
                _ -> :ok
              end
            true -> :ok
          end
          forward_response(remote, sock, conn_id, user, bps)
        after
          :gen_tcp.close(remote)
          P.State.remove_conn(conn_id)
        end
      _ -> :gen_tcp.send(sock, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
    end
  end

  # Stream chunked body từ client → remote, giống relayChunked của Go
  defp relay_chunked(reader, remote, conn_id, user) do
    case do_relay_chunked(reader, remote, conn_id, user, 0) do
      :ok -> :ok
      {:error, e} -> Logger.warning("relay_chunked: #{inspect(e)}")
    end
  end

  defp do_relay_chunked(reader, remote, conn_id, user, total) when total > 100_000_000 do
    # chặn 100MB — tránh DoS
    :gen_tcp.send(remote, "0\r\n\r\n")
    :ok
  end

  defp do_relay_chunked(reader, remote, conn_id, user, total) do
    case P.Buf.read_line(reader, 1024) do
      {:ok, size_line, r} ->
        size_str = case String.split(size_line, ";", parts: 2) do
          [s | _] -> String.trim(s)
        end
        case Integer.parse(size_str, 16) do
          {0, _} ->
            # đọc trailer
            consume_trailers(r)
            :gen_tcp.send(remote, "0\r\n\r\n")
            :ok
          {size, _} when size > 0 ->
            :gen_tcp.send(remote, size_line <> "\r\n")
            case P.Buf.read_n(r, size + 2) do
              {:ok, chunk_plus_crlf, r2} ->
                :gen_tcp.send(remote, chunk_plus_crlf)
                P.State.inc(:bytes_up, size)
                P.State.inc_conn(conn_id, :up, size)
                P.State.usage_add(user, size)
                do_relay_chunked(r2, remote, conn_id, user, total + size)
              _ -> {:error, :eof}
            end
          _ -> {:error, :bad_chunk}
        end
      _ -> {:error, :eof}
    end
  end

  defp consume_trailers(reader), do: consume_trailers(reader, 0)
  defp consume_trailers(_reader, n) when n > @max_headers, do: :ok
  defp consume_trailers(reader, n) do
    case P.Buf.read_line(reader) do
      {:ok, "", _} -> :ok
      {:ok, _, r} -> consume_trailers(r, n + 1)
      _ -> :ok
    end
  end

  defp forward_body(reader, remote, conn_id, n, user) do
    case P.Buf.read_n(reader, n) do
      {:ok, data, _} ->
        :gen_tcp.send(remote, data)
        P.State.inc(:bytes_up, byte_size(data))
        P.State.inc_conn(conn_id, :up, byte_size(data))
        P.State.usage_add(user, byte_size(data))
      _ -> :ok
    end
  end

  defp forward_response(remote, sock, conn_id, user, bps) do
    case :gen_tcp.recv(remote, 65536, 180_000) do
      {:ok, data} ->
        if bps > 0, do: Process.sleep(trunc(byte_size(data) * 1000 / bps))
        :gen_tcp.send(sock, data)
        P.State.inc(:bytes_down, byte_size(data))
        P.State.inc_conn(conn_id, :down, byte_size(data))
        P.State.usage_add(user, byte_size(data))
        forward_response(remote, sock, conn_id, user, bps)
      _ -> :ok
    end
  end

  defp send_simple(sock, code, text) do
    body = "#{code} #{text}\n"
    resp = "HTTP/1.1 #{code} #{text}\r\nConnection: close\r\nContent-Length: #{byte_size(body)}\r\n\r\n#{body}"
    :gen_tcp.send(sock, resp)
  end

  defp peer_port(sock) do
    case :inet.peername(sock) do
      {:ok, {_, p}} -> p
      _ -> 0
    end
  end
end

# ============================================================================
# UDP RELAY
# ============================================================================
defmodule P.UDPRelay do
  require Logger
  import Bitwise

  def start(sock, _reader, _host, _port, peer_ip, user) do
    # Địa chỉ mà client đã kết nối tới (dùng cho BND.ADDR trong reply).
    reply_ip = case :inet.sockname(sock) do
      {:ok, {{0, 0, 0, 0}, _}} -> {127, 0, 0, 1}
      {:ok, {ip, _}} -> ip
      _ -> {127, 0, 0, 1}
    end

    # CRITICAL: UDP socket PHẢI bind 0.0.0.0.
    # Nếu bind 127.0.0.1, gọi :gen_udp.send(udp, {8,8,8,8}, 53, ...)
    # sẽ fail với :enetunreach trên Linux → không bao giờ có reply.
    {:ok, udp} = :gen_udp.open(0, [:binary, active: false])
    {:ok, udp_port} = :inet.port(udp)

    reply = <<5, 0, 0, 1>> <> ip_to_bin4(reply_ip) <> <<udp_port::16>>
    :gen_tcp.send(sock, reply)
    Logger.info("UDP relay: reply_ip=#{:inet.ntoa(reply_ip) |> to_string()} udp_port=#{udp_port}")

    # Đăng ký UDP connection vào dashboard
    conn_id = "udp" <> Integer.to_string(:erlang.unique_integer([:positive]))
    info = %{
      id: conn_id, ip: peer_ip, port: 0,
      type: "SOCKS5_UDP", target: "UDP:any",
      user: user, rate_bps: 0,
      bytes_up: 0, bytes_down: 0, pid: self(),
      client_sock: {:tcp, sock}, udp_sock: {:udp, udp},
      start: System.system_time(:second)
    }
    P.State.add_conn(conn_id, info)
    P.State.inc(:socks5_udp)

    # Spawn child đọc UDP. Parent giữ TCP control channel.
    pid = spawn(fn ->
      receive do
        {:go, u} -> udp_loop(u, peer_ip, user, conn_id, nil, %{})
        :stop -> :ok
      end
    end)

    # CRITICAL: chuyển ownership socket UDP cho child TRƯỚC khi child recv.
    # Thiếu bước này => child nhận {:error, :not_owner} ngay lập tức.
    case :gen_udp.controlling_process(udp, pid) do
      :ok -> send(pid, {:go, udp})
      other ->
        Logger.error("controlling_process fail: #{inspect(other)}")
        send(pid, :stop)
        :gen_udp.close(udp)
        :gen_tcp.close(sock)
        :ok
    end

    # Watch TCP control channel
    try do
      case :gen_tcp.recv(sock, 0, :infinity) do
        {:ok, _} ->
          send(pid, :stop)
          start(sock, nil, nil, nil, peer_ip, user)
        _ ->
          send(pid, :stop)
          :ok
      end
    after
      P.State.remove_conn(conn_id)
    end
  end

  defp ip_to_bin4({a, b, c, d}), do: <<a, b, c, d>>
  defp ip_to_bin4(_), do: <<0, 0, 0, 0>>

  @udp_idle_ms 120_000

  defp udp_loop(udp, peer_ip, user, conn_id, client_addr, dest_map),
    do: udp_loop(udp, peer_ip, user, conn_id, client_addr, dest_map, System.monotonic_time(:millisecond))

  defp udp_loop(udp, peer_ip, user, conn_id, client_addr, dest_map, last_act) do
    now = System.monotonic_time(:millisecond)
    if now - last_act > @udp_idle_ms do
      Logger.info("UDP idle timeout (#{@udp_idle_ms}ms) — đóng assoc")
      :gen_udp.close(udp)
      :ok
    else
      case :gen_udp.recv(udp, 65535, 1000) do
        {:ok, {ip, port, pkt}} ->
          {ca, dm} = process(udp, ip, port, pkt, peer_ip, user, conn_id, client_addr, dest_map)
          udp_loop(udp, peer_ip, user, conn_id, ca, dm, now)
        {:error, :timeout} ->
          udp_loop(udp, peer_ip, user, conn_id, client_addr, dest_map, last_act)
        {:error, _} -> :ok
      end
    end
  end

  defp process(udp, ip, port, pkt, peer_ip, user, conn_id, nil, dm) do
    ip_str = P.IP.format(ip)
    if ip_str == peer_ip do
      process(udp, ip, port, pkt, peer_ip, user, conn_id, {ip, port}, dm)
    else
      {nil, dm}
    end
  end

  defp process(udp, ip, port, pkt, _peer_ip, user, conn_id, {cip, cport}, dm) do
    if ip == cip and port == cport do
      case parse_udp(pkt) do
        {:ok, dst_host, dst_port, payload} ->
          case resolve(dst_host) do
            {:ok, dst_ip} ->
              if not Application.get_env(:proxy, :allow_private, false) and P.IP.blocked?(dst_ip) do
                Logger.debug("UDP block target #{P.IP.format(dst_ip)}")
                {{cip, cport}, dm}
              else
                case :gen_udp.send(udp, dst_ip, dst_port, payload) do
                  :ok ->
                    Logger.debug("UDP → #{P.IP.format(dst_ip)}:#{dst_port} (#{byte_size(payload)}B)")
                  err ->
                    Logger.warning("UDP send fail → #{P.IP.format(dst_ip)}:#{dst_port}: #{inspect(err)}")
                end
                dm2 = Map.put(dm, {dst_ip, dst_port}, true)
                P.State.inc(:udp_up, byte_size(payload))
                P.State.inc_conn(conn_id, :up, byte_size(payload))
                P.State.usage_add(user, byte_size(payload))
                {{cip, cport}, dm2}
              end
            _ -> {{cip, cport}, dm}
          end
        _ -> {{cip, cport}, dm}
      end
    else
      if Map.get(dm, {ip, port}, false) do
        hdr = <<0, 0, 0, 1>> <> ip_to_bin4(ip) <> <<port::16>>
        case :gen_udp.send(udp, cip, cport, hdr <> pkt) do
          :ok ->
            Logger.debug("UDP ← #{P.IP.format(ip)}:#{port} → client #{P.IP.format(cip)}:#{cport} (#{byte_size(pkt)}B)")
          err ->
            Logger.warning("UDP reply fail → client: #{inspect(err)}")
        end
        P.State.inc(:udp_down, byte_size(pkt))
        P.State.inc_conn(conn_id, :down, byte_size(pkt))
        P.State.usage_add(user, byte_size(pkt))
      else
        Logger.debug("UDP drop unexpected #{P.IP.format(ip)}:#{port} (#{byte_size(pkt)}B)")
      end
      {{cip, cport}, dm}
    end
  end

  defp parse_udp(<<0, 0, 0, 1, a, b, c, d, p::16, payload::binary>>),
    do: {:ok, "#{a}.#{b}.#{c}.#{d}", p, payload}
  defp parse_udp(<<0, 0, 0, 3, ln, host::binary-size(ln), p::16, payload::binary>>),
    do: {:ok, host, p, payload}
  defp parse_udp(_), do: :error

  defp resolve(h) do
    case :inet.parse_address(String.to_charlist(h)) do
      {:ok, t} -> {:ok, t}
      _ -> case :inet.getaddr(String.to_charlist(h), :inet) do
        {:ok, t} -> {:ok, t}
        _ -> :error
      end
    end
  end
end

# ============================================================================
# LISTENER
# ============================================================================
defmodule P.Listener do
  require Logger

  def start_link(_) do
    port = Application.get_env(:proxy, :port, 1080)
    bind = Application.get_env(:proxy, :listen, "0.0.0.0")
    parent = self()
    pid = spawn(fn ->
      ip = case :inet.parse_address(String.to_charlist(bind)) do
        {:ok, t} -> t
        _ -> {0, 0, 0, 0}
      end
      opts = [:binary, packet: :raw, active: false, reuseaddr: true, ip: ip, backlog: 1024]
      case :gen_tcp.listen(port, opts) do
        {:ok, lsock} ->
          Logger.info("Proxy STARTED → #{bind}:#{port}")
          send(parent, {:listener_ok, self()})
          accept_loop(lsock)
        {:error, e} ->
          send(parent, {:listener_err, self(), e})
      end
    end)
    receive do
      {:listener_ok, ^pid} -> {:ok, pid}
      {:listener_err, ^pid, e} ->
        Logger.error("Proxy listen fail: #{inspect(e)}")
        {:error, e}
    after 5000 ->
      Logger.error("Proxy listen timeout")
      {:error, :timeout}
    end
  end

  @max_conn 4000

  defp accept_loop(lsock) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        cur = P.State.counter(:current)
        if cur >= @max_conn do
          Logger.warning("Đạt MAX_CONNECTIONS (#{@max_conn}), đóng kết nối mới")
          :gen_tcp.close(sock)
          accept_loop(lsock)
        else
          P.State.inc(:current, 1)
          P.State.inc(:total)
          handler = spawn(fn ->
            receive do
              :go -> handle(sock)
            end
          end)
          case :gen_tcp.controlling_process(sock, handler) do
            :ok -> send(handler, :go)
            _ -> P.State.inc(:current, -1); :gen_tcp.close(sock)
          end
          accept_loop(lsock)
        end
      {:error, :closed} -> :ok
      {:error, _} -> Process.sleep(100); accept_loop(lsock)
    end
  end

  defp handle(sock) do
    try do
      case :inet.peername(sock) do
        {:ok, {ip, _}} ->
          peer_ip = P.IP.format(ip)
          cond do
            not P.IP.ip_allowed?(peer_ip, P.Cfg.allow_cidrs(), P.Cfg.deny_cidrs()) ->
              Logger.warning("IP #{peer_ip} bị từ chối bởi whitelist/blacklist")
              :gen_tcp.close(sock)
            P.Socks5.blocked?(peer_ip) -> :gen_tcp.close(sock)
            true ->
              case :gen_tcp.recv(sock, 1, 30_000) do
                {:ok, <<fb>>} ->
                  reader = %P.Buf{sock: sock, buf: <<fb>>}
                  conn_id = "c" <> Integer.to_string(:erlang.unique_integer([:positive]))
                  cond do
                    fb == 5 -> P.Socks5.handle(sock, reader, peer_ip, conn_id)
                    fb in [?C, ?G, ?P, ?D, ?H, ?O, ?T] -> P.HTTPProxy.handle(sock, reader, peer_ip, conn_id)
                    true -> :ok
                  end
                  :gen_tcp.close(sock)
                _ -> :gen_tcp.close(sock)
              end
          end
        _ -> :gen_tcp.close(sock)
      end
    rescue
      e -> Logger.error("Handler crash: #{inspect(e)}")
    after
      P.State.inc(:current, -1)
    end
  end
end



defmodule P.Audit do
  @max_events 200
  @max_reload 30

  def init do
    ensure_ets(:p_audit)
    ensure_ets(:p_reload_hist)
  end

  defp ensure_ets(name) do
    case :ets.whereis(name) do
      :undefined -> try do :ets.new(name, [:named_table, :public, :ordered_set]) rescue _ -> :ok end
      _ -> :ok
    end
  end

  def event(actor, action, details \\ "") do
    init()
    t = System.system_time(:second)
    :ets.insert(:p_audit, {t, actor, action, details})
    trim(:p_audit, @max_events)
  end

  def reload_event(source, success, info \\ %{}) do
    init()
    t = System.system_time(:second)
    ev = Map.merge(%{
      "t" => t, "source" => source, "success" => success,
      "error" => nil, "allow_count" => 0, "deny_count" => 0,
      "upstream_count" => 0, "user_count" => 0, "invalid_cidrs" => []
    }, info)
    :ets.insert(:p_reload_hist, {t, ev})
    trim(:p_reload_hist, @max_reload)
  end

  defp trim(tbl, max) do
    sz = :ets.info(tbl, :size)
    if sz > max do
      :ets.tab2list(tbl)
      |> Enum.sort()
      |> Enum.take(sz - max)
      |> Enum.each(fn {k, _} -> :ets.delete(tbl, k) end)
    end
  end

  def audit_log(limit \\ 100) do
    init()
    :ets.tab2list(:p_audit)
    |> Enum.sort(fn {t1, _, _, _}, {t2, _, _, _} -> t1 >= t2 end)
    |> Enum.take(limit)
    |> Enum.map(fn {t, actor, action, details} ->
      %{"t" => t, "actor" => actor, "action" => action, "details" => details}
    end)
  end

  def reload_history(limit \\ 30) do
    init()
    :ets.tab2list(:p_reload_hist)
    |> Enum.sort(fn {t1, _}, {t2, _} -> t1 >= t2 end)
    |> Enum.take(limit)
    |> Enum.map(fn {_, ev} -> ev end)
  end
end

defmodule P.Dashboard do
  require Logger

  def start_link(_) do
    case :ets.whereis(:p_pwcache) do
      :undefined -> try do :ets.new(:p_pwcache, [:named_table, :public, :set]) rescue _ -> :ok end
      _ -> :ok
    end
    case :ets.whereis(:p_sse) do
      :undefined -> try do :ets.new(:p_sse, [:named_table, :public, :set]) rescue _ -> :ok end
      _ -> :ok
    end
    port = Application.get_env(:proxy, :dashboard_port, 8081)
    bind = Application.get_env(:proxy, :dashboard_bind, "127.0.0.1")
    parent = self()
    pid = spawn(fn ->
      ip = case :inet.parse_address(String.to_charlist(bind)) do
        {:ok, t} -> t
        _ -> {0, 0, 0, 0}
      end
      opts = [:binary, packet: :raw, active: false, reuseaddr: true, ip: ip, backlog: 256]
      case :gen_tcp.listen(port, opts) do
        {:ok, lsock} ->
          Logger.info("Dashboard: http://#{bind}:#{port}")
          send(parent, {:dash_ok, self()})
          loop(lsock)
        {:error, e} ->
          send(parent, {:dash_err, self(), e})
      end
    end)
    receive do
      {:dash_ok, ^pid} -> {:ok, pid}
      {:dash_err, ^pid, e} ->
        Logger.error("Dashboard listen fail: #{inspect(e)}")
        {:ok, pid}  # dashboard fail không nên kill proxy
    after 5000 ->
      {:ok, pid}
    end
  end


  defp loop(lsock) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        handler = spawn(fn ->
          receive do
            :go -> handle(sock)
          end
        end)
        :gen_tcp.controlling_process(sock, handler)
        send(handler, :go)
        loop(lsock)
      {:error, :closed} -> :ok
      _ -> Process.sleep(100); loop(lsock)
    end
  end

  defp handle(sock) do
    reader = %P.Buf{sock: sock, buf: <<>>}
    case P.Buf.read_line(reader) do
      {:ok, req_line, r2} ->
        case String.split(req_line, " ", parts: 3) do
          [method, raw_target, _] ->
            {path, query} = split_path_query(raw_target)
            case read_headers(r2, %{}) do
              {:ok, headers, r3} ->
                body = read_body(r3, headers)
                safe_route(sock, method, path, query, headers, body)
              _ ->
                respond(sock, 400, "text/plain", "bad headers")
            end
          _ ->
            respond(sock, 400, "text/plain", "bad request line")
        end
      _ -> :gen_tcp.close(sock)
    end
  end

  defp split_path_query(t) do
    case String.split(t, "?", parts: 2) do
      [p] -> {p, %{}}
      [p, qs] ->
        q = qs
            |> String.split("&")
            |> Enum.map(fn kv ->
              case String.split(kv, "=", parts: 2) do
                [k, v] -> {k, URI.decode_www_form(v)}
                [k] -> {k, ""}
              end
            end)
            |> Map.new()
        {p, q}
    end
  end

  # Wrapper: bắt mọi exception, log, gửi 500 thay vì silent crash
  defp safe_route(sock, method, path, query, headers, body) do
    route(sock, method, path, query, headers, body)
  rescue
    e ->
      stack = __STACKTRACE__
      Logger.error("Dashboard handler crash: #{inspect(e)}\n#{Exception.format_stacktrace(stack)}")
      try do
        respond(sock, 500, "application/json",
          P.JSON.encode(%{"error" => "internal", "detail" => Exception.message(e)}))
      rescue
        _ -> :gen_tcp.close(sock)
      end
  end

  defp read_headers(reader, acc) do
    case P.Buf.read_line(reader) do
      {:ok, "", r} -> {:ok, acc, r}
      {:ok, line, r} ->
        case String.split(line, ":", parts: 2) do
          [k, v] ->
            key = String.downcase(String.trim(k))
            val = String.trim(v)
            # Giống Go: nếu trùng key, nối thêm bằng ", " (Set-Cookie lặp thì giữ riêng)
            new_acc =
              if key == "set-cookie" or key == "cookie" do
                Map.update(acc, key, val, &(&1 <> "\n" <> val))
              else
                Map.update(acc, key, val, &(&1 <> ", " <> val))
              end
            read_headers(r, new_acc)
          _ -> read_headers(r, acc)
        end
      _ -> {:error, :eof}
    end
  end

  defp read_body(reader, headers) do
    case headers["content-length"] do
      nil -> ""
      cl ->
        case Integer.parse(cl) do
          {n, ""} when n > 0 and n <= 5_000_000 ->
            case P.Buf.read_n(reader, n) do
              {:ok, d, _} -> d
              _ -> ""
            end
          _ -> ""
        end
    end
  end

  # ---- CSRF: giống csrfOK() của Go ----
  # GET/HEAD/OPTIONS luôn qua; POST/PUT/DELETE phải:
  #   * Sec-Fetch-Site = same-origin | none (nếu có header)
  #   * Origin (nếu có) phải cùng host với Host header
  #   * Content-Type phải bắt đầu bằng "application/json"
  defp csrf_check(method, headers, _sock) do
    cond do
      method in ["GET", "HEAD", "OPTIONS"] ->
        :ok
      true ->
        site = String.downcase(headers["sec-fetch-site"] || "")
        origin = headers["origin"] || ""
        host_hdr = headers["host"] || ""
        ctype = String.downcase(headers["content-type"] || "")
        cond do
          site != "" and site not in ["same-origin", "none"] ->
            {:error, "Sec-Fetch-Site=" <> site}

          origin != "" ->
            case URI.parse(origin) do
              %URI{host: h, port: p} when is_binary(h) ->
                origin_host =
                  case p do
                    nil -> h
                    _ -> "#{h}:#{p}"
                  end
                if origin_host == host_hdr or h == host_hdr do
                  csrf_ctype(ctype)
                else
                  {:error, "Origin host #{origin_host} != Host #{host_hdr}"}
                end
              _ -> {:error, "bad origin"}
            end

          true ->
            csrf_ctype(ctype)
        end
    end
  end

  defp csrf_ctype(ctype) do
    if String.starts_with?(ctype, "application/json") do
      :ok
    else
      {:error, "Content-Type must be application/json (got: " <> ctype <> ")"}
    end
  end

  # /healthz — phản ánh graceful shutdown
  defp route(sock, "GET", "/healthz", _q, _, _) do
    sd = try do :persistent_term.get({:proxy, :shutting_down}, false) rescue _ -> false end
    if sd do
      respond(sock, 503, "application/json", ~s({"status":"shutting_down"}))
    else
      respond(sock, 200, "application/json", ~s({"status":"ok"}))
    end
  end
  defp route(sock, "GET", "/metrics", _q, _, _), do: respond(sock, 200, "text/plain; version=0.0.4", metrics())
  defp route(sock, "GET", "/stats", _q, headers, _) do
    case auth(sock, headers) do
      {:ok, _} -> respond(sock, 200, "application/json", stats_only())
      :unauthorized -> respond(sock, 401, "text/plain", "unauthorized")
    end
  end

  defp route(sock, method, path, query, headers, body) do
    case auth(sock, headers) do
      {:ok, actor} ->
        case csrf_check(method, headers, sock) do
          :ok ->
            do_route(sock, actor, method, path, query, headers, body)
          {:error, why} ->
            Logger.warning("CSRF reject: #{why}")
            respond(sock, 403, "text/plain", "403 Forbidden (CSRF: " <> why <> ")")
        end
      :unauthorized ->
        :gen_tcp.send(sock, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Dashboard\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        :gen_tcp.close(sock)
    end
  end

  # Tách phần dispatch ra khỏi route/6 để CSRF/route clean hơn
  defp do_route(sock, actor, method, path, query, headers, body) do
        case {method, path} do
          {"GET", "/"} -> respond(sock, 200, "text/html; charset=utf-8", html())
          {"GET", "/api/all"} -> respond(sock, 200, "application/json", api_all())
          {"GET", "/api/users"} -> respond(sock, 200, "application/json", api_users())
          {"GET", "/api/tokens"} -> respond(sock, 200, "application/json", api_tokens())
          {"GET", "/api/network-config"} -> respond(sock, 200, "application/json", api_net())
          {"GET", "/api/audit-log"} -> respond(sock, 200, "application/json", P.JSON.encode(%{"events" => P.Audit.audit_log()}))
          {"GET", "/api/reload-history"} -> respond(sock, 200, "application/json", P.JSON.encode(%{"history" => P.Audit.reload_history()}))
          {"GET", "/api/stream"} -> sse(sock)
          {"GET", "/api/config/export"} -> export_config(sock, actor)
          {"POST", "/api/config/import"} -> import_config(sock, actor, body)
          {"GET", "/api/export"} -> export_conns(sock, query)
          {"POST", "/api/reload"} -> do_reload(sock, actor)
          {"POST", "/api/kick"} -> do_kick(sock, actor, body)
          {"POST", "/api/users"} -> do_user(sock, actor, body)
          {"POST", "/api/users/delete"} -> do_del_user(sock, actor, body)
          {"POST", "/api/tokens"} -> do_token(sock, actor, body)
          {"POST", "/api/tokens/delete"} -> do_del_token(sock, actor, body)
          {"POST", "/api/network-config"} -> do_net(sock, actor, body)
          {"POST", "/api/change-password"} -> do_change_pw(sock, actor, body)
          _ -> respond(sock, 404, "text/plain", "404")
        end
  end

  # Cache verify password thành công trong 5 phút (browser gọi fetch liên tục)
  defp auth(sock, headers) do
    peer_ip = case :inet.peername(sock) do
      {:ok, {ip, _port}} -> P.IP.format(ip)
      _ -> ""
    end
    if P.Socks5.blocked?(peer_ip) do
      :unauthorized
    else
      case headers["authorization"] do
        "Bearer " <> token ->
          h = P.Hash.sha256_hex(String.trim(token))
          now = System.monotonic_time(:second)
          key = :crypto.hash(:sha256, "bearer:" <> h)
          if cache_hit?(key, now) do
            {:ok, "token:cached"}
          else
            tokens = P.Cfg.tokens()
            if Enum.any?(tokens, fn t ->
              :crypto.hash_equals(String.downcase(t["token_hash"] || ""), h)
            end) do
              cache_put(key, now + 300)
              {:ok, "token"}
            else
              :unauthorized
            end
          end

        "Basic " <> b64 ->
          case Base.decode64(b64) do
            {:ok, dec} ->
              case String.split(dec, ":", parts: 2) do
                [u, p] ->
                  {cu, ch} = P.Cfg.creds()
                  key = :crypto.hash(:sha256, (ch || "") <> "\0" <> u <> "\0" <> p)
                  now = System.monotonic_time(:second)

                  if cache_hit?(key, now) do
                    {:ok, "dashboard:" <> u}
                  else
                    if u == cu and P.Hash.verify(p, ch) do
                      cache_put(key, now + 300)
                      {:ok, "dashboard:" <> u}
                    else
                      :unauthorized
                    end
                  end

                _ -> :unauthorized
              end
            _ -> :unauthorized
          end
        _ -> :unauthorized
      end
    end
  end

  defp cache_hit?(key, now) do
    case :ets.lookup(:p_pwcache, key) do
      [{^key, exp}] -> exp > now
      _ -> false
    end
  rescue
    _ -> false
  end

  defp cache_put(key, exp) do
    :ets.insert(:p_pwcache, {key, exp})
    # trim nếu quá lớn
    if :ets.info(:p_pwcache, :size) > 256 do
      :ets.delete_all_objects(:p_pwcache)
      :ets.insert(:p_pwcache, {key, exp})
    end
  rescue
    _ -> :ok
  end

  defp respond(sock, code, ctype, body) do
    text = case code do
      200 -> "OK"; 400 -> "Bad Request"; 401 -> "Unauthorized"
      403 -> "Forbidden"; 404 -> "Not Found"; 405 -> "Method Not Allowed"
      409 -> "Conflict"; 500 -> "Internal Server Error"
      _ -> "OK"
    end
    body_b = IO.iodata_to_binary(body)
    resp = "HTTP/1.1 #{code} #{text}\r\n" <>
           "Content-Type: #{ctype}\r\n" <>
           "Content-Length: #{byte_size(body_b)}\r\n" <>
           "Cache-Control: no-store\r\n" <>
           "Connection: close\r\n\r\n" <> body_b
    case :gen_tcp.send(sock, resp) do
      :ok -> :ok
      {:error, e} -> Logger.warning("respond: send fail (#{code} #{ctype}): #{inspect(e)}")
    end
    :gen_tcp.close(sock)
  end

  defp api_all do
    s = P.State.stats_all()
    now = System.system_time(:second)
    conns = Enum.map(P.State.all_conns(), fn c -> %{
      "id" => Map.get(c, :id, ""),
      "ip" => Map.get(c, :ip, "?"),
      "port" => Map.get(c, :port, 0),
      "type" => Map.get(c, :type, "?"),
      "target" => Map.get(c, :target, "N/A"),
      "user" => Map.get(c, :user, ""),
      "bytes_up" => Map.get(c, :bytes_up, 0),
      "bytes_down" => Map.get(c, :bytes_down, 0),
      "start_time" => Map.get(c, :start, now),
      "duration" => now - Map.get(c, :start, now)
    } end)
    d = Map.merge(s, %{
      "active_connections" => conns,
      "upstream" => %{"proxies" => [], "status" => [], "current_index" => 0},
      "udp_associations" => %{}
    })
    P.JSON.encode(d)
  end

  defp api_users do
    us = Enum.map(P.Cfg.users(), fn u -> %{
      "username" => u["username"],
      "max_bandwidth_bps" => u["max_bandwidth_bps"] || 0,
      "max_connections" => u["max_connections"] || 0,
      "quota_bytes_per_month" => u["quota_bytes_per_month"] || 0,
      "usage_bytes_this_month" => P.State.usage_get(u["username"])
    } end)
    P.JSON.encode(%{"users" => us})
  end

  defp api_tokens do
    ts = Enum.map(P.Cfg.tokens(), fn t -> %{"name" => t["name"], "created_at" => t["created_at"]} end)
    P.JSON.encode(%{"tokens" => ts})
  end

  defp api_net do
    c = P.Cfg.get()
    P.JSON.encode(%{
      "allow_list" => Map.get(c, "allow_list", []),
      "deny_list" => Map.get(c, "deny_list", []),
      "upstream_proxies" => Map.get(c, "upstream_proxies", [])
    })
  end

  defp metrics do
    s = P.State.stats_all()
    Enum.map_join([
      {"connections_total",     "counter", "Tổng số kết nối đã nhận từ khi khởi động",           s["total"]},
      {"connections_current",   "gauge",   "Số kết nối đang mở",                                 s["current"]},
      {"connections_active",    "gauge",   "Số kết nối active trong bảng dashboard",              s["active"]},
      {"socks5_tcp_total",      "counter", "Tổng số kết nối SOCKS5 TCP",                          s["socks5_tcp"]},
      {"socks5_udp_total",      "counter", "Tổng số kết nối SOCKS5 UDP",                          s["socks5_udp"]},
      {"http_requests_total",   "counter", "Tổng số request HTTP proxy",                          s["http"]},
      {"bytes_up_total",        "counter", "Tổng bytes gửi lên (client -> target) qua TCP",       s["bytes_up"]},
      {"bytes_down_total",      "counter", "Tổng bytes tải về (target -> client) qua TCP",        s["bytes_down"]},
      {"udp_bytes_up_total",    "counter", "Tổng bytes UDP gửi lên",                              s["udp_up"]},
      {"udp_bytes_down_total",  "counter", "Tổng bytes UDP tải về",                               s["udp_down"]},
      {"udp_associations",      "gauge",   "Số UDP association đang mở",                          s["udp_assocs"]},
      {"auth_fail_total",       "counter", "Tổng số lần xác thực thất bại (SOCKS5 + HTTP)",       s["auth_fail"]},
      {"uptime_seconds",        "gauge",   "Thời gian server đã chạy (giây)",                     s["uptime"]}
    ], fn {n, t, help, v} ->
      "# HELP proxy_#{n} #{help}\n# TYPE proxy_#{n} #{t}\nproxy_#{n} #{v}\n"
    end)
  end

  # Chỉ stats gọn cho /stats (khác /api/all)
  defp stats_only do
    P.JSON.encode(P.State.stats_all())
  end

  @max_sse 16

  defp sse(sock) do
    n = case :ets.info(:p_sse, :size) do
      :undefined -> 0
      k -> k
    end
    if n >= @max_sse do
      respond(sock, 503, "text/plain", "503 Too many streaming clients")
      :gen_tcp.close(sock)
    else
      ref = make_ref()
      :ets.insert(:p_sse, {ref, self()})
      try do
        :gen_tcp.send(sock, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\nX-Accel-Buffering: no\r\n\r\n")
        P.State.subscribe()
        hist = P.State.history()
        :gen_tcp.send(sock, "event: history\ndata: #{P.JSON.encode(hist)}\n\n")
        sse_loop(sock)
      after
        :ets.delete(:p_sse, ref)
      end
    end
  end

  defp sse_loop(sock) do
    receive do
      {:sample, s} ->
        case :gen_tcp.send(sock, "event: sample\ndata: #{P.JSON.encode(s)}\n\n") do
          :ok -> sse_loop(sock)
          _ -> :ok  # client đóng
        end
    after 15_000 ->
      case :gen_tcp.send(sock, ": keepalive\n\n") do
        :ok -> sse_loop(sock)
        _ -> :ok
      end
    end
  end

  defp export_config(sock, actor) do
    respond(sock, 200, "application/json", P.JSON.encode(P.Cfg.get()))
  end

  defp import_config(sock, actor, body) do
    Logger.info("import_config: nhận #{byte_size(body)} bytes")
    case P.JSON.decode(body) do
      {:ok, cfg} when is_map(cfg) ->
        if cfg["dashboard_user"] && cfg["dashboard_password_hash"] do
          path = Application.get_env(:proxy, :config_path, "proxy_config.json")
          tmp = path <> ".import.tmp"
          try do
            File.write!(tmp, P.JSON.encode(cfg))
            File.chmod!(tmp, 0o600)
            File.rename!(tmp, path)
            case P.Cfg.reload() do
              {:ok, _} ->
                P.Audit.event(actor, "import_config", "success")
                Logger.info("import_config: thành công")
                respond(sock, 200, "application/json", ~s({"success":true}))
              {:error, e} ->
                P.Audit.event(actor, "import_config", "reload_failed: " <> e)
                Logger.error("import_config: reload fail: #{e}")
                respond(sock, 500, "application/json", P.JSON.encode(%{"error" => e}))
            end
          rescue
            e ->
              P.Audit.event(actor, "import_config", "write_failed: " <> inspect(e))
              Logger.error("import_config: write fail: #{inspect(e)}")
              respond(sock, 500, "application/json", P.JSON.encode(%{"error" => inspect(e)}))
          end
        else
          respond(sock, 400, "application/json", ~s({"error":"missing dashboard_user/hash"}))
        end
      {:error, reason} ->
        Logger.warning("import_config: JSON decode fail: #{inspect(reason)}")
        respond(sock, 400, "application/json", P.JSON.encode(%{"error" => "invalid JSON: " <> inspect(reason)}))
      _ ->
        respond(sock, 400, "application/json", ~s({"error":"invalid JSON"}))
    end
  end

  defp export_conns(sock, query) do
    fmt = Map.get(query, "format", "json")
    now = System.system_time(:second)
    rows = Enum.map(P.State.all_conns(), fn c ->
      start = Map.get(c, :start, now)
      %{
        "id" => Map.get(c, :id, ""),
        "ip" => Map.get(c, :ip, "?"),
        "port" => Map.get(c, :port, 0),
        "type" => Map.get(c, :type, "?"),
        "target" => Map.get(c, :target, "N/A"),
        "user" => Map.get(c, :user, ""),
        "bytes_up" => Map.get(c, :bytes_up, 0),
        "bytes_down" => Map.get(c, :bytes_down, 0),
        "duration_seconds" => now - start
      }
    end)
    case fmt do
      "csv" ->
        header = "id,ip,port,type,target,user,bytes_up,bytes_down,duration_seconds\n"
        rows_csv = Enum.map_join(rows, "", fn r ->
          target_esc = String.replace(r["target"], "\"", "\"\"")
          "#{r["id"]},#{r["ip"]},#{r["port"]},#{r["type"]},\"#{target_esc}\",#{r["user"]},#{r["bytes_up"]},#{r["bytes_down"]},#{r["duration_seconds"]}\n"
        end)
        respond_attachment(sock, "text/csv", "connections.csv", header <> rows_csv)
      _ ->
        respond_attachment(sock, "application/json", "connections.json", P.JSON.encode(rows))
    end
  end

  defp respond_attachment(sock, ctype, filename, body) do
    b = IO.iodata_to_binary(body)
    resp = "HTTP/1.1 200 OK\r\n" <>
           "Content-Type: #{ctype}\r\n" <>
           "Content-Length: #{byte_size(b)}\r\n" <>
           "Content-Disposition: attachment; filename=#{filename}\r\n" <>
           "Cache-Control: no-store\r\n" <>
           "Connection: close\r\n\r\n" <> b
    :gen_tcp.send(sock, resp)
    :gen_tcp.close(sock)
  end

  defp do_reload(sock, actor) do
    case P.Cfg.reload() do
      {:ok, cfg} ->
        P.Audit.reload_event(actor, true, %{
          "allow_count" => length(Map.get(cfg, "allow_list", [])),
          "deny_count" => length(Map.get(cfg, "deny_list", [])),
          "upstream_count" => length(Map.get(cfg, "upstream_proxies", [])),
          "user_count" => length(Map.get(cfg, "users", []))
        })
        P.Audit.event(actor, "reload_config", "success")
        respond(sock, 200, "application/json", ~s({"success":true}))
      {:error, e} ->
        P.Audit.reload_event(actor, false, %{"error" => e})
        P.Audit.event(actor, "reload_config", "failed: " <> e)
        respond(sock, 400, "application/json", P.JSON.encode(%{"error" => e}))
    end
  end

  defp do_kick(sock, actor, body) do
    case P.JSON.decode(body) do
      {:ok, %{"id" => id}} ->
        P.State.close_conn(id)
        P.Audit.event(actor, "kick_connection", "id=" <> id)
        respond(sock, 200, "application/json", ~s({"success":true}))
      _ -> respond(sock, 400, "application/json", ~s({"error":"missing id"}))
    end
  end

  defp do_user(sock, actor, body) do
    case P.JSON.decode(body) do
      {:ok, m} when is_map(m) ->
        uname = String.trim(m["username"] || "")
        pwd = m["password"] || ""
        cond do
          uname == "" -> respond(sock, 400, "application/json", ~s({"error":"username required"}))
          pwd != "" and String.length(pwd) < 4 -> respond(sock, 400, "application/json", ~s({"error":"password >=4"}))
          true ->
            existing = Enum.find(P.Cfg.users(), &(&1["username"] == uname))
            hash = cond do
              pwd != "" -> P.Hash.hash_password(pwd)
              existing -> existing["password_hash"]
              true -> nil
            end
            if hash == nil do
              respond(sock, 400, "application/json", ~s({"error":"password required"}))
            else
              P.Cfg.upsert_user(%{
                "username" => uname,
                "password_hash" => hash,
                "max_bandwidth_bps" => m["max_bandwidth_bps"] || 0,
                "max_connections" => m["max_connections"] || 0,
                "quota_bytes_per_month" => m["quota_bytes_per_month"] || 0
              })
              P.Audit.event(actor, "upsert_user", "username=" <> uname)
              respond(sock, 200, "application/json", ~s({"success":true}))
            end
        end
      _ -> respond(sock, 400, "application/json", ~s({"error":"bad json"}))
    end
  end

  defp do_del_user(sock, actor, body) do
    case P.JSON.decode(body) do
      {:ok, %{"username" => u}} ->
        P.Cfg.delete_user(u)
        P.Audit.event(actor, "delete_user", "username=" <> u)
        respond(sock, 200, "application/json", ~s({"success":true}))
      _ -> respond(sock, 400, "application/json", ~s({"error":"missing"}))
    end
  end

  defp do_token(sock, actor, body) do
    case P.JSON.decode(body) do
      {:ok, %{"name" => name}} ->
        case P.Cfg.add_token(name) do
          {:ok, tok} ->
            P.Audit.event(actor, "create_api_token", "name=" <> name)
            respond(sock, 200, "application/json",
              P.JSON.encode(%{"success" => true, "token" => tok, "name" => name}))
          {:error, e} -> respond(sock, 409, "application/json", P.JSON.encode(%{"error" => e}))
        end
      _ -> respond(sock, 400, "application/json", ~s({"error":"missing name"}))
    end
  end

  defp do_del_token(sock, actor, body) do
    case P.JSON.decode(body) do
      {:ok, %{"name" => n}} ->
        P.Cfg.del_token(n)
        P.Audit.event(actor, "revoke_api_token", "name=" <> n)
        respond(sock, 200, "application/json", ~s({"success":true}))
      _ -> respond(sock, 400, "application/json", ~s({"error":"missing"}))
    end
  end

  defp do_net(sock, actor, body) do
    case P.JSON.decode(body) do
      {:ok, m} ->
        allow = m["allow_list"] || []
        deny = m["deny_list"] || []
        ups = m["upstream_proxies"] || []
        P.Cfg.save_network(allow, deny, ups)
        P.Audit.reload_event(actor, true, %{
          "allow_count" => length(allow),
          "deny_count" => length(deny),
          "upstream_count" => length(ups),
          "user_count" => length(P.Cfg.users())
        })
        P.Audit.event(actor, "update_network_config",
          "#{length(allow)} allow, #{length(deny)} deny, #{length(ups)} upstream")
        respond(sock, 200, "application/json", ~s({"success":true}))
      _ -> respond(sock, 400, "application/json", ~s({"error":"bad json"}))
    end
  end

  defp do_change_pw(sock, actor, body) do
    case P.JSON.decode(body) do
      {:ok, m} ->
        {cu, ch} = P.Cfg.creds()
        cur = m["current_password"] || ""
        np = m["new_password"] || ""
        nu = String.trim(m["new_username"] || "")
        cond do
          not P.Hash.verify(cur, ch) ->
            respond(sock, 403, "application/json", ~s({"error":"current password wrong"}))
          String.length(np) < 8 ->
            respond(sock, 400, "application/json", ~s({"error":"new password must be >= 8 characters"}))
          np == cur ->
            respond(sock, 400, "application/json", ~s({"error":"new password must differ from current"}))
          true ->
            new_u = if nu == "", do: cu, else: nu
            case P.Cfg.set_creds(new_u, P.Hash.hash_password(np)) do
              :ok ->
                P.Audit.event(actor, "change_dashboard_password", "#{cu} -> #{new_u}")
                # Xoá cache password cũ để không bị stale
                try do :ets.delete_all_objects(:p_pwcache) rescue _ -> :ok end
                respond(sock, 200, "application/json", P.JSON.encode(%{"success" => true, "username" => new_u}))
              {:error, e} ->
                respond(sock, 500, "application/json", P.JSON.encode(%{"error" => "save failed: " <> inspect(e)}))
            end
        end
      {:error, r} ->
        respond(sock, 400, "application/json", P.JSON.encode(%{"error" => "bad json: " <> inspect(r)}))
      _ ->
        respond(sock, 400, "application/json", ~s({"error":"bad json"}))
    end
  end

defp html do
    ~S"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Proxy Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f0f1a;--fg:#e0e0e0;--container-bg:#14141f;--box-bg:#1a1a2e;--box-hover:#22223b;--border:#2a2a3a;--border2:#28283a;--th-bg:#1e1e32;--muted:#9999bb;--muted2:#b4b4d4;--accent:#f0c27a;--accent-contrast:#1a1a2e;--btn-bg:#2a2a3a;--btn-border:#3a3a52;--btn-hover:#33334a;--badge-bg:#2a2a4a;--badge-fg:#c0c0e0;--badge-socks5tcp-bg:#1e3a5f;--badge-socks5tcp-fg:#7dd3fc;--badge-socks5udp-bg:#3b1f4a;--badge-socks5udp-fg:#d8b4fe;--badge-http-bg:#2d4a2d;--badge-http-fg:#86efac;--danger-border:#7a3030;--danger-hover-bg:#4a1a1a;--danger-fg:#fca5a5}
html[data-theme="light"]{--bg:#f4f4f9;--fg:#1c1c2a;--container-bg:#fff;--box-bg:#f0f0f7;--box-hover:#e6e6f2;--border:#dcdce8;--border2:#e4e4f0;--th-bg:#ececf5;--muted:#52526a;--muted2:#33334a;--accent:#8a5010;--accent-contrast:#fff;--btn-bg:#ececf5;--btn-border:#c8c8dc;--btn-hover:#e0e0ee;--badge-bg:#e4e4f4;--badge-fg:#3f3f66;--badge-socks5tcp-bg:#dbeafe;--badge-socks5tcp-fg:#1d4ed8;--badge-socks5udp-bg:#f3e8ff;--badge-socks5udp-fg:#7e22ce;--badge-http-bg:#dcfce7;--badge-http-fg:#15803d;--danger-border:#e5a5a5;--danger-hover-bg:#fde2e2;--danger-fg:#b91c1c}
body{background:var(--bg);color:var(--fg);font-family:'Segoe UI','Roboto',monospace;padding:30px 20px;transition:background .2s,color .2s}
.container{max-width:1400px;margin:0 auto}
h1{font-size:2.2rem;font-weight:300;letter-spacing:1px;color:var(--accent);display:flex;align-items:center;gap:10px}
h1 span{background:var(--btn-bg);padding:0 12px;border-radius:30px;font-size:.8rem;color:var(--muted)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;margin:20px 0}
.stat-box{background:var(--box-bg);padding:14px 16px;border-radius:12px;border-left:4px solid #6c6c9a}
.stat-box:hover{background:var(--box-hover)}
.stat-label{font-size:.8rem;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
.stat-value{font-size:1.7rem;font-weight:600;margin-top:4px}
.section{margin-top:30px;background:var(--container-bg);border-radius:14px;padding:20px 20px 10px 20px;border:1px solid var(--border)}
.section-title-row{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:15px}
.section-title{font-size:1.2rem;font-weight:400;color:var(--muted2);letter-spacing:.3px}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.toolbar input[type=text]{background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:6px 10px;color:var(--fg);font-size:.85rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{text-align:left;padding:10px 8px;background:var(--th-bg);color:var(--muted);font-weight:500;cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--accent)}
th.sorted-asc::after{content:' \25B2';font-size:.7em}
th.sorted-desc::after{content:' \25BC';font-size:.7em}
td{padding:8px;border-bottom:1px solid var(--border2)}
tr:hover td{background:var(--box-bg)}
.badge{display:inline-block;padding:2px 12px;border-radius:20px;font-size:.7rem;font-weight:600;background:var(--badge-bg);color:var(--badge-fg)}
.badge.socks5-tcp{background:var(--badge-socks5tcp-bg);color:var(--badge-socks5tcp-fg)}
.badge.socks5-udp{background:var(--badge-socks5udp-bg);color:var(--badge-socks5udp-fg)}
.badge.http{background:var(--badge-http-bg);color:var(--badge-http-fg)}
.header-bar{display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid var(--border);padding-bottom:15px;margin-bottom:10px;flex-wrap:wrap;gap:10px}
.header-actions{display:flex;gap:8px;flex-wrap:wrap}
.btn{background:var(--btn-bg);color:var(--fg);border:1px solid var(--btn-border);padding:8px 16px;border-radius:8px;cursor:pointer;font-size:.85rem}
.btn:hover{background:var(--btn-hover);border-color:var(--accent)}
.btn-sm{padding:4px 10px;font-size:.75rem}
.btn-danger{border-color:var(--danger-border);color:var(--danger-fg)}
.btn-danger:hover{background:var(--danger-hover-bg);color:var(--danger-fg)}
.btn-primary{background:var(--accent);color:var(--accent-contrast);border-color:var(--accent);font-weight:600}
.btn-primary:hover{filter:brightness(1.1)}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);align-items:center;justify-content:center;z-index:100}
.modal-overlay.open{display:flex}
.modal{background:var(--container-bg);border:1px solid var(--border);border-radius:14px;padding:24px;width:340px;max-width:90vw}
.modal h2{font-size:1.1rem;font-weight:500;color:var(--accent);margin-bottom:16px}
.modal label{display:block;font-size:.8rem;color:var(--muted);margin:12px 0 4px}
.modal input{width:100%;background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:9px;color:var(--fg);font-size:.9rem}
.modal input:focus{outline:none;border-color:var(--accent)}
.modal-actions{display:flex;gap:10px;margin-top:20px}
.modal-actions .btn{flex:1}
.modal-msg{margin-top:12px;font-size:.82rem;min-height:18px}
.modal-msg.error{color:#dc2626}
.modal-msg.success{color:#16a34a}
textarea{background:var(--box-bg);border:1px solid var(--border);border-radius:8px;padding:8px;color:var(--fg);font-size:.82rem;font-family:monospace}
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
  <div class="section">
    <div class="section-title-row">
      <div class="section-title">📈 Real-time Traffic <span id="streamStatus" style="font-size:.75rem;color:var(--muted);">(connecting...)</span></div>
    </div>
    <canvas id="trafficChart" height="80"></canvas>
  </div>
  <div class="section">
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
  <div class="section">
    <div class="section-title">🌐 Upstream Proxies</div>
    <div id="upstreamInfo">Loading...</div>
  </div>
  <div class="section">
    <div class="section-title-row">
      <div class="section-title">👤 Proxy Users (multi-user + bandwidth limit)</div>
      <div class="toolbar"><button class="btn btn-sm" onclick="openUserModal()">+ Add / Update User</button></div>
    </div>
    <div id="usersTable">Loading...</div>
  </div>
  <div class="section">
    <div class="section-title-row">
      <div class="section-title">🌐 Network Rules (whitelist / blacklist / upstream)</div>
      <div class="toolbar"><button class="btn btn-sm" onclick="reloadFromDisk()">↻ Reload from disk</button></div>
    </div>
    <div style="font-size:.78rem;color:var(--muted);margin-bottom:10px;">Mỗi dòng 1 IP hoặc CIDR. Lưu sẽ tự động reload ngay.</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;">
      <div>
        <label style="display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px;">Whitelist IP/CIDR (để trống = cho phép tất cả)</label>
        <textarea id="netAllow" rows="5" style="width:100%;"></textarea>
      </div>
      <div>
        <label style="display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px;">Blacklist IP/CIDR</label>
        <textarea id="netDeny" rows="5" style="width:100%;"></textarea>
      </div>
      <div>
        <label style="display:block;font-size:.8rem;color:var(--muted);margin-bottom:4px;">Upstream proxies (host:port)</label>
        <textarea id="netUpstream" rows="5" style="width:100%;"></textarea>
      </div>
    </div>
    <div class="modal-msg" id="netMsg" style="margin-top:10px;"></div>
    <div style="margin-top:10px;"><button class="btn btn-primary" onclick="saveNetworkConfig()">Save & Apply Now</button></div>
  </div>
  <div class="section">
    <div class="section-title">🕒 Reload History</div>
    <div id="reloadHistoryTable">Loading...</div>
  </div>
  <div class="section">
    <div class="section-title-row">
      <div class="section-title">🔑 API Tokens (cho script/monitoring)</div>
      <div class="toolbar"><button class="btn btn-sm" onclick="openTokenModal()">+ Create Token</button></div>
    </div>
    <div style="font-size:.78rem;color:var(--muted);margin-bottom:10px;">Dùng <code>Authorization: Bearer &lt;token&gt;</code> thay Basic Auth khi gọi API từ script.</div>
    <div id="tokensTable">Loading...</div>
  </div>
  <div class="section">
    <div class="section-title">📋 Audit Log</div>
    <div id="auditTable">Loading...</div>
  </div>
  <div class="section">
    <div class="section-title-row">
      <div class="section-title">💾 Backup / Restore Config</div>
    </div>
    <div style="font-size:.78rem;color:var(--muted);margin-bottom:10px;">File backup chứa hash (không phải plaintext) nhưng vẫn nên giữ bí mật.</div>
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
      <label>Token name</label>
      <input type="text" id="tName" required>
      <div class="modal-msg" id="tokenMsg"></div>
      <div id="tokenResultBox" style="display:none;margin-top:12px;padding:10px;background:var(--box-bg);border-radius:8px;">
        <div style="font-size:.78rem;color:var(--danger-fg);margin-bottom:6px;">⚠️ Chỉ hiện MỘT LẦN:</div>
        <code id="tokenResultValue" style="word-break:break-all;font-size:.8rem;"></code>
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
      <label>Username</label><input type="text" id="uUsername" required>
      <label>Password (min 4, để trống = giữ nguyên)</label><input type="password" id="uPassword" minlength="4">
      <label>Max bandwidth (KB/s, 0 = unlimited)</label><input type="number" id="uBandwidth" min="0" value="0">
      <label>Max connections (0 = unlimited)</label><input type="number" id="uMaxConn" min="0" value="0">
      <label>Monthly quota (MB, 0 = unlimited)</label><input type="number" id="uQuota" min="0" value="0">
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
      <label>Current password</label><input type="password" id="curPass" required>
      <label>New username (blank = keep)</label><input type="text" id="newUser">
      <label>New password (min 8)</label><input type="password" id="newPass" minlength="8" required>
      <label>Confirm new password</label><input type="password" id="newPass2" minlength="8" required>
      <div class="modal-msg" id="pwMsg"></div>
      <div class="modal-actions">
        <button type="button" class="btn" onclick="closePwModal()">Cancel</button>
        <button type="submit" class="btn btn-primary">Save changes</button>
      </div>
    </form>
  </div>
</div>

<script>
let lastConns=[],sortKey='start_time',sortDir='desc',trafficChart=null;
const CHART_MAX_POINTS=150;
function initChart(){const ctx=document.getElementById('trafficChart').getContext('2d');trafficChart=new Chart(ctx,{type:'line',data:{labels:[],datasets:[{label:'Upload (B/s)',data:[],borderColor:'#ea580c',backgroundColor:'rgba(234,88,12,.1)',tension:.3,pointRadius:0,borderWidth:2},{label:'Download (B/s)',data:[],borderColor:'#0891b2',backgroundColor:'rgba(8,145,178,.1)',tension:.3,pointRadius:0,borderWidth:2}]},options:{responsive:true,animation:false,interaction:{mode:'index',intersect:false},scales:{x:{ticks:{color:getComputedStyle(document.documentElement).getPropertyValue('--muted')},grid:{color:getComputedStyle(document.documentElement).getPropertyValue('--border2')}},y:{ticks:{color:getComputedStyle(document.documentElement).getPropertyValue('--muted'),callback:v=>formatBytes(v)+'/s'},grid:{color:getComputedStyle(document.documentElement).getPropertyValue('--border2')}}},plugins:{legend:{labels:{color:getComputedStyle(document.documentElement).getPropertyValue('--fg')}}}}});}
function pushChartSample(s){if(!trafficChart)return;const label=new Date(s.t*1000).toLocaleTimeString();trafficChart.data.labels.push(label);trafficChart.data.datasets[0].data.push(s.up_bps);trafficChart.data.datasets[1].data.push(s.down_bps);if(trafficChart.data.labels.length>CHART_MAX_POINTS){trafficChart.data.labels.shift();trafficChart.data.datasets[0].data.shift();trafficChart.data.datasets[1].data.shift();}trafficChart.update('none');}
function connectStream(){const st=document.getElementById('streamStatus');const es=new EventSource('/api/stream');es.addEventListener('history',e=>{try{JSON.parse(e.data).forEach(pushChartSample);st.textContent='(live)';st.style.color='#86efac';}catch(err){console.error(err);}});es.addEventListener('sample',e=>{try{pushChartSample(JSON.parse(e.data));}catch(err){console.error(err);}});es.onerror=()=>{st.textContent='(reconnecting...)';st.style.color='#fca5a5';};es.onopen=()=>{st.textContent='(live)';st.style.color='#86efac';};}
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);document.getElementById('themeToggleBtn').textContent=t==='light'?'☀️ Theme':'🌙 Theme';try{localStorage.setItem('dashboard-theme',t);}catch(e){}}
function toggleTheme(){const cur=document.documentElement.getAttribute('data-theme')||'dark';applyTheme(cur==='light'?'dark':'light');}
(function(){let s='dark';try{s=localStorage.getItem('dashboard-theme')||'dark';}catch(e){}applyTheme(s);})();
async function fetchAll(){try{const res=await fetch('/api/all');if(!res.ok)throw new Error('HTTP '+res.status);const d=await res.json();renderStats(d);lastConns=d.active_connections||[];renderConnections();renderUpstream(d.upstream||{});}catch(e){console.error(e);document.getElementById('statsGrid').innerHTML='<div style="color:#dc2626;">⚠️ Failed to load. Retrying...</div>';}}
function renderStats(d){const boxes=[['Total Connections',d.total],['Active',d.active],['SOCKS5 TCP',d.socks5_tcp],['SOCKS5 UDP',d.socks5_udp],['HTTP Requests',d.http],['UDP Associations',d.udp_assocs||0],['Bytes Up (TCP)',formatBytes(d.bytes_up)],['Bytes Down (TCP)',formatBytes(d.bytes_down)],['UDP Up',formatBytes(d.udp_up)],['UDP Down',formatBytes(d.udp_down)],['Uptime',formatUptime(d.uptime)]];document.getElementById('statsGrid').innerHTML=boxes.map(b=>'<div class="stat-box"><div class="stat-label">'+b[0]+'</div><div class="stat-value">'+b[1]+'</div></div>').join('');}
function sortConns(k){if(sortKey===k){sortDir=sortDir==='asc'?'desc':'asc';}else{sortKey=k;sortDir='asc';}renderConnections();}
function renderConnections(){const f=(document.getElementById('connFilter').value||'').toLowerCase().trim();let conns=lastConns.slice();if(f){conns=conns.filter(c=>(c.ip||'').toLowerCase().includes(f)||(c.target||'').toLowerCase().includes(f)||(c.type||'').toLowerCase().includes(f));}conns.sort((a,b)=>{let av=a[sortKey],bv=b[sortKey];if(typeof av==='string'){av=av.toLowerCase();bv=(bv||'').toLowerCase();}if(av<bv)return sortDir==='asc'?-1:1;if(av>bv)return sortDir==='asc'?1:-1;return 0;});if(!conns.length){document.getElementById('connectionsTable').innerHTML='<div style="padding:15px;color:var(--muted);">No active connections</div>';return;}const cols=[['ip','IP'],['port','Port'],['type','Type'],['target','Target'],['duration','Duration'],['bytes_up','Bytes Up'],['bytes_down','Bytes Down']];let thead='<tr>';cols.forEach(c=>{let cls=sortKey===c[0]?(sortDir==='asc'?'sorted-asc':'sorted-desc'):'';thead+='<th class="'+cls+'" onclick="sortConns(\''+c[0]+'\')">'+c[1]+'</th>';});thead+='<th>Action</th></tr>';let html='<table><thead>'+thead+'</thead><tbody>';conns.forEach(c=>{let bg='<span class="badge">'+esc(c.type)+'</span>';if(c.type==='SOCKS5_TCP')bg='<span class="badge socks5-tcp">SOCKS5 TCP</span>';else if(c.type==='SOCKS5_UDP')bg='<span class="badge socks5-udp">SOCKS5 UDP</span>';else if(c.type==='HTTP')bg='<span class="badge http">HTTP</span>';html+='<tr><td>'+esc(c.ip)+'</td><td>'+esc(c.port)+'</td><td>'+bg+'</td><td>'+esc(c.target||'N/A')+'</td><td>'+formatUptime(c.duration)+'</td><td>'+formatBytes(c.bytes_up)+'</td><td>'+formatBytes(c.bytes_down)+'</td><td><button class="btn btn-sm btn-danger" onclick="kickConn(\''+esc(c.id)+'\')">Kick</button></td></tr>';});html+='</tbody></table>';document.getElementById('connectionsTable').innerHTML=html;}
async function kickConn(id){if(!id)return;try{const res=await fetch('/api/kick',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})});if(res.ok)fetchAll();else alert('Kick failed: '+res.status);}catch(e){alert('Kick failed: '+e.message);}}
function exportConns(f){window.location.href='/api/export?format='+encodeURIComponent(f);}
function renderUpstream(up){const st=up.status||[];let h='<div style="padding:8px 0;color:var(--muted2);">';if(st.length){h+=st.map(s=>esc(s.addr)+' '+(s.alive?'<span class="badge" style="background:var(--badge-http-bg);color:var(--badge-http-fg);">alive</span>':'<span class="badge" style="background:var(--danger-hover-bg);color:var(--danger-fg);">dead</span>')).join(' | ');h+='<br><span style="font-size:.78rem;color:var(--muted);">Round-robin index hiện tại: '+up.current_index+'</span>';}else{h+='<span style="color:var(--muted);">No upstream proxies configured.</span>';}h+='</div>';document.getElementById('upstreamInfo').innerHTML=h;}
async function fetchNetworkConfig(){try{const res=await fetch('/api/network-config');const d=await res.json();document.getElementById('netAllow').value=(d.allow_list||[]).join('\n');document.getElementById('netDeny').value=(d.deny_list||[]).join('\n');document.getElementById('netUpstream').value=(d.upstream_proxies||[]).join('\n');}catch(e){console.error(e);}}
function lines(t){return t.split('\n').map(s=>s.trim()).filter(s=>s.length>0);}
async function saveNetworkConfig(){const m=document.getElementById('netMsg');m.textContent='Saving...';m.className='modal-msg';try{const res=await fetch('/api/network-config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({allow_list:lines(document.getElementById('netAllow').value),deny_list:lines(document.getElementById('netDeny').value),upstream_proxies:lines(document.getElementById('netUpstream').value)})});const d=await res.json();if(!res.ok){m.textContent=d.error||'HTTP '+res.status;m.className='modal-msg error';return;}m.textContent='Saved & applied.';m.className='modal-msg success';fetchReloadHistory();}catch(e){m.textContent='Err: '+e.message;m.className='modal-msg error';}}
async function reloadFromDisk(){const m=document.getElementById('netMsg');m.textContent='Reloading...';try{const res=await fetch('/api/reload',{method:'POST'});const d=await res.json();if(!res.ok){m.textContent=d.error||'HTTP '+res.status;m.className='modal-msg error';return;}m.textContent='Reloaded.';m.className='modal-msg success';fetchNetworkConfig();fetchReloadHistory();}catch(e){m.textContent='Err: '+e.message;m.className='modal-msg error';}}
async function fetchReloadHistory(){try{const res=await fetch('/api/reload-history');const d=await res.json();renderReloadHistory(d.history||[]);}catch(e){document.getElementById('reloadHistoryTable').innerHTML='<div style="padding:15px;color:var(--muted);">Failed</div>';}}
function renderReloadHistory(h){if(!h.length){document.getElementById('reloadHistoryTable').innerHTML='<div style="padding:15px;color:var(--muted);">No reload events yet.</div>';return;}let html='<table><thead><tr><th>Time</th><th>Source</th><th>Status</th><th>Details</th></tr></thead><tbody>';h.forEach(ev=>{const time=new Date(ev.t*1000).toLocaleString();const sb=ev.success?'<span class="badge" style="background:var(--badge-http-bg);color:var(--badge-http-fg);">OK</span>':'<span class="badge" style="background:var(--danger-hover-bg);color:var(--danger-fg);">FAILED</span>';let det=ev.success?ev.allow_count+' allow, '+ev.deny_count+' deny, '+ev.upstream_count+' upstream, '+ev.user_count+' users':'<span style="color:var(--danger-fg);">'+esc(ev.error||'')+'</span>';html+='<tr><td>'+time+'</td><td>'+esc(ev.source)+'</td><td>'+sb+'</td><td>'+det+'</td></tr>';});html+='</tbody></table>';document.getElementById('reloadHistoryTable').innerHTML=html;}
async function fetchTokens(){try{const res=await fetch('/api/tokens');const d=await res.json();renderTokens(d.tokens||[]);}catch(e){document.getElementById('tokensTable').innerHTML='<div style="padding:15px;color:var(--muted);">Failed</div>';}}
function renderTokens(ts){if(!ts.length){document.getElementById('tokensTable').innerHTML='<div style="padding:15px;color:var(--muted);">No API tokens yet.</div>';return;}let h='<table><thead><tr><th>Name</th><th>Created</th><th>Action</th></tr></thead><tbody>';ts.forEach(t=>{h+='<tr><td>'+esc(t.name)+'</td><td>'+new Date(t.created_at*1000).toLocaleString()+'</td><td><button class="btn btn-sm btn-danger" onclick="deleteToken(\''+esc(t.name)+'\')">Revoke</button></td></tr>';});h+='</tbody></table>';document.getElementById('tokensTable').innerHTML=h;}
function openTokenModal(){document.getElementById('tokenMsg').textContent='';document.getElementById('tokenResultBox').style.display='none';document.getElementById('tokenForm').reset();document.getElementById('tName').disabled=false;document.getElementById('tokenSubmitBtn').style.display='inline-block';document.getElementById('tokenModalOverlay').classList.add('open');}
function closeTokenModal(){document.getElementById('tokenModalOverlay').classList.remove('open');fetchTokens();}
async function submitTokenForm(e){e.preventDefault();const m=document.getElementById('tokenMsg');const name=document.getElementById('tName').value.trim();try{const res=await fetch('/api/tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name})});const d=await res.json();if(!res.ok){m.textContent=d.error||'HTTP '+res.status;m.className='modal-msg error';return false;}document.getElementById('tokenResultValue').textContent=d.token;document.getElementById('tokenResultBox').style.display='block';document.getElementById('tName').disabled=true;document.getElementById('tokenSubmitBtn').style.display='none';}catch(err){m.textContent='Err: '+err.message;m.className='modal-msg error';}return false;}
async function deleteToken(n){if(!confirm('Revoke token "'+n+'"?'))return;try{const res=await fetch('/api/tokens/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})});if(res.ok)fetchTokens();}catch(e){alert('Err: '+e.message);}}
async function fetchAuditLog(){try{const res=await fetch('/api/audit-log');const d=await res.json();renderAuditLog(d.events||[]);}catch(e){document.getElementById('auditTable').innerHTML='<div style="padding:15px;color:var(--muted);">Failed</div>';}}
function renderAuditLog(evs){if(!evs.length){document.getElementById('auditTable').innerHTML='<div style="padding:15px;color:var(--muted);">No audit events yet.</div>';return;}let h='<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead><tbody>';evs.forEach(ev=>{h+='<tr><td>'+new Date(ev.t*1000).toLocaleString()+'</td><td>'+esc(ev.actor)+'</td><td>'+esc(ev.action)+'</td><td style="font-size:.8rem;color:var(--muted2);">'+esc(ev.details||'')+'</td></tr>';});h+='</tbody></table>';document.getElementById('auditTable').innerHTML=h;}
async function restoreConfig(e){const f=e.target.files[0];if(!f)return;const m=document.getElementById('backupMsg');if(!confirm('Restore from "'+f.name+'"? Will overwrite current settings.')){e.target.value='';return;}m.textContent='Restoring...';try{const text=await f.text();const res=await fetch('/api/config/import',{method:'POST',headers:{'Content-Type':'application/json'},body:text});const d=await res.json();if(!res.ok){m.textContent=d.error||'HTTP '+res.status;m.className='modal-msg error';return;}m.textContent='Restored. Reloading...';m.className='modal-msg success';setTimeout(()=>window.location.reload(),1500);}catch(err){m.textContent='Err: '+err.message;m.className='modal-msg error';}finally{e.target.value='';}}
async function fetchUsers(){try{const res=await fetch('/api/users');const d=await res.json();renderUsers(d.users||[]);}catch(e){document.getElementById('usersTable').innerHTML='<div style="padding:15px;color:var(--muted);">Failed</div>';}}
function renderUsers(us){if(!us.length){document.getElementById('usersTable').innerHTML='<div style="padding:15px;color:var(--muted);">No users configured — proxy still works via -u/-P if set.</div>';return;}let h='<table><thead><tr><th>Username</th><th>Max Bandwidth</th><th>Max Conns</th><th>Quota/Month</th><th>Used This Month</th><th>Action</th></tr></thead><tbody>';us.forEach(u=>{const bw=u.max_bandwidth_bps>0?formatBytes(u.max_bandwidth_bps)+'/s':'Unlimited';const mc=u.max_connections>0?u.max_connections:'Unlimited';const q=u.quota_bytes_per_month>0?formatBytes(u.quota_bytes_per_month):'Unlimited';const used=formatBytes(u.usage_bytes_this_month||0);const over=u.quota_bytes_per_month>0&&(u.usage_bytes_this_month||0)>=u.quota_bytes_per_month;h+='<tr><td>'+esc(u.username)+'</td><td>'+bw+'</td><td>'+mc+'</td><td>'+q+'</td><td>'+(over?'<span style="color:var(--danger-fg);">'+used+' ⚠️ OVER</span>':used)+'</td><td><button class="btn btn-sm btn-danger" onclick="deleteUser(\''+esc(u.username)+'\')">Delete</button></td></tr>';});h+='</tbody></table>';document.getElementById('usersTable').innerHTML=h;}
function openUserModal(){document.getElementById('userMsg').textContent='';document.getElementById('userForm').reset();document.getElementById('userModalOverlay').classList.add('open');}
function closeUserModal(){document.getElementById('userModalOverlay').classList.remove('open');}
async function submitUserForm(e){e.preventDefault();const m=document.getElementById('userMsg');const u=document.getElementById('uUsername').value.trim();const p=document.getElementById('uPassword').value;const bw=parseFloat(document.getElementById('uBandwidth').value)||0;const mc=parseInt(document.getElementById('uMaxConn').value)||0;const q=parseFloat(document.getElementById('uQuota').value)||0;try{const res=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p,max_bandwidth_bps:Math.round(bw*1024),max_connections:mc,quota_bytes_per_month:Math.round(q*1024*1024)})});const d=await res.json();if(!res.ok){m.textContent=d.error||'HTTP '+res.status;m.className='modal-msg error';return false;}closeUserModal();fetchUsers();}catch(err){m.textContent='Err: '+err.message;m.className='modal-msg error';}return false;}
async function deleteUser(u){if(!confirm('Delete user "'+u+'"?'))return;try{const res=await fetch('/api/users/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u})});if(res.ok)fetchUsers();}catch(e){alert('Err: '+e.message);}}
function esc(v){return String(v===undefined||v===null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function formatBytes(b){if(!b)return '0 B';const u=['B','KiB','MiB','GiB','TiB'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++;}return b.toFixed(1)+' '+u[i];}
function formatUptime(s){if(!s)return '00:00:00';const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),x=Math.floor(s%60);return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(x).padStart(2,'0');}
function openPwModal(){document.getElementById('pwMsg').textContent='';document.getElementById('pwForm').reset();document.getElementById('pwModalOverlay').classList.add('open');}
function closePwModal(){document.getElementById('pwModalOverlay').classList.remove('open');}
async function submitPwChange(e){e.preventDefault();const m=document.getElementById('pwMsg');const cur=document.getElementById('curPass').value,nuser=document.getElementById('newUser').value.trim(),np=document.getElementById('newPass').value,np2=document.getElementById('newPass2').value;if(np!==np2){m.textContent='Password confirmation mismatch.';m.className='modal-msg error';return false;}if(np.length<8){m.textContent='Password >= 8 chars.';m.className='modal-msg error';return false;}try{const res=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_username:nuser,new_password:np})});const d=await res.json();if(!res.ok){m.textContent=d.error||'HTTP '+res.status;m.className='modal-msg error';return false;}m.textContent='Changed! Reloading...';m.className='modal-msg success';setTimeout(()=>window.location.reload(),1500);}catch(err){m.textContent='Err: '+err.message;m.className='modal-msg error';}return false;}
fetchAll();fetchUsers();fetchNetworkConfig();fetchReloadHistory();fetchTokens();fetchAuditLog();
setInterval(fetchAll,5000);setInterval(fetchUsers,15000);setInterval(fetchReloadHistory,15000);setInterval(fetchAuditLog,15000);
function loadScript(src){return new Promise((res,rej)=>{const t=document.createElement('script');t.src=src;t.onload=()=>res();t.onerror=()=>rej(new Error('fail '+src));document.head.appendChild(t);});}
async function loadChartJS(){for(const u of ['https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js','https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js','https://unpkg.com/chart.js@4.4.4/dist/chart.umd.min.js']){try{await loadScript(u);if(typeof Chart!=='undefined')return true;}catch(e){}}return false;}
(async function(){try{const ok=await loadChartJS();if(!ok)throw new Error('Chart.js CDN blocked');initChart();connectStream();}catch(err){console.error(err);const st=document.getElementById('streamStatus');if(st){st.textContent='(unavailable)';st.style.color='#fca5a5';}const cv=document.getElementById('trafficChart');if(cv){cv.outerHTML='<div style="padding:20px;color:#fca5a5;font-size:.85rem;">⚠️ Không tải được biểu đồ: '+err.message+'<br>Stats/Connections/Users vẫn hoạt động.</div>';}}})();
</script>
</body></html>
"""
  end
end

# ============================================================================
# CLI ENTRY
# ============================================================================
defmodule P.CLI do
  require Logger

  def main(argv) do
    # CRITICAL: trap exit để CLI main không bị kill khi process con crash
    Process.flag(:trap_exit, true)

    {opts, _, _} = OptionParser.parse(argv,
      strict: [
        listen: :string, port: :integer, username: :string, password: :string,
        no_udp: :boolean, upstream: :string,
        dashboard_port: :integer, dashboard_bind: :string,
        config: :string, usage_file: :string,
        allow: :string, deny: :string,
        allow_private: :boolean, hash_iters: :integer,
        webui_port: :integer, webui_bind: :string,
        no_webui: :boolean
      ]
    )

    Enum.each(opts, fn
      {:listen, v} -> Application.put_env(:proxy, :listen, v)
      {:port, v} -> Application.put_env(:proxy, :port, v)
      {:dashboard_port, v} -> Application.put_env(:proxy, :dashboard_port, v)
      {:dashboard_bind, v} -> Application.put_env(:proxy, :dashboard_bind, v)
      {:config, v} -> Application.put_env(:proxy, :config_path, v)
      {:usage_file, v} -> Application.put_env(:proxy, :usage_path, v)
      {:no_udp, v} -> Application.put_env(:proxy, :no_udp, v)
      {:upstream, v} -> Application.put_env(:proxy, :upstream, v)
      {:username, v} -> Application.put_env(:proxy, :username, v)
      {:password, v} -> Application.put_env(:proxy, :password, v)
      {:allow_private, v} -> Application.put_env(:proxy, :allow_private, v)
      {:hash_iters, v} -> Application.put_env(:proxy, :hash_iters, v)
      {:webui_port, v} -> Application.put_env(:proxy, :webui_port, v)
      {:webui_bind, v} -> Application.put_env(:proxy, :webui_bind, v)
      {:no_webui, v} -> Application.put_env(:proxy, :no_webui, v)
      _ -> :ok
    end)

    case P.State.start_link([]) do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> :ok
      other -> Logger.error("State start failed: #{inspect(other)}"); System.halt(1)
    end

    case P.Cfg.start_link([]) do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> :ok
      other -> Logger.error("Cfg start failed: #{inspect(other)}"); System.halt(1)
    end

    P.Audit.init()

    listener_pid = case P.Listener.start_link([]) do
      {:ok, p} -> p
      other ->
        Logger.error("Listener start failed: #{inspect(other)}")
        System.halt(1)
    end

    dash_pid = case P.Dashboard.start_link([]) do
      {:ok, p} -> p
      other ->
        Logger.error("Dashboard start failed: #{inspect(other)}")
        System.halt(1)
    end

    webui_pid =
      if Application.get_env(:proxy, :no_webui, false) do
        nil
      else
        case P.WebUI.start_link([]) do
          {:ok, p} -> Process.monitor(p); p
          {:error, e} ->
            Logger.error("WebUI start failed: #{inspect(e)}")
            nil
        end
      end

    P.Up.health_loop()

    Process.monitor(listener_pid)
    Process.monitor(dash_pid)

    main_loop(listener_pid, dash_pid, webui_pid)
  end

  defp main_loop(listener_pid, dash_pid, webui_pid) do
    receive do
      {:DOWN, _, :process, ^listener_pid, reason} ->
        Logger.error("Listener exited: #{inspect(reason)}. Restarting in 1s...")
        Process.sleep(1000)
        new_pid = case P.Listener.start_link([]) do
          {:ok, p} -> Process.monitor(p); p
          _ -> nil
        end
        main_loop(new_pid, dash_pid, webui_pid)

      {:DOWN, _, :process, ^dash_pid, reason} ->
        Logger.error("Dashboard exited: #{inspect(reason)}. Restarting in 1s...")
        Process.sleep(1000)
        new_pid = case P.Dashboard.start_link([]) do
          {:ok, p} -> Process.monitor(p); p
          _ -> nil
        end
        main_loop(listener_pid, new_pid, webui_pid)

      {:DOWN, _, :process, ^webui_pid, reason} when is_pid(webui_pid) ->
        Logger.error("WebUI exited: #{inspect(reason)}. Restarting in 1s...")
        Process.sleep(1000)
        new_pid = case P.WebUI.start_link([]) do
          {:ok, p} -> Process.monitor(p); p
          _ -> nil
        end
        main_loop(listener_pid, dash_pid, new_pid)

      {:DOWN, _, :process, _, reason} ->
        Logger.warning("Monitored child exited: #{inspect(reason)}")
        main_loop(listener_pid, dash_pid, webui_pid)

      _ ->
        main_loop(listener_pid, dash_pid, webui_pid)
    after
      60_000 -> main_loop(listener_pid, dash_pid, webui_pid)
    end
  end
end



defmodule P.WebUI do
  require Logger

  @chrome_ua "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  @scheme_sep "%3A%2F%2F"
  @max_body 20_000_000

  # ==================== UI ====================
  @page_html ~S"""
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Web Proxy</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;width:100%;font-family:system-ui,'Segoe UI',Roboto,sans-serif;background:#0f0f1a;color:#e0e0e0;overflow:hidden;position:fixed;inset:0;-webkit-text-size-adjust:100%}
#app{display:flex;flex-direction:column;height:100vh;height:100dvh;width:100vw}
.toolbar{flex:0 0 auto;display:flex;gap:6px;align-items:center;padding:8px 10px;background:#14141f;border-bottom:1px solid #2a2a3a;padding-top:max(8px,env(safe-area-inset-top));padding-left:max(10px,env(safe-area-inset-left));padding-right:max(10px,env(safe-area-inset-right))}
input[type=text]{flex:1 1 auto;min-width:0;background:#1a1a2e;border:1px solid #2a2a3a;border-radius:8px;padding:8px 12px;color:#e0e0e0;font-size:.9rem;outline:none;font-family:inherit}
input[type=text]:focus{border-color:#f0c27a}
button{flex:0 0 auto;background:#2a2a3a;color:#e0e0e0;border:1px solid #3a3a52;border-radius:8px;padding:8px 10px;font-size:.9rem;cursor:pointer;font-family:inherit;line-height:1;transition:.15s;user-select:none;-webkit-tap-highlight-color:transparent}
button:hover{background:#33334a;border-color:#f0c27a}
button:active{transform:scale(.96)}
button.go{background:#f0c27a;color:#1a1a2e;font-weight:600;border-color:#f0c27a}
button.go:hover{filter:brightness(1.1)}
button.nav{padding:8px 10px;font-size:1rem;min-width:36px}
.status{flex:0 0 auto;font-size:.72rem;color:#9999bb;white-space:nowrap;min-width:50px;text-align:right;overflow:hidden;text-overflow:ellipsis}
.frame-wrap{flex:1 1 auto;position:relative;background:#fff;overflow:hidden;min-height:0}
iframe{display:block;width:100%;height:100%;border:0;background:#fff}
@media (max-width:520px){.status{display:none}button.nav{padding:8px 8px}input[type=text]{font-size:.85rem;padding:8px 10px}}
</style>
</head>
<body>
<div id="app">
  <div class="toolbar">
    <button class="nav" onclick="nav('back')" title="Back">←</button>
    <button class="nav" onclick="nav('forward')" title="Forward">→</button>
    <button class="nav" onclick="nav('reload')" title="Reload">⟳</button>
    <input type="text" id="u" placeholder="https://example.com — nhập URL rồi Enter" autofocus autocomplete="off" spellcheck="false" autocapitalize="off">
    <button class="go" onclick="go()">Go</button>
    <div class="status" id="s"></div>
  </div>
  <div class="frame-wrap">
    <iframe id="f" referrerpolicy="no-referrer-when-downgrade" allow="clipboard-read; clipboard-write; fullscreen; geolocation; camera; microphone"></iframe>
  </div>
</div>
<script>
(function(){
  var inp=document.getElementById('u'), frm=document.getElementById('f'), st=document.getElementById('s');
  function enc(u){ return u.replace('://','%3A%2F%2F'); }
  function dec(s){
    var i=s.toLowerCase().indexOf('%3a%2f%2f');
    if(i>=0) return s.slice(0,i)+'://'+s.slice(i+9);
    return s;
  }
  inp.addEventListener('keydown', function(e){
    if(e.key==='Enter'){ e.preventDefault(); go(); }
  });
  function go(){
    var raw=inp.value.trim();
    if(!raw) return;
    if(raw.slice(0,3)==='/p/') raw=dec(raw.slice(3));
    var u;
    try{ u=new URL(raw); }
    catch(e){
      try{ u=new URL('https://'+raw); }
      catch(e2){ st.textContent='URL sai'; return; }
    }
    if(u.protocol!=='http:'&&u.protocol!=='https:'){ st.textContent='scheme sai'; return; }
    inp.value=u.href;
    st.textContent='đang tải...';
    frm.src='/p/'+enc(u.href);
  }
  window.go=go;
  function nav(a){
    try{
      var w=frm.contentWindow;
      if(a==='back') w.history.back();
      else if(a==='forward') w.history.forward();
      else if(a==='reload'){ try{ w.location.reload(); }catch(e){ frm.src=frm.src; } }
    }catch(e){ if(a==='reload') frm.src=frm.src; }
  }
  window.nav=nav;
  setInterval(function(){
    try{
      var w=frm.contentWindow;
      var p=w.location.pathname, s=w.location.search;
      if(p.indexOf('/p/')===0){
        var orig=dec(p.slice(3))+s;
        if(document.activeElement!==inp && inp.value!==orig){
          inp.value=orig;
          st.textContent='';
        }
      }
    }catch(e){}
  },400);
  window.addEventListener('message', function(e){
    if(!e.data || typeof e.data!=='object') return;
    if(e.data.__proxyNav && typeof e.data.url==='string'){
      if(document.activeElement!==inp) inp.value=e.data.url;
      st.textContent='';
    }
  });
  function resize(){
    document.documentElement.style.setProperty('--vh',(window.innerHeight*0.01)+'px');
  }
  window.addEventListener('resize', resize);
  window.addEventListener('orientationchange', function(){ setTimeout(resize,120); });
  resize();
  window.addEventListener('load', function(){ inp.focus(); });
})();
</script>
</body>
</html>
"""

  # ==================== JS SHIM ====================
  @js_shim ~S"""
(function(){
  var PREFIX='/p/';
  function enc(u){ return u.replace('://','%3A%2F%2F'); }
  function dec(s){
    var i=s.toLowerCase().indexOf('%3a%2f%2f');
    if(i>=0) return s.slice(0,i)+'://'+s.slice(i+9);
    return s;
  }
  var ORIG=(function(){
    var p=location.pathname;
    if(p.indexOf(PREFIX)===0) return dec(p.slice(3))+location.search+location.hash;
    return location.href;
  })();
  function px(u){
    if(typeof u!=='string'||!u) return u;
    if(u.indexOf(PREFIX)===0) return u;
    if(/^(data|blob|javascript|mailto|tel|about):/i.test(u)) return u;
    if(u.charAt(0)==='#') return u;
    var abs;
    if(u.indexOf('//')===0){ abs=location.protocol+u; }
    else if(/^https?:\/\//i.test(u)){ abs=u; }
    else if(/^wss?:\/\//i.test(u)){ abs=u; }
    else if(u.charAt(0)==='/'){ try{abs=new URL(ORIG).origin+u;}catch(e){return u;} }
    else { return u; }
    return PREFIX+enc(abs);
  }
  window.__proxify=px;
  var _fetch=window.fetch;
  if(_fetch) window.fetch=function(input,init){
    try{
      if(typeof input==='string') input=px(input);
      else if(input && input.url) input=new Request(px(input.url),input);
    }catch(e){}
    return _fetch.call(this,input,init);
  };
  var _open=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    var a=Array.prototype.slice.call(arguments);
    if(typeof u==='string') a[1]=px(u);
    return _open.apply(this,a);
  };
  var _winOpen=window.open;
  window.open=function(u,n,f){
    if(typeof u==='string') u=px(u);
    return _winOpen.call(window,u,n,f);
  };
  try{
    var _push=history.pushState.bind(history);
    var _repl=history.replaceState.bind(history);
    history.pushState=function(s,t,u){ if(u) u=px(u); return _push(s,t,u); };
    history.replaceState=function(s,t,u){ if(u) u=px(u); return _repl(s,t,u); };
  }catch(e){}
  try{
    if(location.assign){
      var _a=location.assign.bind(location);
      location.assign=function(u){ return _a(px(u)); };
    }
    if(location.replace){
      var _r=location.replace.bind(location);
      location.replace=function(u){ return _r(px(u)); };
    }
  }catch(e){}
  try{
    var _Worker=window.Worker;
    if(_Worker) window.Worker=function(u,o){
      if(typeof u==='string') u=px(u);
      return o===undefined ? new _Worker(u) : new _Worker(u,o);
    };
  }catch(e){}
  try{
    var _SharedWorker=window.SharedWorker;
    if(_SharedWorker) window.SharedWorker=function(u,o){
      if(typeof u==='string') u=px(u);
      return o===undefined ? new _SharedWorker(u) : new _SharedWorker(u,o);
    };
  }catch(e){}
  try{
    var _ES=window.EventSource;
    if(_ES) window.EventSource=function(u,o){
      if(typeof u==='string') u=px(u);
      return o===undefined ? new _ES(u) : new _ES(u,o);
    };
  }catch(e){}
  try{
    var _WS=window.WebSocket;
    if(_WS){
      var pxyWS=function(u,p){
        if(typeof u==='string'){
          var e2=u.replace('://','%3A%2F%2F');
          var proto=(location.protocol==='https:')?'wss://':'ws://';
          u=proto+location.host+PREFIX+e2;
        }
        if(p===undefined) return new _WS(u);
        return new _WS(u,p);
      };
      pxyWS.CONNECTING=0; pxyWS.OPEN=1; pxyWS.CLOSING=2; pxyWS.CLOSED=3;
      pxyWS.prototype=_WS.prototype;
      window.WebSocket=pxyWS;
    }
  }catch(e){}
  try{
    if(navigator.serviceWorker && navigator.serviceWorker.register){
      navigator.serviceWorker.register=function(){
        console.log('[proxy] SW disabled');
        return Promise.reject(new Error('SW disabled by proxy'));
      };
      try{ navigator.serviceWorker.getRegistrations().then(function(rs){rs.forEach(function(r){r.unregister()})}); }catch(e){}
    }
  }catch(e){}
  function sync(){
    try{ parent.postMessage({__proxyNav:true,url:ORIG},'*'); }catch(e){}
  }
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded',sync);
  } else { sync(); }
})();
"""

  # ==================== COOKIE JAR ====================
  defmodule Jar do
    def ensure, do: :ets.whereis(:p_webui_jar)
    def init do
      case :ets.whereis(:p_webui_jar) do
        :undefined ->
          try do :ets.new(:p_webui_jar, [:named_table, :public, :set]) rescue _ -> :ok end
        _ -> :ok
      end
      :ok
    end

    def store(host, set_cookie_lines) do
      jar = for line <- set_cookie_lines do
        case String.split(line, ";", parts: 2) do
          [kv | _] ->
            case String.split(kv, "=", parts: 2) do
              [k, v] -> {String.trim(k), String.trim(v)}
              _ -> nil
            end
          _ -> nil
        end
      end |> Enum.reject(&is_nil/1)
      existing =
        case :ets.lookup(:p_webui_jar, host) do
          [{^host, m}] -> m
          [] -> %{}
        end
      merged = Enum.reduce(jar, existing, fn {k, v}, acc -> Map.put(acc, k, v) end)
      :ets.insert(:p_webui_jar, {host, merged})
    end

    def header(host) do
      case :ets.lookup(:p_webui_jar, host) do
        [{^host, m}] when map_size(m) > 0 ->
          Enum.map_join(m, "; ", fn {k, v} -> "#{k}=#{v}" end)
        _ -> nil
      end
    end
  end

  # ==================== PUBLIC API ====================
  def start_link(_) do
    Jar.init()
    port = Application.get_env(:proxy, :webui_port, 8080)
    bind = Application.get_env(:proxy, :webui_bind, "0.0.0.0")
    parent = self()
    pid = spawn(fn ->
      ip = case :inet.parse_address(String.to_charlist(bind)) do
        {:ok, t} -> t
        _ -> {0, 0, 0, 0}
      end
      opts = [:binary, packet: :raw, active: false, reuseaddr: true, ip: ip, backlog: 256]
      case :gen_tcp.listen(port, opts) do
        {:ok, lsock} ->
          Logger.info("WebUI: http://#{bind}:#{port}")
          send(parent, {:webui_ok, self()})
          accept_loop(lsock)
        {:error, e} -> send(parent, {:webui_err, self(), e})
      end
    end)
    receive do
      {:webui_ok, ^pid} -> {:ok, pid}
      {:webui_err, ^pid, e} ->
        Logger.error("WebUI listen fail: #{inspect(e)}")
        {:error, e}
    after 5000 -> {:error, :timeout}
    end
  end

  defp accept_loop(lsock) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        h = spawn(fn -> receive do :go -> handle(sock) end end)
        case :gen_tcp.controlling_process(sock, h) do
          :ok -> send(h, :go)
          _ -> :gen_tcp.close(sock)
        end
        accept_loop(lsock)
      {:error, :closed} -> :ok
      _ -> Process.sleep(50); accept_loop(lsock)
    end
  end

  # ==================== REQUEST READ ====================
  defp handle(sock) do
    reader = %P.Buf{sock: sock, buf: <<>>}
    case read_request(reader) do
      {:ok, method, target, version, headers, r2} ->
        body = read_body(r2, headers)
        route(sock, method, target, version, headers, body)
      _ -> :gen_tcp.close(sock)
    end
  end

  defp read_request(reader) do
    case P.Buf.read_line(reader) do
      {:ok, "", r} -> read_request(r)
      {:ok, line, r} ->
        case String.split(line, " ", parts: 3) do
          [m, t, v] ->
            case read_headers(r, %{}) do
              {:ok, h, r2} -> {:ok, m, t, v, h, r2}
              _ -> :error
            end
          _ -> :error
        end
      _ -> :error
    end
  end

  defp read_headers(reader, acc) do
    case P.Buf.read_line(reader) do
      {:ok, "", r} -> {:ok, acc, r}
      {:ok, line, r} ->
        case String.split(line, ":", parts: 2) do
          [k, v] ->
            key = String.downcase(String.trim(k))
            val = String.trim(v)
            read_headers(r, Map.update(acc, key, val, &(&1 <> ", " <> val)))
          _ -> read_headers(r, acc)
        end
      _ -> {:error, :eof}
    end
  end

  defp read_body(reader, headers) do
    case headers["content-length"] do
      nil -> ""
      cl ->
        case Integer.parse(cl) do
          {n, ""} when n > 0 and n <= @max_body ->
            case P.Buf.read_n(reader, n) do
              {:ok, d, _} -> d
              _ -> ""
            end
          _ -> ""
        end
    end
  end

  # ==================== ROUTING ====================
  defp route(sock, _m, "/", _v, _h, _b) do
    send_response(sock, 200, "text/html; charset=utf-8", @page_html)
    :gen_tcp.close(sock)
  end

  defp route(sock, method, "/p/" <> _ = target, version, headers, body) do
    proxy(sock, method, target, version, headers, body)
  end

  defp route(sock, _m, target, _v, headers, _b) do
    case referer_origin(headers) do
      {:ok, origin} ->
        send_redirect(sock, "/p/" <> encode_target_url(origin <> target))
      _ ->
        send_response(sock, 404, "text/plain", "404")
    end
    :gen_tcp.close(sock)
  end

  defp referer_origin(headers) do
    case headers["referer"] do
      nil -> :error
      ref ->
        case URI.parse(ref) do
          %URI{path: p} when is_binary(p) ->
            if String.starts_with?(p, "/p/") do
              raw = decode_target_url(String.slice(p, 3..-1//1))
              case URI.parse(raw) do
                %URI{scheme: s, host: h} = u when is_binary(s) and is_binary(h) ->
                  origin = "#{s}://#{h}" <> if is_integer(u.port), do: ":#{u.port}", else: ""
                  {:ok, origin}
                _ -> :error
              end
            else :error
            end
          _ -> :error
        end
    end
  end

  # ==================== PROXY DISPATCH ====================
  defp proxy(sock, method, target_path, _version, headers, body) do
    raw = target_path |> String.slice(3..-1//1) |> decode_target_url()
    case URI.parse(raw) do
      %URI{host: host, scheme: scheme} = url when is_binary(host) and host != "" ->
        scheme = String.downcase(scheme || "")
        cond do
          scheme in ["http", "https"] ->
            case check_target(url) do
              :ok -> do_http(sock, method, url, headers, body)
              {:error, e} ->
                send_response(sock, 403, "text/plain", "SSRF: #{e}")
                :gen_tcp.close(sock)
            end
          scheme in ["ws", "wss"] and websocket_upgrade?(headers) ->
            do_websocket(sock, url, headers)
          true ->
            send_response(sock, 400, "text/plain", "Unsupported scheme: #{scheme}")
            :gen_tcp.close(sock)
        end
      _ ->
        send_response(sock, 400, "text/plain", "Bad URL")
        :gen_tcp.close(sock)
    end
  end

  defp websocket_upgrade?(h) do
    String.contains?(String.downcase(h["connection"] || ""), "upgrade") and
      String.downcase(h["upgrade"] || "") == "websocket"
  end

  defp check_target(%URI{host: host}) do
    if Application.get_env(:proxy, :allow_private, false) do
      :ok
    else
      case :inet.parse_address(String.to_charlist(host)) do
        {:ok, ip} -> if P.IP.blocked?(ip), do: {:error, "blocked"}, else: :ok
        _ ->
          case :inet.getaddrs(String.to_charlist(host), :inet) do
            {:ok, ips} -> if Enum.any?(ips, &P.IP.blocked?/1), do: {:error, "private"}, else: :ok
            _ -> :ok
          end
      end
    end
  end

  # ==================== HTTP PROXY ====================
  defp do_http(sock, method, url, headers, body) do
    scheme = String.downcase(url.scheme || "http")
    host = url.host
    port = url.port || if(scheme == "https", do: 443, else: 80)
    path = (url.path || "/") <> if(url.query, do: "?" <> url.query, else: "")

    case do_connect(scheme, host, port) do
      {:ok, conn} ->
        try do
          hdrs = build_forward_headers(headers, host, byte_size(body))
          req = "#{method} #{path} HTTP/1.1\r\n#{hdrs}\r\n" <> body
          :ok = conn_send(conn, req)
          case read_response(conn) do
            {:ok, status, rh, rbody} ->
              # Lưu cookies
              case Map.get(rh, "set-cookie") do
                nil -> :ok
                val -> Jar.store(host, String.split(val, ", "))
              end
              rh = maybe_rewrite_redirect(rh, url)
              ct = String.downcase(rh["content-type"] || "")
              cond do
                String.contains?(ct, "text/html") and status in 200..299 ->
                  out = rewrite_html(rbody, url)
                  send_full(sock, status, rh, "text/html; charset=utf-8", out)
                String.contains?(ct, "text/css") and status in 200..299 ->
                  out = rewrite_css(rbody, url)
                  send_full(sock, status, rh, "text/css; charset=utf-8", out)
                true ->
                  send_full(sock, status, rh, rh["content-type"] || "application/octet-stream", rbody)
              end
            {:error, e} ->
              send_response(sock, 502, "text/plain", "Resp: #{inspect(e)}")
          end
        rescue
          e ->
            Logger.error("WebUI: #{inspect(e)}")
            send_response(sock, 502, "text/plain", "Err: #{inspect(e)}")
        after
          conn_close(conn)
          :gen_tcp.close(sock)
        end
      {:error, e} ->
        send_response(sock, 502, "text/plain", "Connect: #{inspect(e)}")
        :gen_tcp.close(sock)
    end
  end

  # ==================== WEBSOCKET ====================
  defp do_websocket(sock, url, headers) do
    scheme = String.downcase(url.scheme || "ws")
    host = url.host
    port = url.port || if(scheme == "wss", do: 443, else: 80)
    use_tls = scheme == "wss"

    target_conn =
      if use_tls do
        case :ssl.connect(String.to_charlist(host), port,
          [:binary, active: false, verify: :verify_none,
           server_name_indication: String.to_charlist(host)], 15_000) do
          {:ok, s} -> {:ok, {:ssl, s}}
          e -> e
        end
      else
        case :gen_tcp.connect(String.to_charlist(host), port, [:binary, active: false, packet: :raw], 15_000) do
          {:ok, s} -> {:ok, {:tcp, s}}
          e -> e
        end
      end

    case target_conn do
      {:ok, tconn} ->
        path = (url.path || "/") <> if(url.query, do: "?" <> url.query, else: "")
        hlines = headers
          |> Map.drop(["proxy-connection"])
          |> Map.put("host", host)
          |> Enum.map_join("", fn {k, v} -> "#{k}: #{v}\r\n" end)
        req = "GET #{path} HTTP/1.1\r\n#{hlines}\r\n"
        conn_send(tconn, req)
        tunnel(sock, tconn)
      {:error, e} ->
        send_response(sock, 502, "text/plain", "WS dial: #{inspect(e)}")
        :gen_tcp.close(sock)
    end
  end

  defp tunnel(sock, tconn) do
    parent = self()
    pid = spawn(fn -> receive do :go -> ws_pump(tconn, {:tcp, sock}, parent) end end)
    case tconn do
      {:ssl, s} -> :ssl.controlling_process(s, pid)
      {:tcp, s} -> :gen_tcp.controlling_process(s, pid)
    end
    send(pid, :go)
    ws_pump({:tcp, sock}, tconn, parent)
    if Process.alive?(pid), do: Process.exit(pid, :kill)
    :gen_tcp.close(sock)
  end

  defp ws_pump(from, to, _parent) do
    case conn_recv(from, 0, 300_000) do
      {:ok, data} ->
        case conn_send(to, data) do
          :ok -> ws_pump(from, to, nil)
          _ -> :ok
        end
      _ -> :ok
    end
  end

  # ==================== SOCKET HELPERS ====================
  defp do_connect("https", host, port) do
    case :ssl.connect(String.to_charlist(host), port,
      [:binary, active: false, verify: :verify_none,
       server_name_indication: String.to_charlist(host)], 25_000) do
      {:ok, s} -> {:ok, {:ssl, s}}
      e -> e
    end
  end
  defp do_connect(_, host, port) do
    case :gen_tcp.connect(String.to_charlist(host), port, [:binary, active: false, packet: :raw], 25_000) do
      {:ok, s} -> {:ok, {:tcp, s}}
      e -> e
    end
  end

  defp conn_send({:ssl, s}, d), do: :ssl.send(s, d)
  defp conn_send({:tcp, s}, d), do: :gen_tcp.send(s, d)
  defp conn_recv({:ssl, s}, n, t), do: :ssl.recv(s, n, t)
  defp conn_recv({:tcp, s}, n, t), do: :gen_tcp.recv(s, n, t)
  defp conn_close({:ssl, s}), do: :ssl.close(s)
  defp conn_close({:tcp, s}), do: :gen_tcp.close(s)

  # ==================== HEADERS ====================
  defp build_forward_headers(headers, host, blen) do
    skip = ["host", "connection", "keep-alive", "proxy-connection",
            "transfer-encoding", "upgrade", "te", "trailer",
            "content-length"]
    h = headers
        |> Map.drop(skip)
        |> Map.put("host", host)
        |> Map.put_new("user-agent", @chrome_ua)
        |> Map.put_new("accept-language", "en-US,en;q=0.9")
        |> Map.put_new("accept-encoding", "gzip, deflate")
    h =
      case Jar.header(host) do
        nil -> h
        ck -> Map.put(h, "cookie", ck)
      end
    h = if blen > 0, do: Map.put(h, "content-length", "#{blen}"), else: h
    Enum.map_join(h, "", fn {k, v} -> "#{k}: #{v}\r\n" end)
  end

  # ==================== RESPONSE PARSE ====================
  defp read_response(conn) do
    case read_until_headers(conn, <<>>, 0) do
      {:ok, status, headers, rest} ->
        case read_body_stream(conn, headers, rest) do
          {:ok, body} ->
            body = maybe_gunzip(body, headers["content-encoding"])
            {:ok, status, headers, body}
          e -> e
        end
      e -> e
    end
  end

  defp read_until_headers(_conn, _buf, n) when n > @max_body, do: {:error, :too_large}
  defp read_until_headers(conn, buf, n) do
    case :binary.match(buf, "\r\n\r\n") do
      {i, 4} ->
        head = :binary.part(buf, 0, i)
        rest = :binary.part(buf, i + 4, byte_size(buf) - i - 4)
        parse_head(head, rest)
      :nomatch ->
        case conn_recv(conn, 0, 30_000) do
          {:ok, more} -> read_until_headers(conn, buf <> more, n + byte_size(more))
          e -> e
        end
    end
  end

  defp parse_head(head, rest) do
    [sl | hlines] = String.split(head, "\r\n")
    case String.split(sl, " ", parts: 3) do
      [_v, code, _] ->
        try do
          hdrs = Enum.reduce(hlines, %{}, fn line, acc ->
            case String.split(line, ":", parts: 2) do
              [k, v] ->
                key = String.downcase(String.trim(k))
                val = String.trim(v)
                Map.update(acc, key, val, &(&1 <> ", " <> val))
              _ -> acc
            end
          end)
          {:ok, String.to_integer(code), hdrs, rest}
        rescue
          _ -> {:error, :bad_status}
        end
      _ -> {:error, :bad_status}
    end
  end

  defp read_body_stream(conn, headers, rest) do
    te = String.downcase(headers["transfer-encoding"] || "")
    cond do
      String.contains?(te, "chunked") -> read_chunked(conn, rest, <<>>, 0)
      headers["content-length"] ->
        case Integer.parse(headers["content-length"]) do
          {n, ""} when n >= 0 and n <= @max_body -> read_n(conn, rest, n)
          _ -> {:error, :bad_length}
        end
      true -> read_to_close(conn, rest, 0)
    end
  end

  defp read_n(_conn, buf, n) when byte_size(buf) >= n, do: {:ok, :binary.part(buf, 0, n)}
  defp read_n(conn, buf, n) do
    case conn_recv(conn, 0, 30_000) do
      {:ok, more} -> read_n(conn, buf <> more, n)
      e -> e
    end
  end

  defp read_to_close(_conn, buf, n) when n > @max_body, do: {:ok, buf}
  defp read_to_close(conn, buf, n) do
    case conn_recv(conn, 0, 30_000) do
      {:ok, more} -> read_to_close(conn, buf <> more, n + byte_size(more))
      {:error, :closed} -> {:ok, buf}
      e -> e
    end
  end

  defp read_chunked(_conn, _buf, acc, n) when n > @max_body, do: {:ok, acc}
  defp read_chunked(conn, buf, acc, n) do
    case :binary.match(buf, "\r\n") do
      {i, 2} ->
        size_line = :binary.part(buf, 0, i)
        rest = :binary.part(buf, i + 2, byte_size(buf) - i - 2)
        size = case Integer.parse(String.split(size_line, ";") |> hd() |> String.trim(), 16) do
          {v, _} -> v
          _ -> -1
        end
        cond do
          size == 0 -> {:ok, acc}
          size > 0 ->
            case ensure_bytes(conn, rest, size + 2) do
              {:ok, b} ->
                chunk = :binary.part(b, 0, size)
                r2 = :binary.part(b, size + 2, byte_size(b) - size - 2)
                read_chunked(conn, r2, acc <> chunk, n + size)
              e -> e
            end
          true -> {:error, :bad_chunk}
        end
      :nomatch ->
        case conn_recv(conn, 0, 30_000) do
          {:ok, more} -> read_chunked(conn, buf <> more, acc, n)
          e -> e
        end
    end
  end

  defp ensure_bytes(_c, b, n) when byte_size(b) >= n, do: {:ok, b}
  defp ensure_bytes(c, b, n) do
    case conn_recv(c, 0, 30_000) do
      {:ok, more} -> ensure_bytes(c, b <> more, n)
      e -> e
    end
  end

  defp maybe_gunzip(body, "gzip") do
    try do
      :zlib.gunzip(body)
    rescue
      _ -> body
    end
  end
  defp maybe_gunzip(body, "deflate") do
    try do
      :zlib.uncompress(body)
    rescue
      _ ->
        try do
          z = :zlib.open()
          :zlib.inflateInit(z)
          out = :zlib.inflate(z, body)
          :zlib.close(z)
          IO.iodata_to_binary(out)
        rescue _ -> body end
    end
  end
  defp maybe_gunzip(body, _), do: body

  # ==================== RESPONSE SEND ====================
  defp send_response(sock, code, ctype, body) do
    b = IO.iodata_to_binary(body)
    resp = "HTTP/1.1 #{code} #{stext(code)}\r\n" <>
           "Content-Type: #{ctype}\r\n" <>
           "Content-Length: #{byte_size(b)}\r\n" <>
           "Cache-Control: no-store\r\n" <>
           "Connection: close\r\n\r\n" <> b
    :gen_tcp.send(sock, resp)
  end

  defp send_redirect(sock, loc) do
    :gen_tcp.send(sock, "HTTP/1.1 302 Found\r\nLocation: #{loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
  end

  defp send_full(sock, code, headers, ctype, body) do
    b = IO.iodata_to_binary(body)
    skip = ["content-length", "content-encoding", "transfer-encoding",
            "connection", "keep-alive", "content-type",
            "content-security-policy", "content-security-policy-report-only",
            "x-frame-options", "public-key-pins", "strict-transport-security",
            "cross-origin-opener-policy", "cross-origin-embedder-policy",
            "cross-origin-resource-policy", "set-cookie"]
    hline = headers |> Map.drop(skip) |> Enum.map_join("", fn {k, v} -> "#{k}: #{v}\r\n" end)
    setck = case Map.get(headers, "set-cookie") do
      nil -> ""
      val -> "Set-Cookie: #{val}\r\n"
    end
    resp = "HTTP/1.1 #{code} #{stext(code)}\r\n" <> hline <> setck <>
           "Content-Type: #{ctype}\r\n" <>
           "Content-Length: #{byte_size(b)}\r\n" <>
           "Cache-Control: no-store\r\n" <>
           "Connection: close\r\n\r\n" <> b
    :gen_tcp.send(sock, resp)
  end

  defp stext(200), do: "OK"
  defp stext(204), do: "No Content"
  defp stext(301), do: "Moved Permanently"
  defp stext(302), do: "Found"
  defp stext(303), do: "See Other"
  defp stext(304), do: "Not Modified"
  defp stext(307), do: "Temporary Redirect"
  defp stext(308), do: "Permanent Redirect"
  defp stext(400), do: "Bad Request"
  defp stext(401), do: "Unauthorized"
  defp stext(403), do: "Forbidden"
  defp stext(404), do: "Not Found"
  defp stext(405), do: "Method Not Allowed"
  defp stext(500), do: "Internal Server Error"
  defp stext(502), do: "Bad Gateway"
  defp stext(503), do: "Service Unavailable"
  defp stext(_), do: "OK"

  # ==================== REDIRECT REWRITE ====================
  defp maybe_rewrite_redirect(headers, base) do
    case headers["location"] do
      nil -> headers
      loc ->
        abs = case URI.parse(loc) do
          %URI{scheme: s, host: h} when is_binary(s) and is_binary(h) -> loc
          _ ->
            case URI.merge(base, URI.parse(loc)) do
              %URI{} = u -> URI.to_string(u)
              _ -> loc
            end
        end
        Map.put(headers, "location", "/p/" <> encode_target_url(abs))
    end
  end

  # ==================== URL ENCODE ====================
  defp encode_target_url(s) do
    case :binary.match(s, "://") do
      {i, 3} ->
        :binary.part(s, 0, i) <> @scheme_sep <>
          :binary.part(s, i + 3, byte_size(s) - i - 3)
      :nomatch -> s
    end
  end

  defp decode_target_url(s) do
    lower = String.downcase(s)
    case :binary.match(lower, "%3a%2f%2f") do
      {i, _} ->
        :binary.part(s, 0, i) <> "://" <>
          :binary.part(s, i + 9, byte_size(s) - i - 9)
      :nomatch -> s
    end
  end

  # ==================== HTML REWRITE ====================
  defp rewrite_html(body, base) do
    body
    |> rewrite_base_tag(base)
    |> rewrite_meta_refresh(base)
    |> rewrite_attrs(base)
    |> rewrite_srcset(base)
    |> rewrite_style_attrs(base)
    |> rewrite_style_tags(base)
    |> inject_shim()
  end

  defp rewrite_attrs(body, base) do
    Regex.replace(
      ~r/\b(href|src|action|poster|data-src|data-href|formaction)\s*=\s*["']([^"']*)["']/i,
      body, fn _, name, u -> ~s(#{name}="#{to_proxy_url(u, base)}") end)
  end

  defp rewrite_srcset(body, base) do
    Regex.replace(~r/\bsrcset\s*=\s*["']([^"']*)["']/i, body, fn _, val ->
      parts = val |> String.split(",") |> Enum.map(fn p ->
        fields = String.split(String.trim(p))
        case fields do
          [u | rest] -> Enum.join([to_proxy_url(u, base) | rest], " ")
          _ -> String.trim(p)
        end
      end)
      ~s(srcset="#{Enum.join(parts, ", ")}")
    end)
  end

  defp rewrite_style_attrs(body, base) do
    Regex.replace(~r/\bstyle\s*=\s*["']([^"']*)["']/i, body, fn _, css ->
      ~s(style="#{rewrite_css_string(css, base)}")
    end)
  end

  defp rewrite_style_tags(body, base) do
    Regex.replace(~r/<style[^>]*>(.*?)<\/style>/is, body, fn _, css ->
      "<style>" <> rewrite_css_string(css, base) <> "</style>"
    end)
  end

  defp rewrite_css_string(css, base) do
    Regex.replace(~r/url\(\s*['"]?([^'")]+?)['"]?\s*\)/i, css, fn _, u ->
      "url(" <> to_proxy_url(u, base) <> ")"
    end)
  end

  defp rewrite_css(body, base), do: rewrite_css_string(body, base)

  defp rewrite_meta_refresh(body, base) do
    Regex.replace(
      ~r/<meta\s+[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>/i, body, fn full ->
        case Regex.run(~r/content\s*=\s*["']([^"']*)["']/i, full) do
          [_, content] ->
            new = Regex.replace(~r/(url\s*=\s*)([^\s;]+)/i, content,
              fn _, pre, u -> pre <> to_proxy_url(u, base) end)
            ~s(<meta http-equiv="refresh" content="#{new}">)
          _ -> full
        end
      end)
  end

  defp rewrite_base_tag(body, base) do
    case Regex.run(~r/<base\s+([^>]*)>/i, body) do
      [_, attrs] ->
        href = case Regex.run(~r/href\s*=\s*["']([^"']+)["']/i, attrs) do
          [_, h] -> h
          _ -> URI.to_string(base)
        end
        base2 = case URI.merge(base, URI.parse(href)) do
          %URI{} = u -> u
          _ -> base
        end
        stripped = Regex.replace(~r/<base\s+[^>]*>/i, body, "")
        tag = ~s(<base href="/p/#{encode_target_url(URI.to_string(base2))}">)
        case Regex.run(~r/<head>/i, stripped) do
          [m] -> String.replace(stripped, m, m <> tag, global: false)
          _ -> tag <> stripped
        end
      _ -> body
    end
  end

  defp inject_shim(body) do
    shim = "<script>" <> @js_shim <> "</script>"
    case Regex.run(~r/<head>/i, body) do
      [m] -> String.replace(body, m, m <> shim, global: false)
      _ -> shim <> body
    end
  end

  defp to_proxy_url(raw, base) do
    raw = String.trim(raw)
    cond do
      raw == "" -> raw
      String.starts_with?(raw, ["/p/", "#", "data:", "blob:", "javascript:", "mailto:", "tel:", "about:"]) ->
        raw
      true ->
        lower = String.downcase(raw)
        cond do
          String.starts_with?(lower, ["ws://", "wss://"]) ->
            "/p/" <> encode_target_url(raw)
          String.starts_with?(raw, "//") ->
            sch = if is_binary(base.scheme) and base.scheme != "", do: base.scheme, else: "http"
            "/p/" <> encode_target_url(sch <> ":" <> raw)
          true ->
            abs = case URI.parse(raw) do
              %URI{scheme: s, host: h} when is_binary(s) and is_binary(h) -> URI.parse(raw)
              _ -> URI.merge(base, URI.parse(raw))
            end
            case abs do
              %URI{scheme: s, host: h} when s in ["http", "https"] and is_binary(h) ->
                "/p/" <> encode_target_url(URI.to_string(abs))
              _ -> raw
            end
        end
    end
  rescue
    _ -> raw
  end
end

P.CLI.main(System.argv())

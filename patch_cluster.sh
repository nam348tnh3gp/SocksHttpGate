#!/data/data/com.termux/files/usr/bin/bash
set -u
FILE=proxy.js
[ ! -f "$FILE" ] && { echo "Không thấy $FILE"; exit 1; }

# Backup
cp "$FILE" "$FILE.bak.$(date +%Y%m%d_%H%M%S)"
echo "[*] Backup: $(ls -t ${FILE}.bak.* | head -1)"

# 1) Thêm require cluster + state ngay sau 'use strict';
if ! grep -q "REQUIRE_CLUSTER_INJECTED" "$FILE"; then
  sed -i "1a\\
// REQUIRECLUSTERINJECTED_ANCHOR
" "$FILE"
  # Đặt require cluster sau khối use strict
  awk '
    /^'use strict';$/ && !done {
      print
      print "const cluster = require(\"cluster\");"
      print "const IS_CLUSTER_MODE = !!process.env.CLUSTER_MODE;"
      print "const IS_WORKER = IS_CLUSTER_MODE && cluster.isWorker;"
      print "const IS_DASHBOARD_LEADER = !IS_CLUSTER_MODE || !cluster.isWorker || cluster.worker.id === 1;"
      print "const peerStats = new Map(); // workerId -> stats (chỉ dashboard leader dùng)"
      print "// REQUIRECLUSTERINJECTED"
      done = 1
      next
    }
    { print }
  ' "$FILE" > "$FILE.tmp" && mv "$FILE.tmp" "$FILE"
  echo "[+] Đã inject require cluster"
else
  echo "[=] require cluster đã có, bỏ qua"
fi

# 2) Skip dashboard listener ở worker không phải leader
#    Tìm dòng "dashServer.listen" và wrap với điều kiện
if ! grep -q "IS_DASHBOARD_LEADER" "$FILE" || ! grep -q "if (IS_DASHBOARD_LEADER) {" "$FILE"; then
  # Chuyển cả block dashServer thành conditional
  awk '
    /^    const dashServer = http\.createServer/ && !done {
      print "    if (IS_DASHBOARD_LEADER) {"
      print
      done = 1
      next
    }
    /^    setupSignals\(proxyServer, dashServer\);$/ && done2 == 0 {
      print "    setupSignals(proxyServer, dashServer);"
      print "    } else {"
      print "      setupSignals(proxyServer);"
      print "    }"
      done2 = 1
      next
    }
    { print }
  ' "$FILE" > "$FILE.tmp" && mv "$FILE.tmp" "$FILE"
  echo "[+] Đã wrap dashboard listener"
fi

# 3) Thêm IPC handler ở cuối main()
#    Tìm dòng "if (!authRequired()) logWarn" (gần cuối main) và thêm trước
if ! grep -q "IS_WORKER.*process.send\|process.send.*IS_WORKER" "$FILE"; then
  cat > .insert_ipc.txt <<'EOF'

  // ============ CLUSTER IPC (chỉ khi chạy cluster mode) ============
  if (IS_WORKER) {
    if (IS_DASHBOARD_LEADER) {
      // Nhận stats từ các worker khác (qua master forward)
      process.on('message', (msg) => {
        if (!msg) return;
        if (msg.type === 'peer_stats') {
          peerStats.set(msg.workerId, { payload: msg.payload, t: Date.now() });
        } else if (msg.type === 'kick') {
          const ci = activeConns.get(msg.id);
          if (ci) { try { ci.socket.destroy(); } catch {} }
        } else if (msg.type === 'reload') {
          try { reloadConfig('master'); } catch {}
        }
      });
    } else {
      // Worker phụ: gửi stats định kỳ + nhận lệnh
      process.on('message', (msg) => {
        if (!msg) return;
        if (msg.type === 'kick') {
          const ci = activeConns.get(msg.id);
          if (ci) { try { ci.socket.destroy(); } catch {} }
        } else if (msg.type === 'reload') {
          try { reloadConfig('master'); } catch {}
        }
      });
      setInterval(() => {
        if (!process.send) return;
        try {
          const conns = [];
          for (const ci of activeConns.values()) {
            conns.push({
              id: ci.id, ip: ci.ip, port: ci.port, type: ci.type, target: ci.target,
              user: ci.username,
              start_time: Math.floor(ci.startTime / 1000),
              bytes_up: ci.bytesUp, bytes_down: ci.bytesDown,
              duration: (Date.now() - ci.startTime) / 1000,
            });
          }
          process.send({
            type: 'stats',
            payload: {
              total: stats.total, current: stats.current,
              socks5TCP: stats.socks5TCP, socks5UDP: stats.socks5UDP,
              http: stats.http, authFail: stats.authFail,
              bytesUp: stats.bytesUp, bytesDown: stats.bytesDown,
              udpUp: stats.udpUp, udpDown: stats.udpDown,
              udpAssocs: udpAssocs.size,
              active_connections: conns,
              uptime: (Date.now() - stats.startTime) / 1000,
            },
          });
        } catch {}
      }, 1000);
    }
  }
EOF

  # Chèn block IPC vào trước dòng "logInfo(`Gửi SIGHUP" trong main
  awk '
    /logInfo\(`Gửi SIGHUP/ && !done {
      while ((getline line < ".insert_ipc.txt") > 0) print line
      close(".insert_ipc.txt")
      done = 1
    }
    { print }
  ' "$FILE" > "$FILE.tmp" && mv "$FILE.tmp" "$FILE"
  rm -f .insert_ipc.txt
  echo "[+] Đã inject IPC handlers"
fi

# 4) Patch getAllStats() để merge peerStats nếu là dashboard leader
if ! grep -q "MERGE_PEER_STATS" "$FILE"; then
  awk '
    /^function getAllStats\(\) \{/ {
      print "function getAllStats() {"
      print "  // MERGE_PEER_STATS"
      print "  const localStats = getAllStatsLocal();"
      print "  if (IS_DASHBOARD_LEADER && peerStats.size > 0) {"
      print "    for (const [wId, entry] of peerStats) {"
      print "      if (Date.now() - entry.t > 5000) continue;"
      print "      const p = entry.payload;"
      print "      localStats.total += p.total || 0;"
      print "      localStats.current += p.current || 0;"
      print "      localStats.active = (localStats.active || 0) + (p.current || 0);"
      print "      localStats.socks5_tcp += p.socks5TCP || 0;"
      print "      localStats.socks5_udp += p.socks5UDP || 0;"
      print "      localStats.http += p.http || 0;"
      print "      localStats.auth_fail += p.authFail || 0;"
      print "      localStats.bytes_up += p.bytesUp || 0;"
      print "      localStats.bytes_down += p.bytesDown || 0;"
      print "      localStats.udp_up += p.udpUp || 0;"
      print "      localStats.udp_down += p.udpDown || 0;"
      print "      localStats.udp_assocs += p.udpAssocs || 0;"
      print "      if (p.active_connections) {"
      print "        localStats.active_connections = localStats.active_connections.concat(p.active_connections);"
      print "      }"
      print "    }"
      print "  }"
      print "  return localStats;"
      print "}"
      # Đổi tên function getAllStats cũ thành getAllStatsLocal
      print "function getAllStatsLocal() {"
      next
    }
    { print }
  ' "$FILE" > "$FILE.tmp" && mv "$FILE.tmp" "$FILE"
  echo "[+] Đã patch getAllStats → merge peer stats"
fi

# Verify
echo ""
echo "=== Verify ==="
for pat in "REQUIRECLUSTERINJECTED" "IS_DASHBOARD_LEADER" "IS_WORKER" "peerStats" "MERGE_PEER_STATS" "getAllStatsLocal"; do
  printf "%-30s %s\n" "$pat:" "$(grep -c "$pat" "$FILE")"
done
echo ""
echo "=== Node syntax check ==="
if node --check "$FILE" 2>&1; then
  echo "✓ OK"
else
  echo "✗ Syntax lỗi — restore: cp $(ls -t ${FILE}.bak.* | head -1) $FILE"
  exit 1
fi

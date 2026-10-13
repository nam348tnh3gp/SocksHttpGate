#!/usr/bin/env node
'use strict';
// Master entry point — spawn N worker chạy proxy.js, forward stats giữa workers.

const cluster = require('cluster');
const os = require('os');

if (cluster.isPrimary) {
  const workers = parseInt(process.env.WORKERS, 10) || Math.max(2, os.cpus().length - 1);
  console.log(`[MASTER] pid=${process.pid} spawning ${workers} workers (${os.cpus().length} CPU)`);

  // Truyền env xuống workers
  process.env.CLUSTER_MODE = '1';

  for (let i = 0; i < workers; i++) cluster.fork({ ...process.env, CLUSTER_MODE: '1', ARGV: JSON.stringify(process.argv.slice(2)) });

  // Respawn worker nếu crash
  cluster.on('exit', (worker, code, signal) => {
    if (!worker.exitedAfterDisconnect && code !== 0) {
      console.log(`[MASTER] worker ${worker.id} died (code=${code} sig=${signal}), respawning`);
      cluster.fork();
    }
  });

  // Forward stats từ worker phụ (id != 1) tới worker 1
  cluster.on('message', (worker, msg) => {
    if (!msg || !msg.type) return;
    if (msg.type === 'stats' && worker.id !== 1) {
      const leader = cluster.workers[1];
      if (leader && leader.isConnected()) {
        try { leader.send({ type: 'peer_stats', workerId: worker.id, payload: msg.payload }); }
        catch {}
      }
    }
  });

  // Signal: shutdown toàn bộ
  const shutdown = (sig) => {
    console.log(`[MASTER] ${sig} → graceful shutdown`);
    for (const id of Object.keys(cluster.workers)) {
      try { cluster.workers[id].kill('SIGTERM'); } catch {}
    }
    setTimeout(() => process.exit(0), 1000);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGHUP', () => {
    console.log('[MASTER] SIGHUP → broadcast reload');
    for (const id of Object.keys(cluster.workers)) {
      try { cluster.workers[id].send({ type: 'reload' }); } catch {}
    }
  });
} else {
  // Worker: chạy proxy.js bình thường
  require('./proxy.js');
}

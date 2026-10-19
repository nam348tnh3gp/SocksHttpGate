#!/data/data/com.termux/files/usr/bin/bash
# Script cập nhật IP cho DuckDNS
DOMAIN="odohtermux"
TOKEN="0f3b0e0e-6617-4304-a957-87ffbb426454"
LOG="$HOME/duckdns.log"

# Gửi yêu cầu cập nhật, để DuckDNS tự phát hiện IP công cộng
response=$(curl -sS "https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=127.0.0.1")
echo "$(date '+%Y-%m-%d %H:%M:%S') - $response" >> "$LOG"

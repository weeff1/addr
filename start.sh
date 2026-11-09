#!/data/data/com.termux/files/usr/bin/bash
# 聊天站 · 一键启动（保活版）
# 目标：让这条隧道活得尽量久，地址尽量不换
# 用法：bash ~/start.sh

set -u
CHAT_DIR="$HOME/chat"
PORT=3000
ADDR_REPO="weeff1/addr"
LOG="$HOME/tunnel.log"
TOKEN_FILE="$HOME/.gh_token"

cd "$CHAT_DIR" || { echo "[!] 找不到 ~/chat 目录"; exit 1; }

# 防止手机锁屏后系统把网络掐了
termux-wake-lock 2>/dev/null

echo "[*] 检查聊天站服务…"
if curl -s -m 2 "http://127.0.0.1:$PORT/api/health" | grep -q '"ok":true'; then
  echo "[*] 服务已在运行"
else
  echo "[*] 启动服务…"
  nohup node server.js > chat.log 2>&1 &
  for i in $(seq 1 20); do
    curl -s -m 2 "http://127.0.0.1:$PORT/api/health" | grep -q '"ok":true' && break
    sleep 0.5
  done
fi

# 把当前隧道地址写进 GitHub 中转文件，入口页读它
update_addr() {
  local url="$1"
  [ -f "$TOKEN_FILE" ] || { echo "[!] 没有 ~/.gh_token，跳过中转更新"; return; }
  local token
  token=$(tr -d '\r\n' < "$TOKEN_FILE")
  local raw
  raw=$(curl -s -m 15 -H "Authorization: token $token" \
        "https://api.github.com/repos/$ADDR_REPO/contents/README.md")
  local sha
  sha=$(printf '%s' "$raw" | grep -o '"sha":[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
  local b64
  b64=$(printf '%s' "$url" | base64 | tr -d '\r\n')
  local body
  body=$(printf '{"message":"auto update","content":"%s"%s}' \
          "$b64" "${sha:+,\"sha\":\"$sha\"}")
  local code
  code=$(curl -s -m 20 -o /dev/null -w '%{http_code}' -X PUT \
        -H "Authorization: token $token" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "https://api.github.com/repos/$ADDR_REPO/contents/README.md")
  echo "中转文件更新: $code"
}

echo "[*] 正在建立隧道（带保活参数）…"

while true; do
  : > "$LOG"
  # 关键：ServerAliveInterval 让它每 10 秒互相打个招呼，
  # 手机 NAT / 运营商不会以为这条连接死了把它掐掉
  ssh -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=10 \
      -o ServerAliveCountMax=3 \
      -o TCPKeepAlive=yes \
      -o ExitOnForwardFailure=yes \
      -o ConnectTimeout=15 \
      -R 80:localhost:$PORT \
      nokey@localhost.run > "$LOG" 2>&1 &
  SSH_PID=$!

  URL=""
  for i in $(seq 1 40); do
    URL=$(grep -o 'https://[a-z0-9]*\.lhr\.life' "$LOG" 2>/dev/null | head -1)
    [ -n "$URL" ] && break
    kill -0 "$SSH_PID" 2>/dev/null || break
    sleep 1
  done

  HB_PID=""
  if [ -n "$URL" ]; then
    echo "[+] 隧道地址: $URL"
    update_addr "$URL"
    # 反向心跳：每 60 秒从本机访问一次自己的公网地址，
    # 让隧道里一直有数据流动，服务端不会按"空闲"把你踢下去
    (
      while kill -0 "$SSH_PID" 2>/dev/null; do
        curl -s -m 10 -o /dev/null "$URL/api/health"
        sleep 60
      done
    ) &
    HB_PID=$!
    echo "[*] 保活已开：每 60 秒自动心跳一次"
    echo "[*] 现在可以把这个地址发给朋友： $URL"
  else
    echo "[!] 隧道没连上，看看 ~/tunnel.log"
  fi

  wait "$SSH_PID"
  [ -n "$HB_PID" ] && kill "$HB_PID" 2>/dev/null
  echo "[!] 隧道断开，5 秒后自动重连…"
  sleep 5
done

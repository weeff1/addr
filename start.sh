#!/data/data/com.termux/files/usr/bin/bash
# 聊天站：一键启动 + 隧道自动重连 + 自动更新中转地址
REPO="weeff1/addr"
TOKEN_FILE="$HOME/.gh_token"
URL_FILE="$HOME/current_url.txt"

start_server() {
  if curl -s --max-time 3 http://127.0.0.1:3000/api/health >/dev/null 2>&1; then
    echo "[*] 服务在跑"
  else
    echo "[*] 启动服务..."
    cd "$HOME/chat" || exit 1
    nohup node server.js >> chat.log 2>&1 &
    sleep 3
  fi
}

update_readme() {
  local url="$1"
  [ -f "$TOKEN_FILE" ] || { echo "[!] 缺少令牌文件 $TOKEN_FILE"; return 1; }
  local tk; tk=$(tr -d '\n\r ' < "$TOKEN_FILE")
  local sha
  sha=$(curl -s -H "Authorization: token $tk" "https://api.github.com/repos/$REPO/contents/README.md" \
        | tr ',' '\n' | grep '"sha"' | head -1 | cut -d'"' -f4)
  local content; content=$(printf '%s' "$url" | base64 -w0)
  curl -s -o /dev/null -w "  README 更新: %{http_code}\n" -X PUT \
    -H "Authorization: token $tk" -H "Content-Type: application/json" \
    "https://api.github.com/repos/$REPO/contents/README.md" \
    -d "{\"message\":\"auto update tunnel\",\"content\":\"$content\",\"sha\":\"$sha\"}"
}

while true; do
  start_server
  TMP=$(mktemp)
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ServerAliveInterval=20 -o ServerAliveCountMax=2 -o ExitOnForwardFailure=yes \
      -R 80:localhost:3000 nokey@localhost.run > "$TMP" 2>&1 &
  PID=$!
  URL=""
  for i in $(seq 1 40); do
    sleep 2
    URL=$(grep -oE 'https://[a-z0-9]+\.lhr\.life' "$TMP" | head -1)
    [ -n "$URL" ] && break
  done
  if [ -n "$URL" ]; then
    echo "$URL" > "$URL_FILE"
    echo "[+] 隧道地址: $URL"
    update_readme "$URL"
  else
    echo "[!] 没拿到地址，重试..."
  fi
  wait $PID 2>/dev/null
  echo "[!] 隧道断开，5 秒后自动重连..."
  sleep 5
done

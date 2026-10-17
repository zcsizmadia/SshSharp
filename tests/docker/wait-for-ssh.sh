#!/usr/bin/env bash
# Waits (at most 30 s) until an SSH server on 127.0.0.1:PORT sends its identification line, and prints it. The same connection that
# answers gives the banner, so a server that is still starting cannot pass the wait and then fail a second read.
# Usage: wait-for-ssh.sh PORT
set -uo pipefail
port="$1"
for _ in $(seq 1 30); do
  banner="$(timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port && head -n 1 <&3" 2>/dev/null | tr -d '\r')"
  if [[ "$banner" == SSH-* ]]; then
    echo "$banner"
    exit 0
  fi
  sleep 1
done
echo "no SSH banner on 127.0.0.1:$port after 30 s" >&2
exit 1

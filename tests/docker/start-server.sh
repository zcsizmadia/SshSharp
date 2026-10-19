#!/usr/bin/env bash
# Starts a test server container (tests/docker/Dockerfile) on 127.0.0.1:2200 with a random password for the account sshsharp, and
# writes the SSHSHARP_TEST_* settings for the interop tests to $GITHUB_ENV. Used by the CI and Stress workflows.
# Usage: start-server.sh IMAGE SERVER SOFTWARE STRICTKEX [INNER_PORT]
#   SERVER: openssh, dropbear, asyncssh, mina or erlang (the Dockerfile's SERVER argument)
#   SOFTWARE: the name in the server's identification line, for SSHSHARP_TEST_SERVER
#   STRICTKEX: 1 when the server supports strict key exchange, else 0
#   INNER_PORT: the port inside the container (22 by default; the servers that run as the test account use 2222)
set -euo pipefail
image="$1" server="$2" software="$3" strict="$4" inner_port="${5:-22}"
here="$(cd "$(dirname "$0")" && pwd)"

password="$(openssl rand -hex 16)"
echo "::add-mask::$password"
docker build -q -t sshsharp-interop --build-arg BASE="$image" --build-arg SERVER="$server" "$here"
docker run -d --name server -p "127.0.0.1:2200:$inner_port" -e TEST_PASSWORD="$password" sshsharp-interop
banner="$("$here/wait-for-ssh.sh" 2200)" || { echo "::error::the server does not answer"; docker logs server || true; exit 1; }
echo "Server: $banner"
echo "Server: \`$banner\`" >> "$GITHUB_STEP_SUMMARY"
{
  echo "SSHSHARP_TEST_SSHD=127.0.0.1:2200"
  echo "SSHSHARP_TEST_SSHD_INNER_PORT=$inner_port"
  echo "SSHSHARP_TEST_USER=sshsharp"
  echo "SSHSHARP_TEST_PASSWORD=$password"
  echo "SSHSHARP_TEST_SERVER=$software"
  echo "SSHSHARP_TEST_SERVER_STRICTKEX=$strict"
} >> "$GITHUB_ENV"

case "$server" in
  # OpenSSH (RekeyLimit) and AsyncSSH (rekey_bytes) re-key every 32 KiB. MINA keeps its default limit (see MinaServer.java).
  openssh|asyncssh) echo "SSHSHARP_TEST_SSHD_REKEY=1" >> "$GITHUB_ENV" ;;
  # Dropbear serves the sftp subsystem by running OpenSSH's sftp-server from /usr/libexec (the image links it there). A missing
  # binary fails the job: the SFTP tests would otherwise skip themselves and the job would pass without them.
  dropbear)
    if ! docker exec server test -x /usr/libexec/sftp-server; then
      echo "::error::the Dropbear image has no /usr/libexec/sftp-server"
      exit 1
    fi
    echo "SSHSHARP_TEST_DROPBEAR_SFTP=1" >> "$GITHUB_ENV"
    ;;
esac

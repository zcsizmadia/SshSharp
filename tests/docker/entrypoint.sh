#!/bin/sh
# Sets the throwaway account's password from TEST_PASSWORD, then runs the server in the foreground with logs on stderr.
set -e
echo "sshsharp:$TEST_PASSWORD" | chpasswd
if command -v dropbear > /dev/null 2>&1; then
  mkdir -p /etc/dropbear
  exec dropbear -F -E -R -p 22
fi
# AsyncSSH runs as the test account, so it listens on an unprivileged port (2222); it checks the password itself.
if [ "$SSH_SERVER" = "asyncssh" ]; then
  cd /home/sshsharp
  exec su-exec sshsharp env HOME=/home/sshsharp USER=sshsharp PORT=2222 python3 /asyncssh_server.py
fi
ssh-keygen -A
# sshd takes the first value of each keyword, and Alpine's default file turns forwarding off: drop those lines before appending. Its
# Subsystem line names an sftp-server binary that may not be installed, and a second definition would be fatal: use internal-sftp.
sed -i '/^AllowTcpForwarding/d;/^AllowStreamLocalForwarding/d;/^Subsystem/d' /etc/ssh/sshd_config
cat >> /etc/ssh/sshd_config <<CONFIG
PasswordAuthentication yes
MaxStartups 200:30:300
MaxSessions 64
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
Subsystem sftp internal-sftp
RekeyLimit ${REKEY_LIMIT:-32K}
KexAlgorithms +diffie-hellman-group14-sha256,diffie-hellman-group16-sha512
LogLevel DEBUG1
CONFIG
# OpenSSH 9.8+ shuts out an address after failed or unauthenticated connections, which the tests make on purpose.
if /usr/sbin/sshd -T 2>/dev/null | grep -qi '^persourcepenalties '; then
  echo "PerSourcePenalties no" >> /etc/ssh/sshd_config
fi
exec /usr/sbin/sshd -D -e

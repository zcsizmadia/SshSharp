#!/bin/sh
# Sets the throwaway account's password from TEST_PASSWORD, then runs the server in the foreground with logs on stderr.
set -e
echo "sshsharp:$TEST_PASSWORD" | chpasswd
if command -v dropbear > /dev/null 2>&1; then
  mkdir -p /etc/dropbear
  exec dropbear -F -E -R -p 22
fi
ssh-keygen -A
# sshd takes the first value of each keyword, and Alpine's default file turns forwarding off: drop those lines before appending.
sed -i '/^AllowTcpForwarding/d;/^AllowStreamLocalForwarding/d' /etc/ssh/sshd_config
cat >> /etc/ssh/sshd_config <<CONFIG
PasswordAuthentication yes
MaxStartups 200:30:300
MaxSessions 64
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
RekeyLimit 32K
KexAlgorithms +diffie-hellman-group14-sha256,diffie-hellman-group16-sha512
LogLevel DEBUG1
CONFIG
# OpenSSH 9.8+ shuts out an address after failed or unauthenticated connections, which the tests make on purpose.
if /usr/sbin/sshd -T 2>/dev/null | grep -qi '^persourcepenalties '; then
  echo "PerSourcePenalties no" >> /etc/ssh/sshd_config
fi
exec /usr/sbin/sshd -D -e

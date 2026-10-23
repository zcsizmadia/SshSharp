#!/bin/sh
# ProFTPD's mod_sftp as an SFTP-only server for the interop tests, run inside a pinned Alpine image by the CI workflow (interop-sftp):
# the account tester with the password in TEST_PASSWORD (generated per run), chrooted to its home, on port 2222. mod_sftp announces
# check-file, so the file hash test runs against it. Its log goes to /var/log/proftpd/sftp.log, which the workflow prints on failure.
set -eu
apk add -q proftpd proftpd-mod_sftp openssh-keygen > /dev/null
proftpd --version

adduser -D -s /sbin/nologin tester
printf 'tester:%s\n' "$TEST_PASSWORD" | chpasswd > /dev/null
unset TEST_PASSWORD

mkdir -p /etc/proftpd/keys /run/proftpd /var/log/proftpd
ssh-keygen -q -t rsa -b 3072 -N '' -m PEM -f /etc/proftpd/keys/rsa
ssh-keygen -q -t ecdsa -b 256 -N '' -m PEM -f /etc/proftpd/keys/ecdsa

cat > /etc/proftpd/proftpd.conf <<'EOF'
ModulePath /usr/lib/proftpd
LoadModule mod_sftp.c
ServerName "sftp"
ServerType standalone
DefaultServer on
Port 2222
UseIPv6 off
User proftpd
Group proftpd
Umask 022
AllowOverwrite on
MaxInstances 100
RequireValidShell off
DefaultRoot ~
WtmpLog off
SFTPEngine on
SFTPLog /var/log/proftpd/sftp.log
SFTPHostKey /etc/proftpd/keys/rsa
SFTPHostKey /etc/proftpd/keys/ecdsa
SFTPAuthMethods password
SFTPExtensions +checkFile
EOF

exec proftpd --nodaemon -c /etc/proftpd/proftpd.conf

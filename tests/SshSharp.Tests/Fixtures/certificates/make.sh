#!/bin/sh
# How the certificate fixtures here were made, with OpenSSH 10.6's ssh-keygen (SshCertificateVerifyTests reads them). Only public keys
# and certificates are kept; the private keys are throwaway and deleted. Run it in an empty directory to make a new set (the tests
# then need their fingerprints and fields updated).
set -eu
ssh-keygen -q -t ed25519 -N '' -C ca-ed25519 -f ca_ed25519
ssh-keygen -q -t ecdsa -b 384 -N '' -C ca-ecdsa -f ca_ecdsa
ssh-keygen -q -t rsa -b 3072 -N '' -C ca-rsa -f ca_rsa
ssh-keygen -q -t rsa -b 1024 -N '' -C ca-rsa1024 -f ca_rsa1024
ssh-keygen -q -t ed25519 -N '' -C other-ca -f other_ca
ssh-keygen -q -t ed25519 -N '' -C user-ed25519 -f user_ed25519
ssh-keygen -q -t ecdsa -b 256 -N '' -C host-ecdsa -f host_ecdsa
ssh-keygen -q -t rsa -b 2048 -N '' -C user-rsa -f user_rsa
ssh-keygen -q -t ecdsa -b 521 -N '' -C user-ecdsa521 -f user_ecdsa521
cp user_ed25519.pub weak_sha1.pub
cp user_ed25519.pub weak_rsa1024.pub
ssh-keygen -q -s ca_ed25519 -I deploy-ci -z 1001 -n deploy,ci -V 20260101000000Z:20990101000000Z \
  -O force-command=/usr/bin/true -O source-address=192.0.2.0/24 user_ed25519.pub
ssh-keygen -q -s ca_rsa -I web-1 -h -z 1002 -n 'web1.example.com,*.example.com' -V 20260101000000Z:forever host_ecdsa.pub
ssh-keygen -q -s ca_ecdsa -I expired -z 1003 -n deploy -V 20200101000000Z:20210101000000Z user_rsa.pub
ssh-keygen -q -s ca_rsa -t rsa-sha2-256 -I sha256 -z 1004 -n deploy -V always:forever user_ecdsa521.pub
# Refused by SshSharp: a SHA-1 (ssh-rsa) signature, and a 1024-bit RSA authority.
ssh-keygen -q -s ca_rsa -t ssh-rsa -I sha1 -z 1005 -n deploy weak_sha1.pub
ssh-keygen -q -s ca_rsa1024 -I rsa1024 -z 1006 -n deploy weak_rsa1024.pub
rm ca_ed25519 ca_ecdsa ca_rsa ca_rsa1024 other_ca user_ed25519 host_ecdsa user_rsa user_ecdsa521 \
  user_ed25519.pub host_ecdsa.pub user_rsa.pub user_ecdsa521.pub weak_sha1.pub weak_rsa1024.pub

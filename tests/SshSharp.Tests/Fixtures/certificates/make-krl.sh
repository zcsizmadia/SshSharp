#!/bin/sh
# How the KRL and vendor-extension fixtures here were made, with OpenSSH 10.5's ssh-keygen (SshKeyRevocationListTests and
# SshCertificateVerifyTests read them). Only public keys, certificates and the KRL are kept; the private keys are throwaway and deleted.
# Run it in an empty directory to make a new set (the tests then need their fields updated).
set -eu
ssh-keygen -q -t ed25519 -N '' -C krl-ca -f krl_ca
ssh-keygen -q -t ed25519 -N '' -C revoked-serial -f revoked_serial
ssh-keygen -q -t ed25519 -N '' -C revoked-id -f revoked_id
ssh-keygen -q -t ed25519 -N '' -C revoked-key -f revoked_key
ssh-keygen -q -t ecdsa -b 256 -N '' -C revoked-hash -f revoked_hash
ssh-keygen -q -t ed25519 -N '' -C not-revoked -f not_revoked

# Certificates from krl_ca: one revoked by serial, one by key id, one whose key is revoked, and one that is not revoked. The last also
# carries a vendor extension with a value (SshCertificate.ExtensionValues).
ssh-keygen -q -s krl_ca -I serial-1001 -z 1001 -n deploy revoked_serial.pub
ssh-keygen -q -s krl_ca -I revoked-id -z 20 -n deploy revoked_id.pub
ssh-keygen -q -s krl_ca -I key-revoked -z 21 -n deploy revoked_key.pub
ssh-keygen -q -s krl_ca -I fine -z 22 -n deploy -O extension:login@example.com=deploy not_revoked.pub

# The KRL: serials 1000-1005 and the key id revoked-id for krl_ca only, the key revoked_key explicitly, and revoked_hash by its SHA-256
# fingerprint.
printf 'serial: 1000-1005\nid: revoked-id\n' > certs.spec
printf 'hash: %s\n' "$(ssh-keygen -l -E sha256 -f revoked_hash.pub | cut -d' ' -f2)" > keys.spec
ssh-keygen -k -f users.krl -s krl_ca.pub certs.spec
ssh-keygen -k -u -f users.krl revoked_key.pub keys.spec

rm krl_ca revoked_serial revoked_id revoked_key revoked_hash not_revoked revoked_serial.pub revoked_id.pub not_revoked.pub \
  certs.spec keys.spec

#!/bin/sh
# How the FIDO security-key certificate fixtures here were made, with OpenSSH 10.5's ssh-keygen (SshKeyRevocationListTests reads them).
# No security key is needed: a certificate is signed over the public key only, so the sk public keys are built from throwaway software
# keys (the Ed25519 key or the P-256 point, then the application string "ssh:", as PROTOCOL.u2f lays them out). Only the sk public keys
# and their certificates are kept. Run it in an empty directory to make a new set.
set -eu

# Writes an SSH string (uint32 length, then the bytes) for the bytes on stdin.
sshstring() {
  f=$(mktemp)
  cat > "$f"
  printf '%08x' "$(wc -c < "$f")" | xxd -r -p
  cat "$f"
  rm -f "$f"
}

# The fields after the key type in a public key line's blob ($2 is the length of the type name).
fields() { cut -d' ' -f2 "$1" | base64 -d | tail -c +$((4 + $2 + 1)); }

ssh-keygen -q -t ed25519 -N '' -C sk-ca -f sk_ca
ssh-keygen -q -t ed25519 -N '' -f soft_ed25519
ssh-keygen -q -t ecdsa -b 256 -N '' -f soft_ecdsa

# sk-ssh-ed25519@openssh.com: the 32-byte key (the ssh-ed25519 blob's last field), then the application.
{ printf 'sk-ssh-ed25519@openssh.com' | sshstring; fields soft_ed25519.pub 11; printf 'ssh:' | sshstring; } > sk_ed25519.blob
printf 'sk-ssh-ed25519@openssh.com %s revoked-sk-ed25519\n' "$(base64 -w0 sk_ed25519.blob)" > sk_ed25519.pub

# sk-ecdsa-sha2-nistp256@openssh.com: the curve name and point (the ecdsa-sha2-nistp256 blob's fields), then the application.
{ printf 'sk-ecdsa-sha2-nistp256@openssh.com' | sshstring; fields soft_ecdsa.pub 19; printf 'ssh:' | sshstring; } > sk_ecdsa.blob
printf 'sk-ecdsa-sha2-nistp256@openssh.com %s revoked-sk-ecdsa\n' "$(base64 -w0 sk_ecdsa.blob)" > sk_ecdsa.pub

ssh-keygen -q -s sk_ca -I sk-ed25519 -z 30 -n deploy sk_ed25519.pub
ssh-keygen -q -s sk_ca -I sk-ecdsa -z 31 -n deploy sk_ecdsa.pub

# ssh-keygen reads the certificates back (the certified keys are well formed). In a text RevokedKeys file sshd compares each line's key
# with the plain key (sshkey_in_file), so a certificate line revokes the key it certifies.
ssh-keygen -L -f sk_ed25519-cert.pub > /dev/null
ssh-keygen -L -f sk_ecdsa-cert.pub > /dev/null

rm -f sk_ca sk_ca.pub soft_ed25519 soft_ed25519.pub soft_ecdsa soft_ecdsa.pub sk_ed25519.blob sk_ecdsa.blob

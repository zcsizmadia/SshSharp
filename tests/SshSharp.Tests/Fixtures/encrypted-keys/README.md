# Encrypted OpenSSH private keys

Test keys made by OpenSSH's `ssh-keygen` (OpenSSH_for_Windows_9.5p2), one per cipher it can encrypt a key file with:

```
ssh-keygen -t ed25519 -N "fixture passphrase" -Z <cipher> -C "sshsharp-fixture-<cipher>" -f ed25519-<cipher>
```

The passphrase is `fixture passphrase`. They are throwaway keys for tests only; nothing trusts them.

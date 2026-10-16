# Project Wycheproof test vectors

Copied unchanged from https://github.com/C2SP/wycheproof at commit `3fa63dd0344abb611f1fb1d77e119938603ea230` (2026-09-02),
directory `testvectors_v1`. Licensed under the Apache License 2.0 (`LICENSE` in this folder).

Used by `Crypto/WycheproofTests.cs` (#218). Only the files for what SshSharp does are here: X25519, Ed25519, ChaCha20-Poly1305,
ECDH and ECDSA on P-256/384/521, RSA PKCS#1 v1.5 signatures (verifying and signing), AES-GCM, ML-KEM-768/1024 and HMAC-SHA-256/512.

## Checking for updates

Wycheproof keeps adding vectors as new implementation bugs are found. Check it from time to time, and before each release:

1. Look at the commits to `testvectors_v1` since the commit above:
   https://github.com/C2SP/wycheproof/commits/main/testvectors_v1
2. Download the same files from the newest commit, for example:
   ```sh
   commit=<new commit>
   for f in *.json; do curl -sfL -o "$f" "https://raw.githubusercontent.com/C2SP/wycheproof/$commit/testvectors_v1/$f"; done
   ```
3. Look for new files that cover something SshSharp does (a new curve, key size or algorithm SshSharp supports) and add them, with a
   test in `WycheproofTests.cs`.
4. Run the tests on every platform (a vector that fails on one platform only is how the macOS RSA bug was found, #222), then
   change the commit and date above.

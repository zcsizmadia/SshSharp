#!/usr/bin/env python3
"""Judges what SshSharp offers, from the JSON report of `ssh-audit -c -j` (the ssh-audit job in CI, #218).

ssh-audit rates every key exchange, host key, cipher and MAC that the client offers. This fails on:
- a [fail] or [warn] rating that is not in ACCEPTED below, where each entry says why SshSharp keeps the algorithm;
- any CVE ssh-audit lists for the client;
- a missing strict key exchange marker (the Terrapin countermeasure);
- with --post-quantum-first, a first key exchange that is not a post-quantum hybrid;
- with --fips, an algorithm FIPS mode must not offer (Curve25519 and Ed25519, ChaCha20-Poly1305, sntrup761).

A new weak algorithm, or a rating ssh-audit adds in a later version, then fails the job until it is fixed or added to ACCEPTED with
its reason. Exact algorithm lists are not compared: they depend on the platform (the ML-KEM hybrids need a platform with ML-KEM).

Prints a Markdown table of everything offered, for the job summary, and the problems on stderr.

    check_client_audit.py <report.json> <label> [--post-quantum-first] [--fips]
"""

import json
import sys

ACCEPTED = {
    # ssh-audit's opinion of the NIST curves (ECDH, ECDSA and the ML-KEM/NIST hybrids). OpenSSH 10's client offers them by
    # default, and FIPS mode needs them.
    "using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency",
    # The classical key exchanges, offered after the post-quantum hybrids as fallbacks, as OpenSSH's client does.
    "does not provide protection against post-quantum attacks",
    # diffie-hellman-group14-sha256, offered last, as OpenSSH's client does (#99).
    "2048-bit modulus only provides 112-bits of symmetric strength",
    # ECDSA host keys: a warning about how a server made its key, not about the client that accepts the algorithm.
    "using weak random number generator could reveal the key",
    # hmac-sha2-256 and hmac-sha2-512 (#268), offered after the encrypt-then-MAC variants, as OpenSSH's client does, for servers
    # (often network equipment) that offer nothing else with aes*-ctr. A server offering both always gets encrypt-then-MAC.
    "using encrypt-and-MAC mode",
}

SECTIONS = (("kex", "key exchange"), ("key", "host key"), ("enc", "cipher"), ("mac", "MAC"))
POST_QUANTUM = ("mlkem", "sntrup761")
STRICT_KEX = "kex-strict-c-v00@openssh.com"
NOT_FIPS = ("25519", "chacha20", "sntrup761")


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2

    path, label = argv[1], argv[2]
    post_quantum_first = "--post-quantum-first" in argv[3:]
    fips = "--fips" in argv[3:]
    with open(path, encoding="utf-8") as f:
        report = json.load(f)

    problems = []
    rows = []
    for section, kind in SECTIONS:
        for entry in report.get(section, []):
            name = entry["algorithm"]
            notes = entry.get("notes", {})
            ratings = [(level, text) for level in ("fail", "warn") for text in notes.get(level, [])]
            if fips and any(part in name for part in NOT_FIPS):
                problems.append(f"{kind} {name} is offered in FIPS mode")

            for level, text in ratings:
                if text not in ACCEPTED:
                    problems.append(f"{kind} {name}: [{level}] {text}")

            shown = "; ".join(f"[{level}] {text}" for level, text in ratings) or "ok"
            rows.append(f"| {kind} | `{name}` | {shown} |")

    for cve in report.get("cves", []):
        problems.append(f"CVE: {cve.get('name', cve)}")

    kex = [entry["algorithm"] for entry in report.get("kex", [])]
    if STRICT_KEX not in kex:
        problems.append(f"the strict key exchange marker {STRICT_KEX} is not offered")

    if post_quantum_first and (not kex or not kex[0].startswith(POST_QUANTUM)):
        problems.append(f"the first key exchange is {kex[0] if kex else 'missing'}, not a post-quantum hybrid")

    print(f"### ssh-audit: {label} ({report.get('banner', {}).get('raw', '')})")
    print()
    print("| | Algorithm | ssh-audit |")
    print("|---|---|---|")
    print("\n".join(rows))
    print()
    print(f"**{len(problems)} problem(s).**" if problems else "**No problems** (accepted ratings are explained in tests/ssh-audit/check_client_audit.py).")
    print()

    for problem in problems:
        print(f"{label}: {problem}", file=sys.stderr)

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

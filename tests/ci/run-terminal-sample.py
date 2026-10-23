#!/usr/bin/env python3
"""Runs the terminal sample (samples/SshSharp.Samples.Terminal) in a pseudo-terminal, as a person at a keyboard would.

It waits for the remote shell's prompt, types a command whose output differs from what was typed (so the output must have come back
from the server, not from the local echo), then types `exit 7`, and checks that the sample ended with the shell's exit status 7.

Usage: run-terminal-sample.py <sample executable> <destination>

The destination connects through ssh_config as `ssh` would: the agent's keys, and the server's host key in ~/.ssh/known_hosts.
"""
import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time

TIMEOUT = 60
EXIT_STATUS = 7


def main() -> int:
    executable, destination = sys.argv[1], sys.argv[2]
    pid, fd = pty.fork()
    if pid == 0:
        # The child's terminal gets a size before the sample starts, as a terminal window has one: it reads it for the remote pty.
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        os.execv(executable, [executable, destination])

    output = bytearray()
    deadline = time.monotonic() + TIMEOUT

    def read_until(token: bytes) -> bool:
        """Reads the sample's output until it holds token; False when the output ends or time runs out first."""
        while token not in output:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                continue
            try:
                data = os.read(fd, 4096)
            except OSError:  # EIO: the sample has exited and closed the terminal
                data = b""
            if not data:
                return False
            output.extend(data)
        return True

    def fail(message: str) -> int:
        print(f"::error::{message}")
        print(output.decode("utf-8", "replace"))
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
        return 1

    # The prompt ends with "$ " for a normal user's bash. Typing before it would race the sample's own terminal setup.
    if not read_until(b"$ "):
        return fail("the remote shell's prompt did not appear")

    os.write(fd, b"echo terminal-sample-$((6*7))\r")
    if not read_until(b"terminal-sample-42"):
        return fail("the command's output did not come back")

    os.write(fd, f"exit {EXIT_STATUS}\r".encode())
    read_until(b"\0")  # drain to the end (or the deadline), so the sample is not blocked writing
    # The terminal closes as the process exits, a moment before its status is there to collect.
    exited, status = os.waitpid(pid, os.WNOHANG)
    for _ in range(100):
        if exited != 0:
            break
        time.sleep(0.1)
        exited, status = os.waitpid(pid, os.WNOHANG)

    if exited == 0:
        return fail("the terminal sample did not exit after the remote shell did")

    code = os.waitstatus_to_exitcode(status)
    print(output.decode("utf-8", "replace"))
    if code != EXIT_STATUS:
        print(f"::error::the terminal sample exited with {code}, not the shell's {EXIT_STATUS}")
        return 1

    print(f"The terminal sample ran a command and exited with the shell's status {EXIT_STATUS}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

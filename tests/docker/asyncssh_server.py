#!/usr/bin/env python3
"""A throwaway AsyncSSH server for the CI interop matrix: an independent SSH implementation, in Python, next to OpenSSH and Dropbear.

It runs as the test account, in its home directory, and serves shells and commands (with or without a pseudo-terminal), SFTP, SCP,
TCP and Unix-socket forwarding in both directions, and agent forwarding. The account's password comes from TEST_PASSWORD, and it
re-keys every 32 KiB, as the OpenSSH container does. Never used outside CI.
"""

import asyncio
import fcntl
import logging
import os
import struct
import sys
import termios

import asyncssh

USER = "sshsharp"
PASSWORD = os.environ["TEST_PASSWORD"]
PORT = int(os.environ.get("PORT", "2222"))


class Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True  # every user must authenticate

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == USER and password == PASSWORD

    # Forwarding in every direction, as the OpenSSH container allows.
    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        return True

    def server_requested(self, listen_host, listen_port):
        return True

    def unix_connection_requested(self, dest_path):
        return True

    def unix_server_requested(self, listen_path):
        return True


def child_environment(process):
    env = {k: v for k, v in os.environ.items() if k != "TEST_PASSWORD"}
    env.update(process.env)
    if process.get_terminal_type():
        env["TERM"] = process.get_terminal_type()

    try:
        agent_path = process.channel.get_agent_path()
    except AttributeError:
        agent_path = None
    if agent_path:
        env["SSH_AUTH_SOCK"] = agent_path

    return env


async def handle(process: asyncssh.SSHServerProcess):
    """Runs the command, or a shell, as a child process: through a pseudo-terminal when the client asked for one."""
    args = ["/bin/sh", "-c", process.command] if process.command else ["/bin/sh", "-i"]
    env = child_environment(process)
    try:
        if process.get_terminal_type():
            master, slave = os.openpty()
            columns, rows, width, height = process.get_terminal_size()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, width, height))
            child = await asyncio.create_subprocess_exec(
                *args, stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True,
                preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
            os.close(slave)
            await process.redirect(stdin=os.fdopen(os.dup(master), "wb", buffering=0), stdout=os.fdopen(master, "rb", buffering=0))
        else:
            child = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
            await process.redirect(stdin=child.stdin, stdout=child.stdout, stderr=child.stderr)

        status = await child.wait()
        await process.stdout.drain()
        process.exit(status if status >= 0 else 128 - status)
    except Exception:  # noqa: BLE001 - logged, and the session ends with a failure status instead of hanging
        logging.exception("session failed")
        process.exit(255)


async def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    asyncssh.set_debug_level(1)
    keys = [asyncssh.generate_private_key(alg) for alg in ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa")]
    await asyncssh.create_server(
        Server, "", PORT,
        server_host_keys=keys,
        process_factory=handle,
        sftp_factory=True,
        allow_scp=True,
        agent_forwarding=True,
        rekey_bytes=32 * 1024,
        login_timeout=60,
    )
    logging.info("AsyncSSH %s listening on port %d", asyncssh.__version__, PORT)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())

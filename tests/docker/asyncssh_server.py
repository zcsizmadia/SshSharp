#!/usr/bin/env python3
"""A throwaway AsyncSSH server for the CI interop matrix: an independent SSH implementation, in Python, next to OpenSSH and Dropbear.

It runs as the test account, in its home directory, and serves shells and commands (with or without a pseudo-terminal), SFTP, SCP,
TCP and Unix-socket forwarding in both directions, and agent forwarding. The account's password comes from TEST_PASSWORD, and it
re-keys every 32 KiB, as the OpenSSH container does. Never used outside CI.

Sessions copy data between the channel and the child process themselves rather than with SSHServerProcess.redirect, which ended
channels (and connections) with "read() called while another coroutine is already waiting for incoming data" under load.

Each connection signs with its own copy of the host keys (see choose_server_host_key below).
"""

import asyncio
import copy
import fcntl
import logging
import os
import signal
import struct
import sys
import termios

import asyncssh

USER = "sshsharp"
PASSWORD = os.environ["TEST_PASSWORD"]
PORT = int(os.environ.get("PORT", "2222"))
CHUNK = 32 * 1024


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


# AsyncSSH 2.21.0 races when connections choose different RSA signature algorithms at once. choose_server_host_key calls
# set_sig_algorithm on the keypair from options.server_host_keys, which every connection shares, so a connection that negotiated
# rsa-sha2-512 can sign its exchange hash with rsa-sha2-256 because another connection chose that in between. The client then
# correctly refuses the signature ("signature over the exchange hash is invalid"; #188). A shallow copy per connection is enough:
# set_sig_algorithm only sets attributes on the keypair.
_choose_server_host_key = asyncssh.connection.SSHServerConnection.choose_server_host_key


def choose_server_host_key(self, peer_host_key_algs):
    self._server_host_keys = {alg: copy.copy(keypair) for alg, keypair in self._server_host_keys.items()}
    return _choose_server_host_key(self, peer_host_key_algs)


asyncssh.connection.SSHServerConnection.choose_server_host_key = choose_server_host_key


def child_environment(process):
    env = {k: v for k, v in os.environ.items() if k != "TEST_PASSWORD"}
    env.update(process.env)
    if process.get_terminal_type():
        env["TERM"] = process.get_terminal_type()

    agent_path = process.channel.get_agent_path()  # set when the client forwards its agent
    if agent_path:
        env["SSH_AUTH_SOCK"] = agent_path

    return env


def set_window_size(fd, columns, rows, width, height):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, width, height))


async def copy_to_client(reader, writer):
    """The child's output to the channel, until the child closes it (a pty reports EIO then)."""
    try:
        while data := await reader.read(CHUNK):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass


async def copy_to_child(process, child, write, close, pty_fd):
    """The channel's input to the child, acting on what arrives with it: window changes, signals and breaks."""
    while True:
        try:
            data = await process.stdin.read(CHUNK)
        except asyncssh.TerminalSizeChanged as change:
            if pty_fd is not None:
                set_window_size(pty_fd, change.width, change.height, change.pixwidth, change.pixheight)
            continue
        except asyncssh.SignalReceived as received:
            number = getattr(signal, "SIG" + received.signal, None)
            if number is not None and child.returncode is None:
                child.send_signal(number)
            continue
        except asyncssh.BreakReceived:
            continue

        if not data:
            break

        await write(data)

    close()


async def handle(process: asyncssh.SSHServerProcess):
    """Runs the command, or a shell, as a child process: through a pseudo-terminal when the client asked for one."""
    if process.subsystem:
        process.exit(127)  # sftp is served by AsyncSSH itself; no other subsystem exists here
        return

    loop = asyncio.get_running_loop()
    args = ["/bin/sh", "-c", process.command] if process.command else ["/bin/sh", "-i"]
    env = child_environment(process)
    feeder = None
    try:
        if process.get_terminal_type():
            master, slave = os.openpty()
            set_window_size(slave, *process.get_terminal_size())
            child = await asyncio.create_subprocess_exec(
                *args, stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True,
                preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
            os.close(slave)
            output = asyncio.StreamReader()
            await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(output), os.fdopen(os.dup(master), "rb", buffering=0))

            async def write_pty(data):
                await loop.run_in_executor(None, os.write, master, data)

            feeder = asyncio.ensure_future(copy_to_child(process, child, write_pty, lambda: None, master))
            await copy_to_client(output, process.stdout)
            os.close(master)
        else:
            child = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)

            async def write_pipe(data):
                child.stdin.write(data)
                try:
                    await child.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the child stopped reading; the rest of the input goes nowhere, as with sshd

            feeder = asyncio.ensure_future(copy_to_child(process, child, write_pipe, child.stdin.close, None))
            await asyncio.gather(copy_to_client(child.stdout, process.stdout), copy_to_client(child.stderr, process.stderr))

        status = await child.wait()
        if status < 0:
            process.exit_with_signal(signal.Signals(-status).name[3:])
        else:
            process.exit(status)
    except Exception:  # noqa: BLE001 - logged, and the session ends with a failure status instead of hanging
        logging.exception("session failed")
        process.exit(255)
    finally:
        if feeder is not None:
            feeder.cancel()


async def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    asyncssh.set_debug_level(1)
    keys = [asyncssh.generate_private_key(alg) for alg in ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa")]
    await asyncssh.create_server(
        Server, "", PORT,
        server_host_keys=keys,
        process_factory=handle,
        encoding=None,  # sessions carry bytes, not text
        line_editor=False,  # the pseudo-terminal does the echoing and editing, as with sshd
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

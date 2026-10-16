// A throwaway Apache MINA SSHD server for the CI interop matrix: an independent SSH implementation, in Java, next to OpenSSH, Dropbear
// and AsyncSSH (#218). MINA SSHD is the server inside Jenkins, Gerrit and Eclipse.
//
// It runs as the test account, in its home directory, and serves shells, commands, SCP, SFTP and TCP forwarding in both directions.
// The account's password comes from TEST_PASSWORD. Never used outside CI.
//
// Its re-key limit stays at MINA's default (1 GB), so the server starts no re-key in the tests; the client's re-keys still run. With
// a 32 KiB limit, as in the OpenSSH container, MINA 2.20.0 sometimes failed a session in CI while both sides re-keyed: its own key
// agreement threw "IllegalStateException: Not initialized" (XDHKeyAgreement) and it closed the connection. MINA checks the limit only
// after a message from the client or a write, so it has no fixed interval to test anyway; colliding re-keys are covered against
// OpenSSH and AsyncSSH, which re-key every 32 KiB.
//
// Shells and commands run as processes with their streams copied by ProcessCommand below, not by MINA's ProcessShellFactory: its
// wrapper copies all three streams on one thread, so a command that reads a lot of input while writing output (tr, cat) deadlocks
// once a pipe fills (200 KB through "tr" hung for OpenSSH's client too). MINA has no pseudo-terminal: a shell with a terminal runs on
// pipes. Java reports a killed process as 128 + the signal number, which is sent as an exit status.
//
// Run as a single source file: java -cp '/mina/*' /MinaServer.java

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.util.List;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;

public final class MinaServer {
    private static final String USER = "sshsharp";

    public static void main(String[] args) throws Exception {
        String password = System.getenv("TEST_PASSWORD");
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "2222"));

        List<KeyPair> hostKeys = List.of(
                KeyUtils.generateKeyPair("ssh-ed25519", 256),
                KeyUtils.generateKeyPair("ecdsa-sha2-nistp256", 256),
                KeyUtils.generateKeyPair("ssh-rsa", 3072));

        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(KeyPairProvider.wrap(hostKeys));
        sshd.setPasswordAuthenticator((user, given, session) -> USER.equals(user) && password.equals(given));
        // Commands go through "sh -c", as with sshd; scp commands are served by MINA itself.
        CommandFactory commands = (channel, command) -> new ProcessCommand(List.of("/bin/sh", "-c", command));
        sshd.setShellFactory(channel -> new ProcessCommand(List.of("/bin/sh", "-i")));
        sshd.setCommandFactory(new ScpCommandFactory.Builder().withDelegate(commands).build());
        // SFTP and SCP see the real file system, as with sshd; relative paths start in the home directory, where the server runs.
        sshd.setSubsystemFactories(List.of(new SftpSubsystemFactory()));
        sshd.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
        // EXPERIMENT (#240): the 32 KiB limit back on, to catch the "Not initialized" key agreement error with a trace.
        CoreModuleProperties.REKEY_BYTES_LIMIT.set(sshd, 32L * 1024);
        sshd.start();
        System.err.println("MINA SSHD listening on port " + port);
        Thread.currentThread().join();
    }

    /** A process whose stdin, stdout and stderr each have their own copying thread; the exit status follows the end of its output. */
    private static final class ProcessCommand implements Command {
        private final List<String> argv;
        private InputStream in;
        private OutputStream out;
        private OutputStream err;
        private ExitCallback exit;
        private Process process;

        ProcessCommand(List<String> argv) {
            this.argv = argv;
        }

        @Override
        public void setInputStream(InputStream in) {
            this.in = in;
        }

        @Override
        public void setOutputStream(OutputStream out) {
            this.out = out;
        }

        @Override
        public void setErrorStream(OutputStream err) {
            this.err = err;
        }

        @Override
        public void setExitCallback(ExitCallback exit) {
            this.exit = exit;
        }

        @Override
        public void start(ChannelSession channel, Environment environment) throws IOException {
            ProcessBuilder builder = new ProcessBuilder(argv);
            builder.environment().putAll(environment.getEnv());
            process = builder.start();
            copy(in, process.getOutputStream(), true); // the channel's EOF closes the process's stdin
            Thread stdout = copy(process.getInputStream(), out, false);
            Thread stderr = copy(process.getErrorStream(), err, false);
            Thread waiter = new Thread(() -> {
                try {
                    int status = process.waitFor();
                    stdout.join();
                    stderr.join();
                    exit.onExit(status);
                } catch (InterruptedException e) {
                    exit.onExit(255);
                }
            });
            waiter.setDaemon(true);
            waiter.start();
        }

        @Override
        public void destroy(ChannelSession channel) {
            if (process != null) {
                process.destroy();
            }
        }

        private static Thread copy(InputStream from, OutputStream to, boolean closeAtEnd) {
            Thread thread = new Thread(() -> {
                byte[] buffer = new byte[32 * 1024];
                try {
                    int read;
                    while ((read = from.read(buffer)) > 0) {
                        to.write(buffer, 0, read);
                        to.flush();
                    }
                } catch (IOException e) {
                    // The process or the channel went away; the exit status (or the channel's close) ends the session.
                } finally {
                    if (closeAtEnd) {
                        try {
                            to.close();
                        } catch (IOException e) {
                            // already closed
                        }
                    }
                }
            });
            thread.setDaemon(true);
            thread.start();
            return thread;
        }
    }
}

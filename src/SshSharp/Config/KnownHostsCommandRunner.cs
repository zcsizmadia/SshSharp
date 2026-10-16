using System.Diagnostics;
using System.Text;

namespace SshSharp.Config;

/// <summary>
/// Runs <c>KnownHostsCommand</c> as OpenSSH does (sshconnect.c, load_hostkeys_command): the command is split into arguments (no shell
/// is involved, so token values cannot inject anything), each argument after the program has its <c>${VAR}</c> and <c>%</c> tokens
/// expanded (the program itself is taken as written), and the program, which must be given
/// by absolute path, is run directly. On Windows a batch file is refused, since Windows would run it through cmd.exe. Its standard output is read as known_hosts lines. A non-zero exit status fails the connection.
/// Unlike OpenSSH, the run is bounded: <see cref="Timeout"/> and <see cref="MaxOutput"/>.
/// </summary>
internal static class KnownHostsCommandRunner
{
    /// <summary>How long the command may run.</summary>
    internal static TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>The most output read (OpenSSH has no limit; 1 MiB is many thousands of host keys).</summary>
    internal const int MaxOutput = 1024 * 1024;

    /// <summary>
    /// Runs the command for <paramref name="name"/>:<paramref name="port"/> (<c>%H</c>), for <paramref name="reason"/> (<c>%I</c>:
    /// <c>HOSTNAME</c> or <c>ORDER</c>), with the presented <paramref name="key"/> (<c>%K %f %t</c>; <c>NONE</c> before one is known). With
    /// <paramref name="asCertificate"/>, <c>%K</c> and <c>%t</c> are the key's certificate and its type, as ssh passes while it checks the
    /// certificate; <c>%f</c> is the plain key's fingerprint either way, as ssh's is.
    /// </summary>
    /// <exception cref="SshException">The command could not run, failed, ran too long or wrote too much (<see cref="SshFailureReason.ConnectFailed"/>).</exception>
    public static async Task<KnownHostsFile> RunAsync(string command, SshTokenContext tokens, string name, int port, string reason, SshHostKey? key,
        bool asCertificate, CancellationToken cancellationToken)
    {
        var certificate = asCertificate ? key?.Certificate : null;
        var context = tokens with
        {
            Extra = new Dictionary<char, string>
            {
                ['H'] = port == 22 ? name : $"[{name}]:{port}",
                ['I'] = reason,
                ['K'] = certificate is not null ? Convert.ToBase64String(certificate.Blob.Span)
                    : key is null ? "NONE" : Convert.ToBase64String(key.PublicKey.Span),
                ['f'] = key?.Fingerprint ?? "NONE",
                ['t'] = certificate?.Algorithm ?? key?.KeyType ?? "NONE",
            },
        };

        List<string> arguments;
        try
        {
            // As sshconnect.c: the program is taken as written; each argument after it gets ${VAR} and the % tokens, in one pass.
            var words = Split(command);
            arguments = [.. words.Take(1), .. words.Skip(1).Select(context.ExpandTokensAndVariables)];
        }
        catch (FormatException ex)
        {
            throw new SshException(SshFailureReason.ConnectFailed, $"KnownHostsCommand is malformed: {ex.Message}", ex);
        }

        if (arguments.Count == 0 || !Path.IsPathFullyQualified(arguments[0]))
        {
            throw new SshException(SshFailureReason.ConnectFailed, "KnownHostsCommand must name its program by absolute path.");
        }

        if (OperatingSystem.IsWindows() &&
            Path.GetExtension(arguments[0].TrimEnd('.', ' ')).ToUpperInvariant() is ".BAT" or ".CMD")
        {
            // Windows starts a batch file through cmd.exe, which reparses the arguments (%VAR%, ^, !): token values could then reach a shell.
            throw new SshException(SshFailureReason.ConnectFailed, "KnownHostsCommand cannot be a batch file on Windows: cmd.exe would reparse its arguments. Use an executable, for example powershell.exe -File script.ps1.");
        }

        var start = new ProcessStartInfo(arguments[0])
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments.Skip(1))
        {
            start.ArgumentList.Add(argument);
        }

        Process process;
        try
        {
            process = Process.Start(start) ?? throw new InvalidOperationException("The process did not start.");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            throw new SshException(SshFailureReason.ConnectFailed, $"KnownHostsCommand could not be started: {ex.Message}", ex);
        }

        using (process)
        {
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(Timeout);
            try
            {
                process.StandardInput.Close();
                var error = process.StandardError.BaseStream.CopyToAsync(Stream.Null, limit.Token); // drained, so the command cannot block on it
                var output = await ReadBoundedAsync(process.StandardOutput.BaseStream, limit.Token).ConfigureAwait(false);
                await process.WaitForExitAsync(limit.Token).ConfigureAwait(false);
                await error.ConfigureAwait(false);
                if (process.ExitCode != 0)
                {
                    throw new SshException(SshFailureReason.ConnectFailed, $"KnownHostsCommand failed (exit status {process.ExitCode}).");
                }

                return KnownHostsFile.Parse(output);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new SshException(SshFailureReason.ConnectFailed, $"KnownHostsCommand did not finish within {Timeout.TotalSeconds:0} s.");
            }
            finally
            {
                if (!process.HasExited)
                {
                    try
                    {
                        process.Kill(entireProcessTree: true);
                    }
                    catch (InvalidOperationException)
                    {
                        // It exited meanwhile.
                    }
                }
            }
        }
    }

    private static async Task<string> ReadBoundedAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxOutput)
            {
                throw new SshException(SshFailureReason.ConnectFailed, $"KnownHostsCommand wrote more than {MaxOutput} bytes.");
            }

            buffer.Write(chunk, 0, read);
        }

        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    /// <summary>
    /// Splits a command into arguments as OpenSSH's argv_split does: white space separates, single and double quotes group (and are
    /// removed), and a backslash escapes a quote, a backslash, or (outside quotes) a space.
    /// </summary>
    /// <exception cref="FormatException">A quote is not closed.</exception>
    internal static List<string> Split(string command)
    {
        var arguments = new List<string>();
        var current = new StringBuilder();
        var inArgument = false;
        var quote = '\0';
        for (var i = 0; i < command.Length; i++)
        {
            var c = command[i];
            if (quote == '\0' && char.IsWhiteSpace(c))
            {
                if (inArgument)
                {
                    arguments.Add(current.ToString());
                    current.Clear();
                    inArgument = false;
                }

                continue;
            }

            inArgument = true;
            if (c == '\\' && i + 1 < command.Length && (command[i + 1] is '\'' or '"' or '\\' || (quote == '\0' && command[i + 1] == ' ')))
            {
                current.Append(command[++i]);
            }
            else if (quote == '\0' && c is '\'' or '"')
            {
                quote = c;
            }
            else if (c == quote)
            {
                quote = '\0';
            }
            else
            {
                current.Append(c);
            }
        }

        if (quote != '\0')
        {
            throw new FormatException("A quote in KnownHostsCommand is not closed.");
        }

        if (inArgument)
        {
            arguments.Add(current.ToString());
        }

        return arguments;
    }
}

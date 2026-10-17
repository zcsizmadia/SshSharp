namespace SshSharp;

/// <summary>Why an SSH operation failed.</summary>
public enum SshFailureReason
{
    /// <summary>An unspecified failure.</summary>
    Unknown,

    /// <summary>The peer sent data that violates the SSH protocol.</summary>
    ProtocolError,

    /// <summary>No common key exchange, cipher, MAC or host key algorithm.</summary>
    KeyExchangeFailed,

    /// <summary>The server's host key was rejected.</summary>
    HostKeyRejected,

    /// <summary>User authentication failed.</summary>
    AuthenticationFailed,

    /// <summary>The connection was closed, by the peer or because of an error.</summary>
    ConnectionClosed,

    /// <summary>A channel was closed or refused.</summary>
    ChannelClosed,

    /// <summary>An operation timed out.</summary>
    Timeout,

    /// <summary>The network connection to the server could not be established.</summary>
    ConnectFailed,

    /// <summary>The SSH agent could not be reached, refused a request, or answered with something unexpected.</summary>
    AgentFailed,

    /// <summary>
    /// A file transfer failed: an SCP transfer that the remote side reported an error in, or broke the protocol of, or an SFTP tree
    /// transfer that the remote tree made unsafe (too deep, or a name that would leave the target). A single SFTP request that the server
    /// refuses is <see cref="SftpFailed"/>.
    /// </summary>
    TransferFailed,

    /// <summary>An SFTP request failed with an error status from the server (see <c>SftpException.Status</c>).</summary>
    SftpFailed,

    /// <summary>
    /// A remote command ran but did not succeed: it exited with a non-zero status, was ended by a signal, or ended without reporting
    /// either. Raised by <see cref="SshCommandResult.EnsureSuccess"/> as an <see cref="SshCommandException"/>.
    /// </summary>
    CommandFailed,
}

/// <summary>The base class for errors raised by SshSharp when talking SSH.</summary>
public class SshException : Exception
{
    /// <summary>Creates an exception.</summary>
    /// <param name="reason">Why the operation failed.</param>
    /// <param name="message">A description.</param>
    /// <param name="innerException">The underlying exception, if any.</param>
    public SshException(SshFailureReason reason, string message, Exception? innerException = null)
        : base(message, innerException) => Reason = reason;

    /// <summary>Why the operation failed.</summary>
    public SshFailureReason Reason { get; }
}

/// <summary>The peer sent data that violates the SSH protocol (malformed packet, bad length, unexpected message).</summary>
public sealed class SshProtocolException : SshException
{
    /// <summary>Creates an exception.</summary>
    /// <param name="message">A description.</param>
    public SshProtocolException(string message)
        : base(SshFailureReason.ProtocolError, message)
    {
    }

    /// <summary>Creates an exception with the one that caused it.</summary>
    /// <param name="message">A description.</param>
    /// <param name="innerException">The exception that caused this one.</param>
    public SshProtocolException(string message, Exception? innerException)
        : base(SshFailureReason.ProtocolError, message, innerException)
    {
    }
}
/// <summary>The server's host key was not trusted, changed, or revoked, or the server could not prove it holds the key.</summary>
public sealed class SshHostKeyException : SshException
{
    /// <summary>Creates an exception.</summary>
    /// <param name="message">A description.</param>
    /// <param name="hostKey">The key the server presented, if it got that far.</param>
    public SshHostKeyException(string message, SshHostKey? hostKey = null)
        : base(SshFailureReason.HostKeyRejected, message) => HostKey = hostKey;

    /// <summary>The key the server presented, when known.</summary>
    public SshHostKey? HostKey { get; }
}

/// <summary>The server refused every authentication method that was tried.</summary>
public sealed class SshAuthenticationException : SshException
{
    /// <summary>Creates an exception.</summary>
    /// <param name="message">A description.</param>
    /// <param name="allowedMethods">The methods the server said it still accepts.</param>
    public SshAuthenticationException(string message, IReadOnlyList<string> allowedMethods)
        : base(SshFailureReason.AuthenticationFailed, message) => AllowedMethods = allowedMethods;

    /// <summary>The methods the server still accepts (from its last <c>USERAUTH_FAILURE</c>), for example <c>publickey</c>.</summary>
    public IReadOnlyList<string> AllowedMethods { get; }
}

/// <summary>
/// A remote command did not succeed (<see cref="SshCommandResult.EnsureSuccess"/>): it exited with a non-zero <see cref="ExitStatus"/>,
/// was ended by <see cref="ExitSignal"/>, or ended without reporting either. <see cref="StandardError"/> holds the end of what it wrote to
/// standard error. The message names the status or the signal only: neither the command nor its output is in it, since exception messages
/// often end up in logs.
/// </summary>
public sealed class SshCommandException : SshException
{
    /// <summary>The most standard error kept: the last 4 KiB, where a failing program usually says why.</summary>
    internal const int MaxStandardErrorBytes = 4 * 1024;

    /// <summary>Creates the exception.</summary>
    /// <param name="message">A description.</param>
    /// <param name="exitStatus">The command's exit status, or null if it reported none.</param>
    /// <param name="exitSignal">The signal that ended the command, if any.</param>
    /// <param name="standardError">What the command wrote to standard error; only the last 4 KiB is kept (copied).</param>
    public SshCommandException(string message, int? exitStatus, SshExitSignal? exitSignal, ReadOnlyMemory<byte> standardError)
        : base(SshFailureReason.CommandFailed, message)
    {
        ExitStatus = exitStatus;
        ExitSignal = exitSignal;
        IsStandardErrorTruncated = standardError.Length > MaxStandardErrorBytes;
        StandardError = standardError[Math.Max(0, standardError.Length - MaxStandardErrorBytes)..].ToArray();
    }

    /// <summary>The command's exit status, or null if it ended without one (for example, killed by a signal).</summary>
    public int? ExitStatus { get; }

    /// <summary>The signal that ended the command, if any.</summary>
    public SshExitSignal? ExitSignal { get; }

    /// <summary>
    /// The end of what the command wrote to standard error: all of it up to 4 KiB, otherwise the last 4 KiB
    /// (<see cref="IsStandardErrorTruncated"/>). The full output is in the <see cref="SshCommandResult"/> the exception came from.
    /// </summary>
    public ReadOnlyMemory<byte> StandardError { get; }

    /// <summary>Whether <see cref="StandardError"/> holds only the last 4 KiB of a longer standard error.</summary>
    public bool IsStandardErrorTruncated { get; }

    /// <summary>
    /// <see cref="StandardError"/> decoded as UTF-8. When it was truncated, a character that the cut split at the start is left out. The text
    /// comes from the server: strip control characters before showing it in a terminal.
    /// </summary>
    public string StandardErrorText
    {
        get
        {
            var span = StandardError.Span;
            if (IsStandardErrorTruncated)
            {
                // Skip UTF-8 continuation bytes (10xxxxxx) at the cut, at most three: the rest of a character that began before it.
                var skip = 0;
                while (skip < 3 && skip < span.Length && (span[skip] & 0xC0) == 0x80)
                {
                    skip++;
                }

                span = span[skip..];
            }

            return System.Text.Encoding.UTF8.GetString(span);
        }
    }
}

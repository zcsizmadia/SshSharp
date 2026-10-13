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
}
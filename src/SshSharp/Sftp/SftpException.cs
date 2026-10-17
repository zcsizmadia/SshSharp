
namespace SshSharp.Sftp;

/// <summary>An SFTP status code (draft-ietf-secsh-filexfer-02 section 7).</summary>
public enum SftpStatusCode
{
    /// <summary>Success.</summary>
    Ok = 0,

    /// <summary>End of file, or of a directory listing.</summary>
    EndOfFile = 1,

    /// <summary>The file or directory does not exist.</summary>
    NoSuchFile = 2,

    /// <summary>The server's user may not do this.</summary>
    PermissionDenied = 3,

    /// <summary>A failure with no more specific code (on OpenSSH, for example, a directory that is not empty, or a file that exists).</summary>
    Failure = 4,

    /// <summary>The server could not parse the request.</summary>
    BadMessage = 5,

    /// <summary>No connection.</summary>
    NoConnection = 6,

    /// <summary>The connection was lost.</summary>
    ConnectionLost = 7,

    /// <summary>The server does not support the operation.</summary>
    OperationUnsupported = 8,
}

/// <summary>An SFTP request failed: the server answered with an error status (<see cref="Status"/>), about <see cref="Path"/>.</summary>
public sealed class SftpException : SshException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="status">The status the server sent.</param>
    /// <param name="message">What failed.</param>
    /// <param name="path">The remote path concerned, if any.</param>
    public SftpException(SftpStatusCode status, string message, string? path = null)
        : base(SshFailureReason.SftpFailed, message)
    {
        Status = status;
        Path = path;
    }

    /// <summary>The status the server sent.</summary>
    public SftpStatusCode Status { get; }

    /// <summary>The remote path concerned, if any.</summary>
    public string? Path { get; }
}

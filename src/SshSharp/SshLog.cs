using Microsoft.Extensions.Logging;

namespace SshSharp;

/// <summary>Log messages. None of them include passwords, key material, command text, user names or host names.</summary>
internal static partial class SshLog
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "Server identification: {Identification}")]
    public static partial void ServerIdentified(ILogger logger, string identification);

    [LoggerMessage(EventId = 2, Level = LogLevel.Debug, Message = "Negotiated key exchange {Kex}, host key {HostKey}, cipher {CipherClientToServer}/{CipherServerToClient}, strict key exchange {Strict}")]
    public static partial void Negotiated(ILogger logger, string kex, string hostKey, string cipherClientToServer, string cipherServerToClient, bool strict);

    [LoggerMessage(EventId = 3, Level = LogLevel.Debug, Message = "Key exchange {Count} completed")]
    public static partial void KeyExchangeCompleted(ILogger logger, int count);

    [LoggerMessage(EventId = 4, Level = LogLevel.Debug, Message = "Starting a key re-exchange ({Reason})")]
    public static partial void RekeyStarting(ILogger logger, string reason);

    [LoggerMessage(EventId = 5, Level = LogLevel.Information, Message = "Connected: {Kex}, {Cipher}, host key {KeyType} {Fingerprint}")]
    public static partial void Connected(ILogger logger, string kex, string cipher, string keyType, string fingerprint);

    [LoggerMessage(EventId = 6, Level = LogLevel.Warning, Message = "The host key {Fingerprint} was not accepted")]
    public static partial void HostKeyRejected(ILogger logger, string fingerprint);

    [LoggerMessage(EventId = 7, Level = LogLevel.Debug, Message = "Authenticating with method {Method}")]
    public static partial void Authenticating(ILogger logger, string method);

    [LoggerMessage(EventId = 8, Level = LogLevel.Information, Message = "Authenticated with method {Method}")]
    public static partial void Authenticated(ILogger logger, string method);

    [LoggerMessage(EventId = 9, Level = LogLevel.Warning, Message = "Authentication failed; the server accepts: {Methods}")]
    public static partial void AuthenticationFailed(ILogger logger, string methods);

    [LoggerMessage(EventId = 10, Level = LogLevel.Debug, Message = "Channel {Id} opened")]
    public static partial void ChannelOpened(ILogger logger, uint id);

    [LoggerMessage(EventId = 11, Level = LogLevel.Debug, Message = "Channel {Id} closed")]
    public static partial void ChannelClosed(ILogger logger, uint id);

    [LoggerMessage(EventId = 12, Level = LogLevel.Debug, Message = "Running a command ({Length} characters) on channel {Id}")]
    public static partial void CommandStarting(ILogger logger, int length, uint id);

    [LoggerMessage(EventId = 13, Level = LogLevel.Debug, Message = "Command on channel {Id} finished with exit status {ExitStatus} and signal {ExitSignal}")]
    public static partial void CommandFinished(ILogger logger, uint id, int? exitStatus, string? exitSignal);

    [LoggerMessage(EventId = 14, Level = LogLevel.Warning, Message = "Received message {Type}, which this client does not implement")]
    public static partial void UnimplementedMessage(ILogger logger, byte type);

    [LoggerMessage(EventId = 15, Level = LogLevel.Error, Message = "The connection failed")]
    public static partial void ConnectionFailed(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 16, Level = LogLevel.Debug, Message = "Disconnecting")]
    public static partial void Disconnecting(ILogger logger);

    [LoggerMessage(EventId = 17, Level = LogLevel.Information, Message = "Identity file {FileName} was skipped: {Reason}")]
    public static partial void IdentitySkipped(ILogger logger, string fileName, string reason);

    [LoggerMessage(EventId = 18, Level = LogLevel.Information, Message = "Recorded {Count} new host key(s) the server proved it holds (UpdateHostKeys)")]
    public static partial void HostKeysUpdated(ILogger logger, int count);

    [LoggerMessage(EventId = 19, Level = LogLevel.Debug, Message = "Host key update skipped: {Reason}")]
    public static partial void HostKeyUpdateSkipped(ILogger logger, string reason);

    [LoggerMessage(EventId = 20, Level = LogLevel.Debug, Message = "Started a {Kind} session on channel {Id} (terminal: {Terminal})")]
    public static partial void SessionStarted(ILogger logger, string kind, uint id, bool terminal);

    [LoggerMessage(EventId = 21, Level = LogLevel.Debug, Message = "Session on channel {Id} closed with exit status {ExitStatus} and signal {ExitSignal}")]
    public static partial void SessionClosed(ILogger logger, uint id, int? exitStatus, string? exitSignal);
}
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

    [LoggerMessage(EventId = 18, Level = LogLevel.Information, Message = "known_hosts updated: {Added} host key(s) the server proved it holds added, {Removed} it no longer announces removed (UpdateHostKeys)")]
    public static partial void HostKeysUpdated(ILogger logger, int added, int removed);

    [LoggerMessage(EventId = 19, Level = LogLevel.Debug, Message = "Host key update skipped: {Reason}")]
    public static partial void HostKeyUpdateSkipped(ILogger logger, string reason);

    [LoggerMessage(EventId = 20, Level = LogLevel.Debug, Message = "Started a {Kind} session on channel {Id} (terminal: {Terminal})")]
    public static partial void SessionStarted(ILogger logger, string kind, uint id, bool terminal);

    [LoggerMessage(EventId = 21, Level = LogLevel.Debug, Message = "Session on channel {Id} closed with exit status {ExitStatus} and signal {ExitSignal}")]
    public static partial void SessionClosed(ILogger logger, uint id, int? exitStatus, string? exitSignal);

    [LoggerMessage(EventId = 22, Level = LogLevel.Information, Message = "Agent key {Fingerprint} was skipped: {Reason}")]
    public static partial void AgentKeySkipped(ILogger logger, string fingerprint, string reason);

    [LoggerMessage(EventId = 23, Level = LogLevel.Debug, Message = "The SSH agent was not used: {Reason}")]
    public static partial void AgentUnavailable(ILogger logger, string reason);

    [LoggerMessage(EventId = 24, Level = LogLevel.Information, Message = "Forwarding {LocalEndPoint} to remote port {RemotePort}")]
    public static partial void ForwardingStarted(ILogger logger, string localEndPoint, int remotePort);

    [LoggerMessage(EventId = 25, Level = LogLevel.Information, Message = "Stopped forwarding {LocalEndPoint}")]
    public static partial void ForwardingStopped(ILogger logger, string localEndPoint);

    [LoggerMessage(EventId = 26, Level = LogLevel.Warning, Message = "A connection forwarded to remote port {RemotePort} was refused: {Reason}")]
    public static partial void ForwardingRefused(ILogger logger, int remotePort, string reason);

    [LoggerMessage(EventId = 27, Level = LogLevel.Information, Message = "The server forwards its port {RemotePort} to local port {LocalPort}")]
    public static partial void RemoteForwardingStarted(ILogger logger, int remotePort, int localPort);

    [LoggerMessage(EventId = 28, Level = LogLevel.Warning, Message = "A connection forwarded to local port {LocalPort} could not be made: {Reason}")]
    public static partial void RemoteForwardingConnectFailed(ILogger logger, int localPort, string reason);

    [LoggerMessage(EventId = 29, Level = LogLevel.Warning, Message = "{Keyword} number {Index} for this host was skipped: {Reason}")]
    public static partial void ConfiguredForwardingSkipped(ILogger logger, string keyword, int index, string reason);

    [LoggerMessage(EventId = 30, Level = LogLevel.Information, Message = "The key exchange {Kex} is not post-quantum: traffic recorded now could be decrypted by a future quantum computer. The server needs to offer a post-quantum key exchange: mlkem768x25519-sha256 (OpenSSH 9.9 or later), sntrup761x25519-sha512 (OpenSSH 8.5 or later), or in FIPS mode mlkem768nistp256-sha256 or mlkem1024nistp384-sha384")]
    public static partial void KeyExchangeNotPostQuantum(ILogger logger, string kex);

    [LoggerMessage(EventId = 31, Level = LogLevel.Information, Message = "The server forwards its port {RemotePort} to a SOCKS proxy on this machine (remote dynamic forwarding)")]
    public static partial void RemoteDynamicForwardingStarted(ILogger logger, int remotePort);

    [LoggerMessage(EventId = 33, Level = LogLevel.Information, Message = "The server forwards a Unix socket to this machine (streamlocal-forward)")]
    public static partial void RemoteSocketForwardingStarted(ILogger logger);

    [LoggerMessage(EventId = 40, Level = LogLevel.Debug, Message = "Kerberos (gssapi-with-mic) is not available here: {Reason}")]
    public static partial void GssapiUnavailable(ILogger logger, string reason);

    [LoggerMessage(EventId = 34, Level = LogLevel.Information, Message = "Key {Fingerprint} was added to the agent (AddKeysToAgent)")]
    public static partial void KeyAddedToAgent(ILogger logger, string fingerprint);

    [LoggerMessage(EventId = 41, Level = LogLevel.Information, Message = "Channel {Id} ({Type}) carried no data for {Seconds} s and was closed (ChannelTimeout)")]
    public static partial void ChannelTimedOut(ILogger logger, uint id, string type, int seconds);

    [LoggerMessage(EventId = 32, Level = LogLevel.Warning, Message = "A connection through remote dynamic forwarding on port {RemotePort} was not made: {Reason}")]
    public static partial void RemoteDynamicConnectFailed(ILogger logger, int remotePort, string reason);

    [LoggerMessage(EventId = 42, Level = LogLevel.Information, Message = "The server forwards its port {RemotePort} to a handler in this process")]
    public static partial void RemoteHandlerForwardingStarted(ILogger logger, int remotePort);

    [LoggerMessage(EventId = 43, Level = LogLevel.Information, Message = "The server forwards a Unix socket to a handler in this process (streamlocal-forward)")]
    public static partial void RemoteSocketHandlerForwardingStarted(ILogger logger);

    // The exception's type only: its message is the application's, and can name hosts or carry the data it was handling.
    [LoggerMessage(EventId = 44, Level = LogLevel.Warning, Message = "The handler for a connection forwarded from remote port {RemotePort} (0 for a Unix socket) failed with {ExceptionType}; that connection was closed")]
    public static partial void RemoteForwardingHandlerFailed(ILogger logger, int remotePort, string exceptionType);

    [LoggerMessage(EventId = 45, Level = LogLevel.Information, Message = "A forwarded agent request ({Operation}) for key {Fingerprint} was refused by ForwardAgentFilter")]
    public static partial void ForwardedAgentRequestRefused(ILogger logger, SshAgentOperation operation, string fingerprint);

    // The exception's type only, as for forwarding handlers: its message is the application's.
    [LoggerMessage(EventId = 46, Level = LogLevel.Warning, Message = "ForwardAgentFilter failed with {ExceptionType}; the forwarded agent request was refused")]
    public static partial void AgentFilterFailed(ILogger logger, string exceptionType);

    // The socket path stays out: paths often contain the user name.
    [LoggerMessage(EventId = 51, Level = LogLevel.Information, Message = "Forwarding a local Unix socket to remote port {RemotePort} (0 for a Unix socket on the server)")]
    public static partial void LocalSocketForwardingStarted(ILogger logger, int remotePort);

    [LoggerMessage(EventId = 52, Level = LogLevel.Information, Message = "Forwarding {LocalEndPoint} to a Unix socket on the server")]
    public static partial void ForwardingToSocketStarted(ILogger logger, string localEndPoint);
}
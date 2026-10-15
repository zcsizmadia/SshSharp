namespace SshSharp.Protocol;

/// <summary>SSH message numbers (RFC 4250 section 4.1, plus RFC 8308 and RFC 5656 key exchange messages).</summary>
internal static class SshMessage
{
    public const byte Disconnect = 1;
    public const byte Ignore = 2;
    public const byte Unimplemented = 3;
    public const byte Debug = 4;
    public const byte ServiceRequest = 5;
    public const byte ServiceAccept = 6;
    public const byte ExtInfo = 7;

    public const byte KexInit = 20;
    public const byte NewKeys = 21;

    // Key exchange specific (30-49): the same numbers mean different things per method.
    public const byte KexEcdhInit = 30;
    public const byte KexEcdhReply = 31;
    public const byte KexDhInit = 30;
    public const byte KexDhReply = 31;

    public const byte UserAuthRequest = 50;
    public const byte UserAuthFailure = 51;
    public const byte UserAuthSuccess = 52;
    public const byte UserAuthBanner = 53;
    public const byte UserAuthPkOk = 60;
    public const byte UserAuthInfoRequest = 60;
    public const byte UserAuthInfoResponse = 61;

    public const byte GlobalRequest = 80;
    public const byte RequestSuccess = 81;
    public const byte RequestFailure = 82;

    public const byte ChannelOpen = 90;
    public const byte ChannelOpenConfirmation = 91;
    public const byte ChannelOpenFailure = 92;
    public const byte ChannelWindowAdjust = 93;
    public const byte ChannelData = 94;
    public const byte ChannelExtendedData = 95;
    public const byte ChannelEof = 96;
    public const byte ChannelClose = 97;
    public const byte ChannelRequest = 98;
    public const byte ChannelSuccess = 99;
    public const byte ChannelFailure = 100;

    // OpenSSH's transport ping (PROTOCOL 1.8, ping@openssh.com).
    public const byte Ping = 192;
    public const byte Pong = 193;
}

/// <summary>Reason codes for <c>SSH_MSG_DISCONNECT</c> (RFC 4253 section 11.1).</summary>
internal enum DisconnectReason : uint
{
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

/// <summary>Reason codes for <c>SSH_MSG_CHANNEL_OPEN_FAILURE</c> (RFC 4254 section 5.1).</summary>
internal enum ChannelOpenFailureReason : uint
{
    AdministrativelyProhibited = 1,
    ConnectFailed = 2,
    UnknownChannelType = 3,
    ResourceShortage = 4,
}

namespace SshSharp.Sftp;

/// <summary>SFTP version 3 (draft-ietf-secsh-filexfer-02), the version OpenSSH implements, and OpenSSH's extensions (PROTOCOL section 4).</summary>
internal static class SftpProtocol
{
    public const uint Version = 3;

    // Packet types.
    public const byte Init = 1;
    public const byte VersionReply = 2;
    public const byte Open = 3;
    public const byte Close = 4;
    public const byte Read = 5;
    public const byte Write = 6;
    public const byte LStat = 7;
    public const byte FStat = 8;
    public const byte SetStat = 9;
    public const byte FSetStat = 10;
    public const byte OpenDir = 11;
    public const byte ReadDir = 12;
    public const byte Remove = 13;
    public const byte MkDir = 14;
    public const byte RmDir = 15;
    public const byte RealPath = 16;
    public const byte Stat = 17;
    public const byte Rename = 18;
    public const byte ReadLink = 19;
    public const byte Symlink = 20;
    public const byte Status = 101;
    public const byte Handle = 102;
    public const byte Data = 103;
    public const byte Name = 104;
    public const byte Attrs = 105;
    public const byte Extended = 200;
    public const byte ExtendedReply = 201;

    // SSH_FXF_* open flags.
    public const uint OpenRead = 0x01;
    public const uint OpenWrite = 0x02;
    public const uint OpenAppend = 0x04;
    public const uint OpenCreate = 0x08;
    public const uint OpenTruncate = 0x10;
    public const uint OpenExclusive = 0x20;

    // SSH_FILEXFER_ATTR_* flags.
    public const uint AttrSize = 0x01;
    public const uint AttrUidGid = 0x02;
    public const uint AttrPermissions = 0x04;
    public const uint AttrAcModTime = 0x08;
    public const uint AttrExtended = 0x80000000;

    // OpenSSH extensions.
    public const string LimitsExtension = "limits@openssh.com";
    public const string PosixRenameExtension = "posix-rename@openssh.com";
    public const string HardlinkExtension = "hardlink@openssh.com";
    public const string FsyncExtension = "fsync@openssh.com";
    public const string HomeDirectoryExtension = "home-directory";
    public const string StatVfsExtension = "statvfs@openssh.com";
    public const string CopyDataExtension = "copy-data";
    public const string ExpandPathExtension = "expand-path@openssh.com";
    public const string LSetStatExtension = "lsetstat@openssh.com";
    public const string UsersGroupsByIdExtension = "users-groups-by-id@openssh.com";

    /// <summary>The largest packet accepted from the server: OpenSSH's sftp-server sends at most 256 KiB, so this leaves room.</summary>
    public const int MaxPacket = 1024 * 1024;

    /// <summary>Read and write sizes when the server does not announce limits: 32 KiB, which every server accepts.</summary>
    public const int DefaultChunk = 32 * 1024;

    /// <summary>The largest read or write requested, whatever the server announces (OpenSSH announces 255 KiB).</summary>
    public const int MaxChunk = 255 * 1024;
}

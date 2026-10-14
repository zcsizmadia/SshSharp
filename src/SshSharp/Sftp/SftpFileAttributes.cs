using System.Diagnostics.CodeAnalysis;
using SshSharp.Protocol;

namespace SshSharp.Sftp;

/// <summary>What kind of file an <see cref="SftpFileAttributes"/> describes, from the file type bits of its permissions.</summary>
[Experimental(SftpClient.ExperimentalId)]
public enum SftpFileType
{
    /// <summary>The server did not say (no permissions in the attributes), or an unknown type.</summary>
    Unknown,

    /// <summary>A regular file.</summary>
    RegularFile,

    /// <summary>A directory.</summary>
    Directory,

    /// <summary>A symbolic link (only from <see cref="SftpClient.GetAttributesAsync"/> with <c>followSymbolicLinks: false</c>, or a listing).</summary>
    SymbolicLink,

    /// <summary>A device, socket or FIFO.</summary>
    Special,
}

/// <summary>
/// File attributes in SFTP (version 3): each is null when the server did not send it. To change some with
/// <see cref="SftpClient.SetAttributesAsync"/>, set only those.
/// </summary>
[Experimental(SftpClient.ExperimentalId)]
public sealed class SftpFileAttributes
{
    private const uint TypeMask = 0xF000;

    /// <summary>The size in bytes.</summary>
    public long? Size { get; init; }

    /// <summary>The owner's numeric user id.</summary>
    public int? UserId { get; init; }

    /// <summary>The owning group's numeric id.</summary>
    public int? GroupId { get; init; }

    /// <summary>The permission bits (rwx for owner, group and others, and setuid, setgid and sticky).</summary>
    public UnixFileMode? Permissions { get; init; }

    /// <summary>What kind of file this is.</summary>
    public SftpFileType FileType { get; init; }

    /// <summary>The last access time (whole seconds).</summary>
    public DateTimeOffset? LastAccessTime { get; init; }

    /// <summary>The last modification time (whole seconds).</summary>
    public DateTimeOffset? LastWriteTime { get; init; }

    /// <summary>Server-specific extended attributes, by name; empty when there are none.</summary>
    public IReadOnlyDictionary<string, byte[]> Extended { get; init; } = new Dictionary<string, byte[]>();

    /// <summary>Whether this is a directory.</summary>
    public bool IsDirectory => FileType == SftpFileType.Directory;

    /// <summary>Whether this is a regular file.</summary>
    public bool IsRegularFile => FileType == SftpFileType.RegularFile;

    /// <summary>Whether this is a symbolic link.</summary>
    public bool IsSymbolicLink => FileType == SftpFileType.SymbolicLink;

    internal static SftpFileAttributes Read(ref SshReader reader)
    {
        var flags = reader.ReadUInt32();
        long? size = (flags & SftpProtocol.AttrSize) != 0 ? (long)Math.Min(reader.ReadUInt64(), long.MaxValue) : null;
        int? uid = null, gid = null;
        if ((flags & SftpProtocol.AttrUidGid) != 0)
        {
            uid = unchecked((int)reader.ReadUInt32());
            gid = unchecked((int)reader.ReadUInt32());
        }

        UnixFileMode? permissions = null;
        var type = SftpFileType.Unknown;
        if ((flags & SftpProtocol.AttrPermissions) != 0)
        {
            var mode = reader.ReadUInt32();
            permissions = (UnixFileMode)(mode & 0xFFF);
            type = (mode & TypeMask) switch
            {
                0x8000 => SftpFileType.RegularFile,
                0x4000 => SftpFileType.Directory,
                0xA000 => SftpFileType.SymbolicLink,
                0x1000 or 0x2000 or 0x6000 or 0xC000 => SftpFileType.Special,
                _ => SftpFileType.Unknown,
            };
        }

        DateTimeOffset? accessed = null, modified = null;
        if ((flags & SftpProtocol.AttrAcModTime) != 0)
        {
            accessed = DateTimeOffset.FromUnixTimeSeconds(reader.ReadUInt32());
            modified = DateTimeOffset.FromUnixTimeSeconds(reader.ReadUInt32());
        }

        var extended = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if ((flags & SftpProtocol.AttrExtended) != 0)
        {
            var count = reader.ReadUInt32();
            for (var i = 0; i < count; i++)
            {
                var name = reader.ReadUtf8String(); // each pair is at least 8 bytes, so a huge count runs out of data and throws
                extended[name] = reader.ReadString().ToArray();
            }
        }

        return new SftpFileAttributes
        {
            Size = size,
            UserId = uid,
            GroupId = gid,
            Permissions = permissions,
            FileType = type,
            LastAccessTime = accessed,
            LastWriteTime = modified,
            Extended = extended,
        };
    }

    /// <summary>Writes the attributes that are set. Times go together in SFTP v3: setting one keeps the other as given, or the same.</summary>
    internal void Write(SshWriter writer)
    {
        uint flags = 0;
        if (Size is not null)
        {
            flags |= SftpProtocol.AttrSize;
        }

        if (UserId is not null || GroupId is not null)
        {
            if (UserId is null || GroupId is null)
            {
                throw new ArgumentException("SFTP sets the owner and group together: set both UserId and GroupId.");
            }

            flags |= SftpProtocol.AttrUidGid;
        }

        if (Permissions is not null)
        {
            flags |= SftpProtocol.AttrPermissions;
        }

        if (LastAccessTime is not null || LastWriteTime is not null)
        {
            flags |= SftpProtocol.AttrAcModTime;
        }

        if (Extended.Count > 0)
        {
            flags |= SftpProtocol.AttrExtended;
        }

        writer.WriteUInt32(flags);
        if (Size is { } size)
        {
            writer.WriteUInt64((ulong)size);
        }

        if (UserId is { } uid)
        {
            writer.WriteUInt32(unchecked((uint)uid));
            writer.WriteUInt32(unchecked((uint)GroupId!.Value));
        }

        if (Permissions is { } permissions)
        {
            writer.WriteUInt32((uint)permissions & 0xFFF);
        }

        if ((flags & SftpProtocol.AttrAcModTime) != 0)
        {
            var accessed = LastAccessTime ?? LastWriteTime!.Value;
            var modified = LastWriteTime ?? LastAccessTime!.Value;
            writer.WriteUInt32(UnixSeconds(accessed));
            writer.WriteUInt32(UnixSeconds(modified));
        }

        if (Extended.Count > 0)
        {
            writer.WriteUInt32((uint)Extended.Count);
            foreach (var (name, data) in Extended)
            {
                writer.WriteString(name);
                writer.WriteString(data);
            }
        }
    }

    private static uint UnixSeconds(DateTimeOffset time)
    {
        var seconds = time.ToUnixTimeSeconds();
        return seconds is < 0 or > uint.MaxValue
            ? throw new ArgumentOutOfRangeException(nameof(time), time, "SFTP version 3 times are from 1970 to 2106.")
            : (uint)seconds;
    }
}

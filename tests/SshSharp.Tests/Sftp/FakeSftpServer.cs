using System.Buffers;
using System.Buffers.Binary;
using SshSharp.Protocol;
using SshSharp.Tests.Protocol;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// An in-memory SFTP version 3 server for the fake SSH server's <c>sftp</c> subsystem: a small file system of directories, files and
/// symbolic links, the OpenSSH extensions, and switches to misbehave as real servers do (short reads, replies out of order).
/// </summary>
internal sealed class FakeSftpServer
{
    public const string Home = "/home/tester";

    private sealed class Node
    {
        public bool IsDirectory { get; init; }

        public string? LinkTarget { get; init; }

        public List<byte> Data { get; } = [];

        public uint Mode { get; set; } = 0x1A4; // 0644

        public uint AccessTime { get; set; } = 1_700_000_000;

        public uint ModifyTime { get; set; } = 1_700_000_000;
    }

    private readonly Dictionary<string, Node> _nodes = new(StringComparer.Ordinal)
    {
        ["/"] = new Node { IsDirectory = true, Mode = 0x1ED },
        ["/home"] = new Node { IsDirectory = true, Mode = 0x1ED },
        [Home] = new Node { IsDirectory = true, Mode = 0x1ED },
    };

    private readonly Dictionary<string, (string Path, int Position)> _handles = new(StringComparer.Ordinal);
    private readonly HashSet<string> _rawListed = new(StringComparer.Ordinal);
    private int _nextHandle;

    /// <summary>The extensions announced in SSH_FXP_VERSION.</summary>
    public Dictionary<string, string> Extensions { get; } = new(StringComparer.Ordinal)
    {
        ["posix-rename@openssh.com"] = "1",
        ["hardlink@openssh.com"] = "1",
        ["limits@openssh.com"] = "1",
        ["home-directory"] = "1",
        ["fsync@openssh.com"] = "1",
        ["statvfs@openssh.com"] = "2",
        ["copy-data"] = "1",
        ["expand-path@openssh.com"] = "1",
        ["lsetstat@openssh.com"] = "1",
        ["users-groups-by-id@openssh.com"] = "1",
    };

    /// <summary>The user and group names users-groups-by-id@openssh.com knows (uid and gid 1000, the files' owner); other ids are unknown.</summary>
    public Dictionary<uint, string> UserNames { get; } = new() { [1000] = "tester" };

    /// <inheritdoc cref="UserNames"/>
    public Dictionary<uint, string> GroupNames { get; } = new() { [1000] = "testers" };

    /// <summary>Answer home-directory for the empty user name with Failure, as OpenSSH 9.x does.</summary>
    public bool HomeDirectoryFailsForEmptyUser { get; set; }

    /// <summary>What home-directory answers when not <see cref="Home"/>: OpenSSH answers the passwd home even inside a ChrootDirectory.</summary>
    public string? HomeDirectoryAnswer { get; set; }

    /// <summary>How many fsync@openssh.com requests arrived.</summary>
    public int Fsyncs { get; private set; }

    /// <summary>The read and write lengths announced with limits@openssh.com.</summary>
    public (ulong Read, ulong Write) Limits { get; set; } = (64 * 1024, 64 * 1024);

    /// <summary>Answer reads with at most half the bytes asked for (the draft allows short reads).</summary>
    public bool ShortReads { get; set; }

    /// <summary>Take SSH_FXP_SYMLINK in the draft's order (link, then target), as AsyncSSH does with clients that are not OpenSSH.</summary>
    public bool SymlinkInDraftOrder { get; set; }

    /// <summary>Hold each reply back until the next request arrives, answering them in reverse pairs (replies may come in any order).</summary>
    public bool ReorderReplies { get; set; }

    /// <summary>Answer STAT and LSTAT of the paths this matches with PERMISSION_DENIED, as for a directory the user may not search.</summary>
    public Func<string, bool>? DenyStat { get; set; }

    /// <summary>How long to hold a reply back, by request type and reply type (a slow server); none by default.</summary>
    public Func<byte, byte, TimeSpan>? ReplyDelay { get; set; }

    /// <summary>The protocol version to announce.</summary>
    public uint Version { get; set; } = 3;

    /// <summary>Directory entries per SSH_FXP_NAME batch.</summary>
    public int ListingBatch { get; set; } = 3;

    /// <summary>The most requests waiting for a reply at once: more than one proves the client pipelines.</summary>
    public int MaxOutstanding { get; private set; }

    /// <summary>How many pairs of replies were sent in reverse order.</summary>
    public int ReorderedPairs { get; private set; }

    /// <summary>
    /// Every request type received so far, in order: a copy taken under the lock. The server keeps adding while a test reads, as a
    /// read-ahead request can still arrive after a copy has returned, and enumerating the live list then threw "Collection was
    /// modified" (the stress run on macOS).
    /// </summary>
    public List<byte> Requests
    {
        get
        {
            lock (_requests)
            {
                return [.. _requests];
            }
        }
    }

    private readonly List<byte> _requests = [];

    /// <summary>How many handles are open now.</summary>
    public int OpenHandles => _handles.Count;

    /// <summary>Bytes written to stderr after every reply, as <c>sftp-server -e -l DEBUG</c> logs.</summary>
    public int StderrPerReply { get; set; }

    /// <summary>While set, OPEN and OPENDIR are answered only once it completes (the client may give up first).</summary>
    public TaskCompletionSource? HoldOpens { get; set; }

    /// <summary>A name in a legacy encoding (not UTF-8), added to every listing as a regular file.</summary>
    public byte[]? RawListingName { get; set; }

    /// <summary>READDIR never ends: an empty NAME batch every time.</summary>
    public bool EndlessListing { get; set; }

    /// <summary>Extensions announced with raw (possibly binary) data.</summary>
    public List<(string Name, byte[] Data)> RawExtensions { get; } = [];

    /// <summary>How many OPEN or OPENDIR requests waited for <see cref="HoldOpens"/>.</summary>
    public int HeldOpens { get; private set; }

    /// <summary>OPEN answers a status of OK instead of a handle.</summary>
    public bool OpenAnswersOk { get; set; }

    public void AddDirectory(string path) => _nodes[path] = new Node { IsDirectory = true, Mode = 0x1ED };

    public void AddFile(string path, byte[] data, uint modifyTime = 1_700_000_000)
    {
        var node = new Node { ModifyTime = modifyTime, AccessTime = modifyTime };
        node.Data.AddRange(data);
        _nodes[path] = node;
    }

    public void AddLink(string path, string target) => _nodes[path] = new Node { LinkTarget = target, Mode = 0x1FF };

    public byte[]? FileData(string path) => _nodes.TryGetValue(path, out var node) && !node.IsDirectory && node.LinkTarget is null ? [.. node.Data] : null;

    public bool Exists(string path) => _nodes.ContainsKey(path);

    public uint? ModifyTime(string path) => _nodes.TryGetValue(path, out var node) ? node.ModifyTime : null;

    public uint? Mode(string path) => _nodes.TryGetValue(path, out var node) ? node.Mode : null;

    /// <summary>Sets a node's permission bits (the low 12 bits of st_mode, setuid included).</summary>
    public void SetMode(string path, uint mode) => _nodes[path].Mode = mode & 0xFFF;

    public void Install(FakeSessionServer server) => server.Subsystems["sftp"] = RunAsync;

    /// <summary>How many SFTP sessions have started, and the most open at once.</summary>
    public int Sessions { get; private set; }

    public int MaxConcurrentSessions { get; private set; }

    /// <summary>How many SFTP sessions are open now (the client has not closed them).</summary>
    public int OpenSessions => Volatile.Read(ref _openSessions);

    private int _openSessions;

    /// <summary>For a request, raw bytes to send instead of its framed reply (a broken or hostile server); null answers normally.</summary>
    public Func<byte[], byte[]?>? RawFrame { get; set; }

    /// <summary>End the session (stdout closed) right after a <see cref="RawFrame"/> was sent.</summary>
    public bool EndSessionAfterRawFrame { get; set; }

    /// <summary>Fails a READ at this offset with a Failure status (a disk error on the server, say).</summary>
    public Func<long, bool>? FailReadAt { get; set; }

    /// <summary>Every READ's offset, in arrival order across sessions.</summary>
    public List<long> ReadOffsets { get; } = [];

    /// <summary>Sessions share the file system, so requests are handled one at a time, whichever session they come from.</summary>
    private byte[]? HandleLocked(byte[] packet)
    {
        lock (_nodes)
        {
            return Handle(packet);
        }
    }

    private async Task RunAsync(ExecScript script)
    {
        lock (_nodes)
        {
            Sessions++;
            MaxConcurrentSessions = Math.Max(MaxConcurrentSessions, ++_openSessions);
        }

        var opened = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            await RunSessionAsync(script, opened);
        }
        finally
        {
            lock (_nodes)
            {
                _openSessions--;

                // As sftp-server does when its session ends: the handles it opened are closed, including ones whose OPEN the client
                // stopped waiting for and so never learned.
                foreach (var handle in opened)
                {
                    _handles.Remove(handle);
                }
            }
        }
    }

    /// <summary>Handles a request for one session, remembering the handles it opens.</summary>
    private byte[]? HandleLocked(byte[] packet, HashSet<string> opened)
    {
        var reply = HandleLocked(packet);
        if (reply is [102, ..] && packet[0] is 3 or 11)
        {
            var length = BinaryPrimitives.ReadInt32BigEndian(reply.AsSpan(5));
            opened.Add(System.Text.Encoding.UTF8.GetString(reply, 9, length));
        }

        return reply;
    }

    private async Task RunSessionAsync(ExecScript script, HashSet<string> opened)
    {
        // A reader queues requests as they arrive and a responder answers them, so requests the client sends without waiting pile up
        // in the queue (MaxOutstanding), and two queued ones can be answered in reverse order.
        var queue = System.Threading.Channels.Channel.CreateUnbounded<byte[]>();
        var unanswered = 0;
        var endedEarly = false;
        var reader = Task.Run(async () =>
        {
            var buffer = new List<byte>();
            while (await script.ReadInputAsync() is { } chunk)
            {
                await script.GrantWindowAsync((uint)chunk.Length); // consumed: the client may send that much more, as sshd allows
                buffer.AddRange(chunk);
                while (buffer.Count >= 4)
                {
                    var length = BinaryPrimitives.ReadInt32BigEndian(buffer.GetRange(0, 4).ToArray());
                    if (buffer.Count < 4 + length)
                    {
                        break;
                    }

                    var packet = buffer.GetRange(4, length).ToArray();
                    buffer.RemoveRange(0, 4 + length);
                    var now = Interlocked.Increment(ref unanswered);
                    lock (_requests)
                    {
                        MaxOutstanding = Math.Max(MaxOutstanding, now);
                    }

                    queue.Writer.TryWrite(packet);
                }
            }

            queue.Writer.Complete();
        });

        await foreach (var packet in queue.Reader.ReadAllAsync())
        {
            await Task.Yield(); // lets requests the client already sent arrive behind this one
            if (packet[0] is 3 or 11 && HoldOpens is { } hold)
            {
                lock (_requests)
                {
                    HeldOpens++;
                }

                await hold.Task;
            }

            var reply = HandleLocked(packet, opened);
            if (StderrPerReply > 0)
            {
                await script.StderrAsync(new byte[StderrPerReply]);
            }

            if (ReplyDelay?.Invoke(packet[0], reply![0]) is { } delay && delay > TimeSpan.Zero)
            {
                await Task.Delay(delay);
            }

            if (RawFrame?.Invoke(packet) is { } raw)
            {
                // A hostile or broken server: these bytes instead of the framed reply, and optionally the end of the session after them.
                Interlocked.Decrement(ref unanswered);
                await script.StdoutAsync(raw);
                if (EndSessionAfterRawFrame)
                {
                    endedEarly = true;
                    break;
                }

                continue;
            }

            if (ReorderReplies && packet[0] != 1 && queue.Reader.TryRead(out var next))
            {
                var nextReply = HandleLocked(next, opened);
                Interlocked.Add(ref unanswered, -2);
                await script.StdoutAsync(Frame(nextReply!));
                await script.StdoutAsync(Frame(reply!));
                ReorderedPairs++;
                continue;
            }

            // Answered once its reply starts out, not once the send returns: the client can read the reply and send its next request
            // before then, and counting that one first made a single request in flight look like two (the stress run on arm64 saw it).
            Interlocked.Decrement(ref unanswered);
            await script.StdoutAsync(Frame(reply!));
        }

        if (!endedEarly)
        {
            await reader; // otherwise the client still has the session open: end it from this side
        }

        await script.FinishAsync(0);
    }

    private static byte[] Frame(byte[] payload)
    {
        var frame = new byte[4 + payload.Length];
        BinaryPrimitives.WriteInt32BigEndian(frame, payload.Length);
        payload.CopyTo(frame, 4);
        return frame;
    }

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>();
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] Status(uint id, uint code, string message = "") => Build(w =>
    {
        w.WriteByte(101);
        w.WriteUInt32(id);
        w.WriteUInt32(code);
        w.WriteString(message);
        w.WriteString("en");
    });

    private static string Resolve(string path)
    {
        var full = path.StartsWith('/') ? path : Home + "/" + path;
        var parts = new List<string>();
        foreach (var part in full.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".")
            {
                continue;
            }

            if (part == "..")
            {
                if (parts.Count > 0)
                {
                    parts.RemoveAt(parts.Count - 1);
                }

                continue;
            }

            parts.Add(part);
        }

        return "/" + string.Join('/', parts);
    }

    /// <summary>The path with a final symbolic link (and links it leads to) resolved; unchanged when it is not a link.</summary>
    private string Canonical(string path)
    {
        for (var hops = 0; hops < 8 && _nodes.TryGetValue(path, out var node) && node.LinkTarget is { } target; hops++)
        {
            path = Resolve(target.StartsWith('/') ? target : path[..path.LastIndexOf('/')] + "/" + target);
        }

        return path;
    }

    private Node? Follow(string path)
    {
        for (var hops = 0; hops < 8 && _nodes.TryGetValue(path, out var node); hops++)
        {
            if (node.LinkTarget is null)
            {
                return node;
            }

            path = Resolve(node.LinkTarget.StartsWith('/') ? node.LinkTarget : path[..path.LastIndexOf('/')] + "/" + node.LinkTarget);
        }

        return null;
    }

    private static void WriteAttributes(SshWriter w, Node node)
    {
        w.WriteUInt32(0x01 | 0x02 | 0x04 | 0x08);
        w.WriteUInt64((ulong)node.Data.Count);
        w.WriteUInt32(1000);
        w.WriteUInt32(1000);
        var type = node.IsDirectory ? 0x4000u : node.LinkTarget is not null ? 0xA000u : 0x8000u;
        w.WriteUInt32(type | node.Mode);
        w.WriteUInt32(node.AccessTime);
        w.WriteUInt32(node.ModifyTime);
    }

    private static uint[] ReadIds(ReadOnlySpan<byte> packed)
    {
        var ids = new uint[packed.Length / 4];
        for (var i = 0; i < ids.Length; i++)
        {
            ids[i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(packed[(i * 4)..]);
        }

        return ids;
    }

    /// <summary>One string per id, in order; an empty string for an id with no name, as OpenSSH answers.</summary>
    private static byte[] Names(uint[] ids, Dictionary<uint, string> known)
    {
        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        var w = new SshWriter(buffer);
        foreach (var id in ids)
        {
            w.WriteString(known.TryGetValue(id, out var name) ? name : string.Empty);
        }

        return buffer.WrittenSpan.ToArray();
    }

    private static void ApplyAttributes(ref SshReader r, Node node)
    {
        var flags = r.ReadUInt32();
        if ((flags & 0x01) != 0)
        {
            var size = (int)r.ReadUInt64();
            if (size < node.Data.Count)
            {
                node.Data.RemoveRange(size, node.Data.Count - size);
            }
            else
            {
                node.Data.AddRange(new byte[size - node.Data.Count]);
            }
        }

        if ((flags & 0x02) != 0)
        {
            r.ReadUInt32();
            r.ReadUInt32();
        }

        if ((flags & 0x04) != 0)
        {
            node.Mode = r.ReadUInt32() & 0xFFF;
        }

        if ((flags & 0x08) != 0)
        {
            node.AccessTime = r.ReadUInt32();
            node.ModifyTime = r.ReadUInt32();
        }
    }

    private byte[]? Handle(byte[] packet)
    {
        var r = new SshReader(packet);
        var type = r.ReadByte();
        lock (_requests)
        {
            _requests.Add(type);
        }

        if (type == 1)
        {
            r.ReadUInt32();
            return Build(w =>
            {
                w.WriteByte(2);
                w.WriteUInt32(Version);
                foreach (var (name, data) in Extensions)
                {
                    w.WriteString(name);
                    w.WriteString(data);
                }

                foreach (var (name, data) in RawExtensions)
                {
                    w.WriteString(name);
                    w.WriteString(data);
                }
            });
        }

        var id = r.ReadUInt32();
        if (type is 7 or 17 && DenyStat is { } deny && deny(Resolve(new SshReader(r.Remaining).ReadUtf8String())))
        {
            return Status(id, 3, "Permission denied"); // LSTAT or STAT of a path the user may not look at
        }

        switch (type)
        {
            case 3 when OpenAnswersOk:
                return Status(id, 0);

            case 3: // OPEN
            {
                var path = Resolve(r.ReadUtf8String());
                var flags = r.ReadUInt32();
                r.ReadUInt32(); // attrs (flags 0 from the client)
                var exists = _nodes.TryGetValue(path, out var node);
                if (exists && (flags & 0x20) != 0 && (flags & 0x08) != 0)
                {
                    return Status(id, 4, "File exists");
                }

                if (!exists)
                {
                    if ((flags & 0x08) == 0)
                    {
                        return Status(id, 2, "No such file");
                    }

                    if (!_nodes.TryGetValue(path[..Math.Max(1, path.LastIndexOf('/'))], out var parent) || !parent.IsDirectory)
                    {
                        return Status(id, 2, "No such file");
                    }

                    node = new Node();
                    _nodes[path] = node;
                }
                else
                {
                    node = Follow(path);
                    if (node is null)
                    {
                        return Status(id, 2, "No such file");
                    }

                    if (node.IsDirectory)
                    {
                        return Status(id, 4, "Is a directory");
                    }
                }

                if ((flags & 0x10) != 0)
                {
                    node!.Data.Clear();
                }

                var handle = "h" + _nextHandle++;
                _handles[handle] = (path, 0);
                return Build(w => { w.WriteByte(102); w.WriteUInt32(id); w.WriteString(handle); });
            }

            case 4: // CLOSE
                return _handles.Remove(r.ReadUtf8String()) ? Status(id, 0) : Status(id, 4, "Bad handle");

            case 5: // READ
            {
                var handle = r.ReadUtf8String();
                var offset = (long)r.ReadUInt64();
                var length = (int)r.ReadUInt32();
                if (!_handles.TryGetValue(handle, out var open) || Follow(open.Path) is not { } node)
                {
                    return Status(id, 4, "Bad handle");
                }

                ReadOffsets.Add(offset);
                if (FailReadAt?.Invoke(offset) == true)
                {
                    return Status(id, 4, "Input/output error");
                }

                if (offset >= node.Data.Count)
                {
                    return Status(id, 1, "EOF");
                }

                var count = (int)Math.Min(length, node.Data.Count - offset);
                if (ShortReads && count > 1)
                {
                    count /= 2;
                }

                var data = node.Data.GetRange((int)offset, count).ToArray();
                return Build(w => { w.WriteByte(103); w.WriteUInt32(id); w.WriteString(data); });
            }

            case 6: // WRITE
            {
                var handle = r.ReadUtf8String();
                var offset = (int)r.ReadUInt64();
                var data = r.ReadString().ToArray();
                if (!_handles.TryGetValue(handle, out var open) || Follow(open.Path) is not { } node)
                {
                    return Status(id, 4, "Bad handle");
                }

                if (node.Data.Count < offset + data.Length)
                {
                    node.Data.AddRange(new byte[offset + data.Length - node.Data.Count]);
                }

                for (var i = 0; i < data.Length; i++)
                {
                    node.Data[offset + i] = data[i];
                }

                return Status(id, 0);
            }

            case 7 or 17: // LSTAT, STAT
            {
                var path = Resolve(r.ReadUtf8String());
                var node = type == 17 ? Follow(path) : _nodes.GetValueOrDefault(path);
                return node is null ? Status(id, 2, "No such file") : Build(w => { w.WriteByte(105); w.WriteUInt32(id); WriteAttributes(w, node); });
            }

            case 8: // FSTAT
            {
                var handle = r.ReadUtf8String();
                return _handles.TryGetValue(handle, out var open) && Follow(open.Path) is { } node
                    ? Build(w => { w.WriteByte(105); w.WriteUInt32(id); WriteAttributes(w, node); })
                    : Status(id, 4, "Bad handle");
            }

            case 9 or 10: // SETSTAT, FSETSTAT
            {
                Node? node;
                if (type == 9)
                {
                    node = Follow(Resolve(r.ReadUtf8String()));
                }
                else
                {
                    node = _handles.TryGetValue(r.ReadUtf8String(), out var open) ? Follow(open.Path) : null;
                }

                if (node is null)
                {
                    return Status(id, 2, "No such file");
                }

                ApplyAttributes(ref r, node);
                return Status(id, 0);
            }

            case 11: // OPENDIR
            {
                var path = Resolve(r.ReadUtf8String());
                if (Follow(path) is not { IsDirectory: true })
                {
                    return Status(id, 2, "No such file");
                }

                var handle = "d" + _nextHandle++;
                _handles[handle] = (path, 0);
                return Build(w => { w.WriteByte(102); w.WriteUInt32(id); w.WriteString(handle); });
            }

            case 12: // READDIR
            {
                var handle = r.ReadUtf8String();
                if (!_handles.TryGetValue(handle, out var open))
                {
                    return Status(id, 4, "Bad handle");
                }

                if (EndlessListing)
                {
                    return Build(w => { w.WriteByte(104); w.WriteUInt32(id); w.WriteUInt32(0); });
                }

                if (RawListingName is not null && _rawListed.Add(handle))
                {
                    // The legacy-encoded name first (once per listing), then the rest as usual.
                    var file = new Node();
                    file.Data.AddRange("legacy"u8.ToArray());
                    return Build(w =>
                    {
                        w.WriteByte(104);
                        w.WriteUInt32(id);
                        w.WriteUInt32(1);
                        w.WriteString(RawListingName!);
                        w.WriteString(RawListingName!);
                        WriteAttributes(w, file);
                    });
                }

                var prefix = open.Path == "/" ? "/" : open.Path + "/";
                var entries = new List<(string Name, Node Node)> { (".", _nodes[open.Path]), ("..", _nodes[open.Path]) };
                entries.AddRange(_nodes
                    .Where(n => n.Key.StartsWith(prefix, StringComparison.Ordinal) && n.Key.Length > prefix.Length && !n.Key[prefix.Length..].Contains('/'))
                    .OrderBy(n => n.Key, StringComparer.Ordinal)
                    .Select(n => (n.Key[prefix.Length..], n.Value)));
                var batch = entries.Skip(open.Position).Take(ListingBatch).ToList();
                if (batch.Count == 0)
                {
                    return Status(id, 1, "EOF");
                }

                _handles[handle] = (open.Path, open.Position + batch.Count);
                return Build(w =>
                {
                    w.WriteByte(104);
                    w.WriteUInt32(id);
                    w.WriteUInt32((uint)batch.Count);
                    foreach (var (name, node) in batch)
                    {
                        w.WriteString(name);
                        w.WriteString($"-rw-r--r-- 1 tester tester {node.Data.Count} Nov 14 2023 {name}");
                        WriteAttributes(w, node);
                    }
                });
            }

            case 13: // REMOVE
            {
                var path = Resolve(r.ReadUtf8String());
                return !_nodes.TryGetValue(path, out var node) ? Status(id, 2, "No such file")
                    : node.IsDirectory ? Status(id, 4, "Is a directory")
                    : _nodes.Remove(path) ? Status(id, 0) : Status(id, 4);
            }

            case 14: // MKDIR
            {
                var path = Resolve(r.ReadUtf8String());
                if (_nodes.ContainsKey(path))
                {
                    return Status(id, 4, "File exists");
                }

                var directory = new Node { IsDirectory = true, Mode = 0x1ED };
                ApplyAttributes(ref r, directory);
                _nodes[path] = directory;
                return Status(id, 0);
            }

            case 15: // RMDIR
            {
                var path = Resolve(r.ReadUtf8String());
                if (!_nodes.TryGetValue(path, out var node) || !node.IsDirectory)
                {
                    return Status(id, 2, "No such file");
                }

                return _nodes.Keys.Any(k => k.StartsWith(path + "/", StringComparison.Ordinal)) ? Status(id, 4, "Directory not empty") : _nodes.Remove(path) ? Status(id, 0) : Status(id, 4);
            }

            case 16: // REALPATH (resolving links, as OpenSSH's realpath(3) does)
            {
                var path = Canonical(Resolve(r.ReadUtf8String()));
                return Build(w => { w.WriteByte(104); w.WriteUInt32(id); w.WriteUInt32(1); w.WriteString(path); w.WriteString(path); w.WriteUInt32(0); });
            }

            case 18: // RENAME (fails if the target exists, like OpenSSH)
                return Rename(id, Resolve(r.ReadUtf8String()), Resolve(r.ReadUtf8String()), overwrite: false);

            case 19: // READLINK
            {
                var path = Resolve(r.ReadUtf8String());
                return _nodes.TryGetValue(path, out var node) && node.LinkTarget is { } target
                    ? Build(w => { w.WriteByte(104); w.WriteUInt32(id); w.WriteUInt32(1); w.WriteString(target); w.WriteString(target); w.WriteUInt32(0); })
                    : Status(id, 2, "No such file");
            }

            case 20: // SYMLINK, in OpenSSH's order (target, then link) unless SymlinkInDraftOrder
            {
                var first = r.ReadUtf8String();
                var second = r.ReadUtf8String();
                var (target, link) = SymlinkInDraftOrder ? (second, Resolve(first)) : (first, Resolve(second));
                if (_nodes.ContainsKey(link))
                {
                    return Status(id, 4, "File exists");
                }

                AddLink(link, target);
                return Status(id, 0);
            }

            case 200: // EXTENDED
            {
                var name = r.ReadUtf8String();
                switch (name)
                {
                    case "limits@openssh.com":
                        return Build(w =>
                        {
                            w.WriteByte(201);
                            w.WriteUInt32(id);
                            w.WriteUInt64(256 * 1024);
                            w.WriteUInt64(Limits.Read);
                            w.WriteUInt64(Limits.Write);
                            w.WriteUInt64(1024);
                        });
                    case "posix-rename@openssh.com":
                        return Rename(id, Resolve(r.ReadUtf8String()), Resolve(r.ReadUtf8String()), overwrite: true);
                    case "hardlink@openssh.com":
                    {
                        var existing = Resolve(r.ReadUtf8String());
                        var link = Resolve(r.ReadUtf8String());
                        if (!_nodes.TryGetValue(existing, out var node) || node.IsDirectory)
                        {
                            return Status(id, 2, "No such file");
                        }

                        _nodes[link] = node; // the same node: a write through either name shows in both
                        return Status(id, 0);
                    }

                    case "fsync@openssh.com":
                        Fsyncs++;
                        return _handles.ContainsKey(r.ReadUtf8String()) ? Status(id, 0) : Status(id, 4, "Bad handle");
                    case "statvfs@openssh.com":
                        r.ReadUtf8String();
                        return Build(w =>
                        {
                            w.WriteByte(201);
                            w.WriteUInt32(id);
                            foreach (var value in new ulong[] { 4096, 4096, 1000, 400, 300, 5000, 2000, 1500, 42, 1, 255 })
                            {
                                w.WriteUInt64(value);
                            }
                        });
                    case "copy-data":
                    {
                        var from = r.ReadUtf8String();
                        var fromOffset = (int)r.ReadUInt64();
                        var length = (int)r.ReadUInt64();
                        var to = r.ReadUtf8String();
                        var toOffset = (int)r.ReadUInt64();
                        if (!_handles.TryGetValue(from, out var source) || !_handles.TryGetValue(to, out var target)
                            || Follow(source.Path) is not { } sourceNode || Follow(target.Path) is not { } targetNode)
                        {
                            return Status(id, 4, "Bad handle");
                        }

                        var data = sourceNode.Data.Skip(fromOffset).Take(length == 0 ? int.MaxValue : length).ToArray();
                        if (targetNode.Data.Count < toOffset + data.Length)
                        {
                            targetNode.Data.AddRange(new byte[toOffset + data.Length - targetNode.Data.Count]);
                        }

                        for (var i = 0; i < data.Length; i++)
                        {
                            targetNode.Data[toOffset + i] = data[i];
                        }

                        return Status(id, 0);
                    }

                    case "expand-path@openssh.com":
                    {
                        // ~ and ~/... start at the home directory, ~user/... at /home/user; the rest resolves as REALPATH does.
                        var requested = r.ReadUtf8String();
                        if (requested.StartsWith('~'))
                        {
                            var slash = requested.IndexOf('/', StringComparison.Ordinal);
                            var user = slash < 0 ? requested[1..] : requested[1..slash];
                            var rest = slash < 0 ? string.Empty : requested[slash..];
                            requested = (user.Length == 0 ? Home : "/home/" + user) + rest;
                        }

                        var path = Canonical(Resolve(requested));
                        return Build(w => { w.WriteByte(104); w.WriteUInt32(id); w.WriteUInt32(1); w.WriteString(path); w.WriteString(path); w.WriteUInt32(0); });
                    }

                    case "lsetstat@openssh.com":
                    {
                        // The link itself, not what it points to.
                        if (!_nodes.TryGetValue(Resolve(r.ReadUtf8String()), out var node))
                        {
                            return Status(id, 2, "No such file");
                        }

                        ApplyAttributes(ref r, node);
                        return Status(id, 0);
                    }

                    case "users-groups-by-id@openssh.com":
                    {
                        var users = ReadIds(r.ReadString());
                        var groups = ReadIds(r.ReadString());
                        return Build(w =>
                        {
                            w.WriteByte(201);
                            w.WriteUInt32(id);
                            w.WriteString(Names(users, UserNames));
                            w.WriteString(Names(groups, GroupNames));
                        });
                    }

                    case "home-directory" when HomeDirectoryFailsForEmptyUser && r.ReadUtf8String().Length == 0:
                        return Status(id, 4, "Failure"); // OpenSSH before 10.x looks the empty name up as a user
                    case "home-directory":
                        return Build(w => { w.WriteByte(104); w.WriteUInt32(id); w.WriteUInt32(1); w.WriteString(HomeDirectoryAnswer ?? Home); w.WriteString(HomeDirectoryAnswer ?? Home); w.WriteUInt32(0); });
                    default:
                        return Status(id, 8, "Unsupported");
                }
            }

            default:
                return Status(id, 8, "Unsupported");
        }
    }

    private byte[] Rename(uint id, string from, string to, bool overwrite)
    {
        if (!_nodes.TryGetValue(from, out var node))
        {
            return Status(id, 2, "No such file");
        }

        if (_nodes.ContainsKey(to) && !overwrite)
        {
            return Status(id, 4, "File exists");
        }

        foreach (var key in _nodes.Keys.Where(k => k.StartsWith(from + "/", StringComparison.Ordinal)).ToList())
        {
            _nodes[to + key[from.Length..]] = _nodes[key];
            _nodes.Remove(key);
        }

        _nodes.Remove(from);
        _nodes[to] = node;
        return Status(id, 0);
    }
}

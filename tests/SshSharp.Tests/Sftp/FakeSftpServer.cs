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
    private int _nextHandle;

    /// <summary>The extensions announced in SSH_FXP_VERSION.</summary>
    public Dictionary<string, string> Extensions { get; } = new(StringComparer.Ordinal)
    {
        ["posix-rename@openssh.com"] = "1",
        ["hardlink@openssh.com"] = "1",
        ["limits@openssh.com"] = "1",
        ["home-directory"] = "1",
    };

    /// <summary>The read and write lengths announced with limits@openssh.com.</summary>
    public (ulong Read, ulong Write) Limits { get; set; } = (64 * 1024, 64 * 1024);

    /// <summary>Answer reads with at most half the bytes asked for (the draft allows short reads).</summary>
    public bool ShortReads { get; set; }

    /// <summary>Hold each reply back until the next request arrives, answering them in reverse pairs (replies may come in any order).</summary>
    public bool ReorderReplies { get; set; }

    /// <summary>The protocol version to announce.</summary>
    public uint Version { get; set; } = 3;

    /// <summary>Directory entries per SSH_FXP_NAME batch.</summary>
    public int ListingBatch { get; set; } = 3;

    /// <summary>The most requests waiting for a reply at once: more than one proves the client pipelines.</summary>
    public int MaxOutstanding { get; private set; }

    /// <summary>How many pairs of replies were sent in reverse order.</summary>
    public int ReorderedPairs { get; private set; }

    /// <summary>Every request type received, in order.</summary>
    public List<byte> Requests { get; } = [];

    /// <summary>How many handles are open now.</summary>
    public int OpenHandles => _handles.Count;

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

    public void Install(FakeSessionServer server) => server.Subsystems["sftp"] = RunAsync;

    private async Task RunAsync(ExecScript script)
    {
        // A reader queues requests as they arrive and a responder answers them, so requests the client sends without waiting pile up
        // in the queue (MaxOutstanding), and two queued ones can be answered in reverse order.
        var queue = System.Threading.Channels.Channel.CreateUnbounded<byte[]>();
        var unanswered = 0;
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
                    lock (Requests)
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
            var reply = Handle(packet);
            if (ReorderReplies && packet[0] != 1 && queue.Reader.TryRead(out var next))
            {
                var nextReply = Handle(next);
                await script.StdoutAsync(Frame(nextReply!));
                await script.StdoutAsync(Frame(reply!));
                ReorderedPairs++;
                Interlocked.Add(ref unanswered, -2);
                continue;
            }

            await script.StdoutAsync(Frame(reply!));
            Interlocked.Decrement(ref unanswered);
        }

        await reader;
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
        lock (Requests)
        {
            Requests.Add(type);
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
            });
        }

        var id = r.ReadUInt32();
        switch (type)
        {
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

            case 16: // REALPATH
            {
                var path = Resolve(r.ReadUtf8String());
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

            case 20: // SYMLINK, in OpenSSH's order: target, then link
            {
                var target = r.ReadUtf8String();
                var link = Resolve(r.ReadUtf8String());
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

                    case "home-directory":
                        return Build(w => { w.WriteByte(104); w.WriteUInt32(id); w.WriteUInt32(1); w.WriteString(Home); w.WriteString(Home); w.WriteUInt32(0); });
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

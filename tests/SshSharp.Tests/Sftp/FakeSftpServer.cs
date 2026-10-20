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

    /// <summary>
    /// Hold a session's first request that <see cref="PipelineGateFor"/> matches (by default the first READ or WRITE), unanswered, until
    /// this many matching requests have arrived (0: no gate). Requests are answered in order, so all of them wait for a reply together.
    /// A test that checks the client sends such requests together (<see cref="MaxOutstanding"/>, <see cref="ReorderedPairs"/>,
    /// <see cref="MaxOpenFileHandles"/>) then does not depend on the client's next request winning a race against this server's reply,
    /// which a slow client loses (the instrumented build in the stress run did). A client that never sends that many at once is answered
    /// after <see cref="PipelineGateLimit"/>, and the test's assertion fails.
    /// </summary>
    public int PipelineGate { get; set; }

    /// <summary>The requests (the raw packet, type first) the <see cref="PipelineGate"/> holds and counts: READ and WRITE by default.</summary>
    public Func<byte[], bool> PipelineGateFor { get; set; } = static packet => packet[0] is 5 or 6;

    /// <summary>How long the <see cref="PipelineGate"/> waits for the client before answering anyway: only a client that does not pipeline waits it out.</summary>
    public TimeSpan PipelineGateLimit { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>List every entry twice, as a broken or hostile server might.</summary>
    public bool ListEntriesTwice { get; set; }

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

    /// <summary>Refuse to open a file for writing while another handle has it open for writing (a server with one writer per file).</summary>
    public bool RefuseSecondWriter { get; set; }

    /// <summary>Refuse a WRITE anywhere but at the file's current end (a server that stores files as objects, written from the start).</summary>
    public bool WritesInOrderOnly { get; set; }

    /// <summary>Refuse to set a file's size (SETSTAT or FSETSTAT with a size): a server that cannot truncate.</summary>
    public bool RefuseSetSize { get; set; }

    /// <summary>The algorithms check-file and md5-hash hash with: the first of those asked for that is here is used.</summary>
    public List<string> HashAlgorithms { get; } = ["md5", "sha1", "sha256", "sha384", "sha512"];

    /// <summary>Every check-file or md5-hash request: its name, the file's path, the algorithms asked for, the offset and length.</summary>
    public List<(string Request, string Path, string Algorithms, long Offset, long Length)> HashRequests { get; } = [];

    /// <summary>The payloads of the vendor extension <c>echo@example.com</c>, which answers an EXTENDED_REPLY with the payload.</summary>
    public List<byte[]> Echoes { get; } = [];

    /// <summary>Extended requests answered with OP_UNSUPPORTED although the server handles them otherwise (announced or not).</summary>
    public HashSet<string> UnsupportedRequests { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Requests (the raw packet, type first) this matches are answered only once <see cref="Released"/> completes, and so is every
    /// later request of the same session: a server that stops answering on one session.
    /// </summary>
    public Func<byte[], bool>? Hold { get; set; }

    /// <summary>Completed to answer the requests <see cref="Hold"/> holds.</summary>
    public TaskCompletionSource Released { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>How many requests <see cref="Hold"/> has held.</summary>
    public int Held => Volatile.Read(ref _held);

    private int _held;

    /// <summary>
    /// Once a request (the raw packet, type first) this matches has arrived, its session stops reading what the client sends, and so
    /// stops opening the channel's window, until <see cref="ReadingResumed"/> completes: an <c>sftp-server</c> that hangs while sshd
    /// goes on (and answers keep-alives). The requests that arrived before are still answered.
    /// </summary>
    public Func<byte[], bool>? StopReading { get; set; }

    /// <summary>Completed to let sessions <see cref="StopReading"/> stopped read again.</summary>
    public TaskCompletionSource ReadingResumed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>How many sessions <see cref="StopReading"/> has stopped.</summary>
    public int StoppedReading => Volatile.Read(ref _stoppedReading);

    private int _stoppedReading;

    /// <summary>The offset of a WRITE request (the raw packet), or null for another request.</summary>
    public static long? WriteOffset(byte[] packet)
    {
        if (packet[0] != 6)
        {
            return null;
        }

        var handleLength = BinaryPrimitives.ReadInt32BigEndian(packet.AsSpan(5));
        return (long)BinaryPrimitives.ReadUInt64BigEndian(packet.AsSpan(9 + handleLength));
    }

    private readonly Dictionary<string, uint> _openFlags = new(StringComparer.Ordinal);

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

    /// <summary>Fails a WRITE at this offset with a Failure status, writing nothing (a full disk on the server, say).</summary>
    public Func<long, bool>? FailWriteAt { get; set; }

    /// <summary>Every WRITE's offset, in arrival order across sessions.</summary>
    public List<long> WriteOffsets { get; } = [];

    /// <summary>While set and not completed, the first WRITE (and every request behind it) waits for it before being answered.</summary>
    public TaskCompletionSource? HoldWrites { get; set; }

    /// <summary>
    /// How long every reply takes to reach the client, as on a link with this round-trip time: replies are delayed without holding up
    /// the requests behind them, so a client that pipelines pays the latency once per batch, not once per request. None by default.
    /// </summary>
    public TimeSpan Latency { get; set; }

    /// <summary>Answers OPEN of the paths this matches with Failure (a disk error on the server, say).</summary>
    public Func<string, bool>? FailOpen { get; set; }

    /// <summary>Describe a symbolic link in a listing by what it points to (stat rather than lstat), as a careless server might.</summary>
    public bool ListingFollowsLinks { get; set; }

    /// <summary>Answers REMOVE of the paths this matches with PERMISSION_DENIED, removing nothing (a file the user may not delete).</summary>
    public Func<string, bool>? DenyRemove { get; set; }

    /// <summary>The most file handles (not directory handles) open at once, across sessions.</summary>
    public int MaxOpenFileHandles { get; private set; }

    /// <summary>The open handles announced with limits@openssh.com (0: no limit).</summary>
    public ulong MaxHandles { get; set; } = 1024;

    /// <summary>The most READ and WRITE requests in flight at once, across sessions: from their arrival until their reply goes out.</summary>
    public int MaxDataRequestsInFlight => Volatile.Read(ref _maxDataInFlight);

    private int _dataInFlight;
    private int _maxDataInFlight;

    private void DataRequestArrived()
    {
        var now = Interlocked.Increment(ref _dataInFlight);
        int seen;
        while (now > (seen = Volatile.Read(ref _maxDataInFlight)) && Interlocked.CompareExchange(ref _maxDataInFlight, now, seen) != seen)
        {
        }
    }

    /// <summary>Answers OPENDIR of the paths this matches with PERMISSION_DENIED (a directory the user may not read).</summary>
    public Func<string, bool>? DenyOpenDir { get; set; }

    /// <summary>
    /// List each directory in reverse name order, as a server whose order is the file system's (not alphabetical) may: listings are
    /// otherwise sorted, which would hide a client that sorts, or a test that expects sorted entries.
    /// </summary>
    public bool ReverseListing { get; set; }

    /// <summary>
    /// What MKDIR of an existing path answers: Failure with "File exists" by default, as OpenSSH does; Apache MINA SSHD answers
    /// SSH_FX_FILE_ALREADY_EXISTS (11) with a message, and Erlang/OTP 11 with none.
    /// </summary>
    public (uint Code, string Message) MkdirExistingStatus { get; set; } = (4, "File exists");

    /// <summary>Answers a READDIR after the one that said EOF with Failure, instead of EOF again.</summary>
    public bool FailReaddirAfterEof { get; set; }

    private readonly HashSet<string> _listedToEnd = new(StringComparer.Ordinal);

    /// <summary>The most directory handles open at once, across sessions.</summary>
    public int MaxOpenDirectoryHandles { get; private set; }

    /// <summary>While set and not completed, the first READDIR (and every request behind it) waits for it before being answered.</summary>
    public TaskCompletionSource? HoldListings { get; set; }

    /// <summary>READDIR requests in flight now, and the most at once, across sessions: from their arrival until their reply goes out.</summary>
    public int ListingRequestsInFlight => Volatile.Read(ref _listingInFlight);

    /// <inheritdoc cref="ListingRequestsInFlight"/>
    public int MaxListingRequestsInFlight => Volatile.Read(ref _maxListingInFlight);

    private int _listingInFlight;
    private int _maxListingInFlight;

    private void ListingRequestArrived()
    {
        var now = Interlocked.Increment(ref _listingInFlight);
        int seen;
        while (now > (seen = Volatile.Read(ref _maxListingInFlight)) && Interlocked.CompareExchange(ref _maxListingInFlight, now, seen) != seen)
        {
        }
    }

    /// <summary>How many OPEN or MKDIR requests named a path whose parent directory did not exist (yet).</summary>
    public int MissingParents { get; private set; }

    /// <summary>The paths of the regular files that exist, below <paramref name="directory"/>.</summary>
    public List<string> FilesUnder(string directory)
    {
        lock (_nodes)
        {
            return [.. _nodes.Where(n => n.Key.StartsWith(directory + "/", StringComparison.Ordinal) && !n.Value.IsDirectory && n.Value.LinkTarget is null)
                .Select(n => n.Key).Order(StringComparer.Ordinal)];
        }
    }

    /// <summary>Whether the parent directory of the absolute <paramref name="path"/> exists.</summary>
    private bool ParentExists(string path) =>
        _nodes.TryGetValue(path[..Math.Max(1, path.LastIndexOf('/'))], out var parent) && parent.IsDirectory;

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
        var gateSize = PipelineGate;
        var gateFor = PipelineGateFor;
        var gateArrived = 0; // matching requests arrived (the reader's alone)
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (gateSize <= 1)
        {
            gate.SetResult();
        }

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
                    if (packet[0] is 5 or 6)
                    {
                        DataRequestArrived();
                    }
                    else if (packet[0] is 12)
                    {
                        ListingRequestArrived();
                    }

                    var now = Interlocked.Increment(ref unanswered);
                    lock (_requests)
                    {
                        MaxOutstanding = Math.Max(MaxOutstanding, now);
                    }

                    // Counted before the queueing, signalled after it: a reply reordered at the gate finds this request waiting. The
                    // first matching request is held, and every later one is queued behind it, so all those counted are unanswered.
                    var gateCounts = gateSize > 1 && gateFor(packet) && ++gateArrived >= gateSize;
                    queue.Writer.TryWrite(packet);
                    if (gateCounts)
                    {
                        gate.TrySetResult();
                    }

                    if (StopReading?.Invoke(packet) == true)
                    {
                        Interlocked.Increment(ref _stoppedReading);
                        await ReadingResumed.Task;
                    }
                }
            }

            gate.TrySetResult(); // the client sends nothing more
            queue.Writer.Complete();
        });

        // With Latency, replies go out through a sender that holds each one until it is due, while the responder goes on to the next
        // request: a round trip costs the latency, and requests sent together share it.
        var delayed = System.Threading.Channels.Channel.CreateUnbounded<(long Due, byte Type, byte[] Frame)>();
        var latency = Latency;
        var sender = latency <= TimeSpan.Zero ? Task.CompletedTask : Task.Run(async () =>
        {
            await foreach (var (due, type, frame) in delayed.Reader.ReadAllAsync())
            {
                var wait = System.Diagnostics.Stopwatch.GetElapsedTime(System.Diagnostics.Stopwatch.GetTimestamp(), due);
                if (wait > TimeSpan.Zero)
                {
                    await Task.Delay(wait);
                }

                Answered(type);
                await script.StdoutAsync(frame);
            }
        });

        async Task ReplyAsync(byte type, byte[] frame)
        {
            if (latency > TimeSpan.Zero)
            {
                delayed.Writer.TryWrite((System.Diagnostics.Stopwatch.GetTimestamp() + (long)(latency.TotalSeconds * System.Diagnostics.Stopwatch.Frequency), type, frame));
            }
            else
            {
                Answered(type);
                await script.StdoutAsync(frame);
            }
        }

        void Answered(byte type)
        {
            if (type is 5 or 6)
            {
                Interlocked.Decrement(ref _dataInFlight);
            }
            else if (type is 12)
            {
                Interlocked.Decrement(ref _listingInFlight);
            }
        }

        await foreach (var packet in queue.Reader.ReadAllAsync())
        {
            await Task.Yield(); // lets requests the client already sent arrive behind this one
            if (!gate.Task.IsCompleted && gateFor(packet))
            {
                try
                {
                    await gate.Task.WaitAsync(PipelineGateLimit);
                }
                catch (TimeoutException)
                {
                    // The client did not send them together: answered anyway, and the test's assertion fails.
                }

                gate.TrySetResult(); // only the first matching request waits
            }

            if (packet[0] is 3 or 11 && HoldOpens is { } hold)
            {
                lock (_requests)
                {
                    HeldOpens++;
                }

                await hold.Task;
            }

            if (packet[0] is 6 && HoldWrites is { } holdWrites)
            {
                await holdWrites.Task;
            }

            if (packet[0] is 12 && HoldListings is { } holdListings)
            {
                await holdListings.Task;
            }

            if (Hold?.Invoke(packet) == true)
            {
                Interlocked.Increment(ref _held);
                await Released.Task;
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
                Answered(packet[0]);
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
                Answered(next[0]);
                Answered(packet[0]);
                await script.StdoutAsync(Frame(nextReply!));
                await script.StdoutAsync(Frame(reply!));
                ReorderedPairs++;
                continue;
            }

            // Answered once its reply starts out, not once the send returns: the client can read the reply and send its next request
            // before then, and counting that one first made a single request in flight look like two (the stress run on arm64 saw it).
            Interlocked.Decrement(ref unanswered);
            await ReplyAsync(packet[0], Frame(reply!));
        }

        delayed.Writer.Complete();
        await sender;
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
                if (!ParentExists(path))
                {
                    MissingParents++;
                }

                if (FailOpen?.Invoke(path) == true)
                {
                    return Status(id, 4, "Input/output error");
                }

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

                if ((flags & 0x02) != 0 && RefuseSecondWriter
                    && _handles.Any(h => h.Value.Path == path && _openFlags.TryGetValue(h.Key, out var other) && (other & 0x02) != 0))
                {
                    return Status(id, 4, "Text file busy");
                }

                if ((flags & 0x10) != 0)
                {
                    node!.Data.Clear();
                }

                var handle = "h" + _nextHandle++;
                _handles[handle] = (path, 0);
                _openFlags[handle] = flags;
                MaxOpenFileHandles = Math.Max(MaxOpenFileHandles, _handles.Keys.Count(h => h.StartsWith('h')));
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

                WriteOffsets.Add(offset);
                if (FailWriteAt?.Invoke(offset) == true)
                {
                    return Status(id, 4, "No space left on device");
                }

                if (WritesInOrderOnly && offset != node.Data.Count)
                {
                    return Status(id, 4, "Out of order write");
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

                if (RefuseSetSize && (new SshReader(r.Remaining).ReadUInt32() & 0x01) != 0)
                {
                    return Status(id, 8, "Truncation is not supported");
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

                if (DenyOpenDir?.Invoke(path) == true)
                {
                    return Status(id, 3, "Permission denied");
                }

                var handle = "d" + _nextHandle++;
                _handles[handle] = (Canonical(path), 0); // a link to a directory lists the directory
                MaxOpenDirectoryHandles = Math.Max(MaxOpenDirectoryHandles, _handles.Keys.Count(k => k[0] == 'd'));
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
                    .OrderBy(n => n.Key, ReverseListing ? Comparer<string>.Create((x, y) => string.CompareOrdinal(y, x)) : StringComparer.Ordinal)
                    .Select(n => (n.Key[prefix.Length..], n.Value)));
                if (ListEntriesTwice)
                {
                    entries = [.. entries.SelectMany(e => new[] { e, e })];
                }

                var batch = entries.Skip(open.Position).Take(ListingBatch).ToList();
                if (batch.Count == 0)
                {
                    // A server may answer a READDIR after the end with an error rather than EOF again.
                    return FailReaddirAfterEof && !_listedToEnd.Add(handle) ? Status(id, 4, "Failure") : Status(id, 1, "EOF");
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
                        WriteAttributes(w, ListingFollowsLinks && node.LinkTarget is not null && Follow(prefix + name) is { } target ? target : node);
                    }
                });
            }

            case 13: // REMOVE
            {
                var path = Resolve(r.ReadUtf8String());
                if (DenyRemove?.Invoke(path) == true)
                {
                    return Status(id, 3, "Permission denied");
                }

                return !_nodes.TryGetValue(path, out var node) ? Status(id, 2, "No such file")
                    : node.IsDirectory ? Status(id, 4, "Is a directory")
                    : _nodes.Remove(path) ? Status(id, 0) : Status(id, 4);
            }

            case 14: // MKDIR
            {
                var path = Resolve(r.ReadUtf8String());
                if (_nodes.ContainsKey(path))
                {
                    return Status(id, MkdirExistingStatus.Code, MkdirExistingStatus.Message);
                }

                if (!ParentExists(path))
                {
                    MissingParents++;
                    return Status(id, 2, "No such file"); // as mkdir(2): the parent must exist
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
                if (UnsupportedRequests.Contains(name))
                {
                    return Status(id, 8, "Unsupported");
                }

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
                            w.WriteUInt64(MaxHandles);
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

                    case "check-file-name" or "check-file-handle" or "md5-hash" or "md5-hash-handle":
                        return HashFile(id, name, ref r);
                    case "echo@example.com":
                    {
                        var payload = r.Remaining.ToArray();
                        Echoes.Add(payload);
                        return Build(w => { w.WriteByte(201); w.WriteUInt32(id); w.WriteBytes(payload); });
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

    /// <summary>check-file-name, check-file-handle, md5-hash and md5-hash-handle, with a block size of 0 only (one hash per request).</summary>
    private byte[] HashFile(uint id, string request, ref SshReader r)
    {
        var target = r.ReadUtf8String();
        string path;
        if (request.EndsWith("-handle", StringComparison.Ordinal))
        {
            if (!_handles.TryGetValue(target, out var open))
            {
                return Status(id, 4, "Bad handle");
            }

            path = open.Path;
        }
        else
        {
            path = Resolve(target);
        }

        var md5 = request.StartsWith("md5", StringComparison.Ordinal);
        var algorithms = md5 ? "md5" : r.ReadUtf8String();
        var offset = (long)r.ReadUInt64();
        var length = (long)r.ReadUInt64();
        if (md5 ? r.ReadString().Length != 0 : r.ReadUInt32() != 0)
        {
            return Status(id, 8, "Quick-check and block hashes are not supported");
        }

        HashRequests.Add((request, path, algorithms, offset, length));
        if (Follow(path) is not { IsDirectory: false } node)
        {
            return Status(id, 2, "No such file");
        }

        var algorithm = algorithms.Split(',').FirstOrDefault(HashAlgorithms.Contains);
        if (algorithm is null)
        {
            return Status(id, 8, "No such hash algorithm");
        }

        var data = node.Data.Skip((int)Math.Min(offset, node.Data.Count)).Take(length == 0 ? int.MaxValue : (int)length).ToArray();
#pragma warning disable CA5350, CA5351 // the fake server computes what the client asks for: MD5 and SHA-1 are interop formats here, not security
        var hash = algorithm switch
        {
            "md5" => System.Security.Cryptography.MD5.HashData(data),
            "sha1" => System.Security.Cryptography.SHA1.HashData(data),
            "sha256" => System.Security.Cryptography.SHA256.HashData(data),
            "sha384" => System.Security.Cryptography.SHA384.HashData(data),
            _ => System.Security.Cryptography.SHA512.HashData(data),
        };
#pragma warning restore CA5350, CA5351
        return md5
            ? Build(w => { w.WriteByte(201); w.WriteUInt32(id); w.WriteString("md5-hash"); w.WriteString(hash); })
            : Build(w => { w.WriteByte(201); w.WriteUInt32(id); w.WriteString("check-file"); w.WriteString(algorithm); w.WriteBytes(hash); });
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

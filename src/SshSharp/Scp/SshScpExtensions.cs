using System.Globalization;

namespace SshSharp.Scp;

/// <summary>
/// File transfers with SCP (the server's <c>scp</c> program in sink or source mode). Uploads and downloads of single files, streams and
/// whole directories, with progress and cancellation. Names the server sends while downloading are checked: a file or directory name
/// must be a single path component, so nothing is ever written outside the target.
/// </summary>
public static class SshScpExtensions
{
    // ---- uploads ----

    /// <summary>Uploads <paramref name="localPath"/> to <paramref name="remotePath"/> (a file, or an existing directory to put it in).</summary>
    /// <exception cref="SshException">The remote scp refused or failed (<see cref="SshFailureReason.TransferFailed"/>).</exception>
    public static async Task UploadFileAsync(this SshClient client, string localPath, string remotePath, SshScpOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(localPath);
        options ??= new SshScpOptions();
        var file = new FileInfo(localPath);
        await using var source = file.OpenRead();
        await using var scp = await ScpChannel.StartAsync(client, options, "-t", remotePath, cancellationToken).ConfigureAwait(false);
        await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
        await SendFileAsync(scp, file.Name, source, file.Length, FileModeOf(file, options), Times(file), remotePath, options, cancellationToken).ConfigureAwait(false);
        await scp.FinishAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Uploads <paramref name="length"/> bytes of <paramref name="source"/> as the file <paramref name="remotePath"/>. The length is
    /// needed up front (SCP sends it before the data); a seekable stream's remaining length is used when it is null.
    /// </summary>
    /// <exception cref="SshException">The remote scp refused or failed (<see cref="SshFailureReason.TransferFailed"/>).</exception>
    public static async Task UploadAsync(this SshClient client, Stream source, string remotePath, long? length = null, SshScpOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(source);
        options ??= new SshScpOptions();
        var size = length ?? (source.CanSeek ? source.Length - source.Position : throw new ArgumentException("The length is needed for a stream that cannot seek.", nameof(length)));
        ArgumentOutOfRangeException.ThrowIfNegative(size, nameof(length));
        var name = RemoteFileName(remotePath);
        await using var scp = await ScpChannel.StartAsync(client, options, "-t", remotePath, cancellationToken).ConfigureAwait(false);
        await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
        await SendFileAsync(scp, name, source, size, options.FileMode, null, remotePath, options, cancellationToken).ConfigureAwait(false);
        await scp.FinishAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Uploads the directory <paramref name="localDirectory"/> and everything in it (<c>scp -r</c>). As with scp, it becomes
    /// <paramref name="remotePath"/> when that does not exist, or a directory inside it when it does.
    /// </summary>
    /// <exception cref="SshException">The remote scp refused or failed (<see cref="SshFailureReason.TransferFailed"/>).</exception>
    public static async Task UploadDirectoryAsync(this SshClient client, string localDirectory, string remotePath, SshScpOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(localDirectory);
        options ??= new SshScpOptions();
        var root = new DirectoryInfo(localDirectory);
        if (!root.Exists)
        {
            throw new DirectoryNotFoundException($"The directory '{localDirectory}' does not exist.");
        }

        await using var scp = await ScpChannel.StartAsync(client, options, "-r -t", remotePath, cancellationToken).ConfigureAwait(false);
        await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
        await SendDirectoryAsync(scp, root, root.Name, options, cancellationToken).ConfigureAwait(false);
        await scp.FinishAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task SendDirectoryAsync(ScpChannel scp, DirectoryInfo directory, string relative, SshScpOptions options, CancellationToken cancellationToken)
    {
        if (options.PreserveTimes)
        {
            await scp.SendLineAsync(TimesLine(directory.LastWriteTimeUtc, directory.LastAccessTimeUtc), cancellationToken).ConfigureAwait(false);
            await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
        }

        await scp.SendLineAsync($"D{Octal(options.DirectoryMode)} 0 {CheckName(directory.Name)}", cancellationToken).ConfigureAwait(false);
        await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
        foreach (var file in directory.EnumerateFiles().OrderBy(f => f.Name, StringComparer.Ordinal))
        {
            await using var source = file.OpenRead();
            await SendFileAsync(scp, file.Name, source, file.Length, FileModeOf(file, options), Times(file), $"{relative}/{file.Name}", options, cancellationToken).ConfigureAwait(false);
        }

        foreach (var child in directory.EnumerateDirectories().OrderBy(d => d.Name, StringComparer.Ordinal))
        {
            if (child.LinkTarget is not null)
            {
                continue; // like scp: a directory symlink is not followed, so a loop cannot make the transfer endless
            }

            await SendDirectoryAsync(scp, child, $"{relative}/{child.Name}", options, cancellationToken).ConfigureAwait(false);
        }

        await scp.SendLineAsync("E", cancellationToken).ConfigureAwait(false);
        await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task SendFileAsync(ScpChannel scp, string name, Stream source, long length, int mode, (DateTime Modified, DateTime Accessed)? times,
        string reportedPath, SshScpOptions options, CancellationToken cancellationToken)
    {
        if (options.PreserveTimes && times is { } t)
        {
            await scp.SendLineAsync(TimesLine(t.Modified, t.Accessed), cancellationToken).ConfigureAwait(false);
            await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
        }

        await scp.SendLineAsync($"C{Octal(mode)} {length.ToString(CultureInfo.InvariantCulture)} {CheckName(name)}", cancellationToken).ConfigureAwait(false);
        await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
        options.Progress?.Report(new SshScpProgress(reportedPath, 0, length));
        await scp.SendDataAsync(source, length, done => options.Progress?.Report(new SshScpProgress(reportedPath, done, length)), cancellationToken).ConfigureAwait(false);
        await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
    }

    // ---- downloads ----

    /// <summary>
    /// Downloads the remote file <paramref name="remotePath"/> to <paramref name="localPath"/> (a file, or an existing directory to put it
    /// in under the remote name).
    /// </summary>
    /// <exception cref="SshException">The file does not exist, is a directory, or the transfer failed (<see cref="SshFailureReason.TransferFailed"/>).</exception>
    public static async Task DownloadFileAsync(this SshClient client, string remotePath, string localPath, SshScpOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(localPath);
        options ??= new SshScpOptions();
        await using var scp = await ScpChannel.StartAsync(client, options, "-f", remotePath, cancellationToken).ConfigureAwait(false);
        var sink = new FileSink(localPath, directoryTarget: Directory.Exists(localPath), recursive: false, options);
        await ReceiveAsync(scp, sink, options, cancellationToken).ConfigureAwait(false);
        if (sink.Files == 0)
        {
            throw await scp.FailureAsync($"'{remotePath}' was not downloaded.").ConfigureAwait(false);
        }
    }

    /// <summary>Downloads the remote file <paramref name="remotePath"/> into <paramref name="destination"/>.</summary>
    /// <exception cref="SshException">The file does not exist, is a directory, or the transfer failed (<see cref="SshFailureReason.TransferFailed"/>).</exception>
    public static async Task DownloadAsync(this SshClient client, string remotePath, Stream destination, SshScpOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(destination);
        options ??= new SshScpOptions();
        await using var scp = await ScpChannel.StartAsync(client, options, "-f", remotePath, cancellationToken).ConfigureAwait(false);
        var sink = new StreamSink(destination);
        await ReceiveAsync(scp, sink, options, cancellationToken).ConfigureAwait(false);
        if (sink.Files == 0)
        {
            throw await scp.FailureAsync($"'{remotePath}' was not downloaded.").ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Downloads the remote directory <paramref name="remotePath"/> and everything in it (<c>scp -r</c>). As with scp, it becomes
    /// <paramref name="localDirectory"/> when that does not exist, or a directory inside it when it does.
    /// </summary>
    /// <exception cref="SshException">The transfer failed (<see cref="SshFailureReason.TransferFailed"/>).</exception>
    public static async Task DownloadDirectoryAsync(this SshClient client, string remotePath, string localDirectory, SshScpOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(localDirectory);
        options ??= new SshScpOptions();
        await using var scp = await ScpChannel.StartAsync(client, options, "-r -f", remotePath, cancellationToken).ConfigureAwait(false);
        var sink = new FileSink(localDirectory, directoryTarget: Directory.Exists(localDirectory), recursive: true, options);
        await ReceiveAsync(scp, sink, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The source side's messages, until it ends: files, directories, times, and errors for files it could not send.</summary>
    private static async Task ReceiveAsync(ScpChannel scp, Sink sink, SshScpOptions options, CancellationToken cancellationToken)
    {
        await scp.SendAckAsync(cancellationToken).ConfigureAwait(false); // ready
        (DateTime Modified, DateTime Accessed)? times = null;
        var errors = new List<string>();
        while (true)
        {
            var type = await scp.ReadByteAsync(cancellationToken).ConfigureAwait(false);
            if (type == -1)
            {
                break;
            }

            switch (type)
            {
                case 1 or 2:
                    // A file the source could not send (1), or a fatal error (2); it carries on after 1, so the rest still arrives.
                    errors.Add((await scp.ReadLineAsync(cancellationToken).ConfigureAwait(false)).Trim());
                    if (type == 2)
                    {
                        throw new SshException(SshFailureReason.TransferFailed, string.Join(" ", errors));
                    }

                    break;

                case 'T':
                    times = ParseTimes(await scp.ReadLineAsync(cancellationToken).ConfigureAwait(false))
                        ?? throw await scp.FailureAsync("The remote scp sent a malformed time line.").ConfigureAwait(false);
                    await scp.SendAckAsync(cancellationToken).ConfigureAwait(false);
                    break;

                case 'C':
                {
                    var (mode, size, name) = ParseEntry(await scp.ReadLineAsync(cancellationToken).ConfigureAwait(false))
                        ?? throw await scp.FailureAsync("The remote scp sent a malformed file line.").ConfigureAwait(false);
                    var path = sink.Describe(name);
                    var (destination, owned) = sink.OpenFile(name);
                    try
                    {
                        await scp.SendAckAsync(cancellationToken).ConfigureAwait(false);
                        options.Progress?.Report(new SshScpProgress(path, 0, size));
                        await scp.ReadDataAsync(destination, size, done => options.Progress?.Report(new SshScpProgress(path, done, size)), cancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        if (owned)
                        {
                            await destination.DisposeAsync().ConfigureAwait(false);
                        }
                    }

                    await scp.ReadAckAsync(cancellationToken).ConfigureAwait(false);
                    sink.Finish(name, mode, times);
                    times = null;
                    await scp.SendAckAsync(cancellationToken).ConfigureAwait(false);
                    break;
                }

                case 'D':
                {
                    var (mode, _, name) = ParseEntry(await scp.ReadLineAsync(cancellationToken).ConfigureAwait(false))
                        ?? throw await scp.FailureAsync("The remote scp sent a malformed directory line.").ConfigureAwait(false);
                    sink.EnterDirectory(name, mode, times);
                    times = null;
                    await scp.SendAckAsync(cancellationToken).ConfigureAwait(false);
                    break;
                }

                case 'E':
                    await scp.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    sink.LeaveDirectory();
                    await scp.SendAckAsync(cancellationToken).ConfigureAwait(false);
                    break;

                default:
                    throw await scp.FailureAsync($"The remote scp sent an unexpected message (byte {type}).").ConfigureAwait(false);
            }
        }

        if (errors.Count > 0)
        {
            throw new SshException(SshFailureReason.TransferFailed, string.Join(" ", errors));
        }

        await scp.FinishAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Where downloaded entries go.</summary>
    private abstract class Sink
    {
        public int Files { get; protected set; }

        public abstract string Describe(string name);

        /// <summary>Where the file's bytes go, and whether the transfer owns (and so disposes) that stream.</summary>
        public abstract (Stream Stream, bool Owned) OpenFile(string name);

        public abstract void Finish(string name, int mode, (DateTime Modified, DateTime Accessed)? times);

        public abstract void EnterDirectory(string name, int mode, (DateTime Modified, DateTime Accessed)? times);

        public abstract void LeaveDirectory();
    }

    /// <summary>One file into a caller's stream; anything else is a protocol surprise.</summary>
    private sealed class StreamSink(Stream destination) : Sink
    {
        public override string Describe(string name) => CheckName(name);

        public override (Stream Stream, bool Owned) OpenFile(string name)
        {
            if (Files++ > 0)
            {
                throw new SshException(SshFailureReason.TransferFailed, "The remote scp sent more than one file.");
            }

            return (destination, false); // the caller's stream stays open
        }

        public override void Finish(string name, int mode, (DateTime Modified, DateTime Accessed)? times)
        {
            // Nothing to set on a stream.
        }

        public override void EnterDirectory(string name, int mode, (DateTime Modified, DateTime Accessed)? times) =>
            throw new SshException(SshFailureReason.TransferFailed, "The remote path is a directory; use DownloadDirectoryAsync.");

        public override void LeaveDirectory() => throw new SshException(SshFailureReason.TransferFailed, "The remote scp ended a directory it never started.");
    }

    /// <summary>
    /// Files and directories on disk under a target. Every name is one checked path component, so writes stay inside the target whatever
    /// the server sends.
    /// </summary>
    private sealed class FileSink(string target, bool directoryTarget, bool recursive, SshScpOptions options) : Sink
    {
        private readonly Stack<string> _directories = new();
        private readonly Stack<(string Path, int Mode, (DateTime Modified, DateTime Accessed)? Times)> _pendingDirectories = new();
        private string? _lastFile;

        public override string Describe(string name) =>
            _directories.Count == 0 ? CheckName(name) : Path.GetRelativePath(target, Path.Combine(_directories.Peek(), CheckName(name)));

        private string FilePath(string name)
        {
            CheckName(name);
            if (_directories.Count > 0)
            {
                return Path.Combine(_directories.Peek(), name);
            }

            if (recursive)
            {
                throw new SshException(SshFailureReason.TransferFailed, "The remote path is a file; use DownloadFileAsync.");
            }

            if (Files > 0)
            {
                throw new SshException(SshFailureReason.TransferFailed, "The remote scp sent more than one file.");
            }

            return directoryTarget ? Path.Combine(target, name) : target;
        }

        public override (Stream Stream, bool Owned) OpenFile(string name)
        {
            var path = FilePath(name);
            Files++;
            _lastFile = path;
            return (new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: true), true);
        }

        public override void Finish(string name, int mode, (DateTime Modified, DateTime Accessed)? times) =>
            Apply(_lastFile!, mode, times, isDirectory: false);

        public override void EnterDirectory(string name, int mode, (DateTime Modified, DateTime Accessed)? times)
        {
            CheckName(name);
            if (!recursive)
            {
                throw new SshException(SshFailureReason.TransferFailed, "The remote path is a directory; use DownloadDirectoryAsync.");
            }

            // The top directory becomes the target, or goes inside it when it exists, as with scp -r.
            var path = _directories.Count > 0 ? Path.Combine(_directories.Peek(), name) : directoryTarget ? Path.Combine(target, name) : target;
            Directory.CreateDirectory(path);
            _directories.Push(path);
            _pendingDirectories.Push((path, mode, times));
        }

        public override void LeaveDirectory()
        {
            if (_directories.Count == 0)
            {
                throw new SshException(SshFailureReason.TransferFailed, "The remote scp ended a directory it never started.");
            }

            _directories.Pop();
            var (path, mode, times) = _pendingDirectories.Pop();
            Apply(path, mode, times, isDirectory: true); // after its contents, so writing them does not change its time again
        }

        private void Apply(string path, int mode, (DateTime Modified, DateTime Accessed)? times, bool isDirectory)
        {
            if (!options.PreserveTimes)
            {
                return;
            }

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, (UnixFileMode)(mode & 0x1FF)); // the rwx bits only, never set-id or sticky from the server
            }

            if (times is { } t)
            {
                if (isDirectory)
                {
                    Directory.SetLastWriteTimeUtc(path, t.Modified);
                    Directory.SetLastAccessTimeUtc(path, t.Accessed);
                }
                else
                {
                    File.SetLastWriteTimeUtc(path, t.Modified);
                    File.SetLastAccessTimeUtc(path, t.Accessed);
                }
            }
        }
    }

    // ---- protocol helpers ----

    /// <summary>
    /// A name from (or for) a control line must be a single path component: not empty, <c>.</c> or <c>..</c>, without separators (either
    /// kind, whatever this system uses), drive colons or control characters. This is what keeps a malicious server's names inside the target.
    /// </summary>
    internal static string CheckName(string name)
    {
        if (name.Length == 0 || name is "." or ".." || name.Any(c => c is '/' or '\\' or ':' || char.IsControl(c)))
        {
            throw new SshException(SshFailureReason.TransferFailed, $"'{name}' is not an acceptable file name.");
        }

        return name;
    }

    /// <summary><c>Cmmmm size name</c> or <c>Dmmmm 0 name</c>, without the type letter; null when malformed.</summary>
    internal static (int Mode, long Size, string Name)? ParseEntry(string line)
    {
        var parts = line.Split(' ', 3);
        if (parts.Length != 3 || parts[0].Length is < 3 or > 4 || !parts[0].All(c => c is >= '0' and <= '7')
            || !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var size))
        {
            return null;
        }

        return (Convert.ToInt32(parts[0], 8), size, CheckName(parts[2]));
    }

    /// <summary><c>mtime 0 atime 0</c> (seconds since 1970), without the type letter; null when malformed.</summary>
    internal static (DateTime Modified, DateTime Accessed)? ParseTimes(string line)
    {
        var parts = line.Split(' ');
        if (parts.Length != 4 || !long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var modified)
            || !long.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var accessed)
            || modified > 253402300799 || accessed > 253402300799)
        {
            return null;
        }

        return (DateTime.UnixEpoch.AddSeconds(modified), DateTime.UnixEpoch.AddSeconds(accessed));
    }

    private static string TimesLine(DateTime modified, DateTime accessed) =>
        string.Create(CultureInfo.InvariantCulture, $"T{Seconds(modified)} 0 {Seconds(accessed)} 0");

    private static long Seconds(DateTime time) => Math.Max(0, (long)(time.ToUniversalTime() - DateTime.UnixEpoch).TotalSeconds);

    private static string Octal(int mode) => Convert.ToString(mode & 0xFFF, 8).PadLeft(4, '0');

    private static (DateTime Modified, DateTime Accessed) Times(FileSystemInfo info) => (info.LastWriteTimeUtc, info.LastAccessTimeUtc);

    /// <summary>The source file's permission bits when they are preserved on a system that has them, otherwise the configured mode.</summary>
    private static int FileModeOf(FileInfo file, SshScpOptions options) =>
        options.PreserveTimes && !OperatingSystem.IsWindows() ? (int)file.UnixFileMode & 0x1FF : options.FileMode;

    /// <summary>The name to send for a stream upload: the last component of the remote path.</summary>
    private static string RemoteFileName(string remotePath)
    {
        var name = remotePath.TrimEnd('/');
        name = name[(name.LastIndexOf('/') + 1)..];
        return name.Length > 0 ? name : throw new ArgumentException("The remote path must name a file.", nameof(remotePath));
    }
}

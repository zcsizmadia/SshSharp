using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using SshSharp.Sftp;
using SshNet = Renci.SshNet;

namespace SshSharp.Benchmarks;

/// <summary>
/// SFTP: SshSharp's <see cref="SftpClient"/> against SSH.NET's on the same server, with the same algorithms (see
/// <see cref="ComparisonBenchmarks"/> for the connection settings): a 32 MiB upload from memory, a 32 MiB download into
/// <see cref="Stream.Null"/>, and 32 MiB copied into a stream opened for writing. Each library works in a remote directory of its own
/// under <c>/tmp</c>, removed in <see cref="CleanUp"/>. Allocated bytes and Gen0/1/2 collections show how much each transfer costs
/// the garbage collector. See docs/benchmarks.md.
/// </summary>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "BenchmarkDotNet disposes through GlobalCleanup.")]
public class SftpBenchmarks
{
    private const int TransferBytes = ComparisonBenchmarks.TransferBytes;

    private readonly byte[] _payload = new byte[TransferBytes];
    private readonly string _directory = $"/tmp/sshsharp-sftp-bench-{Guid.NewGuid():N}";
    private SshClient _sshSharp = null!;
    private SftpClient _sftp = null!;
    private SshNet.SftpClient _sshNet = null!;

    private string DownloadPath => _directory + "/download.bin";

    [GlobalSetup]
    public async Task SetUp()
    {
        _sshSharp = await ComparisonBenchmarks.ConnectSshSharpAsync();
        _sftp = await _sshSharp.OpenSftpAsync();
        _sshNet = new SshNet.SftpClient(ComparisonBenchmarks.SshNetConnection());
        await _sshNet.ConnectAsync(CancellationToken.None);

        Random.Shared.NextBytes(_payload);
        await _sftp.CreateDirectoryAsync(_directory);
        await _sftp.UploadAsync(new MemoryStream(_payload), DownloadPath); // the file both libraries download
    }

    [GlobalCleanup]
    public async Task CleanUp()
    {
        await foreach (var entry in _sftp.ListDirectoryAsync(_directory))
        {
            await _sftp.DeleteFileAsync(entry.FullPath);
        }

        await _sftp.DeleteDirectoryAsync(_directory);
        await _sftp.DisposeAsync();
        await _sshSharp.DisposeAsync();
        _sshNet.Dispose();
    }

    // ---- 32 MiB uploaded from memory ----

    [Benchmark(Baseline = true), BenchmarkCategory("SftpUpload32MiB")]
    public Task Upload_SshNet() => _sshNet.UploadFileAsync(new MemoryStream(_payload), _directory + "/upload-sshnet.bin", CancellationToken.None);

    [Benchmark, BenchmarkCategory("SftpUpload32MiB")]
    public Task<long> Upload_SshSharp() => _sftp.UploadAsync(new MemoryStream(_payload), _directory + "/upload-sshsharp.bin");

    // ---- 32 MiB downloaded, the data dropped ----

    [Benchmark(Baseline = true), BenchmarkCategory("SftpDownload32MiB")]
    public Task Download_SshNet() => _sshNet.DownloadFileAsync(DownloadPath, Stream.Null, CancellationToken.None);

    [Benchmark, BenchmarkCategory("SftpDownload32MiB")]
    public async Task<long> Download_SshSharp() => Check(await _sftp.DownloadAsync(DownloadPath, Stream.Null));

    // ---- 32 MiB copied into a remote file opened as a stream ----

    [Benchmark(Baseline = true), BenchmarkCategory("SftpOpenWrite32MiB")]
    public async Task OpenWrite_SshNet()
    {
        await using var remote = await _sshNet.OpenAsync(_directory + "/stream-sshnet.bin", FileMode.Create, FileAccess.Write, CancellationToken.None);
        await new MemoryStream(_payload).CopyToAsync(remote);
    }

    [Benchmark, BenchmarkCategory("SftpOpenWrite32MiB")]
    public async Task OpenWrite_SshSharp()
    {
        await using var remote = await _sftp.OpenWriteAsync(_directory + "/stream-sshsharp.bin");
        await new MemoryStream(_payload).CopyToAsync(remote);
    }

    private static long Check(long transferred) =>
        transferred == TransferBytes ? transferred : throw new InvalidOperationException($"Transferred {transferred} bytes, expected {TransferBytes}.");
}

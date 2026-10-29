using System.Diagnostics;

namespace SshSharp.Protocol;

/// <summary>
/// Runs an <c>ssh_config</c> <c>ProxyCommand</c> in the system shell and talks SSH over its standard input and output, as ssh does.
/// Its standard error is read and discarded (ssh shows it on the terminal; a library has none). Disposing ends the process.
/// </summary>
internal sealed class ProxyCommandStream : Stream
{
    private readonly Process _process;
    private readonly Stream _output;
    private readonly Stream _input;
    private int _disposed;

    private ProxyCommandStream(Process process)
    {
        _process = process;
        _output = process.StandardOutput.BaseStream;
        _input = process.StandardInput.BaseStream;
    }

    /// <summary>Starts <paramref name="command"/> (already token-expanded) with <c>/bin/sh -c "exec ..."</c>, or <c>cmd.exe /c</c> on Windows.</summary>
    public static ProxyCommandStream Start(string command)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        var windows = OperatingSystem.IsWindows();
        var info = new ProcessStartInfo(windows ? "cmd.exe" : "/bin/sh")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        if (windows)
        {
            info.Arguments = "/d /s /c \"" + command + "\"";
        }
        else
        {
            // exec, as ssh does, so the shell is replaced and disposing reaches the command itself.
            info.ArgumentList.Add("-c");
            info.ArgumentList.Add("exec " + command);
        }

        var process = ProcessTree.Start(info) ?? throw new SshException(SshFailureReason.ConnectFailed, "The ProxyCommand could not be started.");
        process.ErrorDataReceived += static (_, _) => { };
        process.BeginErrorReadLine();
        return new ProxyCommandStream(process);
    }

    public override bool CanRead => true;

    public override bool CanWrite => true;

    public override bool CanSeek => false;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => _output.ReadAsync(buffer, cancellationToken);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _output.ReadAsync(buffer, offset, count, cancellationToken);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        _input.WriteAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _input.WriteAsync(buffer, offset, count, cancellationToken);

    public override Task FlushAsync(CancellationToken cancellationToken) => _input.FlushAsync(cancellationToken);

    public override void Flush() => _input.Flush();

    public override int Read(byte[] buffer, int offset, int count) => _output.Read(buffer, offset, count);

    public override void Write(byte[] buffer, int offset, int count) => _input.Write(buffer, offset, count);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try
            {
                if (!_process.HasExited)
                {
                    ProcessTree.Kill(_process);
                }
            }
            catch (InvalidOperationException)
            {
                // Already exited.
            }

            try
            {
                _input.Dispose(); // flushes; the process may already be gone
            }
            catch (IOException)
            {
                // The pipe is closed: nothing left to deliver.
            }

            _output.Dispose();
            _process.Dispose();
        }

        base.Dispose(disposing);
    }
}

using System.IO.Abstractions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using SshSharp;
using SshSharp.FileProviders;
using SshSharp.IO.Abstractions;
using SshSharp.Sftp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/file-system-adapters.md.</summary>
internal static class FileSystems
{
    // <report-writer>
    /// <summary>Code written against IFileSystem: it does not know, or care, where the files are.</summary>
    public sealed class ReportWriter(IFileSystem fileSystem)
    {
        public async Task WriteAsync(string directory, string name, string text, CancellationToken cancellationToken)
        {
            fileSystem.Directory.CreateDirectory(directory);
            var path = fileSystem.Path.Combine(directory, name);
            await fileSystem.File.WriteAllTextAsync(path, text, cancellationToken);
        }

        public IEnumerable<string> List(string directory) =>
            fileSystem.Directory.EnumerateFiles(directory, "*.txt", SearchOption.AllDirectories);
    }
    // </report-writer>

    public static async Task UseFileSystemAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <file-system>
        await using var sftp = await client.OpenSftpAsync(cancellationToken);
        IFileSystem remote = new SftpFileSystem(sftp, new SftpFileSystemOptions { OperationTimeout = TimeSpan.FromSeconds(30) });

        var writer = new ReportWriter(remote);                    // the same class works with new FileSystem() for local files
        await writer.WriteAsync("reports/2026", "summary.txt", "All green.", cancellationToken);
        foreach (var file in writer.List("reports"))
        {
            Console.WriteLine(file);                               // POSIX paths: reports/2026/summary.txt
        }
        // </file-system>
    }

    public static async Task CopyBetweenAsync(SshClient client, CancellationToken cancellationToken)
    {
        // <copy-between>
        // A local file into a remote one, stream to stream.
        await using var sftp = await client.OpenSftpAsync(cancellationToken);
        IFileSystem remote = new SftpFileSystem(sftp);

        await using var source = File.OpenRead("build/app.zip");
        await using var target = remote.File.Create("/srv/drop/app.zip");
        await source.CopyToAsync(target, cancellationToken);
        // </copy-between>
    }

    public static async Task StaticFilesAsync(WebApplication app)
    {
        // <file-provider>
        // Static files served from /srv/www on the server. The provider keeps one SFTP session for the application's lifetime.
        var ssh = await SshClient.ConnectAsync(app.Configuration["Ssh:Alias"] ?? "web-content");
        var sftp = await ssh.OpenSftpAsync();
        var provider = new SftpFileProvider(sftp, "/srv/www", new SftpFileProviderOptions { CacheDuration = TimeSpan.FromSeconds(30) });

        app.UseStaticFiles(new StaticFileOptions { FileProvider = provider, RequestPath = "/content" });
        app.Lifetime.ApplicationStopped.Register(() =>
        {
            sftp.DisposeAsync().AsTask().GetAwaiter().GetResult();   // the provider does not own the session
            ssh.DisposeAsync().AsTask().GetAwaiter().GetResult();
        });
        // </file-provider>
    }

    public static void Configuration(SftpClient sftp, IConfigurationBuilder configuration)
    {
        // <configuration>
        // Read a JSON configuration file that lives on the server (read once: SFTP has no change notifications).
        var provider = new SftpFileProvider(sftp, "/etc/myapp");
        configuration.AddJsonFile(provider, "appsettings.json", optional: false, reloadOnChange: false);
        // </configuration>
    }
}

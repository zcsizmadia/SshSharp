using System.Net;
using SshSharp;

namespace SshSharp.Docs.Snippets.Scenarios;

/// <summary>docs/scenarios/database-tunnel.md.</summary>
internal static class DatabaseTunnel
{
    // <tunnel>
    /// <summary>An SSH connection to the bastion and a local port forwarded to the database, for as long as it is not disposed.</summary>
    public sealed class DatabaseTunnelHandle : IAsyncDisposable
    {
        private readonly SshClient _bastion;
        private readonly SshLocalPortForwarder _forwarder;

        private DatabaseTunnelHandle(SshClient bastion, SshLocalPortForwarder forwarder) => (_bastion, _forwarder) = (bastion, forwarder);

        /// <summary>The local port the database is reachable on.</summary>
        public int Port => _forwarder.LocalEndPoint.Port;

        /// <summary>Cancelled when the SSH connection drops: the tunnel is gone, and with it the database connections.</summary>
        public CancellationToken Closed => _bastion.ConnectionClosed;

        public static async Task<DatabaseTunnelHandle> OpenAsync(string bastionAlias, string databaseHost, int databasePort,
            CancellationToken cancellationToken)
        {
            var bastion = await SshClient.ConnectAsync(bastionAlias, cancellationToken: cancellationToken);
            try
            {
                // Loopback only, port 0: a free port, reachable from this machine and nowhere else.
                var forwarder = await bastion.ForwardLocalPortAsync(new IPEndPoint(IPAddress.Loopback, 0), databaseHost, databasePort,
                    cancellationToken);
                return new DatabaseTunnelHandle(bastion, forwarder);
            }
            catch
            {
                await bastion.DisposeAsync();
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _forwarder.DisposeAsync();
            await _bastion.DisposeAsync();
        }
    }
    // </tunnel>

    public static async Task UseAsync(CancellationToken cancellationToken)
    {
        // <use>
        await using var tunnel = await DatabaseTunnelHandle.OpenAsync("bastion", "db.internal", 5432, cancellationToken);

        // The database password from the environment or a secret store; the tunnel does not change how the database authenticates.
        var connectionString =
            $"Host=127.0.0.1;Port={tunnel.Port};Database=reports;Username=report_reader;" +
            $"Password={Environment.GetEnvironmentVariable("REPORTS_DB_PASSWORD")};SSL Mode=Require";

        // Hand the connection string to your ADO.NET provider (Npgsql here), Dapper or EF Core as usual:
        // await using var db = new NpgsqlConnection(connectionString);
        // await db.OpenAsync(cancellationToken);
        // </use>
        _ = connectionString;
    }
}

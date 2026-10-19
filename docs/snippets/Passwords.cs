using SshSharp;

namespace SshSharp.Docs.Snippets;

/// <summary>docs/how-to/passwords.md.</summary>
internal static class Passwords
{
    /// <summary>Reads a line without echoing it, as a terminal password prompt does.</summary>
    private static string ReadHidden()
    {
        var text = new System.Text.StringBuilder();
        for (var key = Console.ReadKey(intercept: true); key.Key != ConsoleKey.Enter; key = Console.ReadKey(intercept: true))
        {
            if (key.Key == ConsoleKey.Backspace && text.Length > 0)
            {
                text.Length--;
            }
            else if (!char.IsControl(key.KeyChar))
            {
                text.Append(key.KeyChar);
            }
        }

        Console.WriteLine();
        return text.ToString();
    }

    public static async Task PromptAsync(SshHostKeyVerifier verifier, IReadOnlyList<SshPrivateKey> keys, CancellationToken cancellationToken)
    {
        // <password-prompt>
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            PrivateKeys = keys,           // tried first: the prompt appears only if none of them logs in
            HostKeyVerifier = verifier,
            PasswordProvider = (prompt, ct) =>
            {
                if (prompt.IsRetry)
                {
                    Console.WriteLine("Permission denied, please try again.");
                }

                Console.Write($"{prompt.UserName}@{prompt.Host}'s password: ");
                return ValueTask.FromResult<string?>(ReadHidden()); // or null to stop asking
            },
            NumberOfPasswordPrompts = 3,  // ssh's default
        }, cancellationToken);
        // </password-prompt>
    }

    public static async Task ChangeAsync(SshHostKeyVerifier verifier, CancellationToken cancellationToken)
    {
        // <password-change>
        await using var client = await SshClient.ConnectAsync("example.com", 22, new SshClientOptions
        {
            UserName = "deploy",
            Password = Environment.GetEnvironmentVariable("DEPLOY_PASSWORD"),
            HostKeyVerifier = verifier,
            ChangePassword = (request, ct) =>
            {
                // The server's text: strip control characters before showing it.
                var reason = new string(request.Prompt.Where(c => !char.IsControl(c)).ToArray());
                Console.WriteLine(reason.Length > 0 ? reason : "Your password has expired.");
                Console.Write("New password: ");
                var first = ReadHidden();
                Console.Write("Retype new password: ");
                return ValueTask.FromResult<string?>(first == ReadHidden() ? first : null); // null: leave it unchanged
            },
        }, cancellationToken);
        // </password-change>
    }

    public static async Task FailureDetailAsync(SshClientOptions options, CancellationToken cancellationToken)
    {
        // <failure-detail>
        try
        {
            await using var client = await SshClient.ConnectAsync("example.com", 22, options, cancellationToken);
        }
        catch (SshAuthenticationException ex)
        {
            Console.Error.WriteLine($"Login failed; the server accepts: {string.Join(", ", ex.AllowedMethods)}");
            foreach (var attempt in ex.Attempts)
            {
                // For example "publickey SHA256:... (Rejected)", "password (PasswordChangeRequired)".
                Console.Error.WriteLine($"  {attempt.Method} {attempt.KeyFingerprint} {attempt.Outcome}");
            }
        }
        // </failure-detail>
    }

    public static async Task ConfigAsync(CancellationToken cancellationToken)
    {
        // <password-config>
        // ~/.ssh/config:  Host build
        //                   HostName build.example.com
        //                   NumberOfPasswordPrompts 2
        await using var client = await SshClient.ConnectAsync("build", new SshConfigConnectOptions
        {
            PasswordProvider = (prompt, ct) =>
            {
                Console.Write($"{prompt.UserName}@{prompt.Host}'s password: ");
                return ValueTask.FromResult<string?>(ReadHidden());
            },
        }, cancellationToken);
        // </password-config>
    }
}

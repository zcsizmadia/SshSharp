namespace SshSharp;

/// <summary>One question in a keyboard-interactive round.</summary>
/// <param name="Text">The prompt, for example <c>Password: </c> or <c>Verification code: </c>. Server-supplied text: strip control
/// characters before showing it in a terminal.</param>
/// <param name="Echo">Whether the answer may be shown as it is typed. False for passwords and other secrets.</param>
public sealed record SshAuthenticationPrompt(string Text, bool Echo);

/// <summary>
/// A round of keyboard-interactive authentication (RFC 4256): the server's questions, answered by
/// <see cref="SshClientOptions.KeyboardInteractive"/>. All text comes from the server: strip control characters before showing it in
/// a terminal.
/// </summary>
public sealed class SshKeyboardInteractiveRequest
{
    internal SshKeyboardInteractiveRequest(string name, string instruction, IReadOnlyList<SshAuthenticationPrompt> prompts)
    {
        Name = name;
        Instruction = instruction;
        Prompts = prompts;
    }

    /// <summary>A title for the round, often empty.</summary>
    public string Name { get; }

    /// <summary>Text to show before the prompts, often empty.</summary>
    public string Instruction { get; }

    /// <summary>The questions, in order. A round may have none (the server only shows <see cref="Instruction"/>); answer it with an empty list.</summary>
    public IReadOnlyList<SshAuthenticationPrompt> Prompts { get; }
}

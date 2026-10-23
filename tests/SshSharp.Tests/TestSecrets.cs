using System.Security.Cryptography;

namespace SshSharp.Tests;

/// <summary>
/// Passwords and passphrases for tests, generated per run so that none is written down (CONTRIBUTING.md). A test that
/// needs a wrong one asks for another <see cref="New"/>, which differs from every other value with overwhelming probability.
/// </summary>
internal static class TestSecrets
{
    /// <summary>The password the fake servers accept unless a test sets its own, and that tests sign in to them with.</summary>
    public static string Password { get; } = New();

    /// <summary>A fresh random password or passphrase: 24 hex characters.</summary>
    public static string New() => Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
}

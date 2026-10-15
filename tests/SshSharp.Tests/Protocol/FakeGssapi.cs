using System.Net;
using System.Security.Cryptography;
using System.Text;
using SshSharp.Protocol;

namespace SshSharp.Tests.Protocol;

/// <summary>
/// A stand-in GSS-API mechanism for testing gssapi-with-mic without a KDC: the client sends C0, C1, ... and the server answers S1, S2, ...;
/// the client's context is established after <see cref="Rounds"/> answers (its last token is C&lt;Rounds&gt;), and the MIC is an HMAC
/// with a key both sides know.
/// </summary>
internal sealed class FakeGssapi(int rounds = 1) : IGssapiContext
{
    private static readonly byte[] Key = "fake gss-api session key"u8.ToArray();
    private int _received;

    public int Rounds => rounds;

    public string? Host { get; private set; }

    public bool Delegate { get; private set; }

    public NetworkCredential? Credential { get; private set; }

    public bool Disposed { get; private set; }

    /// <summary>Fails on this call to <see cref="Step"/> (0 is the first), as a missing ticket or unknown principal would.</summary>
    public int? FailAtStep { get; init; }

    private int _steps;

    public static byte[] Mic(byte[] data) => HMACSHA256.HashData(Key, data);

    /// <summary>The factory a test passes as the context factory; records what the client asked for.</summary>
    public Func<string, NetworkCredential?, bool, IGssapiContext> Factory => (host, credential, delegateCredentials) =>
    {
        Host = host;
        Credential = credential;
        Delegate = delegateCredentials;
        return this;
    };

    public byte[]? Step(ReadOnlySpan<byte> incoming, out bool complete)
    {
        if (_steps++ == FailAtStep)
        {
            throw new SshException(SshFailureReason.AuthenticationFailed, "Kerberos (GSS-API) failed: no credentials.");
        }

        if (!incoming.IsEmpty)
        {
            var token = Encoding.ASCII.GetString(incoming);
            if (token != $"S{_received + 1}")
            {
                throw new SshException(SshFailureReason.AuthenticationFailed, $"Kerberos (GSS-API) failed: unexpected token {token}.");
            }

            _received++;
        }

        complete = _received == rounds;
        return Encoding.ASCII.GetBytes($"C{_received}");
    }

    public byte[] GetMic(ReadOnlySpan<byte> data) => Mic(data.ToArray());

    public void Dispose() => Disposed = true;
}

/// <summary>What the fake server does with gssapi-with-mic.</summary>
internal sealed class FakeGssapiServer
{
    /// <summary>How many tokens the server answers before the client's context completes (matches <see cref="FakeGssapi.Rounds"/>).</summary>
    public int Rounds { get; init; } = 1;

    public bool ChooseWrongMechanism { get; init; }

    public bool FailWithErrorToken { get; init; }

    /// <summary>Rejects only the client's last token (the one that completes its context), with an error token, as OpenSSH does.</summary>
    public bool FailLastTokenWithErrorToken { get; init; }

    public bool SendStatusMessage { get; init; }

    public bool RejectMic { get; init; }
}

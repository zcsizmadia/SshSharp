using System.Buffers;

namespace SshSharp.Protocol;

/// <summary>The result of one authentication attempt.</summary>
/// <param name="Success">Whether the server accepted it.</param>
/// <param name="RemainingMethods">The methods the server will still accept (from <c>SSH_MSG_USERAUTH_FAILURE</c>).</param>
/// <param name="PartialSuccess">Whether the attempt succeeded but the server requires further methods.</param>
internal sealed record AuthOutcome(bool Success, IReadOnlyList<string> RemainingMethods, bool PartialSuccess);

/// <summary>Client side of user authentication (RFC 4252).</summary>
internal static class SshUserAuth
{
    private const string ServiceName = "ssh-userauth";
    private const string ConnectionService = "ssh-connection";

    /// <summary>Asks the server to start the <c>ssh-userauth</c> service.</summary>
    public static async Task RequestServiceAsync(SshTransport transport, CancellationToken cancellationToken)
    {
        await transport.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.ServiceRequest);
            w.WriteString(ServiceName);
        }), cancellationToken).ConfigureAwait(false);

        using var reply = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        var reader = new SshReader(reply.Payload.Span);
        var type = reader.ReadByte();
        if (type != SshMessage.ServiceAccept || reader.ReadUtf8String() != ServiceName)
        {
            throw new SshException(SshFailureReason.ProtocolError, $"The server did not accept the {ServiceName} service (message {type}).");
        }
    }

    /// <summary>The <c>none</c> method: usually fails, but tells us which methods the server accepts.</summary>
    public static Task<AuthOutcome> NoneAsync(SshTransport transport, string userName, CancellationToken cancellationToken) =>
        RequestAsync(transport, userName, "none", null, cancellationToken);

    /// <summary>The <c>password</c> method (RFC 4252 section 8).</summary>
    public static Task<AuthOutcome> PasswordAsync(SshTransport transport, string userName, string password, CancellationToken cancellationToken) =>
        RequestAsync(transport, userName, "password", w =>
        {
            w.WriteBoolean(false); // not a password change
            w.WriteString(password);
        }, cancellationToken);

    private static async Task<AuthOutcome> RequestAsync(SshTransport transport, string userName, string method, Action<SshWriter>? body, CancellationToken cancellationToken)
    {
        await transport.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.UserAuthRequest);
            w.WriteString(userName);
            w.WriteString(ConnectionService);
            w.WriteString(method);
            body?.Invoke(w);
        }), cancellationToken).ConfigureAwait(false);

        while (true)
        {
            using var reply = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            var reader = new SshReader(reply.Payload.Span);
            var type = reader.ReadByte();
            switch (type)
            {
                case SshMessage.UserAuthBanner:
                    continue; // shown to the user by interactive clients; ignored here
                case SshMessage.UserAuthSuccess:
                    return new AuthOutcome(true, [], false);
                case SshMessage.UserAuthFailure:
                    var methods = reader.ReadNameList();
                    return new AuthOutcome(false, methods, reader.ReadBoolean());
                case SshMessage.UserAuthPkOk when method == "password":
                    // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ shares the number 60.
                    throw new SshException(SshFailureReason.AuthenticationFailed, "The server requires the password to be changed.");
                default:
                    throw new SshProtocolException($"Unexpected message {type} during user authentication.");
            }
        }
    }

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>(128);
        body(new SshWriter(buffer));
        return buffer.WrittenSpan.ToArray();
    }
}
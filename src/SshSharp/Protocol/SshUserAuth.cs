using System.Buffers;
using System.Security.Cryptography;

namespace SshSharp.Protocol;

/// <summary>The result of one authentication attempt.</summary>
/// <param name="Success">Whether the server accepted it.</param>
/// <param name="RemainingMethods">The methods the server will still accept (from <c>SSH_MSG_USERAUTH_FAILURE</c>).</param>
/// <param name="PartialSuccess">Whether the attempt succeeded but the server requires further methods.</param>
/// <param name="KeyAcceptable">For a publickey query: the server would accept this key with a signature (<c>SSH_MSG_USERAUTH_PK_OK</c>).</param>
internal sealed record AuthOutcome(bool Success, IReadOnlyList<string> RemainingMethods, bool PartialSuccess, bool KeyAcceptable = false);

/// <summary>Client side of user authentication (RFC 4252) for one connection.</summary>
internal sealed class SshUserAuth(SshTransport transport, string userName, Func<string, CancellationToken, ValueTask>? banner)
{
    private const string ServiceName = "ssh-userauth";
    private const string ConnectionService = "ssh-connection";

    /// <summary>OpenSSH's limit on prompts in one keyboard-interactive round.</summary>
    internal const int MaxPrompts = 100;

    /// <summary>Rounds of keyboard-interactive before the client gives up on a server that keeps asking.</summary>
    internal const int MaxRounds = 32;

    /// <summary>Asks the server to start the <c>ssh-userauth</c> service.</summary>
    public async Task RequestServiceAsync(CancellationToken cancellationToken)
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
    public Task<AuthOutcome> NoneAsync(CancellationToken cancellationToken) =>
        RequestAsync("none", null, Reply.None, cancellationToken);

    /// <summary>The <c>password</c> method (RFC 4252 section 8).</summary>
    public Task<AuthOutcome> PasswordAsync(string password, CancellationToken cancellationToken) =>
        RequestAsync("password", w =>
        {
            w.WriteBoolean(false); // not a password change
            w.WriteString(password);
        }, Reply.None, cancellationToken);

    /// <summary>
    /// The <c>publickey</c> method (RFC 4252 section 7). First asks whether the server would accept the key at all (no signature, so a
    /// refused key costs no private-key operation), then signs: session id, the request, and the chosen algorithm and public key.
    /// </summary>
    /// <remarks>
    /// When the server advertises <c>publickey-hostbound@openssh.com</c> (OpenSSH 8.9 and later), the request is host-bound
    /// (<c>publickey-hostbound-v00@openssh.com</c>, PROTOCOL section 3.1): it also carries the server's host key, which is then part of
    /// what is signed, so an agent can check the destination of a constrained key (<c>ssh-add -h</c>). Agent keys sign on a connection
    /// bound to this session (<c>session-bind@openssh.com</c>).
    /// </remarks>
    public async Task<AuthOutcome> PublicKeyAsync(SshPrivateKey key, string algorithm, CancellationToken cancellationToken)
    {
        var publicKey = key.PublicKey;
        var hostBound = transport.ServerExtensions.TryGetValue(HostBoundExtension, out var version) && version == "0" && transport.HostKey is not null;
        var method = hostBound ? HostBoundMethod : "publickey";
        var hostKey = hostBound ? transport.HostKey!.Presented : ReadOnlyMemory<byte>.Empty;

        var query = await RequestAsync(method, w =>
        {
            w.WriteBoolean(false);
            w.WriteString(algorithm);
            w.WriteString(publicKey.Span);
            if (hostBound)
            {
                w.WriteString(hostKey.Span);
            }
        }, Reply.PkOk, cancellationToken).ConfigureAwait(false);
        if (!query.KeyAcceptable)
        {
            // Refused (or, oddly, accepted without a signature): nothing to sign.
            return query;
        }

        var signed = Build(w =>
        {
            w.WriteString(transport.SessionId);
            w.WriteByte(SshMessage.UserAuthRequest);
            w.WriteString(userName);
            w.WriteString(ConnectionService);
            w.WriteString(method);
            w.WriteBoolean(true);
            w.WriteString(algorithm);
            w.WriteString(publicKey.Span);
            if (hostBound)
            {
                w.WriteString(hostKey.Span);
            }
        });
        var signature = await key.SignAsync(algorithm, signed, transport.AgentBinding, cancellationToken).ConfigureAwait(false);
        return await RequestAsync(method, w =>
        {
            w.WriteBoolean(true);
            w.WriteString(algorithm);
            w.WriteString(publicKey.Span);
            if (hostBound)
            {
                w.WriteString(hostKey.Span);
            }

            w.WriteString(signature);
        }, Reply.None, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The EXT_INFO extension a server advertises host-bound public key authentication with (value "0").</summary>
    internal const string HostBoundExtension = "publickey-hostbound@openssh.com";

    /// <summary>The host-bound public key method (PROTOCOL section 3.1).</summary>
    internal const string HostBoundMethod = "publickey-hostbound-v00@openssh.com";

    /// <summary>
    /// The <c>keyboard-interactive</c> method (RFC 4256): the server sends rounds of prompts and <paramref name="respond"/> answers each.
    /// Returns null when <paramref name="respond"/> gives up; the server drops the attempt when the next request arrives.
    /// </summary>
    public async Task<AuthOutcome?> KeyboardInteractiveAsync(
        Func<SshKeyboardInteractiveRequest, CancellationToken, ValueTask<IReadOnlyList<string>?>> respond, CancellationToken cancellationToken)
    {
        var outcome = await RequestCoreAsync("keyboard-interactive", w =>
        {
            w.WriteString(""); // language tag (deprecated)
            w.WriteString(""); // submethods: let the server choose
        }, Reply.InfoRequest, cancellationToken).ConfigureAwait(false);

        for (var round = 0; outcome.Request is { } request; round++)
        {
            if (round == MaxRounds)
            {
                throw new SshException(SshFailureReason.AuthenticationFailed, $"The server asked more than {MaxRounds} rounds of keyboard-interactive questions.");
            }

            var responses = await respond(request, cancellationToken).ConfigureAwait(false);
            if (responses is null)
            {
                return null;
            }

            if (responses.Count != request.Prompts.Count)
            {
                throw new InvalidOperationException($"The keyboard-interactive handler returned {responses.Count} responses for {request.Prompts.Count} prompts.");
            }

            var message = Build(w =>
            {
                w.WriteByte(SshMessage.UserAuthInfoResponse);
                w.WriteUInt32((uint)responses.Count);
                foreach (var response in responses)
                {
                    w.WriteString(response ?? "");
                }
            });
            try
            {
                await transport.SendAsync(message, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(message); // the responses are usually secrets, whether the send worked or not
            }
            outcome = await ReceiveReplyAsync(Reply.InfoRequest, cancellationToken).ConfigureAwait(false);
        }

        return outcome.Outcome;
    }

    internal const string GssapiMethod = "gssapi-with-mic";

    /// <summary>Token exchanges before the client gives up on a context that never completes (Kerberos needs one or two).</summary>
    internal const int MaxGssapiRounds = 16;

    /// <summary>
    /// The <c>gssapi-with-mic</c> method (RFC 4462 section 3) with Kerberos 5: offer the krb5 mechanism, exchange context tokens until the
    /// context is established, then send a MIC over the session identifier and this request, which binds the Kerberos authentication to
    /// this SSH session. Returns null when the GSS-API layer fails on this side (no ticket, for example): the attempt is abandoned and the
    /// next method's request tells the server so.
    /// </summary>
    public async Task<AuthOutcome?> GssapiAsync(IGssapiContext context, CancellationToken cancellationToken)
    {
        await transport.SendAsync(Build(w =>
        {
            w.WriteByte(SshMessage.UserAuthRequest);
            w.WriteString(userName);
            w.WriteString(ConnectionService);
            w.WriteString(GssapiMethod);
            w.WriteUInt32(1);
            w.WriteString(Gssapi.Krb5Oid);
        }), cancellationToken).ConfigureAwait(false);

        // SSH_MSG_USERAUTH_GSSAPI_RESPONSE: the mechanism the server chose, which must be the one offered; or a FAILURE.
        var received = await ReceiveGssapiAsync(cancellationToken).ConfigureAwait(false);
        if (received.Outcome is { } refused)
        {
            return refused;
        }

        if (received.Type != GssapiResponse || !received.Data.AsSpan().SequenceEqual(Gssapi.Krb5Oid))
        {
            throw new SshProtocolException("The server answered gssapi-with-mic with a mechanism it was not offered.");
        }

        byte[]? token;
        bool complete;
        try
        {
            token = context.Step([], out complete);
        }
        catch (SshException)
        {
            return null; // no ticket, or the service principal is unknown: not this method, then
        }

        for (var round = 0; ; round++)
        {
            if (token is not null)
            {
                await SendGssapiAsync(GssapiToken, token, cancellationToken).ConfigureAwait(false);
            }

            if (complete)
            {
                break;
            }

            if (round == MaxGssapiRounds)
            {
                throw new SshException(SshFailureReason.AuthenticationFailed, $"The GSS-API context was not established in {MaxGssapiRounds} exchanges.");
            }

            received = await ReceiveGssapiAsync(cancellationToken).ConfigureAwait(false);
            if (received.Outcome is { } outcome)
            {
                return outcome; // the server gave up (its context failed): FAILURE with the methods it still accepts
            }

            if (received.Type == GssapiErrorToken)
            {
                // The server's context failed and it sends its error token; ours cannot go on either. The server answers with FAILURE.
                try
                {
                    context.Step(received.Data, out _);
                }
                catch (SshException)
                {
                    // Expected: the token describes a failure.
                }

                var failed = await ReceiveGssapiAsync(cancellationToken).ConfigureAwait(false);
                return failed.Outcome ?? throw new SshProtocolException("The server sent another message after a GSS-API error token.");
            }

            if (received.Type != GssapiToken)
            {
                throw new SshProtocolException($"Unexpected message {received.Type} during gssapi-with-mic.");
            }

            try
            {
                token = context.Step(received.Data, out complete);
            }
            catch (SshException)
            {
                return null;
            }
        }

        // RFC 4462 section 3.5: the MIC covers the session identifier and this method's request.
        var mic = context.GetMic(Build(w =>
        {
            w.WriteString(transport.SessionId);
            w.WriteByte(SshMessage.UserAuthRequest);
            w.WriteString(userName);
            w.WriteString(ConnectionService);
            w.WriteString(GssapiMethod);
        }));
        await SendGssapiAsync(GssapiMic, mic, cancellationToken).ConfigureAwait(false);
        var final = await ReceiveGssapiAsync(cancellationToken).ConfigureAwait(false);
        return final.Outcome ?? throw new SshProtocolException($"Unexpected message {final.Type} after the GSS-API MIC.");
    }

    // RFC 4462 section 3: the gssapi-with-mic messages (60 is SSH_MSG_USERAUTH_GSSAPI_RESPONSE for this method).
    internal const byte GssapiResponse = 60;
    internal const byte GssapiToken = 61;
    internal const byte GssapiExchangeComplete = 63;
    internal const byte GssapiError = 64;
    internal const byte GssapiErrorToken = 65;
    internal const byte GssapiMic = 66;

    private async Task SendGssapiAsync(byte type, byte[] data, CancellationToken cancellationToken) =>
        await transport.SendAsync(Build(w =>
        {
            w.WriteByte(type);
            w.WriteString(data);
        }), cancellationToken).ConfigureAwait(false);

    private readonly record struct GssapiReceived(byte Type, byte[] Data, AuthOutcome? Outcome);

    /// <summary>
    /// The next gssapi-with-mic message: a RESPONSE, TOKEN or ERRTOK with its data, or SUCCESS/FAILURE as an outcome. Banners are shown and
    /// SSH_MSG_USERAUTH_GSSAPI_ERROR (the server's GSS-API status, informational) is skipped.
    /// </summary>
    private async Task<GssapiReceived> ReceiveGssapiAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            string? bannerText = null;
            using (var message = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false))
            {
                var reader = new SshReader(message.Payload.Span);
                var type = reader.ReadByte();
                switch (type)
                {
                    case SshMessage.UserAuthBanner:
                        bannerText = reader.ReadUtf8String();
                        break;
                    case SshMessage.UserAuthSuccess:
                        return new GssapiReceived(type, [], new AuthOutcome(true, [], false));
                    case SshMessage.UserAuthFailure:
                        var methods = reader.ReadNameList();
                        return new GssapiReceived(type, [], new AuthOutcome(false, methods, reader.ReadBoolean()));
                    case GssapiResponse or GssapiToken or GssapiErrorToken:
                        return new GssapiReceived(type, reader.ReadString().ToArray(), null);
                    case GssapiError:
                        break; // uint32 major, uint32 minor, string message, string language: the server's diagnostics, not a decision
                    default:
                        throw new SshProtocolException($"Unexpected message {type} during gssapi-with-mic.");
                }
            }

            if (bannerText is not null && banner is not null)
            {
                await banner(bannerText, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Picks the signature algorithm for <paramref name="key"/>: the first one the key supports that the server lists in
    /// <c>server-sig-algs</c> (RFC 8308), or the key's preferred one when the server did not say.
    /// </summary>
    public static string? ChooseSignatureAlgorithm(SshPrivateKey key, IReadOnlyDictionary<string, string> serverExtensions)
    {
        if (!serverExtensions.TryGetValue("server-sig-algs", out var list))
        {
            return key.SignatureAlgorithms[0];
        }

        var accepted = list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        // server-sig-algs lists plain algorithms; a certificate algorithm is acceptable when its base one is.
        return key.SignatureAlgorithms.FirstOrDefault(a => accepted.Contains(SshCertificate.BaseAlgorithm(a), StringComparer.Ordinal));
    }

    /// <summary>What message 60 means for the request in flight: it is PK_OK, PASSWD_CHANGEREQ and INFO_REQUEST depending on the method.</summary>
    private enum Reply
    {
        None,
        PkOk,
        InfoRequest,
    }

    private readonly record struct Received(AuthOutcome? Outcome, SshKeyboardInteractiveRequest? Request);

    private async Task<AuthOutcome> RequestAsync(string method, Action<SshWriter>? body, Reply reply, CancellationToken cancellationToken)
    {
        var received = await RequestCoreAsync(method, body, reply, cancellationToken).ConfigureAwait(false);
        return received.Outcome!; // only Reply.InfoRequest yields a request instead
    }

    private async Task<Received> RequestCoreAsync(string method, Action<SshWriter>? body, Reply reply, CancellationToken cancellationToken)
    {
        var message = Build(w =>
        {
            w.WriteByte(SshMessage.UserAuthRequest);
            w.WriteString(userName);
            w.WriteString(ConnectionService);
            w.WriteString(method);
            body?.Invoke(w);
        });
        try
        {
            await transport.SendAsync(message, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message); // a password request carries the password, whether the send worked or not
        }
        return await ReceiveReplyAsync(reply, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Received> ReceiveReplyAsync(Reply reply, CancellationToken cancellationToken)
    {
        while (true)
        {
            string? bannerText = null;
            Received? result = null;
            using (var message = await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false))
            {
                var reader = new SshReader(message.Payload.Span);
                var type = reader.ReadByte();
                switch (type)
                {
                    case SshMessage.UserAuthBanner:
                        bannerText = reader.ReadUtf8String();
                        break;
                    case SshMessage.UserAuthSuccess:
                        result = new Received(new AuthOutcome(true, [], false), null);
                        break;
                    case SshMessage.UserAuthFailure:
                        var methods = reader.ReadNameList();
                        result = new Received(new AuthOutcome(false, methods, reader.ReadBoolean()), null);
                        break;
                    case SshMessage.UserAuthPkOk when reply == Reply.PkOk:
                        result = new Received(new AuthOutcome(false, [], false, KeyAcceptable: true), null);
                        break;
                    case SshMessage.UserAuthInfoRequest when reply == Reply.InfoRequest:
                        result = new Received(null, ReadInfoRequest(ref reader));
                        break;
                    case SshMessage.UserAuthPkOk:
                        // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ shares the number 60.
                        throw new SshException(SshFailureReason.AuthenticationFailed, "The server requires the password to be changed.");
                    default:
                        throw new SshProtocolException($"Unexpected message {type} during user authentication.");
                }
            }

            if (result is { } done)
            {
                return done;
            }

            // A banner (RFC 4252 section 5.4) can arrive at any point before success; shown by interactive clients.
            if (banner is not null)
            {
                await banner(bannerText!, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static SshKeyboardInteractiveRequest ReadInfoRequest(ref SshReader reader)
    {
        var name = reader.ReadUtf8String();
        var instruction = reader.ReadUtf8String();
        reader.ReadUtf8String(); // language tag
        var count = reader.ReadUInt32();
        if (count > MaxPrompts)
        {
            throw new SshProtocolException($"The server sent {count} keyboard-interactive prompts; at most {MaxPrompts} are accepted.");
        }

        var prompts = new SshAuthenticationPrompt[count];
        for (var i = 0; i < prompts.Length; i++)
        {
            prompts[i] = new SshAuthenticationPrompt(reader.ReadUtf8String(), reader.ReadBoolean());
        }

        return new SshKeyboardInteractiveRequest(name, instruction, prompts);
    }

    private static byte[] Build(Action<SshWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>(128);
        body(new SshWriter(buffer));
        var message = buffer.WrittenSpan.ToArray();
        buffer.Clear(); // zeroes the written bytes, which may include a password
        return message;
    }
}

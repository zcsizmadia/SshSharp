using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace SshSharp.Protocol;

/// <summary>
/// The named pipe Pageant (PuTTY's agent, 0.75 and later) listens on, derived as PuTTY derives it (windows/utils/agent_named_pipe_name.c):
/// <c>\\.\pipe\pageant.&lt;user&gt;.&lt;hex SHA-256&gt;</c>. The user is the user principal name before its <c>@</c> (the account name when there
/// is none); the hash is of the string <c>"Pageant"</c>, zero-padded to <c>CryptProtectMemory</c>'s 16-byte block, encrypted with
/// <c>CRYPTPROTECTMEMORY_CROSS_PROCESS</c> (so only processes of the same logon session agree on it), and hashed with its length as an
/// SSH string. The pipe speaks the ordinary agent protocol.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class PageantPipe
{
    private const int NameUserPrincipal = 8; // EXTENDED_NAME_FORMAT
    private const uint CrossProcess = 1; // CRYPTPROTECTMEMORY_CROSS_PROCESS
    private const int BlockSize = 16; // CRYPTPROTECTMEMORY_BLOCK_SIZE

    /// <summary>The pipe name without <c>\\.\pipe\</c>, or null when it cannot be derived.</summary>
    public static string? Name()
    {
        try
        {
            return UserName() is { Length: > 0 } user && Obfuscate("Pageant") is { } suffix ? $"pageant.{user}.{suffix}" : null;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }

    /// <summary>PuTTY's get_username: the user principal name up to its '@', or the account name.</summary>
    private static string? UserName()
    {
        var size = 0u;
        GetUserNameExW(NameUserPrincipal, null, ref size);
        if (size > 0)
        {
            var buffer = new char[size];
            if (GetUserNameExW(NameUserPrincipal, buffer, ref size))
            {
                var principal = new string(buffer, 0, (int)size);
                var at = principal.IndexOf('@', StringComparison.Ordinal);
                return at >= 0 ? principal[..at] : principal;
            }
        }

        return Environment.UserName; // a local account has no principal name
    }

    /// <summary>PuTTY's capi_obfuscate_string: SHA-256 of the length-prefixed, CryptProtectMemory-encrypted string, in lower-case hex.</summary>
    internal static string? Obfuscate(string text)
    {
        var length = (Encoding.ASCII.GetByteCount(text) + 1 + BlockSize - 1) / BlockSize * BlockSize; // with its NUL, in whole blocks
        var data = new byte[4 + length];
        BinaryPrimitives.WriteUInt32BigEndian(data, (uint)length);
        Encoding.ASCII.GetBytes(text, data.AsSpan(4));
        var block = data.AsSpan(4).ToArray();
        if (!CryptProtectMemory(block, (uint)block.Length, CrossProcess))
        {
            return null;
        }

        block.CopyTo(data, 4);
        return Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
    }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetUserNameExW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool GetUserNameExW(int nameFormat, [Out] char[]? buffer, ref uint size);

    [DllImport("crypt32.dll", EntryPoint = "CryptProtectMemory")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectMemory([In, Out] byte[] data, uint size, uint flags);
}

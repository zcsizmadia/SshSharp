namespace SshSharp.Config;

/// <summary>OpenSSH-style glob matching (<c>*</c> and <c>?</c>), case-insensitive.</summary>
internal static class Glob
{
    public static bool IsMatch(ReadOnlySpan<char> pattern, ReadOnlySpan<char> text)
    {
        int p = 0, t = 0, starP = -1, starT = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && pattern[p] == '*')
            {
                starP = p++;
                starT = t;
            }
            else if (p < pattern.Length && (pattern[p] == '?' || CharsEqual(pattern[p], text[t])))
            {
                p++;
                t++;
            }
            else if (starP >= 0)
            {
                p = starP + 1;
                t = ++starT;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }

    private static bool CharsEqual(char a, char b) => a == b || char.ToLowerInvariant(a) == char.ToLowerInvariant(b);
}
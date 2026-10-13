using System.Text;

namespace SshSharp.Config;

/// <summary>Splits one <c>ssh_config</c> line into a keyword and arguments, following OpenSSH's quoting rules.</summary>
internal static class SshConfigLine
{
    /// <summary>
    /// Parses a line. Returns false for blank and comment lines. Throws <see cref="FormatException"/> for an unterminated quote
    /// or a keyword without arguments.
    /// </summary>
    /// <param name="line">The line text.</param>
    /// <param name="keyword">The keyword, as written.</param>
    /// <param name="arguments">The arguments with quotes removed.</param>
    /// <param name="rawValue">Everything after the keyword (and optional <c>=</c>), trimmed, verbatim.</param>
    public static bool TryParse(string line, out string keyword, out List<string> arguments, out string rawValue)
    {
        keyword = string.Empty;
        arguments = [];
        rawValue = string.Empty;

        var span = line.AsSpan().Trim();
        if (span.IsEmpty || span[0] == '#')
        {
            return false;
        }

        var end = 0;
        while (end < span.Length && !char.IsWhiteSpace(span[end]) && span[end] != '=')
        {
            end++;
        }

        keyword = span[..end].ToString();
        var rest = span[end..].TrimStart();
        if (!rest.IsEmpty && rest[0] == '=')
        {
            rest = rest[1..].TrimStart();
        }

        rawValue = rest.TrimEnd().ToString();
        var i = 0;
        while (i < rest.Length)
        {
            if (char.IsWhiteSpace(rest[i]))
            {
                i++;
            }
            else if (rest[i] == '#')
            {
                break;
            }
            else if (rest[i] == '"')
            {
                i = ReadQuoted(rest, i + 1, arguments);
            }
            else
            {
                var start = i;
                while (i < rest.Length && !char.IsWhiteSpace(rest[i]))
                {
                    i++;
                }

                arguments.Add(rest[start..i].ToString());
            }
        }

        if (arguments.Count == 0)
        {
            throw new FormatException($"Missing argument for '{keyword}'.");
        }

        return true;
    }

    private static int ReadQuoted(ReadOnlySpan<char> text, int start, List<string> arguments)
    {
        var sb = new StringBuilder();
        var i = start;
        while (i < text.Length)
        {
            var c = text[i];
            if (c == '\\' && i + 1 < text.Length && (text[i + 1] == '"' || text[i + 1] == '\\'))
            {
                sb.Append(text[i + 1]);
                i += 2;
            }
            else if (c == '"')
            {
                arguments.Add(sb.ToString());
                return i + 1;
            }
            else
            {
                sb.Append(c);
                i++;
            }
        }

        throw new FormatException("Unterminated quote.");
    }
}
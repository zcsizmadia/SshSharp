using System.Globalization;
using System.Text;

namespace SshSharp;

/// <summary>
/// Text the server chose (a disconnect reason, a refusal, an error line), made fit for an exception message or a log entry. A server
/// could otherwise put a line break in it to forge a log line, or terminal escape sequences (or bidirectional overrides) that act
/// when the message is shown in a terminal.
/// </summary>
internal static class ServerText
{
    /// <summary>The most characters kept: enough for any real message, and a bound on what a server can put in one.</summary>
    internal const int MaxLength = 200;

    /// <summary>
    /// <paramref name="text"/> with every line break, tab and line or paragraph separator turned into one space, every other control
    /// or format character (Unicode Cc and Cf: escapes, bell, bidirectional overrides, zero-width characters) removed, trimmed, and cut
    /// to <paramref name="maxLength"/> characters, never inside a surrogate pair. An unpaired surrogate becomes U+FFFD.
    /// </summary>
    public static string Clean(string? text, int maxLength = MaxLength)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var clean = new StringBuilder(Math.Min(text.Length, maxLength));
        foreach (var rune in text.EnumerateRunes())
        {
            var category = Rune.GetUnicodeCategory(rune);
            string? append;
            if (Rune.IsWhiteSpace(rune) && (category is UnicodeCategory.Control or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator))
            {
                // A break between words stays a break, but only ever one space, never a new line.
                append = clean.Length == 0 || clean[^1] == ' ' ? null : " ";
            }
            else if (category is UnicodeCategory.Control or UnicodeCategory.Format)
            {
                append = null;
            }
            else
            {
                append = rune.ToString();
            }

            if (append is null)
            {
                continue;
            }

            if (clean.Length + append.Length > maxLength)
            {
                break;
            }

            clean.Append(append);
        }

        return clean.ToString().Trim();
    }
}

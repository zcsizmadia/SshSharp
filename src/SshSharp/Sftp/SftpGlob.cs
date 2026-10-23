using System.Text;

namespace SshSharp.Sftp;

/// <summary>
/// A shell-style pattern for one file name (<see cref="SftpListOptions.Pattern"/>), matched as fnmatch(3) without flags matches it:
/// <c>*</c> is any run of characters, <c>?</c> one character, <c>[...]</c> one of a set (<c>[abc]</c>, a range <c>[a-z]</c>, negated
/// with <c>!</c> or <c>^</c>, a <c>]</c> first in the set is part of it), and <c>\</c> takes the next character literally. Everything
/// else matches itself, case-sensitively (Unicode code points compared ordinally) unless compiled to ignore case
/// (<see cref="SftpListOptions.IgnoreCase"/>). A <c>[</c> without its closing <c>]</c> matches itself. Names starting with a dot are not
/// special: <c>*</c> matches them too.
/// </summary>
/// <remarks>
/// It is compiled once into tokens and matched with one star remembered at a time (the classic greedy algorithm): a mismatch returns to
/// the last <c>*</c> and lets it take one more character. That takes at most the pattern's length times the name's, whatever the
/// pattern, so a pattern cannot make a listing hang. Named classes such as <c>[[:digit:]]</c> are not supported.
/// </remarks>
internal sealed class SftpGlob
{
    private enum Kind
    {
        Literal,
        AnyOne,
        Star,
        Set,
    }

    private readonly record struct Token(Kind Kind, int Value = 0, (int Low, int High)[]? Ranges = null, bool Negated = false);

    private readonly Token[] _tokens;

    private readonly bool _ignoreCase;

    private SftpGlob(Token[] tokens, bool ignoreCase)
    {
        _tokens = tokens;
        _ignoreCase = ignoreCase;
    }

    /// <summary>
    /// Compiles <paramref name="pattern"/>; every pattern is valid (a malformed set is taken literally). With
    /// <paramref name="ignoreCase"/>, a character matches its upper- and lowercase forms too, by the invariant culture's simple case
    /// mapping (as <c>FNM_CASEFOLD</c> folds both sides), so the same pattern matches the same names whatever this machine's culture is.
    /// </summary>
    public static SftpGlob Parse(string pattern, bool ignoreCase = false)
    {
        var runes = Runes(pattern);
        var tokens = new List<Token>();
        var i = 0;
        while (i < runes.Length)
        {
            var c = runes[i];
            if (c == '*')
            {
                if (tokens.Count == 0 || tokens[^1].Kind != Kind.Star)
                {
                    tokens.Add(new Token(Kind.Star)); // a run of stars is one star
                }

                i++;
            }
            else if (c == '?')
            {
                tokens.Add(new Token(Kind.AnyOne));
                i++;
            }
            else if (c == '[' && TryParseSet(runes, i, out var set, out var next))
            {
                tokens.Add(set);
                i = next;
            }
            else if (c == '\\' && i + 1 < runes.Length)
            {
                tokens.Add(new Token(Kind.Literal, runes[i + 1]));
                i += 2;
            }
            else
            {
                tokens.Add(new Token(Kind.Literal, c)); // a trailing backslash, or a '[' that opens no set, is itself
                i++;
            }
        }

        return new SftpGlob([.. tokens], ignoreCase);
    }

    /// <summary>Whether <paramref name="name"/> matches the whole pattern.</summary>
    public bool IsMatch(string name)
    {
        var text = Runes(name);
        int t = 0, n = 0, starToken = -1, starText = 0;
        while (n < text.Length)
        {
            if (t < _tokens.Length && _tokens[t].Kind == Kind.Star)
            {
                // Remember where the star is; it takes nothing for now, and one more character each time what follows fails.
                starToken = ++t;
                starText = n;
            }
            else if (t < _tokens.Length && Matches(_tokens[t], text[n], _ignoreCase))
            {
                t++;
                n++;
            }
            else if (starToken >= 0)
            {
                t = starToken;
                n = ++starText;
            }
            else
            {
                return false;
            }
        }

        while (t < _tokens.Length && _tokens[t].Kind == Kind.Star)
        {
            t++;
        }

        return t == _tokens.Length;
    }

    private static bool Matches(Token token, int c, bool ignoreCase) => token.Kind switch
    {
        Kind.Literal => token.Value == c || (ignoreCase && Fold(token.Value) == Fold(c)),
        Kind.AnyOne => true,

        // Ignoring case, a character is in the set when any of its forms is: [a-z] takes 'Q', and [!a-z] does not.
        _ => (InRanges(token, c) || (ignoreCase && (InRanges(token, Lower(c)) || InRanges(token, Upper(c))))) != token.Negated,
    };

    private static bool InRanges(Token token, int c)
    {
        foreach (var (low, high) in token.Ranges!)
        {
            if (c >= low && c <= high)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>One form for a character and its other cases, to compare literals with; the invariant culture's, never this machine's.</summary>
    private static int Fold(int c) => Lower(Upper(c));

    private static int Lower(int c) => Rune.ToLowerInvariant(new Rune(c)).Value;

    private static int Upper(int c) => Rune.ToUpperInvariant(new Rune(c)).Value;

    /// <summary>
    /// Parses the set that opens at <paramref name="start"/> (a <c>[</c>); false when it has no closing <c>]</c>, and the <c>[</c> is
    /// then an ordinary character.
    /// </summary>
    private static bool TryParseSet(int[] runes, int start, out Token set, out int next)
    {
        var i = start + 1;
        var negated = i < runes.Length && runes[i] is '!' or '^';
        if (negated)
        {
            i++;
        }

        var ranges = new List<(int, int)>();
        var first = true;
        while (i < runes.Length)
        {
            if (runes[i] == ']' && !first)
            {
                set = new Token(Kind.Set, Ranges: [.. ranges], Negated: negated);
                next = i + 1;
                return true;
            }

            first = false;
            var low = Member(runes, ref i);
            var high = low;
            if (i + 1 < runes.Length && runes[i] == '-' && runes[i + 1] != ']')
            {
                i++;
                high = Member(runes, ref i);
            }

            ranges.Add((low, high)); // a reversed range (z-a) matches nothing, as in fnmatch
        }

        set = default;
        next = start;
        return false;
    }

    /// <summary>One member of a set at <paramref name="i"/>, with a backslash taking the next character literally; moves past it.</summary>
    private static int Member(int[] runes, ref int i)
    {
        if (runes[i] == '\\' && i + 1 < runes.Length)
        {
            i++;
        }

        return runes[i++];
    }

    /// <summary>The code points of <paramref name="s"/>: a character outside the BMP (an emoji) is one, as <c>?</c> should take it.</summary>
    private static int[] Runes(string s)
    {
        var runes = new List<int>(s.Length);
        foreach (var rune in s.EnumerateRunes())
        {
            runes.Add(rune.Value); // a lone surrogate is U+FFFD
        }

        return [.. runes];
    }
}

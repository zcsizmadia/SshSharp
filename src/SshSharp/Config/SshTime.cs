using System.Globalization;

namespace SshSharp.Config;

/// <summary>Parses OpenSSH time values such as <c>30</c>, <c>90s</c>, <c>10m</c>, <c>1h30m</c>, <c>1d</c>, <c>2w</c>.</summary>
internal static class SshTime
{
    public static bool TryParse(string value, out TimeSpan result)
    {
        result = default;
        if (value.Length == 0)
        {
            return false;
        }

        double seconds = 0;
        var i = 0;
        while (i < value.Length)
        {
            var start = i;
            while (i < value.Length && char.IsAsciiDigit(value[i]))
            {
                i++;
            }

            if (i == start || !long.TryParse(value.AsSpan(start, i - start), NumberStyles.None, CultureInfo.InvariantCulture, out var number))
            {
                return false;
            }

            double unit = 1;
            if (i < value.Length)
            {
                switch (char.ToLowerInvariant(value[i]))
                {
                    case 's': unit = 1; break;
                    case 'm': unit = 60; break;
                    case 'h': unit = 3600; break;
                    case 'd': unit = 86400; break;
                    case 'w': unit = 604800; break;
                    default: return false;
                }

                i++;
            }

            seconds += number * unit;
        }

        // Like OpenSSH's convtime: more than INT_MAX seconds is invalid (and would overflow TimeSpan further up).
        if (seconds > int.MaxValue)
        {
            return false;
        }

        result = TimeSpan.FromSeconds(seconds);
        return true;
    }
}
using SshSharp.Config;

namespace SshSharp;

/// <summary>
/// An algorithm list for <see cref="SshClientOptions.KexAlgorithms"/>, <see cref="SshClientOptions.HostKeyAlgorithms"/>,
/// <see cref="SshClientOptions.Ciphers"/>, <see cref="SshClientOptions.Macs"/> or <see cref="SshClientOptions.PubkeyAcceptedAlgorithms"/>,
/// in the forms ssh_config's <c>Ciphers</c>, <c>KexAlgorithms</c>, <c>MACs</c>, <c>HostKeyAlgorithms</c> and
/// <c>PubkeyAcceptedAlgorithms</c> take: a list that replaces SshSharp's defaults (<see cref="Only"/>), or a change to them that keeps
/// up with new defaults in later versions (<see cref="Append"/>, <see cref="Prepend"/>, <see cref="Remove"/>).
/// </summary>
/// <remarks>
/// <para>
/// The names are checked when the list is assigned to an option: one SshSharp does not implement for that kind of algorithm is an
/// <see cref="ArgumentException"/>, so a typo does not silently fall back to the defaults. <see cref="SshClientOptions.FipsMode"/> still
/// applies on top of the list. <see cref="ToString"/> gives the ssh_config form, which <see cref="Parse"/> reads back.
/// </para>
/// <para>
/// A list means what the same text means in ssh_config, where SshSharp applies it as ssh does, with one restriction: only
/// <see cref="Remove"/> takes wildcards here, while in ssh_config a pattern in any form stands for the names it matches.
/// </para>
/// </remarks>
public sealed class SshAlgorithmList
{
    private readonly char _operation; // '\0' replaces the defaults; '+', '-' and '^' change them, as in ssh_config

    private SshAlgorithmList(char operation, IReadOnlyList<string> algorithms)
    {
        _operation = operation;
        Algorithms = algorithms;
    }

    /// <summary>The names (or, for <see cref="Remove"/>, patterns) the list holds, in order.</summary>
    internal IReadOnlyList<string> Algorithms { get; }

    /// <summary>Whether this list removes from the defaults, where its entries are patterns rather than names.</summary>
    internal bool IsRemoval => _operation == '-';

    /// <summary>
    /// Whether the list decides the order itself (a plain list, or <c>^</c>), rather than changing the defaults' (<c>+</c>, <c>-</c>).
    /// As in ssh, only for the latter may the client reorder host key algorithms (certificates first when an authority is trusted).
    /// </summary>
    internal bool SetsOrder => _operation is '\0' or '^';

    /// <summary>Whether this is a removal (<c>-</c>) one of whose patterns matches <paramref name="name"/>.</summary>
    internal bool Removes(string name) => IsRemoval && Algorithms.Any(p => Glob.IsMatch(p, name));

    /// <summary>Exactly these algorithms, in this order of preference (ssh_config's plain list, <c>Ciphers a,b</c>).</summary>
    /// <param name="algorithms">The algorithm names, most preferred first.</param>
    /// <exception cref="ArgumentException">The list is empty, or a name is empty, contains a comma, white space or a wildcard.</exception>
    public static SshAlgorithmList Only(params string[] algorithms) => Create('\0', algorithms);

    /// <summary>The defaults, with these algorithms added at the end (ssh_config's <c>+</c>, <c>Ciphers +a,b</c>).</summary>
    /// <param name="algorithms">The algorithm names to add. One already among the defaults stays where it is, as with ssh_config's
    /// <c>+</c> (use <see cref="Prepend"/> to move it).</param>
    /// <exception cref="ArgumentException">The list is empty, or a name is empty, contains a comma, white space or a wildcard.</exception>
    public static SshAlgorithmList Append(params string[] algorithms) => Create('+', algorithms);

    /// <summary>The defaults, with these algorithms moved or added to the front (ssh_config's <c>^</c>, <c>Ciphers ^a,b</c>).</summary>
    /// <param name="algorithms">The algorithm names to prefer, most preferred first.</param>
    /// <exception cref="ArgumentException">The list is empty, or a name is empty, contains a comma, white space or a wildcard.</exception>
    public static SshAlgorithmList Prepend(params string[] algorithms) => Create('^', algorithms);

    /// <summary>The defaults, without the algorithms that match these patterns (ssh_config's <c>-</c>, <c>Ciphers -a,b*</c>).</summary>
    /// <param name="patterns">Algorithm names, or patterns with <c>*</c> and <c>?</c> wildcards (<c>aes*-ctr</c>).</param>
    /// <exception cref="ArgumentException">The list is empty, or a pattern is empty or contains a comma or white space.</exception>
    public static SshAlgorithmList Remove(params string[] patterns) => Create('-', patterns);

    /// <summary>Reads a list in ssh_config's syntax: <c>a,b</c>, <c>+a,b</c>, <c>-a,b*</c> or <c>^a,b</c>.</summary>
    /// <param name="specification">The comma-separated list, as it would follow <c>Ciphers</c> in ssh_config.</param>
    /// <exception cref="ArgumentException">The specification is empty, or an entry is not a valid name for its form.</exception>
    public static SshAlgorithmList Parse(string specification)
    {
        ArgumentNullException.ThrowIfNull(specification);
        var spec = specification.Trim();
        var operation = spec.Length > 0 && spec[0] is '+' or '-' or '^' ? spec[0] : '\0';
        return Create(operation, Split(operation == '\0' ? spec : spec[1..]), nameof(specification));
    }

    /// <summary>The list in ssh_config's syntax, for example <c>-chacha20-poly1305@openssh.com</c>.</summary>
    public override string ToString() => (_operation == '\0' ? string.Empty : _operation.ToString()) + string.Join(',', Algorithms);

    /// <summary>
    /// Applies the list to <paramref name="defaults"/> as ssh applies an ssh_config value (its <c>kex_assemble_names</c>): the resulting
    /// algorithms in preference order, without duplicates. <c>+</c> adds the names after the defaults and <c>^</c> before them, a name
    /// listed twice keeping its first place (so <c>+</c> of a default changes nothing); <c>-</c> removes the defaults its patterns match.
    /// In a plain, <c>+</c> or <c>^</c> list (which only ssh_config gives wildcards), an entry with wildcards stands for each name of
    /// <paramref name="known"/> it matches, in that order.
    /// </summary>
    internal IReadOnlyList<string> Apply(IReadOnlyList<string> defaults, IReadOnlyList<string>? known = null)
    {
        ArgumentNullException.ThrowIfNull(defaults);
        if (_operation == '-')
        {
            return [.. defaults.Where(d => !Removes(d))];
        }

        IEnumerable<string> names = _operation switch
        {
            '+' => [.. defaults, .. Algorithms],
            '^' => [.. Algorithms, .. defaults],
            _ => Algorithms,
        };
        return Distinct(names.SelectMany(name => name.AsSpan().IndexOfAny('*', '?') >= 0 ? (known ?? defaults).Where(k => Glob.IsMatch(name, k)) : [name]));
    }

    /// <summary>
    /// Applies an ssh_config specification to <paramref name="defaults"/> as ssh does (wildcards expand against <paramref name="known"/>,
    /// or the defaults), without checking the names: unknown ones are the caller's to drop, and an empty specification leaves the defaults.
    /// </summary>
    internal static IReadOnlyList<string> Apply(string specification, IReadOnlyList<string> defaults, IReadOnlyList<string>? known = null)
    {
        ArgumentNullException.ThrowIfNull(specification);
        ArgumentNullException.ThrowIfNull(defaults);
        return FromConfig(specification)?.Apply(defaults, known) ?? [.. defaults];
    }

    /// <summary>An ssh_config specification as a list, unchecked as ssh_config values are; null when it is empty (the defaults apply).</summary>
    internal static SshAlgorithmList? FromConfig(string? specification)
    {
        var spec = specification?.Trim();
        if (string.IsNullOrEmpty(spec))
        {
            return null;
        }

        var operation = spec[0] is '+' or '-' or '^' ? spec[0] : '\0';
        return new SshAlgorithmList(operation, Split(operation == '\0' ? spec : spec[1..]));
    }

    private static SshAlgorithmList Create(char operation, string[] algorithms, string parameterName = "algorithms")
    {
        ArgumentNullException.ThrowIfNull(algorithms, parameterName);
        if (algorithms.Length == 0)
        {
            throw new ArgumentException("The list needs at least one algorithm.", parameterName);
        }

        foreach (var name in algorithms)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Any(c => c == ',' || char.IsWhiteSpace(c)))
            {
                throw new ArgumentException($"'{name}' is not an algorithm name: names are not empty and have no commas or white space.", parameterName);
            }

            // ssh_config takes wildcards only in a list that removes; elsewhere a name with one would match nothing a server offers.
            if (operation != '-' && name.AsSpan().IndexOfAny('*', '?') >= 0)
            {
                throw new ArgumentException($"'{name}': wildcards are allowed only in a list that removes algorithms (Remove, or '-' in ssh_config).",
                    parameterName);
            }
        }

        return new SshAlgorithmList(operation, [.. algorithms]);
    }

    private static string[] Split(string text) => text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static List<string> Distinct(IEnumerable<string> items)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        return [.. items.Where(seen.Add)];
    }
}

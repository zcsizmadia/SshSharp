using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace SshSharp.Tests.Integration;

/// <summary>
/// The steps a test has gone through, with when each started, so a test that times out says where it was stuck and how long each
/// step took instead of only "The operation was canceled". For tests that hang intermittently against real servers.
/// </summary>
internal sealed class Stages
{
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly List<(TimeSpan At, string Step)> _steps = [];
    private readonly object _lock = new();

    /// <summary>Marks the start of a step.</summary>
    public void Step(string step)
    {
        lock (_lock)
        {
            _steps.Add((_clock.Elapsed, step));
        }
    }

    /// <summary>Runs <paramref name="body"/>; a cancellation or timeout comes back as a <see cref="TimeoutException"/> naming the step it was in.</summary>
    public static async Task RunAsync(Func<Stages, Task> body, Func<string>? state = null)
    {
        var stages = new Stages();
        try
        {
            await body(stages);
        }
        catch (Exception ex) when (ex is OperationCanceledException or TimeoutException)
        {
            throw new TimeoutException(stages.Describe(state?.Invoke()), ex);
        }
    }

    private string Describe(string? state)
    {
        var text = new StringBuilder();
        lock (_lock)
        {
            var (at, step) = _steps.Count > 0 ? _steps[^1] : (TimeSpan.Zero, "(before the first step)");
            text.Append(CultureInfo.InvariantCulture, $"Stuck at \"{step}\" for {(_clock.Elapsed - at).TotalSeconds:0.0} s.");
            if (state is not null)
            {
                text.Append(' ').Append(state);
            }

            text.Append(" Steps:");
            foreach (var (stepAt, name) in _steps)
            {
                text.Append(CultureInfo.InvariantCulture, $" [{stepAt.TotalSeconds:0.000} s] {name};");
            }
        }

        return text.ToString();
    }
}

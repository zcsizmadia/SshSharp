using System.Diagnostics;
using Microsoft.Extensions.Time.Testing;
using SshSharp.Sftp;

namespace SshSharp.Tests.Sftp;

/// <summary>
/// Moves a <see cref="FakeTimeProvider"/> that a client's timeouts and a <see cref="FakeSftpServer"/>'s reply delays both run on, so a
/// test about timing holds on any machine: the clock moves only when the test moves it, never while a loaded machine stalls.
/// </summary>
internal static class FakeClock
{
    /// <summary>
    /// Moves the clock on by <paramref name="step"/> each time the server holds a reply back (<see cref="FakeSftpServer.ReplyDelay"/>)
    /// and the client has taken every reply sent so far, until <paramref name="work"/> ends: with a delay of <paramref name="step"/>
    /// per reply, the server answers one reply per step, and the client never sees it silent for longer than that.
    /// </summary>
    public static async Task AnswerEachInTurnAsync(FakeTimeProvider time, FakeSftpServer files, SftpClient sftp, TimeSpan step, Task work)
    {
        var stuck = Stopwatch.StartNew();
        while (!work.IsCompleted)
        {
            // The client's measure of the server's silence is zero once it has taken the reply the last step let out.
            if (files.DelayingReplies > 0 && sftp.SinceServerSent == TimeSpan.Zero)
            {
                time.Advance(step);
                stuck.Restart();
            }
            else if (stuck.Elapsed > TimeSpan.FromSeconds(60))
            {
                throw new TimeoutException("The work neither ended nor waited for a reply the server holds back.");
            }
            else
            {
                await Task.Delay(1);
            }
        }
    }

    /// <summary>Moves the clock on by <paramref name="step"/> at a time until <paramref name="done"/> holds (at most 1,200 steps).</summary>
    public static async Task AdvanceUntilAsync(FakeTimeProvider time, TimeSpan step, Func<bool> done)
    {
        for (var i = 0; i < 1200 && !done(); i++)
        {
            time.Advance(step);
            for (var j = 0; j < 20 && !done(); j++)
            {
                await Task.Delay(5); // what the clock released is on its way
            }
        }
    }
}

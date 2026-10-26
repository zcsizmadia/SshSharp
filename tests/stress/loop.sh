#!/usr/bin/env bash
# Runs the (already built) test assembly again and again, to catch intermittent failures. Used by .github/workflows/stress.yml.
#
#   tests/stress/loop.sh <iterations> <out-dir> <frameworks, comma-separated> [treenode filter] [extra test arguments...]
#
# Each failing iteration's full output is kept in <out-dir>; <out-dir>/summary.md lists the failed tests and how often each failed,
# and the instrumented build's reports (SSHSHARP_INSTRUMENT_LOG) end up in <out-dir>/instrumentation.log. Exits non-zero if any
# iteration failed or the instrumentation reported anything.
set -uo pipefail

iterations="$1"; out="$2"; frameworks="$3"; filter="${4:-}"; shift $(( $# < 4 ? $# : 4 ))
mkdir -p "$out"
export SSHSHARP_INSTRUMENT_LOG="$out/instrumentation.log"
IFS=',' read -r -a fws <<< "$frameworks"

failed_runs=0
: > "$out/failed-tests.txt"
for i in $(seq 1 "$iterations"); do
  fw="${fws[$(( (i - 1) % ${#fws[@]} ))]}"
  log="$out/iteration-$i-$fw.log"
  args=()
  [ -n "$filter" ] && args+=(--treenode-filter "$filter")
  start=$(date +%s)
  dotnet "tests/SshSharp.Tests/bin/Release/$fw/SshSharp.Tests.dll" ${args[@]+"${args[@]}"} "$@" --no-progress > "$log" 2>&1
  status=$?
  took=$(( $(date +%s) - start ))
  # Strip colours (perl: macOS sed knows neither -i without a suffix nor \x1b), then keep the names of the tests that failed: "failed <name> (<duration>)",
  # where a parameterised name may contain spaces and parentheses of its own.
  perl -pi -e 's/\e\[[0-9;]*m//g' "$log"
  # -a: a log with one byte that is not valid UTF-8 is "binary" to grep, which then prints "Binary file matches" instead of the lines.
  failures=$(grep -aE '^failed ' "$log" | sed -E 's/^failed (.*) \([^()]*\)$/\1/' || true)
  if [ "$status" -ne 0 ] || [ -n "$failures" ]; then
    failed_runs=$(( failed_runs + 1 ))
    echo "iteration $i ($fw, ${took}s): FAILED (exit $status) ${failures//$'\n'/, }"
    if [ -n "$failures" ]; then
      while IFS= read -r name; do printf '%s :: %s\n' "$fw" "$name"; done <<< "$failures" >> "$out/failed-tests.txt"
    else
      printf '%s :: %s\n' "$fw" "(exit $status, no failed test named: a crash or a hang?)" >> "$out/failed-tests.txt"
    fi
  else
    # The counts too: a run that skipped everything also "passes".
    counts=$(grep -aE '^\s*(succeeded|skipped):' "$log" | tr -s ' ' | tr '\n' ' ')
    echo "iteration $i ($fw, ${took}s): passed ($counts)"
    rm -f "$log"
  fi
done

reports=0
[ -s "$SSHSHARP_INSTRUMENT_LOG" ] && reports=$(grep -ac 'SshSharp instrumentation' "$SSHSHARP_INSTRUMENT_LOG")
{
  echo "### $iterations iterations ($frameworks): $failed_runs failed, $reports instrumentation reports"
  if [ -s "$out/failed-tests.txt" ]; then
    echo
    echo "| failures | framework | test |"
    echo "|---:|---|---|"
    sort "$out/failed-tests.txt" | uniq -c | sort -rn | sed -E 's/^ *([0-9]+) ([^ ]+) :: (.*)$/| \1 | \2 | \3 |/'
  fi
  if [ "$reports" -gt 0 ]; then
    echo
    echo "Instrumentation (first reports):"
    echo '```'
    head -n 60 "$SSHSHARP_INSTRUMENT_LOG"
    echo '```'
  fi
} > "$out/summary.md"
cat "$out/summary.md"

[ "$failed_runs" -eq 0 ] && [ "$reports" -eq 0 ]

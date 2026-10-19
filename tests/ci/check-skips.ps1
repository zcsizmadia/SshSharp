<#
.SYNOPSIS
Compares the tests a run skipped with the tests the job may skip (tests/ci/skips/<job>.txt).

.DESCRIPTION
A skipped test passes silently, so a server that stops offering a feature, a missing tool or a broken environment variable would turn
checks off without anyone noticing. Each CI job therefore lists the tests it may skip, one "Class.DisplayName" per line (sorted; blank
lines and lines starting with # are ignored), and this script reads the run's TRX reports and:

- fails, naming each test and its skip reason, when a test is skipped that the list does not have;
- prints a notice for each listed test that ran, or did not run at all, so the list gets tightened;
- writes the skip counts by reason to the job summary ($GITHUB_STEP_SUMMARY) when there is one.

With -Update it writes the run's skips to the list instead (to start a list or refresh one; review the diff before committing it).

.EXAMPLE
pwsh tests/ci/check-skips.ps1 -Job "unit (ubuntu-latest) net10.0" -Trx TestResults/unit-net10.0.trx
#>
param(
    # The job's name; it is turned into the list's file name (lower case, anything but letters, digits and dots becomes "-"), so
    # "interop (OpenSSH, Alpine 3.6)" reads tests/ci/skips/interop-openssh-alpine-3.6.txt.
    [Parameter(Mandatory)] [string] $Job,
    # TRX reports (MTP's --report-trx), or directories to search for them.
    [Parameter(Mandatory)] [string[]] $Trx,
    [string] $Baselines = (Join-Path $PSScriptRoot 'skips'),
    [switch] $Update
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$key = ($Job.ToLowerInvariant() -replace '[^a-z0-9.]+', '-').Trim('-')
$listPath = Join-Path $Baselines "$key.txt"

# GitHub's workflow commands end at a newline and treat % specially.
function Escape([string] $text) { $text -replace '%', '%25' -replace "`r", '%0D' -replace "`n", '%0A' }

$files = foreach ($path in $Trx) {
    if (Test-Path $path -PathType Container) { Get-ChildItem $path -Recurse -Filter *.trx | ForEach-Object FullName }
    elseif (Test-Path $path) { (Resolve-Path $path).Path }
}
if (-not $files) {
    Write-Output "::error::No TRX report found in $($Trx -join ', '): did the tests run with --report-trx?"
    exit 1
}

# Every test the run saw, by "Class.DisplayName", with its outcome and, for a skipped one, the reason.
$results = @{}
foreach ($file in $files) {
    [xml] $doc = Get-Content -LiteralPath $file -Raw -Encoding utf8
    $classes = @{}
    foreach ($test in $doc.SelectNodes('//*[local-name()="UnitTest"]')) {
        $method = $test.SelectSingleNode('*[local-name()="TestMethod"]')
        $classes[$test.id] = ($method.className -split '\.')[-1]
    }
    foreach ($result in $doc.SelectNodes('//*[local-name()="UnitTestResult"]')) {
        $name = "$($classes[$result.testId]).$($result.testName)"
        $reason = ''
        if ($result.outcome -eq 'NotExecuted') {
            $output = $result.SelectSingleNode('*[local-name()="Output"]')
            $reason = if ($output) { ($output.InnerText -replace '^\s*Skipped:\s*', '').Trim() } else { '' }
            if (-not $reason) { $reason = '(no reason given)' }
        }
        $previous = $results[$name]
        # A test seen in several reports counts as run if it ran in any of them.
        if (-not $previous -or $previous.Outcome -eq 'NotExecuted') {
            $results[$name] = [pscustomobject]@{ Outcome = $result.outcome; Reason = $reason }
        }
    }
}

$skipped = @($results.GetEnumerator() | Where-Object { $_.Value.Outcome -eq 'NotExecuted' } | Sort-Object Name -CaseSensitive)

if ($Update) {
    New-Item -ItemType Directory -Force $Baselines | Out-Null
    $lines = [string[]] @($skipped | ForEach-Object Name)
    [Array]::Sort($lines, [StringComparer]::Ordinal)
    [IO.File]::WriteAllLines($listPath, $lines, [Text.UTF8Encoding]::new($false))
    Write-Output "Wrote $($lines.Count) skipped tests to $listPath"
    exit 0
}

if (-not (Test-Path $listPath)) {
    Write-Output "::error::$listPath does not exist. Every job lists the tests it may skip; create it (empty if nothing may be skipped), or run this script with -Update and review the result."
    exit 1
}
$allowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($line in [IO.File]::ReadAllLines($listPath)) {
    $line = $line.Trim()
    if ($line -and -not $line.StartsWith('#')) { [void] $allowed.Add($line) }
}

$unexpected = @($skipped | Where-Object { -not $allowed.Contains($_.Name) })
$ranAnyway = @($allowed | Where-Object { $results.ContainsKey($_) -and $results[$_].Outcome -ne 'NotExecuted' } | Sort-Object -CaseSensitive)
$missing = @($allowed | Where-Object { -not $results.ContainsKey($_) } | Sort-Object -CaseSensitive)

foreach ($test in $unexpected) {
    Write-Output "::error title=Unexpected skip::$(Escape "$($test.Name) was skipped: $($test.Value.Reason)")"
}
foreach ($name in $ranAnyway) {
    Write-Output "::notice title=Listed skip ran::$(Escape "$name is in $key.txt but ran ($($results[$name].Outcome)); remove it from the list if it now runs here for good.")"
}
foreach ($name in $missing) {
    Write-Output "::notice title=Listed skip not found::$(Escape "$name is in $key.txt but was not in this run (renamed, removed or filtered out?); remove it from the list.")"
}

$byReason = $skipped | Group-Object { $_.Value.Reason } | Sort-Object @{ Expression = 'Count'; Descending = $true }, Name
$summary = [Text.StringBuilder]::new()
[void] $summary.AppendLine("### Skipped tests: $Job")
[void] $summary.AppendLine()
[void] $summary.AppendLine("$($results.Count) tests, $($skipped.Count) skipped; $($unexpected.Count) not in ``tests/ci/skips/$key.txt``, $($ranAnyway.Count) listed but ran, $($missing.Count) listed but not in the run.")
if ($skipped.Count) {
    [void] $summary.AppendLine()
    [void] $summary.AppendLine('| Skipped | Reason |')
    [void] $summary.AppendLine('|---:|---|')
    foreach ($group in $byReason) { [void] $summary.AppendLine("| $($group.Count) | $($group.Name -replace '\|', '\|' -replace '\r?\n', ' ') |") }
}
if ($unexpected.Count) {
    [void] $summary.AppendLine()
    [void] $summary.AppendLine('Unexpected skips:')
    [void] $summary.AppendLine()
    foreach ($test in $unexpected) { [void] $summary.AppendLine("- ``$($test.Name)``: $($test.Value.Reason -replace '\r?\n', ' ')") }
}
Write-Output $summary.ToString()
if ($env:GITHUB_STEP_SUMMARY) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary.ToString() -Encoding utf8 }

if ($unexpected.Count) {
    Write-Output "$($unexpected.Count) unexpected skip(s). A skip is a check that did not run: fix the cause, or, if this job really cannot run the test, add it to tests/ci/skips/$key.txt."
    exit 1
}

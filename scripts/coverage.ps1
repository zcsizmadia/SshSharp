<#
.SYNOPSIS
  Runs the unit tests with code coverage and writes an HTML report. Local use; CI does not gate on coverage.
.PARAMETER Framework
  Target framework to test (default net10.0).
#>
param([string]$Framework = 'net10.0')

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'coverage'
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue

dotnet test --project (Join-Path $root 'tests/SshSharp.Tests') -c Release -f $Framework `
  --coverage --coverage-output-format cobertura --coverage-output (Join-Path $out 'coverage.cobertura.xml') `
  --results-directory $out
if ($LASTEXITCODE -ne 0) { throw 'tests failed' }

dotnet tool update --global dotnet-reportgenerator-globaltool | Out-Null
reportgenerator "-reports:$out/**/*.cobertura.xml" "-targetdir:$out/report" '-reporttypes:Html;TextSummary' `
  '-assemblyfilters:+SshSharp'
Get-Content (Join-Path $out 'report/Summary.txt')
Write-Host "HTML report: $out/report/index.html"
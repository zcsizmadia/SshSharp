<#
.SYNOPSIS
  Starts the CI's throwaway SSH server in Docker for the interop tests, and points the current session at it.
.DESCRIPTION
  Dot-source it so the SSHSHARP_TEST_* variables land in your session, then run the tests:

    . ./scripts/test-server.ps1                     # OpenSSH on Alpine 3.22
    . ./scripts/test-server.ps1 -Server dropbear
    dotnet test --project tests/SshSharp.Tests -c Release --treenode-filter "/*/*/*InteropTests/*"
    ./scripts/test-server.ps1 -Stop

  The account's password is random and only stored in SSHSHARP_TEST_PASSWORD. Tests that need keys, certificates or an agent skip
  (CI's runner job sets those up); everything that needs only a password runs.
.PARAMETER Server
  openssh or dropbear.
.PARAMETER Image
  The Alpine image to build on (CI pins digests of 3.6, 3.13, 3.19 and 3.22).
.PARAMETER Port
  The local port to publish the server on.
.PARAMETER Stop
  Remove the container and clear the variables.
#>
param(
    [ValidateSet('openssh', 'dropbear')][string]$Server = 'openssh',
    [string]$Image = 'alpine:3.22',
    [int]$Port = 2200,
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'
$name = 'sshsharp-test-server'
$docker = (Get-Command docker -ErrorAction SilentlyContinue)?.Source
if (-not $docker) { throw 'docker is not on the PATH.' }

& $docker rm -f $name 2>$null | Out-Null
if ($Stop) {
    Remove-Item Env:SSHSHARP_TEST_SSHD, Env:SSHSHARP_TEST_USER, Env:SSHSHARP_TEST_PASSWORD, Env:SSHSHARP_TEST_SERVER,
        Env:SSHSHARP_TEST_SERVER_STRICTKEX, Env:SSHSHARP_TEST_SSHD_REKEY, Env:SSHSHARP_TEST_SSHD_INNER_PORT -ErrorAction SilentlyContinue
    Write-Host "Stopped $name."
    return
}

$root = Split-Path -Parent $PSScriptRoot
& $docker build -q -t sshsharp-interop --build-arg "BASE=$Image" --build-arg "SERVER=$Server" (Join-Path $root 'tests/docker') | Out-Null
$password = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
& $docker run -d --name $name -p "127.0.0.1:${Port}:22" -e "TEST_PASSWORD=$password" sshsharp-interop | Out-Null

# Wait for the identification line.
$banner = $null
for ($i = 0; $i -lt 30 -and -not $banner; $i++) {
    try {
        $tcp = [Net.Sockets.TcpClient]::new('127.0.0.1', $Port)
        $tcp.ReceiveTimeout = 2000
        $banner = [IO.StreamReader]::new($tcp.GetStream()).ReadLine()
        $tcp.Dispose()
    } catch {
        $banner = $null
    }

    # Docker's port proxy accepts before sshd is up and then closes the connection: no line yet, so wait.
    if (-not $banner) { Start-Sleep -Seconds 1 }
}

if (-not $banner) { throw "The server did not start; see: docker logs $name" }

$env:SSHSHARP_TEST_SSHD = "127.0.0.1:$Port"
$env:SSHSHARP_TEST_USER = 'sshsharp'
$env:SSHSHARP_TEST_PASSWORD = $password
$env:SSHSHARP_TEST_SERVER = if ($Server -eq 'dropbear') { 'dropbear' } else { 'OpenSSH' }
$env:SSHSHARP_TEST_SERVER_STRICTKEX = '1'
$env:SSHSHARP_TEST_SSHD_INNER_PORT = '22'
if ($Server -eq 'openssh') { $env:SSHSHARP_TEST_SSHD_REKEY = '1' } else { Remove-Item Env:SSHSHARP_TEST_SSHD_REKEY -ErrorAction SilentlyContinue }
Write-Host "Started $banner on 127.0.0.1:$Port; SSHSHARP_TEST_* are set in this session. Stop it with ./scripts/test-server.ps1 -Stop"

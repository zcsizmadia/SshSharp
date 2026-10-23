# Starts Microsoft's OpenSSH for Windows on 127.0.0.1:2222 and [::1]:2222 for the interop tests, with Git Bash as the default shell
# (the tests run POSIX commands) and a local, non-administrator account sshsharp with a random password, and writes the
# SSHSHARP_TEST_* settings to $GITHUB_ENV. sshd re-keys every 32 KiB (RekeyLimit), as on Linux. Password-only: the tests that need
# keys or certificates skip themselves. Used by the CI and Stress workflows on a hosted Windows runner.
$ErrorActionPreference = 'Stop'
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
}

$password = -join ((1..24) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) }) + 'Aa1!'
Write-Output "::add-mask::$password"
New-LocalUser -Name sshsharp -Password (ConvertTo-SecureString $password -AsPlainText -Force) -PasswordNeverExpires | Out-Null
Add-LocalGroupMember -Group Users -Member sshsharp

New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value 'C:\Program Files\Git\bin\bash.exe' -PropertyType String -Force | Out-Null
Start-Service sshd # creates the default sshd_config and host keys
Stop-Service sshd
$config = "$env:ProgramData\ssh\sshd_config"
@(
  'Port 2222'
  'ListenAddress 127.0.0.1'
  'ListenAddress ::1' # "localhost" resolves to ::1 first on Windows (the forwarding tests connect to it by name)
  'PasswordAuthentication yes'
  'MaxStartups 200:30:300'
  'MaxSessions 64'
  'AllowTcpForwarding yes'
  'RekeyLimit 32K' # re-keys every 32 KiB, as the Linux servers do, for the server-initiated re-key tests (RekeyInteropTests)
  'SyslogFacility LOCAL0' # log to a file (logs\sshd.log), not the event log
  'LogLevel DEBUG2' # channel EOF and shutdown events (rcvd eof, chan_shutdown_write), for the intermittent stdin hang (#86)
  'KexAlgorithms +diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'
) + (Get-Content $config | Where-Object { $_ -notmatch '^\s*(Port|ListenAddress|PasswordAuthentication|Match|AuthorizedKeysFile|AllowGroups|AllowUsers|DenyGroups|DenyUsers)\b' -and $_ -notmatch '^\s+' }) |
  Set-Content $config -Encoding ascii
& "$env:WINDIR\System32\OpenSSH\sshd.exe" -t
if ($LASTEXITCODE -ne 0) { throw "sshd_config is invalid" }
Start-Service sshd

$client = [System.Net.Sockets.TcpClient]::new('127.0.0.1', 2222)
$banner = [System.IO.StreamReader]::new($client.GetStream()).ReadLine()
$client.Dispose()
Write-Output "Server: $banner"
"Server: ``$banner``" >> $env:GITHUB_STEP_SUMMARY
@(
  'SSHSHARP_TEST_SSHD=127.0.0.1:2222'
  'SSHSHARP_TEST_USER=sshsharp'
  "SSHSHARP_TEST_PASSWORD=$password"
  'SSHSHARP_TEST_SERVER=OpenSSH'
  'SSHSHARP_TEST_SERVER_OS=windows'
  'SSHSHARP_TEST_SSHD_REKEY=1'
) >> $env:GITHUB_ENV

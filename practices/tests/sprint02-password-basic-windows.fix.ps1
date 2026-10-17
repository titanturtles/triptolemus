$ErrorActionPreference = 'Stop'

$inf = Join-Path $env:TEMP 'ptcomp_basic.inf'
$sdb = Join-Path $env:TEMP 'ptcomp_basic.sdb'
Remove-Item $sdb -Force -ErrorAction SilentlyContinue
@"
[Unit]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
ClearTextPassword = 0
MaximumPasswordAge = 60
MinimumPasswordAge = 1
PasswordHistorySize = 5
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@ | Set-Content -Path $inf -Encoding Unicode
secedit /configure /db $sdb /cfg $inf /areas SECURITYPOLICY | Out-Null

# Fixes for sprint01-accounts-adv-windows (CI tests only; never uploaded to students).
$ErrorActionPreference = 'Stop'
Remove-LocalUser -Name 'mallory'
Remove-LocalUser -Name 'eve'
Remove-LocalUser -Name 'ghost'
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'bob'
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'carol'
Remove-LocalGroupMember -SID 'S-1-5-32-555' -Member 'dave'
Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser
Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Disable-LocalUser
net accounts /minpwlen:12 | Out-Null
$inf = Join-Path $env:TEMP 'sp_fix.inf'
@"
[Unicode]
Unicode=yes
[System Access]
ClearTextPassword = 0
[Version]
signature="`$CHICAGO`$"
"@ | Set-Content -Path $inf -Encoding Unicode
secedit /configure /db (Join-Path $env:TEMP 'spfix.sdb') /cfg $inf /areas SECURITYPOLICY /quiet

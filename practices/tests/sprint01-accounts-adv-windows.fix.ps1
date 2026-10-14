# Fixes for sprint01-accounts-adv-windows (CI tests only; never uploaded to students).
$ErrorActionPreference = 'Stop'
Remove-LocalUser -Name 'mallory'
net user "sysadmin$" /delete | Out-Null
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'bob'
Remove-LocalGroupMember -SID 'S-1-5-32-551' -Member 'carol'
Remove-LocalGroupMember -SID 'S-1-5-32-555' -Member 'dave'
Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser
Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Disable-LocalUser
$w = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -Path $w -Name AutoAdminLogon -Value '0'
Remove-ItemProperty -Path $w -Name DefaultPassword -ErrorAction SilentlyContinue
Set-LocalUser -Name 'bob' -PasswordNeverExpires $false
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

# Remote-management service: least-privilege the account, drop unauthorized remote access, bring WinRM up
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'svc_wsman' -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID 'S-1-5-32-580' -Member 'wsmanguest' -ErrorAction SilentlyContinue
Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
try { Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null } catch { }
Start-Service -Name WinRM -ErrorAction SilentlyContinue

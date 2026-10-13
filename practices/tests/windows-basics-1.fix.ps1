# The fixes for windows-basics-1 (CI tests only; never uploaded to students).
$ErrorActionPreference = 'Stop'
Remove-LocalUser -Name 'hacker'
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'bob'
Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
net accounts /minpwlen:12 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "net accounts failed ($LASTEXITCODE)" }

# Fixes for sprint01-accounts-basic-windows (CI tests only; never uploaded to students).
$ErrorActionPreference = 'Stop'
Remove-LocalUser -Name 'mallory'
Remove-LocalUser -Name 'eve'
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'bob'
Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser
Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Disable-LocalUser

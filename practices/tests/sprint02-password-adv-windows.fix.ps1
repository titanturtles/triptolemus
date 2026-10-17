# Fixes for sprint02-password-adv-windows (CI only; never uploaded to students).
$ErrorActionPreference = 'Stop'
Remove-LocalUser -Name 'sauron'  -ErrorAction SilentlyContinue
Remove-LocalUser -Name 'saruman' -ErrorAction SilentlyContinue
Remove-LocalUser -Name 'gollum'  -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'boromir' -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID 'S-1-5-32-573' -Member 'merry'   -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID 'S-1-5-32-580' -Member 'pippin'  -ErrorAction SilentlyContinue

$inf = Join-Path $env:TEMP 'ptcomp_secpol.inf'
$sdb = Join-Path $env:TEMP 'ptcomp_secpol.sdb'
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
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@ | Set-Content -Path $inf -Encoding Unicode
secedit /configure /db $sdb /cfg $inf /areas SECURITYPOLICY | Out-Null

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name 'Enabled' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableWebPnPDownload' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -Name 'EnableProtectedEventLogging' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Type DWord -Value 0
Set-Service -Name Spooler -StartupType Disabled -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
schtasks /Delete /TN 'OrcGen' /F | Out-Null
foreach ($s in 'Wireshark','Nmap','TeamViewer') {
    Remove-Item -Path (Join-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' $s) -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path 'C:\Program Files' $s) -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item -Path 'C:\Users\Public\Videos\gandalf_dance.mp4' -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\Users\Public\Music\one_ring.mp3' -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\Users\Public\Documents\creditcards.txt' -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\Users\Public\Documents\passwords.txt' -Force -ErrorAction SilentlyContinue

Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'svc_winrm'   -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID 'S-1-5-32-580' -Member 'mordoragent' -ErrorAction SilentlyContinue
Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
try { Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null } catch { }
Start-Service -Name WinRM -ErrorAction SilentlyContinue
Set-Service -Name LanmanServer -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name LanmanServer -ErrorAction SilentlyContinue
Revoke-SmbShareAccess -Name 'CompanyData' -AccountName 'Everyone' -Force -ErrorAction SilentlyContinue | Out-Null
Grant-SmbShareAccess  -Name 'CompanyData' -AccountName 'Authenticated Users' -AccessRight Read -Force -ErrorAction SilentlyContinue | Out-Null

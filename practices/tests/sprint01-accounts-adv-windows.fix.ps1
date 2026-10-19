# Fixes for sprint01-accounts-adv-windows (CI only; never uploaded to students).
$ErrorActionPreference = 'Stop'
Remove-LocalUser -Name 'pmckinney' -ErrorAction SilentlyContinue
Remove-LocalUser -Name 'yismaylov' -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'jbyers'  -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'mbauman' -ErrorAction SilentlyContinue
if (-not (Get-LocalUser -Name esinclair -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name esinclair -Password (ConvertTo-SecureString 'Str0ng!Pass#99x' -AsPlainText -Force) -PasswordNeverExpires | Out-Null
}
if (-not (Get-LocalGroup -Name dragonfire -ErrorAction SilentlyContinue)) { New-LocalGroup -Name dragonfire | Out-Null }
foreach ($u in 'emunson','gareth','jeff','mwheeler','dhenderson','lsinclair','esinclair') { Add-LocalGroupMember -Group dragonfire -Member $u -ErrorAction SilentlyContinue }
cmd /c 'net accounts /maxpwage:90' | Out-Null
cmd /c 'net accounts /lockoutthreshold:10 /lockoutduration:30 /lockoutwindow:30' | Out-Null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Type DWord -Value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM'  -Type DWord -Value 1
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 0
foreach ($s in 'Wireshark','NetStumbler','PC Cleaner') {
    Remove-Item -Path (Join-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' $s) -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path 'C:\Program Files' $s) -Recurse -Force -ErrorAction SilentlyContinue
}

# WinRM: least-privilege the service account, drop the rogue remote user, harden the config, keep it RUNNING
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member 'svc_wsman'  -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID 'S-1-5-32-580' -Member 'wsmanguest' -ErrorAction SilentlyContinue
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic'              -Type DWord -Value 0
Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name WinRM -ErrorAction SilentlyContinue

# CompanyData: tighten SMB, remove the Everyone grant, keep the file server RUNNING
$lsp = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-ItemProperty -Path $lsp -Name 'SMB1'                     -Type DWord -Value 0
Set-ItemProperty -Path $lsp -Name 'RequireSecuritySignature' -Type DWord -Value 1
Set-ItemProperty -Path $lsp -Name 'EnableSecuritySignature'  -Type DWord -Value 1
Set-ItemProperty -Path $lsp -Name 'RestrictNullSessAccess'   -Type DWord -Value 1
Set-Service -Name LanmanServer -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service -Name LanmanServer -ErrorAction SilentlyContinue
Revoke-SmbShareAccess -Name 'CompanyData' -AccountName 'Everyone' -Force -ErrorAction SilentlyContinue | Out-Null
Grant-SmbShareAccess  -Name 'CompanyData' -AccountName 'Authenticated Users' -AccessRight Read -Force -ErrorAction SilentlyContinue | Out-Null

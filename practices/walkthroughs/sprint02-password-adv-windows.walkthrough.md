# Walkthrough — Week 2 Advanced: Password & Policy (Windows)

A guided solve of `sprint02-password-adv-windows` (the "Fellowship" / LOTR image). It reveals the answers,
so it's a teaching aid / debrief, not a handout to give before students try it.

**The brief:** you administer the Fellowship Logistics workstation. This week emphasizes **password &
policy**, but a full review turned up account, group, registry, service, and software problems. Authorized
users are **frodo, sam, aragorn, gandalf, boromir, merry, pippin** (boromir is ordinary — not an admin;
merry and pippin hold no special groups), plus the service account **svc_winrm**. Two services (WinRM and
the CompanyData share) are **stopped** and must come back **secured**. There are forensics questions, and
**deleting a legitimate app (7-Zip, Notepad++) costs points**.

Open **PowerShell as Administrator**.

---

## 0. Recon first

```powershell
Get-LocalUser | Select Name, Enabled
Get-LocalGroupMember Administrators
Get-LocalGroupMember 'Event Log Readers'
Get-LocalGroupMember 'Remote Management Users'
Get-Service WinRM, LanmanServer, Spooler | Select Name, Status, StartType
```
Unauthorized accounts jump out: **sauron**, **saruman**, **gollum**, and **mordoragent**. **boromir** is
wrongly in Administrators; **merry** in Event Log Readers; **pippin** and **mordoragent** in Remote
Management Users; **svc_winrm** is wrongly an admin.

## 1. Accounts & groups

```powershell
Remove-LocalUser sauron; Remove-LocalUser saruman; Remove-LocalUser gollum
Remove-LocalUser mordoragent                                              # rogue remote account
Remove-LocalGroupMember -Group Administrators -Member boromir             # demote, keep the account
Remove-LocalGroupMember -Group 'Event Log Readers' -Member merry
Remove-LocalGroupMember -Group 'Remote Management Users' -Member pippin
```

## 2. Password & lockout policy (this week's focus)

Open **secpol.msc → Account Policies**, or script it with `secedit`:
```powershell
$inf = "$env:TEMP\pw.inf"
@"
[Unit]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
ClearTextPassword = 0
MaximumPasswordAge = 60
MinimumPasswordAge = 1
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@ | Set-Content $inf -Encoding Unicode
secedit /configure /db "$env:TEMP\pw.sdb" /cfg $inf /areas SECURITYPOLICY
```
(Complexity on, reversible encryption off, length ≥ 10, max age 1–90, lockout 1–10.)

## 3. Local policy registry

```powershell
$sys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty $sys -Name DisableCAD -Type DWord -Value 0                 # require CTRL+ALT+DEL
Set-ItemProperty $sys -Name ShutdownWithoutLogon -Type DWord -Value 0        # no shutdown without logon
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Type DWord -Value 255   # autoplay off
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name Enabled -Type DWord -Value 1
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name DisableWebPnPDownload -Type DWord -Value 1
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -Name EnableProtectedEventLogging -Type DWord -Value 1
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -Type DWord -Value 1
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Type DWord -Value 0
```
(Create a key first with `New-Item -Force` if `Set-ItemProperty` complains it doesn't exist.)

## 4. Services off & firewall

```powershell
Set-Service Spooler -StartupType Disabled; Stop-Service Spooler -Force      # PrintNightmare
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
```

## 5. Prohibited software, files & tasks

The three tools are really installed — uninstall them in **Settings → Apps**, or force-remove:
```powershell
foreach ($s in 'Wireshark','Nmap','TeamViewer') {
    Remove-Item (Join-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' $s) -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path 'C:\Program Files' $s) -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item 'C:\Users\Public\Videos\gandalf_dance.mp4','C:\Users\Public\Music\one_ring.mp3' -Force
Remove-Item 'C:\Users\Public\Documents\creditcards.txt','C:\Users\Public\Documents\passwords.txt' -Force
schtasks /Delete /TN OrcGen /F                                             # 'orc generator' persistence
```
> ⚠️ **7-Zip** and **Notepad++** are also in the installed-apps list — they're legitimate. Removing either
> is −10.

## 6. Forensics (answer in the agent's "Forensics…" panel)

```powershell
Get-Content C:\Users\Public\meme.png -Stream Zone.Identifier    # HostUrl -> mordor-downloads.example  (fq1)
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content C:\Users\Public\forensics\note.b64).Trim()))  # -> precious (fq2)
```
- **fq1** → `mordor-downloads.example`  · **fq2** → `precious`

## 7. Bring the two services back — working AND secured

**WinRM.** Its service account is an admin and a rogue account can manage the box. Fix, then start it:
```powershell
Remove-LocalGroupMember -Group Administrators -Member svc_winrm            # least-privilege (already removed mordoragent in step 1)
Set-Service -Name WinRM -StartupType Automatic
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Start-Service WinRM
Test-WSMan -ComputerName localhost                                        # should respond
```
Leave `svc_winrm` *in* "Remote Management Users" — that's its least-privileged role; you only remove admin.

**CompanyData file share.** Stopped and open to Everyone:
```powershell
Set-Service -Name LanmanServer -StartupType Automatic
Start-Service LanmanServer
Revoke-SmbShareAccess -Name CompanyData -AccountName Everyone -Force
Grant-SmbShareAccess  -Name CompanyData -AccountName 'Authenticated Users' -AccessRight Read -Force
Get-Content \\localhost\CompanyData\sentinel.txt     # -> PT-SMB-OK-7B2E
Get-SmbShareAccess -Name CompanyData                 # no 'Everyone / Allow' entry
```

## 8. Final sweep

- Recon again: only authorized users remain; Administrators has no boromir/svc_winrm; Event Log Readers has
  no merry; Remote Management Users has no pippin/mordoragent.
- `Get-Service WinRM, LanmanServer` → both **Running**; `Test-WSMan localhost` responds; share serves its
  sentinel and Everyone is gone; `Get-Service Spooler` → Disabled.
- Confirm 7-Zip and Notepad++ are still installed (didn't earn a penalty).

That's 33 hardening checks + 2 forensics, 2 penalties to avoid. Work top-down: recon, accounts/groups,
policy, registry, software/files — and the services last so you can verify they still work.

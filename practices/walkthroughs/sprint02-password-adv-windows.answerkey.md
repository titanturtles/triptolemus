# Answer Key — Week 2 Advanced: Password & Policy (Windows)

**INSTRUCTOR ONLY.** Contains every solution and the forensics answers. Do not give to students
before the exercise. Scenario: `sprint02-password-adv-windows` (image-is-body, the "Fellowship" / Lord of
the Rings theme, Windows 10). 33 scored hardening problems (20 pts each) + 2 forensics (20 pts) + 2
penalties (−10 each).

**Authorized users:** frodo, sam, aragorn, gandalf, boromir, merry, pippin (boromir is an ordinary user,
not an admin; merry and pippin hold no special group memberships). The one permitted service account is
**svc_winrm**. Open an **elevated PowerShell** (Run as administrator).

---

## Accounts & groups

| # | Check | Fix |
|---|-------|-----|
| 1 | Removed unauthorized user **sauron** | `Remove-LocalUser sauron` |
| 2 | Removed unauthorized user **saruman** | `Remove-LocalUser saruman` |
| 3 | Removed unauthorized user **gollum** | `Remove-LocalUser gollum` |
| 4 | **boromir** is no longer an administrator | `Remove-LocalGroupMember -Group Administrators -Member boromir` (keep the account) |
| 5 | **merry** is no longer an **Event Log Reader** | `Remove-LocalGroupMember -Group 'Event Log Readers' -Member merry` |
| 6 | **pippin** is no longer a **Remote Management User** | `Remove-LocalGroupMember -Group 'Remote Management Users' -Member pippin` |

> Also remove the rogue remote account **mordoragent** (unauthorized, planted in *Remote Management
> Users*): `Remove-LocalUser mordoragent`. It isn't individually scored, but the README's authorized list
> excludes it and it can manage the box — clean it up.

## Password & lockout policy (secpol.msc → Account Policies, or `secedit`)

| # | Check | Setting |
|---|-------|---------|
| 7 | Passwords must meet complexity requirements | `PasswordComplexity = 1` (Enabled) |
| 8 | No reversible encryption | `ClearTextPassword = 0` (Disabled) |
| 9 | Minimum password length ≥ 10 | `MinimumPasswordLength = 12` |
| 10 | Secure maximum password age (1–90) | `MaximumPasswordAge = 60` |
| 11 | Secure account lockout threshold (1–10) | `LockoutBadCount = 5` |

## Local policy registry

| # | Check | Fix |
|---|-------|-----|
| 12 | CTRL+ALT+DEL required for logon | `...\Policies\System\DisableCAD = 0` |
| 13 | Cannot shut down without logon | `...\Policies\System\ShutdownWithoutLogon = 0` |
| 14 | Autoplay/Autorun disabled on all drives | `...\Policies\Explorer\NoDriveTypeAutoRun = 255` |
| 15 | FIPS-compliant algorithms enabled | `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled = 1` |
| 16 | Print drivers over HTTP disabled | `...\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload = 1` |
| 17 | Protected event logging enabled | `...\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging\EnableProtectedEventLogging = 1` |
| 18 | Defender SmartScreen enabled | `...\Policies\Microsoft\Windows\System\EnableSmartScreen = 1` |
| 19 | Defender antivirus not disabled by policy | `...\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 0` |

## Services, firewall

| # | Check | Fix |
|---|-------|-----|
| 20 | Print Spooler disabled | `Set-Service Spooler -StartupType Disabled; Stop-Service Spooler` (PrintNightmare) |
| 21 | Firewall enabled | `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True` |

## Prohibited software (really installed — uninstall via Programs & Features, or force-remove)

The scoring passes once **both** the `Uninstall` key and the `C:\Program Files\<name>` folder are gone.

| # | Check | Fix |
|---|-------|-----|
| 22 | **Wireshark** removed | Uninstall, or remove `...\Uninstall\Wireshark` + `C:\Program Files\Wireshark` |
| 23 | **Nmap** removed | Uninstall, or remove `...\Uninstall\Nmap` + `C:\Program Files\Nmap` |
| 24 | **TeamViewer** removed | Uninstall, or remove `...\Uninstall\TeamViewer` + `C:\Program Files\TeamViewer` |

## Prohibited files & tasks

| # | Check | Fix |
|---|-------|-----|
| 25 | Unauthorized video removed | `Remove-Item 'C:\Users\Public\Videos\gandalf_dance.mp4'` |
| 26 | Unauthorized audio removed | `Remove-Item 'C:\Users\Public\Music\one_ring.mp3'` |
| 27 | Credit-card file removed | `Remove-Item 'C:\Users\Public\Documents\creditcards.txt'` |
| 28 | Plaintext password file removed | `Remove-Item 'C:\Users\Public\Documents\passwords.txt'` |
| 29 | **OrcGen** scheduled task removed | `schtasks /Delete /TN OrcGen /F` (or `Unregister-ScheduledTask -TaskName OrcGen -Confirm:$false`) |

## The two services — keep WORKING and harden

Both were left **stopped**. Bring each up and secure it.

**WinRM remote management.** It's stopped/disabled, `svc_winrm` is an administrator, and `mordoragent` is a
rogue Remote Management User.
```powershell
Remove-LocalGroupMember -Group Administrators -Member svc_winrm            # demote (keep the account + its Remote Management role)
Remove-LocalGroupMember -Group 'Remote Management Users' -Member mordoragent
Set-Service -Name WinRM -StartupType Automatic
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Start-Service WinRM
```
- Check 30 "WinRM running and responds": service up **and** `Test-WSMan -ComputerName localhost` succeeds.
- Check 31 "svc_winrm is not an administrator": account exists, not in **Administrators**.

**CompanyData file share.** Left stopped and open to **Everyone**.
```powershell
Set-Service -Name LanmanServer -StartupType Automatic
Start-Service LanmanServer
Revoke-SmbShareAccess -Name CompanyData -AccountName Everyone -Force
Grant-SmbShareAccess  -Name CompanyData -AccountName 'Authenticated Users' -AccessRight Read -Force
```
- Check 32 "share available": `LanmanServer` running **and** `Get-Content \\localhost\CompanyData\sentinel.txt` → `PT-SMB-OK-7B2E`.
- Check 33 "not open to Everyone": `Get-SmbShareAccess -Name CompanyData` shows no `Everyone / Allow`.

## Forensics (enter in the agent's "Forensics…" panel)

| Q | Question | Answer |
|---|----------|--------|
| fq1 | `meme.png` in `C:\Users\Public` carries a mark-of-the-web — what host was it downloaded from? | **mordor-downloads.example** (read the ADS: `Get-Content C:\Users\Public\meme.png -Stream Zone.Identifier` → `HostUrl=http://mordor-downloads.example/meme.png`) |
| fq2 | Decode the Base64 in `C:\Users\Public\forensics\note.b64` — what word? | **precious** (`cHJlY2lvdXM=`) |

## Penalties — do NOT trigger (−10 each)

- Do **not** uninstall / delete `C:\Program Files\7-Zip` (real Programs & Features entry).
- Do **not** uninstall / delete `C:\Program Files\Notepad++`.

Both are legitimate installed applications. Only **Wireshark**, **Nmap**, and **TeamViewer** are prohibited.

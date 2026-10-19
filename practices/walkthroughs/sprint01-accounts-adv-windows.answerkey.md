# Answer Key — Week 1 Advanced: Accounts (Windows)

**INSTRUCTOR ONLY.** Contains every solution and the forensics answers. Do not give to students
before the exercise. Scenario: `sprint01-accounts-adv-windows` (image-is-body, a Stranger Things–themed
Windows 10 workstation). 25 scored hardening problems (20 pts each) + 2 forensics (20 pts) + 4 penalties
(−10 each: two apps, two required services).

**Authorized users** (now stated in the README): emunson, gareth, jeff, mwheeler, dhenderson, lsinclair,
jbyers, mbauman — all ordinary users, none a local administrator — plus **esinclair** (student creates) and
the service account **svc_wsman**. Any other non-built-in account is unauthorized.

**Authorized end-state:** remove **pmckinney** and **yismaylov** (and **wsmanguest**); keep **jbyers** and
**mbauman** but strip their admin rights; **create** user **esinclair** and group **dragonfire**. The two
services (WinRM and the CompanyData share) start **running but misconfigured** — harden them **in place and
leave them running**. Removing a legitimate app (Firefox, GIMP) is a penalty, and so is **leaving either
required service stopped**. Note: unlike the Linux scenario, there is **no penalty** for deleting an
authorized user.

Open an **elevated PowerShell** (Run as administrator) and run everything below there.

---

## Accounts & groups

| # | Check | Fix |
|---|-------|-----|
| 1 | Removed the unauthorized user **pmckinney** | `Remove-LocalUser -Name pmckinney` |
| 2 | Removed the unauthorized user **yismaylov** | `Remove-LocalUser -Name yismaylov` |
| 3 | **jbyers** is no longer an administrator | `Remove-LocalGroupMember -Group Administrators -Member jbyers` (keep the jbyers account) |
| 4 | **mbauman** is no longer an administrator | `Remove-LocalGroupMember -Group Administrators -Member mbauman` (keep the mbauman account) |
| 5 | Created the required user **esinclair** | `New-LocalUser -Name esinclair -Password (Read-Host -AsSecureString)` (give it a strong password; `-PasswordNeverExpires` optional) |
| 6 | Created the required group **dragonfire** | `New-LocalGroup -Name dragonfire` |
| 7 | The **dragonfire** group has the required members | Add all seven: `foreach ($u in 'emunson','gareth','jeff','mwheeler','dhenderson','lsinclair','esinclair') { Add-LocalGroupMember -Group dragonfire -Member $u }` |

## Password & account policy

| # | Check | Fix |
|---|-------|-----|
| 8 | A secure **maximum password age** (1–90 days) | `net accounts /maxpwage:90` (or secpol.msc → Account Policies → Password Policy) |
| 9 | A secure **account lockout threshold** (5–50) | `net accounts /lockoutthreshold:10 /lockoutduration:30 /lockoutwindow:30` |
| 10 | **Blank passwords** limited to console logon only | `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -Type DWord -Value 1` |
| 11 | **Anonymous enumeration of SAM** disabled | `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -Type DWord -Value 1` |

## Features & updates

| # | Check | Fix |
|---|-------|-----|
| 12 | The **firewall** is enabled | `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True` |
| 13 | **Remote Assistance** is disabled | `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Type DWord -Value 0` |
| 14 | **Automatic updates** are enabled | `Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Type DWord -Value 0` (value must not be 1) |

## Prohibited software

These are **really installed** now — each shows up in **Programs & Features** (Settings → Apps) with a
publisher, version, size, and a working uninstaller, and has real files under `C:\Program Files\<name>`.
The scoring passes once **both** the `Uninstall` registry key **and** the `C:\Program Files\<name>` folder
are gone, so the cleanest fix is a proper uninstall (Settings → Apps → *Uninstall*, or run the app's
`UninstallString`); the registry key and folder both disappear.

| # | Check | Fix |
|---|-------|-----|
| 15 | **Wireshark** removed | Uninstall via Programs & Features, **or** remove `...\Uninstall\Wireshark` and `C:\Program Files\Wireshark` |
| 16 | **NetStumbler** removed | Uninstall, **or** remove the `...\Uninstall\NetStumbler` key and `C:\Program Files\NetStumbler` |
| 17 | **PC Cleaner** removed | Uninstall, **or** remove the `...\Uninstall\PC Cleaner` key and `C:\Program Files\PC Cleaner` |

A loop clears all three by force (equivalent to uninstalling):
```powershell
foreach ($s in 'Wireshark','NetStumbler','PC Cleaner') {
    Remove-Item (Join-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' $s) -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path 'C:\Program Files' $s) -Recurse -Force -ErrorAction SilentlyContinue
}
```

## The two services — harden IN PLACE (do not stop them)

Both services start **running but misconfigured**. Secure each one **without stopping or disabling it** —
leaving either stopped is a −10 penalty (see below).

**WinRM remote management.** `svc_wsman` was made an administrator, `wsmanguest` was planted in *Remote
Management Users*, and the service accepts unencrypted traffic and Basic auth.
```powershell
Remove-LocalGroupMember -Group Administrators -Member svc_wsman             # drop the admin right (keep the account, keep it in Remote Management Users)
Remove-LocalGroupMember -Group 'Remote Management Users' -Member wsmanguest   # revoke the rogue remote user
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowUnencryptedTraffic -Type DWord -Value 0
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowBasic              -Type DWord -Value 0
Set-Service -Name WinRM -StartupType Automatic; Start-Service WinRM          # keep it running
```
- Check 18 "svc_wsman is not an administrator": account exists, not in **Administrators**. (Leave it in *Remote Management Users* — that's its least-privileged role.)
- Check 19 "no unauthorized account can manage remotely": **wsmanguest** not in *Remote Management Users* (removing it from the group is enough; deleting the account also passes).
- Check 20 "WinRM refuses unencrypted traffic": policy value `AllowUnencryptedTraffic = 0`.
- Check 21 "WinRM does not allow Basic authentication": policy value `AllowBasic = 0`.

**CompanyData file share.** Shared to **Everyone**, with SMBv1 on, signing not required, and anonymous
null-session access allowed.
```powershell
Revoke-SmbShareAccess -Name CompanyData -AccountName Everyone -Force
Grant-SmbShareAccess  -Name CompanyData -AccountName 'Authenticated Users' -AccessRight Read -Force
$lsp = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-ItemProperty $lsp -Name SMB1                     -Type DWord -Value 0   # or: Set-SmbServerConfiguration -EnableSMB1Protocol $false
Set-ItemProperty $lsp -Name RequireSecuritySignature -Type DWord -Value 1
Set-ItemProperty $lsp -Name RestrictNullSessAccess   -Type DWord -Value 1
Set-Service -Name LanmanServer -StartupType Automatic; Start-Service LanmanServer   # keep it running
```
- Check 22 "share not open to Everyone": `Get-SmbShareAccess -Name CompanyData` shows **no** `Everyone / Allow` entry (serve `\\localhost\CompanyData\sentinel.txt` → `PT-SMB-OK-9A4D`).
- Check 23 "SMBv1 is disabled": `LanmanServer\Parameters\SMB1 = 0`.
- Check 24 "SMB signing is required": `RequireSecuritySignature = 1`.
- Check 25 "null-session access restricted": `RestrictNullSessAccess = 1`.

## Forensics (enter in the agent's "Forensics…" panel)

Artifacts live in **`C:\Users\Public\forensics`**.

| Q | Question | Answer |
|---|----------|--------|
| fq1 | Decode the **hex** message in `C:\Users\Public\forensics` | **Running Up That Hill** (`q1_hex.txt` = `52756e...` → ASCII) |
| fq2 | Decode the **Base64** message in `C:\Users\Public\forensics` | **stranger** (`q2_base64.txt` = `c3RyYW5nZXI=`) |

Decode quickly in PowerShell:
```powershell
# fq1 — hex -> text
$h = (Get-Content C:\Users\Public\forensics\q1_hex.txt).Trim()
-join ($h -split '(?<=\G..)(?=.)' | ForEach-Object { [char][convert]::ToInt32($_,16) })
# fq2 — base64 -> text
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content C:\Users\Public\forensics\q2_base64.txt).Trim()))
```

## Penalties — do NOT trigger (−10 each)

- Do **not** uninstall / delete `C:\Program Files\Mozilla Firefox` (now a real Programs & Features entry).
- Do **not** uninstall / delete `C:\Program Files\GIMP 2`.
- Do **not** leave **WinRM** stopped — it must be running at scoring time.
- Do **not** leave the **Server service (LanmanServer)** stopped — the file share must stay served.

Firefox and GIMP are legitimate installed applications — only **Wireshark**, **NetStumbler**, and
**PC Cleaner** are prohibited. The service penalties exist so students can't "solve" a service vuln by
disabling the service: the fix is to harden it in place, not to stop it.

# Walkthrough — Week 1 Advanced: Accounts (Windows)

A guided solve of `sprint01-accounts-adv-windows`. It reveals the answers, so it's a teaching aid /
post-exercise debrief, not a handout to give before students try it themselves.

**The brief:** you administer a Windows 10 workstation modeled on a real competition image. A security
review turned up problems across accounts, groups, policy, the registry, services, and installed
software. Harden the box **without** breaking what the company needs. This one also asks you to **add**
things: create the user **esinclair**, create the group **dragonfire**, and populate it. Two services must
end up **running and secured** — WinRM remote management and the CompanyData file share — and both start
stopped. There are forensics questions, and **deleting a legitimate app costs points**.

Open **PowerShell as Administrator** (right-click → Run as administrator). Everything below goes there.

---

## 0. Recon first (look before you touch)

```powershell
Get-LocalUser | Select Name, Enabled                       # who exists
Get-LocalGroupMember Administrators                        # who has admin
Get-LocalGroupMember 'Remote Management Users'             # who can manage remotely
Get-SmbShare                                               # what's shared
Get-Service WinRM, LanmanServer | Select Name, Status, StartType
```

Compare against the brief's authorized-users list — **emunson, gareth, jeff, mwheeler, dhenderson,
lsinclair, jbyers, mbauman** (ordinary users, none an admin), plus **esinclair** you'll create, and the one
service account **svc_wsman**. Anyone else is unauthorized: **pmckinney** and **yismaylov** aren't on the
list; **jbyers** and **mbauman** are authorized but are wrongly in Administrators; **svc_wsman** is wrongly
an admin (it should be remote-management only); **wsmanguest** can manage the box remotely but isn't on
the list at all.

## 1. Accounts & groups

```powershell
Remove-LocalUser -Name pmckinney                           # unauthorized
Remove-LocalUser -Name yismaylov                           # unauthorized
Remove-LocalGroupMember -Group Administrators -Member jbyers    # demote, keep the account
Remove-LocalGroupMember -Group Administrators -Member mbauman   # demote, keep the account
```

Now **add** what the company needs:
```powershell
New-LocalUser -Name esinclair -Password (Read-Host -AsSecureString)   # type a strong password when prompted
New-LocalGroup -Name dragonfire
foreach ($u in 'emunson','gareth','jeff','mwheeler','dhenderson','lsinclair','esinclair') {
    Add-LocalGroupMember -Group dragonfire -Member $u
}
Get-LocalGroupMember dragonfire     # verify all seven are present
```

> ⚠️ Don't delete jbyers or mbauman — they're authorized, you only strip their admin rights. And don't
> forget esinclair has to exist *before* you can add it to dragonfire.

## 2. Password & account policy

```powershell
net accounts /maxpwage:90                                      # max password age in range (1–90)
net accounts /lockoutthreshold:10 /lockoutduration:30 /lockoutwindow:30   # lockout after 10 bad tries

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -Type DWord -Value 1
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM  -Type DWord -Value 1
```
(The two `net accounts` settings are the same ones under `secpol.msc` → Account Policies if you prefer the GUI.)

## 3. Features & updates

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True         # firewall on, all profiles
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Type DWord -Value 0   # kill Remote Assistance
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Type DWord -Value 0    # re-enable auto updates
```

## 4. Prohibited software

Three tools must go — **Wireshark**, **NetStumbler**, **PC Cleaner**. They're really installed: open
**Settings → Apps → Installed apps** (or `appwiz.cpl`) and you'll see all three with a publisher and
version. The normal way is to **Uninstall** each one there — that clears both the Programs & Features entry
and the files on disk, which is exactly what the scoring checks for.

If you'd rather script it, this force-removes the same two things (the uninstall registry key *and* the
install folder) for all three:
```powershell
foreach ($s in 'Wireshark','NetStumbler','PC Cleaner') {
    Remove-Item (Join-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' $s) -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path 'C:\Program Files' $s) -Recurse -Force -ErrorAction SilentlyContinue
}
```

> ⚠️ **Mozilla Firefox** and **GIMP** are also in that Installed-apps list, and they're legitimate —
> uninstalling or deleting either is −10. Only remove the three tools above.

## 5. Forensics (answer in the agent's "Forensics…" panel)

The artifacts are in `C:\Users\Public\forensics`.
```powershell
# Q1 — decode the hex
$h = (Get-Content C:\Users\Public\forensics\q1_hex.txt).Trim()
-join ($h -split '(?<=\G..)(?=.)' | ForEach-Object { [char][convert]::ToInt32($_,16) })    # -> Running Up That Hill

# Q2 — decode the Base64
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content C:\Users\Public\forensics\q2_base64.txt).Trim()))   # -> stranger
```
- **fq1** → `Running Up That Hill`
- **fq2** → `stranger`

## 6. Harden the two services — IN PLACE, and keep them running

Both services are **already running** this time; they're just misconfigured. Secure each one **without
stopping or disabling it** — if you leave WinRM or the file server stopped at scoring time, that's a −10
penalty each. Don't try to "fix" a service by turning it off.

**WinRM (remote management).** Its service account is an admin, a rogue account can manage the box, and it
accepts unencrypted + Basic auth. Fix all of that, leave it running:
```powershell
Remove-LocalGroupMember -Group Administrators -Member svc_wsman             # least-privilege the service account
Remove-LocalGroupMember -Group 'Remote Management Users' -Member wsmanguest   # revoke the rogue remote user
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowUnencryptedTraffic -Type DWord -Value 0
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name AllowBasic              -Type DWord -Value 0
Get-Service WinRM        # confirm it's still Running — do NOT stop it
```
Leave `svc_wsman` *in* "Remote Management Users" — that's exactly the least-privileged role it needs. You're
only taking away its admin rights.

**CompanyData file share.** Shared to **Everyone**, with SMBv1 on, signing off, and anonymous null-session
access allowed. Tighten all of it; keep the Server service running:
```powershell
Revoke-SmbShareAccess -Name CompanyData -AccountName Everyone -Force
Grant-SmbShareAccess  -Name CompanyData -AccountName 'Authenticated Users' -AccessRight Read -Force
$lsp = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
Set-ItemProperty $lsp -Name SMB1                     -Type DWord -Value 0   # disable SMBv1
Set-ItemProperty $lsp -Name RequireSecuritySignature -Type DWord -Value 1   # require SMB signing
Set-ItemProperty $lsp -Name RestrictNullSessAccess   -Type DWord -Value 1   # block anonymous access
Get-Content \\localhost\CompanyData\sentinel.txt        # -> PT-SMB-OK-9A4D (share still served)
Get-SmbShareAccess -Name CompanyData                    # no 'Everyone / Allow' entry remains
```

## 7. Final sweep

- Re-run the recon from step 0: only authorized users remain; Administrators has no jbyers/mbauman/svc_wsman;
  Remote Management Users has no wsmanguest; dragonfire has its seven members and esinclair exists.
- `Get-Service WinRM, LanmanServer` → both **Running** (you hardened them without stopping them); the share
  serves its sentinel and Everyone is gone.
- Confirm Firefox and GIMP are still installed (didn't earn a penalty).

That's 25 hardening checks plus 2 forensics, with 4 penalties to avoid. In a real round, work top-down like
this — recon, then accounts/groups, then policy/registry, then prohibited software, and leave the services for last so
you can verify they still work after you harden them.

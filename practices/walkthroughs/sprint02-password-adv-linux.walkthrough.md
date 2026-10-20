# Walkthrough — Week 2 Advanced: Password & Policy (Linux)

A guided solve of `sprint02-password-adv-linux` (the "NEVERMORE" image). It reveals the answers, so it's a
teaching aid / debrief, not a handout to give before students try it.

**The brief:** you administer the NEVERMORE Publishing House workstation. This week emphasizes **password &
policy**, but a full review turned up account, kernel, sudo, service, and persistence problems. Authorized
users are **edgar, lenore, usher, vkinbott** (vkinbott is an ordinary user — **no sudo**). Two services (an
FTP download service and password-only SSH) are **stopped** and must come back **secured**. There are
forensics questions, and **deleting edgar or usher costs points**.

Work as your admin account; prefix privileged commands with `sudo`.

**How CyberPatriot scores this image.** The scoring report groups every point by *vulnerability category*.
This image touches, in order: **Forensics Questions**, **Account Management**, **Account & Password Policy**,
**Defensive Countermeasures**, **Uncategorized Operating System Settings**, **Operating System & Application
Updates**, **Service Auditing**, **Malware**, and **Unwanted Software**, plus **Penalties** for actions that
lose points. Answer the Forensics questions FIRST — before you change anything — because your fixes can
destroy the evidence; then work down the categories.

---

## Recon first

```bash
cut -d: -f1,3 /etc/passwd                       # users + UIDs
awk -F: '$3==0 {print $1}' /etc/passwd          # anyone with UID 0 — should be ONLY root
getent group sudo                                # who's an admin
systemctl is-active vsftpd ssh apparmor          # service state
```
You'll find unauthorized accounts (**rowan**, **mmouse**), a UID-0 impostor (**lgates**), and **vkinbott**
wrongly in `sudo`.

## Forensics Questions

_Questions you answer about the image; read and answer these BEFORE changing anything, since fixes can destroy the evidence._

Answer these in the agent's "Forensics…" panel.

```bash
grep 'Failed password' /var/log/auth.log            # -> from 198.51.100.77   (fq1)
base64 -d /home/edgar/.cache/raven.b64; echo        # -> nevermore            (fq2)
grep 198.51.100.77 /etc/crontab                     # -> ...:8443/x | bash    (fq3 = 8443)
```
- **fq1** → `198.51.100.77`  · **fq2** → `nevermore`  · **fq3** → `8443`

## Account Management

_Unauthorized accounts, administrator/sudo rights, required users and groups, and UID‑0 impostors._

```bash
sudo userdel -rf rowan
sudo userdel -rf mmouse
sudo gpasswd -d vkinbott sudo                    # strip admin, keep the account
sudo userdel -f lgates                           # the UID-0 impostor (-f: shares UID 0)
```
> ⚠️ Never `pkill -u lgates` — it shares UID 0 with root, so you'd kill every root process. Just `userdel`.

## Account & Password Policy

_Password policy (length, hashing, dictionary checking, history) and related account policy._

This is the week's focus.

```bash
sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs       # strong hashing
sudo tee /etc/security/pwquality.conf >/dev/null <<'EOF'
minlen = 12
dictcheck = 1
EOF
# password history: add before the pam_unix.so line in /etc/pam.d/common-password
sudo sed -i '/pam_unix.so/i password\trequired\t\t\tpam_pwhistory.so remember=5 use_authtok' /etc/pam.d/common-password
```

## Defensive Countermeasures

_Firewall, antivirus, and mandatory-access-control (AppArmor) protections._

```bash
sudo ufw --force enable
sudo systemctl enable --now apparmor
```

## Uncategorized Operating System Settings

_OS hardening that doesn't fit another category: kernel sysctl parameters and file-permission hardening (world-writable configs, stray SUID bits, sudoers environment hardening)._

Kernel hardening:
```bash
sudo tee /etc/sysctl.d/99-ptcomp.conf >/dev/null <<'EOF'
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2
net.ipv4.tcp_syncookies = 1
kernel.dmesg_restrict = 1
EOF
sudo sysctl --system
```

sudo & file permissions:
```bash
sudo rm -f /etc/sudoers.d/90-ptcomp-preload      # drops the dangerous LD_PRELOAD env_keep
sudo rm -f /etc/sudoers.d/91-ptcomp-coredump     # drops '!disable_coredump'
sudo chmod 644 /etc/ssh/sshd_config              # was world-writable
sudo chmod u-s /bin/date                         # strip the planted SUID bit
```

## Operating System & Application Updates

_Automatic OS and application update settings._

```bash
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades
```

## Service Auditing

_Required services brought up and hardened IN PLACE (never by disabling them); includes each service's per-setting sub-checks._

The two services were left stopped — bring each back **working AND secured**.

**FTP (vsftpd).** lenore must be able to download a file; anonymous login OFF.
```bash
sudo install -d /var/run/vsftpd/empty               # or vsftpd refuses to start (secure_chroot_dir)
sudo tee /etc/vsftpd.conf >/dev/null <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=NO
pam_service_name=vsftpd
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30010
EOF
sudo systemctl enable --now vsftpd
curl -s --ftp-pasv -u lenore:<lenore-pw> ftp://127.0.0.1/sentinel.txt   # -> PT-FTP-OK-3C9E
```

**SSH (password-only).** edgar logs in with a password; root blocked; empty passwords refused; key auth OFF.
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
Note the house policy is **password-only** SSH, so you turn key auth *off* (the opposite of most hardening
guides) — read the brief carefully.

## Malware

_Attacker-planted footholds and backdoors: malicious cron jobs, package-manager hooks, and MOTD payloads._

Hunt the attacker (198.51.100.77):
```bash
sudo sed -i '/198.51.100.77/d' /etc/crontab                 # malicious cron callout
sudo rm -f /etc/apt/apt.conf.d/99-ptcomp-hook               # APT Pre-Invoke hook
sudo sed -i '/198.51.100.77/d' /etc/update-motd.d/00-header # MOTD backdoor line
```

## Unwanted Software

_Hacking tools and unauthorized applications/servers that must be uninstalled._

```bash
sudo apt-get purge -y apache2                     # unneeded web server
sudo rm -f /home/edgar/linpeas.sh                 # privesc script
sudo rm -f "$(command -v sucrack)" "$(command -v changeme)"   # prohibited tools on PATH
```

## Penalties

_Actions that LOSE points; each is noted with the category it relates to._

Two **Account Management** mistakes cost **−10 each**: edgar and usher are authorized, so **do not delete**
either of them. Confirm you did **not** delete edgar or usher (−10 each).

## Final sweep

- Recon again: only authorized users remain; only root has UID 0; vkinbott isn't in `sudo`.
- `systemctl is-active vsftpd ssh apparmor` → all `active`; `ufw status` → active.

That's 33 hardening checks + 3 forensics, 2 penalties to avoid. Work top-down through the categories:
forensics first, then accounts, password policy, defensive countermeasures, OS settings, updates, services,
malware, and unwanted software — re-verify the two services at the end so you know they still work.

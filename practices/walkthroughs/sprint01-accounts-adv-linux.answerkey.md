# Answer Key — Week 1 Advanced: Accounts (Linux)

**INSTRUCTOR ONLY.** Contains every solution and the forensics answers. Do not give to students
before the exercise. Scenario: `sprint01-accounts-adv-linux` (image-is-body from the "1984 (Mint)"
community image). 29 hardening problems (20 pts each) + 3 forensics (20 pts) + 2 penalties (−10 each).

Authorized users: **winston, julia, charrington** (julia is an ordinary user, not an admin).
Run everything below with `sudo` (the student works as their admin account in the VM).

Scored items are grouped below by **CyberPatriot vulnerability category** — the same breakdown the
CyberPatriot Scoring Report uses to describe an image. Work top-to-bottom: answer Forensics first
(before touching anything), then Account Management down through the software categories; the
Penalties section lists what loses points.

---

## Forensics Questions

_Questions you answer about the image; read and answer these BEFORE changing anything, since fixes can destroy the evidence._

| Q | Question | Answer |
|---|----------|--------|
| fq1 | Which user kept the disguised diary? | **winston** (the file is in `/home/winston/.linuxmint/mintwelcome/norun.flag`) |
| fq2 | The logs show a brute-force attack — attacker's source IP? | **172.16.164.1** (from `/var/log/auth.log`: "Failed password … from 172.16.164.1") |
| fq4 | Decode the cipher calculator log on winston's Desktop — what number does it spell? | **1984735260** (the alphametic `RED + RED + QUARK = STORK` in `~winston/Desktop/calclog.txt`: each of the 10 distinct letters is a distinct digit; read out, it spells 1984735260) |

## Account Management

_Unauthorized accounts, administrator/sudo rights, required users and groups, group membership, UID‑0 impostors, guest/root account state, and rogue account entries._

| # | Check | Fix |
|---|-------|-----|
| 1 | Removed the unauthorized user **aaronson** | `sudo userdel -r aaronson` |
| 2 | Removed the unauthorized user **goldstein** | `sudo userdel -r goldstein` (was created with UID 1984) |
| 3 | Removed the extra **UID‑0 account** | A hidden impostor **goldstein1** shares UID 0. Find it: `awk -F: '$3==0 {print $1}' /etc/passwd` → shows `root` **and** `goldstein1`. Remove: `sudo userdel -f goldstein1` |
| 4 | **julia** is no longer an administrator | `sudo gpasswd -d julia sudo` (keep the julia account) |
| 5 | **winston** is a member of the **suspects** group | `sudo usermod -aG suspects winston` |
| 6 | The **root group** has no group password | A password was set on the root group in `/etc/gshadow`. Clear it: `sudo gpasswd -r root` (verify the `root:` line in `/etc/gshadow` has `!` or empty, not a hash) |

## Account & Password Policy

_Password policy (length, age, complexity, history, hashing) and account-lockout policy; locking the root account._

| # | Check | Fix |
|---|-------|-----|
| 7 | A **minimum password age** is set | Set `PASS_MIN_DAYS` ≥ 1 in `/etc/login.defs` (e.g. `PASS_MIN_DAYS 7`) |
| 8 | The **root account is locked** | `sudo usermod -L root` (or `sudo passwd -l root`); `passwd -S root` should then show `L` |

## Local Policies

_Security options, audit policy, and user-rights settings, e.g. audit logging (auditd)._

| # | Check | Fix |
|---|-------|-----|
| 16 | The **audit daemon** is running | `sudo systemctl enable --now auditd` |

## Defensive Countermeasures

_Firewall, antivirus, and mandatory-access-control (AppArmor) protections._

| # | Check | Fix |
|---|-------|-----|
| 15 | The **firewall** is enabled | `sudo ufw enable` |

## Uncategorized Operating System Settings

_OS hardening that doesn't fit another category: kernel sysctl parameters and file-permission hardening._

Set these in a file under `/etc/sysctl.d/` (e.g. `/etc/sysctl.d/99-hardening.conf`) then apply with
`sudo sysctl --system`:

| Check | Correct value |
|-------|---------------|
| `kernel.kptr_restrict` | `2` |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` |
| `kernel.dmesg_restrict` | `1` |
| `net.ipv4.tcp_syncookies` | `1` |
| `kernel.randomize_va_space` | `2` |
| `net.ipv4.ip_forward` | `0` |

## Operating System & Application Updates

_Automatic OS and application update settings._

| # | Check | Fix |
|---|-------|-----|
| 23 | **Automatic updates** are enabled | In `/etc/apt/apt.conf.d/20auto-upgrades` set `APT::Periodic::Update-Package-Lists "1";` (and `Unattended-Upgrade "1";`) |

## Service Auditing

_Required services brought up and hardened IN PLACE (never by disabling them); includes each service's per-setting sub-checks._

**SSH (must stay usable by an authorized user; root blocked; empty passwords refused).** It was left
stopped and insecure.
```bash
# harden (drop-in wins over the main config)
printf 'PermitRootLogin no\nPermitEmptyPasswords no\n' | sudo tee /etc/ssh/sshd_config.d/99-hardening.conf
sudo systemctl enable --now ssh        # start it
sudo systemctl reload ssh
```
- Check 25 "SSH service running and an authorized user can log in": the service must be up **and** winston's key login works (winston's authorized_keys is already in place).
- Check 26 "Root cannot log in over SSH": `sshd -T | grep permitrootlogin` → `no`.
- Check 27 "SSH does not accept empty passwords": `sshd -T | grep permitemptypasswords` → `no`.

**Internal web status page on port 8099 (must run, but listen on localhost only).** The `ptweb`
systemd unit was left stopped and bound to `0.0.0.0`.
```bash
sudo sed -i 's/--bind 0.0.0.0/--bind 127.0.0.1/' /etc/systemd/system/ptweb.service
sudo systemctl daemon-reload
sudo systemctl enable --now ptweb
```
- Check 28 "web service running and serves its status page": `curl http://127.0.0.1:8099/sentinel.txt` → `PT-WEB-OK-5B2C`.
- Check 29 "listens on localhost only": `ss -ltn | grep 8099` shows `127.0.0.1:8099`, not `0.0.0.0:8099`.

## Malware

_Attacker-planted footholds and backdoors: malicious cron jobs, scripts, binaries, aliases, planted SSH keys, and malicious ACLs/privilege backdoors._

| # | Check | Fix |
|---|-------|-----|
| 19 | Malicious **cron job** (attacker 172.16.164.1) removed | Remove the line from `/etc/crontab` that references `172.16.164.1` (`sudo sed -i '/172.16.164.1/d' /etc/crontab`) |
| 20 | The **'goose' alias** malware is removed | `sudo rm /bin/goose` **and** delete the `alias ls='/bin/goose'` line from `/etc/bash.bashrc` |
| 21 | The **sabotage script** is removed | `sudo rm /root/downwithbigbrother.sh` (and its line in `/etc/crontab`) |
| 22 | The unauthorized **SSH key on julia** is removed | `sudo rm /home/julia/.ssh/authorized_keys` (a planted attacker key) |
| 24 | The malicious **ACL on /usr/bin/sudo** is removed | `sudo setfacl -b /usr/bin/sudo` (check with `getfacl /usr/bin/sudo`) |

## Unwanted Software

_Hacking tools and unauthorized applications that must be uninstalled (e.g. password crackers)._

| # | Check | Fix |
|---|-------|-----|
| 17 | The prohibited tool **john** is removed | `sudo apt-get purge -y john` |

## Prohibited Files

_Non-work-related media and disguised data files that must be removed._

| # | Check | Fix |
|---|-------|-----|
| 18 | winston's hidden **diary file** is removed | `sudo rm /home/winston/.linuxmint/mintwelcome/norun.flag` (contents: "DOWN WITH BIG BROTHER" — read it first for forensics Q1) |

## Penalties

_Actions that LOSE points; each is noted with the category it relates to._

Do NOT trigger these (−10 each):

- Do **not** delete **winston**. _(relates to Account Management)_
- Do **not** delete **charrington**. _(relates to Account Management)_

Both are authorized users. (julia is also authorized — remove her from `sudo`, don't delete her.)

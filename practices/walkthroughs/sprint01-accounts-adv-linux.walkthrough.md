# Walkthrough — Week 1 Advanced: Accounts (Linux)

A guided solve of `sprint01-accounts-adv-linux`. It reveals the answers, so it's a teaching aid /
post-exercise debrief, not a handout to give before students try it themselves.

**The brief:** you administer a Linux workstation modeled on a real competition image. Authorized
users are **winston, julia, charrington** (julia is an ordinary user, *not* an admin). Harden the box
without breaking what the company needs. Two services must end up **running and secured** — SSH and an
internal web page on 8099 — and both start stopped. There are forensics questions, and **deleting an
authorized user costs points**.

Work as your admin account; prefix privileged commands with `sudo`. Open a terminal.

---

## 0. Recon first (look before you touch)

```bash
# who exists, and who has dangerous power
cut -d: -f1,3 /etc/passwd            # users and their UIDs
awk -F: '$3==0 {print $1}' /etc/passwd   # anyone with UID 0 (should be ONLY root)
getent group sudo                     # who is an admin
getent group suspects                 # who's in the suspects group
```

You'll notice three users who aren't on the authorized list — **aaronson**, **goldstein**, and a
second account with **UID 0** (that's the big one: a non-root account with UID 0 is a root impostor).

## 1. Accounts & groups

```bash
sudo userdel -r aaronson            # unauthorized
sudo userdel -r goldstein           # unauthorized (UID 1984)
sudo userdel -f goldstein1          # the UID-0 impostor you found above (-f: it shares UID 0)
sudo gpasswd -d julia sudo          # julia must NOT be an admin — remove from sudo, keep the account
sudo usermod -aG suspects winston   # winston belongs in the 'suspects' group but was taken out
```

The **root group** also has a password set — that lets someone `newgrp` into the root group. Remove it:
```bash
sudo gpasswd -r root
grep '^root:' /etc/gshadow           # should now be  root:!::  (or empty), not a hash
```

> ⚠️ Do **not** delete winston or charrington (−10 each). They're authorized. julia stays too — you
> only strip her admin rights.

## 2. Password & account policy

```bash
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs   # a minimum password age (≥1)
sudo usermod -L root                                                 # lock the root account
passwd -S root                                                       # shows 'L' = locked
```

## 3. Kernel hardening (sysctl)

The image shipped with several kernel protections turned off. Set them in one drop-in and apply:
```bash
sudo tee /etc/sysctl.d/99-hardening.conf >/dev/null <<'EOF'
kernel.kptr_restrict = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.dmesg_restrict = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
net.ipv4.ip_forward = 0
EOF
sudo sysctl --system
```
Spot-check: `sysctl kernel.randomize_va_space` → `= 2`.

## 4. Firewall & auditing

```bash
sudo ufw enable                      # firewall on
sudo systemctl enable --now auditd   # audit daemon running
```

## 5. Prohibited software & files

```bash
sudo apt-get purge -y john           # password cracker — not allowed
# winston's "diary" is disguised as a Mint welcome flag; read it (forensics!) then remove it
cat /home/winston/.linuxmint/mintwelcome/norun.flag
sudo rm /home/winston/.linuxmint/mintwelcome/norun.flag
```

## 6. Persistence — hunt the attacker's footholds

```bash
# scheduled callbacks
sudo cat /etc/crontab                 # look for odd lines
sudo sed -i '/172.16.164.1/d;/downwithbigbrother/d' /etc/crontab

# a trojaned 'ls' alias that runs /bin/goose for every shell
grep goose /etc/bash.bashrc
sudo rm -f /bin/goose
sudo sed -i "\|alias ls='/bin/goose'|d" /etc/bash.bashrc

# a sabotage script left in root's home
sudo rm -f /root/downwithbigbrother.sh

# a planted attacker SSH key on julia
sudo cat /home/julia/.ssh/authorized_keys     # not julia's — an attacker placeholder
sudo rm /home/julia/.ssh/authorized_keys

# a sneaky ACL granting extra rights on sudo itself
getfacl /usr/bin/sudo                 # note the extra user entry
sudo setfacl -b /usr/bin/sudo         # strip all ACLs back to normal
```

## 7. Updates

```bash
sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
```

## 8. Bring the two services back — working AND secured

**SSH.** It's stopped and wide open. Harden it with a drop-in (which overrides the main config), then
start it. winston's key is already installed, so his login keeps working.
```bash
printf 'PermitRootLogin no\nPermitEmptyPasswords no\n' | sudo tee /etc/ssh/sshd_config.d/99-hardening.conf
sudo systemctl enable --now ssh
sudo sshd -T | grep -E 'permitrootlogin|permitemptypasswords'   # both -> no
```

**Internal web page (port 8099).** The `ptweb` service is stopped and, worse, set to listen on every
interface. It must run but be reachable only from localhost.
```bash
sudo sed -i 's/--bind 0.0.0.0/--bind 127.0.0.1/' /etc/systemd/system/ptweb.service
sudo systemctl daemon-reload
sudo systemctl enable --now ptweb
curl http://127.0.0.1:8099/sentinel.txt     # -> PT-WEB-OK-5B2C
ss -ltn | grep 8099                          # 127.0.0.1:8099, NOT 0.0.0.0:8099
```

## 9. Forensics (answer in the agent's "Forensics…" panel)

- **Who kept the disguised diary?** The file lived under `/home/winston/…`, so → **winston**.
- **Attacker's source IP (brute force)?** `grep 'Failed password' /var/log/auth.log` → repeated
  failures *from* **172.16.164.1**.
- **Decode the cipher calculator log on winston's Desktop.** `cat ~winston/Desktop/calclog.txt` shows
  the alphametic `RED + RED + QUARK = STORK`. Each of the 10 distinct letters stands for a distinct
  digit; solving and reading the digits out gives **1984735260**.

## 10. Final sweep

- Re-run the recon from step 0: only `root` has UID 0; only authorized users remain; julia isn't in
  `sudo`; winston is in `suspects`.
- `systemctl is-active auditd ssh ptweb` → all `active`; `ufw status` → active.
- Confirm you did **not** delete winston or charrington.

That's the full 34 checks. In a real round, work top-down like this — recon, then accounts/policy, then
kernel/firewall, then hunt persistence, and leave the services for last so you can verify they still work.

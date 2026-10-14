#!/bin/bash
# Fixes for sprint01-accounts-adv-linux (CI tests only; never uploaded to students).
set -e
for u in mallory eve ghost; do userdel -r "$u" 2>/dev/null || userdel "$u"; done
userdel -f lgates   # -f: lgates shares UID 0 with root, so userdel otherwise refuses it
gpasswd -d bob sudo >/dev/null
gpasswd -d carol sudo >/dev/null
gpasswd -d bob shadow >/dev/null
groupdel pirates
usermod -s /usr/sbin/nologin www-data
chage -d 0 dave

# Remote-login service: harden SSH and bring the required service up
install -d -m 755 /etc/ssh/sshd_config.d
printf 'PermitRootLogin no\nPermitEmptyPasswords no\n' > /etc/ssh/sshd_config.d/99-ptcomp.conf
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd

# ===== TEMP DIAG (remove) =====
echo "=== DIAG svc ==="; systemctl is-active ssh; systemctl is-active sshd 2>/dev/null; systemctl --no-pager status ssh 2>&1 | head -4 || true
echo "=== DIAG port ==="; ss -tlnp 2>/dev/null | grep ':22' || echo "nothing on :22"
echo "=== DIAG perms ==="; ls -ld /home/alice /home/alice/.ssh; ls -l /home/alice/.ssh/authorized_keys /home/alice/sentinel.txt /opt/ptcheck/alice_id
echo "=== DIAG probe ==="; ssh -i /opt/ptcheck/alice_id -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -v alice@localhost 'cat /home/alice/sentinel.txt' 2>&1 | tail -30 || true
echo "=== DIAG end (exit $?) ==="

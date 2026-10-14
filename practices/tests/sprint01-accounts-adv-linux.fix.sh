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

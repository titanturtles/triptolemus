#!/bin/bash
# Fixes for sprint02-password-adv-linux (CI only; never uploaded to students).
set -e
for u in rowan mmouse; do userdel -rf "$u" 2>/dev/null || userdel -f "$u"; done
gpasswd -d vkinbott sudo >/dev/null 2>&1 || true
# remove the UID-0 impostor; strip ANY non-root UID-0 account (a shared CI runner may carry one
# from another practice — on a real single-scenario VM this is just lgates). NOTE: never
# `pkill -u lgates` — lgates shares UID 0 with root, so that would kill every root process.
userdel -f lgates 2>/dev/null || true
cp -f /etc/passwd /etc/passwd.ptbak
awk -F: '!($3==0 && $1!="root")' /etc/passwd.ptbak > /etc/passwd
rm -f /etc/passwd.ptbak
# account policy
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
cat > /etc/security/pwquality.conf <<PWQ
minlen = 12
dictcheck = 1
PWQ
grep -q 'pam_pwhistory' /etc/pam.d/common-password || \
  sed -i '/pam_unix.so/i password\trequired\t\t\tpam_pwhistory.so remember=5 use_authtok' /etc/pam.d/common-password
# kernel sysctl
cat > /etc/sysctl.d/99-ptcomp.conf <<SYS
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2
net.ipv4.tcp_syncookies = 1
kernel.dmesg_restrict = 1
SYS
sysctl --system >/dev/null
# sudo / policy
rm -f /etc/sudoers.d/90-ptcomp-preload /etc/sudoers.d/91-ptcomp-coredump
# file perms
chmod 644 /etc/ssh/sshd_config
chmod u-s /bin/date
# firewall / services
ufw --force enable >/dev/null
systemctl enable --now apparmor
DEBIAN_FRONTEND=noninteractive apt-get purge -y -q apache2 >/dev/null 2>&1 || dpkg -P apache2 >/dev/null 2>&1 || true
# prohibited
rm -f /home/edgar/linpeas.sh /usr/local/bin/sucrack /usr/local/bin/changeme
# updates
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
# persistence
sed -i '/198.51.100.77/d' /etc/crontab
rm -f /etc/apt/apt.conf.d/99-ptcomp-hook
sed -i '/198.51.100.77/d' /etc/update-motd.d/00-header
# service 1: FTP secured + up
install -d /var/run/vsftpd/empty   # vsftpd's secure_chroot_dir must exist or it won't start
cat > /etc/vsftpd.conf <<FTP
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=NO
pam_service_name=vsftpd
seccomp_sandbox=NO
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30010
FTP
systemctl enable --now vsftpd
# service 2: SSH secured + up (password-only)
cat > /etc/ssh/sshd_config.d/00-ptcomp.conf <<SSHC
PasswordAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
PubkeyAuthentication no
LogLevel INFO
SSHC
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd

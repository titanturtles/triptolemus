#!/bin/bash
# Fixes for sprint01-accounts-adv-linux (CI only; never uploaded to students).
set -e
for u in aaronson goldstein goldstein1; do userdel -rf "$u" 2>/dev/null || userdel -f "$u"; done
gpasswd -d julia sudo >/dev/null
usermod -aG suspects winston
gpasswd -r root
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t14/' /etc/login.defs
usermod -L root
cat > /etc/sysctl.d/99-ptcomp.conf <<SYS
kernel.kptr_restrict = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.dmesg_restrict = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
net.ipv4.ip_forward = 0
SYS
sysctl --system >/dev/null
ufw --force enable >/dev/null
systemctl enable --now auditd
DEBIAN_FRONTEND=noninteractive apt-get purge -y -q john >/dev/null 2>&1 || dpkg -P john >/dev/null 2>&1 || true
rm -f /home/winston/.linuxmint/mintwelcome/norun.flag
sed -i '/172.16.164.1/d;/downwithbigbrother/d' /etc/crontab
rm -f /bin/goose /root/downwithbigbrother.sh
sed -i "\|alias ls='/bin/goose'|d" /etc/bash.bashrc
rm -f /home/julia/.ssh/authorized_keys
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
setfacl -b /usr/bin/sudo
# service 1: SSH
printf 'PermitRootLogin no\nPermitEmptyPasswords no\n' > /etc/ssh/sshd_config.d/99-ptcomp.conf
systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd
# service 2: web on localhost
cat > /etc/systemd/system/ptweb.service <<UNIT
[Unit]
Description=PT Comp internal status web service
After=network.target
[Service]
User=ptweb
ExecStart=/usr/bin/python3 -m http.server 8099 --bind 127.0.0.1 --directory /srv/ptweb
Restart=no
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now ptweb

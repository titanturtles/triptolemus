#!/bin/bash
# The fixes for linux-basics-1 (CI tests only; never uploaded to students).
set -e
userdel -r hacker 2>/dev/null || userdel hacker
gpasswd -d bob sudo >/dev/null
ufw --force enable >/dev/null
sed -i -E 's/^[[:space:]]*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
chmod 640 /etc/shadow

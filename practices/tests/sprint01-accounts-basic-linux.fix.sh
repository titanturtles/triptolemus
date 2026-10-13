#!/bin/bash
# Fixes for sprint01-accounts-basic-linux (CI tests only; never uploaded to students).
set -e
userdel -r mallory 2>/dev/null || userdel mallory
userdel -r eve 2>/dev/null || userdel eve
gpasswd -d bob sudo >/dev/null
groupdel pirates
usermod -s /usr/sbin/nologin www-data

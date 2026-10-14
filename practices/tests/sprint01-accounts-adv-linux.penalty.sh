#!/bin/bash
# Sets off every penalty of sprint01-accounts-adv-linux (CI tests only; never uploaded).
set -e
for u in alice frank; do
    pkill -KILL -u "$u" 2>/dev/null || true   # the SSH login can leave a lingering systemd --user process
    userdel -rf "$u" 2>/dev/null || userdel -f "$u"   # -f: remove even while a process is still using the account
done

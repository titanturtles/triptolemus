#!/bin/bash
# Fires every penalty of sprint01-accounts-adv-linux (CI only; never uploaded).
set -e
for u in winston charrington; do
    pkill -KILL -u "$u" 2>/dev/null || true
    userdel -rf "$u" 2>/dev/null || userdel -f "$u"
done

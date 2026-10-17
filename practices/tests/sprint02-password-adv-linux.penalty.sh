#!/bin/bash
# Fires every penalty of sprint02-password-adv-linux (CI only; never uploaded).
set -e
for u in edgar usher; do
    pkill -KILL -u "$u" 2>/dev/null || true
    userdel -rf "$u" 2>/dev/null || userdel -f "$u"
done

#!/bin/bash
# Sets off every penalty of sprint01-accounts-adv-linux (CI tests only; never uploaded).
set -e
userdel -r alice 2>/dev/null || userdel alice
userdel -r frank 2>/dev/null || userdel frank

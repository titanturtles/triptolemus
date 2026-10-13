#!/bin/bash
# Sets off every penalty of linux-basics-1 (CI tests only; never uploaded to students).
set -e
userdel -r alice 2>/dev/null || userdel alice
userdel -r bob 2>/dev/null || userdel bob

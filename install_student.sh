#!/usr/bin/env bash
# install_student.sh - one-step Linux student setup (mirror of install_student.ps1).
# Run it from the folder containing pt_agent (or pt_agent.py). It will:
#   1. Ensure the pt_agent binary (use ./pt_agent, copy ./dist/pt_agent, or build pt_agent.py).
#   2. Write pt_agent.conf.json with the server URL + class token baked in (students only
#      enter a Team ID; the token is never typed).
#   3. Create a desktop launcher + autostart entry (app opens at login).
#
# Usage:
#   ./install_student.sh                              install (build if needed)
#   LEVELSVC=https://.../levels CLASS_TOKEN=xxx ./install_student.sh   override server
#   ./install_student.sh --remove                     remove launcher + autostart
#
# Does NOT touch Packet Tracer's agent registration - do that once per machine
# (Extensions > IPC > Configure Apps > Add ptagent.pta, then quit PT normally).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEVELSVC="${LEVELSVC:-https://scoreboard.titanturtles.xyz/levels}"
CLASS_TOKEN="${CLASS_TOKEN:-0b90c526f93f638dd1fb1bd1b27e2c18a521c30daf8203a0}"
NAME="Cisco PT Competition"
EXE="$HERE/pt_agent"
APP_DESKTOP="$HOME/.local/share/applications/cisco-pt-competition.desktop"
AUTOSTART="$HOME/.config/autostart/cisco-pt-competition.desktop"
DESK_ICON="$HOME/Desktop/cisco-pt-competition.desktop"

if [ "${1:-}" = "--remove" ] || [ "${1:-}" = "-r" ]; then
  rm -f "$APP_DESKTOP" "$AUTOSTART" "$DESK_ICON"
  echo "[+] removed launcher + autostart (Packet Tracer registration untouched)"
  exit 0
fi

# 1) ensure the binary
if [ ! -x "$EXE" ]; then
  if [ -x "$HERE/dist/pt_agent" ]; then
    cp "$HERE/dist/pt_agent" "$EXE"; echo "[*] used dist/pt_agent"
  elif [ -f "$HERE/pt_agent.py" ]; then
    echo "[*] building pt_agent from source (first run can take a minute)..."
    PY="$(command -v python3 || command -v python || true)"
    [ -n "$PY" ] || { echo "ERROR: Python 3 not found (install: sudo apt install python3 python3-tk python3-pip)"; exit 1; }
    "$PY" -m pip install --user --quiet --upgrade pyinstaller cryptography
    "$PY" -m PyInstaller --onefile --name pt_agent --noconfirm \
      --distpath "$HERE/dist" --workpath "$HERE/build" --specpath "$HERE" "$HERE/pt_agent.py"
    cp "$HERE/dist/pt_agent" "$EXE"
  else
    echo "ERROR: need pt_agent, dist/pt_agent, or pt_agent.py in $HERE"; exit 1
  fi
fi
chmod +x "$EXE"

# 2) server config (baked-in defaults; students only enter a Team ID)
cat > "$HERE/pt_agent.conf.json" <<CONF
{
  "levelsvc": "$LEVELSVC",
  "class_token": "$CLASS_TOKEN",
  "interval": 10,
  "auto_launch": true
}
CONF
echo "[*] wrote pt_agent.conf.json (server-served)"
[ -f "$HERE/ptagent.pta" ] || echo "WARNING: ptagent.pta missing - the app needs it to register with Packet Tracer"

# 3) desktop launcher + autostart
mkdir -p "$(dirname "$APP_DESKTOP")" "$(dirname "$AUTOSTART")" "$HOME/Desktop"
cat > "$APP_DESKTOP" <<ENTRY
[Desktop Entry]
Type=Application
Name=$NAME
Exec="$EXE"
Path=$HERE
Terminal=false
Categories=Education;
ENTRY
cp "$APP_DESKTOP" "$AUTOSTART"
cp "$APP_DESKTOP" "$DESK_ICON"
chmod +x "$DESK_ICON" 2>/dev/null || true
gio set "$DESK_ICON" metadata::trusted true 2>/dev/null || true   # GNOME: allow launching

echo "[+] Installed: desktop launcher + autostart at login."
echo "    One-time per machine: open Packet Tracer -> Extensions > IPC > Configure Apps >"
echo "    Add  $HERE/ptagent.pta , then quit Packet Tracer normally (File > Exit)."

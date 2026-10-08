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
NAME="PT Comp"
EXE="$HERE/pt_agent"
APP_DESKTOP="$HOME/.local/share/applications/pt-comp.desktop"
AUTOSTART="$HOME/.config/autostart/pt-comp.desktop"
DESK_ICON="$HOME/Desktop/pt-comp.desktop"
# older installs used these names; clean them up so there is just one icon
OLD_ENTRIES=("$HOME/.local/share/applications/cisco-pt-competition.desktop" "$HOME/.config/autostart/cisco-pt-competition.desktop" "$HOME/Desktop/cisco-pt-competition.desktop")

if [ "${1:-}" = "--remove" ] || [ "${1:-}" = "-r" ]; then
  rm -f "$APP_DESKTOP" "$AUTOSTART" "$DESK_ICON" "${OLD_ENTRIES[@]}"
  echo "[+] removed launcher + autostart (Packet Tracer registration untouched)"
  exit 0
fi

# --force / -f : rebuild the binary from source even if one exists
if [ "${1:-}" = "--force" ] || [ "${1:-}" = "-f" ]; then
  rm -f "$EXE" "$HERE/dist/pt_agent"
fi

# 1) ensure the binary
if [ ! -x "$EXE" ]; then
  if [ -x "$HERE/dist/pt_agent" ]; then
    cp "$HERE/dist/pt_agent" "$EXE"; echo "[*] used dist/pt_agent"
  elif [ -f "$HERE/pt_agent.py" ]; then
    VER="$(sed -n 's/^AGENT_VERSION *= *"\([^"]*\)".*/\1/p' "$HERE/pt_agent.py")"
    echo "[*] building pt_agent version ${VER:-?} from source (first run can take a minute)..."
    SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    HAVE_APT=0; command -v apt-get >/dev/null 2>&1 && HAVE_APT=1
    apt_install() {   # best-effort; never aborts the script (set -e safe)
      echo "[*] installing build dependency: $*"
      $SUDO apt-get update -y >/dev/null 2>&1 || true
      $SUDO apt-get install -y "$@" || true
    }
    PY="$(command -v python3 || command -v python || true)"
    if [ -z "$PY" ]; then
      [ "$HAVE_APT" = 1 ] && apt_install python3 python3-tk python3-pip
      PY="$(command -v python3 || command -v python || true)"
    fi
    [ -n "$PY" ] || { echo "ERROR: Python 3 not found and could not auto-install it. Install python3 python3-tk python3-pip, or drop a prebuilt 'pt_agent' binary here."; exit 1; }

    # ensure pip (ensurepip, then apt)
    if ! "$PY" -m pip --version >/dev/null 2>&1; then "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true; fi
    if ! "$PY" -m pip --version >/dev/null 2>&1 && [ "$HAVE_APT" = 1 ]; then apt_install python3-pip; fi
    if ! "$PY" -m pip --version >/dev/null 2>&1; then
      echo "ERROR: pip unavailable and auto-install failed. Install python3-pip (or drop a prebuilt 'pt_agent' binary here)."; exit 1
    fi

    # ensure tkinter (apt)
    if ! "$PY" -c 'import tkinter' >/dev/null 2>&1 && [ "$HAVE_APT" = 1 ]; then apt_install python3-tk; fi
    if ! "$PY" -c 'import tkinter' >/dev/null 2>&1; then
      echo "ERROR: tkinter unavailable and auto-install failed. Install python3-tk."; exit 1
    fi

    "$PY" -m pip install --quiet --upgrade pyinstaller cryptography \
      || "$PY" -m pip install --user --quiet --upgrade pyinstaller cryptography
    "$PY" -m PyInstaller --onefile --name pt_agent --noconfirm \
      --distpath "$HERE/dist" --workpath "$HERE/build" --specpath "$HERE" "$HERE/pt_agent.py"
    cp "$HERE/dist/pt_agent" "$EXE"
    echo "[+] built pt_agent version ${VER:-?}  (publish this version on the console's App update page)"
  else
    echo "ERROR: need pt_agent, dist/pt_agent, or pt_agent.py in $HERE"; exit 1
  fi
fi
chmod +x "$EXE"
# report the built binary's version (works even when the file was prebuilt/copied)
BUILT_VER="$("$EXE" --version 2>/dev/null | awk '{print $NF}')"
[ -n "$BUILT_VER" ] && echo "[*] pt_agent version: $BUILT_VER"

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
rm -f "${OLD_ENTRIES[@]}"   # no duplicate icons from older installs
cp "$APP_DESKTOP" "$DESK_ICON"
chmod +x "$DESK_ICON" 2>/dev/null || true
gio set "$DESK_ICON" metadata::trusted true 2>/dev/null || true   # GNOME: allow launching

echo "[+] Installed: desktop launcher + autostart at login."
echo "    One-time per machine: open Packet Tracer -> Extensions > IPC > Configure Apps >"
echo "    Add  $HERE/ptagent.pta , then quit Packet Tracer normally (File > Exit)."

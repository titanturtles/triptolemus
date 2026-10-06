#!/bin/bash
# Build the double-click executables for the CURRENT OS (Linux or macOS).
# PyInstaller cannot cross-compile: run this on each target OS.
#   dist/pt_agent             -> student agent (ship with pt_agent.conf.json)
#   dist/scoreboard_manager   -> Cisco Scoreboard Manager (ship with the pka_tool/ folder)
set -e
cd "$(dirname "$0")/.."   # ptagent/ root

if ! python3 -c "import PyInstaller" 2>/dev/null; then
  echo "PyInstaller not found. If your system pip is externally-managed, use a venv:"
  echo "  python3 -m venv --system-site-packages .buildenv && . .buildenv/bin/activate && pip install pyinstaller"
  exit 1
fi

pyinstaller --onefile --windowed --name pt_agent --clean --noconfirm pt_agent.py
pyinstaller --onefile --windowed --name scoreboard_manager --clean --noconfirm scoreboard_manager.py

echo
echo "Built:  dist/pt_agent   dist/scoreboard_manager"
echo "Students:     ship 'pt_agent' + 'pt_agent.conf.json' in one folder."
echo "Test creator: ship 'scoreboard_manager' + the 'pka_tool/' folder in one folder."

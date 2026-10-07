@echo off
setlocal enabledelayedexpansion
REM Build the double-click executables for Windows. Run ON Windows.
REM   dist\pt_agent.exe           -> student agent (ship with pt_agent.conf.json + ptagent.pta)
REM   dist\scoreboard_manager.exe -> Cisco Scoreboard Manager (ship with pka_tool\ folder)
cd /d "%~dp0\.."

REM --- find a working Python 3 launcher ---
set "PY="
py -3 --version >nul 2>&1 && set "PY=py -3"
if not defined PY ( python --version >nul 2>&1 && set "PY=python" )
if not defined PY (
  echo(
  echo ERROR: Python 3 was not found.
  echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH",
  echo then reopen this window. If "python" opens the Microsoft Store, turn off the alias:
  echo Settings ^> Apps ^> Advanced app settings ^> App execution aliases ^> python.exe = Off
  exit /b 1
)
echo Using Python: %PY%

for /f "usebackq tokens=2 delims== " %%V in (`findstr /b /c:"AGENT_VERSION" pt_agent.py`) do set "AGENTVER=%%~V"
echo Building pt_agent version %AGENTVER%  (publish this version on the console's App update page)

%PY% -m pip install --upgrade pyinstaller cryptography || ( echo ERROR: pip install failed & exit /b 1 )
%PY% -m PyInstaller --onefile --windowed --name pt_agent --clean --noconfirm pt_agent.py || ( echo ERROR: pt_agent build failed & exit /b 1 )
%PY% -m PyInstaller --onefile --windowed --name scoreboard_manager --clean --noconfirm scoreboard_manager.py || ( echo ERROR: scoreboard_manager build failed & exit /b 1 )

if exist "dist\pt_agent.exe" (
  echo(
  echo Built:  dist\pt_agent.exe  (version %AGENTVER%)   dist\scoreboard_manager.exe
  echo Students:     ship pt_agent.exe + pt_agent.conf.json + ptagent.pta in one folder.
  echo Test creator: ship scoreboard_manager.exe + the pka_tool\ folder in one folder.
) else (
  echo ERROR: build did not produce dist\pt_agent.exe -- see messages above.
  exit /b 1
)
endlocal

@echo off
REM One-step student setup. Double-click to run.
REM Builds pt_agent.exe if needed (from pt_agent.py, or copies from dist\),
REM then creates the Desktop + Startup shortcuts.
REM Must sit in the same folder as pt_agent.py (or pt_agent.exe), pt_agent.conf.json and ptagent.pta.
REM   install_student.bat                                             install (build if needed)
REM   install_student.bat -Levelsvc "<url>" -ClassToken "<token>"     also write the server config
REM   install_student.bat -ForceBuild                                 rebuild the exe then install
REM   install_student.bat -Remove                                     remove the shortcuts
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_student.ps1" %*
echo.
pause

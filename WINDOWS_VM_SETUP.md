# Student VM setup (one time, when building the image)

Goal: a Windows VM where the competition app launches on boot, and **no student ever
has to do "first-time setup."** You do the registration once in the image; every clone
keeps it.

## Build the image once

1. **Install Cisco Packet Tracer** and sign in (NetAcad / Skills for All) so it's ready.
2. Put the student folder somewhere permanent, e.g. `C:\CiscoComp\`, containing:
   - `pt_agent.py`  (source — the installer builds the exe), **or** a prebuilt `pt_agent.exe` / `dist\pt_agent.exe`
   - `pt_agent.conf.json`  (the **Student bootstrap** file from the manager: server URL + class token)
   - `ptagent.pta`
   - `install_student.ps1`, `install_student.bat`
   - (for building from source) **Python 3** from python.org with "Add to PATH" checked
3. **Register the agent in Packet Tracer — once:**
   - Open Packet Tracer → **Extensions → IPC → Configure Apps → Add** → select `ptagent.pta` → **Ok**.
   - **Quit Packet Tracer normally** (File → Exit) so it saves the registration.
   - This is the *only* time first-time setup is done. It is stored in Packet Tracer's
     config and survives reboots and clones.
4. **Build + shortcut + auto-start, in one step:** double-click **`install_student.bat`**.
   It finds `pt_agent.exe` (or copies it from `dist\`, or **builds it from `pt_agent.py`**,
   installing PyInstaller automatically), then creates a Desktop shortcut and a
   Startup-folder shortcut so the app opens at login. (First build can take a minute.
   Use `-ForceBuild` to rebuild, `-Remove` to delete the shortcuts.)
5. **Start on boot:** enable **automatic logon** for the kiosk Windows user
   (e.g. `netplwiz` → uncheck "Users must enter a user name and password", or set
   `AutoAdminLogon`), so login — and the app — happen without a password at boot.
6. Snapshot / seal the image.

## Per student (no setup, no re-registration)

- The app opens on boot (or from the Desktop shortcut).
- Student picks the **Competition** (default is pre-selected), enters **Team ID**, clicks **Start**.
- **Reset (new student)** button clears the saved Team ID and leftover local files so the
  next student starts clean. It does **not** touch the Packet Tracer registration, so
  first-time setup is never needed again.

## If the registration is ever lost

Only happens if Packet Tracer is force-killed right after a *new* registration change, or
the image's PT config was wiped. Re-do step 3 once, or revert to the snapshot.

## Instructor side

- The agent fetches the competition list, the default, and keys from the server on open,
  so changing competitions on the server needs no new files on the VMs (students click
  **Reload** or reopen).
- In the manager's **Review** window you can **Restore (let team resume)** any saved copy
  (a paused checkpoint or a final submission) back into a team's resumable slot — so a
  student can reopen and continue even after clicking **Finish Competition**.

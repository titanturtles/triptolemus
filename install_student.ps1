# install_student.ps1 - one-step student VM setup.
#
# Run this ONCE while building the Windows VM image (double-click install_student.bat,
# or:  powershell -ExecutionPolicy Bypass -File install_student.ps1 ).
# It will:
#   1. Find pt_agent.exe next to this script, OR copy it from .\dist\, OR BUILD it from
#      pt_agent.py (installing PyInstaller if needed).
#   2. Create a Desktop shortcut and a Startup-folder shortcut (auto-start at login).
#
# Needed in this folder: pt_agent.py  (or a prebuilt pt_agent.exe / dist\pt_agent.exe),
# plus pt_agent.conf.json and ptagent.pta for the app to run.
#
# This does NOT touch Packet Tracer's agent registration - do first-time setup once in
# the image and every clone keeps it.  Switches:  -Remove  (delete shortcuts),
# -ForceBuild  (rebuild the exe even if one exists).

param(
  [switch]$Remove,
  [switch]$ForceBuild,
  # Server config baked in as defaults so plain install_student.bat produces a
  # server-served VM (students only type a Team ID). Override for a different server.
  [string]$Levelsvc   = "https://scoreboard.titanturtles.xyz/levels",
  [string]$ClassToken = "0b90c526f93f638dd1fb1bd1b27e2c18a521c30daf8203a0"
)
$ErrorActionPreference = "Stop"

$here    = Split-Path -Parent $MyInvocation.MyCommand.Definition
$name    = "PT Comp.lnk"
$oldname = "Cisco PT Competition.lnk"   # remove shortcuts from older installs
$desktop = [Environment]::GetFolderPath("Desktop")
$startup = [Environment]::GetFolderPath("Startup")
$targets = @((Join-Path $desktop $name), (Join-Path $startup $name))
$oldtargets = @((Join-Path $desktop $oldname), (Join-Path $startup $oldname))

if ($Remove) {
    foreach ($t in ($targets + $oldtargets)) { if (Test-Path $t) { Remove-Item $t -Force; Write-Host "removed $t" } }
    Write-Host "Done (Packet Tracer registration was not touched)."
    return
}

# Always (over)write the server bootstrap config so the app loads every competition
# from the server on open/Reload. This overwrites any stale/legacy config in the folder.
# The class token lives here, never typed by students -- they only enter a Team ID.
$conf = [ordered]@{ levelsvc = $Levelsvc; class_token = $ClassToken; interval = 10; auto_launch = $true }
($conf | ConvertTo-Json) | Set-Content -Path (Join-Path $here "pt_agent.conf.json") -Encoding ASCII
Write-Host "Wrote pt_agent.conf.json (server-served). Students only open the app and enter a Team ID."

$exe  = Join-Path $here "pt_agent.exe"
$dist = Join-Path $here "dist\pt_agent.exe"
$src  = Join-Path $here "pt_agent.py"

if ($ForceBuild -and (Test-Path $exe)) { Remove-Item $exe -Force }

# 1) use a prebuilt exe from dist\ if the top-level one isn't there
if ((-not (Test-Path $exe)) -and (Test-Path $dist) -and (-not $ForceBuild)) {
    Write-Host "Using existing dist\pt_agent.exe."
    Copy-Item $dist $exe -Force
}

# 2) otherwise build it from source
if (-not (Test-Path $exe)) {
    if (-not (Test-Path $src)) {
        Write-Error "No pt_agent.exe, dist\pt_agent.exe, or pt_agent.py in this folder:`n  $here`nCopy pt_agent.py (or a prebuilt pt_agent.exe) here and run again."
        exit 1
    }
    $ver = (Select-String -Path $src -Pattern 'AGENT_VERSION\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches.Groups[1].Value
    Write-Host "Building pt_agent.exe version $ver from pt_agent.py (first run can take a minute)..."

    # find a Python
    $py = $null; $pyargs = @()
    foreach ($cand in @(@('py', '-3'), @('python', ''), @('python3', ''))) {
        if (Get-Command $cand[0] -ErrorAction SilentlyContinue) {
            $py = $cand[0]
            if ($cand[1]) { $pyargs = @($cand[1]) }
            break
        }
    }
    if (-not $py) { Write-Error "Python 3 not found. Install it from https://python.org (check 'Add Python to PATH'), then run this again."; exit 1 }
    Write-Host "Using Python: $py $($pyargs -join ' ')"

    # ensure pip (python.org Python ships it; recover with ensurepip if missing)
    & $py @pyargs -m pip --version > $null 2>&1
    if ($LASTEXITCODE -ne 0) { & $py @pyargs -m ensurepip --upgrade 2>&1 | Out-Null }
    & $py @pyargs -m pip --version > $null 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Error "pip is unavailable. Reinstall Python from python.org with pip, or drop a prebuilt pt_agent.exe / dist\pt_agent.exe in this folder and re-run."; exit 1 }

    # ensure build deps
    & $py @pyargs -m pip install --disable-pip-version-check --quiet --upgrade pyinstaller cryptography
    if ($LASTEXITCODE -ne 0) { Write-Error "Could not install PyInstaller/cryptography with pip."; exit 1 }

    # build (args as an array so there are no fragile line continuations)
    $paArgs = @('-m', 'PyInstaller', '--onefile', '--windowed', '--name', 'pt_agent', '--noconfirm',
        '--distpath', (Join-Path $here 'dist'), '--workpath', (Join-Path $here 'build'),
        '--specpath', $here, $src)
    & $py @pyargs @paArgs
    if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $dist))) { Write-Error "PyInstaller build failed."; exit 1 }
    Copy-Item $dist $exe -Force
    Write-Host "Built pt_agent.exe version $ver  -- publish '$ver' on the console's App update page."
}

# warn (non-fatal) if the runtime config files are missing
foreach ($need in @("pt_agent.conf.json", "ptagent.pta")) {
    if (-not (Test-Path (Join-Path $here $need))) {
        Write-Warning "$need is not in this folder - the app needs it at runtime. Put it next to pt_agent.exe."
    }
}

# 3) shortcuts: Desktop + Startup (auto-start at login)
foreach ($t in $oldtargets) { if (Test-Path $t) { Remove-Item $t -Force; Write-Host "removed old $t" } }
$ws = New-Object -ComObject WScript.Shell
foreach ($t in $targets) {
    $lnk = $ws.CreateShortcut($t)
    $lnk.TargetPath       = $exe
    $lnk.WorkingDirectory = $here
    $lnk.IconLocation     = $exe
    $lnk.Description       = "PT Comp"
    $lnk.Save()
    Write-Host "created $t"
}

Write-Host ""
Write-Host "Done. Desktop shortcut + auto-start at login are set."
Write-Host "For 'starts on boot', enable automatic logon for this Windows user on the VM."

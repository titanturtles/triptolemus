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

param([switch]$Remove, [switch]$ForceBuild)
$ErrorActionPreference = "Stop"

$here    = Split-Path -Parent $MyInvocation.MyCommand.Definition
$name    = "Cisco PT Competition.lnk"
$desktop = [Environment]::GetFolderPath("Desktop")
$startup = [Environment]::GetFolderPath("Startup")
$targets = @((Join-Path $desktop $name), (Join-Path $startup $name))

if ($Remove) {
    foreach ($t in $targets) { if (Test-Path $t) { Remove-Item $t -Force; Write-Host "removed $t" } }
    Write-Host "Done (Packet Tracer registration was not touched)."
    return
}

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
    Write-Host "Building pt_agent.exe from pt_agent.py (first run can take a minute)..."

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
    Write-Host "Built pt_agent.exe"
}

# warn (non-fatal) if the runtime config files are missing
foreach ($need in @("pt_agent.conf.json", "ptagent.pta")) {
    if (-not (Test-Path (Join-Path $here $need))) {
        Write-Warning "$need is not in this folder - the app needs it at runtime. Put it next to pt_agent.exe."
    }
}

# 3) shortcuts: Desktop + Startup (auto-start at login)
$ws = New-Object -ComObject WScript.Shell
foreach ($t in $targets) {
    $lnk = $ws.CreateShortcut($t)
    $lnk.TargetPath       = $exe
    $lnk.WorkingDirectory = $here
    $lnk.IconLocation     = $exe
    $lnk.Description       = "Cisco Packet Tracer Competition"
    $lnk.Save()
    Write-Host "created $t"
}

Write-Host ""
Write-Host "Done. Desktop shortcut + auto-start at login are set."
Write-Host "For 'starts on boot', enable automatic logon for this Windows user on the VM."

# Fires every penalty of sprint01-accounts-adv-windows (CI only; never uploaded).
$ErrorActionPreference = 'Stop'
# leave the two required services stopped (service-not-running penalties)
Stop-Service -Name WinRM        -Force -ErrorAction SilentlyContinue
Stop-Service -Name LanmanServer -Force -ErrorAction SilentlyContinue
# remove legitimate applications (app-removal penalties)
Remove-Item -Path 'C:\Program Files\Mozilla Firefox' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\Program Files\GIMP 2' -Recurse -Force -ErrorAction SilentlyContinue

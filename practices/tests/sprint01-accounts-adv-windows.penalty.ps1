# Fires every penalty of sprint01-accounts-adv-windows (CI only; never uploaded).
$ErrorActionPreference = 'Stop'
Remove-Item -Path 'C:\Program Files\Mozilla Firefox' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\Program Files\GIMP 2' -Recurse -Force -ErrorAction SilentlyContinue

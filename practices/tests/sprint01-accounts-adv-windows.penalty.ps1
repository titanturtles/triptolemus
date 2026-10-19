# Fires every penalty of sprint01-accounts-adv-windows (CI only; never uploaded).
$ErrorActionPreference = 'Stop'
# Leave the two required services stopped AND disabled. Disabling matters: LanmanServer is a
# trigger-start service, so an SMB access during the scoring pass (e.g. Get-SmbShareAccess in the
# "not open to Everyone" check) would otherwise restart it before the "service not running" penalty
# is evaluated. Setup re-enables (Automatic) and starts them again on the next pass.
foreach ($svc in 'WinRM','LanmanServer') {
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
}
# remove legitimate applications (app-removal penalties)
Remove-Item -Path 'C:\Program Files\Mozilla Firefox' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\Program Files\GIMP 2' -Recurse -Force -ErrorAction SilentlyContinue

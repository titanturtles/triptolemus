# Sets off every penalty of sprint01-accounts-adv-windows (CI tests only; never uploaded).
$ErrorActionPreference = 'Stop'
Remove-LocalUser -Name 'alice'
Remove-LocalUser -Name 'frank'

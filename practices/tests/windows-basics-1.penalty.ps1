# Sets off every penalty of windows-basics-1 (CI tests only; never uploaded to students).
$ErrorActionPreference = 'Stop'
Remove-LocalUser -Name 'alice'
Remove-LocalUser -Name 'bob'

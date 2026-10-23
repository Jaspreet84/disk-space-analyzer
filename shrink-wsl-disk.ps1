# Shrinks a WSL distribution's virtual disk (ext4.vhdx) so Windows gets back space that was freed inside Linux.
# The disk file grows as Linux needs space but never shrinks by itself.
#
#   powershell -ExecutionPolicy Bypass -File shrink-wsl-disk.ps1 [-Distro Ubuntu]
#
# Needs administrator rights (it asks for them). It shuts down WSL, which also stops Docker Desktop.

param([string]$Distro = 'Ubuntu')

$ErrorActionPreference = 'Stop'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host 'Asking for administrator rights...'
    Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit',
        '-File', "`"$PSCommandPath`"", '-Distro', $Distro
    return
}

# Find the distribution's disk file from WSL's own registration.
$entry = Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' |
    ForEach-Object { Get-ItemProperty $_.PSPath } |
    Where-Object { $_.DistributionName -eq $Distro } | Select-Object -First 1
if (-not $entry) { throw "No WSL distribution named '$Distro'. Run 'wsl -l' to see the names." }
$disk = Join-Path ($entry.BasePath -replace '^\\\\\?\\', '') 'ext4.vhdx'
if (-not (Test-Path $disk)) { throw "Disk file not found: $disk" }

$before = (Get-Item $disk).Length
Write-Host ("Disk file: {0}`nSize now:  {1:N1} GB" -f $disk, ($before / 1GB))

# Tell the disk which blocks Linux no longer uses, so compacting can release them.
Write-Host 'Marking free space inside Linux...'
wsl -d $Distro -u root fstrim -v /

Write-Host 'Shutting down WSL...'
wsl --shutdown
Start-Sleep -Seconds 3

$script = Join-Path $env:TEMP 'compact-wsl-disk.txt'
@(
    "select vdisk file=`"$disk`""
    'attach vdisk readonly'
    'compact vdisk'
    'detach vdisk'
) | Set-Content -Encoding ascii $script
Write-Host 'Compacting (this can take a few minutes)...'
diskpart /s $script
Remove-Item $script

$after = (Get-Item $disk).Length
Write-Host ("`nSize after: {0:N1} GB  (freed {1:N1} GB)" -f ($after / 1GB), (($before - $after) / 1GB))

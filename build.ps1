# Builds bin\DiskSpaceAnalyzer.exe (the app) and bin\dsa.exe (the command-line version) with the
# C# compiler that ships with Windows as part of .NET Framework 4.x. Nothing needs to be installed.
#
#   powershell -ExecutionPolicy Bypass -File build.ps1

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$src = Join-Path $root 'src'
$ui = Join-Path $src 'Ui'
$bin = Join-Path $root 'bin'
$obj = Join-Path $root 'obj'

$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
if (-not (Test-Path (Join-Path $framework 'csc.exe'))) { $framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319' }
$csc = Join-Path $framework 'csc.exe'
if (-not (Test-Path $csc)) { throw 'The .NET Framework 4.x C# compiler (csc.exe) was not found.' }

New-Item -ItemType Directory -Force $bin, $obj | Out-Null

$common = 'Native.cs', 'Model.cs', 'Scanner.cs', 'Placement.cs', 'Protect.cs', 'AppIcon.cs', 'Program.cs' | ForEach-Object { Join-Path $src $_ }
$options = @('/nologo', '/optimize+', '/codepage:65001', '/platform:anycpu', "/win32manifest:$src\app.manifest",
             '/r:System.dll', '/r:System.Core.dll', '/r:System.Drawing.dll', '/r:System.Management.dll')

Write-Host 'Building dsa.exe'
& $csc @options /target:exe /define:CLI "/out:$bin\dsa.exe" @common (Join-Path $src 'Cli.cs')
if ($LASTEXITCODE -ne 0) { throw 'dsa.exe failed to build.' }

# The app icon is drawn in code; dsa.exe writes it out so it can be embedded in the app.
$icon = Join-Path $obj 'app.ico'
& (Join-Path $bin 'dsa.exe') --write-icon $icon
if ($LASTEXITCODE -ne 0) { throw 'Could not write the app icon.' }

Write-Host 'Building DiskSpaceAnalyzer.exe'
$app = @('Shell.cs', 'VirtualDisks.cs', 'Insights.cs', 'Transfer.cs' | ForEach-Object { Join-Path $src $_ }) + @(Get-ChildItem $ui -Filter *.cs | ForEach-Object { $_.FullName })
$wpf = @("/r:$framework\WPF\PresentationCore.dll", "/r:$framework\WPF\PresentationFramework.dll",
         "/r:$framework\WPF\WindowsBase.dll", "/r:$framework\System.Xaml.dll")
# The XAML is embedded as-is and loaded when the app starts.
$xaml = Get-ChildItem $ui -Filter *.xaml | ForEach-Object { "/resource:$($_.FullName),DiskSpace.$($_.Name)" }
& $csc @options @wpf @xaml /target:winexe "/win32icon:$icon" "/out:$bin\DiskSpaceAnalyzer.exe" @common @app
if ($LASTEXITCODE -ne 0) { throw 'DiskSpaceAnalyzer.exe failed to build.' }

# The Protect page's guarantees: no network code anywhere, no file writes in Protect. A failure fails the build.
& (Join-Path $root 'tools\check-trust.ps1')

Write-Host "Done. Run $bin\DiskSpaceAnalyzer.exe"

# Runs the Protect tests. Writes the fixture tree, compiles tests\ProtectTests.cs with the app's source, runs
# it, then checks that the source-level trust checks catch planted file writes and planted content reads.
#
#   powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1
#
# Everything the tests write goes under obj\tests, except the fixture tree (%TEMP%\dsa-protect-tree-<guid>) and
# the coverage folders (%TEMP%\dsa-cov-<guid>), which are removed afterwards.

param([string]$Work)  # -Work: another folder under obj\ to use, so two runs at once do not collide

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root 'src'
$obj = Join-Path $root 'obj'
$work = if ($Work) { Join-Path $obj $Work } else { Join-Path $obj 'tests' }
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force $work | Out-Null

$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
if (-not (Test-Path (Join-Path $framework 'csc.exe'))) { $framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319' }
$csc = Join-Path $framework 'csc.exe'

Write-Host 'Writing the fixture tree'
# The tree goes under %TEMP%, not obj: a scan root below a folder named obj or tests would put every case below a
# build-output or fixture folder, which changes what Protect reports.
$tree = Join-Path $env:TEMP ('dsa-protect-tree-' + [Guid]::NewGuid().ToString('N'))
& (Join-Path $PSScriptRoot 'make-protect-tree.ps1') -Out $tree | Out-Null

Write-Host 'Compiling the tests'
$sources = @('Native.cs', 'Model.cs', 'Scanner.cs', 'Protect.cs', 'ProtectContext.cs', 'ProtectNames.cs', 'ProtectCoverage.cs' |
             ForEach-Object { Join-Path $src $_ }) +
           @((Join-Path $root 'tools\CheckTrust.cs'), (Join-Path $PSScriptRoot 'ProtectTests.cs'))
& $csc /nologo /optimize+ /nowarn:649 /target:exe /main:ProtectTests /r:System.dll /r:System.Core.dll /r:System.Drawing.dll "/out:$work\tests.exe" @sources
if ($LASTEXITCODE -ne 0) { throw 'The tests failed to compile.' }

Write-Host 'Running the tests'
& "$work\tests.exe" (Join-Path $work 'work') $csc $root $tree
$failed = $LASTEXITCODE
Remove-Item -LiteralPath $tree -Recurse -Force -ErrorAction SilentlyContinue

# The trust checks must refuse a Protect source file that writes a file or reads one's contents. Each case is a
# copy of src\Protect.cs plus one planted file (or one planted line), checked with -Root; the check must throw
# and name the planted file.
function Test-Planted([string]$name, [string]$file, [string]$text, [string]$expect, [switch]$append) {
    $planted = Join-Path $work ('planted-' + $name)
    New-Item -ItemType Directory -Force (Join-Path $planted 'src') | Out-Null
    Copy-Item (Join-Path $src 'Protect.cs') (Join-Path $planted 'src\Protect.cs')
    $target = Join-Path $planted ('src\' + $file)
    if ($append) { Add-Content $target $text } else { Set-Content $target $text }
    $caught = $false
    $message = ''
    try { & (Join-Path $root 'tools\check-trust.ps1') -Root $planted -Programs (Join-Path $root 'bin\dsa.exe') | Out-Null }
    catch { $message = $_.Exception.Message; $caught = $message -like $expect }
    if ($caught) { Write-Host "PASS  the trust check refuses $name" }
    else { Write-Host "FAIL  the trust check let $name through ($message)"; $script:failed++ }
}

Write-Host 'Checking that the source trust checks catch planted writes and reads'
Test-Planted 'a planted File.Delete (check 2)' 'Protect.Planted.cs' `
    'class Planted { static void Go(string p) { System.IO.File.Delete(p); } }' '*Protect.Planted.cs*writes*'
Test-Planted 'a planted profile.Open( (check 2, no word boundary)' 'ProtectPlantedProfile.cs' `
    'class Planted { static void Go(Planted profile) { profile.Open(1); } void Open(int x) { } }' '*ProtectPlantedProfile.cs*writes*'
Test-Planted 'a planted File.ReadAllText (check 3)' 'ProtectPlantedRead.cs' `
    'class Planted { static string Go(string p) { return System.IO.File.ReadAllText(p); } }' '*ProtectPlantedRead.cs*reads*'
Test-Planted 'a planted StreamReader (check 3)' 'ProtectNamesPlanted.cs' `
    'class Planted { static void Go(string p) { using (var r = new System.IO.StreamReader(p)) { } } }' '*ProtectNamesPlanted.cs*reads*'
Test-Planted 'a planted File.ReadLines (check 3)' 'ProtectPlantedLines.cs' `
    'class Planted { static int Go(string p) { int n = 0; foreach (var l in System.IO.File.ReadLines(p)) n++; return n; } }' '*ProtectPlantedLines.cs*reads*'
Test-Planted 'a planted Image.FromFile (check 3)' 'ProtectPlantedImage.cs' `
    'class Planted { static object Go(string p) { return System.Drawing.Image.FromFile(p); } }' '*ProtectPlantedImage.cs*reads*'
Test-Planted 'a planted XDocument.Load (check 3)' 'ProtectPlantedXml.cs' `
    'class Planted { static object Go(string p) { return System.Xml.Linq.XDocument.Load(p); } }' '*ProtectPlantedXml.cs*reads*'
Test-Planted 'a trust-read marker outside Protect.cs (check 3)' 'ProtectCoveragePlanted.cs' `
    'class Planted { static string Go(string p) { return System.IO.File.ReadAllText(p); } } // trust-read: sneaked in' '*marker outside Protect.cs*ProtectCoveragePlanted.cs*'
Test-Planted 'a second trust-read marker in Protect.cs (check 3)' 'Protect.cs' `
    '// File.ReadAllText again // trust-read: a second marked read' '*marked read lines*' -append

if ($failed -ne 0) { throw "$failed test(s) failed." }
Write-Host 'All tests passed.'

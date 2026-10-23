# Runs the Protect tests. Compiles tests\ProtectTests.cs with the app's source, runs it, then checks that the
# source-level trust check catches a planted file write.
#
#   powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root 'src'
$obj = Join-Path $root 'obj'
$work = Join-Path $obj 'tests'
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force $work | Out-Null

$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
if (-not (Test-Path (Join-Path $framework 'csc.exe'))) { $framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319' }
$csc = Join-Path $framework 'csc.exe'

Write-Host 'Compiling the tests'
$sources = @('Native.cs', 'Model.cs', 'Scanner.cs', 'Protect.cs' | ForEach-Object { Join-Path $src $_ }) +
           @((Join-Path $root 'tools\CheckTrust.cs'), (Join-Path $PSScriptRoot 'ProtectTests.cs'))
& $csc /nologo /nowarn:649 /target:exe /main:ProtectTests /r:System.dll /r:System.Core.dll /r:System.Drawing.dll "/out:$work\tests.exe" @sources
if ($LASTEXITCODE -ne 0) { throw 'The tests failed to compile.' }

Write-Host 'Running the tests'
& "$work\tests.exe" (Join-Path $work 'work') $csc $root
$failed = $LASTEXITCODE

# The trust check must refuse a Protect source file that writes a file. A copy of src with one planted line
# is checked with -Root; the check is expected to throw.
Write-Host 'Checking that the source trust check catches a planted write'
$planted = Join-Path $work 'planted-root'
New-Item -ItemType Directory -Force (Join-Path $planted 'src') | Out-Null
Copy-Item (Join-Path $src 'Protect.cs') (Join-Path $planted 'src\Protect.cs')
Set-Content (Join-Path $planted 'src\Protect.Planted.cs') 'class Planted { static void Go(string p) { System.IO.File.Delete(p); } }'
$caught = $false
try { & (Join-Path $root 'tools\check-trust.ps1') -Root $planted -Programs (Join-Path $root 'bin\dsa.exe') | Out-Null }
catch { $caught = $_.Exception.Message -like '*Protect.Planted.cs*' }
if ($caught) { Write-Host 'PASS  the trust check refuses a planted File.Delete in a Protect source file' }
else { Write-Host 'FAIL  the trust check let a planted File.Delete through'; $failed++ }

if ($failed -ne 0) { throw "$failed test(s) failed." }
Write-Host 'All tests passed.'

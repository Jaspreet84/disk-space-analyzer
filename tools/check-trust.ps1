# The trust checks behind the Protect page. build.ps1 runs this after every build, and anyone can run it on
# the finished programs:
#
#   powershell -ExecutionPolicy Bypass -File tools\check-trust.ps1 [path\to\program.exe ...]
#
# 1. No network code: the compiled programs name no System.Net type and reference no System.Net assembly.
# 2. Protect is read-only: the Protect source files contain no call that writes, deletes or moves a file,
#    except the two marked "// trust:" lines in Protect.cs that save protect.json.
# It throws on the first failure, which fails the build.

param([string[]]$Programs, [string]$Root)

$ErrorActionPreference = 'Stop'
$root = if ($Root) { $Root } else { Split-Path $PSScriptRoot -Parent }  # -Root: another source tree to check (used by the tests)
$obj = Join-Path (Split-Path $PSScriptRoot -Parent) 'obj'
New-Item -ItemType Directory -Force $obj | Out-Null

$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
if (-not (Test-Path (Join-Path $framework 'csc.exe'))) { $framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319' }
$csc = Join-Path $framework 'csc.exe'
$checker = Join-Path $obj 'CheckTrust.exe'
& $csc /nologo /optimize+ /target:exe "/out:$checker" (Join-Path $PSScriptRoot 'CheckTrust.cs')
if ($LASTEXITCODE -ne 0) { throw 'The trust checker failed to build.' }

if (-not $Programs -or $Programs.Count -eq 0) {
    $Programs = @((Join-Path $root 'bin\DiskSpaceAnalyzer.exe'), (Join-Path $root 'bin\dsa.exe'))
}

Write-Host 'Trust check 1: no network code'
& $checker @Programs
if ($LASTEXITCODE -ne 0) { throw 'Trust check failed: a program names a System.Net type.' }

Write-Host 'Trust check 2: Protect never writes a file'
$files = @(Get-ChildItem (Join-Path $root 'src') -Recurse -File |
    Where-Object { $_.Name -match '^(Protect.*|SecretScan|GitStatus|MainWindow\.Protect)\.cs$' })
$forbidden = 'File\.(Write|Delete|Move|Copy|Create|Open\(|Append|Replace|SetAttributes)|Directory\.(Delete|Move|CreateDirectory)|' +
             'new FileStream\(|StreamWriter|FileMode\.|FileAccess\.(Write|ReadWrite)|SHFileOperation|MoveToRecycleBin|CopyFileEx'
$markers = 0
foreach ($f in $files) {
    $n = 0
    foreach ($line in Get-Content $f.FullName) {
        $n++
        if ($line -notmatch $forbidden) { continue }
        if ($line -match '// trust:') {
            if ($f.Name -ne 'Protect.cs') { throw "Trust check failed: a '// trust:' marker outside Protect.cs ($($f.Name):$n)." }
            $markers++
            continue
        }
        throw "Trust check failed: $($f.Name):$n writes, deletes or moves a file: $($line.Trim())"
    }
}
if ($markers -gt 2) { throw "Trust check failed: Protect.cs has $markers marked write lines; only the two that save protect.json are allowed." }
Write-Host ("  {0} Protect source file(s), {1} marked write line(s) in Protect.cs, no others" -f $files.Count, $markers)
Write-Host 'Trust checks passed.'

# Runs the Protect tests. Writes the fixture tree, compiles tests\ProtectTests.cs with the app's source, runs
# it, checks the command line's content-scan switches, then checks that the source-level trust checks catch
# planted file writes, planted content reads and the other planted trust breaks.
#
#   powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1 [-TrustOnly]
#
# Everything the tests write goes under obj\tests, except the fixture tree (%TEMP%\dsa-protect-tree-<guid>), the
# coverage folders (%TEMP%\dsa-cov-<guid>) and the generated content corpus and skip plants
# (%TEMP%\dsa-content-<guid>, %TEMP%\dsa-plant-<guid>), which are removed afterwards. Left-over ones from a run
# that crashed are removed at the start.

param([string]$Work,       # another folder under obj\ to use, so two runs at once do not collide
      [switch]$TrustOnly)  # run only the planted trust cases (no fixture tree, no tests.exe)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root 'src'
$obj = Join-Path $root 'obj'
$work = if ($Work) { Join-Path $obj $Work } else { Join-Path $obj 'tests' }
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force $work | Out-Null
$failed = 0

# Generated content files hold well-formed test keys; a crash must not leave them where a content scan of Temp
# would find them later.
foreach ($stale in @(Get-ChildItem $env:TEMP -Directory -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -like 'dsa-content-*' -or $_.Name -like 'dsa-plant-*' })) {
    Remove-Item -LiteralPath $stale.FullName -Recurse -Force -ErrorAction SilentlyContinue
}

$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
if (-not (Test-Path (Join-Path $framework 'csc.exe'))) { $framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319' }
$csc = Join-Path $framework 'csc.exe'
$dsa = Join-Path $root 'bin\dsa.exe'

# Runs dsa.exe and returns its exit code and stderr. Stdout goes to a temporary file that is deleted unread.
function Invoke-Dsa([string[]]$arguments) {
    $err = [IO.Path]::GetTempFileName()
    $out = [IO.Path]::GetTempFileName()
    try {
        $quoted = @($arguments | ForEach-Object { '"' + ($_ -replace '\\$', '\\') + '"' })
        $p = Start-Process -FilePath $dsa -ArgumentList $quoted -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $out -RedirectStandardError $err
        return @{ Code = $p.ExitCode; Err = [IO.File]::ReadAllText($err) }
    }
    finally { Remove-Item -LiteralPath $err, $out -ErrorAction SilentlyContinue }
}

function Report([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "PASS  $what" } else { Write-Host "FAIL  $what"; $script:failed++ }
}

if (-not $TrustOnly) {
    Write-Host 'Writing the fixture tree'
    # The tree goes under %TEMP%, not obj: a scan root below a folder named obj or tests would put every case below a
    # build-output or fixture folder, which changes what Protect reports.
    $tree = Join-Path $env:TEMP ('dsa-protect-tree-' + [Guid]::NewGuid().ToString('N'))
    & (Join-Path $PSScriptRoot 'make-protect-tree.ps1') -Out $tree | Out-Null

    try {
        Write-Host 'Compiling the tests'
        $sources = @('Native.cs', 'Model.cs', 'Scanner.cs', 'Protect.cs', 'ProtectContext.cs', 'ProtectNames.cs', 'ProtectCoverage.cs',
                     'SecretScan.cs' | ForEach-Object { Join-Path $src $_ }) +
                   @((Join-Path $root 'tools\CheckTrust.cs'), (Join-Path $PSScriptRoot 'ProtectTests.cs'),
                     (Join-Path $PSScriptRoot 'ContentCorpus.cs'))
        & $csc /nologo /optimize+ /nowarn:649 /target:exe /main:ProtectTests /r:System.dll /r:System.Core.dll /r:System.Drawing.dll "/out:$work\tests.exe" @sources
        if ($LASTEXITCODE -ne 0) { throw 'The tests failed to compile.' }

        Write-Host 'Running the tests'
        & "$work\tests.exe" (Join-Path $work 'work') $csc $root $tree
        $failed = $LASTEXITCODE

        # The command line: without --content nothing is opened, and --content alone is refused (spec 4.6.1, 10.1.12).
        Write-Host 'Checking the command line'
        $off = Invoke-Dsa @($tree, '--protect', '--protect-home', $tree, '--timing')
        Report ($off.Code -eq 0 -and $off.Err -match '(?m)^files_opened 0\s*$') 'dsa --protect --timing prints files_opened 0 (nothing opened without --content)'
        $alone = Invoke-Dsa @($tree, '--content')
        Report ($alone.Code -eq 2 -and $alone.Err -match '--content needs --protect\.') 'dsa --content without --protect is refused'
    }
    finally { Remove-Item -LiteralPath $tree -Recurse -Force -ErrorAction SilentlyContinue }
}

# The trust checks must refuse a Protect source tree that writes a file, reads one's contents outside the audited
# region, or breaks one of the content-scan rules. Each case is a copy of src\Protect.cs, src\SecretScan.cs and
# src\Shell.cs (a non-Protect file that declares a class, for check 7) with one change: a planted file, a planted
# line, or an edit. The check runs with -Root on the copy and must throw and name the file. The unchanged copy
# must pass.
#   -text/-append: write $text as a new file, or append it to $file.
#   -edit: a script block that gets the file's lines and returns the changed lines.
#   -pass: the check must not throw.
function Test-Planted([string]$name, [string]$file, [string]$text, [string]$expect, [switch]$append,
                      [scriptblock]$edit, [switch]$pass) {
    $planted = Join-Path $work ('planted-' + ($name -replace '[^A-Za-z0-9]+', '-'))
    New-Item -ItemType Directory -Force (Join-Path $planted 'src') | Out-Null
    foreach ($copy in 'Protect.cs', 'SecretScan.cs', 'Shell.cs') { Copy-Item (Join-Path $src $copy) (Join-Path $planted ('src\' + $copy)) }
    $target = Join-Path $planted ('src\' + $file)
    $message = ''
    try {
        if ($edit) {
            $lines = [IO.File]::ReadAllText($target) -split "`n"
            $changed = @(& $edit $lines)
            [IO.File]::WriteAllText($target, ($changed -join "`n"))
        }
        elseif ($append) { [IO.File]::AppendAllText($target, "`n" + $text + "`n") }
        elseif ($text) { [IO.File]::WriteAllText($target, $text + "`n") }
    }
    catch { Report $false "planting $name ($($_.Exception.Message))"; return }
    $threw = $false
    try { & (Join-Path $root 'tools\check-trust.ps1') -Root $planted -Programs $dsa 6>$null | Out-Null }  # 6>: its progress lines
    catch { $threw = $true; $message = $_.Exception.Message }
    if ($pass) { Report (-not $threw) ("the trust check passes $name" + $(if ($threw) { " ($message)" } else { '' })); return }
    if ($threw -and $message -like $expect) { Write-Host "PASS  the trust check refuses $name" }
    else { Write-Host "FAIL  the trust check let $name through ($message)"; $script:failed++ }
}

# Edits used by the cases below. Each throws when the line it needs is missing, so a case cannot pass by accident.
function Insert-AfterBegin([string[]]$lines, [string]$text) {
    $i = [Array]::FindIndex($lines, [Predicate[string]] { param($l) $l.Trim() -eq '// trust-read-begin: content' })
    if ($i -lt 0) { throw 'no begin marker' }
    return @($lines[0..$i]) + @($text) + @($lines[($i + 1)..($lines.Count - 1)])
}
function Edit-OpenLine([string[]]$lines, [string]$from, [string]$to) {
    $inside = $false; $done = $false
    $out = foreach ($l in $lines) {
        if ($l.Trim() -eq '// trust-read-begin: content') { $inside = $true }
        elseif ($l.Trim() -eq '// trust-read-end') { $inside = $false }
        elseif ($inside -and -not $done -and $l -match 'CreateFileW\(' -and $l -notmatch 'extern') { $l = $l -replace $from, $to; $done = $true }
        $l
    }
    if (-not $done) { throw 'no open line' }
    return $out
}

Write-Host 'Checking that the source trust checks catch planted writes and reads'
Test-Planted 'the unchanged copy' 'Protect.cs' -pass
Test-Planted 'a comment saying shared in SecretScan.cs (no SHA ban)' 'SecretScan.cs' `
    '// Each buffer is shared by no one; files are opened shared for reading.' -append -pass

# Stage 1 cases.
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

# Stage 2 cases (spec 4.5, cases 10 to 30).
Test-Planted '10: ReadFile( outside the region (check 3)' 'SecretScan.cs' `
    'static class PlantedRead { static void Go() { ReadFile(System.IntPtr.Zero); } }' '*check 3*SecretScan.cs*outside the marked region*' -append
Test-Planted '11: File.ReadAllBytes in SecretScan.cs (check 3)' 'SecretScan.cs' `
    'static class PlantedRead { static byte[] Go(string p) { return System.IO.File.ReadAllBytes(p); } }' '*check 3*SecretScan.cs*' -append
Test-Planted '12: a second region (check 3a)' 'SecretScan.cs' `
    "// trust-read-begin: content`n// trust-read-end" '*check 3*SecretScan.cs*1 marked region*' -append
Test-Planted '13: a begin marker in ProtectNames.cs (check 3)' 'ProtectNames.cs' `
    '// trust-read-begin: content' '*check 3*outside SecretScan.cs*ProtectNames.cs*'
Test-Planted '14: an unclosed region (check 3)' 'SecretScan.cs' -expect '*check 3*SecretScan.cs*no trust-read-end*' `
    -edit { param($l) $o = @($l | Where-Object { $_.Trim() -ne '// trust-read-end' }); if ($o.Count -eq $l.Count) { throw 'no end marker' }; $o }
Test-Planted '15: an end marker before the begin marker (check 3)' 'SecretScan.cs' -expect '*check 3*no open region*SecretScan.cs*' `
    -edit { param($l) @('// trust-read-end') + $l }
Test-Planted '16: GENERIC_WRITE inside the region (check 3c)' 'SecretScan.cs' -expect '*check 3*SecretScan.cs*GENERIC_WRITE*' `
    -edit { param($l) Insert-AfterBegin $l '        const uint PlantedAccess = GENERIC_WRITE;' }
Test-Planted '17: a second CreateFileW( call in the region (check 3a)' 'SecretScan.cs' -expect '*check 3*SecretScan.cs*1 open call*' `
    -edit { param($l) Insert-AfterBegin $l '        static object Planted(string p) { return CreateFileW(p, GENERIC_READ, 7, System.IntPtr.Zero, OPEN_EXISTING, 0, System.IntPtr.Zero); }' }
Test-Planted '18: the open line without OPEN_EXISTING (check 3)' 'SecretScan.cs' -expect '*check 3*OPEN_EXISTING*SecretScan.cs*' `
    -edit { param($l) Edit-OpenLine $l 'OPEN_EXISTING' '3' }
Test-Planted '19: a [DllImport outside the region (check 3)' 'SecretScan.cs' `
    'static class PlantedImport { [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern uint GetTickCount(); }' '*check 3*SecretScan.cs*P/Invoke outside*' -append
Test-Planted '20: a trust-read marker in SecretScan.cs (check 3b)' 'SecretScan.cs' `
    '// trust-read: one more' '*check 3*trust-read*SecretScan.cs*' -append
Test-Planted '21: ContentReader named in MainWindow.Protect.cs (check 3e)' 'MainWindow.Protect.cs' `
    'class Planted { object Go() { return typeof(SecretScan.ContentReader); } }' '*check 3*MainWindow.Protect.cs*ContentReader*'
Test-Planted '22: new string( in SecretScan.cs (check 4)' 'SecretScan.cs' `
    'static class PlantedText { static object Go(char[] c) { return new string(c); } }' '*check 4*SecretScan.cs*' -append
Test-Planted '23: Encoding.UTF8 in SecretScan.cs (check 4)' 'SecretScan.cs' `
    'static class PlantedText { static object Go() { return System.Text.Encoding.UTF8; } }' '*check 4*SecretScan.cs*' -append
Test-Planted '24: a second new byte[ (check 4)' 'SecretScan.cs' `
    'static class PlantedBuffer { static object Go() { return new byte[16]; } }' '*check 4*SecretScan.cs*new byte*' -append
Test-Planted '25: Array.Copy( in SecretScan.cs (check 4)' 'SecretScan.cs' `
    'static class PlantedCopy { static void Go(byte[] a, byte[] b) { System.Array.Copy(a, b, 4); } }' '*check 4*SecretScan.cs*' -append
Test-Planted '26: a second new Finding( (check 5)' 'SecretScan.cs' `
    'static class PlantedFinding { static object Go() { return new Finding("x", FindingTier.Likely, "p", 1, 1, Place.Other); } }' '*check 5*SecretScan.cs*' -append
Test-Planted '27: FromCommandLine in MainWindow.Protect.cs (check 6)' 'MainWindow.Protect.cs' `
    'class Planted { object Go() { return ContentConsent.FromCommandLine(true); } }' '*check 6*MainWindow.Protect.cs*'
Test-Planted '28: SecretScan.cs calling ShellOps.Open (check 7)' 'SecretScan.cs' `
    'static class PlantedShell { static void Go(string x) { ShellOps.Open(x); } }' '*check 7*SecretScan.cs*ShellOps*' -append
Test-Planted '29: SecretScan.cs calling Scanner.Scan( (check 7)' 'SecretScan.cs' `
    'static class PlantedScan { static object Go() { return Scanner.Scan(null); } }' '*check 7*SecretScan.cs*Scanner*' -append
Test-Planted '30: SetFileInformationByHandle in SecretScan.cs (check 3d)' 'SecretScan.cs' `
    'static class PlantedHint { static void Go() { SetFileInformationByHandle(System.IntPtr.Zero, 12, System.IntPtr.Zero, 4); } }' '*check 3*SecretScan.cs*SetFileInformationByHandle*' -append

# The open call's names must keep their read-only values (check 3 a2).
function Edit-Const([string[]]$lines, [string]$from, [string]$to) {
    $done = $false
    $out = foreach ($l in $lines) { if (-not $done -and $l -match $from) { $l = $l -replace $from, $to; $done = $true }; $l }
    if (-not $done) { throw "no line matching $from" }
    return $out
}
Test-Planted '31: GENERIC_READ redefined as read plus write (check 3)' 'SecretScan.cs' -expect '*check 3*GENERIC_READ*' `
    -edit { param($l) Edit-Const $l 'GENERIC_READ = 0x80000000;' 'GENERIC_READ = 3u << 30;' }
Test-Planted '32: OPEN_EXISTING redefined as OPEN_ALWAYS (check 3)' 'SecretScan.cs' -expect '*check 3*OPEN_EXISTING*' `
    -edit { param($l) Edit-Const $l 'OPEN_EXISTING = 3;' 'OPEN_EXISTING = 4;' }
Test-Planted '33: the share mode set to 0 (check 3)' 'SecretScan.cs' -expect '*check 3*FILE_SHARE_READ*' `
    -edit { param($l) Edit-Const $l 'FILE_SHARE_READ = 1,' 'FILE_SHARE_READ = 0,' }
Test-Planted '34: a fourth flag on the open call (check 3)' 'SecretScan.cs' -expect '*check 3*three allowed flags*' `
    -edit { param($l) Edit-OpenLine $l 'FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero\)' 'FILE_FLAG_OPEN_REPARSE_POINT | 0x400, IntPtr.Zero)' }
Test-Planted '35: a second value for OPEN_EXISTING (check 3)' 'SecretScan.cs' -expect '*check 3*OPEN_EXISTING*exactly once*' `
    -edit { param($l) Insert-AfterBegin $l '        static uint Planted() { uint OPEN_EXISTING = 4; return OPEN_EXISTING; }' }

if ($failed -ne 0) { throw "$failed test(s) failed." }
Write-Host 'All tests passed.'

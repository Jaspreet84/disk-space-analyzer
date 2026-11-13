# The scan-time budget for Protect stage 1: a scan with Protect may take at most 5% longer than one without.
# Runs dsa.exe on a folder with --protect and with --no-protect, alternating, one warm-up of each and then
# -Runs timed runs of each, and compares the medians of scan_ms + analyze_ms (from --timing). Both runs load
# the drive list, so it does not skew the comparison. The findings themselves are not printed.
#
#   powershell -ExecutionPolicy Bypass -File tests\bench-protect.ps1 [-Path C:\Users\you] [-Runs 7]
#
# Exit code 0 when the budget holds, 1 when it does not.

param([string]$Path = $env:USERPROFILE, [int]$Runs = 7, [double]$Budget = 1.05,
      [string]$Dsa = (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\dsa.exe'))

$ErrorActionPreference = 'Stop'
# A trailing backslash would escape the closing quote on dsa.exe's command line (C:\ would become C:"), so it is
# doubled: "C:\\" reaches dsa.exe as C:\.
$quotedPath = '"' + ($Path -replace '\\$', '\\') + '"'
if (-not (Test-Path $Dsa)) { throw "dsa.exe not found at $Dsa; run build.ps1 first." }

function Invoke-Timed([string]$mode) {
    $err = [IO.Path]::GetTempFileName()
    $out = [IO.Path]::GetTempFileName()  # the findings; deleted below, never printed
    try {
        $p = Start-Process -FilePath $Dsa -ArgumentList @($quotedPath, $mode, '--timing') -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $out -RedirectStandardError $err
        if ($p.ExitCode -ne 0) { throw "dsa.exe $mode exited with $($p.ExitCode)." }
        $t = @{}
        foreach ($line in [IO.File]::ReadAllLines($err)) {
            if ($line -match '^(\w+_ms)\s+(\d+)\s*$') { $t[$matches[1]] = [long]$matches[2] }
        }
        if (-not $t.ContainsKey('scan_ms') -or -not $t.ContainsKey('analyze_ms')) { throw "dsa.exe $mode printed no timing." }
        return $t
    }
    finally { Remove-Item -LiteralPath $err, $out -ErrorAction SilentlyContinue }
}

function Median([long[]]$values) {
    $s = @($values | Sort-Object)
    $n = $s.Count
    if ($n % 2 -eq 1) { return [double]$s[($n - 1) / 2] }
    return ($s[$n / 2 - 1] + $s[$n / 2]) / 2.0
}

Write-Host "Warming up on $Path"
Invoke-Timed '--protect' | Out-Null
Invoke-Timed '--no-protect' | Out-Null

$with = New-Object 'System.Collections.Generic.List[long]'
$without = New-Object 'System.Collections.Generic.List[long]'
$analyzeWith = New-Object 'System.Collections.Generic.List[long]'
$analyzeWithout = New-Object 'System.Collections.Generic.List[long]'
for ($i = 1; $i -le $Runs; $i++) {
    $a = Invoke-Timed '--protect'
    $b = Invoke-Timed '--no-protect'
    $with.Add($a.scan_ms + $a.analyze_ms); $analyzeWith.Add($a.analyze_ms)
    $without.Add($b.scan_ms + $b.analyze_ms); $analyzeWithout.Add($b.analyze_ms)
    Write-Host ("  run {0}: protect {1} ms (analyze {2}), no protect {3} ms (analyze {4})" -f $i, ($a.scan_ms + $a.analyze_ms), $a.analyze_ms, ($b.scan_ms + $b.analyze_ms), $b.analyze_ms)
}

$mWith = Median $with.ToArray()
$mWithout = Median $without.ToArray()
$ratio = if ($mWithout -gt 0) { $mWith / $mWithout } else { 1.0 }
Write-Host ("Median scan + analyze: protect {0} ms, no protect {1} ms, ratio {2:0.000} (budget {3:0.00})" -f $mWith, $mWithout, $ratio, $Budget)
Write-Host ("Median analyze alone: protect {0} ms, no protect {1} ms" -f (Median $analyzeWith.ToArray()), (Median $analyzeWithout.ToArray()))
if ($ratio -le $Budget) { Write-Host 'PASS  Protect stays within the scan-time budget'; exit 0 }
Write-Host 'FAIL  Protect is over the scan-time budget'
exit 1

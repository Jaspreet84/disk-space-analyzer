# The time budget for the Protect content scan (stage 2): dsa <path> --protect --content, from start to the end
# of the content scan, must take under 180 s on C:\, cold (run it once right after a reboot, with Defender on).
# Runs dsa.exe -Runs times, and prints the median and maximum of the total and of content_ms, and the files/s
# and MB/s the content scan reached. Fails when any total is over the budget, or when files_opened differs from
# candidates (the counter counts every attempt to open, so the two must agree).
#
#   powershell -ExecutionPolicy Bypass -File tests\bench-content.ps1 [-Path C:\] [-Runs 3]
#
# Stdout (paths and kinds of key, never a key) is not needed here: it goes to a temporary file that is deleted
# unread. Only the counters on stderr are parsed. Record the cold total and content_ms in tests.md.
#
# Exit code 0 when the budget holds, 1 when it does not.

param([string]$Path = 'C:\', [int]$Runs = 3, [long]$BudgetMs = 180000,
      [string]$Dsa = (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\dsa.exe'))

$ErrorActionPreference = 'Stop'
# A trailing backslash would escape the closing quote on dsa.exe's command line (C:\ would become C:"), so it is
# doubled: "C:\\" reaches dsa.exe as C:\.
$quotedPath = '"' + ($Path -replace '\\$', '\\') + '"'
if (-not (Test-Path $Dsa)) { throw "dsa.exe not found at $Dsa; run build.ps1 first." }

$keys = 'scan_ms', 'context_ms', 'analyze_ms', 'plan_ms', 'content_ms', 'candidates', 'files_opened', 'bytes_read',
        'skipped_binary', 'skipped_utf16', 'skipped_large', 'skipped_unreadable'

function Invoke-Content {
    $err = [IO.Path]::GetTempFileName()
    $out = [IO.Path]::GetTempFileName()  # stdout: deleted below, never read
    try {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $p = Start-Process -FilePath $Dsa -ArgumentList @($quotedPath, '--protect', '--content', '--timing') -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $out -RedirectStandardError $err
        $wall = $clock.ElapsedMilliseconds
        if ($p.ExitCode -ne 0) { throw "dsa.exe exited with $($p.ExitCode)." }
        $t = @{ wall_ms = $wall }
        foreach ($line in [IO.File]::ReadAllLines($err)) {
            if ($line -match '^(\w+)\s+(\d+)\s*$') { $t[$matches[1]] = [long]$matches[2] }
        }
        foreach ($k in $keys) { if (-not $t.ContainsKey($k)) { throw "dsa.exe printed no $k." } }
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

Write-Host "Content scan of $Path, $Runs run(s); the first one is the cold run only right after a reboot"
$totals = New-Object 'System.Collections.Generic.List[long]'
$contents = New-Object 'System.Collections.Generic.List[long]'
$ok = $true
for ($i = 1; $i -le $Runs; $i++) {
    $t = Invoke-Content
    # The total is the wall time of the whole run: walk, Analyze, Plan and the content scan.
    $total = $t.wall_ms
    $content = $t.plan_ms + $t.content_ms
    $totals.Add($total); $contents.Add($t.content_ms)
    $seconds = [Math]::Max($t.content_ms, 1) / 1000.0
    Write-Host ("  run {0}: total {1} ms (scan {2}, analyze {3}, plan {4}, content {5}); {6} candidates, {7} opened, {8:N1} MB read; {9:N0} files/s, {10:N1} MB/s" -f `
        $i, $total, $t.scan_ms, $t.analyze_ms, $t.plan_ms, $t.content_ms, $t.candidates, $t.files_opened, ($t.bytes_read / 1MB),
        ($t.files_opened / $seconds), ($t.bytes_read / 1MB / $seconds))
    Write-Host ("         content part (plan_ms + content_ms) {0} ms; skipped: {1} binary, {2} UTF-16, {3} too large, {4} unreadable" -f `
        $content, $t.skipped_binary, $t.skipped_utf16, $t.skipped_large, $t.skipped_unreadable)
    if ($total -gt $BudgetMs) { Write-Host "  run $i is over the budget of $BudgetMs ms"; $ok = $false }
    if ($t.files_opened -ne $t.candidates) { Write-Host "  run ${i}: files_opened $($t.files_opened) differs from candidates $($t.candidates)"; $ok = $false }
}

Write-Host ("Total:      median {0} ms, max {1} ms (budget {2} ms)" -f (Median $totals.ToArray()), ($totals | Measure-Object -Maximum).Maximum, $BudgetMs)
Write-Host ("content_ms: median {0} ms, max {1} ms" -f (Median $contents.ToArray()), ($contents | Measure-Object -Maximum).Maximum)
if ($ok) { Write-Host 'Within budget.'; exit 0 }
Write-Host 'Over budget, or the open counter disagrees.'
exit 1

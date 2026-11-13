# Writes the Protect fixture tree: the relative cases of tests\protect-corpus\by-name\cases.tsv as real files
# under a pretend user folder, so the app can be scanned and screenshotted without a real profile.
#
#   powershell -ExecutionPolicy Bypass -File tests\make-protect-tree.ps1 -Out %TEMP%\dsa-protect-tree
#   bin\DiskSpaceAnalyzer.exe %TEMP%\dsa-protect-tree --protect-home %TEMP%\dsa-protect-tree --snapshot out.png --page protect
#
# Each file has the size its case gives (4096 bytes by default) and holds only the text "not a secret "
# repeated. Nothing in the tree is a key or any other credential format. Cases with a drive letter are left
# out, and so are "#! online" cases, because a cloud placeholder cannot be made by hand. Each "#! repo"
# folder gets an empty .git folder. The output folder must be inside %TEMP% or the repository's obj folder.

param([string]$Out = (Join-Path $env:TEMP 'dsa-protect-tree'),
      [string]$Corpus = (Join-Path $PSScriptRoot 'protect-corpus\by-name\cases.tsv'))

$ErrorActionPreference = 'Stop'
$home0 = 'C:\Users\pat'
$markerName = '.dsa-protect-tree'

function Test-Under([string]$path, [string]$folder) {
    $f = [IO.Path]::GetFullPath($folder).TrimEnd('\') + '\'
    return $path.StartsWith($f, [StringComparison]::OrdinalIgnoreCase)
}

$Out = [IO.Path]::GetFullPath($Out).TrimEnd('\')
$repoObj = Join-Path (Split-Path $PSScriptRoot -Parent) 'obj'
if (-not ((Test-Under $Out $env:TEMP) -or (Test-Under $Out $repoObj))) {
    throw "The fixture tree is written only inside %TEMP% or $repoObj, not $Out."
}
if ([IO.Directory]::Exists($Out)) {
    $entries = @([IO.Directory]::EnumerateFileSystemEntries($Out))
    if ($entries.Count -gt 0) {
        if (-not [IO.File]::Exists((Join-Path $Out $markerName))) {
            throw "$Out exists and is not a fixture tree written by this script; choose another folder."
        }
        Remove-Item -LiteralPath $Out -Recurse -Force
    }
}
[IO.Directory]::CreateDirectory($Out) | Out-Null
[IO.File]::WriteAllText((Join-Path $Out $markerName), "Written by tests\make-protect-tree.ps1. Safe to delete.`n")

$fillText = [Text.Encoding]::ASCII.GetBytes('not a secret ')
$filler = $null

function Ensure-Filler([long]$size) {
    if ($null -eq $script:filler -or $script:filler.Length -lt $size) {
        $n = [Math]::Max([long]65536, $size)
        $repeats = [int][Math]::Ceiling($n / $fillText.Length)
        $script:filler = [Text.Encoding]::ASCII.GetBytes('not a secret ' * $repeats)
    }
}

function Write-Filler([string]$path, [long]$size) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
    Ensure-Filler $size
    $buf = $script:filler
    $fs = [IO.File]::Create($path)
    try { if ($size -gt 0) { $fs.Write($buf, 0, [int]$size) } } finally { $fs.Close() }
}

function Local-Path([string]$windowsPath) {
    if ($windowsPath -eq $home0) { return $Out }
    if (-not $windowsPath.StartsWith($home0 + '\', [StringComparison]::OrdinalIgnoreCase)) { return $null }
    return $Out + $windowsPath.Substring($home0.Length)
}

$files = 0; $folders = 0; $skipped = 0; $repos = 0
$size = 4096; $online = $false; $siblings = @()
$written = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$pendingSiblings = New-Object 'System.Collections.Generic.List[string]'

foreach ($line in [IO.File]::ReadAllLines($Corpus)) {
    if ($line.Length -eq 0) { continue }
    if ($line.StartsWith('#!')) {
        $rest = $line.Substring(2).Trim()
        $cut = $rest.IndexOf(' ')
        $word = if ($cut -lt 0) { $rest } else { $rest.Substring(0, $cut) }
        $arg = if ($cut -lt 0) { '' } else { $rest.Substring($cut + 1).Trim() }
        switch ($word) {
            'size' { $size = [long]$arg }
            'online' { $online = $true }
            'siblings' { $siblings = @($arg.Split(',') | Where-Object { $_ -ne '' }) }
            'home' { if ($arg -ne $home0) { throw "The corpus home is $arg; this script expects $home0." } }
            'repo' {
                $local = Local-Path $arg
                if ($local -ne $null) { [IO.Directory]::CreateDirectory((Join-Path $local '.git')) | Out-Null; $repos++ }
            }
        }
        continue
    }
    if ($line.StartsWith('#')) { continue }
    $cols = $line.Split("`t")
    $path = $cols[0]
    $caseSize = $size; $caseOnline = $online; $caseSiblings = $siblings
    $size = 4096; $online = $false; $siblings = @()
    if ($path -match '^[A-Za-z]:/') { $skipped++; continue }
    if ($caseOnline) { $skipped++; continue }
    $local = Join-Path $Out ($path.TrimEnd('/').Replace('/', '\'))
    if ($path.EndsWith('/')) {
        [IO.Directory]::CreateDirectory($local) | Out-Null
        $folders++
        continue
    }
    Write-Filler $local $caseSize
    $written.Add($local) | Out-Null
    $files++
    foreach ($s in $caseSiblings) { $pendingSiblings.Add((Join-Path ([IO.Path]::GetDirectoryName($local)) $s)) }
}

# Siblings named by "#! siblings" that are not cases of their own (deploy_github.pub, for one).
foreach ($s in $pendingSiblings) {
    if ($written.Contains($s)) { continue }
    Write-Filler $s 4096
    $written.Add($s) | Out-Null
    $files++
}

Write-Host ("Wrote {0} files, {1} folder cases and {2} .git folders to {3} ({4} cases with a drive letter or online-only left out)." -f $files, $folders, $repos, $Out, $skipped)

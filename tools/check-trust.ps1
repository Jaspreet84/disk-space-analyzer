# The trust checks behind the Protect page. build.ps1 runs this after every build, and anyone can run it on
# the finished programs:
#
#   powershell -ExecutionPolicy Bypass -File tools\check-trust.ps1 [path\to\program.exe ...]
#
# 1. No network code: the compiled programs name no System.Net type and reference no System.Net assembly.
# 2. Protect is read-only: the Protect source files contain no call that writes, deletes or moves a file,
#    except the two marked "// trust:" lines in Protect.cs that save protect.json.
# 3. Protect reads file contents in one audited place only: the marked region in SecretScan.cs (the opt-in
#    content scan, one read-only open call), plus the one marked "// trust-read:" line in Protect.cs that loads
#    protect.json. Nothing else in Protect reads a file.
# 4. Content never becomes text or a copy: SecretScan.cs has no string conversion, copy, log or hash call.
# 5. A content finding is built in one place: "new Finding(" appears exactly once in SecretScan.cs.
# 6. Only the command line can give consent without the switch: FromCommandLine appears only in Cli.cs and
#    SecretScan.cs.
# 7. SecretScan.cs reaches no other part of the app: of the types declared outside Protect, it may name only
#    the scan tree types, Finding, its tier and place, and Scanner.LongPath.
# It throws on the first failure, which fails the build. Every failure names the file and, where there is
# one, the line.

param([string[]]$Programs, [string]$Root)

$ErrorActionPreference = 'Stop'
$root = if ($Root) { $Root } else { Split-Path $PSScriptRoot -Parent }  # -Root: another source tree to check (used by the tests)
$obj = Join-Path (Split-Path $PSScriptRoot -Parent) 'obj'
New-Item -ItemType Directory -Force $obj | Out-Null

# Set to $true only if the per-handle low I/O hint fallback (spec section 3.1) is adopted; see check 3 (d).
$ioHintFallback = $false

function Fail([int]$check, [string]$message) { throw "Trust check $check failed: $message" }

$srcDir = Join-Path $root 'src'
$allSources = @(Get-ChildItem $srcDir -Recurse -File -Filter *.cs)
$protectNames = '^(Protect.*|SecretScan|GitStatus|MainWindow\.Protect)\.cs$'
$files = @($allSources | Where-Object { $_.Name -match $protectNames })
$scan = @($files | Where-Object { $_.Name -eq 'SecretScan.cs' })
if ($scan.Count -ne 1) { Fail 3 "src\SecretScan.cs is missing (or there is more than one); the content scan must live in exactly one file." }
$scan = $scan[0]
$scanLines = @(Get-Content $scan.FullName)
$scanText = [IO.File]::ReadAllText($scan.FullName)

# ---------------------------------------------------------------------------------------------------------------
# Check 1. Guarantees: neither program can make a network connection, because neither names a System.Net type
# or references a System.Net assembly. CheckTrust.cs reads the compiled metadata, so it sees what the C# code
# cannot hide.
# ---------------------------------------------------------------------------------------------------------------
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
if ($LASTEXITCODE -ne 0) { Fail 1 'a program names a System.Net type.' }

# ---------------------------------------------------------------------------------------------------------------
# Check 2. Guarantees: Protect never writes, deletes or moves a file. The only exceptions are the two lines in
# Protect.cs marked "// trust:", which save protect.json. The match has no word boundary on purpose, so
# "profile.Open(" counts too.
# ---------------------------------------------------------------------------------------------------------------
Write-Host 'Trust check 2: Protect never writes a file'
$forbidden = 'File\.(Write|Delete|Move|Copy|Create|Open\(|Append|Replace|SetAttributes)|Directory\.(Delete|Move|CreateDirectory)|' +
             'new FileStream\(|StreamWriter|FileMode\.|FileAccess\.(Write|ReadWrite)|SHFileOperation|MoveToRecycleBin|CopyFileEx'
$markers = 0
foreach ($f in $files) {
    $n = 0
    foreach ($line in Get-Content $f.FullName) {
        $n++
        if ($line -notmatch $forbidden) { continue }
        if ($line -match '// trust:') {
            if ($f.Name -ne 'Protect.cs') { Fail 2 "a '// trust:' marker outside Protect.cs ($($f.Name):$n)." }
            $markers++
            continue
        }
        Fail 2 "$($f.Name):$n writes, deletes or moves a file: $($line.Trim())"
    }
}
if ($markers -gt 2) { Fail 2 "Protect.cs has $markers marked write lines; only the two that save protect.json are allowed." }
Write-Host ("  {0} Protect source file(s), {1} marked write line(s) in Protect.cs, no others" -f $files.Count, $markers)

# ---------------------------------------------------------------------------------------------------------------
# Check 3. Guarantees: the only code in Protect that reads a file's contents is (1) the one marked region in
# SecretScan.cs, which holds every P/Invoke of that file, exactly one read-only open call (GENERIC_READ,
# OPEN_EXISTING) and at most two read calls, and (2) the one "// trust-read:" line in Protect.cs that loads
# protect.json. No other file may name the reader.
# ---------------------------------------------------------------------------------------------------------------
Write-Host 'Trust check 3: Protect reads file contents only in its one audited place'
# Also the indirect ways .NET or Win32 open a file for its contents: line readers, images, XML documents,
# memory maps, raw reads.
$reads = 'ReadAll|ReadLines|OpenRead|OpenText|StreamReader|BinaryReader|File\.Open|Transfer\.|\.Verify\(|' +
         'FromFile\(|FromStream\(|BitmapImage|BitmapDecoder|UriSource|XDocument\.Load|XElement\.Load|XmlDocument|XmlReader|' +
         'MemoryMapped|ReadFile\(|CreateFileW?\(|ReadFileEx|ReadFileScatter|GetFileSizeEx|MapViewOfFile|NtReadFile|' +
         'DeviceIoControl|_lread|FILE_FLAG_BACKUP'
$allowedInRegion = 'ReadFile\(|CreateFileW\(|GetFileSizeEx'  # removed from a region line before $reads is tested
$readMarkers = 0; $regions = 0; $opens = 0; $readCalls = 0; $readDecls = 0
foreach ($f in $files) {
    $isScan = $f.Name -eq 'SecretScan.cs'
    $inside = $false
    $n = 0
    foreach ($line in Get-Content $f.FullName) {
        $n++
        $where = "$($f.Name):$n"
        if ($line -match 'trust-read-begin') {
            if (-not $isScan) { Fail 3 "a trust-read-begin marker outside SecretScan.cs ($where)." }
            if ($inside) { Fail 3 "a trust-read-begin marker inside the region ($where)." }
            if ($line.Trim() -cne '// trust-read-begin: content') { Fail 3 "the begin marker must read exactly '// trust-read-begin: content' ($where)." }
            $regions++; $inside = $true; continue
        }
        if ($line -match 'trust-read-end') {
            if (-not $inside) { Fail 3 "a trust-read-end marker with no open region ($where)." }
            if ($line.Trim() -cne '// trust-read-end') { Fail 3 "the end marker must read exactly '// trust-read-end' ($where)." }
            $inside = $false; continue
        }
        if ($inside) {
            if ($line -match 'CreateFileW\(' -and $line -notmatch 'extern') {
                $opens++
                if ($line -notmatch 'GENERIC_READ' -or $line -notmatch 'OPEN_EXISTING') { Fail 3 "the open call must use GENERIC_READ and OPEN_EXISTING ($where)." }
            }
            if ($line -match 'ReadFile\(') { if ($line -match 'extern') { $readDecls++ } else { $readCalls++ } }
            if (($line -replace $allowedInRegion, '') -match $reads) { Fail 3 "$where reads a file's contents another way: $($line.Trim())" }
            continue
        }
        if ($isScan) {
            # Also the fully qualified attribute, and the extern method it decorates.
            if ($line -match '\[\s*(?:[\w.]*\.)?DllImport|\bstatic\s+extern\b|\bextern\s+static\b') { Fail 3 "$where declares a P/Invoke outside the marked region: $($line.Trim())" }
            if ($line -match '// trust-read:') { Fail 3 "a '// trust-read:' marker in SecretScan.cs ($where); its one read path is the marked region." }
            if ($line -match $reads) { Fail 3 "$where reads a file's contents outside the marked region: $($line.Trim())" }
            continue
        }
        if ($line -notmatch $reads) { continue }
        if ($line -match '// trust-read:') {
            if ($f.Name -ne 'Protect.cs') { Fail 3 "a '// trust-read:' marker outside Protect.cs ($where)." }
            $readMarkers++
            continue
        }
        Fail 3 "$where reads a file's contents: $($line.Trim())"
    }
    if ($inside) { Fail 3 "$($f.Name) has a trust-read-begin marker with no trust-read-end." }
}
if ($readMarkers -gt 1) { Fail 3 "Protect.cs has $readMarkers marked read lines; only the one that loads protect.json is allowed." }
# (a) one region, one open call, one ReadFile declaration, at most two ReadFile calls (the probe and the rest).
if ($regions -ne 1 -or $opens -ne 1 -or $readDecls -ne 1 -or $readCalls -gt 2) {
    Fail 3 "SecretScan.cs must have 1 marked region, 1 open call, 1 ReadFile declaration and at most 2 ReadFile calls; it has $regions, $opens, $readDecls and $readCalls."
}
# (a2) the names on the open call stand for the read-only values. Each constant is defined once, with its
# exact value, and the call passes exactly these names, so redefining one (say GENERIC_READ = 3u << 30, which
# adds write access, or OPEN_EXISTING = 4, which creates a missing file) fails here.
$pinned = @(
    @{ Name = 'GENERIC_READ';                 Def = 'const\s+uint\s+GENERIC_READ\s*=\s*0x80000000\s*;' },
    @{ Name = 'FILE_SHARE_READ';              Def = 'const\s+uint\s+FILE_SHARE_READ\s*=\s*1\s*,\s*FILE_SHARE_WRITE\s*=\s*2\s*,\s*FILE_SHARE_DELETE\s*=\s*4\s*;' },
    @{ Name = 'FILE_SHARE_WRITE';             Def = $null },
    @{ Name = 'FILE_SHARE_DELETE';            Def = $null },
    @{ Name = 'OPEN_EXISTING';                Def = 'const\s+uint\s+OPEN_EXISTING\s*=\s*3\s*;' },
    @{ Name = 'FILE_FLAG_SEQUENTIAL_SCAN';    Def = 'const\s+uint\s+FILE_FLAG_SEQUENTIAL_SCAN\s*=\s*0x08000000\s*,\s*FILE_FLAG_OPEN_NO_RECALL\s*=\s*0x00100000\s*,\s*FILE_FLAG_OPEN_REPARSE_POINT\s*=\s*0x00200000\s*;' },
    @{ Name = 'FILE_FLAG_OPEN_NO_RECALL';     Def = $null },
    @{ Name = 'FILE_FLAG_OPEN_REPARSE_POINT'; Def = $null }
)
foreach ($c in $pinned) {
    $assigned = ([regex]::Matches($scanText, '\b' + $c.Name + '\s*=(?!=)')).Count
    if ($assigned -ne 1) { Fail 3 "SecretScan.cs must give $($c.Name) a value exactly once; it does so $assigned times." }
    if ($c.Def -ne $null -and ([regex]::Matches($scanText, $c.Def)).Count -ne 1) { Fail 3 "SecretScan.cs must define $($c.Name) with its read-only value, as in: $($c.Def -replace '\\s[*+]', ' ' -replace '\\', '')" }
}
$openCall = 'CreateFileW\(\s*longPath\s*,\s*GENERIC_READ\s*,\s*FILE_SHARE_READ\s*\|\s*FILE_SHARE_WRITE\s*\|\s*FILE_SHARE_DELETE\s*,\s*IntPtr\.Zero\s*,\s*OPEN_EXISTING\s*,\s*' +
            'FILE_FLAG_SEQUENTIAL_SCAN\s*\|\s*FILE_FLAG_OPEN_NO_RECALL\s*\|\s*FILE_FLAG_OPEN_REPARSE_POINT\s*,\s*IntPtr\.Zero\s*\)'
if (([regex]::Matches($scanText, $openCall)).Count -ne 1) {
    Fail 3 'the open call must pass exactly GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING and the three allowed flags.'
}
# (b) the trust-read marker in SecretScan.cs is caught in the loop above.
# (c) nothing in SecretScan.cs asks for write, delete or execute access, or uses unsafe code.
$writeWords = 'GENERIC_WRITE|GENERIC_ALL|GENERIC_EXECUTE|0x40000000|0xC0000000|0x10000000|0x20000000|WriteFile|DeleteFile|' +
              'MoveFile|CopyFile|SetEndOfFile|SetFileTime|CREATE_ALWAYS|CREATE_NEW|OPEN_ALWAYS|TRUNCATE_EXISTING|' +
              'DELETE_ON_CLOSE|FILE_WRITE_|FILE_APPEND|0x02000000|0x04000000|unsafe|stackalloc'
for ($i = 0; $i -lt $scanLines.Count; $i++) {
    if ($scanLines[$i] -match $writeWords) { Fail 3 "SecretScan.cs:$($i + 1) names write access or unsafe code ($($matches[0]))." }
}
# (d) SetFileInformationByHandle only as the adopted low I/O hint fallback.
$hintLines = @(Select-String -Path $scan.FullName -Pattern 'SetFileInformationByHandle')
if ($hintLines.Count -gt 0 -and -not $ioHintFallback) { Fail 3 "SecretScan.cs:$($hintLines[0].LineNumber) calls SetFileInformationByHandle, and the I/O hint fallback is not adopted." }
if ($ioHintFallback) {
    $region = $false; $declared = 0; $called = 0
    for ($i = 0; $i -lt $scanLines.Count; $i++) {
        $l = $scanLines[$i]
        if ($l.Trim() -eq '// trust-read-begin: content') { $region = $true; continue }
        if ($l.Trim() -eq '// trust-read-end') { $region = $false; continue }
        if ($l -notmatch 'SetFileInformationByHandle') { continue }
        if (-not $region) { Fail 3 "SecretScan.cs:$($i + 1) calls SetFileInformationByHandle outside the marked region." }
        if ($l -match 'extern') { $declared++ } elseif ($l -match 'FileIoPriorityHintInfo') { $called++ }
        else { Fail 3 "SecretScan.cs:$($i + 1) calls SetFileInformationByHandle for something other than FileIoPriorityHintInfo." }
    }
    $constants = ([regex]::Matches($scanText, 'FileIoPriorityHintInfo\s*=\s*12')).Count
    if ($declared -gt 1 -or $called -ne 1 -or $constants -ne 1) { Fail 3 'SecretScan.cs must call SetFileInformationByHandle once, with FileIoPriorityHintInfo = 12 defined once.' }
}
# (e) only SecretScan.cs may name the reader.
foreach ($f in $allSources) {
    if ($f.Name -eq 'SecretScan.cs') { continue }
    $hit = @(Select-String -Path $f.FullName -Pattern 'ContentReader')
    if ($hit.Count -gt 0) { Fail 3 "$($f.Name):$($hit[0].LineNumber) names ContentReader, which only SecretScan.cs may use." }
}
Write-Host ("  content read: {0} marked region in SecretScan.cs ({1} open call, read-only); protect.json read: {2} marked line in Protect.cs; no others" -f $regions, $opens, $readMarkers)

# ---------------------------------------------------------------------------------------------------------------
# Check 4. Guarantees: bytes read by the content scan never become a string, a copy, a log line or a hash, and
# each reader has exactly one buffer. Case-insensitive, comments included.
# ---------------------------------------------------------------------------------------------------------------
Write-Host 'Trust check 4: content never becomes text or a copy'
$textWords = 'GetString|GetChars|GetDecoder|Encoding|new string\(|PtrToString|StringBuilder|Regex|' +
             '\.ToString\(|string\.Concat|string\.Format|String\.Format|ToCharArray|Convert\.To|' +
             'Array\.Copy|Buffer\.BlockCopy|BlockCopy|\.Clone\(|\.CopyTo\(|ToArray\(|ToList\(|' +
             'Marshal\.Copy|Console\.|Debug\.|Trace\.|File\.|Directory\.|LargeObjectHeapCompactionMode|' +
             'SHA1|SHA256|SHA384|SHA512|MD5|HashAlgorithm|Cryptography'
for ($i = 0; $i -lt $scanLines.Count; $i++) {
    if ($scanLines[$i] -match $textWords) { Fail 4 "SecretScan.cs:$($i + 1) could turn content into text or a copy ($($matches[0]))." }
}
$buffers = ([regex]::Matches($scanText, 'new byte\[', 'IgnoreCase')).Count
if ($buffers -ne 1) { Fail 4 "SecretScan.cs must allocate its buffer with exactly one 'new byte['; it has $buffers." }
Write-Host '  SecretScan.cs: no string conversion, copy, log or hash; one buffer allocation'

# ---------------------------------------------------------------------------------------------------------------
# Check 5. Guarantees: there is one place where a content finding is made, so review of that one line shows
# that a finding holds only the pattern, path, line, column and place.
# ---------------------------------------------------------------------------------------------------------------
Write-Host 'Trust check 5: one place builds a content finding'
$builds = ([regex]::Matches($scanText, 'new Finding\(')).Count
if ($builds -ne 1) { Fail 5 "SecretScan.cs must build findings in exactly one 'new Finding('; it has $builds." }
Write-Host '  SecretScan.cs: 1 new Finding('

# ---------------------------------------------------------------------------------------------------------------
# Check 6. Guarantees: the app can start the content scan only from the stored switch. The command-line consent
# (passing --content) is named only in Cli.cs and in SecretScan.cs, which defines it.
# ---------------------------------------------------------------------------------------------------------------
Write-Host 'Trust check 6: only the command line gives consent without the switch'
foreach ($f in $allSources) {
    if ($f.Name -eq 'Cli.cs' -or $f.Name -eq 'SecretScan.cs') { continue }
    $hit = @(Select-String -Path $f.FullName -Pattern 'FromCommandLine')
    if ($hit.Count -gt 0) { Fail 6 "$($f.Name):$($hit[0].LineNumber) names FromCommandLine, which only Cli.cs may call." }
}
Write-Host '  FromCommandLine: only in Cli.cs and SecretScan.cs'

# ---------------------------------------------------------------------------------------------------------------
# Check 7. Guarantees: SecretScan.cs cannot hand content to code outside Protect. Of the types declared in the
# other src files, it may name only the allowed ones below, and Scanner only as Scanner.LongPath(. Comments and
# string literals are removed first; .NET types are not declared in src, so they are not affected.
# ---------------------------------------------------------------------------------------------------------------
Write-Host 'Trust check 7: SecretScan.cs uses only allowed app types'
$allowedTypes = @('Node', 'FileNode', 'DirNode', 'ScanResult', 'FileFlags', 'Place', 'Finding', 'FindingTier', 'Scanner')
$declared = New-Object 'System.Collections.Generic.HashSet[string]'
$declPattern = '(?m)^\s*(?:(?:public|internal|private|protected|static|sealed|abstract|partial)\s+)*(?:class|struct|enum|interface)\s+(\w+)'
foreach ($f in $allSources) {
    if ($f.Name -match $protectNames) { continue }
    $text = [IO.File]::ReadAllText($f.FullName)
    foreach ($m in [regex]::Matches($text, $declPattern)) { [void]$declared.Add($m.Groups[1].Value) }
    foreach ($m in [regex]::Matches($text, 'delegate\s+\S+\s+(\w+)\s*\(')) { [void]$declared.Add($m.Groups[1].Value) }
}
[void]$declared.Add('Scanner')  # its rule applies even when the tree checked has no Scanner.cs
# Comments and literals become blanks; newlines are kept so line numbers still match the file.
$literal = '@"(?:""|[^"])*"|"(?:\\.|[^"\\\n])*"|''(?:\\.|[^''\\\n])+''|//[^\n]*|/\*[\s\S]*?\*/'
$code = [regex]::Replace($scanText, $literal, { param($m) ' ' + ($m.Value -replace '[^\n]', '') })
foreach ($name in $declared) {
    foreach ($m in [regex]::Matches($code, '\b' + [regex]::Escape($name) + '\b')) {
        $lineNo = $code.Substring(0, $m.Index).Split("`n").Count
        if ($allowedTypes -cnotcontains $name) { Fail 7 "SecretScan.cs:$lineNo uses the app type $name, which is not on its allowlist." }
        if ($name -eq 'Scanner' -and -not $code.Substring($m.Index).StartsWith('Scanner.LongPath(')) {
            Fail 7 "SecretScan.cs:$lineNo uses Scanner for something other than Scanner.LongPath(."
        }
    }
}
Write-Host ("  SecretScan.cs: {0} app types checked; only the allowed ones are used" -f $declared.Count)
Write-Host 'Trust checks passed.'

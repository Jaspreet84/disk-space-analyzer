# Protect test corpus

The cases the Protect page's matchers are measured against. Every pattern in `ProtectConstants.Patterns` has at least one true case here, and most also have a false case aimed at their own guards. `tests\run-tests.ps1` checks every case on each run and prints precision per tier and recall.

Both files are tab-separated, one case per line, with `#` for comments. A case names what the matcher must do, not what a secret looks like: no case in this folder contains a real credential or a real person's data.

## `by-name/cases.tsv`

Findings by file name and location (Protect stage 1). No content is involved, so the "file" is only a path.

| Column | Meaning |
|---|---|
| `path` | A path relative to the pretend user folder `C:\Users\pat`, with `/` separators, for example `.ssh/id_rsa` or `Downloads/backup/.env`. A path that starts with a drive letter and `:/` (`D:/Downloads/W2-2024.pdf`) is absolute. A trailing `/` marks a folder case. |
| `expect` | The pattern id expected to match, or `none` |
| `tier` | `Confirmed`, `Likely`, `WorthALook`, or `-` when `expect` is `none` |
| `place` | The place the matcher must report, for example `HomeFolder` or `Downloads`, or `-` when `expect` is `none` |

Every non-comment line has exactly these four columns.

### Directives

Lines that start with `#!` are directives. They start with `#`, so a reader that only knows the four columns skips them.

Context directives apply from that line on. Each is followed by a Windows path, and each may repeat to add to its list:

| Directive | Sets |
|---|---|
| `#! home` | the user folder |
| `#! roaming`, `#! local` | AppData\Roaming and AppData\Local |
| `#! downloads`, `#! desktop`, `#! documents`, `#! pictures` | the known folders (known and legacy) |
| `#! temp` | a Temp folder |
| `#! sync` | a registered sync root |
| `#! external` | the root of an external drive |
| `#! repo` | a git repository root (the tree generator creates a `.git` folder in it) |

Case directives apply to the next case only:

| Directive | Meaning |
|---|---|
| `#! size N` | the file's size in bytes. The default is 4096. |
| `#! online` | the file is online-only (a cloud placeholder): it is checked with size 0 and the online-only flag |
| `#! siblings a,b` | the other names in the same folder |

A folder case (trailing `/`) is checked as a folder. A `Scanned Documents` folder case assumes it holds a qualifying document; the tree test covers the empty case.

### How the tests use it

1. **Corpus gate.** Every case goes through `ProtectNames.MatchPath` with the context from the header. Any difference in `expect`, `tier` or `place` fails the run.
2. **Tree equality.** The relative cases (no drive letter) are built into an in-memory folder tree under `C:\Users\pat`, with `.git` folders for each `#! repo`, and `ScanResult.Analyze()` must find exactly what `MatchPath` finds. `ProtectContext.ForTree(fakeHome)` must equal the header with `C:\Users\pat` replaced and the drive-letter entries dropped.
3. **Fixture tree on disk.** `tests\make-protect-tree.ps1 -Out <folder>` writes the relative cases as real files of the given sizes, filled with the text `not a secret ` repeated (never a key format). Online-only cases cannot be made on disk and are left out. The app's snapshot mode scans that folder with `--protect-home <folder>`, so screenshots never show a real profile.

## `by-content/cases.tsv`

Findings in file contents (stage 2, the opt-in content scan).

No file here holds a key in a valid format. Templates hold recipes; the tests build the real files in %TEMP%\dsa-content-<guid> at test time and delete them. This keeps the public repository clear of GitHub push protection and secret-scanning alerts, and keeps your own content scan from finding them later in Temp.

| Column | Meaning |
|---|---|
| `file` | The generated file, relative to the generated root, with `/` separators. It starts with `home/` (the pretend user folder) or `proj/` (a folder next to it). Its template is `files/<file>.tpl`. |
| `expect` | The content pattern id expected, or `none` |
| `tier` | `Confirmed` or `Likely`, or `-` when `expect` is `none` |
| `line` | `L:C`, the 1-based line and column of the match, or `-` when `expect` is `none` |

A file with several expected findings has one row per finding. A file whose rows are all `none` must give no finding at all. A line `# --- <pattern id>` starts the cases aimed at that pattern; the tests count each pattern's negatives by it.

### Directives

They apply to the next file only, and come before its first row.

| Directive | Meaning |
|---|---|
| `#! encoding utf16le`, `utf16be`, `utf8bom` | Write the file in that encoding, with its byte order mark. The default is UTF-8 without one. |
| `#! pad N` | Append the filler text `not a secret ` after the template until the file is N bytes. |
| `#! nul N` | Start the file with N bytes of filler and one zero byte at offset N; the template follows it. |
| `#! crlf`, `#! cr` | Write CR LF or CR line endings instead of LF. |

### Templates and recipes

A template is the file's text with each secret written as a recipe, `<<kind:variant:seed>>`, using only lower-case letters, digits and `:`. No template line matches any pattern, and the tests check that by running the app's matcher over every template. Templates use LF line endings. The expected column is the column of the recipe's `<<`; for a quoted .env value, the column after the quote.

`tests\ContentCorpus.cs` expands the recipes. It builds each body from a seeded `System.Random`, so each run gives the same files, and it computes the GitHub checksum with its own bitwise CRC32 and base62 code, separate from the app's. It assembles every vendor prefix and PEM label from split strings, so the file holds no match itself.

| Recipe | Gives |
|---|---|
| `gh:<ghp\|gho\|ghu\|ghs\|ghr>:<seed>` | a classic GitHub token with a valid checksum |
| `gh:badcrc:<seed>`, `gh:len35:<seed>`, `gh:len37:<seed>`, `gh:allx`, `gh:jwt:<seed>` | the right shape with the last checksum digit moved by one; 35 or 37 characters after the prefix; all `x`; a stateless installation token (`ghs_`, digits, `_`, a JWT) |
| `ghfg:ok:<seed>`, `ghfg:split2160:<seed>`, `ghfg:len92:<seed>`, `ghfg:allx` | a fine-grained token (22 + 59), the wrong split, one character short, all `x` |
| `aws:akia:<seed>`, `aws:asia:<seed>`, `aws:sample1`, `aws:sample2`, `aws:aida:<seed>`, `aws:digit:<seed>`, `aws:allx`, `aws:b64:<seed>` | access key ids; two ids ending in `EXAMPLE`; a user id; a 0, 1, 8 or 9 in the tail; all `X`; an id inside a base64 run |
| `slack:bot:<seed>`, `slack:user:<seed>`, `slack:app:<seed>`, `slack:zeros`, `slack:docs`, `slack:legacy:<seed>` | bot, user and app tokens; all-zero digit groups; the not-a-real-token shape; a legacy prefix |
| `hook:ok:<seed>`, `hook:zeros`, `hook:short:<seed>`, `hook:workflows:<seed>` | a webhook address; the docs form; a 23-character secret; a workflows address |
| `stripe:sklive:<n>:<seed>`, `stripe:rklive:<n>:<seed>`, `stripe:sktest:<seed>`, `stripe:pklive:<seed>`, `stripe:short:<seed>` | live secret and restricted keys with an n-character body; a test-mode key; a publishable key; a 23-character body |
| `google:ok:<seed>`, `google:sample:<i>`, `google:samples`, `google:len34:<seed>`, `google:alpha`, `google:alphasy`, `google:alphasylow` | an API key; entry i of the app's published sample list; every entry, one per line; 34 characters; a straight alphabet run; the same run after the usual leading `Sy`, in upper or lower case |
| `openai:proj:<58\|74>:<seed>`, `openai:svcacct:<seed>`, `openai:legacy:<seed>`, `openai:nomarker:<seed>`, `openai:half57:<seed>`, `openai:ant:<seed>` | project, service-account and legacy keys; no marker; 57 characters before the marker; another vendor's prefix |
| `pem:<pkcs8\|rsa\|ec\|dsa\|openssh\|pgp>:<seed>` | a private-key header, 20 lines of 64 random base64 characters (random bytes, not a key) and the END line |
| `pem:enc:<seed>`, `pem:procenc:<seed>`, `pem:json:<seed>` | an encrypted PKCS#8 block; an RSA block with a `Proc-Type: 4,ENCRYPTED` header; a block escaped with `\n` inside a JSON string |
| `pem:headeronly:<rsa\|pkcs8\|enc>`, `pem:public:<seed>`, `pem:cert:<seed>`, `pem:mismatch:<seed>`, `pem:short63:[enc:]<seed>`, `pem:noend:<seed>` | a header alone; a public key; a certificate; a different END label; 63 base64 characters; no END line |
| `rand:<uuid\|sha1\|sha256\|md5\|b64\|jwt>:<seed>` | random look-alikes that are no key |
| `env:mixed:<len>:<seed>` | a .env value of that length mixing upper and lower case, digits and `-` |

### How the tests use it

`tests\ProtectTests.cs` builds the files under %TEMP%\dsa-content-<guid>, runs the matcher over each file's bytes, then scans the folder end to end (scan, Analyze with the pretend user folder, Plan and the content scan) and compares the set of file, pattern, tier and `L:C` with this file. It prints precision and recall per pattern and per tier. The run fails below 95% precision for Confirmed or 80% for Likely, or when any `L:C` differs; the target is 100%. The folder is deleted afterwards, and any stale `dsa-content-*` folder is deleted when the tests start.

`tests\make-protect-tree.ps1 -Content` writes the same files on top of the by-name fixture tree, for screenshots: `home/` goes to the pretend user folder and `proj/` to its `code\app` repository. That tree holds format-valid test values, so delete it after use.

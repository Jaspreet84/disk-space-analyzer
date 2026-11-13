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

Findings in file contents (stage 2). Each case points at a file under `by-content/files/`.

| Column | Meaning |
|---|---|
| `file` | The file under `files/` to scan |
| `expect` | The pattern id expected to match, or `none` |
| `tier` | The tier expected, or `-` |
| `line` | The 1-based line the match must be reported on, or `-` |

Content files hold only values that are published as examples by their vendors (such as AWS's documentation key) or values built for the test with a valid format and no live meaning. A negative case is as useful as a positive one: a UUID, a hash and a long base64 string each belong here with `expect` set to `none`.

# Protect test corpus

The cases the Protect page's matchers are measured against. Every pattern added to `ProtectConstants.Patterns` gets at least one true case and one false case here, and the tests report precision per tier on each build. Stage 0 ships the format; the cases arrive with the matchers.

Both files are tab-separated, one case per line, with `#` for comments. A case names what the matcher must do, not what a secret looks like: no case in this folder contains a real credential.

## `by-name/cases.tsv`

Findings by file name and location. No content is involved, so the "file" is only a path.

| Column | Meaning |
|---|---|
| `path` | A path as it would appear on a PC, relative to a pretend user folder, for example `.ssh/id_rsa` or `Downloads/backup/.env` |
| `expect` | The pattern id expected to match, or `none` |
| `tier` | `Confirmed`, `Likely`, `WorthALook`, or `-` when `expect` is `none` |
| `place` | The place the matcher must report, for example `HomeFolder` or `Downloads` |

## `by-content/cases.tsv`

Findings in file contents. Each case points at a file under `by-content/files/`.

| Column | Meaning |
|---|---|
| `file` | The file under `files/` to scan |
| `expect` | The pattern id expected to match, or `none` |
| `tier` | The tier expected, or `-` |
| `line` | The 1-based line the match must be reported on, or `-` |

Content files hold only values that are published as examples by their vendors (such as AWS's documentation key) or values built for the test with a valid format and no live meaning. A negative case is as useful as a positive one: a UUID, a hash and a long base64 string each belong here with `expect` set to `none`.

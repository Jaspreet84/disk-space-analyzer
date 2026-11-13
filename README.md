# Disk Space Analyzer

A Windows tool that shows what is using space on a drive or in a folder, and helps you get it back. It uses the Windows 11 (Fluent) look, with light and dark themes. It is a single `.exe` with no installer and no dependencies. It uses the .NET Framework 4.8 that comes with Windows 10 and 11.

**[See the product page](https://jaspreet84.github.io/disk-space-analyzer/)** for a tour of what it does. Its source is `docs/index.html`, published with GitHub Pages.

There are two programs:

- `bin\DiskSpaceAnalyzer.exe`: the app.
- `bin\dsa.exe`: a command-line version that prints a text report.

## Using the app

Start `bin\DiskSpaceAnalyzer.exe`. The navigation pane on the left has a page for each task:

- **Home.** Your drives as cards, each with a meter showing how full it is. Click a drive to scan it, or pick a folder: Downloads, Documents and other common folders, or **Choose a folder…** for any other. A whole drive with about 700,000 files takes under a minute. You can also pass a path when starting the app: `DiskSpaceAnalyzer.exe D:\Projects`.
- **Overview.** The headline numbers: space used and free, files and folders. Below them:
  - a bar showing how much space each kind of file uses (video, images, archives and disk images, programs, and so on)
  - the largest folders
  - the top clean-up suggestions

  **Rescan** and **Export CSV** are at the top. Export CSV saves every folder with its size for Excel.
- **Explore.** The folder you are in, as a list and as a treemap that stay in sync. In the treemap, folders are labelled panels and files are tiles colored by kind. Hover a tile for details. Click to select it, and double-click to open a folder. Use the breadcrumb, **Back** (Alt+Left) or **Up** (Backspace) to move around. The color key under the treemap shows space by kind for this folder; click an entry to highlight those files.
- **Largest files.** The 1,000 largest files, with filters by kind and a search box (Ctrl+F). Double-click a file to see it in Explore.
- **Clean up.** Suggestions based on your scan, largest first, each with a plain explanation and an action. They cover:
  - WSL and Docker disks
  - virtual machine disks
  - installer disk images such as ISOs
  - old installers and archives in Downloads
  - large downloads you haven't touched in six months
  - developer caches (npm, pip, NuGet, Gradle, Cargo and others)
  - temporary files
  - the Recycle Bin
  - a previous Windows installation
  - space the scan couldn't see

  Expand a suggestion to see its files. It also has shortcuts to Windows' Disk Cleanup and storage settings.
- **Virtual disks.** Clean up and shrink WSL and Docker disk files (see below).

When something is selected in Explore or Largest files, a bar at the bottom offers **Open**, **Show in Explorer**, **Copy path**, **Rescan** (folders), **Shrink** (disk files) and **Delete**. Right-clicking gives the same actions plus **Properties**. Delete moves the item to the Recycle Bin after you confirm. Windows warns you if an item is too big for the Recycle Bin, and the space is only freed once you empty it.

**Theme** (bottom left) switches between following Windows, light and dark. **Run as administrator** restarts the app with rights to look inside protected system folders. F5 rescans.

## Virtual disks (WSL and Docker)

WSL keeps each Linux distribution in a single virtual disk file (`ext4.vhdx`), and Docker Desktop does the same for its images and containers (`docker_data.vhdx`). These files grow when Linux needs space but never shrink when files are deleted, so they often hold many gigabytes of free space.

The **Virtual disks** page shows a card for each disk with its file size, the space actually in use inside Linux, and roughly how much could be freed.

- **Clean caches…** clears caches inside a WSL distribution:
  - pnpm packages that no project uses any more
  - the npm, yarn and pip download caches
  - the Go module and build caches
  - apt package downloads

  Each tool is only used if it is installed, and your projects keep working.
- **Clean up Docker…** (on Docker's card) runs `docker system prune`, which removes:
  - stopped containers
  - networks that no container uses
  - dangling images
  - the build cache

  You can also remove every image that no container uses (on by default; images download again when needed). You can separately remove unused volumes (off by default, because volumes hold data such as databases, and you are asked again to confirm). If Docker Desktop is not running, it is started first. The activity log shows `docker system df` before and after.
- **Shrink…** gives free space back to Windows. It does three things:
  1. Marks the free space inside Linux.
  2. Shuts down WSL. This closes Linux terminals and stops Docker Desktop.
  3. Compacts the disk file with Windows' `diskpart` tool.

  Windows asks for administrator rights for the last step. Afterwards the app rescans the folder so the treemap shows the smaller file.

`shrink-wsl-disk.ps1` does the same shrink from a terminal, without the app:

```
powershell -ExecutionPolicy Bypass -File shrink-wsl-disk.ps1 -Distro Ubuntu
```

## Move to other drives

The **Move** page suggests large items that would be better kept on another drive. It bases each suggestion on what the item is, when it last changed, and the drives this PC has. It shows each drive with its role:

| Drive | Treated as | Good for |
|---|---|---|
| The drive Windows is on | System drive | Windows, apps and work in progress |
| Another internal drive | Storage | Data that should always be available |
| A USB or other external drive | External | Backups, archives and things you rarely open |

It knows whether each drive is an SSD or a hard drive, and suggests:

- **Backups and photo or video collections**, found by folder name or by being mostly media.
  - On the system drive, they move to internal storage.
  - On internal storage, they are **copied** to an external drive, so there are two copies on two drives.
- **Installer images and old installers or archives** (unchanged for 3 months) move to external storage. They can be downloaded again.
- **Large personal folders** (Downloads, Videos and others) move to internal storage. The app explains how to use Windows' own Location tab, which keeps the folder in File Explorer.
- **WSL, Docker and virtual machine disks** move only to an internal NTFS drive, never a USB one, because they stop working when it is unplugged.
  - WSL distributions move with one click (`wsl --manage --move`). On a hard drive you are warned that Linux will be slower.
  - Docker and VirtualBox have their own move options, and the app explains them.

Nothing is suggested if the target would drop below 10% free.

**Copy** and **Move** copy the item, then compare every file with the original byte for byte. They read straight from the disk, so a fresh copy is checked as it is on the disk, not as it sits in memory.

- **A move** sends the original to the Recycle Bin only after every file matches.
- **Interruptions are safe.** A copy can be cancelled, and starting it again skips files that are already done.
- **Damaged files are repaired.** If any file doesn't match, **Copy them again** replaces just those files and checks them again.
- **Existing copies are recognized.** If an identical copy is already on the target drive, the item shows as already copied, with **Check the copy** to confirm it.

## Protect, and the trust checks

The Protect page shows which files would hurt if they leaked and which would hurt if a drive died. A normal scan works from file names, folders, sizes and dates only: it does not open your files. It reads small text files only if you turn on the content scan.

- **Keys and sign-ins.** It finds about 30 kinds of credential file by name and place: SSH and PuTTY keys, private key files, `.pfx` certificates, password vaults and exported passwords, cloud and developer tool sign-ins (AWS, Azure, Google Cloud, GitHub CLI, Kubernetes, Docker, npm, PyPI, .NET user secrets, Terraform), `.env` files, crypto wallets and recovery codes. A file where its tool keeps it is listed in a collapsed "In their usual places" group and not counted. A copy in Downloads, on the Desktop, in a synced folder or on an external drive is listed for review.
- **Keys inside text files (off until you turn it on).** The switch "Look inside text files for keys" reads text files of 1 MB or less and looks for 11 kinds of key that have a fixed format: GitHub tokens (their checksum must verify), GitHub fine-grained tokens, AWS access key IDs, Slack tokens and webhook addresses, Stripe live secret keys, Google API keys, OpenAI keys, private key blocks (with or without a passphrase), and settings named like a secret in `.env` files. A match is shown as a file and a line number. The key itself is never shown, copied or saved, and nothing read is kept after the scan.
  - Before it starts, a dialog says how many files it will read and which folders it never opens: package and build folders, test and example folders, most of AppData, editor extension folders, your trusted folders, and others. Online-only files are not opened, so nothing is downloaded. When you scan a network drive or a shared folder on another computer, no file contents are read at all, so nothing is copied over the network.
  - Files are opened read-only and shared for reading, writing and deleting, so no other program is blocked. Four files are read at a time, at low priority. Windows may update a file's last-access time.
  - It does not guess from random-looking text, and published sample keys are never reported. Binary files, UTF-16 files and files over 1 MB are not read. The page's "What Protect does not look for" list names what it leaves out.
  - The switch is remembered. Once it is on, text files are read again after each scan, and after you recycle or rescan something only that folder is read again. Turning it off clears its findings.
  - While it runs you can keep using the app. Cancel stops it and keeps what it found so far. A folder you trust while it runs is left out straight away.
- **Personal documents.** Tax forms, bank statements, payslips and ID documents, matched by name with guards against look-alikes (a camera photo named `t4-...jpg` is not a tax slip).
- **Copies of your folders.** For Documents, Pictures, large photo and backup folders, and folders holding personal documents, it checks whether a copy with the same files and sizes exists on another connected drive. A synced cloud folder is shown as synced, never counted as a copy. Folders with one copy get a "Copy to…" button that uses the Move page's checked copy.
- **Hide and trust.** Hide a finding or trust a folder; both can be undone, and only a hash of each is kept. Hiding a key found in a file hides that kind of key in that file; a new kind of key in the same file still shows. Trusted folders are never read by the content scan.
- **Not yet:** git status for files inside projects (stage 3). `.env` files in projects are listed separately and not counted until then, unless the content scan finds a key with a known format in one.

`dsa <path> --protect [--all] [--coverage]` prints the same findings in a terminal. Add `--content` to read text files as well, and `--findings` to print why each match was reported. Each match is printed as `line 12:5`, the kind of key, its tier, its place and the path; the key is never printed. The command line reads file contents only when `--content` is passed: the app's saved switch does not turn it on there. Press Ctrl+C to stop; the matches found so far are printed.

The rules the page is built on are enforced by the build:

- **No network code.** The app contains none; it is not switched off, it is absent. The build fails if either program names a `System.Net` type or references a `System.Net` assembly.
- **Protect never writes a file.** The Protect source files may not call anything that writes, deletes or moves, except the two marked lines that save its own settings file. The build checks this too.
- **Protect reads file contents in one place only.** The content scan's reader is one marked region in `src\SecretScan.cs`. It holds every Windows call in that file and exactly one open call, which asks for read access to an existing file only. The build checks the values behind the names on that call too, so a constant cannot be quietly changed to ask for write access. Outside that region, no Protect source file may call anything that reads a file, except the one marked line that loads its own settings file.
- **What is read never becomes text.** `SecretScan.cs` may not convert bytes to a string, copy them, log them or hash them, and it allocates exactly one buffer per reader, which is cleared after every file.
- **A finding has no room for a value.** The `Finding` type holds a pattern id, a path, a line and column, and a place. The tests check the field list, and the build checks that `SecretScan.cs` creates a finding in one place only.
- **The content scan needs your consent.** It cannot start without a consent value that comes either from the switch you turned on or from `--content` on the command line, and the build checks that only the command line uses the second one.
- **The reader is walled off.** `SecretScan.cs` may use only the scan's own tree types from the rest of the app, so it cannot pass what it reads to other code.
- **Settings hold no paths in clear.** `%LOCALAPPDATA%\DiskSpaceAnalyzer\protect.json` keeps the content-scan switch and a hash per dismissed finding and trusted folder, nothing else.
- **The app explains itself from its own code.** The Protect page's "What Protect reads" is generated from the same constants the scanner uses, so it describes the build you are running. `dsa --protect-info` prints the same text.

To repeat these checks on the built programs and the source:

```
powershell -ExecutionPolicy Bypass -File tools\check-trust.ps1
```

It compiles a small checker (`tools\CheckTrust.cs`) that reads each program's metadata and lists every `System.Net` name it finds, then checks the Protect source files. To see the same thing from the outside, open Resource Monitor's Network tab while a scan runs: the app never appears.

### Check it yourself: no network traffic during a content scan

The no-network check above is done at build time. This test confirms it while the programs run, with Windows' own firewall log. It needs administrator rights, so run it yourself in an elevated PowerShell from the repository root:

1. Note the current audit setting, so you can put it back at the end:

   ```
   auditpol /get /subcategory:"Filtering Platform Connection"
   ```

2. Turn on logging of allowed and blocked connections:

   ```
   auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
   ```

3. Block both programs from going out:

   ```
   New-NetFirewallRule -DisplayName dsa-block-cli -Direction Outbound -Action Block -Program "$PWD\bin\dsa.exe"
   New-NetFirewallRule -DisplayName dsa-block-app -Direction Outbound -Action Block -Program "$PWD\bin\DiskSpaceAnalyzer.exe"
   ```

4. Run a content scan from the command line, then from the app:

   ```
   $start = Get-Date
   bin\dsa.exe C:\ --protect --content --timing > $null
   ```

   Then open the app, scan C:, turn on "Look inside text files for keys", and wait for "Content scan done".

5. Count the connection events for either program since `$start`:

   ```
   Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156,5157; StartTime=$start} | Where-Object { $_.Message -match 'dsa\.exe|DiskSpaceAnalyzer\.exe' } | Measure-Object
   ```

   The expected Count is **0**: no connection was allowed and none was even attempted and blocked.

6. Clean up: remove the two rules, and set auditpol back to what step 1 showed (for example `auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable` if both were off):

   ```
   Remove-NetFirewallRule -DisplayName dsa-block-cli,dsa-block-app
   ```

Record the result in `tests.md`.

### Tests

To run the tests, which also plant network calls, file writes, file reads and the other trust breaks to confirm the checks catch them, and measure every matcher against the cases in `tests\protect-corpus`:

```
powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1
```

The by-name corpus has 192 cases. The content corpus holds recipes, not keys. This repository is public, and GitHub's push protection refuses any push that contains a real-looking key, so no file in it holds a key in a valid format. Each test file is a template with recipes such as `<<google:ok:7>>`; the tests build the real files from them in `%TEMP%\dsa-content-<guid>` while they run, and delete them afterwards. The tests also run every matcher over the templates, the corpus notes and `cases.tsv`, and fail if any of them would be reported as a key.

To time the content scan of C: (run it once right after a reboot for the cold figure; the budget is 180 s from start to the end of the content scan):

```
powershell -ExecutionPolicy Bypass -File tests\bench-content.ps1
```

It prints counts and timings only.

## Command-line version

```
dsa <drive or folder> [--depth N] [--top N] [--csv file.csv] [--moves] [--protect [--all] [--coverage] [--content] [--findings]]
```

For example, `dsa C: --depth 3 --top 15` lists the largest folders three levels deep. It also lists the largest files, space per category and the top extensions. Use `--csv` to write every folder to a file. `--moves` lists your drives and the Move page's suggestions instead. `--protect` lists the Protect page's findings, `--content` also reads text files for keys, and `--findings` adds why each match was reported (see "Protect, and the trust checks" above).

## How sizes are counted

- **Size on disk.** Compressed (NTFS-compressed) and sparse files count the space they actually take, not their logical size.
- **OneDrive and other cloud files** that are "online-only" count as zero, because they take no space on this PC. Their total is shown separately.
- **Junctions and symbolic links are not followed.** The folders they point to are counted where they really are, so nothing is counted twice.
- **Folders that packaged apps redirect** are counted once. For example, `AppData\Roaming\Claude` is a view of the Claude app's package folder.
- **Hard links are counted each time they appear.** This mostly affects `C:\Windows\WinSxS`, which looks bigger than it really is.
- **Unaccounted space.** On a whole-drive scan, used space that the scan could not find in any file appears as `<Unaccounted space>`. This includes:
  - folders you do not have access to
  - NTFS metadata
  - System Restore points
  - the gap between file sizes and the full disk clusters they occupy

  The Overview links to the list of folders that couldn't be read. **Run as administrator** includes most of them.

## Building

The build uses the C# compiler that ships with Windows, so nothing needs to be installed:

```
powershell -ExecutionPolicy Bypass -File build.ps1
```

This writes both programs to `bin\`. The source is in `src\`:

| File | What it does |
|---|---|
| `Scanner.cs` | Walks folders with `FindFirstFileEx`, several branches in parallel |
| `Model.cs` | The tree, file categories, per-type totals, CSV export |
| `Insights.cs` | Finds the clean-up suggestions |
| `Placement.cs` | Works out what each drive is for and which items would be better on another drive |
| `Transfer.cs` | Copies with progress and resume, then checks every file byte for byte |
| `Protect.cs` | The Protect page's finding type, settings store and self-description |
| `tools\CheckTrust.cs` | Reads a compiled program's metadata for `System.Net` names |
| `VirtualDisks.cs` | Finds WSL and Docker disks, cleans caches, prunes Docker, compacts disk files |
| `Shell.cs` | Explorer, Properties and the Recycle Bin |
| `Cli.cs` | The command-line version |
| `AppIcon.cs` | Draws the app icon |
| `Ui\Styles.xaml` | Control styles in the Fluent look |
| `Ui\Theme.cs` | Light and dark colors, following the Windows theme and accent color |
| `Ui\MainWindow.xaml` | The window layout and pages |
| `Ui\MainWindow*.cs` | What the window and each page do |
| `Ui\TreemapView.cs` | The treemap |
| `Ui\Controls.cs` | The progress ring and spinner |
| `Ui\Interop.cs` | Shell icons, the folder picker, Recycle Bin size |

The XAML files are embedded in the app and loaded when it starts, because the built-in compiler cannot compile XAML.

To check the layout without opening a window, the app can render itself to an image. For example, `DiskSpaceAnalyzer.exe C: --snapshot out.png --page explore --theme dark` scans C:, opens Explore in the dark theme and saves the window as `out.png`.

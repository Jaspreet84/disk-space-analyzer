# Disk Space Analyzer

A Windows tool that shows what is using space on a drive or in a folder, and helps you get it back. It uses the Windows 11 (Fluent) look, with light and dark themes. It is a single `.exe` with no installer and no dependencies. It uses the .NET Framework 4.8 that comes with Windows 10 and 11.

**[See the product page](https://claude.ai/artifact/E5GdXQSaVSH4z8bJR7z1TW)** for a tour of what it does.

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

## Command-line version

```
dsa <drive or folder> [--depth N] [--top N] [--csv file.csv] [--moves]
```

For example, `dsa C: --depth 3 --top 15` lists the largest folders three levels deep. It also lists the largest files, space per category and the top extensions. Use `--csv` to write every folder to a file. `--moves` lists your drives and the Move page's suggestions instead.

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

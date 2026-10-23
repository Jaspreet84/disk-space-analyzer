using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace DiskSpace
{
    enum DriveRole { System, Storage, External }

    // What a drive is good for: the fast system drive, an internal drive that is always there, or an external one.
    sealed class DriveProfile
    {
        public string Root;          // "D:\"
        public string Label;
        public string FileSystem;
        public DriveRole Role;
        public bool IsSsd, IsHdd;
        public long Total, Free;
        public long Promised;        // bytes already suggested for this drive

        public string Letter
        {
            get { return Root.TrimEnd('\\'); }
        }

        public long Available
        {
            get { return Free - Promised - Math.Max(Total / 10, 5L << 30); }  // keep 10% free, at least 5 GB
        }

        // WSL, Docker and virtual machines need a drive that is always connected and formatted as NTFS.
        public bool CanHostRunning
        {
            get { return Role != DriveRole.External && FileSystem == "NTFS"; }
        }

        public string Kind
        {
            get
            {
                if (Role == DriveRole.External) return IsSsd ? "External SSD" : "External drive";
                string media = IsSsd ? "SSD" : IsHdd ? "hard drive" : "drive";
                return Role == DriveRole.System ? "System " + media : "Internal " + media;
            }
        }

        public string Purpose
        {
            get
            {
                switch (Role)
                {
                    case DriveRole.System: return "Windows, apps and work in progress";
                    case DriveRole.Storage: return "Data that should always be available";
                    default: return "Backups, archives and things you rarely open";
                }
            }
        }

        public string Name
        {
            get { return Letter + (string.IsNullOrEmpty(Label) ? "" : " " + Label); }
        }
    }

    static class Drives
    {
        public static List<DriveProfile> Load()
        {
            var drives = new List<DriveProfile>();
            Dictionary<char, int> diskOf;
            Dictionary<int, int> busOf, mediaOf;
            ReadStorageInfo(out diskOf, out busOf, out mediaOf);
            string systemRoot = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows));

            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                try
                {
                    if (!d.IsReady || (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable)) continue;
                    if (d.TotalSize < (8L << 30)) continue;  // card readers, small virtual disks
                    var p = new DriveProfile
                    {
                        Root = d.Name.ToUpperInvariant(),
                        Label = d.VolumeLabel,
                        FileSystem = d.DriveFormat,
                        Total = d.TotalSize,
                        Free = d.TotalFreeSpace
                    };
                    int disk, bus = 0, media = 0;
                    if (diskOf.TryGetValue(char.ToUpperInvariant(d.Name[0]), out disk))
                    {
                        busOf.TryGetValue(disk, out bus);
                        mediaOf.TryGetValue(disk, out media);
                    }
                    bool external = d.DriveType == DriveType.Removable || bus == 7 || bus == 12 || bus == 13 || bus == 4;  // USB, SD, MMC, 1394
                    p.IsSsd = media == 4 || bus == 17;  // SSD media, or NVMe
                    p.IsHdd = media == 3;
                    p.Role = string.Equals(p.Root, systemRoot, StringComparison.OrdinalIgnoreCase) ? DriveRole.System
                        : external ? DriveRole.External : DriveRole.Storage;
                    drives.Add(p);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            drives.Sort((a, b) => string.Compare(a.Root, b.Root, StringComparison.Ordinal));
            return drives;
        }

        // Which physical disk each drive letter is on, and that disk's bus (USB, SATA, NVMe...) and media (SSD, HDD).
        // Windows Storage Management answers these without administrator rights.
        static void ReadStorageInfo(out Dictionary<char, int> diskOf, out Dictionary<int, int> busOf, out Dictionary<int, int> mediaOf)
        {
            diskOf = new Dictionary<char, int>();
            busOf = new Dictionary<int, int>();
            mediaOf = new Dictionary<int, int>();
            try
            {
                var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Storage");
                foreach (ManagementObject o in Query(scope, "SELECT DriveLetter, DiskNumber FROM MSFT_Partition"))
                {
                    char letter = Convert.ToChar(o["DriveLetter"]);
                    if (letter != '\0') diskOf[char.ToUpperInvariant(letter)] = Convert.ToInt32(o["DiskNumber"]);
                }
                foreach (ManagementObject o in Query(scope, "SELECT Number, BusType FROM MSFT_Disk"))
                    busOf[Convert.ToInt32(o["Number"])] = Convert.ToInt32(o["BusType"]);
                foreach (ManagementObject o in Query(scope, "SELECT DeviceId, MediaType FROM MSFT_PhysicalDisk"))
                {
                    int id;
                    if (int.TryParse(Convert.ToString(o["DeviceId"]), out id)) mediaOf[id] = Convert.ToInt32(o["MediaType"]);
                }
            }
            catch (Exception)
            {
                // Without storage information every drive counts as internal, unless Windows calls it removable.
            }
        }

        static ManagementObjectCollection Query(ManagementScope scope, string wql)
        {
            return new ManagementObjectSearcher(scope, new ObjectQuery(wql)).Get();
        }

        public static DriveProfile For(List<DriveProfile> drives, string path)
        {
            string root = Path.GetPathRoot(path);
            foreach (DriveProfile d in drives)
                if (string.Equals(d.Root, root, StringComparison.OrdinalIgnoreCase)) return d;
            return null;
        }
    }

    enum MoveKind { Backup, Media, DiskImage, OldInstaller, PersonalFolder, WslDisk, DockerDisk, VmDisk }

    // Copy and Move are done by the app. Guide explains how the owning app or Windows moves it. WslMove runs wsl --move.
    enum MoveAction { Copy, Move, Guide, WslMove }

    sealed class MoveSuggestion
    {
        public Node Item;
        public MoveKind Kind;
        public MoveAction Action;
        public DriveProfile From, To;
        public string Destination;
        public string Reason;
        public string Usage;
        public string Distro;          // for WslMove
        public bool CanMoveInstead;    // a Copy suggestion that may also be moved
        public bool AlreadyCopied;     // an identical copy is already at the destination

        public string KindName
        {
            get
            {
                switch (Kind)
                {
                    case MoveKind.Backup: return "Backup";
                    case MoveKind.Media: return "Photos and videos";
                    case MoveKind.DiskImage: return "Installer image";
                    case MoveKind.OldInstaller: return "Old installer or archive";
                    case MoveKind.PersonalFolder: return "Personal folder";
                    case MoveKind.WslDisk: return "WSL Linux system";
                    case MoveKind.DockerDisk: return "Docker data";
                    default: return "Virtual machine disk";
                }
            }
        }
    }

    // Suggests where large items in a scan would be better kept, based on what they are, when they last changed,
    // and the drives this PC has. It only suggests; nothing is moved here.
    static class Placement
    {
        const long MB = 1L << 20, GB = 1L << 30;

        static readonly HashSet<string> SkipAtRoot = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Windows", "Windows.old", "Program Files", "Program Files (x86)", "ProgramData", "Recovery", "PerfLogs",
            "WindowsApps", "WpSystem", "XboxGames", ".GamingRoot", "MSOCache", "Config.Msi", "OneDriveTemp", "System Volume Information"
        };
        static readonly HashSet<string> DiskImageExts = Set(".iso .img .wim .esd .dmg");
        static readonly HashSet<string> InstallerExts = Set(".exe .msi .msix .zip .7z .rar .tar .gz .tgz .xz");
        static readonly HashSet<string> VmExts = Set(".vdi .vmdk .vhd .vhdx .qcow2");
        static readonly string[] BackupWords = { "backup", "back-up", "archive" };
        static readonly HashSet<string> BackupTokens = Set("bak bkp old export exports dcim");

        static HashSet<string> Set(string list)
        {
            return new HashSet<string>(list.Split(' '), StringComparer.OrdinalIgnoreCase);
        }

        public static List<MoveSuggestion> Suggest(ScanResult r, List<DriveProfile> drives)
        {
            var found = new List<MoveSuggestion>();
            foreach (DriveProfile d in drives) d.Promised = 0;
            DriveProfile from = Drives.For(drives, r.Root.FullPath);
            if (from == null || from.Role == DriveRole.External) return found;  // already where archives belong

            DriveProfile storage = Best(drives, from, DriveRole.Storage), external = Best(drives, from, DriveRole.External);
            var taken = new HashSet<Node>();
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            Dictionary<string, string> distros = WslDistros();

            // Things that run: only off the system drive, and only to an always-connected NTFS drive.
            if (from.Role == DriveRole.System && storage != null && storage.CanHostRunning)
            {
                foreach (FileNode f in r.LargestFiles)
                {
                    if (f.Size < 5 * GB) continue;
                    string path = f.FullPath;
                    string distro;
                    if (Under(path, Path.Combine(local, @"Docker\wsl")) && VmExts.Contains(Ext(f.Name)))
                        Add(found, taken, Make(f, MoveKind.DockerDisk, MoveAction.Guide, from, storage, Path.Combine(storage.Root, "Docker"),
                            "Docker can keep its images and containers on another drive. Containers run a bit slower from a hard drive " +
                            "but work the same. Docker moves the file for you."));
                    else if (distros.TryGetValue(path, out distro))
                    {
                        MoveSuggestion s = Make(f, MoveKind.WslDisk, MoveAction.WslMove, from, storage, Path.Combine(storage.Root, @"WSL\" + distro),
                            storage.IsSsd ? "WSL can run this Linux system from another drive. WSL is shut down while it moves."
                                : "This frees space here, but everything you do in " + distro + " (installs, builds, git) gets slower on a hard drive. " +
                                  "Worth it only if this drive is short on space.");
                        s.Distro = distro;
                        Add(found, taken, s);
                    }
                    else if (VmExts.Contains(Ext(f.Name)) && Under(path, profile) && path.IndexOf(@"\vm_bundles\", StringComparison.OrdinalIgnoreCase) < 0 &&
                             !Under(path, Path.Combine(profile, "AppData")))
                        Add(found, taken, Make(f, MoveKind.VmDisk, MoveAction.Guide, from, storage, Path.Combine(storage.Root, "Virtual machines"),
                            "Virtual machines run fine from an internal hard drive, just slower. Move it with the app that runs it so it keeps working."));
                }
            }

            // Personal folders that Windows can move as a whole, keeping them in File Explorer.
            if (from.Role == DriveRole.System && storage != null)
            {
                foreach (string folder in PersonalFolders())
                {
                    var d = r.FindNode(folder) as DirNode;
                    if (d == null || d.Size < 2 * GB) continue;
                    Add(found, taken, Make(d, MoveKind.PersonalFolder, MoveAction.Guide, from, storage, Path.Combine(storage.Root, d.Name),
                        "Windows can move your " + d.Name + " folder to another drive. It stays in File Explorer and new files go there too."));
                }
            }

            // Backups and photo or video collections.
            WalkFolders(r, r.Root, 0, from, storage, external, found, taken);

            // Installer images and old installers: needed rarely, and can be downloaded again.
            DriveProfile archive = external ?? (from.Role == DriveRole.System ? storage : null);
            if (archive != null)
            {
                DateTime now = DateTime.UtcNow;
                foreach (FileNode f in r.LargestFiles)
                {
                    if (InsideTaken(f, taken) || InSystemArea(f, r) || Under(f.FullPath, Path.Combine(profile, "AppData"))) continue;
                    string ext = Ext(f.Name);
                    if (DiskImageExts.Contains(ext) && f.Size >= 500 * MB)
                        Add(found, taken, Make(f, MoveKind.DiskImage, MoveAction.Move, from, archive, Path.Combine(archive.Root, @"Disk images\" + f.Name),
                            "Installer images are only needed now and then, and can be downloaded again."));
                    else if (InstallerExts.Contains(ext) && f.Size >= 200 * MB && f.LastWrite > 0 &&
                             (now - DateTime.FromFileTimeUtc(f.LastWrite)).TotalDays > 90)
                        Add(found, taken, Make(f, MoveKind.OldInstaller, MoveAction.Move, from, archive, Path.Combine(archive.Root, @"Installers\" + f.Name),
                            "A setup file or archive that hasn't changed in months. Keep it with your archives in case you need it again."));
                }
            }

            found.Sort((a, b) => b.Item.Size.CompareTo(a.Item.Size));
            return found;
        }

        static void WalkFolders(ScanResult r, DirNode dir, int depth, DriveProfile from, DriveProfile storage, DriveProfile external,
            List<MoveSuggestion> found, HashSet<Node> taken)
        {
            foreach (Node child in dir.Children)
            {
                var d = child as DirNode;
                if (d == null || d.Unaccounted || d.Size < GB || taken.Contains(d)) continue;
                if (d.Name.StartsWith("$", StringComparison.Ordinal) || InSystemArea(d, r) ||
                    d.Name.Equals("AppData", StringComparison.OrdinalIgnoreCase) || d.Name.StartsWith("OneDrive", StringComparison.OrdinalIgnoreCase))
                    continue;

                bool backup = LooksLikeBackup(d.Name);
                long[] bytes = r.CategoryBytesUnder(d);
                long media = bytes[(int)Category.Video] + bytes[(int)Category.Images] + bytes[(int)Category.Audio];
                bool mediaFolder = media >= d.Size * 0.8;
                if (backup || mediaFolder)
                {
                    MoveSuggestion s = ForArchiveFolder(d, backup ? MoveKind.Backup : MoveKind.Media, from, storage, external);
                    if (s != null)
                    {
                        Add(found, taken, s);
                        continue;
                    }
                }
                if (depth < 6) WalkFolders(r, d, depth + 1, from, storage, external, found, taken);
            }
        }

        // Personal files you can't download again. On the system drive they move to internal storage; from internal
        // storage they are copied to an external drive, so there are two copies on two drives.
        static MoveSuggestion ForArchiveFolder(DirNode d, MoveKind kind, DriveProfile from, DriveProfile storage, DriveProfile external)
        {
            string what = kind == MoveKind.Backup ? "Backups" : "Photos and videos";
            if (from.Role == DriveRole.System && storage != null && storage.Available >= d.Size)
            {
                return Make(d, kind, MoveAction.Move, from, storage, Path.Combine(storage.Root, d.Name),
                    what + " don't need the fast system drive. " + storage.Letter + " keeps them available and frees space here." +
                    (external != null ? " Copy them to " + external.Letter + " afterwards for a second copy." : ""));
            }
            if (external != null)
            {
                MoveSuggestion s = Make(d, kind, MoveAction.Copy, from, external, Path.Combine(external.Root, d.Name),
                    "Copying " + (kind == MoveKind.Backup ? "this backup" : "these") + " to " + external.Letter +
                    " gives you a second copy on a separate drive. Keep the original too, so one failed drive can't lose it.");
                s.CanMoveInstead = true;
                return s;
            }
            return null;
        }

        static MoveSuggestion Make(Node item, MoveKind kind, MoveAction action, DriveProfile from, DriveProfile to, string destination, string reason)
        {
            return new MoveSuggestion
            {
                Item = item,
                Kind = kind,
                Action = action,
                From = from,
                To = to,
                Destination = destination,
                Reason = reason,
                Usage = UsageText(item.LastWrite)
            };
        }

        // Keeps a suggestion only if the target has room for it, then reserves that room.
        static void Add(List<MoveSuggestion> found, HashSet<Node> taken, MoveSuggestion s)
        {
            if (s == null || taken.Contains(s.Item)) return;
            bool copiesData = s.Action == MoveAction.Copy || s.Action == MoveAction.Move;
            if (copiesData)
            {
                s.Destination = FreeDestination(s);
                if (s.AlreadyCopied)
                {
                    found.Add(s);
                    taken.Add(s.Item);
                    return;
                }
            }
            if (s.To.Available < s.Item.Size) return;
            s.To.Promised += s.Item.Size;
            found.Add(s);
            taken.Add(s.Item);
        }

        // The planned destination, or a numbered variant if something different already has that name.
        // An identical copy already there marks the suggestion as done.
        static string FreeDestination(MoveSuggestion s)
        {
            bool folder = s.Item is DirNode;
            string dir = Path.GetDirectoryName(s.Destination);
            string stem = folder ? Path.GetFileName(s.Destination) : Path.GetFileNameWithoutExtension(s.Destination);
            string ext = folder ? "" : Path.GetExtension(s.Destination);
            for (int n = 1; n < 100; n++)
            {
                string path = Path.Combine(dir, n == 1 ? stem + ext : stem + " (" + n + ")" + ext);
                string target = Scanner.LongPath(path);
                if (!File.Exists(target) && !Directory.Exists(target)) return path;
                bool sameKind = folder ? Directory.Exists(target) : File.Exists(target);
                if (sameKind && IsSameContent(s.Item, path))
                {
                    s.AlreadyCopied = true;
                    return path;
                }
            }
            return s.Destination;
        }

        // Same file count and total size: a quick check that a copy is complete. Verifying compares the bytes.
        static bool IsSameContent(Node item, string copy)
        {
            try
            {
                var file = item as FileNode;
                if (file != null) return new FileInfo(Scanner.LongPath(copy)).Length == file.Size;
                var dir = (DirNode)item;
                long count = 0, bytes = 0;
                foreach (string f in Directory.EnumerateFiles(Scanner.LongPath(copy), "*", SearchOption.AllDirectories))
                {
                    count++;
                    bytes += new FileInfo(f).Length;
                    if (count > dir.FileCount) return false;
                }
                return count == dir.FileCount && bytes == dir.Size;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        static DriveProfile Best(List<DriveProfile> drives, DriveProfile from, DriveRole role)
        {
            DriveProfile best = null;
            foreach (DriveProfile d in drives)
                if (d != from && d.Role == role && (best == null || d.Available > best.Available)) best = d;
            return best != null && best.Available > GB ? best : null;
        }

        // The item, or a folder it is in, is already part of a suggestion.
        static bool InsideTaken(Node n, HashSet<Node> taken)
        {
            for (Node p = n; p != null; p = p.Parent)
                if (taken.Contains(p)) return true;
            return false;
        }

        static bool LooksLikeBackup(string name)
        {
            string lower = name.ToLowerInvariant();
            foreach (string w in BackupWords)
                if (lower.Contains(w)) return true;
            foreach (string token in lower.Split(new[] { ' ', '-', '_', '.', '(', ')' }, StringSplitOptions.RemoveEmptyEntries))
                if (BackupTokens.Contains(token)) return true;
            return false;
        }

        // Inside Windows, Program Files and the like, when the scan covers a whole drive.
        static bool InSystemArea(Node n, ScanResult r)
        {
            if (!Scanner.IsVolumeRoot(r.Root.FullPath)) return false;
            Node top = n;
            while (top.Parent != null && top.Parent != r.Root) top = top.Parent;
            return top.Parent == r.Root && SkipAtRoot.Contains(top.Name);
        }

        static string UsageText(long fileTime)
        {
            if (fileTime <= 0) return "";
            DateTime when = DateTime.FromFileTimeUtc(fileTime).ToLocalTime();
            double days = (DateTime.Now - when).TotalDays;
            if (days < 7) return "Changed in the last week";
            if (days < 60) return "Last changed " + (int)days + " days ago";
            return "Last changed " + when.ToString("MMMM yyyy");
        }

        static bool Under(string path, string folder)
        {
            return path.StartsWith(folder.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }

        static string Ext(string name)
        {
            int dot = name.LastIndexOf('.');
            return dot < 0 ? "" : name.Substring(dot);
        }

        // WSL disk files by path, with their distribution names.
        static Dictionary<string, string> WslDistros()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using (RegistryKey lxss = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Lxss"))
            {
                if (lxss == null) return map;
                foreach (string id in lxss.GetSubKeyNames())
                {
                    using (RegistryKey k = lxss.OpenSubKey(id))
                    {
                        if (k == null) continue;
                        var name = k.GetValue("DistributionName") as string;
                        var basePath = k.GetValue("BasePath") as string;
                        if (name == null || basePath == null || name.StartsWith("docker-desktop", StringComparison.OrdinalIgnoreCase)) continue;
                        if (basePath.StartsWith(@"\\?\", StringComparison.Ordinal)) basePath = basePath.Substring(4);
                        map[Path.Combine(basePath, k.GetValue("VhdFileName") as string ?? "ext4.vhdx")] = name;
                    }
                }
            }
            return map;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern int SHGetKnownFolderPath([In] ref Guid rfid, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] out string path);

        static IEnumerable<string> PersonalFolders()
        {
            Guid downloads = new Guid("374DE290-123F-4565-9164-39C4925E467B");
            string path;
            if (SHGetKnownFolderPath(ref downloads, 0, IntPtr.Zero, out path) == 0 && !string.IsNullOrEmpty(path)) yield return path;
            yield return Environment.GetFolderPath(Environment.SpecialFolder.MyVideos);
            yield return Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
            yield return Environment.GetFolderPath(Environment.SpecialFolder.MyMusic);
            yield return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        }
    }
}

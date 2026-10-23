using System;
using System.Collections.Generic;
using System.IO;

namespace DiskSpace
{
    enum InsightAction { None, VirtualDisks, DiskCleanup, RecycleBin, RunAsAdmin, SystemProtection }

    // One clean-up suggestion: what it is, how much space it covers, and what the user can do about it.
    sealed class Insight
    {
        public string Title, Description, Glyph, ActionText;
        public InsightAction Action;
        public long Bytes;
        public int ItemCount;
        public bool CountsTowardTotal = true;
        public bool ItemsCanBeRecycled;
        public List<Node> Items = new List<Node>();
    }

    // Looks through a scan for space that is commonly safe to reclaim. Everything here is a suggestion;
    // the user reviews each item before anything is removed.
    static class Insights
    {
        const long MB = 1L << 20, GB = 1L << 30;
        const int ItemsShown = 12;

        static readonly HashSet<string> VmDisks = Set(".vdi .vmdk .vhd .vhdx .avhdx .qcow2");
        static readonly HashSet<string> DiskImages = Set(".iso .img .dmg .esd .wim");
        static readonly HashSet<string> InstallersAndArchives = Set(".exe .msi .msix .msixbundle .appx .zip .7z .rar .tar .gz .tgz");

        static HashSet<string> Set(string list)
        {
            return new HashSet<string>(list.Split(' '), StringComparer.OrdinalIgnoreCase);
        }

        public static List<Insight> Find(ScanResult r, bool elevated)
        {
            var found = new List<Insight>();
            var listed = new HashSet<Node>();
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appData = Path.Combine(profile, "AppData");
            string downloads = WindowsInfo.Downloads();

            // WSL and Docker keep whole Linux systems in disk files that only grow.
            var wsl = new Insight
            {
                Title = "WSL and Docker disks",
                Glyph = "",
                Description = "Linux systems and Docker data live in these files. They grow but never shrink by themselves. " +
                              "Clean them up and shrink them from Virtual disks.",
                Action = InsightAction.VirtualDisks,
                ActionText = "Open virtual disks"
            };
            foreach (FileNode f in r.LargestFiles)
            {
                string path = f.FullPath;
                bool docker = path.StartsWith(Path.Combine(local, @"Docker\wsl"), StringComparison.OrdinalIgnoreCase);
                bool distro = f.Name.Equals("ext4.vhdx", StringComparison.OrdinalIgnoreCase) &&
                              path.StartsWith(Path.Combine(local, "Packages"), StringComparison.OrdinalIgnoreCase);
                if (docker || distro) Take(wsl, f, listed);
            }
            Add(found, wsl, GB);

            var vms = new Insight
            {
                Title = "Virtual machine disks",
                Glyph = "",
                Description = "Disks of virtual machines, for example from VirtualBox or Hyper-V. If you no longer need a " +
                              "machine, remove it in the app that created it so its settings go too."
            };
            foreach (FileNode f in r.LargestFiles)
            {
                if (listed.Contains(f) || !VmDisks.Contains(Extension(f.Name))) continue;
                string path = f.FullPath;
                if (!Under(path, profile) || path.IndexOf(@"\Claude\vm_bundles\", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                Take(vms, f, listed);
            }
            Add(found, vms, GB);

            var images = new Insight
            {
                Title = "Installer disk images",
                Glyph = "",
                Description = "Images for installing Windows, Linux or other software. Once you have used them, you can delete " +
                              "them and download them again if needed.",
                ItemsCanBeRecycled = true
            };
            foreach (FileNode f in r.LargestFiles)
            {
                if (listed.Contains(f) || !DiskImages.Contains(Extension(f.Name))) continue;
                string path = f.FullPath;
                if (Under(path, profile) && !Under(path, appData)) Take(images, f, listed);
            }
            Add(found, images, 200 * MB);

            var dl = r.FindNode(downloads) as DirNode;
            if (dl != null)
            {
                DateTime now = DateTime.UtcNow;
                var installers = new Insight
                {
                    Title = "Old installers and archives in Downloads",
                    Glyph = "",
                    Description = "Setup programs and zip files you downloaded more than a month ago. They are usually no " +
                                  "longer needed once the software is installed or the files are extracted.",
                    ItemsCanBeRecycled = true
                };
                var oldFiles = new Insight
                {
                    Title = "Large downloads you haven't touched",
                    Glyph = "",
                    Description = "Files over 100 MB in Downloads that have not changed in six months.",
                    ItemsCanBeRecycled = true
                };
                var candidates = new List<FileNode>();
                CollectFiles(dl, candidates);
                candidates.Sort(Node.CompareBySize);
                foreach (FileNode f in candidates)
                {
                    if (listed.Contains(f) || f.LastWrite <= 0) continue;
                    double days = (now - DateTime.FromFileTimeUtc(f.LastWrite)).TotalDays;
                    if (InstallersAndArchives.Contains(Extension(f.Name)) && days > 30 && f.Size >= MB) Take(installers, f, listed);
                    else if (f.Size >= 100 * MB && days > 180) Take(oldFiles, f, listed);
                }
                Add(found, installers, 100 * MB);
                Add(found, oldFiles, 200 * MB);
            }

            // Package caches that developer tools refill on demand.
            var caches = new Insight
            {
                Title = "Developer caches",
                Glyph = "",
                Description = "Packages that tools such as npm, pip, NuGet, Gradle and Cargo keep after downloading. Deleting " +
                              "them is safe; each tool downloads what it needs again.",
                ItemsCanBeRecycled = true
            };
            string[] cacheFolders =
            {
                @"AppData\Local\npm-cache", @"AppData\Local\pnpm\store", @".pnpm-store", @"AppData\Local\pip\Cache",
                @"AppData\Local\Yarn\Cache", @".nuget\packages", @".gradle\caches", @".m2\repository", @".cargo\registry",
                @"go\pkg\mod", @"AppData\Local\go-build", @".minikube\cache", @"AppData\Local\ms-playwright",
                @"AppData\Local\electron\Cache", @"AppData\Local\node-gyp\Cache", @".cache\huggingface", @".cache\pip"
            };
            foreach (string relative in cacheFolders)
            {
                var d = r.FindNode(Path.Combine(profile, relative)) as DirNode;
                if (d != null && d.Size >= 50 * MB) Take(caches, d, listed);
            }
            caches.Items.Sort(Node.CompareBySize);
            Add(found, caches, 200 * MB);

            var temp = new Insight
            {
                Title = "Temporary files and crash reports",
                Glyph = "",
                Description = "Files that programs and Windows leave behind. Disk Cleanup removes the ones that are safe to delete.",
                Action = InsightAction.DiskCleanup,
                ActionText = "Open Disk Cleanup"
            };
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            foreach (string folder in new[]
            {
                Path.GetTempPath().TrimEnd('\\'), Path.Combine(windows, "Temp"), Path.Combine(local, "CrashDumps"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\WER")
            })
            {
                var d = r.FindNode(folder) as DirNode;
                if (d != null && d.Size > 0 && !listed.Contains(d)) Take(temp, d, listed);
            }
            Add(found, temp, 300 * MB);

            var oldWindows = r.FindNode(Path.Combine(Path.GetPathRoot(windows), "Windows.old")) as DirNode;
            if (oldWindows != null && oldWindows.Size >= GB)
            {
                Add(found, new Insight
                {
                    Title = "Previous Windows installation",
                    Glyph = "",
                    Description = "Windows keeps this after an upgrade so you can go back. Disk Cleanup can remove it " +
                                  "(choose \"Clean up system files\", then \"Previous Windows installation\").",
                    Bytes = oldWindows.Size,
                    Action = InsightAction.DiskCleanup,
                    ActionText = "Open Disk Cleanup"
                }, 0);
            }

            long recycled = WindowsInfo.RecycleBinBytes();
            if (recycled >= 100 * MB)
            {
                Add(found, new Insight
                {
                    Title = "Recycle Bin",
                    Glyph = "",
                    Description = "Deleted files still take up space until the Recycle Bin is emptied.",
                    Bytes = recycled,
                    Action = InsightAction.RecycleBin,
                    ActionText = "Open Recycle Bin"
                }, 0);
            }

            DirNode unaccounted = r.UnaccountedNode;
            if (unaccounted != null && unaccounted.Size >= GB)
            {
                Add(found, new Insight
                {
                    Title = "Space the scan couldn't see",
                    Glyph = "",
                    Description = elevated
                        ? "Protected system files, restore points and file system overhead. System Protection lets you limit how much space restore points use."
                        : "Protected system folders, restore points and file system overhead. Run as administrator to look inside more of them.",
                    Bytes = unaccounted.Size,
                    CountsTowardTotal = false,
                    Action = elevated ? InsightAction.SystemProtection : InsightAction.RunAsAdmin,
                    ActionText = elevated ? "Open System Protection" : "Run as administrator"
                }, 0);
            }

            found.Sort((a, b) => b.Bytes.CompareTo(a.Bytes));
            return found;
        }

        static void Take(Insight insight, Node node, HashSet<Node> listed)
        {
            insight.Bytes += node.Size;
            insight.ItemCount++;
            if (insight.Items.Count < ItemsShown) insight.Items.Add(node);
            listed.Add(node);
        }

        static void Add(List<Insight> found, Insight insight, long minimum)
        {
            if (insight.Bytes > 0 && insight.Bytes >= minimum) found.Add(insight);
        }

        // Like Path.GetExtension, but never throws on unusual characters in a name.
        static string Extension(string name)
        {
            int dot = name.LastIndexOf('.');
            return dot < 0 ? "" : name.Substring(dot);
        }

        static bool Under(string path, string folder)
        {
            return path.StartsWith(folder.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }

        static void CollectFiles(DirNode dir, List<FileNode> into)
        {
            var stack = new Stack<DirNode>();
            stack.Push(dir);
            while (stack.Count > 0)
            {
                DirNode d = stack.Pop();
                foreach (Node child in d.Children)
                {
                    var sub = child as DirNode;
                    if (sub != null) stack.Push(sub);
                    else into.Add((FileNode)child);
                }
            }
        }
    }
}

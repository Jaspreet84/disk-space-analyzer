using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;

// Protect: the known places of this PC, gathered once per scan by the caller before Analyze runs, so that
// Analyze itself never touches the registry, the known-folder API or the disk.
//
// This file is under the trust checks in tools\check-trust.ps1. It reads folder paths, environment
// variables, registry values and whether a ".git" entry exists. It never opens a file.

namespace DiskSpace
{
    [Flags]
    enum PlaceMarks : ushort
    {
        None = 0, Home = 1, Downloads = 2, Desktop = 4, Documents = 8, Pictures = 16,
        Temp = 32, Sync = 64, Roaming = 128, Local = 256, Videos = 512, Music = 1024,
        HomeAbove = 2048  // a folder that holds the user folder (C:\Users): fixture and build names there say nothing
    }

    sealed class ProtectContext
    {
        public readonly string Home, Roaming, Local, OneDriveHint;
        public readonly string[] Downloads, Desktop, Documents, Pictures, Videos, Music, TempRoots, SyncRoots, ExternalRoots, RepoRoots;
        public readonly bool RootInRepo;

        static readonly string[] None = new string[0];

        public ProtectContext(string home, string roaming, string local, string[] downloads, string[] desktop,
            string[] documents, string[] pictures, string[] videos, string[] music, string[] tempRoots,
            string[] syncRoots, string[] externalRoots, string[] repoRoots, string oneDriveHint, bool rootInRepo)
        {
            Home = Norm(home);
            Roaming = Norm(roaming);
            Local = Norm(local);
            Downloads = NormList(downloads);
            Desktop = NormList(desktop);
            Documents = NormList(documents);
            Pictures = NormList(pictures);
            Videos = NormList(videos);
            Music = NormList(music);
            TempRoots = NormList(tempRoots);
            SyncRoots = NormList(syncRoots);
            ExternalRoots = NormList(externalRoots);
            RepoRoots = NormList(repoRoots);
            OneDriveHint = Norm(oneDriveHint);
            RootInRepo = rootInRepo;
        }

        static string Norm(string path)
        {
            if (string.IsNullOrEmpty(path) || path.Trim().Length == 0) return null;
            try { return ProtectStore.Normalize(path); }
            catch (ArgumentException) { return null; }
            catch (NotSupportedException) { return null; }
            catch (PathTooLongException) { return null; }
            catch (System.Security.SecurityException) { return null; }
        }

        static string[] NormList(string[] paths)
        {
            if (paths == null || paths.Length == 0) return None;
            var list = new List<string>();
            foreach (string p in paths)
            {
                string n = Norm(p);
                if (n != null && !list.Contains(n)) list.Add(n);
            }
            return list.ToArray();
        }

        // The places of the signed-in user on this PC. externalRoots: the roots of drives whose role is External;
        // null means the caller has no drive list, and the removable drives are used instead.
        public static ProtectContext ForMachine(string scanRoot, string[] externalRoots)
        {
            string home = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(home)) home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            var temp = new List<string>();
            try { temp.Add(Path.GetTempPath()); }
            catch (System.Security.SecurityException) { }
            if (!string.IsNullOrEmpty(local)) temp.Add(Path.Combine(local, "Temp"));
            string windir = Environment.GetEnvironmentVariable("WINDIR");
            if (!string.IsNullOrEmpty(windir)) temp.Add(Path.Combine(windir, "Temp"));

            string hint = null;
            foreach (string v in new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
            {
                string value = Environment.GetEnvironmentVariable(v);
                if (!string.IsNullOrEmpty(value)) { hint = value; break; }
            }

            if (externalRoots == null) externalRoots = RemovableRoots();

            return new ProtectContext(home, roaming, local,
                WithLegacy(KnownFolders.Downloads(), home, "Downloads"),
                WithLegacy(KnownFolders.Desktop(), home, "Desktop"),
                WithLegacy(KnownFolders.Documents(), home, "Documents"),
                WithLegacy(KnownFolders.Pictures(), home, "Pictures"),
                WithLegacy(KnownFolders.Videos(), home, "Videos"),
                WithLegacy(KnownFolders.Music(), home, "Music"),
                temp.ToArray(), RegisteredSyncRoots(), externalRoots, None, hint, GitAboveRoot(scanRoot));
        }

        // The corpus header context, with C:\Users\pat replaced by fakeHome and no drive-letter places.
        public static ProtectContext ForTree(string fakeHome)
        {
            string h = fakeHome.TrimEnd('\\', '/');
            return new ProtectContext(h, h + @"\AppData\Roaming", h + @"\AppData\Local",
                new[] { h + @"\Downloads" },
                new[] { h + @"\OneDrive\Desktop", h + @"\Desktop" },
                new[] { h + @"\OneDrive\Documents", h + @"\Documents" },
                new[] { h + @"\Pictures" },
                None, None,
                new[] { h + @"\AppData\Local\Temp" },
                new[] { h + @"\OneDrive" },
                None,
                new[] { h + @"\code\app", h + @"\code\infra", h + @"\code\toolkit" },
                null, false);
        }

        static string[] WithLegacy(string known, string home, string leaf)
        {
            var list = new List<string>();
            if (!string.IsNullOrEmpty(known)) list.Add(known);
            if (!string.IsNullOrEmpty(home)) list.Add(Path.Combine(home, leaf));
            return list.ToArray();
        }

        // Whether a scan root is on another computer: a UNC path (\\server\share, or \\?\UNC\...) or a mapped
        // network drive. The content scan reads no file there (ProtectConstants.NetworkDrivesNote). Metadata only.
        public static bool IsNetworkPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string p = path.Replace('/', '\\');
            if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return true;
            if (p.StartsWith(@"\\?\", StringComparison.Ordinal) || p.StartsWith(@"\\.\", StringComparison.Ordinal)) p = p.Substring(4);
            else if (p.StartsWith(@"\\", StringComparison.Ordinal)) return true;
            if (p.Length < 2 || p[1] != ':' || !char.IsLetter(p[0])) return false;
            try { return new DriveInfo(p.Substring(0, 1)).DriveType == DriveType.Network; }
            catch (ArgumentException) { return false; }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        static string[] RemovableRoots()
        {
            var roots = new List<string>();
            try
            {
                foreach (DriveInfo d in DriveInfo.GetDrives())
                    if (d.DriveType == DriveType.Removable) roots.Add(d.Name);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            return roots.ToArray();
        }

        // Metadata only: whether a real folder above the scan root (not the root itself) holds a ".git" entry.
        static bool GitAboveRoot(string scanRoot)
        {
            if (string.IsNullOrEmpty(scanRoot)) return false;
            try
            {
                string a = Path.GetDirectoryName(Path.GetFullPath(scanRoot).TrimEnd('\\'));
                while (!string.IsNullOrEmpty(a))
                {
                    string git = a.TrimEnd('\\') + "\\.git";
                    if (Directory.Exists(git) || File.Exists(git)) return true;
                    a = Path.GetDirectoryName(a);
                }
            }
            catch (ArgumentException) { }
            catch (NotSupportedException) { }
            catch (PathTooLongException) { }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
            return false;
        }

        // Folders registered with the Windows sync engine, read from the registry only. Any failure gives an
        // empty list, which reads every folder as not synced (the safe direction).
        public static string[] RegisteredSyncRoots()
        {
            var roots = new List<string>();
            try
            {
                const string manager = ProtectConstants.SyncRootManagerKey;
                foreach (RegistryKey hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                {
                    using (RegistryKey key = hive.OpenSubKey(manager, false))
                    {
                        if (key == null) continue;
                        foreach (string sub in key.GetSubKeyNames())
                        {
                            using (RegistryKey users = key.OpenSubKey(sub + @"\UserSyncRoots", false))
                            {
                                if (users == null) continue;
                                foreach (string v in users.GetValueNames())
                                {
                                    string path = users.GetValue(v) as string;
                                    if (!string.IsNullOrEmpty(path)) roots.Add(path);
                                }
                            }
                        }
                    }
                }
                using (RegistryKey accounts = Registry.CurrentUser.OpenSubKey(ProtectConstants.OneDriveAccountsKey, false))
                {
                    if (accounts != null)
                    {
                        foreach (string sub in accounts.GetSubKeyNames())
                        {
                            using (RegistryKey account = accounts.OpenSubKey(sub, false))
                            {
                                if (account == null) continue;
                                string path = account.GetValue("UserFolder") as string;
                                if (!string.IsNullOrEmpty(path)) roots.Add(path);
                            }
                        }
                    }
                }
            }
            catch (Exception) { return new string[0]; }
            return roots.ToArray();
        }

        // Every mark whose list holds exactly this path (in ProtectStore.Normalize form), OR-ed together.
        public PlaceMarks MarksOfPath(string normalizedPath)
        {
            if (normalizedPath == null) return PlaceMarks.None;
            PlaceMarks m = PlaceMarks.None;
            if (normalizedPath == Home) m |= PlaceMarks.Home;
            if (IsAboveHome(normalizedPath)) m |= PlaceMarks.HomeAbove;
            if (normalizedPath == Roaming) m |= PlaceMarks.Roaming;
            if (normalizedPath == Local) m |= PlaceMarks.Local;
            if (In(Downloads, normalizedPath)) m |= PlaceMarks.Downloads;
            if (In(Desktop, normalizedPath)) m |= PlaceMarks.Desktop;
            if (In(Documents, normalizedPath)) m |= PlaceMarks.Documents;
            if (In(Pictures, normalizedPath)) m |= PlaceMarks.Pictures;
            if (In(Videos, normalizedPath)) m |= PlaceMarks.Videos;
            if (In(Music, normalizedPath)) m |= PlaceMarks.Music;
            if (In(TempRoots, normalizedPath)) m |= PlaceMarks.Temp;
            if (In(SyncRoots, normalizedPath)) m |= PlaceMarks.Sync;
            return m;
        }

        // True for a folder above the user folder, not counting the drive root (C:\USERS for C:\USERS\PAT).
        bool IsAboveHome(string normalizedPath)
        {
            if (Home == null || normalizedPath.Length <= 3 || normalizedPath.Length >= Home.Length) return false;
            return Home[normalizedPath.Length] == '\\' && Home.StartsWith(normalizedPath, StringComparison.Ordinal);
        }

        // The parent of a normalized path, or null at (or above) a drive root.
        static string ParentOfNorm(string normalized)
        {
            int cut = normalized.LastIndexOf('\\');
            if (cut <= 2) return null;
            return normalized.Substring(0, cut);
        }

        public bool IsExternalRoot(string normalizedDriveRoot)
        {
            return In(ExternalRoots, normalizedDriveRoot);
        }

        // Every path the context knows, with its mark, for the per-scan node lookup.
        internal IEnumerable<KeyValuePair<string, PlaceMarks>> AllPlaces()
        {
            if (Home != null) yield return new KeyValuePair<string, PlaceMarks>(Home, PlaceMarks.Home);
            if (Home != null)
                for (string up = ParentOfNorm(Home); up != null; up = ParentOfNorm(up))
                    yield return new KeyValuePair<string, PlaceMarks>(up, PlaceMarks.HomeAbove);
            if (Roaming != null) yield return new KeyValuePair<string, PlaceMarks>(Roaming, PlaceMarks.Roaming);
            if (Local != null) yield return new KeyValuePair<string, PlaceMarks>(Local, PlaceMarks.Local);
            foreach (string p in Downloads) yield return new KeyValuePair<string, PlaceMarks>(p, PlaceMarks.Downloads);
            foreach (string p in Desktop) yield return new KeyValuePair<string, PlaceMarks>(p, PlaceMarks.Desktop);
            foreach (string p in Documents) yield return new KeyValuePair<string, PlaceMarks>(p, PlaceMarks.Documents);
            foreach (string p in Pictures) yield return new KeyValuePair<string, PlaceMarks>(p, PlaceMarks.Pictures);
            foreach (string p in Videos) yield return new KeyValuePair<string, PlaceMarks>(p, PlaceMarks.Videos);
            foreach (string p in Music) yield return new KeyValuePair<string, PlaceMarks>(p, PlaceMarks.Music);
            foreach (string p in TempRoots) yield return new KeyValuePair<string, PlaceMarks>(p, PlaceMarks.Temp);
            foreach (string p in SyncRoots) yield return new KeyValuePair<string, PlaceMarks>(p, PlaceMarks.Sync);
        }

        // True when the normalized path is one of the repository roots given to the tests, or below one.
        internal bool UnderRepoRoot(string normalizedPath)
        {
            if (normalizedPath == null) return false;
            foreach (string r in RepoRoots)
            {
                if (normalizedPath.Length == r.Length && normalizedPath == r) return true;
                if (normalizedPath.Length > r.Length && normalizedPath.StartsWith(r, StringComparison.Ordinal) &&
                    (normalizedPath[r.Length] == '\\' || r.EndsWith("\\", StringComparison.Ordinal))) return true;
            }
            return false;
        }

        static bool In(string[] list, string path)
        {
            for (int i = 0; i < list.Length; i++)
                if (list[i] == path) return true;
            return false;
        }
    }
}

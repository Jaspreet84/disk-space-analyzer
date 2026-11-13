using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

// Protect: backup coverage. For each large or personal folder in a scan, is there a copy on another drive that is
// connected now?
//
// This file is under the trust checks in tools\check-trust.ps1. It only lists folders: Directory.Exists,
// Directory.EnumerateDirectories, DirectoryInfo.EnumerateFileSystemInfos, a folder's own attributes and last
// write time (File.GetAttributes, Native.IsNameSurrogate), and the length and last-write time that a listing
// already carries. No file is opened, and nothing is changed.

namespace DiskSpace
{
    enum CoverageState { TwoDrives, CopyDiffers, OneCopy, NotChecked }

    // A drive as the check sees it. Placement.CoverageDrives makes these from the drive profiles.
    sealed class CoverageDrive
    {
        public string Root, Label;
        public bool External;
        public int DiskNumber;
        public long Total;              // the drive's size, which with the label tells disks that share a letter apart
    }

    // One folder to check, copied out of the scan tree on the UI thread so the worker never reads a DirNode.
    sealed class CoverageSource
    {
        public DirNode Node;            // for the UI only; the worker never reads it
        public string Path, Name, Why, DriveRoot;
        public long Files, LogicalBytes, NewestWrite;   // NewestWrite: UTC FILETIME
        public bool LogicalStale, Synced, WasSynced;
        public int OnlineOnlyFiles, DiskNumber;
    }

    // What a listing of one possible copy found.
    sealed class CopyCheck
    {
        public string Path;
        public CoverageDrive Drive;
        public long Files, Bytes;
        public DateTime NewestUtc;
        public bool Same, Capped, Partial;
    }

    sealed class FolderCoverage
    {
        public CoverageSource Source;
        public CoverageState State;
        public CopyCheck Best;
        public List<CopyCheck> Copies;
        public string NotCheckedReason;
    }

    sealed class CoverageReport
    {
        public string ScanDrive;
        public List<FolderCoverage> Folders;
        public string NoDrivesReason;
        public int WithoutCurrentCopy;           // OneCopy + CopyDiffers, never NotChecked
        public long WithoutCurrentCopyBytes;     // folders inside another counted folder add no bytes
        public int NotCheckedCount;
        public TimeSpan Took;
    }

    static class ProtectCoverage
    {
        public const int MaxSources = 40;
        public const long MinKnownFolderBytes = 1L << 20;

        // Limits on listing copies. Tests lower FileCap to try the cap without making 200,000 files.
        public static int FileCap = 200000;
        public static TimeSpan SourceTimeCap = TimeSpan.FromSeconds(20);
        public static TimeSpan TotalTimeCap = TimeSpan.FromSeconds(90);

        public const string ExternalScanReason = "Backups are checked for folders on internal drives.";
        public const string NoOtherDriveReason = "Connect your backup drive and scan again to check for copies.";
        public const string StaleReason = "Rescan to check copies of this folder.";
        public const string CancelledReason = "The check was stopped before this folder.";
        public const string TimeReason = "Checking the copies took too long, so this folder was not checked.";
        public const string CappedReason = "The copy has too many files to count here.";
        public const string PartialReason = "Some folders in the copy could not be read.";
        public const string NoDriveForSourceReason = "No other drive is connected.";

        // ---- Candidates, on the UI thread ----

        enum Rule { Findings = 0, Known = 1, Personal = 2 }

        sealed class Pick
        {
            public DirNode Node;
            public Rule Rule;
            public string Why;
            public string Norm;
        }

        // The folders to check, in order: folders holding personal documents or vaults, then the known folders,
        // then large backup and media folders by size. At most MaxSources. Reads only the tree in memory.
        public static List<CoverageSource> Snapshot(ScanResult r, ProtectContext ctx, IList<DirNode> personal,
            IList<CoverageDrive> drives)
        {
            var sources = new List<CoverageSource>();
            if (r == null || r.Root == null) return sources;

            var picks = new List<Pick>();
            var seen = new Dictionary<DirNode, Pick>();

            // Rule 3: the top folder of each document or vault finding.
            var findingPicks = new List<Pick>();
            if (r.Findings != null && r.FindingNodes != null)
            {
                HashSet<string> anchors = Anchors(ctx);
                HashSet<string> known = KnownSet(ctx);
                HashSet<string> downloads = SetOf(ctx == null ? null : ctx.Downloads);
                // Temp and the Mail attachment cache sit in AppData, which is not a folder to keep a copy of
                // (rule 2 leaves it out too), so their findings give no candidate.
                string appData = ctx != null && ctx.Home != null ? ctx.Home + "\\APPDATA" : null;
                int n = Math.Min(r.Findings.Count, r.FindingNodes.Count);
                for (int i = 0; i < n; i++)
                {
                    Finding f = r.Findings[i];
                    if (f == null || !IsPersonalFinding(f.PatternId)) continue;
                    DirNode top = TopFolder(r.FindingNodes[i], anchors, known, downloads);
                    if (top == null) continue;
                    if (appData != null && Norm(top.FullPath) == appData) continue;
                    string why = WhyForFinding(f.PatternId);
                    Pick p;
                    if (seen.TryGetValue(top, out p))
                    {
                        if (p.Why != why) p.Why = "Holds personal documents";
                        continue;
                    }
                    p = new Pick { Node = top, Rule = Rule.Findings, Why = why, Norm = Norm(top.FullPath) };
                    seen[top] = p;
                    findingPicks.Add(p);
                }
            }
            findingPicks.Sort((a, b) => b.Node.Size.CompareTo(a.Node.Size));
            picks.AddRange(findingPicks);

            // Rule 1: the known folders, when they hold something.
            if (ctx != null)
            {
                AddKnown(r, ctx.Documents, "Your Documents folder", picks, seen);
                AddKnown(r, ctx.Pictures, "Your Pictures folder", picks, seen);
                AddKnown(r, ctx.Videos, "Your Videos folder", picks, seen);
                AddKnown(r, ctx.Music, "Your Music folder", picks, seen);
                AddKnown(r, ctx.Desktop, "Your Desktop", picks, seen);
            }

            // Rule 2: large backup and media folders, largest first.
            var personalPicks = new List<Pick>();
            if (personal != null)
            {
                foreach (DirNode d in personal)
                {
                    if (d == null || seen.ContainsKey(d)) continue;
                    // The caption is worked out after nested folders are folded (below), so a folder that is
                    // dropped is never walked.
                    var p = new Pick { Node = d, Rule = Rule.Personal, Why = null, Norm = Norm(d.FullPath) };
                    seen[d] = p;
                    personalPicks.Add(p);
                }
            }
            personalPicks.Sort((a, b) => b.Node.Size.CompareTo(a.Node.Size));
            picks.AddRange(personalPicks);

            // Nested folders fold into the outermost one, except folders holding findings, which always stay.
            var kept = new List<Pick>();
            foreach (Pick p in picks)
            {
                if (p.Rule != Rule.Findings && HasPickAbove(p, picks)) continue;
                if (p.Why == null)
                    p.Why = !NameSaysBackup(p.Node.Name) && MostlyMedia(r, p.Node) ? "Mostly photos and videos" : "Looks like a backup";
                kept.Add(p);
                if (kept.Count == MaxSources) break;
            }

            string scanRoot = Path.GetPathRoot(r.Root.FullPath);
            int disk = -1;
            if (drives != null && scanRoot != null)
                foreach (CoverageDrive d in drives)
                    if (d != null && d.Root != null && string.Equals(d.Root.TrimEnd('\\'), scanRoot.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                        disk = d.DiskNumber;

            foreach (Pick p in kept)
            {
                DirNode d = p.Node;
                string path = d.FullPath;
                bool synced = ctx != null && UnderAny(p.Norm, ctx.SyncRoots);
                bool wasSynced = !synced && ctx != null && !string.IsNullOrEmpty(ctx.OneDriveHint) && UnderOrSame(p.Norm, Norm(ctx.OneDriveHint));
                sources.Add(new CoverageSource
                {
                    Node = d,
                    Path = path,
                    Name = d.Name,
                    Why = p.Why,
                    DriveRoot = scanRoot == null ? "" : scanRoot.ToUpperInvariant(),
                    Files = d.FileCount,
                    LogicalBytes = d.LogicalBytes,
                    NewestWrite = d.LastWrite,
                    LogicalStale = d.LogicalStale,
                    Synced = synced,
                    WasSynced = wasSynced,
                    OnlineOnlyFiles = d.OnlineOnlyFiles,
                    DiskNumber = disk
                });
            }
            return sources;
        }

        static void AddKnown(ScanResult r, string[] paths, string why, List<Pick> picks, Dictionary<DirNode, Pick> seen)
        {
            if (paths == null) return;
            foreach (string path in paths)
            {
                if (string.IsNullOrEmpty(path)) continue;
                var d = r.FindNode(path) as DirNode;
                if (d == null || d.Unaccounted || seen.ContainsKey(d)) continue;
                if (d.FileCount < 1 || Math.Max(d.Size, d.LogicalBytes) < MinKnownFolderBytes) continue;
                var p = new Pick { Node = d, Rule = Rule.Known, Why = why, Norm = Norm(d.FullPath) };
                seen[d] = p;
                picks.Add(p);
            }
        }

        static bool HasPickAbove(Pick p, List<Pick> picks)
        {
            foreach (Pick other in picks)
                if (other != p && other.Node != p.Node && p.Node.IsUnder(other.Node)) return true;
            return false;
        }

        // Only for the "why" caption; which folders are candidates is Placement's decision.
        static bool NameSaysBackup(string name)
        {
            string lower = name.ToLowerInvariant();
            return lower.Contains("backup") || lower.Contains("back-up") || lower.Contains("archive");
        }

        static bool MostlyMedia(ScanResult r, DirNode d)
        {
            if (d.Size <= 0) return false;
            long[] bytes = r.CategoryBytesUnder(d);
            long media = bytes[(int)Category.Video] + bytes[(int)Category.Images] + bytes[(int)Category.Audio];
            return media >= d.Size * 0.8;
        }

        static bool IsPersonalFinding(string id)
        {
            return id != null && (id.StartsWith("doc-", StringComparison.Ordinal) || id == "password-vault");
        }

        static string WhyForFinding(string id)
        {
            switch (id)
            {
                case "doc-tax":
                case "doc-tax-file": return "Holds tax documents";
                case "doc-statement": return "Holds bank statements";
                case "doc-pay": return "Holds payslips";
                case "doc-id": return "Holds ID documents";
                case "doc-scans-folder": return "Holds scanned documents";
                case "password-vault": return "Holds a password vault";
                default: return "Holds personal documents";
            }
        }

        // The folder that holds a finding, as the page groups it: the ancestor that is a direct child of a drive
        // root, of the user folder, of a known folder or of Downloads. A finding directly in a known folder other
        // than Downloads gives that known folder. One directly in Downloads, in the user folder or in a drive root
        // gives none. When the scan root is below all of those, the scan root is the top folder.
        static DirNode TopFolder(Node node, HashSet<string> anchors, HashSet<string> known, HashSet<string> downloads)
        {
            if (node == null || node.Parent == null) return null;
            string parentNorm = Norm(node.Parent.FullPath);
            if (downloads.Contains(parentNorm)) return null;
            if (known.Contains(parentNorm)) return node.Parent;

            Node c = node;
            while (true)
            {
                DirNode p = c.Parent;
                string pNorm = p != null ? Norm(p.FullPath) : ParentNorm(c);
                if (pNorm == null || IsDriveRoot(pNorm) || anchors.Contains(pNorm))
                    return c as DirNode;  // null when the finding itself sits directly in that folder
                if (p == null) return c as DirNode;  // the scan root, below every anchor
                c = p;
            }
        }

        // The normalised path of the folder above the scan root, which is not in the tree.
        static string ParentNorm(Node root)
        {
            try
            {
                string parent = Path.GetDirectoryName(root.FullPath.TrimEnd('\\'));
                return string.IsNullOrEmpty(parent) ? null : Norm(parent);
            }
            catch (ArgumentException) { return null; }
            catch (PathTooLongException) { return null; }
        }

        static HashSet<string> Anchors(ProtectContext ctx)
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            if (ctx == null) return set;
            if (!string.IsNullOrEmpty(ctx.Home)) set.Add(Norm(ctx.Home));
            AddAll(set, ctx.Downloads);
            set.UnionWith(KnownSet(ctx));
            return set;
        }

        static HashSet<string> KnownSet(ProtectContext ctx)
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            if (ctx == null) return set;
            AddAll(set, ctx.Documents);
            AddAll(set, ctx.Pictures);
            AddAll(set, ctx.Videos);
            AddAll(set, ctx.Music);
            AddAll(set, ctx.Desktop);
            return set;
        }

        static HashSet<string> SetOf(string[] paths)
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            AddAll(set, paths);
            return set;
        }

        static void AddAll(HashSet<string> set, string[] paths)
        {
            if (paths == null) return;
            foreach (string p in paths)
                if (!string.IsNullOrEmpty(p)) set.Add(Norm(p));
        }

        static bool IsDriveRoot(string norm)
        {
            return norm.Length <= 3 && norm.Length >= 2 && norm[1] == ':';
        }

        static string Norm(string path)
        {
            try { return ProtectStore.Normalize(path); }
            catch (ArgumentException) { return path.ToUpperInvariant(); }
            catch (NotSupportedException) { return path.ToUpperInvariant(); }
            catch (PathTooLongException) { return path.ToUpperInvariant(); }
        }

        static bool UnderAny(string norm, string[] roots)
        {
            if (roots == null) return false;
            foreach (string root in roots)
                if (!string.IsNullOrEmpty(root) && UnderOrSame(norm, Norm(root))) return true;
            return false;
        }

        static bool UnderOrSame(string norm, string rootNorm)
        {
            if (norm.Length == rootNorm.Length) return string.Equals(norm, rootNorm, StringComparison.Ordinal);
            if (!norm.StartsWith(rootNorm, StringComparison.Ordinal)) return false;
            return rootNorm.EndsWith("\\", StringComparison.Ordinal) || norm[rootNorm.Length] == '\\';
        }

        // ---- Copies on other drives, on a worker thread ----

        // Looks for a copy of each source on every other drive connected now, by name, and compares the file count
        // and total size of what it finds. Reads only directory listings. The cache (kept by the caller for the
        // session) skips listings whose source and copy path did not change.
        public static CoverageReport Compute(List<CoverageSource> sources, IList<CoverageDrive> drives,
            Func<string, bool> isBackupName, Dictionary<string, CopyCheck> cache, CancellationToken ct)
        {
            Stopwatch clock = Stopwatch.StartNew();
            var report = new CoverageReport { Folders = new List<FolderCoverage>() };
            if (sources == null) sources = new List<CoverageSource>();
            var allDrives = new List<CoverageDrive>();
            if (drives != null)
                foreach (CoverageDrive d in drives)
                    if (d != null && !string.IsNullOrEmpty(d.Root)) allDrives.Add(d);
            // External drives are probed first: that is where backups usually are.
            allDrives.Sort((a, b) =>
            {
                if (a.External != b.External) return a.External ? -1 : 1;
                return string.Compare(a.Root, b.Root, StringComparison.OrdinalIgnoreCase);
            });

            if (sources.Count > 0) report.ScanDrive = sources[0].DriveRoot;
            CoverageDrive scanDrive = report.ScanDrive == null ? null : DriveWithRoot(allDrives, report.ScanDrive);
            bool scanIsExternal = scanDrive != null && scanDrive.External;
            if (scanIsExternal) report.NoDrivesReason = ExternalScanReason;

            bool anyOther = false;
            var topFolders = new Dictionary<CoverageDrive, List<string>>();

            foreach (CoverageSource x in sources)
            {
                var fc = new FolderCoverage { Source = x, Copies = new List<CopyCheck>() };
                report.Folders.Add(fc);
                if (scanIsExternal) { NotChecked(fc, ExternalScanReason); continue; }

                List<CoverageDrive> others = OtherDrives(x, allDrives);
                if (others.Count == 0) { NotChecked(fc, NoDriveForSourceReason); continue; }
                anyOther = true;
                if (ct.IsCancellationRequested) { NotChecked(fc, CancelledReason); continue; }
                if (clock.Elapsed > TotalTimeCap) { NotChecked(fc, TimeReason); continue; }
                if (x.LogicalStale) { NotChecked(fc, StaleReason); continue; }

                Check(x, others, isBackupName, cache, ct, clock, topFolders, fc);
            }
            if (!scanIsExternal && sources.Count > 0 && !anyOther) report.NoDrivesReason = NoOtherDriveReason;

            var uncovered = new List<CoverageSource>();
            foreach (FolderCoverage fc in report.Folders)
            {
                if (fc.State == CoverageState.NotChecked) report.NotCheckedCount++;
                else if (fc.State == CoverageState.OneCopy || fc.State == CoverageState.CopyDiffers)
                {
                    report.WithoutCurrentCopy++;
                    uncovered.Add(fc.Source);
                }
            }
            foreach (CoverageSource s in uncovered)
            {
                bool inside = false;
                foreach (CoverageSource o in uncovered)
                    if (o != s && UnderOrSame(Norm(s.Path), Norm(o.Path)) && !string.Equals(Norm(s.Path), Norm(o.Path), StringComparison.Ordinal))
                        inside = true;
                if (!inside) report.WithoutCurrentCopyBytes += s.LogicalBytes;
            }
            report.Took = clock.Elapsed;
            return report;
        }

        static void NotChecked(FolderCoverage fc, string reason)
        {
            fc.State = CoverageState.NotChecked;
            fc.NotCheckedReason = reason;
        }

        static CoverageDrive DriveWithRoot(List<CoverageDrive> drives, string root)
        {
            foreach (CoverageDrive d in drives)
                if (SameRoot(d.Root, root)) return d;
            return null;
        }

        static bool SameRoot(string a, string b)
        {
            if (a == null || b == null) return false;
            return string.Equals(a.TrimEnd('\\'), b.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        // Drives with a different root, and, when both disk numbers are known, on a different disk.
        static List<CoverageDrive> OtherDrives(CoverageSource x, List<CoverageDrive> drives)
        {
            var list = new List<CoverageDrive>();
            foreach (CoverageDrive d in drives)
            {
                if (SameRoot(d.Root, x.DriveRoot)) continue;
                if (x.DiskNumber >= 0 && d.DiskNumber >= 0 && x.DiskNumber == d.DiskNumber) continue;
                list.Add(d);
            }
            return list;
        }

        static void Check(CoverageSource x, List<CoverageDrive> others, Func<string, bool> isBackupName,
            Dictionary<string, CopyCheck> cache, CancellationToken ct, Stopwatch total,
            Dictionary<CoverageDrive, List<string>> topFolders, FolderCoverage fc)
        {
            Stopwatch own = Stopwatch.StartNew();
            bool stopped = false, timedOut = false;
            foreach (CoverageDrive d in others)
            {
                foreach (string probe in Probes(x, d, isBackupName, topFolders))
                {
                    if (ct.IsCancellationRequested) { stopped = true; break; }
                    if (own.Elapsed > SourceTimeCap || total.Elapsed > TotalTimeCap) { timedOut = true; break; }
                    if (!FolderExists(probe)) continue;
                    // A junction or symbolic link on the way may lead back to the source itself, so it is not a copy.
                    if (ViaLink(probe, d.Root)) continue;

                    string stamp = CopyStamp(d, probe);
                    CopyCheck c = Cached(cache, x, probe, stamp);
                    if (c == null)
                    {
                        c = List(x, probe, ct, own, total);
                        if (c == null) { stopped = true; break; }  // cancelled mid-listing
                        if (!c.Capped && !c.Partial) Store(cache, x, probe, stamp, c);
                    }
                    c.Drive = d;
                    fc.Copies.Add(c);
                    if (c.Same && !c.Capped && !c.Partial)
                    {
                        fc.State = CoverageState.TwoDrives;
                        fc.Best = c;
                        return;
                    }
                }
                if (stopped || timedOut) break;
            }

            if (stopped) { NotChecked(fc, CancelledReason); return; }
            if (timedOut) { NotChecked(fc, TimeReason); return; }
            if (fc.Copies.Count == 0)
            {
                fc.State = CoverageState.OneCopy;
                return;
            }
            foreach (CopyCheck c in fc.Copies)
            {
                if (c.Capped) { NotChecked(fc, CappedReason); fc.Best = c; return; }
                if (c.Partial) { NotChecked(fc, PartialReason); fc.Best = c; return; }
            }
            // No identical copy: the one whose file count is closest is shown as the copy that differs.
            CopyCheck best = null;
            foreach (CopyCheck c in fc.Copies)
            {
                if (best == null) { best = c; continue; }
                long dc = Math.Abs(c.Files - x.Files), db = Math.Abs(best.Files - x.Files);
                if (dc < db || (dc == db && Math.Abs(c.Bytes - x.LogicalBytes) < Math.Abs(best.Bytes - x.LogicalBytes))) best = c;
            }
            fc.State = CoverageState.CopyDiffers;
            fc.Best = best;
        }

        // The places a copy of x on drive d would be, in order: d:\Name, d:\Name (2) to (9) (the names the Move
        // page's copy picks), the same path without the drive letter (a mirror), and d:\T\Name for each top folder
        // T of d whose name looks like a backup.
        static List<string> Probes(CoverageSource x, CoverageDrive d, Func<string, bool> isBackupName,
            Dictionary<CoverageDrive, List<string>> topFolders)
        {
            var list = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(x.Name)) return list;
            AddProbe(list, seen, Join(d.Root, x.Name));
            for (int n = 2; n <= 9; n++) AddProbe(list, seen, Join(d.Root, x.Name + " (" + n + ")"));
            if (!string.IsNullOrEmpty(x.Path) && !string.IsNullOrEmpty(x.DriveRoot) &&
                x.Path.Length > x.DriveRoot.Length && x.Path.StartsWith(x.DriveRoot, StringComparison.OrdinalIgnoreCase))
                AddProbe(list, seen, Join(d.Root, x.Path.Substring(x.DriveRoot.Length).TrimStart('\\')));
            if (isBackupName != null)
                foreach (string t in BackupTops(d, isBackupName, topFolders))
                    AddProbe(list, seen, Join(t, x.Name));
            return list;
        }

        static void AddProbe(List<string> list, HashSet<string> seen, string path)
        {
            if (path != null && seen.Add(path)) list.Add(path);
        }

        // The top folders of a drive that look like backups, listed once per drive per run.
        static List<string> BackupTops(CoverageDrive d, Func<string, bool> isBackupName, Dictionary<CoverageDrive, List<string>> cache)
        {
            List<string> tops;
            if (cache.TryGetValue(d, out tops)) return tops;
            tops = new List<string>();
            try
            {
                foreach (string dir in Directory.EnumerateDirectories(d.Root))
                {
                    string name = Path.GetFileName(dir);
                    if (!string.IsNullOrEmpty(name) && isBackupName(name)) tops.Add(dir);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (ArgumentException) { }
            catch (System.Security.SecurityException) { }
            cache[d] = tops;
            return tops;
        }

        // True when the probe, or a folder between the drive root and it, is a junction, mount point or symbolic
        // link. The scanner does not follow those, and one can point back at the folder being checked.
        static bool ViaLink(string probe, string driveRoot)
        {
            if (string.IsNullOrEmpty(probe) || string.IsNullOrEmpty(driveRoot)) return false;
            string root = driveRoot.EndsWith("\\", StringComparison.Ordinal) ? driveRoot : driveRoot + "\\";
            if (!probe.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return Native.IsNameSurrogate(probe);
            string[] parts = probe.Substring(root.Length).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            string cur = root.TrimEnd('\\');
            foreach (string part in parts)
            {
                cur = cur + "\\" + part;
                try
                {
                    if ((File.GetAttributes(cur) & FileAttributes.ReparsePoint) == 0) continue;
                }
                catch (IOException) { return false; }
                catch (UnauthorizedAccessException) { return false; }
                catch (ArgumentException) { return false; }
                catch (NotSupportedException) { return false; }
                if (Native.IsNameSurrogate(cur)) return true;
            }
            return false;
        }

        // What the cache knows of the copy side: the drive's label and size (so another disk that gets the same
        // letter does not reuse an entry) and the copy folder's last write time.
        static string CopyStamp(CoverageDrive d, string probe)
        {
            long written = 0;
            try { written = Directory.GetLastWriteTimeUtc(probe).Ticks; }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (ArgumentException) { }
            catch (NotSupportedException) { }
            return (d.Label ?? "") + "|" + d.Total + "|" + written;
        }

        static bool FolderExists(string path)
        {
            try { return Directory.Exists(path); }
            catch (ArgumentException) { return false; }
            catch (NotSupportedException) { return false; }
        }

        static string Join(string folder, string name)
        {
            if (string.IsNullOrEmpty(folder)) return null;
            try { return Path.Combine(folder, name); }
            catch (ArgumentException) { return null; }
        }

        // Counts the files and bytes in a copy and finds its newest write, folder by folder. Junctions, mount points
        // and symbolic links are skipped, as the scanner skips them; other reparse-point folders (cloud sync
        // folders) are real folders and are counted, as the scanner counts them. Stops as soon as the copy has more files than the source. Null when
        // cancelled.
        static CopyCheck List(CoverageSource x, string copyPath, CancellationToken ct, Stopwatch own, Stopwatch total)
        {
            var c = new CopyCheck { Path = copyPath };
            long newest = 0;
            var stack = new Stack<DirectoryInfo>();
            stack.Push(new DirectoryInfo(copyPath));
            int entries = 0;
            while (stack.Count > 0)
            {
                DirectoryInfo dir = stack.Pop();
                try
                {
                    foreach (FileSystemInfo item in dir.EnumerateFileSystemInfos())
                    {
                        if ((++entries & 255) == 0)
                        {
                            if (ct.IsCancellationRequested) return null;
                            if (own.Elapsed > SourceTimeCap || total.Elapsed > TotalTimeCap)
                            {
                                c.Capped = true;
                                return Finish(c, x, newest);
                            }
                        }
                        var sub = item as DirectoryInfo;
                        if (sub != null)
                        {
                            if ((sub.Attributes & FileAttributes.ReparsePoint) == 0 || !Native.IsNameSurrogate(sub.FullName))
                                stack.Push(sub);
                            continue;
                        }
                        var fi = item as FileInfo;
                        if (fi == null) continue;
                        c.Files++;
                        c.Bytes += fi.Length;
                        long written = fi.LastWriteTimeUtc.ToFileTimeUtc();
                        if (written > newest) newest = written;
                        if (c.Files > x.Files) return Finish(c, x, newest);  // more files than here: it differs
                        if (c.Files >= FileCap)
                        {
                            c.Capped = true;
                            return Finish(c, x, newest);
                        }
                    }
                }
                catch (UnauthorizedAccessException) { c.Partial = true; }
                catch (IOException) { c.Partial = true; }
                catch (System.Security.SecurityException) { c.Partial = true; }
            }
            return Finish(c, x, newest);
        }

        static CopyCheck Finish(CopyCheck c, CoverageSource x, long newest)
        {
            c.NewestUtc = newest > 0 ? DateTime.FromFileTimeUtc(newest) : DateTime.MinValue;
            c.Same = !c.Capped && !c.Partial && c.Files == x.Files && c.Bytes == x.LogicalBytes;
            return c;
        }

        // sourcePath|FileCount|LogicalBytes|LastWrite|copyStamp|copyPath. The copy path is always last, so the
        // caller can forget every entry for a copy it has just written (ForgetCopy).
        public static string CacheKey(CoverageSource x, string copyPath, string copyStamp)
        {
            return x.Path + "|" + x.Files + "|" + x.LogicalBytes + "|" + x.NewestWrite + "|" + copyStamp + "|" + copyPath;
        }

        // Drops the cached listings of a source folder and of every copy at or below a folder that was written.
        public static void Forget(Dictionary<string, CopyCheck> cache, string sourcePath, string writtenFolder)
        {
            if (cache == null) return;
            lock (cache)
            {
                var stale = new List<string>();
                foreach (string key in cache.Keys)
                {
                    if (sourcePath != null && key.StartsWith(sourcePath + "|", StringComparison.OrdinalIgnoreCase)) { stale.Add(key); continue; }
                    if (writtenFolder == null) continue;
                    string copy = key.Substring(key.LastIndexOf('|') + 1);
                    if (UnderOrSame(Norm(copy), Norm(writtenFolder))) stale.Add(key);
                }
                foreach (string key in stale) cache.Remove(key);
            }
        }

        static CopyCheck Cached(Dictionary<string, CopyCheck> cache, CoverageSource x, string copyPath, string stamp)
        {
            if (cache == null) return null;
            CopyCheck hit;
            lock (cache)
            {
                if (!cache.TryGetValue(CacheKey(x, copyPath, stamp), out hit)) return null;
            }
            // A fresh object, so the caller can set Drive without changing the cached entry.
            return new CopyCheck
            {
                Path = hit.Path, Files = hit.Files, Bytes = hit.Bytes, NewestUtc = hit.NewestUtc,
                Same = hit.Same, Capped = hit.Capped, Partial = hit.Partial
            };
        }

        static void Store(Dictionary<string, CopyCheck> cache, CoverageSource x, string copyPath, string stamp, CopyCheck c)
        {
            if (cache == null) return;
            lock (cache)
            {
                cache[CacheKey(x, copyPath, stamp)] = new CopyCheck
                {
                    Path = c.Path, Files = c.Files, Bytes = c.Bytes, NewestUtc = c.NewestUtc,
                    Same = c.Same, Capped = c.Capped, Partial = c.Partial
                };
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DiskSpace
{
    static class Cli
    {
        static void Usage()
        {
            Console.WriteLine("Usage: dsa <drive or folder> [--depth N] [--top N] [--csv file.csv] [--moves]");
            Console.WriteLine("       dsa <drive or folder> --protect [--content [--findings]] [--all] [--coverage] [--timing] [--protect-home DIR] [--no-protect]");
            Console.WriteLine();
            Console.WriteLine("  --depth N   how many folder levels to list (default 2)");
            Console.WriteLine("  --top N     how many entries to show per list and per folder (default 10)");
            Console.WriteLine("  --csv FILE  also write every folder with its size to a CSV file");
            Console.WriteLine("  --moves     only list your drives and what would be better kept on another drive");
            Console.WriteLine("  --protect-info  print what the Protect page reads and keeps, as this build does it");
            Console.WriteLine("  --protect   list what the Protect page finds by file name and location (nothing is opened)");
            Console.WriteLine("  --content   with --protect, also read small text files for keys with a known format (only lines are shown, never a key)");
            Console.WriteLine("  --findings  with --content, also print why each match was reported");
            Console.WriteLine("  --all       with --protect, also list files in their usual places, in projects, and hidden by you");
            Console.WriteLine("  --coverage  with --protect, check whether your personal folders have a copy on another drive");
            Console.WriteLine("  --timing    print scan_ms, analyze_ms, coverage_ms and the content scan counters on stderr");
            Console.WriteLine("  --protect-home DIR  judge places as if DIR were your user folder (for the test fixture tree)");
            Console.WriteLine("  --no-protect        skip the Protect checks (for timing comparisons)");
            Console.WriteLine();
            Console.WriteLine("Example: dsa C: --depth 3 --top 15");
        }

        public static int Run(string[] args)
        {
            string path = null, csv = null, protectHome = null;
            int top = 10, depth = 2;
            bool moves = false, protect = false, all = false, coverage = false, timing = false, noProtect = false;
            bool content = false, reasons = false;
            try
            {
                for (int i = 0; i < args.Length; i++)
                {
                    string a = args[i];
                    if (a == "--depth" && i + 1 < args.Length) depth = int.Parse(args[++i]);
                    else if (a == "--top" && i + 1 < args.Length) top = int.Parse(args[++i]);
                    else if (a == "--csv" && i + 1 < args.Length) csv = args[++i];
                    else if (a == "--moves") moves = true;
                    else if (a == "--protect") protect = true;
                    else if (a == "--all") all = true;
                    else if (a == "--content") content = true;
                    else if (a == "--findings") reasons = true;
                    else if (a == "--coverage") coverage = true;
                    else if (a == "--timing") timing = true;
                    else if (a == "--no-protect") noProtect = true;
                    else if (a == "--protect-home" && i + 1 < args.Length) protectHome = args[++i];
                    else if (a == "--protect-info")
                    {
                        Console.Write(ProtectInfo.AsText());
                        return 0;
                    }
                    else if (a == "--write-icon" && i + 1 < args.Length)
                    {
                        AppIcon.WriteIcoFile(args[++i]);
                        return 0;
                    }
                    else if (a == "-h" || a == "--help" || a == "/?")
                    {
                        Usage();
                        return 0;
                    }
                    else if (a.StartsWith("-", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine("Unknown option: " + a);
                        return 2;
                    }
                    else path = a;
                }
            }
            catch (FormatException)
            {
                Console.Error.WriteLine("--depth and --top take a whole number.");
                return 2;
            }
            if (path == null)
            {
                Usage();
                return 2;
            }
            if (noProtect && (protect || coverage || protectHome != null))
            {
                Console.Error.WriteLine("--no-protect cannot be combined with --protect, --coverage or --protect-home.");
                return 2;
            }
            // The content scan runs only when asked for on this command line. protect.json's switch is the app's
            // consent and never implies it here.
            if (content && !protect)
            {
                Console.Error.WriteLine("--content needs --protect.");
                return 2;
            }

            try
            {
                path = Scanner.NormalizePath(path);
                if (protectHome != null) protectHome = Path.GetFullPath(protectHome);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Not a valid path: " + ex.Message);
                return 2;
            }
            if (!Directory.Exists(path))
            {
                Console.Error.WriteLine("Folder not found: " + path);
                return 2;
            }

            var scanner = new Scanner();
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };
            Task<ScanResult> task = Task.Run(() => scanner.Scan(path, cts.Token));
            bool showProgress = !Console.IsErrorRedirected;
            while (!task.Wait(400))
            {
                if (showProgress)
                    Console.Error.Write(("\rScanning... " + Fmt.Count(Interlocked.Read(ref scanner.FilesFound)) + " files, " +
                                         Fmt.Size(Interlocked.Read(ref scanner.BytesFound))).PadRight(60));
            }
            if (showProgress) Console.Error.Write("\r" + new string(' ', 60) + "\r");
            ScanResult r = task.Result;
            if (r == null)
            {
                Console.Error.WriteLine("Scan cancelled.");
                return 1;
            }
            long scanMs = (long)r.Elapsed.TotalMilliseconds;  // measured by the scanner, not by the 400 ms progress loop

            // As in the app: the drive list and the Protect context are built once, before the first Analyze,
            // so Analyze itself does no I/O.
            Stopwatch clock = Stopwatch.StartNew();
            List<DriveProfile> drives = Drives.Load();
            if (!noProtect)
                r.Protect = protectHome != null ? ProtectContext.ForTree(protectHome)
                    : ProtectContext.ForMachine(path, Placement.ExternalRoots(drives));
            long contextMs = clock.ElapsedMilliseconds;

            clock.Restart();
            r.Analyze();
            long analyzeMs = clock.ElapsedMilliseconds;

            // The content scan, only with --content. Its consent comes from this command line alone.
            long planMs = 0, contentMs = 0;
            ContentPlan plan = null;
            ContentProgress progress = null;
            bool stopped = false;
            ProtectStore store = protect ? ProtectStore.Load(ProtectStore.DefaultPath) : null;
            if (content && r.Protect != null)
            {
                clock.Restart();
                plan = SecretScan.Plan(r, store, null);
                planMs = clock.ElapsedMilliseconds;

                clock.Restart();
                progress = new ContentProgress();
                ContentConsent consent = ContentConsent.FromCommandLine(true);
                ContentPlan work = plan;
                ContentProgress p = progress;
                Task<ContentResult> job = Task.Run(() => SecretScan.Run(consent, work, p, cts.Token));
                while (!job.Wait(400))
                {
                    if (showProgress)
                        Console.Error.Write(("\rReading text files... " + Fmt.Count(Interlocked.Read(ref p.DoneFiles)) + " of " +
                                             Fmt.Count(plan.Files.Length) + " files").PadRight(60));
                }
                if (showProgress) Console.Error.Write("\r" + new string(' ', 60) + "\r");
                ContentResult done = job.Result;
                r.ContentFindings.AddRange(done.Findings);
                r.ContentNodes.AddRange(done.Nodes);
                stopped = done.Cancelled;
                contentMs = clock.ElapsedMilliseconds;
            }

            long coverageMs = 0;
            if (protect)
            {
                PrintProtect(r, store, all, reasons, progress);
                if (stopped)
                {
                    Console.WriteLine("Stopped after " + Fmt.Count(Interlocked.Read(ref progress.DoneFiles)) + " of " +
                                      Fmt.Count(plan.Files.Length) + " files.");
                }
                else if (coverage) coverageMs = PrintCoverage(r, protectHome != null ? null : drives, cts.Token);
            }
            if (moves)
            {
                if (protect) Console.WriteLine();
                PrintMoves(r, drives);
            }
            if (!protect && !moves)
            {
                Print(r, top, depth);
                if (csv != null)
                {
                    int rows = Export.WriteFolderCsv(r.Root, csv);
                    Console.WriteLine();
                    Console.WriteLine("Wrote " + Fmt.Count(rows) + " folders to " + Path.GetFullPath(csv));
                }
            }

            if (timing)
            {
                Console.Error.WriteLine("scan_ms " + scanMs);
                Console.Error.WriteLine("context_ms " + contextMs);
                Console.Error.WriteLine("analyze_ms " + analyzeMs);
                Console.Error.WriteLine("coverage_ms " + coverageMs);
                // Counts only: the content scan reports no path and no value here.
                Console.Error.WriteLine("plan_ms " + planMs);
                Console.Error.WriteLine("content_ms " + contentMs);
                Console.Error.WriteLine("candidates " + (plan != null ? plan.Files.Length
                    : r.ContentCandidates != null ? r.ContentCandidates.Length : 0));
                Console.Error.WriteLine("files_opened " + Counter(progress, 0));
                Console.Error.WriteLine("bytes_read " + Counter(progress, 1));
                Console.Error.WriteLine("skipped_binary " + Counter(progress, 2));
                Console.Error.WriteLine("skipped_utf16 " + Counter(progress, 3));
                Console.Error.WriteLine("skipped_large " + Counter(progress, 4));
                Console.Error.WriteLine("skipped_unreadable " + Counter(progress, 5));
            }
            return stopped ? 1 : 0;
        }

        // One content scan counter for --timing; 0 when the content scan did not run.
        static long Counter(ContentProgress p, int which)
        {
            if (p == null) return 0;
            switch (which)
            {
                case 0: return Interlocked.Read(ref p.FilesOpened);
                case 1: return Interlocked.Read(ref p.BytesRead);
                case 2: return Interlocked.Read(ref p.SkippedBinary);
                case 3: return Interlocked.Read(ref p.SkippedUtf16);
                case 4: return Interlocked.Read(ref p.SkippedTooLarge);
                default: return Interlocked.Read(ref p.SkippedUnreadable);
            }
        }

        // One file on the Protect list: its findings by name and by content, joined on the normalized path as the
        // page joins them (spec 5.3). Only visible findings are on a card; hidden ones are listed apart.
        sealed class CliCard
        {
            public string Path;
            public readonly List<Finding> ByName = new List<Finding>();
            public readonly List<Finding> ByContent = new List<Finding>();
            public long Size;
            public FindingTier Tier = FindingTier.WorthALook;
            public Place Place = Place.Other;
            public bool PlaceSet;
            public int Group;
        }

        // Findings: to review first (by place, then Confirmed before Likely, then largest first), then the ones in
        // their usual places, then .env files in projects, then the ones the user hid. Without --all the last
        // three groups give one count line each. A file found both by name and by content is one entry, with its
        // content matches listed under it by line. A key itself is never printed.
        static void PrintProtect(ScanResult r, ProtectStore store, bool all, bool reasons, ContentProgress progress)
        {
            bool contentRan = progress != null;
            long read = contentRan ? Interlocked.Read(ref progress.DoneFiles) : 0;
            Console.WriteLine(ProtectInfo.CliHeader(contentRan, read, ProtectConstants.ContentRules.Length) +
                              " Paths can contain names and account numbers.");
            if (r.Protect == null) return;

            var cards = new Dictionary<string, CliCard>(StringComparer.Ordinal);
            var order = new List<CliCard>();
            var hiddenName = new List<int>();  // indexes into r.Findings
            var hiddenContent = new List<Finding>();
            for (int i = 0; i < r.Findings.Count; i++)
            {
                Finding f = r.Findings[i];
                if (store.IsHidden(f)) { hiddenName.Add(i); continue; }
                CliCard c = CardFor(cards, order, f);
                c.ByName.Add(f);
                if (!c.PlaceSet) { c.Place = f.Place; c.PlaceSet = true; }  // a by-name finding's place wins (spec 5.2)
                Node n = i < r.FindingNodes.Count ? r.FindingNodes[i] : null;
                if (n != null) c.Size = Math.Max(c.Size, n.Size);
                if (f.Tier < c.Tier) c.Tier = f.Tier;
            }
            for (int i = 0; i < r.ContentFindings.Count; i++)
            {
                Finding f = r.ContentFindings[i];
                if (store.IsHidden(f)) { hiddenContent.Add(f); continue; }
                CliCard c = CardFor(cards, order, f);
                c.ByContent.Add(f);
                Node n = i < r.ContentNodes.Count ? r.ContentNodes[i] : null;
                if (n != null) c.Size = Math.Max(c.Size, n.Size);
                if (f.Tier < c.Tier) c.Tier = f.Tier;
            }

            var review = new List<CliCard>();
            var usual = new List<CliCard>();
            var projects = new List<CliCard>();
            foreach (CliCard c in order)
            {
                c.ByContent.Sort(ByTierThenLine);
                if (!c.PlaceSet) { c.Place = c.ByContent[0].Place; c.PlaceSet = true; }
                bool hasUsual = false, allEnvSecret = true, dotenvByName = false;
                foreach (Finding f in c.ByName)
                {
                    if (f.Place == Place.UsualPlace) hasUsual = true;
                    if (f.PatternId == "dotenv") dotenvByName = true;
                }
                foreach (Finding f in c.ByContent)
                {
                    if (f.Place == Place.UsualPlace) hasUsual = true;
                    if (f.PatternId != "env-secret") allEnvSecret = false;
                }
                // A repository dotenv file whose only content findings are env-secret (spec 5.3).
                bool onlyEnvSecretInRepo = c.Place == Place.Repository && allEnvSecret && (dotenvByName || c.ByContent.Count > 0);
                Finding lead = c.ByName.Count > 0 ? c.ByName[0] : c.ByContent[0];
                c.Group = ProtectInfo.GroupOf(lead, hasUsual, onlyEnvSecretInRepo);
                if (c.Group == ProtectInfo.GroupUsual) usual.Add(c);
                else if (c.Group == ProtectInfo.GroupProjects) projects.Add(c);
                else review.Add(c);
            }
            Comparison<CliCard> byPlace = (a, b) =>
            {
                int k = PlaceRank(a.Place).CompareTo(PlaceRank(b.Place));
                if (k != 0) return k;
                k = a.Tier.CompareTo(b.Tier);
                if (k != 0) return k;
                k = b.Size.CompareTo(a.Size);
                if (k != 0) return k;
                return string.Compare(a.Path, b.Path, StringComparison.OrdinalIgnoreCase);
            };
            review.Sort(byPlace);
            usual.Sort(byPlace);
            projects.Sort(byPlace);
            // Hidden by-name rows keep the stage 1 order: place, tier, largest first, then path.
            hiddenName.Sort((a, b) =>
            {
                Finding fa = r.Findings[a], fb = r.Findings[b];
                int k = PlaceRank(fa.Place).CompareTo(PlaceRank(fb.Place));
                if (k != 0) return k;
                k = fa.Tier.CompareTo(fb.Tier);
                if (k != 0) return k;
                k = SizeOf(r, b).CompareTo(SizeOf(r, a));
                if (k != 0) return k;
                return string.Compare(fa.Path, fb.Path, StringComparison.OrdinalIgnoreCase);
            });
            hiddenContent.Sort(ByTierThenLine);

            foreach (CliCard c in review) PrintCard(c, null, reasons);
            if (all)
            {
                foreach (CliCard c in usual) PrintCard(c, "usual", reasons);
                foreach (CliCard c in projects) PrintCard(c, "project", reasons);
                foreach (int i in hiddenName) Console.WriteLine(Row(r.Findings[i], "hidden"));
                foreach (Finding f in hiddenContent) Console.WriteLine(ContentRow(f) + "  hidden");
            }

            Console.WriteLine();
            Console.WriteLine(review.Count == 0 ? "Nothing to review." : review.Count + (review.Count == 1 ? " file to review." : " files to review."));
            if (contentRan)
            {
                // Distinct (file, pattern) pairs among the visible content findings on counted entries (spec 5.4).
                int pairs = 0, withKeys = 0;
                foreach (CliCard c in review)
                {
                    var seen = new HashSet<string>(StringComparer.Ordinal);
                    foreach (Finding f in c.ByContent) seen.Add(f.PatternId);
                    pairs += seen.Count;
                    if (seen.Count > 0) withKeys++;
                }
                Console.WriteLine(pairs == 0 ? "Keys in text: none found." :
                    "Keys in text: " + pairs + (withKeys == 1 ? ", in 1 file." : ", in " + withKeys + " files."));
            }
            int hidden = hiddenName.Count + hiddenContent.Count;
            if (!all)
            {
                if (usual.Count > 0) Console.WriteLine(usual.Count + " in their usual places (--all lists them).");
                if (projects.Count > 0) Console.WriteLine(projects.Count + " .env files in your projects (--all lists them).");
                if (hidden > 0) Console.WriteLine(hidden + " hidden by you (--all lists them).");
            }
        }

        static CliCard CardFor(Dictionary<string, CliCard> cards, List<CliCard> order, Finding f)
        {
            string key = ProtectStore.Normalize(f.Path);
            CliCard c;
            if (!cards.TryGetValue(key, out c))
            {
                c = new CliCard();
                c.Path = f.Path;
                cards.Add(key, c);
                order.Add(c);
            }
            return c;
        }

        // A file's by-name rows (or, for a file found only by content, one row naming its strongest match), then
        // one line per content match: "  line 12:5  GitHub token  Confirmed  <place>  <path>".
        static void PrintCard(CliCard c, string mark, bool reasons)
        {
            if (c.ByName.Count > 0)
                foreach (Finding f in c.ByName) Console.WriteLine(Row(f, mark));
            else
                Console.WriteLine(Row(Strongest(c.ByContent), mark));
            foreach (Finding f in c.ByContent)
            {
                Console.WriteLine(ContentRow(f));
                if (reasons)
                {
                    ContentRuleInfo rule = RuleOf(f.PatternId);
                    if (rule != null) Console.WriteLine("      " + rule.Reason);
                }
            }
        }

        static string ContentRow(Finding f)
        {
            return "  line " + f.Line + ":" + f.Column + "  " + f.Kind + "  " + f.Tier + "  " + f.Place + "  " + f.Path;
        }

        // Tier first, then path, then line and column.
        static int ByTierThenLine(Finding a, Finding b)
        {
            int k = a.Tier.CompareTo(b.Tier);
            if (k != 0) return k;
            k = string.Compare(a.Path, b.Path, StringComparison.OrdinalIgnoreCase);
            if (k != 0) return k;
            k = a.Line.CompareTo(b.Line);
            return k != 0 ? k : a.Column.CompareTo(b.Column);
        }

        // The strongest content match: by tier, then by the order of the pattern table (spec 5.3).
        static Finding Strongest(List<Finding> found)
        {
            Finding best = null;
            foreach (Finding f in found)
            {
                if (best == null || f.Tier < best.Tier || (f.Tier == best.Tier && RuleIndex(f.PatternId) < RuleIndex(best.PatternId)))
                    best = f;
            }
            return best;
        }

        static int RuleIndex(string id)
        {
            ContentRuleInfo[] rules = ProtectConstants.ContentRules;
            for (int i = 0; i < rules.Length; i++)
                if (rules[i].Id == id) return i;
            return rules.Length;
        }

        static ContentRuleInfo RuleOf(string id)
        {
            int i = RuleIndex(id);
            return i < ProtectConstants.ContentRules.Length ? ProtectConstants.ContentRules[i] : null;
        }

        static string Row(Finding f, string mark)
        {
            string line = f.Tier + "\t" + f.Kind + "\t" + f.Place + "\t" + f.Path;
            return mark == null ? line : line + "\t" + mark;
        }

        static long SizeOf(ScanResult r, int i)
        {
            if (r.FindingNodes == null || i >= r.FindingNodes.Count || r.FindingNodes[i] == null) return 0;
            return r.FindingNodes[i].Size;
        }

        static int PlaceRank(Place p)
        {
            switch (p)
            {
                case Place.Downloads: return 0;
                case Place.Desktop: return 1;
                case Place.Temp: return 2;
                case Place.Synced: return 3;
                case Place.HomeFolder: return 4;
                case Place.ExternalDrive: return 5;
                case Place.Other: return 6;
                case Place.Repository: return 7;
                default: return 8;  // UsualPlace
            }
        }

        // Returns the milliseconds the check took. With --protect-home, drives is null: a fixture tree is checked
        // against no real drive, so nothing outside the fixture is listed or printed.
        static long PrintCoverage(ScanResult r, List<DriveProfile> drives, CancellationToken ct)
        {
            Console.WriteLine();
            Console.WriteLine("This lists folders on your other drives and may wake a sleeping external drive.");
            List<CoverageDrive> covDrives = drives == null ? new List<CoverageDrive>() : Placement.CoverageDrives(drives);
            List<CoverageSource> sources = ProtectCoverage.Snapshot(r, r.Protect, Placement.PersonalCandidates(r), covDrives);
            CoverageReport report = ProtectCoverage.Compute(sources, covDrives, Placement.IsBackupName,
                new Dictionary<string, CopyCheck>(), ct);
            if (report.NoDrivesReason != null) Console.WriteLine(report.NoDrivesReason);
            foreach (FolderCoverage fc in report.Folders)
            {
                string copy = fc.Best == null ? "-" : fc.Best.Path;
                string newest = fc.Best == null || fc.Best.NewestUtc == DateTime.MinValue ? "-"
                    : fc.Best.NewestUtc.ToLocalTime().ToString("yyyy-MM-dd");
                string line = fc.State + "\t" + fc.Source.Path + "\t" + copy + "\t" + fc.Source.Files + "\t" + newest;
                if (fc.State == CoverageState.NotChecked && fc.NotCheckedReason != null) line += "\t" + fc.NotCheckedReason;
                Console.WriteLine(line);
            }
            Console.WriteLine();
            Console.WriteLine(report.Folders.Count + " folders checked on the drives connected now: " + report.WithoutCurrentCopy +
                " without a current copy (" + Fmt.Size(report.WithoutCurrentCopyBytes) + "), " + report.NotCheckedCount + " not checked.");
            return (long)report.Took.TotalMilliseconds;
        }

        static void PrintMoves(ScanResult r, List<DriveProfile> drives)
        {
            Console.WriteLine("Drives");
            foreach (DriveProfile d in drives)
                Console.WriteLine("  {0,-14} {1,-18} {2,-6} {3,10} free of {4,-10} {5}", d.Name, d.Kind, d.FileSystem, Fmt.Size(d.Free), Fmt.Size(d.Total), d.Purpose);

            List<MoveSuggestion> found = Placement.Suggest(r, drives);
            Console.WriteLine();
            Console.WriteLine(found.Count == 0 ? "Nothing in " + r.Root.FullPath + " would be better on another drive." : "Better on another drive");
            foreach (MoveSuggestion s in found)
            {
                string action = s.AlreadyCopied ? "already copied" : s.Action == MoveAction.Copy ? "copy" : s.Action == MoveAction.Move ? "move"
                    : s.Action == MoveAction.WslMove ? "wsl --move" : "move in its app";
                Console.WriteLine();
                Console.WriteLine("  {0,10}  {1}  [{2}]", Fmt.Size(s.Item.Size), s.Item.FullPath, s.KindName);
                Console.WriteLine("              {0} to {1}  ({2})", action, s.Destination, s.Usage);
                Console.WriteLine("              " + s.Reason);
            }
        }

        static void Print(ScanResult r, int top, int depth)
        {
            DirNode root = r.Root;
            DirNode unaccounted = r.UnaccountedNode;
            long scanned = root.Size - (unaccounted == null ? 0 : unaccounted.Size);

            Console.WriteLine("Scanned " + root.Name + " in " + Fmt.Duration(r.Elapsed));
            Console.WriteLine();
            Field("Found", Fmt.Size(scanned) + " (" + Fmt.Count(scanned) + " bytes) in " +
                           Fmt.Count(root.FileCount) + " files and " + Fmt.Count(root.DirCount) + " folders");
            if (r.DriveTotal > 0)
                Field("Drive", Fmt.Size(r.DriveTotal - r.DriveFree) + " used, " + Fmt.Size(r.DriveFree) + " free of " + Fmt.Size(r.DriveTotal));
            if (unaccounted != null)
                Field("Unaccounted", Fmt.Size(unaccounted.Size) + " in use on the drive but not found by the scan");
            if (r.OnlineOnlyFiles > 0)
                Field("Online-only", Fmt.Size(r.OnlineOnlyBytes) + " in " + Fmt.Count(r.OnlineOnlyFiles) +
                                     " cloud files that are not stored on this PC (not counted)");
            if (r.UnreadableCount > 0)
                Field("Unreadable", Fmt.Count(r.UnreadableCount) + " folders (run as administrator to include them)");

            Section("Largest folders");
            PrintTree(root, 0, depth, top, root.Size);

            Section("Largest files");
            for (int i = 0; i < Math.Min(top, r.LargestFiles.Count); i++)
            {
                FileNode f = r.LargestFiles[i];
                Console.WriteLine("  {0,10}  {1}", Fmt.Size(f.Size), f.FullPath);
            }

            Section("Space by type");
            for (int c = 0; c < Categories.Count; c++)
            {
                if (r.CategoryBytes[c] <= 0) continue;
                Console.WriteLine("  {0,10}  {1,6}  {2}", Fmt.Size(r.CategoryBytes[c]), Fmt.Percent(r.CategoryBytes[c], root.Size), Categories.Names[c]);
            }

            Section("Top extensions");
            var exts = new List<ExtInfo>(r.Extensions);
            exts.Sort((a, b) => b.Size.CompareTo(a.Size));
            for (int i = 0; i < Math.Min(top, exts.Count); i++)
            {
                ExtInfo x = exts[i];
                Console.WriteLine("  {0,10}  {1,6}  {2,-16} {3,12} files  {4}", Fmt.Size(x.Size), Fmt.Percent(x.Size, root.Size),
                    x.Key, Fmt.Count(x.Count), Categories.Names[(int)x.Category]);
            }
        }

        static void PrintTree(DirNode d, int level, int maxLevel, int top, long total)
        {
            string name = level == 0 || d.Unaccounted ? d.Name : d.Name + "\\";
            Console.WriteLine("  {0,10}  {1,6}  {2}{3}", Fmt.Size(d.Size), Fmt.Percent(d.Size, total), new string(' ', level * 2), name);
            if (level >= maxLevel) return;
            int shown = 0;
            foreach (Node child in d.Children)
            {
                var sub = child as DirNode;
                if (sub == null || sub.Size == 0) continue;
                if (shown++ == top) break;
                PrintTree(sub, level + 1, maxLevel, top, total);
            }
        }

        static void Field(string label, string value)
        {
            Console.WriteLine("  " + label.PadRight(13) + value);
        }

        static void Section(string title)
        {
            Console.WriteLine();
            Console.WriteLine(title);
        }
    }
}

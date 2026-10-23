using System;
using System.Collections.Generic;
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
            Console.WriteLine();
            Console.WriteLine("  --depth N   how many folder levels to list (default 2)");
            Console.WriteLine("  --top N     how many entries to show per list and per folder (default 10)");
            Console.WriteLine("  --csv FILE  also write every folder with its size to a CSV file");
            Console.WriteLine("  --moves     only list your drives and what would be better kept on another drive");
            Console.WriteLine();
            Console.WriteLine("Example: dsa C: --depth 3 --top 15");
        }

        public static int Run(string[] args)
        {
            string path = null, csv = null;
            int top = 10, depth = 2;
            bool moves = false;
            try
            {
                for (int i = 0; i < args.Length; i++)
                {
                    string a = args[i];
                    if (a == "--depth" && i + 1 < args.Length) depth = int.Parse(args[++i]);
                    else if (a == "--top" && i + 1 < args.Length) top = int.Parse(args[++i]);
                    else if (a == "--csv" && i + 1 < args.Length) csv = args[++i];
                    else if (a == "--moves") moves = true;
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

            try { path = Scanner.NormalizePath(path); }
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
            r.Analyze();
            if (moves)
            {
                PrintMoves(r);
                return 0;
            }
            Print(r, top, depth);

            if (csv != null)
            {
                int rows = Export.WriteFolderCsv(r.Root, csv);
                Console.WriteLine();
                Console.WriteLine("Wrote " + Fmt.Count(rows) + " folders to " + Path.GetFullPath(csv));
            }
            return 0;
        }

        static void PrintMoves(ScanResult r)
        {
            List<DriveProfile> drives = Drives.Load();
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

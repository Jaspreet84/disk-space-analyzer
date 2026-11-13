using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using DiskSpace;

// Tests for the Protect page: the Finding type, the store, the explanation text and the trust checker
// (stage 0), and for stage 1: the by-name corpus, the folder walk in Analyze, refresh after Replace, logical
// bytes, backup coverage and the cost of the per-file gate. Run with tests\run-tests.ps1, which compiles this
// with the app's source and tools\CheckTrust.cs.
//
// Every folder these tests create is under the work folder (obj\tests) or %TEMP%. No test opens a file it did
// not write itself.
static class ProtectTests
{
    static int fails;
    static string work, csc;

    static void Check(bool ok, string what)
    {
        Console.WriteLine((ok ? "PASS  " : "FAIL  ") + what);
        if (!ok) fails++;
    }

    static int Main(string[] args)
    {
        work = args[0];
        csc = args[1];
        string repo = args[2];
        string tree = args.Length > 3 ? args[3] : null;
        Directory.CreateDirectory(work);

        FindingHasNoRoomForAValue();
        StoreKeepsHashesOnly();
        TrustedFoldersCoverTheirContents();
        ExplanationComesFromTheConstants();
        CheckerCatchesNetworkCode(repo);
        CorpusFilesParse(repo);

        Corpus corpus = Corpus.Load(Path.Combine(repo, @"tests\protect-corpus\by-name\cases.tsv"));
        PatternTable();
        CorpusCounts(corpus);
        CorpusGate(corpus);
        ForTreeMatchesTheHeader(corpus);
        TreeEquality(corpus);
        DriveTrees(corpus);
        FixtureTreeOnDisk(corpus, tree);
        RootCases();
        ScannedDocumentsNeedADocument();
        Refresh(corpus);
        LogicalBytes();
        StoreHidesAndTrusts();
        DescribeStage1();
        Coverage();
        SyntheticTiming();

        Console.WriteLine(fails == 0 ? "All checks passed." : fails + " check(s) failed.");
        return fails;
    }

    // ---------------------------------------------------------------------------------------------------
    // Stage 0

    static void FindingHasNoRoomForAValue()
    {
        var allowed = new HashSet<string> { "PatternId", "Tier", "Path", "Line", "Column", "Place" };
        var names = new List<string>();
        foreach (FieldInfo f in typeof(Finding).GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            names.Add(f.Name);
        Check(names.Count == allowed.Count && names.TrueForAll(allowed.Contains),
            "Finding has exactly the fields PatternId, Tier, Path, Line, Column, Place (" + string.Join(", ", names) + ")");
        foreach (FieldInfo f in typeof(Finding).GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            Check(f.IsInitOnly, "Finding." + f.Name + " is read-only");
    }

    static void StoreKeepsHashesOnly()
    {
        string file = Path.Combine(work, "store", "protect.json");
        string secretPath = @"C:\Users\zq7plarkwood\Downloads\xkwq-vault-export\id_rsa_personal";
        var finding = new Finding("ssh-private-key", FindingTier.Confirmed, secretPath, 0, 0, Place.Downloads);

        var store = new ProtectStore();
        store.ContentScan = true;
        store.Dismiss(finding);
        store.Trust(@"D:\zq7plarkwood-projects");
        store.Save(file);
        string text = File.ReadAllText(file);

        string[] fragments = { "zq7plarkwood", "xkwq-vault-export", "id_rsa_personal", "Downloads", "ssh-private-key" };
        foreach (string fragment in fragments)
            Check(text.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) < 0, "protect.json does not contain \"" + fragment + "\"");

        ProtectStore back = ProtectStore.Load(file);
        Check(back.ContentScan, "the content-scan setting survives a reload");
        Check(back.IsDismissed(finding), "a dismissed finding is still dismissed after a reload");
        Check(back.IsDismissed(new Finding("ssh-private-key", FindingTier.Likely, secretPath.ToLowerInvariant().Replace('\\', '/'), 0, 0, Place.Other)),
            "dismissal ignores case, slashes and tier");
        Check(!back.IsDismissed(new Finding("aws-access-key", FindingTier.Confirmed, secretPath, 0, 0, Place.Downloads)),
            "a different pattern on the same file is not dismissed");
        back.Undismiss(finding);
        Check(!back.IsDismissed(finding), "undismiss works");
        Check(ProtectStore.Normalize(@"c:/foo/../bar\") == ProtectStore.Normalize(@"C:\BAR"), "paths normalise to one form");

        ProtectStore missing = ProtectStore.Load(Path.Combine(work, "nowhere", "protect.json"));
        Check(!missing.ContentScan && missing.DismissedCount == 0, "a missing store loads as empty with the content scan off");
        File.WriteAllText(file, "{ this is not json");
        Check(ProtectStore.Load(file).DismissedCount == 0, "a damaged store loads as empty instead of failing");
    }

    static void TrustedFoldersCoverTheirContents()
    {
        var store = new ProtectStore();
        store.Trust(@"D:\Projects\old");
        Check(store.IsUnderTrusted(@"D:\Projects\old\api\.env"), "a file deep inside a trusted folder is covered");
        Check(store.IsUnderTrusted(@"d:/projects/OLD"), "the trusted folder itself is covered, in any spelling");
        Check(!store.IsUnderTrusted(@"D:\Projects\older\.env"), "a sibling folder with a longer name is not covered");
        Check(!store.IsUnderTrusted(@"D:\Projects\.env"), "the parent folder is not covered");
        store.Untrust(@"D:\Projects\old");
        Check(!store.IsUnderTrusted(@"D:\Projects\old\api\.env"), "untrust works");
    }

    static void ExplanationComesFromTheConstants()
    {
        string text = ProtectInfo.AsText();
        Check(text.Contains(ProtectStore.DefaultPath), "the explanation names the store file");
        Check(text.Contains("check-trust.ps1"), "the explanation says how to repeat the network check");
        bool contentExists = Array.Exists(ProtectConstants.Patterns, p => p.ReadsContent == "content");
        Check(contentExists == text.Contains(Fmt.Size(ProtectConstants.MaxContentBytes)),
            "the content-scan section appears only when the build has content patterns");
        Check(contentExists || text.Contains("does not read file contents"), "without content patterns, the explanation says so");
    }

    // Compiles two throwaway programs: one that uses the network and one that only mentions "System.Net"
    // in a sentence. The checker must flag the first and pass the second, and pass the real programs.
    static void CheckerCatchesNetworkCode(string repo)
    {
        string netSource = Path.Combine(work, "planted-net.cs"), netExe = Path.Combine(work, "planted-net.exe");
        File.WriteAllText(netSource,
            "class P { static void Main() { var c = new System.Net.Http.HttpClient(); System.Console.WriteLine(c.Timeout); } }");
        Check(Compile(netSource, netExe, "/r:System.Net.Http.dll"), "a planted program using HttpClient compiles");
        List<string> names = TrustCheck.NetworkNames(netExe);
        Check(names.Count > 0, "the checker flags the planted network program (" + names.Count + " names)");

        string textSource = Path.Combine(work, "planted-text.cs"), textExe = Path.Combine(work, "planted-text.exe");
        File.WriteAllText(textSource,
            "class P { static void Main() { System.Console.WriteLine(\"This program has no System.Net.Http code, honest.\"); } }");
        Check(Compile(textSource, textExe, null), "a program that only mentions System.Net in text compiles");
        Check(TrustCheck.NetworkNames(textExe).Count == 0, "the checker ignores a sentence that mentions System.Net");

        string sockets = Path.Combine(work, "planted-sockets.cs"), socketsExe = Path.Combine(work, "planted-sockets.exe");
        File.WriteAllText(sockets, "class P { static void Main() { var s = new System.Net.Sockets.TcpClient(); s.Close(); } }");
        Check(Compile(sockets, socketsExe, null), "a planted program using sockets compiles");
        Check(TrustCheck.NetworkNames(socketsExe).Count > 0, "the checker flags sockets, which live in System.dll");

        foreach (string exe in new[] { "DiskSpaceAnalyzer.exe", "dsa.exe" })
        {
            string path = Path.Combine(repo, "bin", exe);
            if (!File.Exists(path)) continue;
            Check(TrustCheck.NetworkNames(path).Count == 0, exe + " names no System.Net type");
        }
    }

    static void CorpusFilesParse(string repo)
    {
        foreach (string name in new[] { @"by-name\cases.tsv", @"by-content\cases.tsv" })
        {
            string file = Path.Combine(repo, "tests", "protect-corpus", name);
            if (!File.Exists(file))
            {
                Check(false, "corpus file exists: " + name);
                continue;
            }
            int rows = 0, bad = 0;
            foreach (string line in File.ReadAllLines(file))
            {
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                if (line.Split('\t').Length != 4) bad++;
                else rows++;
            }
            Check(bad == 0, name + " parses (" + rows + " cases)");
        }
    }

    static bool Compile(string source, string exe, string extra)
    {
        var p = Process.Start(new ProcessStartInfo(csc, "/nologo /target:exe \"/out:" + exe + "\" " + (extra ?? "") + " \"" + source + "\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true
        });
        p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return p.ExitCode == 0 && File.Exists(exe);
    }

    // ---------------------------------------------------------------------------------------------------
    // Stage 1: the pattern table

    static readonly string[] ExpectedIds =
    {
        "ssh-key", "ssh-ppk", "pem-key", "pkcs12", "java-keystore", "password-vault", "password-export", "git-credentials",
        "netrc", "aws-credentials", "aws-keys-csv", "azure-tokens", "gcloud-credentials", "gh-hosts", "kubeconfig",
        "docker-config", "npm-rc", "pypi-rc", "cli-auth-file", "dotnet-user-secrets", "terraform-credentials", "tfstate",
        "dotenv", "pgp-secret", "pgpass", "crypto-wallet", "eth-keystore", "electrum-wallet", "recovery-codes",
        "emergency-kit", "publish-settings", "htpasswd",
        "doc-tax-file", "doc-tax", "doc-statement", "doc-pay", "doc-id", "doc-scans-folder"
    };

    static void PatternTable()
    {
        PatternInfo[] p = ProtectConstants.Patterns;
        bool order = p.Length == ExpectedIds.Length;
        for (int i = 0; order && i < p.Length; i++) order = p[i].Id == ExpectedIds[i];
        Check(order, "Patterns has the 38 stage 1 rows in table order (" + p.Length + " rows)");
        Check(Array.TrueForAll(p, x => x.ReadsContent == "name"), "every stage 1 row reads names only");
        Check(Array.TrueForAll(p, x => !string.IsNullOrEmpty(x.Kind)), "every row has a Kind");

        NameRuleInfo[] rules = ProtectConstants.NameRules;
        bool same = rules.Length == p.Length;
        for (int i = 0; same && i < rules.Length; i++) same = rules[i].Id == p[i].Id && !string.IsNullOrEmpty(rules[i].Usual);
        Check(same, "NameRules has one entry per Patterns row, in the same order");

        var ids = new HashSet<string>();
        foreach (PatternInfo x in p) ids.Add(x.Id);
        Check(!ids.Contains("cargo-credentials") && !ids.Contains("nuget-config"), "the rows that wait for later stages have no PatternInfo");
        Check(ProtectConstants.LaterStages.Length > 0, "LaterStages lists what waits for later stages");
    }

    // ---------------------------------------------------------------------------------------------------
    // Stage 1: the by-name corpus

    sealed class Case
    {
        public int Line;
        public string Raw, FullPath, Expect, Tier, Place;
        public long Size = 4096;
        public bool Online, Folder, Relative;
        public List<string> Siblings;
        public bool Positive { get { return Expect != "none"; } }
    }

    sealed class Corpus
    {
        public string Home, Roaming, Local;
        public readonly List<string> Downloads = new List<string>(), Desktop = new List<string>(), Documents = new List<string>(),
            Pictures = new List<string>(), Temp = new List<string>(), Sync = new List<string>(), External = new List<string>(),
            Repo = new List<string>();
        public readonly List<Case> Cases = new List<Case>();

        public static Corpus Load(string file)
        {
            var c = new Corpus();
            long size = 4096;
            bool online = false;
            List<string> siblings = null;
            int n = 0;
            foreach (string line in File.ReadAllLines(file))
            {
                n++;
                if (line.Length == 0) continue;
                if (line.StartsWith("#!", StringComparison.Ordinal))
                {
                    string rest = line.Substring(2).Trim();
                    int cut = rest.IndexOf(' ');
                    string word = cut < 0 ? rest : rest.Substring(0, cut);
                    string arg = cut < 0 ? "" : rest.Substring(cut + 1).Trim();
                    switch (word)
                    {
                        case "home": c.Home = arg; break;
                        case "roaming": c.Roaming = arg; break;
                        case "local": c.Local = arg; break;
                        case "downloads": c.Downloads.Add(arg); break;
                        case "desktop": c.Desktop.Add(arg); break;
                        case "documents": c.Documents.Add(arg); break;
                        case "pictures": c.Pictures.Add(arg); break;
                        case "temp": c.Temp.Add(arg); break;
                        case "sync": c.Sync.Add(arg); break;
                        case "external": c.External.Add(arg); break;
                        case "repo": c.Repo.Add(arg); break;
                        case "size": size = long.Parse(arg); break;
                        case "online": online = true; break;
                        case "siblings": siblings = new List<string>(arg.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)); break;
                        default: throw new InvalidDataException("Unknown directive on line " + n + ": " + word);
                    }
                    continue;
                }
                if (line.StartsWith("#", StringComparison.Ordinal)) continue;
                string[] cols = line.Split('\t');
                var k = new Case { Line = n, Raw = cols[0], Expect = cols[1], Tier = cols[2], Place = cols[3], Size = size, Online = online, Siblings = siblings };
                size = 4096;
                online = false;
                siblings = null;
                k.Folder = k.Raw.EndsWith("/", StringComparison.Ordinal);
                string p = k.Raw.TrimEnd('/').Replace('/', '\\');
                k.Relative = !(p.Length >= 3 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\');
                k.FullPath = k.Relative ? c.Home + "\\" + p : p;
                c.Cases.Add(k);
            }
            return c;
        }

        public ProtectContext Context(bool driveRoots)
        {
            return new ProtectContext(Home, Roaming, Local, Pick(Downloads, driveRoots), Pick(Desktop, driveRoots),
                Pick(Documents, driveRoots), Pick(Pictures, driveRoots), new string[0], new string[0], Pick(Temp, driveRoots),
                Pick(Sync, driveRoots), driveRoots ? External.ToArray() : new string[0], Pick(Repo, driveRoots), null, false);
        }

        // Without drive roots: only the entries inside the pretend user folder, which is what ForTree gives.
        public string[] Pick(List<string> list, bool driveRoots)
        {
            var keep = new List<string>();
            foreach (string s in list)
                if (driveRoots || UnderOrSame(s, Home)) keep.Add(s);
            return keep.ToArray();
        }
    }

    static bool UnderOrSame(string path, string folder)
    {
        string p = ProtectStore.Normalize(path), f = ProtectStore.Normalize(folder);
        return p == f || p.StartsWith(f.EndsWith("\\", StringComparison.Ordinal) ? f : f + "\\", StringComparison.Ordinal);
    }

    static string Got(Finding f)
    {
        return f == null ? "none\t-\t-" : f.PatternId + "\t" + f.Tier + "\t" + f.Place;
    }

    static string Want(Case k)
    {
        return k.Expect + "\t" + k.Tier + "\t" + k.Place;
    }

    static void CorpusCounts(Corpus corpus)
    {
        int cases = corpus.Cases.Count, negatives = 0;
        var withPositive = new HashSet<string>();
        bool known = true;
        bool repoDotenv = false, repoTemplate = false;
        foreach (Case k in corpus.Cases)
        {
            if (!k.Positive) negatives++;
            else
            {
                withPositive.Add(k.Expect);
                if (ProtectConstants.Pattern(k.Expect) == null)
                {
                    known = false;
                    Console.WriteLine("      line " + k.Line + ": unknown pattern id " + k.Expect);
                }
                if (k.Expect == "dotenv" && k.Place == "Repository") repoDotenv = true;
            }
            if (!k.Positive && k.Raw.StartsWith("code/app/.env.", StringComparison.Ordinal)) repoTemplate = true;
        }
        // Section 9.2 states 187 cases and 97 negatives; amendment A1 turned two repository .env cases positive, and
        // the review fixes added five copy-suffix positives (.ssh, .kube, Downloads, D:\Downloads).
        Check(cases == 192, "the corpus has 192 cases (" + cases + ")");
        Check(negatives == 95, "the corpus has 95 negative cases after amendment A1 (" + negatives + ")");
        Check(known, "every expected pattern id exists in Patterns");
        int rowsCovered = 0;
        foreach (PatternInfo p in ProtectConstants.Patterns)
        {
            if (withPositive.Contains(p.Id)) rowsCovered++;
            else Console.WriteLine("      no positive case for " + p.Id);
        }
        Check(rowsCovered == 38 && rowsCovered == ProtectConstants.Patterns.Length, "all 38 Patterns rows have a positive case (" + rowsCovered + ")");
        Check(repoDotenv && repoTemplate, "the corpus keeps a repository .env positive and a repository template negative");
    }

    static Finding Match(ProtectContext ctx, Case k)
    {
        return ProtectNames.MatchPath(ctx, k.FullPath, k.Online ? 0 : k.Size, k.Online, k.Folder, k.Siblings);
    }

    static void CorpusGate(Corpus corpus)
    {
        ProtectContext ctx = corpus.Context(true);
        int wrong = 0, positives = 0, recalled = 0;
        var emitted = new Dictionary<FindingTier, int>();
        var correct = new Dictionary<FindingTier, int>();
        foreach (Case k in corpus.Cases)
        {
            Finding f;
            try { f = Match(ctx, k); }
            catch (Exception ex)
            {
                wrong++;
                Console.WriteLine("      line " + k.Line + " " + k.Raw + ": MatchPath threw " + ex.GetType().Name + ": " + ex.Message);
                continue;
            }
            bool ok = Got(f) == Want(k);
            if (!ok)
            {
                wrong++;
                Console.WriteLine("      line " + k.Line + " " + k.Raw + ": expected " + Want(k).Replace('\t', ' ') + ", got " + Got(f).Replace('\t', ' '));
            }
            if (f != null)
            {
                int n;
                emitted.TryGetValue(f.Tier, out n);
                emitted[f.Tier] = n + 1;
                if (ok)
                {
                    correct.TryGetValue(f.Tier, out n);
                    correct[f.Tier] = n + 1;
                }
            }
            if (k.Positive)
            {
                positives++;
                if (ok) recalled++;
            }
        }
        foreach (FindingTier t in new[] { FindingTier.Confirmed, FindingTier.Likely, FindingTier.WorthALook })
        {
            int e, c;
            emitted.TryGetValue(t, out e);
            correct.TryGetValue(t, out c);
            if (e == 0) continue;
            Check(c == e, string.Format("precision for {0}: {1}/{2} = {3:0.0}% (gate 100%)", t, c, e, 100.0 * c / e));
        }
        Check(recalled == positives, string.Format("positive recall: {0}/{1} = {2:0.0}% (gate 100%)", recalled, positives,
            positives == 0 ? 0 : 100.0 * recalled / positives));
        Check(wrong == 0, "every corpus case gives its expected pattern, tier and place (" + wrong + " differ)");
    }

    static void ForTreeMatchesTheHeader(Corpus corpus)
    {
        ProtectContext t = ProtectContext.ForTree(corpus.Home);
        ProtectContext h = corpus.Context(false);
        bool same = SameSet(new[] { t.Home }, new[] { h.Home }) && SameSet(new[] { t.Roaming }, new[] { h.Roaming }) &&
                    SameSet(new[] { t.Local }, new[] { h.Local }) && SameSet(t.Downloads, h.Downloads) && SameSet(t.Desktop, h.Desktop) &&
                    SameSet(t.Documents, h.Documents) && SameSet(t.Pictures, h.Pictures) && SameSet(t.Videos, h.Videos) &&
                    SameSet(t.Music, h.Music) && SameSet(t.TempRoots, h.TempRoots) && SameSet(t.SyncRoots, h.SyncRoots) &&
                    SameSet(t.ExternalRoots, h.ExternalRoots) && SameSet(t.RepoRoots, h.RepoRoots) && !t.RootInRepo;
        Check(same, "ForTree(C:\\Users\\pat) equals the corpus header without its drive-letter entries");
    }

    static bool SameSet(string[] a, string[] b)
    {
        var x = new HashSet<string>();
        var y = new HashSet<string>();
        if (a != null) foreach (string s in a) if (s != null) x.Add(ProtectStore.Normalize(s));
        if (b != null) foreach (string s in b) if (s != null) y.Add(ProtectStore.Normalize(s));
        return x.SetEquals(y);
    }

    // ---------------------------------------------------------------------------------------------------
    // In-memory trees

    static readonly long FixedWrite = new DateTime(2026, 2, 3, 10, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();

    sealed class Tree
    {
        public readonly DirNode Root;
        readonly Dictionary<string, DirNode> dirs = new Dictionary<string, DirNode>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<DirNode, List<Node>> kids = new Dictionary<DirNode, List<Node>>();
        readonly Dictionary<FileNode, long> logical = new Dictionary<FileNode, long>();
        public readonly List<FileNode> Files = new List<FileNode>();

        public Tree(string rootPath)
        {
            Root = new DirNode { Name = rootPath, LastWrite = FixedWrite };
            dirs[""] = Root;
            kids[Root] = new List<Node>();
        }

        string Rel(string fullPath)
        {
            string root = Root.Name.TrimEnd('\\');
            if (string.Equals(fullPath.TrimEnd('\\'), root, StringComparison.OrdinalIgnoreCase)) return "";
            if (!fullPath.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(fullPath + " is not under " + Root.Name);
            return fullPath.Substring(root.Length + 1).TrimEnd('\\');
        }

        public DirNode Dir(string fullPath)
        {
            return DirRel(Rel(fullPath));
        }

        DirNode DirRel(string rel)
        {
            DirNode d;
            if (dirs.TryGetValue(rel, out d)) return d;
            int cut = rel.LastIndexOf('\\');
            DirNode parent = DirRel(cut < 0 ? "" : rel.Substring(0, cut));
            d = new DirNode { Name = cut < 0 ? rel : rel.Substring(cut + 1), Parent = parent, LastWrite = FixedWrite };
            dirs[rel] = d;
            kids[d] = new List<Node>();
            kids[parent].Add(d);
            return d;
        }

        public FileNode File(string fullPath, long size, bool online)
        {
            string rel = Rel(fullPath);
            int cut = rel.LastIndexOf('\\');
            DirNode parent = DirRel(cut < 0 ? "" : rel.Substring(0, cut));
            string name = cut < 0 ? rel : rel.Substring(cut + 1);
            foreach (Node n in kids[parent])
                if (string.Equals(n.Name, name, StringComparison.OrdinalIgnoreCase)) return n as FileNode;
            var f = new FileNode { Name = name, Parent = parent, LastWrite = FixedWrite, Size = online ? 0 : size,
                Flags = online ? FileFlags.OnlineOnly : FileFlags.None };
            kids[parent].Add(f);
            logical[f] = size;
            Files.Add(f);
            return f;
        }

        public bool Has(string fullPath)
        {
            string rel = Rel(fullPath);
            if (dirs.ContainsKey(rel)) return true;
            int cut = rel.LastIndexOf('\\');
            DirNode parent;
            if (!dirs.TryGetValue(cut < 0 ? "" : rel.Substring(0, cut), out parent)) return false;
            string name = cut < 0 ? rel : rel.Substring(cut + 1);
            foreach (Node n in kids[parent])
                if (string.Equals(n.Name, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        public List<string> SiblingsOf(Node n)
        {
            var list = new List<string>();
            foreach (Node s in kids[n.Parent])
                if (s != n) list.Add(s.Name);
            return list;
        }

        // Totals, logical bytes and sort order, as the scanner leaves them.
        public ScanResult Finish(ProtectContext ctx)
        {
            Total(Root);
            var r = new ScanResult { Root = Root };
            r.Protect = ctx;
            return r;
        }

        void Total(DirNode d)
        {
            List<Node> list = kids[d];
            long size = 0, files = 0, folders = 0, logicalBytes = 0;
            int online = 0;
            foreach (Node n in list)
            {
                var sub = n as DirNode;
                if (sub != null)
                {
                    Total(sub);
                    size += sub.Size;
                    files += sub.FileCount;
                    folders += 1 + sub.DirCount;
                    logicalBytes += sub.LogicalBytes;
                    online += sub.OnlineOnlyFiles;
                }
                else
                {
                    var f = (FileNode)n;
                    size += f.Size;
                    files++;
                    logicalBytes += logical[f];
                    if ((f.Flags & FileFlags.OnlineOnly) != 0) online++;
                }
            }
            d.Size = size;
            d.FileCount = files;
            d.DirCount = folders;
            d.LogicalBytes = logicalBytes;
            d.OnlineOnlyFiles = online;
            Node[] arr = list.ToArray();
            Array.Sort(arr, Node.CompareBySize);
            d.Children = arr;
        }
    }

    static bool IsUnder(string path, string root)
    {
        return UnderOrSame(path, root) && !string.Equals(ProtectStore.Normalize(path), ProtectStore.Normalize(root), StringComparison.Ordinal);
    }

    // The corpus cases under one root, as a tree: files with their sizes and online flags, folder cases as empty
    // folders, siblings named by directives, and a .git folder in each repository.
    static Tree CorpusTree(Corpus corpus, string root, Func<Case, bool> include)
    {
        var t = new Tree(root);
        foreach (Case k in corpus.Cases)
        {
            if (!include(k) || !IsUnder(k.FullPath, root)) continue;
            if (k.Folder) t.Dir(k.FullPath);
            else t.File(k.FullPath, k.Size, k.Online);
        }
        foreach (Case k in corpus.Cases)
        {
            if (!include(k) || !IsUnder(k.FullPath, root) || k.Siblings == null) continue;
            string folder = Path.GetDirectoryName(k.FullPath);
            foreach (string s in k.Siblings)
            {
                string p = folder + "\\" + s;
                if (!t.Has(p)) t.File(p, 4096, false);
            }
        }
        foreach (string repo in corpus.Repo)
            if (IsUnder(repo, root)) t.Dir(repo + "\\.git");
        return t;
    }

    static string Key(Finding f)
    {
        return f.PatternId + "\t" + f.Tier + "\t" + f.Place + "\t" + ProtectStore.Normalize(f.Path);
    }

    static bool CompareSets(string what, HashSet<string> expected, List<Finding> found)
    {
        var got = new HashSet<string>();
        foreach (Finding f in found) got.Add(Key(f));
        bool ok = got.SetEquals(expected) && got.Count == found.Count;
        if (!ok)
        {
            foreach (string e in expected) if (!got.Contains(e)) Console.WriteLine("      missing: " + e.Replace('\t', ' '));
            foreach (string g in got) if (!expected.Contains(g)) Console.WriteLine("      extra:   " + g.Replace('\t', ' '));
            if (got.Count != found.Count) Console.WriteLine("      " + (found.Count - got.Count) + " duplicate finding(s)");
        }
        Check(ok, what + " (" + found.Count + " findings, " + expected.Count + " expected)");
        return ok;
    }

    // No finding may sit below a SkipFolders segment, a two-segment entry or a "$" folder.
    static void NoSkipSegments(string what, List<Finding> found)
    {
        int bad = 0;
        foreach (Finding f in found)
        {
            if (SkipSegment(f.Path) != null)
            {
                bad++;
                Console.WriteLine("      " + f.Path + " is under " + SkipSegment(f.Path));
            }
        }
        Check(bad == 0, what + ": no finding has a SkipFolders segment in its path");
    }

    static string SkipSegment(string path)
    {
        string[] segs = path.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
        for (int i = 1; i < segs.Length - 1; i++)
        {
            if (segs[i].StartsWith("$", StringComparison.Ordinal)) return segs[i];
            foreach (string s in ProtectConstants.SkipFolders)
            {
                int cut = s.IndexOf('\\');
                if (cut < 0)
                {
                    if (string.Equals(segs[i], s, StringComparison.OrdinalIgnoreCase)) return s;
                }
                else if (i + 1 < segs.Length - 1 && string.Equals(segs[i], s.Substring(0, cut), StringComparison.OrdinalIgnoreCase) &&
                         string.Equals(segs[i + 1], s.Substring(cut + 1), StringComparison.OrdinalIgnoreCase))
                    return s;
            }
        }
        return null;
    }

    static bool FindingNodesMatch(ScanResult r)
    {
        if (r.FindingNodes == null || r.FindingNodes.Count != r.Findings.Count) return false;
        for (int i = 0; i < r.Findings.Count; i++)
        {
            Node n = r.FindingNodes[i];
            if (n == null || ProtectStore.Normalize(n.FullPath) != ProtectStore.Normalize(r.Findings[i].Path)) return false;
        }
        return true;
    }

    static HashSet<string> ExpectedFromMatchPath(Tree t, ScanResult r, ProtectContext ctx, Corpus corpus)
    {
        var expected = new HashSet<string>();
        string ssh = ProtectStore.Normalize(ctx.Home + "\\.ssh");
        foreach (FileNode f in t.Files)
        {
            IList<string> siblings = ProtectStore.Normalize(f.Parent.FullPath) == ssh ? t.SiblingsOf(f) : null;
            Finding m = ProtectNames.MatchPath(ctx, f.FullPath, f.Size, (f.Flags & FileFlags.OnlineOnly) != 0, false, siblings);
            if (m != null) expected.Add(Key(m));
        }
        foreach (Case k in corpus.Cases)
        {
            if (!k.Folder || !IsUnder(k.FullPath, t.Root.Name) || !t.Has(k.FullPath)) continue;
            Finding m = ProtectNames.MatchPath(ctx, k.FullPath, 0, false, true, null);
            if (m != null) expected.Add(Key(m));
        }
        return expected;
    }

    static void TreeEquality(Corpus corpus)
    {
        ProtectContext ctx = ProtectContext.ForTree(corpus.Home);
        Tree t = CorpusTree(corpus, corpus.Home, k => k.Relative);
        ScanResult r = t.Finish(ctx);
        try
        {
            r.Analyze();
            HashSet<string> expected = ExpectedFromMatchPath(t, r, ctx, corpus);
            CompareSets("tree equality: Analyze over the relative cases finds what MatchPath finds", expected, r.Findings);
            Check(FindingNodesMatch(r), "FindingNodes runs parallel to Findings");
            NoSkipSegments("tree", r.Findings);

            // The same set, judged against the corpus columns (the tree's own siblings must not change a result).
            var want = new HashSet<string>();
            foreach (Case k in corpus.Cases)
                if (k.Relative && k.Positive) want.Add(k.Expect + "\t" + k.Tier + "\t" + k.Place + "\t" + ProtectStore.Normalize(k.FullPath));
            CompareSets("tree findings equal the corpus positives under C:\\Users\\pat", want, r.Findings);
        }
        catch (Exception ex)
        {
            Check(false, "tree equality ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
        }
    }

    // Root F:\ (an external drive) and root D:\ (another internal drive), each holding the corpus cases on it,
    // with the full header context: the results must be the corpus's.
    static void DriveTrees(Corpus corpus)
    {
        ProtectContext ctx = corpus.Context(true);
        foreach (string drive in new[] { @"F:\", @"D:\" })
        {
            try
            {
                Tree t = CorpusTree(corpus, drive, k => !k.Relative && !k.Online);
                ScanResult r = t.Finish(ctx);
                r.Analyze();
                var want = new HashSet<string>();
                foreach (Case k in corpus.Cases)
                    if (!k.Relative && !k.Online && k.Positive && IsUnder(k.FullPath, drive))
                        want.Add(k.Expect + "\t" + k.Tier + "\t" + k.Place + "\t" + ProtectStore.Normalize(k.FullPath));
                CompareSets("root " + drive + ": Analyze finds the corpus's results", want, r.Findings);
                NoSkipSegments("root " + drive, r.Findings);
            }
            catch (Exception ex)
            {
                Check(false, "root " + drive + " tree ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
            }
        }
    }

    // The fixture tree written by make-protect-tree.ps1, scanned from disk with the real scanner.
    static void FixtureTreeOnDisk(Corpus corpus, string tree)
    {
        if (tree == null || !Directory.Exists(tree))
        {
            Console.WriteLine("SKIP  the fixture tree on disk (no folder given)");
            return;
        }
        try
        {
            ScanResult r = new Scanner().Scan(tree, CancellationToken.None);
            r.Protect = ProtectContext.ForTree(r.Root.Name);
            r.Analyze();
            var want = new HashSet<string>();
            foreach (Case k in corpus.Cases)
            {
                if (!k.Relative || k.Online || !k.Positive) continue;
                string onDisk = r.Root.Name.TrimEnd('\\') + k.FullPath.Substring(corpus.Home.Length);
                want.Add(k.Expect + "\t" + k.Tier + "\t" + k.Place + "\t" + ProtectStore.Normalize(onDisk));
            }
            CompareSets("the fixture tree on disk, scanned with --protect-home, gives the corpus's results", want, r.Findings);
            NoSkipSegments("fixture tree", r.Findings);
        }
        catch (Exception ex)
        {
            Check(false, "the fixture tree scan ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
        }
    }

    static ProtectContext PatContext(bool rootInRepo, string[] externalRoots)
    {
        const string h = @"C:\Users\pat";
        return new ProtectContext(h, h + @"\AppData\Roaming", h + @"\AppData\Local", new[] { h + @"\Downloads" },
            new[] { h + @"\Desktop" }, new[] { h + @"\Documents" }, new[] { h + @"\Pictures" }, new string[0], new string[0],
            new[] { h + @"\AppData\Local\Temp" }, new string[0], externalRoots ?? new string[0], new string[0], null, rootInRepo);
    }

    static List<Finding> AnalyzeTree(string root, ProtectContext ctx, params object[] files)
    {
        var t = new Tree(root);
        for (int i = 0; i < files.Length; i += 2)
            t.File(root.TrimEnd('\\') + "\\" + (string)files[i], (long)(int)files[i + 1], false);
        ScanResult r = t.Finish(ctx);
        r.Analyze();
        return r.Findings;
    }

    static string Describe(List<Finding> found)
    {
        var parts = new List<string>();
        foreach (Finding f in found) parts.Add(f.PatternId + " " + f.Tier + " " + f.Place + " " + f.Path);
        return parts.Count == 0 ? "none" : string.Join("; ", parts);
    }

    static void RootCases()
    {
        try
        {
            ProtectContext tree = ProtectContext.ForTree(@"C:\Users\pat");
            List<Finding> f = AnalyzeTree(@"C:\Users\pat\code\web\node_modules\pkg", tree, "key.pem", 1700, ".env", 120);
            Check(f.Count == 0, "a scan rooted inside node_modules finds nothing (" + Describe(f) + ")");

            // Amendment A1: a .env in a repository is found, as Likely in Repository. The repository is known only
            // through RootInRepo, because the .git folder is above the scan root.
            f = AnalyzeTree(@"C:\Users\pat\code\app\sub", PatContext(true, null), ".env", 120, ".env.example", 120);
            Check(f.Count == 1 && f[0].PatternId == "dotenv" && f[0].Tier == FindingTier.Likely && f[0].Place == Place.Repository,
                "a scan rooted inside a repository (RootInRepo) reports its .env as Likely in Repository, and not .env.example (" + Describe(f) + ")");
            f = AnalyzeTree(@"C:\Users\pat\code\app\sub", PatContext(false, null), ".env", 120);
            Check(f.Count == 0, "the same .env outside a repository, deep in the user folder (Other), gives nothing (" + Describe(f) + ")");

            f = AnalyzeTree(@"D:\", tree, "private.pem", 1700, "W2-2024.pdf", 4096);
            Check(f.Count == 1 && f[0].PatternId == "doc-tax" && f[0].Tier == FindingTier.Likely && f[0].Place == Place.Other,
                "root D:\\ with no home: private.pem gives nothing and the W-2 gives doc-tax Likely Other (" + Describe(f) + ")");

            f = AnalyzeTree(@"F:\", PatContext(false, new[] { @"F:\" }), "phone-app\\release.jks", 4096, "notes\\private.pem", 1700);
            bool external = f.Count >= 1;
            foreach (Finding x in f) external &= x.Place == Place.ExternalDrive;
            Check(external && f.Exists(x => x.PatternId == "java-keystore"), "root F:\\ on an external drive reads ExternalDrive (" + Describe(f) + ")");

            // A user folder named like a fixture folder ("test", "demo") silences nothing, whether the scan starts at
            // the user folder or above it; a test folder inside it still does.
            f = AnalyzeTree(@"C:\Users\test", ProtectContext.ForTree(@"C:\Users\test"), ".ssh\\id_rsa", 500, "test\\id_rsa", 500);
            Check(f.Count == 1 && f[0].PatternId == "ssh-key" && f[0].Tier == FindingTier.Confirmed && f[0].Place == Place.UsualPlace,
                "a user folder named test still reports .ssh\\id_rsa, and not test\\id_rsa (" + Describe(f) + ")");
            f = AnalyzeTree(@"C:\", ProtectContext.ForTree(@"C:\Users\Demo"), "Users\\Demo\\.ssh\\id_ed25519", 500,
                "Users\\Demo\\Downloads\\id_rsa", 500);
            Check(f.Count == 2 && f.TrueForAll(x => x.PatternId == "ssh-key"),
                "a scan of C:\\ with a user folder named Demo reports its keys (" + Describe(f) + ")");
            f = AnalyzeTree(@"D:\Users\sample", ProtectContext.ForTree(@"D:\Users\sample"), ".kube\\config", 900);
            Check(f.Count == 1 && f[0].PatternId == "kubeconfig", "a user folder named sample on D: reports .kube\\config (" + Describe(f) + ")");
        }
        catch (Exception ex)
        {
            Check(false, "the root cases ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
        }
    }

    static void ScannedDocumentsNeedADocument()
    {
        try
        {
            ProtectContext ctx = ProtectContext.ForTree(@"C:\Users\pat");
            var t = new Tree(@"C:\Users\pat");
            t.Dir(@"C:\Users\pat\Documents\Scanned Documents");
            ScanResult r = t.Finish(ctx);
            r.Analyze();
            Check(r.Findings.Count == 0, "an empty Scanned Documents folder is not a finding (" + Describe(r.Findings) + ")");

            List<Finding> f = AnalyzeTree(@"C:\Users\pat", ctx, @"Documents\Scanned Documents\tiny.png", 1000);
            Check(f.Count == 0, "a Scanned Documents folder holding only a small image is not a finding (" + Describe(f) + ")");

            f = AnalyzeTree(@"C:\Users\pat", ctx, @"Documents\Scanned Documents\2019\scan0001.pdf", 4096);
            Check(f.Count == 1 && f[0].PatternId == "doc-scans-folder" && f[0].Place == Place.UsualPlace &&
                ProtectStore.Normalize(f[0].Path) == ProtectStore.Normalize(@"C:\Users\pat\Documents\Scanned Documents"),
                "a Scanned Documents folder with a PDF below it is one folder finding (" + Describe(f) + ")");
        }
        catch (Exception ex)
        {
            Check(false, "the Scanned Documents cases ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // Refresh and logical bytes

    static void Refresh(Corpus corpus)
    {
        try
        {
            ProtectContext ctx = ProtectContext.ForTree(corpus.Home);
            Tree t = CorpusTree(corpus, corpus.Home, k => k.Relative);
            ScanResult r = t.Finish(ctx);
            r.Analyze();
            int before = r.Findings.Count;

            int pick = -1;
            for (int i = 0; i < r.Findings.Count; i++)
            {
                Finding f = r.Findings[i];
                if (r.FindingNodes[i] is FileNode && f.Path.IndexOf("Scanned Documents", StringComparison.OrdinalIgnoreCase) < 0 &&
                    f.Path.IndexOf("\\.ssh\\", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    pick = i;
                    break;
                }
            }
            Check(pick >= 0, "the tree has a file finding to remove");
            if (pick >= 0)
            {
                string gone = ProtectStore.Normalize(r.Findings[pick].Path);
                r.Replace(r.FindingNodes[pick], null);
                Check(r.Findings.Count == before - 1 && !r.Findings.Exists(x => ProtectStore.Normalize(x.Path) == gone),
                    "Replace(file, null) removes that finding and no other (" + before + " -> " + r.Findings.Count + ")");
                before = r.Findings.Count;
            }

            var keys = new HashSet<string>();
            foreach (Finding f in r.Findings) keys.Add(Key(f));
            var downloads = (DirNode)r.FindNode(corpus.Home + @"\Downloads");
            r.Replace(downloads, Clone(downloads, null));
            var after = new HashSet<string>();
            foreach (Finding f in r.Findings) after.Add(Key(f));
            Check(r.Protect == ctx && after.SetEquals(keys), "Replace of a folder with a rescanned copy keeps the context and the findings");

            // Protect off: no findings, and every other figure is the same as with Protect on.
            Tree a = CorpusTree(corpus, corpus.Home, k => k.Relative), b = CorpusTree(corpus, corpus.Home, k => k.Relative);
            ScanResult on = a.Finish(ctx), off = b.Finish(null);
            on.Analyze();
            off.Analyze();
            Check(off.Findings.Count == 0 && off.FindingNodes.Count == 0, "with Protect null, Findings is empty");
            Check(Figures(on) == Figures(off), "with Protect null, Extensions, CategoryBytes and LargestFiles are identical");
        }
        catch (Exception ex)
        {
            Check(false, "the refresh checks ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
        }
    }

    static DirNode Clone(DirNode d, DirNode parent)
    {
        var c = new DirNode { Name = d.Name, Parent = parent, Size = d.Size, LastWrite = d.LastWrite, FileCount = d.FileCount,
            DirCount = d.DirCount, LogicalBytes = d.LogicalBytes, OnlineOnlyFiles = d.OnlineOnlyFiles, LogicalStale = d.LogicalStale };
        var kids = new Node[d.Children.Length];
        for (int i = 0; i < kids.Length; i++)
        {
            var sub = d.Children[i] as DirNode;
            if (sub != null) kids[i] = Clone(sub, c);
            else
            {
                var f = (FileNode)d.Children[i];
                kids[i] = new FileNode { Name = f.Name, Parent = c, Size = f.Size, LastWrite = f.LastWrite, Flags = f.Flags };
            }
        }
        c.Children = kids;
        return c;
    }

    static string Figures(ScanResult r)
    {
        var sb = new StringBuilder();
        foreach (ExtInfo x in r.Extensions) sb.Append(x.Key).Append(' ').Append(x.Category).Append(' ').Append(x.Size).Append(' ').Append(x.Count).Append('|');
        foreach (long v in r.CategoryBytes) sb.Append(v).Append(',');
        foreach (long v in r.CategoryFiles) sb.Append(v).Append(',');
        foreach (FileNode f in r.LargestFiles) sb.Append(f.FullPath).Append(',');
        return sb.ToString();
    }

    static Tree SmallTree(out FileNode plain, out FileNode online, out DirNode a, out DirNode b)
    {
        var t = new Tree(@"C:\T");
        plain = t.File(@"C:\T\A\a1.txt", 100, false);
        online = t.File(@"C:\T\A\a2.txt", 500, true);
        t.File(@"C:\T\B\b1.txt", 300, false);
        a = t.Dir(@"C:\T\A");
        b = t.Dir(@"C:\T\B");
        return t;
    }

    static void LogicalBytes()
    {
        try
        {
            FileNode plain, online;
            DirNode a, b;
            ScanResult r = SmallTree(out plain, out online, out a, out b).Finish(null);
            r.Analyze();
            Check(r.Root.LogicalBytes == 900 && a.LogicalBytes == 600 && r.Root.OnlineOnlyFiles == 1, "the test tree starts with 900 logical bytes and 1 online-only file");
            r.Replace(plain, null);
            Check(a.LogicalBytes == 500 && r.Root.LogicalBytes == 800 && !a.LogicalStale && !r.Root.LogicalStale,
                "Replace on an unflagged file takes its size off LogicalBytes, with nothing stale");

            r = SmallTree(out plain, out online, out a, out b).Finish(null);
            r.Analyze();
            r.Replace(online, null);
            Check(a.LogicalStale && r.Root.LogicalStale && !b.LogicalStale, "Replace on a flagged (online-only) file sets LogicalStale on its ancestors only");
            Check(a.LogicalBytes == 600 && r.Root.LogicalBytes == 900, "a flagged file's removal leaves LogicalBytes unchanged");
            // Rescanning A (a fresh, exact folder) makes the totals above exact again, and clears the flag there.
            var a2 = new DirNode { Name = "A", Size = 100, FileCount = 1, LogicalBytes = 100, LastWrite = FixedWrite };
            a2.Children = new Node[] { new FileNode { Name = "a1.txt", Parent = a2, Size = 100, LastWrite = FixedWrite } };
            r.Replace(a, a2);
            Check(r.Root.LogicalBytes == 400 && !r.Root.LogicalStale,
                "a rescan of the stale folder clears LogicalStale above it (" + r.Root.LogicalBytes + ", " + r.Root.LogicalStale + ")");

            r = SmallTree(out plain, out online, out a, out b).Finish(null);
            r.Analyze();
            var b2 = new DirNode { Name = "B", Size = 300, FileCount = 1, LogicalBytes = 1000, OnlineOnlyFiles = 2, LastWrite = FixedWrite };
            b2.Children = new Node[] { new FileNode { Name = "b1.txt", Parent = b2, Size = 300, LastWrite = FixedWrite } };
            r.Replace(b, b2);
            Check(r.Root.LogicalBytes == 1600 && r.Root.OnlineOnlyFiles == 3 && !r.Root.LogicalStale,
                "Replace on a folder adjusts LogicalBytes and OnlineOnlyFiles (" + r.Root.LogicalBytes + ", " + r.Root.OnlineOnlyFiles + ")");

            r = SmallTree(out plain, out online, out a, out b).Finish(null);
            r.Analyze();
            var b3 = new DirNode { Name = "B", Size = 300, FileCount = 1, LogicalBytes = 300, LogicalStale = true, LastWrite = FixedWrite };
            b3.Children = new Node[] { new FileNode { Name = "b1.txt", Parent = b3, Size = 300, LastWrite = FixedWrite } };
            r.Replace(b, b3);
            Check(r.Root.LogicalStale, "a stale replacement folder makes its ancestors stale");
        }
        catch (Exception ex)
        {
            Check(false, "the logical-bytes checks ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // Store and explanation

    static void StoreHidesAndTrusts()
    {
        var store = new ProtectStore();
        var dismissed = new Finding("ssh-key", FindingTier.Likely, @"C:\Users\Pat\Downloads\id_rsa", 0, 0, Place.Downloads);
        var trusted = new Finding("tfstate", FindingTier.Likely, @"C:\Users\Pat\Code\App\infra\terraform.tfstate", 0, 0, Place.Repository);
        var other = new Finding("dotenv", FindingTier.Likely, @"C:\Users\Pat\Desktop\.env", 0, 0, Place.Desktop);
        store.Dismiss(dismissed);
        store.Trust(@"c:\users\pat\code\APP");
        Check(store.IsHidden(dismissed), "IsHidden is true for a dismissed finding");
        Check(store.IsHidden(trusted), "IsHidden is true for a finding under a trusted folder");
        Check(!store.IsHidden(other), "IsHidden is false for anything else");
        Check(store.TrustedAncestor(trusted.Path) == @"C:\Users\Pat\Code\App",
            "TrustedAncestor returns the trusted folder in the path's own casing (" + store.TrustedAncestor(trusted.Path) + ")");
        Check(store.TrustedAncestor(other.Path) == null, "TrustedAncestor is null outside trusted folders");

        MethodInfo m = typeof(ProtectStore).GetMethod("DismissKey", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
        string expected = ProtectStore.Hash("dismiss", dismissed.PatternId + "\n" + ProtectStore.Normalize(dismissed.Path));
        Check(m != null && (string)m.Invoke(null, new object[] { dismissed.PatternId, dismissed.Path }) == expected,
            "the dismiss key is still Hash(\"dismiss\", PatternId + \"\\n\" + Normalize(path))");
        string file = Path.Combine(work, "store", "hidden.json");
        store.Save(file);
        Check(File.ReadAllText(file).Contains(expected), "the saved store holds that key");
    }

    static void DescribeStage1()
    {
        string text = ProtectInfo.AsText();
        int missing = 0;
        foreach (PatternInfo p in ProtectConstants.Patterns)
            if (!text.Contains(p.Kind)) { missing++; Console.WriteLine("      Describe does not name " + p.Kind); }
        Check(missing == 0, "Describe names every Patterns Kind");
        missing = 0;
        foreach (string s in ProtectConstants.AppDataExamined)
            if (!text.Contains(s)) { missing++; Console.WriteLine("      Describe does not list " + s); }
        Check(missing == 0, "Describe lists every AppDataExamined entry");
        Check(text.Contains("Windows Mail kept copies of attachments you opened; Protect checks their names. The new Outlook's cache is not checked."),
            "Describe has the Mail sentence with the Outlook caveat");
        missing = 0;
        foreach (string s in ProtectConstants.LaterStages)
            if (!text.Contains(s)) { missing++; Console.WriteLine("      Describe does not list " + s); }
        Check(missing == 0, "Describe lists what waits for later stages");
        Check(text.Contains("Paths are shown in clear on this page and in dsa --protect output. File names can contain names and account numbers; take care when pasting them."),
            "Describe has the path-privacy line");
        // The line is "<Kind>: <Usual>; <Elsewhere>", so the sentence may or may not end in a full stop.
        Check(text.Contains(".env files on your Desktop, in Downloads, synced folders, external drives or your user folder; .env files in your projects are listed separately and not counted"),
            "Describe has the amendment A1 dotenv line");
        Check(text.Contains("Documents are never opened to read them."), "Describe says documents are never opened");
        Check(text.Contains("Compared by file count and total size on the drives connected now."), "Describe explains the copy check");
    }

    // ---------------------------------------------------------------------------------------------------
    // Backup coverage, on folders this test creates under %TEMP%

    static void WriteFiller(string path, int size)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        var bytes = new byte[size];
        byte[] text = Encoding.ASCII.GetBytes("not a secret ");
        for (int i = 0; i < size; i++) bytes[i] = text[i % text.Length];
        File.WriteAllBytes(path, bytes);
    }

    static void MakeFolder(string folder, int files)
    {
        for (int i = 0; i < files; i++) WriteFiller(Path.Combine(folder, (i % 3 == 0 ? "sub\\" : "") + "file" + i + ".txt"), 100 + i);
    }

    static CoverageSource Source(string driveRoot, string path, int disk)
    {
        long files = 0, bytes = 0, newest = 0;
        foreach (string f in Directory.GetFiles(path, "*", SearchOption.AllDirectories))
        {
            var fi = new FileInfo(f);
            files++;
            bytes += fi.Length;
            newest = Math.Max(newest, fi.LastWriteTimeUtc.ToFileTimeUtc());
        }
        return new CoverageSource { Path = path, Name = Path.GetFileName(path), Why = "test", DriveRoot = driveRoot, Files = files,
            LogicalBytes = bytes, NewestWrite = newest, DiskNumber = disk };
    }

    // Makes a directory junction with cmd's mklink /J. False when it could not.
    static bool Junction(string link, string target)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c mklink /J \"" + link + "\" \"" + target + "\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var p = System.Diagnostics.Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
                return p.ExitCode == 0 && Directory.Exists(link);
            }
        }
        catch (Exception) { return false; }
    }

    static CoverageDrive Drive(string root, int disk, bool external)
    {
        Directory.CreateDirectory(root);
        return new CoverageDrive { Root = root, Label = Path.GetFileName(root.TrimEnd('\\')), DiskNumber = disk, External = external };
    }

    static FolderCoverage One(CoverageSource s, Dictionary<string, CopyCheck> cache, CancellationToken ct, params CoverageDrive[] drives)
    {
        CoverageReport rep = ProtectCoverage.Compute(new List<CoverageSource> { s }, new List<CoverageDrive>(drives),
            n => n.IndexOf("backup", StringComparison.OrdinalIgnoreCase) >= 0, cache, ct);
        return rep.Folders[0];
    }

    static string St(FolderCoverage fc)
    {
        return fc.State + (fc.Best == null ? "" : " " + fc.Best.Path) + (fc.NotCheckedReason == null ? "" : " (" + fc.NotCheckedReason + ")");
    }

    static void Coverage()
    {
        string root = Path.Combine(Path.GetTempPath(), "dsa-cov-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var none = CancellationToken.None;

            // Identical copy on another drive.
            string c1 = Path.Combine(root, "c1");
            CoverageDrive a1 = Drive(c1 + "\\A\\", 1, false), b1 = Drive(c1 + "\\B\\", 2, true);
            MakeFolder(c1 + "\\A\\Docs", 6);
            MakeFolder(c1 + "\\B\\Docs", 6);
            CoverageSource s1 = Source(a1.Root, c1 + "\\A\\Docs", 1);
            FolderCoverage fc = One(s1, null, none, a1, b1);
            Check(fc.State == CoverageState.TwoDrives && fc.Best != null && fc.Best.Same, "an identical copy on another drive is TwoDrives (" + St(fc) + ")");

            // One file fewer.
            string c2 = Path.Combine(root, "c2");
            CoverageDrive a2 = Drive(c2 + "\\A\\", 1, false), b2 = Drive(c2 + "\\B\\", 2, true);
            MakeFolder(c2 + "\\A\\Docs", 6);
            MakeFolder(c2 + "\\B\\Docs", 5);
            FolderCoverage differs = One(Source(a2.Root, c2 + "\\A\\Docs", 1), null, none, a2, b2);
            Check(differs.State == CoverageState.CopyDiffers && differs.Best != null && differs.Best.Files == 5,
                "a copy with one file fewer is CopyDiffers (" + St(differs) + ")");

            // No copy.
            string c3 = Path.Combine(root, "c3");
            CoverageDrive a3 = Drive(c3 + "\\A\\", 1, false), b3 = Drive(c3 + "\\B\\", 2, true);
            MakeFolder(c3 + "\\A\\Docs", 4);
            FolderCoverage oneCopy = One(Source(a3.Root, c3 + "\\A\\Docs", 1), null, none, a3, b3);
            Check(oneCopy.State == CoverageState.OneCopy, "no copy anywhere is OneCopy (" + St(oneCopy) + ")");

            // A junction on the other drive that points back at the source is not a copy, nor is a folder under one.
            string c7 = Path.Combine(root, "c7");
            CoverageDrive a7 = Drive(c7 + "\\A\\", 1, false), b7 = Drive(c7 + "\\B\\", 2, true);
            MakeFolder(c7 + "\\A\\Docs", 4);
            if (Junction(c7 + "\\B\\Docs", c7 + "\\A\\Docs") && Junction(c7 + "\\B\\backup-old", c7 + "\\A"))
            {
                fc = One(Source(a7.Root, c7 + "\\A\\Docs", 1), null, none, a7, b7);
                Check(fc.State == CoverageState.OneCopy, "a junction back to the source, or a backup folder that is a junction, is not a copy (" + St(fc) + ")");
            }
            else Console.WriteLine("      (skipped the junction check: mklink /J is not available here)");
            // Removed on their own (not followed) before the temp folder is cleaned up.
            foreach (string link in new[] { c7 + "\\B\\Docs", c7 + "\\B\\backup-old" })
                try { if (Directory.Exists(link)) Directory.Delete(link, false); } catch (IOException) { } catch (UnauthorizedAccessException) { }

            // The three other probes: Name (2), the mirror layout and a backup top folder.
            string c4 = Path.Combine(root, "c4");
            CoverageDrive a4 = Drive(c4 + "\\A\\", 1, false);
            MakeFolder(c4 + "\\A\\deep\\Docs", 4);
            CoverageSource s4 = Source(a4.Root, c4 + "\\A\\deep\\Docs", 1);
            CoverageDrive bn = Drive(c4 + "\\N\\", 2, true), bm = Drive(c4 + "\\M\\", 3, true), bk = Drive(c4 + "\\K\\", 4, true);
            MakeFolder(c4 + "\\N\\Docs (2)", 4);
            MakeFolder(c4 + "\\M\\deep\\Docs", 4);
            MakeFolder(c4 + "\\K\\backup-2026\\Docs", 4);
            fc = One(s4, null, none, a4, bn);
            Check(fc.State == CoverageState.TwoDrives && fc.Best.Path.EndsWith("Docs (2)", StringComparison.Ordinal), "the Name (2) probe finds a copy (" + St(fc) + ")");
            fc = One(s4, null, none, a4, bm);
            Check(fc.State == CoverageState.TwoDrives && fc.Best.Path.EndsWith("M\\deep\\Docs", StringComparison.OrdinalIgnoreCase), "the mirror-layout probe finds a copy (" + St(fc) + ")");
            fc = One(s4, null, none, a4, bk);
            Check(fc.State == CoverageState.TwoDrives && fc.Best.Path.EndsWith("backup-2026\\Docs", StringComparison.OrdinalIgnoreCase), "the backup-folder probe finds a copy (" + St(fc) + ")");

            // Disk numbers: the same disk is not another drive; an unknown disk number falls back to the letter.
            CoverageDrive sameDisk = Drive(c1 + "\\B\\", 1, false), elsewhere = Drive(c1 + "\\C\\", 2, false);
            fc = One(s1, null, none, a1, sameDisk, elsewhere);
            Check(fc.State == CoverageState.OneCopy, "a copy on another partition of the same disk does not count (" + St(fc) + ")");
            fc = One(s1, null, none, a1, sameDisk);
            Check(fc.State == CoverageState.NotChecked, "with only a partition of the same disk connected, the folder is not checked (" + St(fc) + ")");
            CoverageSource unknownDisk = Source(a1.Root, c1 + "\\A\\Docs", -1);
            fc = One(unknownDisk, null, none, a1, Drive(c1 + "\\B\\", 1, false));
            Check(fc.State == CoverageState.TwoDrives, "with the source's disk number unknown, another letter counts as another drive (" + St(fc) + ")");
            fc = One(s1, null, none, a1, Drive(c1 + "\\B\\", -1, false));
            Check(fc.State == CoverageState.TwoDrives, "with the copy's disk number unknown, another letter counts as another drive (" + St(fc) + ")");

            // The file cap, simulated with a cap of 10.
            string c5 = Path.Combine(root, "c5");
            CoverageDrive a5 = Drive(c5 + "\\A\\", 1, false), b5 = Drive(c5 + "\\B\\", 2, true);
            MakeFolder(c5 + "\\A\\Big", 20);
            MakeFolder(c5 + "\\B\\Big", 20);
            int cap = ProtectCoverage.FileCap;
            ProtectCoverage.FileCap = 10;
            try
            {
                fc = One(Source(a5.Root, c5 + "\\A\\Big", 1), null, none, a5, b5);
                Check(fc.State == CoverageState.NotChecked, "a copy over the file cap is NotChecked (" + St(fc) + ")");
            }
            finally { ProtectCoverage.FileCap = cap; }
            Check(cap == 200000, "the file cap is 200,000 (" + cap + ")");

            // Cancelled before it starts; stale totals; a scan root on an external drive.
            var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            fc = One(s1, null, cancelled.Token, a1, b1);
            Check(fc.State == CoverageState.NotChecked, "a run cancelled up front is NotChecked (" + St(fc) + ")");
            CoverageSource stale = Source(a1.Root, c1 + "\\A\\Docs", 1);
            stale.LogicalStale = true;
            fc = One(stale, null, none, a1, b1);
            Check(fc.State == CoverageState.NotChecked && fc.NotCheckedReason == "Rescan to check copies of this folder.",
                "stale totals are NotChecked with the rescan line (" + St(fc) + ")");
            CoverageDrive externalScan = Drive(c1 + "\\A\\", 1, true);
            fc = One(s1, null, none, externalScan, Drive(c1 + "\\B\\", 2, false));
            Check(fc.State == CoverageState.NotChecked && fc.NotCheckedReason == "Backups are checked for folders on internal drives.",
                "a scan root on an external drive is NotChecked (" + St(fc) + ")");

            // The headline counts: OneCopy and CopyDiffers count, NotChecked does not.
            // One pair of drives, four folders with different names so no probe finds another folder's copy.
            string c6 = Path.Combine(root, "c6");
            CoverageDrive a6 = Drive(c6 + "\\A\\", 1, false), b6 = Drive(c6 + "\\B\\", 2, true);
            MakeFolder(c6 + "\\A\\Same", 6);
            MakeFolder(c6 + "\\B\\Same", 6);
            MakeFolder(c6 + "\\A\\Fewer", 6);
            MakeFolder(c6 + "\\B\\Fewer", 5);
            MakeFolder(c6 + "\\A\\Alone", 4);
            MakeFolder(c6 + "\\A\\Stale", 3);
            MakeFolder(c6 + "\\B\\Stale", 3);
            CoverageSource ss = Source(a6.Root, c6 + "\\A\\Same", 1), sd = Source(a6.Root, c6 + "\\A\\Fewer", 1),
                sn = Source(a6.Root, c6 + "\\A\\Alone", 1), st = Source(a6.Root, c6 + "\\A\\Stale", 1);
            st.LogicalStale = true;
            CoverageReport rep = ProtectCoverage.Compute(new List<CoverageSource> { ss, sd, sn, st },
                new List<CoverageDrive> { a6, b6 }, null, null, none);
            Check(rep.WithoutCurrentCopy == 2 && rep.NotCheckedCount == 1 && rep.WithoutCurrentCopyBytes == sd.LogicalBytes + sn.LogicalBytes,
                "the report counts CopyDiffers and OneCopy as without a current copy, and NotChecked apart (" + rep.WithoutCurrentCopy + ", " + rep.NotCheckedCount + ")");

            // The cache: an unchanged source reuses the listing; a changed one lists again.
            var cache = new Dictionary<string, CopyCheck>();
            fc = One(s1, cache, none, a1, b1);
            int entries = cache.Count;
            // A file added deep in the copy leaves the copy folder's own date alone, so the cached listing is used.
            WriteFiller(c1 + "\\B\\Docs\\sub\\added.txt", 50);
            fc = One(s1, cache, none, a1, b1);
            Check(entries > 0 && fc.State == CoverageState.TwoDrives, "an unchanged source reuses the cached listing (" + entries + " entries, " + St(fc) + ")");
            // A file added in the copy folder itself changes its date, so the copy is listed again.
            WriteFiller(c1 + "\\B\\Docs\\added.txt", 50);
            Directory.SetLastWriteTimeUtc(c1 + "\\B\\Docs", DateTime.UtcNow.AddMinutes(5));
            fc = One(s1, cache, none, a1, b1);
            Check(fc.State == CoverageState.CopyDiffers, "a copy whose folder changed is listed again, not taken from the cache (" + St(fc) + ")");
            // Forget drops the entries of a copy that was written, by the copy's folder.
            ProtectCoverage.Forget(cache, null, c1 + "\\B");
            Check(cache.Count == 0, "Forget drops every cached listing of a copy under the folder that was written (" + cache.Count + " left)");
            CoverageSource changed = Source(a1.Root, c1 + "\\A\\Docs", 1);
            changed.NewestWrite += 1;
            fc = One(changed, cache, none, a1, b1);
            Check(fc.State == CoverageState.CopyDiffers, "a changed source lists the copy again (" + St(fc) + ")");
        }
        catch (Exception ex)
        {
            Check(false, "the coverage checks ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
        }
        finally
        {
            try { Directory.Delete(root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // The cost of Protect in Analyze: 700,000 files in 60,000 folders with a realistic mix of names

    static void SyntheticTiming()
    {
        try
        {
            ScanResult off = Synthetic(null), on = Synthetic(ProtectContext.ForTree(@"C:\Users\pat"));
            off.Analyze();
            on.Analyze();
            // Runs are interleaved, and the gates use the median of each pair's ratio and added time, so a burst of
            // background load hits one pair rather than one side of the comparison.
            var tOff = new List<double>();
            var tOn = new List<double>();
            var ratios = new List<double>();
            var added = new List<double>();
            for (int i = 0; i < 9; i++)
            {
                double a, b;
                if (i % 2 == 0) { a = Time(off); b = Time(on); }
                else { b = Time(on); a = Time(off); }
                tOff.Add(a);
                tOn.Add(b);
                ratios.Add(b / a);
                added.Add(b - a);
            }
            double mOff = Median(tOff), mOn = Median(tOn), mRatio = Median(ratios), mAdded = Median(added);
            Console.WriteLine(string.Format("      Analyze over {0:N0} files and {1:N0} folders: {2:0.0} ms without Protect, {3:0.0} ms with it ({4} findings)",
                on.Root.FileCount, on.Root.DirCount, mOff, mOn, on.Findings.Count));
            Console.WriteLine(string.Format("      Paired medians: {0:0.000}x, {1:0.0} ms added", mRatio, mAdded));
            Check(mRatio <= 1.15, string.Format("Analyze with Protect costs at most 1.15x Analyze without it (paired median {0:0.000}x)", mRatio));
            Check(mAdded <= 60, string.Format("Protect adds at most 60 ms to Analyze (paired median {0:0.0} ms)", mAdded));
        }
        catch (Exception ex)
        {
            Check(false, "the timing check ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
        }
    }

    static double Time(ScanResult r)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        var sw = Stopwatch.StartNew();
        r.Analyze();
        return sw.Elapsed.TotalMilliseconds;
    }

    static double Median(List<double> v)
    {
        var s = new List<double>(v);
        s.Sort();
        return s.Count % 2 == 1 ? s[s.Count / 2] : (s[s.Count / 2 - 1] + s[s.Count / 2]) / 2;
    }

    static readonly string[] TopFolders =
    {
        "Downloads", "Documents", "Pictures", "Desktop", "Videos", "Music", "code", "OneDrive", "AppData\\Local", "AppData\\Roaming",
        ".ssh", ".cache", ".vscode", ".nuget\\packages", "go\\pkg\\mod", "source\\repos"
    };

    static readonly string[] FolderWords =
    {
        "src", "lib", "assets", "images", "2019", "2020", "2021", "2022", "2023", "2024", "2025", "Camera", "Screenshots", "node_modules",
        "dist", "build", "bin", "obj", "test", "docs", "Projects", "Work", "Personal", "Invoices", "Photos", "Trip", "Backup", "packages",
        "components", "utils", "Cache", "Logs", "Statements", "tax2024", "payslips", "old", "New folder", "Archive", "vendor", "data"
    };

    static readonly string[] DocNames =
    {
        "Statement 2023-01.pdf", "W2-2024.pdf", "tax-return-2022.pdf", "Payslip-Jan2016.pdf", "passport scan.pdf", "invoice-4471.pdf",
        "manual.pdf", "report-final.pdf", "slides.pdf", "receipt.pdf"
    };

    static readonly string[] OtherNames =
    {
        "index.js", "main.ts", "package.json", "README.md", "notes.txt", "app.dll", "Program.cs", "style.css", "data.csv", "config.yml",
        "LICENSE", "Makefile", "icon.png", "video.mp4", "song.mp3", "setup.exe", "debug.log", "archive.zip", "image.svg", "module.py"
    };

    static readonly string[] DotNames = { ".gitignore", ".editorconfig", ".env.example", ".npmrc", ".prettierrc", ".DS_Store", "_config.yml" };

    static ScanResult Synthetic(ProtectContext ctx)
    {
        var rnd = new Random(1234);
        var root = new DirNode { Name = @"C:\Users\pat", LastWrite = FixedWrite };
        var folders = new List<DirNode>();
        var kids = new Dictionary<DirNode, List<Node>>();
        kids[root] = new List<Node>();
        folders.Add(root);
        foreach (string top in TopFolders)
        {
            DirNode d = root;
            foreach (string part in top.Split('\\'))
            {
                DirNode next = null;
                foreach (Node n in kids[d])
                    if (n.Name == part) next = (DirNode)n;
                if (next == null)
                {
                    next = new DirNode { Name = part, Parent = d, LastWrite = FixedWrite };
                    kids[next] = new List<Node>();
                    kids[d].Add(next);
                    folders.Add(next);
                }
                d = next;
            }
        }
        while (folders.Count < 60000)
        {
            DirNode parent = folders[rnd.Next(folders.Count)];
            var d = new DirNode { Name = FolderWords[rnd.Next(FolderWords.Length)] + (rnd.Next(4) == 0 ? "" : " " + folders.Count),
                Parent = parent, LastWrite = FixedWrite };
            kids[d] = new List<Node>();
            kids[parent].Add(d);
            folders.Add(d);
        }
        for (int i = 0; i < 700000; i++)
        {
            DirNode parent = folders[rnd.Next(folders.Count)];
            int roll = rnd.Next(1000);
            string name;
            if (roll < 300) name = "IMG_" + (1000 + i) + ".jpg";
            else if (roll < 400) name = rnd.Next(20) == 0 ? i + " " + DocNames[rnd.Next(DocNames.Length)] : "document-" + i + ".pdf";
            else if (roll < 450) name = DotNames[rnd.Next(DotNames.Length)];
            else if (roll < 451) name = "id_rsa";
            else name = i + "-" + OtherNames[rnd.Next(OtherNames.Length)];
            var f = new FileNode { Name = name, Parent = parent, Size = 1000 + rnd.Next(5000000), LastWrite = FixedWrite };
            kids[parent].Add(f);
        }
        TotalSynthetic(root, kids);
        var r = new ScanResult { Root = root };
        r.Protect = ctx;
        return r;
    }

    static void TotalSynthetic(DirNode root, Dictionary<DirNode, List<Node>> kids)
    {
        // Children before parents: walk in reverse of a pre-order list.
        var order = new List<DirNode>();
        var stack = new Stack<DirNode>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            DirNode d = stack.Pop();
            order.Add(d);
            foreach (Node n in kids[d])
            {
                var sub = n as DirNode;
                if (sub != null) stack.Push(sub);
            }
        }
        for (int i = order.Count - 1; i >= 0; i--)
        {
            DirNode d = order[i];
            long size = 0, files = 0, dirs = 0;
            foreach (Node n in kids[d])
            {
                var sub = n as DirNode;
                if (sub != null) { size += sub.Size; files += sub.FileCount; dirs += 1 + sub.DirCount; }
                else { size += n.Size; files++; }
            }
            d.Size = size;
            d.LogicalBytes = size;
            d.FileCount = files;
            d.DirCount = dirs;
            Node[] arr = kids[d].ToArray();
            Array.Sort(arr, Node.CompareBySize);
            d.Children = arr;
        }
    }
}

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using DiskSpace;

// Tests for the Protect page: the Finding type, the store, the explanation text and the trust checker
// (stage 0), for stage 1: the by-name corpus, the folder walk in Analyze, refresh after Replace, logical
// bytes, backup coverage and the cost of the per-file gate, and for stage 2: the content scan's checksum,
// selection, plan, reader, corpus, merge and runtime trust tests. Run with tests\run-tests.ps1, which compiles
// this with the app's source, tools\CheckTrust.cs and tests\ContentCorpus.cs.
//
// Every folder these tests create is under the work folder (obj\tests) or %TEMP%. No test opens a file it did
// not write itself. The content files are generated under %TEMP%\dsa-content-<guid> and %TEMP%\dsa-plant-<guid>
// and deleted afterwards; left-over ones from a crashed run are deleted at the start.
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
        SweepStale();
        ContentCorpus.SampleKeys = ProtectConstants.GoogleSampleKeys;

        // Stage 0 and stage 1. None of them may open a file for its contents (spec 4.6.1): the counter is read
        // after every group.
        Group("FindingHasNoRoomForAValue", FindingHasNoRoomForAValue);
        Group("StoreKeepsHashesOnly", StoreKeepsHashesOnly);
        Group("TrustedFoldersCoverTheirContents", TrustedFoldersCoverTheirContents);
        Group("ExplanationComesFromTheConstants", ExplanationComesFromTheConstants);
        Group("CheckerCatchesNetworkCode", () => CheckerCatchesNetworkCode(repo));
        Group("CorpusFilesParse", () => CorpusFilesParse(repo));

        Corpus corpus = Corpus.Load(Path.Combine(repo, @"tests\protect-corpus\by-name\cases.tsv"));
        Group("PatternTable", PatternTable);
        Group("CorpusCounts", () => CorpusCounts(corpus));
        Group("CorpusGate", () => CorpusGate(corpus));
        Group("ForTreeMatchesTheHeader", () => ForTreeMatchesTheHeader(corpus));
        Group("TreeEquality", () => TreeEquality(corpus));
        Group("DriveTrees", () => DriveTrees(corpus));
        Group("FixtureTreeOnDisk", () => FixtureTreeOnDisk(corpus, tree));
        Group("RootCases", RootCases);
        Group("ScannedDocumentsNeedADocument", ScannedDocumentsNeedADocument);
        Group("Refresh", () => Refresh(corpus));
        Group("LogicalBytes", LogicalBytes);
        Group("StoreHidesAndTrusts", StoreHidesAndTrusts);
        Group("DescribeStage1", DescribeStage1);
        Group("Coverage", Coverage);
        Group("SyntheticTiming", SyntheticTiming);
        Check(firstOpenGroup == null && SecretScan.OpenCalls == 0,
            "ZeroOpensWhenOff: no file was opened for its contents after any of the " + groups + " stage 0 and stage 1 groups" +
            (firstOpenGroup == null ? "" : " (first opened in " + firstOpenGroup + ")"));

        // Stage 2: the content scan.
        Guard("ZeroOpensWhenOff", () => ZeroOpensWhenOff(repo));
        Guard("ChecksumKnownAnswers", ChecksumKnownAnswers);
        Guard("ShapeOfSecretScan", () => ShapeOfSecretScan(repo));
        Guard("SampleKeyLines", () => SampleKeyLines(repo));
        Guard("GeneratorSelfCheck", () => GeneratorSelfCheck(repo));
        Guard("ContentCorpusCounts", () => ContentCorpusCounts(repo));
        Guard("Selection", Selection);
        Guard("PlanOrder", PlanOrder);
        Guard("DescribeAndDialog", DescribeAndDialog);
        Guard("MergeGroups", MergeGroups);
        Guard("ContentCorpusGate", () => ContentCorpusGate(repo));
        Guard("SkippedNeverOpened", SkippedNeverOpened);
        Guard("ReaderEdgeCases", ReaderEdgeCases);
        Guard("CancelMidRun", CancelMidRun);
        Guard("MergeCards", () => MergeCards(repo));
        Check(invariantBad == 0, "invariant: across every test tree, no content candidate has a SkipFolders or ContentSkipFolders segment (" +
            invariantChecked + " candidates checked)");

        Console.WriteLine(fails == 0 ? "All checks passed." : fails + " check(s) failed.");
        return fails;
    }

    static int groups;
    static string firstOpenGroup;

    static void Group(string name, Action a)
    {
        a();
        groups++;
        if (firstOpenGroup == null && SecretScan.OpenCalls != 0) firstOpenGroup = name;
    }

    // A stage 2 group: an exception fails the group instead of ending the run.
    static void Guard(string name, Action a)
    {
        try { a(); }
        catch (Exception ex)
        {
            Check(false, name + " ran without an exception (" + ex.GetType().Name + ": " + ex.Message + ")");
            Console.WriteLine(ex.StackTrace);
        }
        finally
        {
            SecretScan.OnOpen = null;
            SecretScan.AfterFile = null;
        }
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
        Check(contentExists, "the build has content patterns, so the content branch of the explanation is taken");
        Check(contentExists == text.Contains(ProtectInfo.Limit(ProtectConstants.MaxContentBytes)),
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
            int rows = 0, bad = 0, badLine = 0;
            bool byContent = name.StartsWith("by-content", StringComparison.Ordinal);
            foreach (string line in File.ReadAllLines(file))
            {
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;
                string[] cols = line.Split('\t');
                if (cols.Length != 4) { bad++; continue; }
                rows++;
                if (!byContent) continue;
                // The by-content line column is L:C or "-", and "-" exactly when nothing is expected.
                bool none = cols[1] == "none";
                bool lc = System.Text.RegularExpressions.Regex.IsMatch(cols[3], @"^[1-9]\d*:[1-9]\d*$");
                if (none ? (cols[2] != "-" || cols[3] != "-") : (!lc || cols[2] == "-"))
                {
                    badLine++;
                    Console.WriteLine("      " + name + ": bad tier or line column: " + line.Replace('\t', ' '));
                }
            }
            Check(bad == 0, name + " parses (" + rows + " cases)");
            if (byContent) Check(badLine == 0, name + ": every line column is L:C for a finding and - for none");
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

    // Stage 2's content rows, in table order (spec 1.2), with their tiers.
    static readonly string[] ContentIds =
    {
        "github-token", "github-fine-grained", "aws-access-key-id", "slack-token", "slack-webhook", "stripe-live-key",
        "google-api-key", "openai-key", "pem-private-key", "pem-private-key-encrypted", "env-secret"
    };

    static readonly FindingTier[] ContentTiers =
    {
        FindingTier.Confirmed, FindingTier.Likely, FindingTier.Likely, FindingTier.Likely, FindingTier.Likely, FindingTier.Likely,
        FindingTier.Likely, FindingTier.Likely, FindingTier.Confirmed, FindingTier.Confirmed, FindingTier.Likely
    };

    static void PatternTable()
    {
        PatternInfo[] p = ProtectConstants.Patterns;
        int names = ExpectedIds.Length;
        bool order = p.Length == names + ContentIds.Length;
        for (int i = 0; order && i < names; i++) order = p[i].Id == ExpectedIds[i] && p[i].ReadsContent == "name";
        Check(order, "Patterns has the 38 stage 1 name rows first, in table order (" + p.Length + " rows)");
        bool content = p.Length == names + ContentIds.Length;
        for (int i = 0; content && i < ContentIds.Length; i++)
            content = p[names + i].Id == ContentIds[i] && p[names + i].ReadsContent == "content" && p[names + i].Tier == ContentTiers[i];
        Check(content, "the last 11 rows are the content rows of spec 1.2, in order, reading content, with their tiers");
        Check(p.Length == 49, "Patterns has 49 rows (" + p.Length + ")");
        Check(Array.TrueForAll(p, x => x.ReadsContent == "content" || x.ReadsContent == "name"), "every row reads names or content");
        Check(!Array.Exists(p, x => x.ReadsContent == "content" && x.Tier == FindingTier.WorthALook), "no content row is Worth a look");
        Check(Array.TrueForAll(p, x => !string.IsNullOrEmpty(x.Kind)), "every row has a Kind");

        NameRuleInfo[] rules = ProtectConstants.NameRules;
        bool same = rules.Length == names;
        for (int i = 0; same && i < rules.Length; i++) same = rules[i].Id == p[i].Id && !string.IsNullOrEmpty(rules[i].Usual);
        Check(same, "NameRules has one entry per name row, in the same order (" + rules.Length + ")");

        ContentRuleInfo[] crules = ProtectConstants.ContentRules;
        bool parallel = crules.Length == ContentIds.Length;
        for (int i = 0; parallel && i < crules.Length; i++)
            parallel = crules[i].Id == ContentIds[i] && !string.IsNullOrEmpty(crules[i].Rule) && !string.IsNullOrEmpty(crules[i].Reason) &&
                       !string.IsNullOrEmpty(crules[i].Plural);
        Check(parallel, "ContentRules has one entry per content row, in the same order, each with a rule, a reason and a plural (" + crules.Length + ")");
        bool index = true;
        for (int i = 0; i < ContentIds.Length; i++) index &= SecretScan.RowIndex(ContentIds[i]) == i;
        Check(index, "SecretScan.RowIndex numbers the content rows in table order");
        Check(ProtectConstants.ContentTableVersion == 1 && ProtectConstants.ContentFindingsPerFile == 20 && ProtectConstants.ContentRowsPerCard == 50,
            "the content table is version 1, with 20 findings per file and 50 rows per card");

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
        int rowsCovered = 0, nameRows = 0;
        foreach (PatternInfo p in ProtectConstants.Patterns)
        {
            if (p.ReadsContent != "name") continue;
            nameRows++;
            if (withPositive.Contains(p.Id)) rowsCovered++;
            else Console.WriteLine("      no positive case for " + p.Id);
        }
        Check(rowsCovered == 38 && rowsCovered == nameRows, "all 38 name rows have a positive case (" + rowsCovered + ")");
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
        Check(text.Contains("No file is opened for its contents unless you turn on the content scan.") &&
              !text.Contains("No file is opened for its contents in a normal scan."),
            "Describe says no file is opened for its contents unless you turn on the content scan");
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

    // =====================================================================================================
    // Stage 2: the content scan
    //
    // The keys these tests use are built at run time by ContentCorpus, in folders under %TEMP%. No literal in
    // this file has a key's format: the generator self-check runs the matcher over this file too.

    static int invariantBad, invariantChecked;

    static readonly string[] StalePrefixes = { "dsa-content-", "dsa-plant-" };

    static string TempRoot(string prefix)
    {
        string d = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    // Generated content files hold well-formed test keys, so a crashed run must not leave them in Temp.
    static void SweepStale()
    {
        int n = 0;
        try
        {
            foreach (string d in Directory.GetDirectories(Path.GetTempPath()))
            {
                string name = Path.GetFileName(d);
                foreach (string p in StalePrefixes)
                {
                    if (!name.StartsWith(p, StringComparison.OrdinalIgnoreCase)) continue;
                    DeleteTree(d);
                    n++;
                    break;
                }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        if (n > 0) Console.WriteLine("      removed " + n + " left-over generated folder(s) from %TEMP%");
    }

    // Deletes a folder these tests generated. A link inside it is removed as a link and never followed.
    static void DeleteTree(string dir)
    {
        for (int attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                if (!Directory.Exists(dir)) return;
                DeleteInside(dir);
                Directory.Delete(dir, false);
                return;
            }
            catch (IOException) { Thread.Sleep(100); }
            catch (UnauthorizedAccessException) { Thread.Sleep(100); }
        }
        if (Directory.Exists(dir)) Check(false, "the generated folder " + dir + " was deleted");
    }

    static void DeleteInside(string dir)
    {
        foreach (string f in Directory.GetFiles(dir))
        {
            if ((File.GetAttributes(f) & FileAttributes.ReadOnly) != 0) File.SetAttributes(f, FileAttributes.Normal);
            File.Delete(f);
        }
        foreach (string d in Directory.GetDirectories(dir))
        {
            if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) == 0) DeleteInside(d);
            Directory.Delete(d, false);
        }
    }

    static string Tok(int seed, List<string> values)
    {
        return ContentCorpus.Expand("<<gh:ghp:" + seed + ">>", values);
    }

    static void WriteText(string path, string text)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        File.WriteAllText(path, text, new UTF8Encoding(false));
    }

    static void WriteBytes(string path, params byte[][] parts)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        var all = new List<byte>();
        foreach (byte[] p in parts) all.AddRange(p);
        File.WriteAllBytes(path, all.ToArray());
    }

    static byte[] Ascii(string s)
    {
        var b = new byte[s.Length];
        for (int i = 0; i < s.Length; i++) b[i] = (byte)s[i];
        return b;
    }

    static void AppendFiller(string path, long size)
    {
        byte[] unit = Ascii("not a secret ");
        var b = new byte[size];
        for (long i = 0; i < size; i++) b[i] = unit[i % unit.Length];
        using (var fs = new FileStream(path, FileMode.Append, FileAccess.Write)) fs.Write(b, 0, b.Length);
    }

    static bool AllZero(byte[] b)
    {
        if (b == null) return false;
        for (int i = 0; i < b.Length; i++) if (b[i] != 0) return false;
        return true;
    }

    static bool SlotsEmpty()
    {
        byte[][] slots = SecretScan.WorkerBuffers;
        if (slots != null) foreach (byte[] s in slots) if (s != null) return false;
        return true;
    }

    // The path the reader got, without the \\?\ long-path prefix.
    static string Plain(string longPath)
    {
        if (longPath.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + longPath.Substring(8);
        if (longPath.StartsWith(@"\\?\", StringComparison.Ordinal)) return longPath.Substring(4);
        return longPath;
    }

    static ScanResult ScanDisk(string root, string home)
    {
        ScanResult r = new Scanner().Scan(root, CancellationToken.None);
        r.Protect = ProtectContext.ForTree(home);
        r.Analyze();
        Invariant(r);
        return r;
    }

    static ContentResult Read(ContentPlan plan, ContentProgress p, CancellationToken ct)
    {
        return SecretScan.Run(ContentConsent.FromCommandLine(true), plan, p, ct);
    }

    static bool IsCandidate(ScanResult r, string path)
    {
        string n = ProtectStore.Normalize(path);
        foreach (ContentCandidate c in r.ContentCandidates)
            if (ProtectStore.Normalize(c.Node.FullPath) == n) return true;
        return false;
    }

    // The content rows of Patterns, in table order (MatchBuffer's row numbers).
    static PatternInfo ContentRow(int i)
    {
        int seen = 0;
        foreach (PatternInfo p in ProtectConstants.Patterns)
        {
            if (p.ReadsContent != "content") continue;
            if (seen == i) return p;
            seen++;
        }
        throw new ArgumentOutOfRangeException("i", "no content row " + i);
    }

    // No candidate may sit below a SkipFolders or ContentSkipFolders segment (spec 10.1.5).
    static void Invariant(ScanResult r)
    {
        foreach (ContentCandidate c in r.ContentCandidates)
        {
            invariantChecked++;
            string path = c.Node.FullPath;
            string seg = SkipSegment(path) ?? ContentSkipSegment(path);
            if (seg == null) continue;
            invariantBad++;
            Console.WriteLine("      candidate " + path + " is under " + seg);
        }
    }

    static string ContentSkipSegment(string path)
    {
        string[] segs = path.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string entry in ProtectConstants.ContentSkipFolders)
        {
            if (entry.IndexOf(' ') >= 0) continue;  // an anchored rule written in words
            string[] parts = entry.Split('\\');
            for (int i = 1; i + parts.Length <= segs.Length - 1; i++)
            {
                bool all = true;
                for (int k = 0; all && k < parts.Length; k++) all = string.Equals(segs[i + k], parts[k], StringComparison.OrdinalIgnoreCase);
                if (all) return entry;
            }
        }
        return null;
    }

    // ---------------------------------------------------------------------------------------------------
    // 4.6.1 ZeroOpensWhenOff

    static void ZeroOpensWhenOff(string repo)
    {
        var off = new ProtectStore();
        var on = new ProtectStore();
        on.ContentScan = true;
        Check(ContentConsent.FromStore(off) == null && ContentConsent.FromStore(null) == null,
            "ZeroOpensWhenOff: FromStore gives no consent while the content scan is off");
        Check(ContentConsent.FromStore(on) != null, "FromStore gives consent once the content scan is on");
        Check(ContentConsent.FromCommandLine(false) == null && ContentConsent.FromCommandLine(true) != null,
            "FromCommandLine gives consent only for --content");

        var t = new Tree(@"C:\Users\pat");
        t.File(@"C:\Users\pat\notes.txt", 300, false);
        ScanResult r = t.Finish(ProtectContext.ForTree(@"C:\Users\pat"));
        r.Analyze();
        ContentPlan plan = SecretScan.Plan(r, off, null);
        long before = SecretScan.OpenCalls;
        bool runThrew = false, beginThrew = false;
        try { SecretScan.Run(null, plan, new ContentProgress(), CancellationToken.None); }
        catch (ArgumentNullException) { runThrew = true; }
        try { SecretScan.Begin(null, plan, new ContentProgress(), CancellationToken.None); }
        catch (ArgumentNullException) { beginThrew = true; }
        Check(runThrew && beginThrew && SecretScan.OpenCalls == before,
            "Run and Begin without consent throw ArgumentNullException and open nothing (" + (SecretScan.OpenCalls - before) + " opens)");

        App app = App.Load(repo);
        if (app == null) return;
        bool gateOff = false, gateOn = false;
        App.Sta(() =>
        {
            object window = FormatterServices.GetUninitializedObject(app.T("MainWindow"));
            object store = app.New("ProtectStore");
            App.Set(store, "ContentScan", false);
            App.Set(window, "protectStore", store);
            gateOff = (bool)App.I(window, "ContentGate");
            App.Set(store, "ContentScan", true);
            gateOn = (bool)App.I(window, "ContentGate");
        });
        Check(!gateOff && gateOn, "the page's ContentGate() is false with the switch off, so nothing calls Run (and true with it on)");
    }

    // ---------------------------------------------------------------------------------------------------
    // 4.6.7 ChecksumKnownAnswers

    static void ChecksumKnownAnswers()
    {
        byte[] nine = Ascii("123456789");
        Check(SecretScan.Crc32(nine, 0, 9) == 0xCBF43926 && ContentCorpus.Crc32(nine, 0, 9) == 0xCBF43926,
            "Crc32(\"123456789\") is 0xCBF43926 in the app and in the test's own bitwise CRC");
        Check(SecretScan.Base62Matches(0, Ascii("000000"), 0) && SecretScan.Base62Matches(0xFFFFFFFF, Ascii("4gfFC3"), 0) &&
              ContentCorpus.Base62(0) == "000000" && ContentCorpus.Base62(0xFFFFFFFF) == "4gfFC3",
            "base62 of 0 is 000000 and of 0xFFFFFFFF is 4gfFC3, in the app and in the test");
        Check(!SecretScan.Base62Matches(0xFFFFFFFF, Ascii("4gfFC4"), 0) && SecretScan.Base62Matches(0, Ascii("x000000"), 1),
            "Base62Matches refuses a wrong digit and honours its offset");

        var rnd = new Random(4242);
        int crcBad = 0, b62Bad = 0;
        for (int i = 0; i < 1000; i++)
        {
            var buf = new byte[rnd.Next(1, 300)];
            rnd.NextBytes(buf);
            int off = rnd.Next(buf.Length), len = rnd.Next(buf.Length - off + 1);
            if (SecretScan.Crc32(buf, off, len) != ContentCorpus.Crc32(buf, off, len)) crcBad++;

            uint v = (uint)rnd.Next() ^ ((uint)rnd.Next(4) << 30);
            byte[] digits = Ascii("ab" + ContentCorpus.Base62(v));
            if (!SecretScan.Base62Matches(v, digits, 2)) b62Bad++;
            int k = 2 + rnd.Next(6);
            digits[k] = (byte)(digits[k] == (byte)'0' ? '1' : '0');
            if (SecretScan.Base62Matches(v, digits, 2)) b62Bad++;
        }
        Check(crcBad == 0, "the app's Crc32 equals the independent bitwise CRC on 1,000 seeded inputs (" + crcBad + " differ)");
        Check(b62Bad == 0, "Base62Matches agrees with the independent base62 encoder on 1,000 seeded values (" + b62Bad + " differ)");
    }

    // ---------------------------------------------------------------------------------------------------
    // 4.6.6 ShapeOfSecretScan

    static readonly string[] AllowedStaticBytes = { "WorkerBuffers", "GoogleSampleBytes", "PrefixTable", "Base62Alphabet" };

    static void ShapeOfSecretScan(string repo)
    {
        string source = File.ReadAllText(Path.Combine(repo, @"src\SecretScan.cs"));
        var declared = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in Regex.Matches(source, @"\b(?:class|struct)\s+([A-Za-z_]\w*)")) declared.Add(m.Groups[1].Value);
        var types = new List<Type>();
        foreach (Type t in typeof(SecretScan).Assembly.GetTypes())
            if (declared.Contains(t.Name) && t.Namespace == typeof(SecretScan).Namespace) types.Add(t);
        Check(types.Exists(x => x == typeof(SecretScan)) && types.Exists(x => x == typeof(ContentConsent)) && types.Count >= 6,
            "ShapeOfSecretScan: found the types declared in SecretScan.cs (" + types.Count + ")");

        var badFields = new List<string>();
        var staticBytes = new List<string>();
        foreach (Type t in types)
        {
            foreach (FieldInfo f in t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                if (f.FieldType == typeof(string) || f.FieldType == typeof(byte[]))
                    badFields.Add(t.Name + "." + f.Name);
            foreach (FieldInfo f in t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            {
                Type ft = f.FieldType;
                bool bytes = ft == typeof(byte[]) || ft == typeof(byte[][]);
                if (!bytes) continue;
                staticBytes.Add(f.Name);
                bool allowed = Array.IndexOf(AllowedStaticBytes, f.Name) >= 0 && (f.Name == "WorkerBuffers" || f.IsInitOnly);
                if (!allowed) badFields.Add("static " + t.Name + "." + f.Name);
            }
        }
        Check(badFields.Count == 0, "no type in SecretScan.cs has an instance string or byte[] field, and the static byte tables are only " +
            string.Join(", ", AllowedStaticBytes) + " (found " + string.Join(", ", staticBytes) +
            (badFields.Count == 0 ? "" : "; not allowed: " + string.Join(", ", badFields)) + ")");
        Check(staticBytes.Contains("WorkerBuffers"), "SecretScan.WorkerBuffers is the one mutable static byte field");
        FindingHasNoRoomForAValue();
        Check(GCSettings.LargeObjectHeapCompactionMode == GCLargeObjectHeapCompactionMode.Default,
            "the large object heap compaction mode is Default, so a reader buffer is never moved and copied");
    }

    // ---------------------------------------------------------------------------------------------------
    // 1.4 The published Google sample keys

    static void SampleKeyLines(string repo)
    {
        string[] keys = ProtectConstants.GoogleSampleKeys;
        Check(keys.Length == ProtectConstants.SampleKeyCount && keys.Length > 0,
            "SampleKeyCount equals the number of GoogleSampleKeys (" + ProtectConstants.SampleKeyCount + ", " + keys.Length + ")");
        Check(Array.TrueForAll(keys, k => k.Length == 39 && k.StartsWith("AI" + "za", StringComparison.Ordinal)),
            "every sample key has the Google key shape (39 characters)");
        int lines = 0, unsplit = 0;
        foreach (string line in File.ReadAllLines(Path.Combine(repo, @"src\Protect.cs")))
        {
            if (line.IndexOf("// sample-key:", StringComparison.Ordinal) < 0) continue;
            lines++;
            Match m = Regex.Match(line, "\"([^\"]*)\"\\s*\\+\\s*\"");
            if (!m.Success || m.Groups[1].Value.Length >= 8) unsplit++;
        }
        Check(lines == ProtectConstants.SampleKeyCount && unsplit == 0,
            "every // sample-key: line in Protect.cs splits its key before byte 8 (" + lines + " lines, " + unsplit + " not split)");
    }

    // ---------------------------------------------------------------------------------------------------
    // 10.1.4 The generator self-check: no committed file holds a match

    static void GeneratorSelfCheck(string repo)
    {
        var files = new List<string>
        {
            Path.Combine(repo, @"tests\ContentCorpus.cs"), Path.Combine(repo, @"tests\ProtectTests.cs"),
            Path.Combine(repo, @"src\SecretScan.cs"), Path.Combine(repo, @"src\Protect.cs"),
            Path.Combine(repo, @"tests\protect-corpus\README.md"), Path.Combine(repo, @"tests\protect-corpus\by-content\cases.tsv")
        };
        int sources = files.Count;
        files.AddRange(Directory.GetFiles(Path.Combine(repo, @"tests\protect-corpus\by-content\files"), "*.tpl", SearchOption.AllDirectories));
        var triples = new int[3 * ProtectConstants.ContentFindingsPerFile];
        int hits = 0;
        foreach (string f in files)
        {
            byte[] b = File.ReadAllBytes(f);
            // Templates are also matched as .env files, so the env-secret row sees them too.
            bool template = f.EndsWith(".tpl", StringComparison.OrdinalIgnoreCase);
            foreach (ContentKind kind in template ? new[] { ContentKind.Text, ContentKind.Dotenv } : new[] { ContentKind.Text })
            {
                int n = SecretScan.MatchBuffer(b, 0, b.Length, kind, triples);
                for (int i = 0; i < n && i < ProtectConstants.ContentFindingsPerFile; i++)
                    Console.WriteLine("      " + f + " " + kind + ": " + ContentRow(triples[3 * i]).Id + " at " + triples[3 * i + 1] + ":" + triples[3 * i + 2]);
                hits += n;
            }
        }
        Check(hits == 0, "generator self-check: the matcher finds nothing in ContentCorpus.cs, ProtectTests.cs, SecretScan.cs, Protect.cs, " +
            "the corpus README and cases.tsv, or any of the " + (files.Count - sources) + " templates (" + hits + " hits)");
    }

    // ---------------------------------------------------------------------------------------------------
    // 8.3 CorpusCounts for the by-content corpus

    const int ContentCases = 120, ContentNegatives = 58, ContentFiles = 100;

    static void ContentCorpusCounts(string repo)
    {
        string dir = Path.Combine(repo, @"tests\protect-corpus\by-content");
        ContentCorpus.CaseSet set = ContentCorpus.Load(Path.Combine(dir, "cases.tsv"));
        int negatives = set.Rows.FindAll(k => !k.Positive).Count;
        Check(set.Rows.Count == ContentCases && negatives == ContentNegatives && set.Files.Count == ContentFiles,
            "the by-content corpus has " + ContentCases + " cases, " + ContentNegatives + " negatives and " + ContentFiles + " files (" +
            set.Rows.Count + ", " + negatives + ", " + set.Files.Count + ")");
        bool rows = true;
        for (int i = 0; i < ContentIds.Length; i++)
        {
            string id = ContentIds[i];
            int pos = set.Rows.FindAll(k => k.Expect == id).Count, neg = set.Rows.FindAll(k => !k.Positive && k.Section == id).Count;
            if (pos >= 2 && neg >= 2) continue;
            rows = false;
            Console.WriteLine("      " + id + ": " + pos + " positives, " + neg + " negatives");
        }
        Check(rows, "every content row has at least 2 positive and 2 negative cases");
        bool known = true;
        foreach (ContentCorpus.Row k in set.Rows)
        {
            if (!k.Positive) continue;
            int i = Array.IndexOf(ContentIds, k.Expect);
            if (i >= 0 && k.Tier == ContentTiers[i].ToString()) continue;
            known = false;
            Console.WriteLine("      line " + k.Line + ": " + k.Expect + " " + k.Tier + " is not a content row with that tier");
        }
        Check(known, "every expected id is a content row, with that row's tier");
        bool alone = true;
        foreach (ContentCorpus.CaseFile f in set.Files)
            if (f.Rows.Exists(k => !k.Positive) && f.Rows.Count != 1) { alone = false; Console.WriteLine("      " + f.File + " mixes none with findings"); }
        Check(alone, "a file expected to give nothing has a single none row");
        int templates = Directory.GetFiles(Path.Combine(dir, "files"), "*.tpl", SearchOption.AllDirectories).Length;
        bool all = set.Files.TrueForAll(f => File.Exists(ContentCorpus.TemplatePath(Path.Combine(dir, "files"), f.File)));
        Check(all && templates == set.Files.Count, "every corpus file has a template and every template is used (" + templates + " templates)");
    }

    // ---------------------------------------------------------------------------------------------------
    // 10.1.5 Selection, on trees built in memory

    static void Selection()
    {
        const string h = @"C:\Users\pat";
        var t = new Tree(h);
        string[] yes =
        {
            @"notes.txt", @"code\app\src\main.py", @"code\app\notes.json", @".ssh\config", @".kube\config", @".aws\credentials",
            @"Desktop\.env", @"bin\tool.ps1", @"target\notes.md", @"code\go1\vendor\x.go", @"code\py1\env\a.py",
            @"code\rs\Cargo.toml", @"code\php\composer.json", @"AppData\Roaming\gcloud\credentials.json", @"AppData\Local\Temp\x.txt",
            @"OneDrive\Documents\notes.txt", @"Documents\extensions\notes.txt", @"code\app\.env.local"
        };
        string[] no =
        {
            @"code\app\node_modules\p\i.js", @"code\app\build\out.txt", @"code\app\bin\x.txt", @"code\app\obj\y.cs", @"code\app\out\z.js",
            @"code\app\intermediates\w.json", @"code\rs\target\t.txt", @"code\php\vendor\v.php", @"code\go2\vendor\v.go",
            @"code\py2\env\lib.py", @"code\py2\env\pyvenv.cfg", @"code\py3\.venv\x.py", @"code\py4\site-packages\a.py",
            @"code\py4\__pycache__\b.py", @"code\py4\.tox\c.py", @"code\tf\.terraform\d.tf", @"code\web\.next\e.js",
            @"code\web\bower_components\f.js", @"code\web\.svelte-kit\g.js", @"code\go\pkg\mod\m.go", @".vscode\extensions\e\p.json",
            @".antigravity\extensions\e\package.json", @".vscode\settings.json", @".cargo\registry\x.toml", @".claude\settings.json",
            @"code\.tools\extensions\z.json", @"AppData\Local\Packages\p\e.json", @"AppData\Roaming\Code\User\settings.json",
            @"$x\f.txt", @"code\app\test\t.json", @"code\examples\e.json", @"code\app\vendor.min.js", @"code\app\page.html",
            @"code\app\app.log", @"AppData\Local\Temp\cachefile", @"code\app\config", @"code\app\.git\config", @"online.txt",
            @"link.txt", @"empty.txt", @"big.txt", @"code\app\.env.example"
        };
        foreach (string s in yes) t.File(h + "\\" + s, 900, false);
        foreach (string s in no)
        {
            long size = s == "empty.txt" ? 0 : s == "big.txt" ? 2 * ProtectConstants.MaxContentBytes : 900;
            FileNode f = t.File(h + "\\" + s, size, s == "online.txt");
            if (s == "link.txt") f.Flags |= FileFlags.Link;
        }
        t.File(h + @"\code\go2\go.mod", 100, false);
        t.Dir(h + @"\code\app\.git");
        ScanResult r = t.Finish(ProtectContext.ForTree(h));
        r.Analyze();
        Invariant(r);

        int missing = 0, extra = 0;
        foreach (string s in yes)
            if (!IsCandidate(r, h + "\\" + s)) { missing++; Console.WriteLine("      not a candidate: " + s); }
        foreach (string s in no)
            if (IsCandidate(r, h + "\\" + s)) { extra++; Console.WriteLine("      a candidate: " + s); }
        Check(missing == 0, "selection: every file outside the content skips is a candidate (anchored rules both ways, cloud file without Link, config in a tool home)");
        Check(extra == 0, "selection: no file under a NoContent folder, OnlineOnly, Link, empty, over 1 MiB, .min.js, .html, .log or extensionless is a candidate");

        ContentCandidate env = null, ssh = null, repo = null;
        foreach (ContentCandidate c in r.ContentCandidates)
        {
            string p = ProtectStore.Normalize(c.Node.FullPath);
            if (p == ProtectStore.Normalize(h + @"\Desktop\.env")) env = c;
            if (p == ProtectStore.Normalize(h + @"\.ssh\config")) ssh = c;
            if (p == ProtectStore.Normalize(h + @"\code\app\src\main.py")) repo = c;
        }
        Check(env != null && env.Kind == ContentKind.Dotenv && env.Place == Place.Desktop && env.Size == 900,
            "a .env candidate has Kind Dotenv, its place and its size");
        Check(ssh != null && ssh.Kind == ContentKind.Text && ssh.Place == Place.UsualPlace, "a file in a tool home is Text in its usual place");
        Check(repo != null && repo.Place == Place.Repository, "a file in a repository has Place Repository");
        Check(r.ContentTooLarge == 1 && r.ContentOnlineOnly == 1 && r.ContentSkippedFolders > 0,
            "Analyze counts 1 text file too large, 1 online-only and the skipped folders (" + r.ContentTooLarge + ", " +
            r.ContentOnlineOnly + ", " + r.ContentSkippedFolders + ")");

        Check(ProtectContext.IsNetworkPath(@"\\server\share") && ProtectContext.IsNetworkPath(@"\\?\UNC\server\share\x") &&
              !ProtectContext.IsNetworkPath(@"\\?\C:\Users") && !ProtectContext.IsNetworkPath(h) && !ProtectContext.IsNetworkPath(""),
            "UNC paths count as network paths; local paths, long local paths and an empty path do not");
        foreach (string root in new[] { h + @"\code\web\node_modules\pkg", @"C:\Program Files\x", @"\\server\share\docs", @"\\?\UNC\server\share\docs" })
        {
            var inside = new Tree(root);
            inside.File(root + @"\a.txt", 500, false);
            inside.File(root + @"\b.json", 500, false);
            ScanResult ri = inside.Finish(ProtectContext.ForTree(h));
            ri.Analyze();
            Check(ri.ContentCandidates.Length == 0, "a scan rooted at " + root + " has no content candidates (" + ri.ContentCandidates.Length + ")");
        }
        var plain = new Tree(h);
        plain.File(h + @"\notes.txt", 500, false);
        ScanResult off = plain.Finish(null);
        off.Analyze();
        Check(off.ContentCandidates != null && off.ContentCandidates.Length == 0, "with Protect null, ContentCandidates is empty and not null");
    }

    // ---------------------------------------------------------------------------------------------------
    // 10.1.6 Plan

    static void PlanOrder()
    {
        var t = new Tree(@"C:\P");
        long sumAB = 0;
        for (int i = 0; i < 12; i++) { long s = (i * 373 % 1000) + 1; t.File(@"C:\P\A\a" + i + ".txt", s, false); sumAB += s; }
        for (int i = 0; i < 8; i++) { long s = (i * 611 % 3000) + 7; t.File(@"C:\P\B\b" + i + ".txt", s, false); sumAB += s; }
        for (int i = 0; i < 5; i++) t.File(@"C:\P\T\t" + i + ".txt", 50 + i, false);
        DirNode a = t.Dir(@"C:\P\A");
        ScanResult r = t.Finish(ProtectContext.ForTree(@"C:\Users\pat"));
        r.Analyze();
        var store = new ProtectStore();
        store.Trust(@"C:\P\T");

        ContentPlan plan = SecretScan.Plan(r, store, null);
        Check(plan.Files.Length == 20 && plan.TrustedSkipped == 5 && plan.TotalBytes == sumAB && plan.Source == r,
            "Plan drops the 5 files in a trusted folder and totals the rest (" + plan.Files.Length + " files, " + plan.TrustedSkipped + " trusted, " +
            plan.TotalBytes + " bytes)");
        bool lanes = true;
        for (int i = 0; i + 4 < plan.Files.Length; i++) lanes &= plan.Files[i].Size >= plan.Files[i + 4].Size;
        var sizes = new List<long>();
        foreach (ContentCandidate c in plan.Files) sizes.Add(c.Size);
        sizes.Sort();
        sizes.Reverse();
        var head = new List<long>();
        for (int i = 0; i < 4 && i < plan.Files.Length; i++) head.Add(plan.Files[i].Size);
        head.Sort();
        head.Reverse();
        for (int i = 0; i < head.Count; i++) lanes &= head[i] == sizes[i];
        Check(lanes, "Plan deals the largest files first, one to each of 4 interleaved lanes, each lane largest first");
        bool parallel = plan.LongPaths.Length == plan.Files.Length;
        for (int i = 0; parallel && i < plan.Files.Length; i++) parallel = plan.LongPaths[i] == Scanner.LongPath(plan.Files[i].Node.FullPath);
        Check(parallel, "Plan's LongPaths run parallel to Files, as Scanner.LongPath of each node");
        Check(plan.TooLarge == r.ContentTooLarge && plan.OnlineOnly == r.ContentOnlineOnly && plan.SkippedFolders == r.ContentSkippedFolders,
            "Plan carries the scan's too-large, online-only and skipped-folder counts");

        ContentPlan under = SecretScan.Plan(r, store, a);
        Check(under.Files.Length == 12 && Array.TrueForAll(under.Files, c => c.Node.IsUnder(a)), "Plan under a folder keeps only the files below it (" + under.Files.Length + ")");
        ContentPlan open = SecretScan.Plan(r, new ProtectStore(), null);
        Check(open.Files.Length == 25 && open.TrustedSkipped == 0, "with nothing trusted, Plan keeps every candidate (" + open.Files.Length + ")");
        Check(!object.ReferenceEquals(open.Files, r.ContentCandidates), "Plan copies the candidates instead of handing out the scan's array");
    }

    // ---------------------------------------------------------------------------------------------------
    // 10.1.10 Describe and the dialog

    static void DescribeAndDialog()
    {
        string text = ProtectInfo.AsText();
        var missing = new List<string>();
        var lists = new List<string>();
        lists.AddRange(ProtectConstants.TextExtensions);
        lists.AddRange(ProtectConstants.TextNames);
        lists.AddRange(ProtectConstants.SkipFolders);
        lists.AddRange(ProtectConstants.ContentSkipFolders);
        lists.AddRange(ProtectConstants.FixtureFolders);
        lists.Add(ProtectInfo.Limit(ProtectConstants.MaxContentBytes));
        lists.Add(ProtectInfo.Limit(ProtectConstants.BinaryProbeBytes));
        lists.Add(ProtectConstants.ContentWorkers + " files are read at a time");
        lists.Add((ProtectConstants.SampleKeyCount + 2) + " published sample keys are never reported");
        foreach (ContentRuleInfo c in ProtectConstants.ContentRules) lists.Add(c.Rule);
        lists.Add("Nothing read here is kept after the scan.");
        lists.Add(ProtectConstants.NetworkDrivesNote);
        lists.Add("A match is shown as a file and a line number. The key itself is never shown, copied or saved.");
        foreach (string s in lists) if (!text.Contains(s)) missing.Add(s);
        Check(missing.Count == 0, "Describe quotes the text extensions and names, the skipped folders, the size limits, the reader count, " +
            "the sample-key count and every content rule" + (missing.Count == 0 ? "" : " (missing: " + string.Join(" | ", missing) + ")"));
        missing.Clear();
        foreach (string s in ProtectConstants.ContentHeldBack) if (!text.Contains(s)) missing.Add(s);
        Check(missing.Count == 0, "Describe lists what the content scan does not look for yet");

        // A plan with 3 text files, one too large and one online-only.
        const string h = @"C:\Users\pat";
        var t = new Tree(h);
        t.File(h + @"\a.txt", 1000, false);
        t.File(h + @"\b.json", 2000, false);
        t.File(h + @"\Desktop\.env", 300, false);
        t.File(h + @"\big.txt", 3 * ProtectConstants.MaxContentBytes, false);
        t.File(h + @"\online.txt", 5000, true);
        ScanResult r = t.Finish(ProtectContext.ForTree(h));
        r.Analyze();
        ContentPlan plan = SecretScan.Plan(r, new ProtectStore(), null);
        string[] lines = ProtectInfo.ContentDialog(plan, @"C:\");
        string dialog = string.Join("\n", lines);
        missing.Clear();
        var want = new List<string>
        {
            "Protect will read " + Fmt.Count(plan.Files.Length) + " text files (" + Fmt.Size(plan.TotalBytes) + ") found by this scan of C:\\",
            "each up to " + ProtectInfo.Limit(ProtectConstants.MaxContentBytes), ProtectConstants.ContentRules.Length + " kinds of key",
            ProtectInfo.Limit(ProtectConstants.BinaryProbeBytes), "1 larger text file", "1 online-only file",
            "It does not guess from random-looking text. Published sample keys are never reported.",
            "A match is shown as a file and a line number. The key itself is never shown, copied or saved."
        };
        want.AddRange(ProtectConstants.SkipFolders);
        want.AddRange(ProtectConstants.ContentSkipFolders);
        foreach (string s in want) if (!dialog.Contains(s)) missing.Add(s);
        Check(missing.Count == 0, "the dialog states the plan, the size limits, the row count and every skipped folder" +
            (missing.Count == 0 ? "" : " (missing: " + string.Join(" | ", missing) + ")"));
        Check(Array.IndexOf(lines, "Nothing read here is kept after the scan.") >= 0,
            "the dialog has the sentence \"Nothing read here is kept after the scan.\" as its own paragraph");
        bool inDescribe = text.Contains(ProtectInfo.Limit(ProtectConstants.MaxContentBytes)) && text.Contains(ProtectInfo.Limit(ProtectConstants.BinaryProbeBytes));
        foreach (string s in ProtectConstants.SkipFolders) inDescribe &= text.Contains(s);
        foreach (string s in ProtectConstants.ContentSkipFolders) inDescribe &= text.Contains(s);
        Check(inDescribe, "every size and folder list in the dialog also appears in Describe");

        string[] other = ProtectInfo.ContentDialog(plan, @"D:\work");
        Check(string.Join("\n", other).Contains("found by this scan of D:\\work"), "the dialog names a scan root that is not a whole drive");

        var empty = new Tree(h);
        empty.File(h + @"\photo.png", 4000, false);
        ScanResult re = empty.Finish(ProtectContext.ForTree(h));
        re.Analyze();
        string zero = string.Join("\n", ProtectInfo.ContentDialog(SecretScan.Plan(re, new ProtectStore(), null), @"C:\"));
        Check(zero.Contains("No text files in this scan qualify.") && !zero.Contains("larger text file") && !zero.Contains("online-only file"),
            "with no candidates the dialog says no text files qualify, and leaves out the clauses whose count is 0");
    }

    // ---------------------------------------------------------------------------------------------------
    // 10.1.9 Merge: the shared grouping and Replace

    static void MergeGroups()
    {
        const string ssh = @"C:\Users\pat\.ssh\id_rsa", env = @"C:\Users\pat\code\app\.env", sec = @"C:\Users\pat\code\app\.secrets.env";
        var byNameUsual = new Finding("ssh-key", FindingTier.Confirmed, ssh, 0, 0, Place.UsualPlace);
        var contentUsual = new Finding("pem-private-key", FindingTier.Confirmed, ssh, 1, 1, Place.UsualPlace);
        var dotenv = new Finding("dotenv", FindingTier.Likely, env, 0, 0, Place.Repository);
        var envSecret = new Finding("env-secret", FindingTier.Likely, env, 3, 11, Place.Repository);
        var token = new Finding("github-token", FindingTier.Confirmed, sec, 2, 14, Place.Repository);
        var tokenDownloads = new Finding("github-token", FindingTier.Confirmed, @"C:\Users\pat\Downloads\notes.txt", 1, 1, Place.Downloads);
        Check(ProtectInfo.GroupOf(byNameUsual, true, false) == ProtectInfo.GroupUsual && ProtectInfo.GroupOf(contentUsual, true, false) == ProtectInfo.GroupUsual,
            "GroupOf: a path with a usual-place finding stays in the usual places, content hit or not");
        Check(ProtectInfo.GroupOf(dotenv, false, true) == ProtectInfo.GroupProjects && ProtectInfo.GroupOf(envSecret, false, true) == ProtectInfo.GroupProjects,
            "GroupOf: a repository .env whose only content findings are env-secret stays in the projects group");
        int g = ProtectInfo.GroupOf(token, false, false);
        Check(g != ProtectInfo.GroupUsual && g != ProtectInfo.GroupProjects && g == ProtectInfo.GroupOf(tokenDownloads, false, false),
            "GroupOf: a format match in a repository file is counted for review, like the same match in Downloads");

        // Replace prunes content findings whose node is no longer attached.
        var t = new Tree(@"C:\T");
        FileNode a = t.File(@"C:\T\A\a.txt", 100, false), b = t.File(@"C:\T\B\b.txt", 100, false);
        FileNode c = t.File(@"C:\T\B\c.txt", 100, false);
        DirNode folderB = t.Dir(@"C:\T\B");
        ScanResult r = t.Finish(ProtectContext.ForTree(@"C:\Users\pat"));
        r.Analyze();
        foreach (FileNode f in new[] { a, b, c })
        {
            r.ContentFindings.Add(new Finding("github-token", FindingTier.Confirmed, f.FullPath, 1, 1, Place.Other));
            r.ContentNodes.Add(f);
        }
        r.Replace(a, null);
        Check(r.ContentFindings.Count == 2 && r.ContentNodes.Count == 2 && !r.ContentNodes.Contains(a),
            "Replace(file, null) drops that file's content findings and keeps the others (" + r.ContentFindings.Count + ")");
        r.Replace(folderB, Clone(folderB, null));
        Check(r.ContentFindings.Count == 0 && r.ContentNodes.Count == 0,
            "Replace of a folder drops the content findings of its detached nodes (" + r.ContentFindings.Count + " left)");
        r.Analyze();
        Check(r.ContentFindings.Count == 0, "Analyze does not touch the content findings");
    }

    // ---------------------------------------------------------------------------------------------------
    // 8 The corpus gate, byte level and end to end, and 4.6.5 ValueNeverStored

    static List<string> MatchBytes(byte[] data, ContentKind kind)
    {
        int start = data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF ? 3 : 0;
        var triples = new int[3 * ProtectConstants.ContentFindingsPerFile];
        int hits = SecretScan.MatchBuffer(data, start, data.Length, kind, triples);
        var list = new List<string>();
        for (int i = 0; i < hits && i < ProtectConstants.ContentFindingsPerFile; i++)
        {
            PatternInfo row = ContentRow(triples[3 * i]);
            list.Add(row.Id + "\t" + row.Tier + "\t" + triples[3 * i + 1] + ":" + triples[3 * i + 2]);
        }
        return list;
    }

    // What the reader does before it matches (spec 3.3): null when it would read these bytes.
    static string ReaderSkip(byte[] d)
    {
        if (d.Length == 0) return "empty";
        if (d.Length > ProtectConstants.MaxContentBytes) return "too large";
        if (d.Length >= 2 && ((d[0] == 0xFF && d[1] == 0xFE) || (d[0] == 0xFE && d[1] == 0xFF))) return "UTF-16";
        int probe = Math.Min(d.Length, ProtectConstants.BinaryProbeBytes);
        for (int i = 0; i < probe; i++) if (d[i] == 0) return "binary";
        return null;
    }

    // The file rule of spec 2.2, by name only, for the byte-level run (the folder rules are left to the end to end run).
    static bool LocalKind(string name, out ContentKind kind)
    {
        kind = ContentKind.Dotenv;
        if (ProtectNames.IsDotenvName(name)) return true;
        kind = ContentKind.Text;
        foreach (string end in ProtectConstants.TextNeverEnds) if (name.EndsWith(end, StringComparison.OrdinalIgnoreCase)) return false;
        foreach (string n in ProtectConstants.TextNames) if (string.Equals(name, n, StringComparison.OrdinalIgnoreCase)) return true;
        string key = Categories.KeyFor(name);
        foreach (string e in ProtectConstants.TextExtensions) if (string.Equals(key, e, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    static string Rel(string root, string path)
    {
        string r = root.TrimEnd('\\') + "\\";
        return path.StartsWith(r, StringComparison.OrdinalIgnoreCase) ? path.Substring(r.Length).Replace('\\', '/') : path;
    }

    static void Inc(Dictionary<string, int> d, string k)
    {
        int n;
        d.TryGetValue(k, out n);
        d[k] = n + 1;
    }

    static int Get(Dictionary<string, int> d, string k)
    {
        int n;
        d.TryGetValue(k, out n);
        return n;
    }

    static string Pct(int a, int b)
    {
        return b == 0 ? "-" : string.Format("{0:0.0}%", 100.0 * a / b);
    }

    // Compares {file, pattern, tier, L:C} with cases.tsv, prints TP, FP, FN, precision and recall per pattern and per
    // tier, and applies the gates of spec 8.3.
    static void Gate(string what, HashSet<string> expected, List<string> got)
    {
        var found = new HashSet<string>(got);
        int duplicates = got.Count - found.Count;
        var tp = new Dictionary<string, int>();
        var fp = new Dictionary<string, int>();
        var fn = new Dictionary<string, int>();
        foreach (string g in found)
        {
            string[] c = g.Split('\t');
            if (expected.Contains(g)) { Inc(tp, c[1]); Inc(tp, c[2]); }
            else { Inc(fp, c[1]); Inc(fp, c[2]); Console.WriteLine("      " + what + ", not expected: " + g.Replace('\t', ' ')); }
        }
        foreach (string e in expected)
        {
            if (found.Contains(e)) continue;
            string[] c = e.Split('\t');
            Inc(fn, c[1]);
            Inc(fn, c[2]);
            Console.WriteLine("      " + what + ", missing: " + e.Replace('\t', ' '));
        }
        bool gates = true;
        Console.WriteLine("      " + what + ":");
        Console.WriteLine(string.Format("      {0,-27} {1,-10} {2,4} {3,4} {4,4} {5,10} {6,8}", "pattern", "tier", "TP", "FP", "FN", "precision", "recall"));
        for (int i = 0; i < ContentIds.Length; i++)
        {
            string id = ContentIds[i];
            int a = Get(tp, id), b = Get(fp, id), c = Get(fn, id);
            Console.WriteLine(string.Format("      {0,-27} {1,-10} {2,4} {3,4} {4,4} {5,10} {6,8}", id, ContentTiers[i], a, b, c, Pct(a, a + b), Pct(a, a + c)));
            double gate = ContentTiers[i] == FindingTier.Confirmed ? 0.95 : 0.80;
            if (a + b > 0 && (double)a / (a + b) < gate) gates = false;
        }
        foreach (FindingTier tier in new[] { FindingTier.Confirmed, FindingTier.Likely })
        {
            string k = tier.ToString();
            int a = Get(tp, k), b = Get(fp, k), c = Get(fn, k);
            Console.WriteLine(string.Format("      {0,-27} {1,-10} {2,4} {3,4} {4,4} {5,10} {6,8}", "(all)", k, a, b, c, Pct(a, a + b), Pct(a, a + c)));
            double gate = tier == FindingTier.Confirmed ? 0.95 : 0.80;
            if (a + b > 0 && (double)a / (a + b) < gate) gates = false;
        }
        Check(gates, what + ": precision is at least 95% for Confirmed and 80% for Likely, per pattern and per tier");
        Check(found.SetEquals(expected) && duplicates == 0, what + ": every finding is expected and every expected L:C is found exactly, " +
            "the target of 100% (" + found.Count + " found, " + expected.Count + " expected, " + duplicates + " duplicates)");
    }

    static void ContentCorpusGate(string repo)
    {
        string dir = Path.Combine(repo, @"tests\protect-corpus\by-content");
        ContentCorpus.CaseSet set = ContentCorpus.Load(Path.Combine(dir, "cases.tsv"));
        string root = TempRoot("dsa-content-");
        try
        {
            string home = Path.Combine(root, "home"), proj = Path.Combine(root, "proj");
            var values = new List<string>();
            ContentCorpus.WriteAll(set, Path.Combine(dir, "files"), home, proj, values);
            var expected = new HashSet<string>();
            foreach (ContentCorpus.Row k in set.Rows)
                if (k.Positive) expected.Add(k.File + "\t" + k.Expect + "\t" + k.Tier + "\t" + k.Lc);

            // The byte level: the matcher over each generated file the reader would read.
            var bytesGot = new List<string>();
            foreach (ContentCorpus.CaseFile f in set.Files)
            {
                byte[] data = File.ReadAllBytes(ContentCorpus.LocalPath(f.File, home, proj));
                ContentKind kind;
                if (!LocalKind(Path.GetFileName(f.File), out kind) || ReaderSkip(data) != null) continue;
                foreach (string m in MatchBytes(data, kind)) bytesGot.Add(f.File + "\t" + m);
            }
            Gate("corpus, byte level", expected, bytesGot);

            // End to end: scan, Analyze with the pretend home, Plan and the content scan.
            ScanResult r = ScanDisk(root, home);
            ContentPlan plan = SecretScan.Plan(r, new ProtectStore(), null);
            var p = new ContentProgress();
            int opened = 0;
            SecretScan.OnOpen = s => Interlocked.Increment(ref opened);
            ContentResult res = Read(plan, p, CancellationToken.None);
            SecretScan.OnOpen = null;
            var e2e = new List<string>();
            foreach (Finding f in res.Findings) e2e.Add(Rel(root, f.Path) + "\t" + f.PatternId + "\t" + f.Tier + "\t" + f.Line + ":" + f.Column);
            Gate("corpus, end to end", expected, e2e);

            bool nodes = !res.Cancelled && res.Nodes.Count == res.Findings.Count;
            for (int i = 0; nodes && i < res.Findings.Count; i++)
                nodes = res.Nodes[i] != null && ProtectStore.Normalize(res.Nodes[i].FullPath) == ProtectStore.Normalize(res.Findings[i].Path);
            Check(nodes, "the run's Nodes list runs parallel to its Findings");
            Check(p.FilesOpened == plan.Files.Length && opened == plan.Files.Length && p.DoneFiles == plan.Files.Length,
                "FilesOpenedEqualsAttempts: on the corpus, FilesOpened, the plan and the OnOpen count agree (" + p.FilesOpened + ", " +
                plan.Files.Length + ", " + opened + ")");
            Check(p.SkippedBinary == 1 && p.SkippedUtf16 == 1 && r.ContentTooLarge == 1 && p.CappedFiles == 1,
                "the reader skips bin.txt as binary and wide.txt as UTF-16, big.json is too large, and many.txt reaches the cap (" +
                p.SkippedBinary + ", " + p.SkippedUtf16 + ", " + r.ContentTooLarge + ", " + p.CappedFiles + ")");
            Check(p.FindingCount == res.Findings.Count && p.ProcessedBytes == plan.TotalBytes && p.TotalFiles == plan.Files.Length,
                "the progress counters add up (" + p.FindingCount + " findings, " + p.ProcessedBytes + " of " + plan.TotalBytes + " bytes)");
            Check(SlotsEmpty() && SecretScan.WorkerBuffersClear(), "after the corpus run every worker buffer slot is empty");

            ValueNeverStored(repo, root, home, values, r, res);
        }
        finally
        {
            SecretScan.OnOpen = null;
            DeleteTree(root);
        }
    }

    // Every generated value, and every 8-character piece of one.
    sealed class Pieces
    {
        public readonly HashSet<string> Windows = new HashSet<string>(StringComparer.Ordinal);
        public readonly List<string> Short = new List<string>();

        public Pieces(List<string> values)
        {
            foreach (string v in values)
            {
                if (v.Length < 8) { Short.Add(v); continue; }
                for (int i = 0; i + 8 <= v.Length; i++) Windows.Add(v.Substring(i, 8));
            }
        }

        public bool In(string text)
        {
            if (text == null) return false;
            foreach (string s in Short) if (s.Length > 0 && text.Contains(s)) return true;
            for (int i = 0; i + 8 <= text.Length; i++) if (Windows.Contains(text.Substring(i, 8))) return true;
            return false;
        }
    }

    static void NoValueIn(Pieces pieces, string where, IEnumerable<string> texts)
    {
        int hits = 0;
        long chars = 0;
        foreach (string t in texts)
        {
            if (t == null) continue;
            chars += t.Length;
            if (pieces.In(t)) hits++;
        }
        Check(hits == 0 && chars > 0, "ValueNeverStored: " + where + " hold no generated value and no 8-byte piece of one (" +
            chars + " characters searched, " + hits + " hits)");
    }

    static void ValueNeverStored(string repo, string root, string home, List<string> values, ScanResult r, ContentResult res)
    {
        var pieces = new Pieces(values);
        Check(values.Count > 100 && pieces.Windows.Count > 1000, "ValueNeverStored: " + values.Count + " generated values to look for");

        // protect.json, after one dismissal and one trusted folder.
        var store = new ProtectStore();
        store.ContentScan = true;
        if (res.Findings.Count > 0) store.Dismiss(res.Findings[0]);
        store.Trust(Path.Combine(root, @"proj\keys"));
        string file = Path.Combine(work, "content-store", "protect.json");
        Directory.CreateDirectory(Path.GetDirectoryName(file));
        store.Save(file);
        byte[] json = File.ReadAllBytes(file);
        var sb = new StringBuilder();
        foreach (byte b in json) sb.Append((char)b);
        NoValueIn(pieces, "protect.json", new[] { sb.ToString() });

        var fields = new List<string>();
        foreach (Finding f in res.Findings) { fields.Add(f.PatternId); fields.Add(f.Path); fields.Add(f.Tier.ToString()); fields.Add(f.Place.ToString()); }
        foreach (Finding f in r.Findings) { fields.Add(f.PatternId); fields.Add(f.Path); }
        NoValueIn(pieces, "every Finding string field", fields);

        App app = App.Load(repo);
        if (app != null)
        {
            var strings = new List<string>();
            App.Sta(() =>
            {
                object appStore = app.New("ProtectStore");
                object ar = app.ScanAndRead(root, home, appStore);
                IList content = (IList)App.Get(ar, "ContentFindings");
                if (content.Count > 0) App.I(appStore, "Dismiss", content[0]);
                App.I(appStore, "Trust", Path.Combine(root, @"proj\keys"));
                App.Strings(app.BuildCards(ar, appStore), strings, 0);
            });
            NoValueIn(pieces, "the Protect card and item view models (" + strings.Count + " strings)", strings);
        }

        string dsa = Path.Combine(BinDir(repo), "dsa.exe");
        if (!File.Exists(dsa))
        {
            Console.WriteLine("SKIP  the command-line checks (bin\\dsa.exe is not built)");
            return;
        }
        string o, e;
        int code = RunProcess(dsa, Q(root) + " --protect --content --findings --all --timing --protect-home " + Q(home), out o, out e);
        Check(code == 0 && o.Contains("GitHub token") && Regex.IsMatch(o, @"line \d+:\d+"),
            "dsa --protect --content --findings lists the corpus's content findings by line (exit " + code + ")");
        NoValueIn(pieces, "dsa --protect --content --findings --all output", new[] { o, e });
        code = RunProcess(dsa, Q(root) + " --protect --timing --protect-home " + Q(home), out o, out e);
        Check(code == 0 && Regex.IsMatch(e, @"(?m)^files_opened 0\r?$"), "without --content, dsa --protect --timing reports files_opened 0");
        code = RunProcess(dsa, Q(root) + " --content", out o, out e);
        Check(code != 0 && (o + e).Contains("--content needs --protect."), "dsa --content without --protect is refused (exit " + code + ")");
    }

    // The built programs: bin\, or the folder in DSA_TEST_BIN (a build under obj\ while the app is running).
    static string BinDir(string repo)
    {
        string over = Environment.GetEnvironmentVariable("DSA_TEST_BIN");
        return string.IsNullOrEmpty(over) ? Path.Combine(repo, "bin") : over;
    }

    static string Q(string s)
    {
        return "\"" + s + "\"";
    }

    static int RunProcess(string exe, string arguments, out string stdout, out string stderr)
    {
        var psi = new ProcessStartInfo(exe, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        using (Process p = Process.Start(psi))
        {
            var err = p.StandardError.ReadToEndAsync();
            stdout = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(300000))
            {
                p.Kill();
                stderr = "timed out";
                return -1;
            }
            stderr = err.Result;
            return p.ExitCode;
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // 4.6.2 SkippedNeverOpened

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.I1)]
    static extern bool CreateSymbolicLinkW(string link, string target, int flags);

    static void SkippedNeverOpened()
    {
        string root = TempRoot("dsa-plant-");
        try
        {
            var values = new List<string>();
            string home = Path.Combine(root, "home");
            string token = Tok(910, values);
            string[] skipped =
            {
                @"Program Files\x\a.txt", @"proj\node_modules\y\b.js", @"proj\tests\node_modules\c.js", @"home\.vscode\extensions\e\d.json",
                @"home\.antigravity\extensions\e\package.json", @"home\AppData\Local\Packages\p\e.json", @"$x\f.txt", @"proj\.git\g.txt",
                @"proj\site-packages\h.py", @"rs\target\debug\i.txt"
            };
            foreach (string s in skipped) WriteText(Path.Combine(root, s), "token " + token + "\n");
            WriteText(Path.Combine(root, @"rs\Cargo.toml"), "[package]\nname = \"rs\"\n");
            string keys = Path.Combine(root, @"proj\src\keys.json"), notes = Path.Combine(root, @"build\notes.txt");
            WriteText(keys, "{\"t\": \"" + token + "\"}\n");
            WriteText(notes, "token " + token + "\n");

            string link = Path.Combine(root, @"proj\src\link.txt");
            bool linked = CreateSymbolicLinkW(link, Path.Combine(root, @"Program Files\x\a.txt"), 2);
            int why = Marshal.GetLastWin32Error();
            if (!linked && why == 87) { linked = CreateSymbolicLinkW(link, Path.Combine(root, @"Program Files\x\a.txt"), 0); why = Marshal.GetLastWin32Error(); }
            if (!linked) Console.WriteLine("SKIP  symlink: CreateSymbolicLink failed with error " + why + " (it needs Developer Mode)");

            var never = new HashSet<string>(StringComparer.Ordinal);
            foreach (string s in skipped) never.Add(ProtectStore.Normalize(Path.Combine(root, s)));
            if (linked) never.Add(ProtectStore.Normalize(link));

            ScanResult r = ScanDisk(root, home);
            ContentPlan plan = SecretScan.Plan(r, new ProtectStore(), null);
            var seen = new List<string>();
            SecretScan.OnOpen = s => { lock (seen) seen.Add(ProtectStore.Normalize(Plain(s))); };
            ContentResult res = Read(plan, new ContentProgress(), CancellationToken.None);
            SecretScan.OnOpen = null;

            int opened = 0, candidates = 0, found = 0;
            foreach (string s in seen) if (never.Contains(s)) { opened++; Console.WriteLine("      opened: " + s); }
            foreach (ContentCandidate c in r.ContentCandidates)
                if (never.Contains(ProtectStore.Normalize(c.Node.FullPath))) { candidates++; Console.WriteLine("      a candidate: " + c.Node.FullPath); }
            foreach (Finding f in res.Findings) if (never.Contains(ProtectStore.Normalize(f.Path))) { found++; Console.WriteLine("      found: " + f.Path); }
            Check(opened == 0, "SkippedNeverOpened: no file in a skipped place is passed to the reader (Program Files, node_modules, " +
                "a fixture folder, editor extensions, AppData\\Local\\Packages, $ folders, .git, site-packages, Rust target)");
            Check(candidates == 0, "none of them is a content candidate");
            Check(found == 0, "none of them appears in a finding");

            var got = new HashSet<string>();
            foreach (Finding f in res.Findings) got.Add(ProtectStore.Normalize(f.Path) + " " + f.PatternId + " " + f.Tier + " " + f.Line + ":" + f.Column);
            Check(seen.Contains(ProtectStore.Normalize(keys)) && seen.Contains(ProtectStore.Normalize(notes)) &&
                  got.Contains(ProtectStore.Normalize(keys) + " github-token Confirmed 1:8") &&
                  got.Contains(ProtectStore.Normalize(notes) + " github-token Confirmed 1:7") && res.Findings.Count == 2,
                "the controls proj\\src\\keys.json and build\\notes.txt (build outside a repository) are opened and give github-token Confirmed at 1:8 and 1:7 (" +
                res.Findings.Count + " findings)");
            if (linked)
            {
                var ln = r.FindNode(link) as FileNode;
                Check(ln != null && (ln.Flags & FileFlags.Link) != 0, "the Scanner marks a file symlink as Link, so the reader never sees it");
            }

            ScanResult nm = ScanDisk(Path.Combine(root, @"proj\node_modules"), home);
            ContentPlan nmPlan = SecretScan.Plan(nm, new ProtectStore(), null);
            int nmOpens = 0;
            SecretScan.OnOpen = s => Interlocked.Increment(ref nmOpens);
            var nmP = new ContentProgress();
            Read(nmPlan, nmP, CancellationToken.None);
            SecretScan.OnOpen = null;
            Check(nm.ContentCandidates.Length == 0 && nmPlan.Files.Length == 0 && nmOpens == 0 && nmP.FilesOpened == 0,
                "a run rooted at proj\\node_modules has 0 candidates and 0 opens");
        }
        finally
        {
            SecretScan.OnOpen = null;
            DeleteTree(root);
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // 10.1.7 Reader edge cases, 4.6.3 BufferHoldsNothing and 4.6.4 FilesOpenedEqualsAttempts

    static void ReaderEdgeCases()
    {
        string root = TempRoot("dsa-content-");
        FileStream held = null;
        try
        {
            var values = new List<string>();
            string d = Path.Combine(root, "r");
            Func<string, string> at = n => Path.Combine(d, n);
            WriteText(at("hit.txt"), "k=" + Tok(901, values) + "\n");
            WriteBytes(at("binary.txt"), Ascii("abc"), new byte[] { 0 }, Ascii("def " + Tok(902, values) + "\n"));
            WriteBytes(at("wide.txt"), new byte[] { 0xFF, 0xFE }, Encoding.Unicode.GetBytes(Tok(903, values) + "\n"));
            WriteText(at("grow.txt"), "a\n");
            WriteText(at("shrink.txt"), "hello " + Tok(904, values) + "\n");
            WriteText(at("large.txt"), Tok(905, values) + "\n");
            WriteText(at("locked.txt"), Tok(906, values) + "\n");
            WriteText(at("dir.txt"), Tok(907, values) + "\n");
            WriteText(at("gone.txt"), Tok(908, values) + "\n");
            WriteBytes(at("empty.txt"), new byte[0]);

            ScanResult r = ScanDisk(root, Path.Combine(root, "home"));
            Check(!IsCandidate(r, at("empty.txt")), "an empty file is not a content candidate");
            ContentPlan plan = SecretScan.Plan(r, new ProtectStore(), null);
            Check(plan.Files.Length == 9, "the reader test plans 9 files (" + plan.Files.Length + ")");

            // After Plan, the files change the way other programs might change them.
            File.AppendAllText(at("grow.txt"), "x=" + Tok(909, values) + "\n");
            using (new FileStream(at("shrink.txt"), FileMode.Truncate, FileAccess.Write)) { }
            AppendFiller(at("large.txt"), ProtectConstants.MaxContentBytes + 10);
            File.Delete(at("dir.txt"));
            Directory.CreateDirectory(at("dir.txt"));
            File.Delete(at("gone.txt"));
            held = new FileStream(at("locked.txt"), FileMode.Open, FileAccess.Read, FileShare.None);

            var p = new ContentProgress();
            int opens = 0, after = 0, dirty = 0;
            SecretScan.OnOpen = s => Interlocked.Increment(ref opens);
            SecretScan.AfterFile = w =>
            {
                Interlocked.Increment(ref after);
                byte[][] slots = SecretScan.WorkerBuffers;
                if (slots == null || !AllZero(slots[w])) Interlocked.Increment(ref dirty);
            };
            ContentResult res = Read(plan, p, CancellationToken.None);
            SecretScan.OnOpen = null;
            SecretScan.AfterFile = null;
            held.Dispose();
            held = null;

            var got = new HashSet<string>();
            foreach (Finding f in res.Findings) got.Add(Path.GetFileName(f.Path) + " " + f.PatternId + " " + f.Line + ":" + f.Column);
            Check(got.Count == 2 && res.Findings.Count == 2 && got.Contains("hit.txt github-token 1:3") && got.Contains("grow.txt github-token 2:3"),
                "the reader finds the hit, and reads a file that grew after Plan up to its length at the open (" + string.Join("; ", got) + ")");
            Check(p.SkippedBinary == 1 && p.SkippedUtf16 == 1 && p.SkippedEmpty == 1 && p.SkippedTooLarge == 1,
                "binary, UTF-16, shrunk to 0 and grown over 1 MiB are each skipped and counted (" + p.SkippedBinary + ", " + p.SkippedUtf16 + ", " +
                p.SkippedEmpty + ", " + p.SkippedTooLarge + ")");
            Check(p.SkippedUnreadable + p.SkippedNotDisk == 3 && p.SkippedUnreadable >= 2,
                "a file locked with share 0, a deleted file and a folder in a file's place are skipped as unreadable or not a disk file (" +
                p.SkippedUnreadable + " unreadable, " + p.SkippedNotDisk + " not a disk file)");
            Check(p.FilesOpened == plan.Files.Length && opens == plan.Files.Length && p.DoneFiles == plan.Files.Length,
                "FilesOpenedEqualsAttempts: FilesOpened, the plan and the OnOpen count agree, failed opens included (" + p.FilesOpened + ", " +
                plan.Files.Length + ", " + opens + ")");
            Check(p.BytesRead < ProtectConstants.MaxContentBytes, "a file over 1 MiB at the open is not read (" + p.BytesRead + " bytes read in all)");
            Check(after == plan.Files.Length && dirty == 0,
                "BufferHoldsNothing: after every file (hit, binary, UTF-16, empty, too large, unreadable) the worker's buffer is all zero (" +
                after + " files, " + dirty + " not clear)");
            Check(SlotsEmpty() && SecretScan.WorkerBuffersClear(), "after the run every worker buffer slot is empty");
        }
        finally
        {
            if (held != null) held.Dispose();
            SecretScan.OnOpen = null;
            SecretScan.AfterFile = null;
            DeleteTree(root);
        }
    }

    static void CancelMidRun()
    {
        string root = TempRoot("dsa-content-");
        try
        {
            var values = new List<string>();
            for (int i = 0; i < 40; i++) WriteText(Path.Combine(root, @"c\c" + i + ".txt"), "k=" + Tok(920 + i, values) + "\n");
            ScanResult r = ScanDisk(root, Path.Combine(root, "home"));
            ContentPlan plan = SecretScan.Plan(r, new ProtectStore(), null);
            var cts = new CancellationTokenSource();
            var p = new ContentProgress();
            int opens = 0, after = 0, dirty = 0;
            SecretScan.OnOpen = s => { if (Interlocked.Increment(ref opens) == 3) cts.Cancel(); };
            SecretScan.AfterFile = w =>
            {
                Interlocked.Increment(ref after);
                byte[][] slots = SecretScan.WorkerBuffers;
                if (slots == null || !AllZero(slots[w])) Interlocked.Increment(ref dirty);
            };
            ContentResult res = Read(plan, p, cts.Token);
            SecretScan.OnOpen = null;
            SecretScan.AfterFile = null;
            Check(plan.Files.Length == 40 && res.Cancelled && p.FilesOpened >= 3 && p.FilesOpened < 40,
                "a cancel during the run stops it early (" + p.FilesOpened + " of " + plan.Files.Length + " files opened)");
            Check(res.Findings.Count == p.FilesOpened, "the files in progress at the cancel finish, and their findings are kept (" + res.Findings.Count + ")");
            Check(dirty == 0 && after == p.FilesOpened, "BufferHoldsNothing: after a cancel every finished file left its buffer all zero (" + after + " files)");
            Check(SlotsEmpty() && SecretScan.WorkerBuffersClear(), "after a cancelled run every worker buffer slot is empty");
        }
        finally
        {
            SecretScan.OnOpen = null;
            SecretScan.AfterFile = null;
            DeleteTree(root);
        }
    }

    // ---------------------------------------------------------------------------------------------------
    // 10.1.9 Merge, as the page shows it (E2's BuildCards, through the built app)

    static void MergeCards(string repo)
    {
        App app = App.Load(repo);
        if (app == null) return;
        string root = TempRoot("dsa-content-");
        try
        {
            var values = new List<string>();
            string home = Path.Combine(root, "home"), proj = Path.Combine(root, "proj");
            WriteText(Path.Combine(home, @".ssh\id_rsa"), ContentCorpus.Expand("<<pem:rsa:930>>", values) + "\n");
            Directory.CreateDirectory(Path.Combine(proj, ".git"));
            WriteText(Path.Combine(proj, ".env"), "API_TOKEN=" + ContentCorpus.Expand("<<env:mixed:24:931>>", values) + "\nDEBUG=1\n" +
                "DB_PASSWORD=" + ContentCorpus.Expand("<<env:mixed:20:936>>", values) + "\n");
            string secrets = Path.Combine(proj, ".secrets.env");
            WriteText(secrets, "GITHUB_TOKEN=" + Tok(932, values) + "\nDEPLOY_TOKEN=" + Tok(933, values) + "\n");
            string mixed = Path.Combine(proj, @"src\mixed.json");
            WriteText(mixed, "{\"t\": \"" + Tok(934, values) + "\",\n\"id\": \"" + ContentCorpus.Expand("<<aws:akia:935>>", values) + "\"}\n");

            App.Sta(() =>
            {
                object store = app.New("ProtectStore");
                object r = app.ScanAndRead(root, home, store);
                IList cards = app.BuildCards(r, store);

                Check(CardText(cards, "usual").Contains("also holds: Private key, line 1"),
                    "merge: a usual-place key file with a content hit stays in the usual places with \"also holds: Private key, line 1\"");
                string projects = CardText(cards, "projects");
                Check(projects.Contains("secret settings on lines 1, 3") && !HasFinding(cards, "secret", Path.Combine(proj, ".env"), null),
                    "merge: a repository .env with only env-secret stays in \"In your projects\" with \"secret settings on lines 1, 3\"");
                if (!projects.Contains("secret settings on lines 1, 3")) Console.WriteLine("      projects group text: " + projects.Replace("\n", " | "));
                Check(HasFinding(cards, "secret", secrets, "github-token") && !CardText(cards, "projects").Contains(".secrets.env"),
                    "merge: a repository .secrets.env with a GitHub token moves to a counted card and leaves the projects group");
                object mixedCard = CardWith(cards, mixed);
                Check(mixedCard != null && Convert.ToInt32(App.Get(mixedCard, "SortTier")) == (int)FindingTier.Confirmed,
                    "merge: the card tier is the best visible tier (Confirmed)");

                // Secrets in text: distinct (path, pattern) pairs among content findings on counted cards.
                var pairs = new HashSet<string>();
                var paths = new HashSet<string>();
                foreach (object c in cards)
                {
                    if ((string)App.Get(c, "Group") != "secret") continue;
                    foreach (object f in (IList)App.Get(c, "Findings"))
                    {
                        if ((int)App.Get(f, "Line") == 0) continue;
                        string p = ProtectStore.Normalize((string)App.Get(f, "Path"));
                        pairs.Add(p + "\n" + (string)App.Get(f, "PatternId"));
                        paths.Add(p);
                    }
                }
                Check(pairs.Count == 3 && paths.Count == 2, "merge: Secrets in text counts 3 (path, pattern) pairs in 2 files (" + pairs.Count + ", " + paths.Count + ")");
                Check(GroupsAgree(app, cards), "merge: every card's group is the one ProtectInfo.GroupOf gives, which the command line uses too");

                // Hide github-token in both files: every github-token row there goes, the dotenv row stays.
                foreach (object c in cards)
                    foreach (object f in (IList)App.Get(c, "Findings"))
                    {
                        string p = (string)App.Get(f, "Path");
                        if ((string)App.Get(f, "PatternId") == "github-token" && (Same(p, secrets) || Same(p, mixed))) App.I(store, "Dismiss", f);
                    }
                cards = app.BuildCards(r, store);
                Check(!HasFinding(cards, null, secrets, "github-token") && !HasFinding(cards, null, mixed, "github-token"),
                    "merge: dismissing github-token hides every github-token row in that file, whatever the line");
                Check(HasFinding(cards, null, secrets, "dotenv"), "merge: the by-name dotenv row of the same file stays visible");
                mixedCard = CardWith(cards, mixed);
                Check(mixedCard != null && Convert.ToInt32(App.Get(mixedCard, "SortTier")) == (int)FindingTier.Likely,
                    "merge: with the Confirmed finding hidden, the card tier is the best visible one (Likely)");
            });
        }
        finally { DeleteTree(root); }
    }

    static bool Same(string a, string b)
    {
        return ProtectStore.Normalize(a) == ProtectStore.Normalize(b);
    }

    static string CardText(IList cards, string group)
    {
        var all = new List<string>();
        foreach (object c in cards)
            if ((string)App.Get(c, "Group") == group) App.Strings(c, all, 0);
        return string.Join("\n", all);
    }

    static bool HasFinding(IList cards, string group, string path, string patternId)
    {
        foreach (object c in cards)
        {
            if (group != null && (string)App.Get(c, "Group") != group) continue;
            IList findings = (IList)App.Get(c, "Findings");
            if (findings == null) continue;
            foreach (object f in findings)
                if (Same((string)App.Get(f, "Path"), path) && (patternId == null || (string)App.Get(f, "PatternId") == patternId)) return true;
        }
        return false;
    }

    static object CardWith(IList cards, string path)
    {
        foreach (object c in cards)
        {
            IList findings = (IList)App.Get(c, "Findings");
            if (findings == null || findings.Count == 0) continue;
            bool all = true;
            foreach (object f in findings) all &= Same((string)App.Get(f, "Path"), path);
            if (all) return c;
        }
        return null;
    }

    // Each card with a content finding is in the group GroupOf gives for its lead finding (spec 5.4).
    static bool GroupsAgree(App app, IList cards)
    {
        int usual = (int)app.Constant("ProtectInfo", "GroupUsual"), projects = (int)app.Constant("ProtectInfo", "GroupProjects");
        bool ok = true;
        foreach (object c in cards)
        {
            string group = (string)App.Get(c, "Group");
            IList findings = (IList)App.Get(c, "Findings");
            if (findings == null || findings.Count == 0) continue;
            object lead = null;
            bool content = false, hasUsual = false, allEnv = true, dotenv = false;
            Place place = Place.Other;
            foreach (object f in findings)
            {
                bool byName = (int)App.Get(f, "Line") == 0;
                if (byName && lead == null) lead = f;
                if (!byName) { content = true; if ((string)App.Get(f, "PatternId") != "env-secret") allEnv = false; }
                if (byName && (string)App.Get(f, "PatternId") == "dotenv") dotenv = true;
                if (Convert.ToInt32(App.Get(f, "Place")) == (int)Place.UsualPlace) hasUsual = true;
            }
            if (!content) continue;
            if (lead == null) lead = findings[0];
            place = (Place)Convert.ToInt32(App.Get(lead, "Place"));
            bool onlyEnv = place == Place.Repository && allEnv && dotenv;
            int g = (int)app.S("ProtectInfo", "GroupOf", lead, hasUsual, onlyEnv);
            string want = g == usual ? "usual" : g == projects ? "projects" : "secret";
            if (group != want) { ok = false; Console.WriteLine("      card " + App.Get(c, "Title") + " is in " + group + ", GroupOf says " + want); }
        }
        return ok;
    }

    // The built app, bin\DiskSpaceAnalyzer.exe, loaded from its bytes so the file is not locked. The UI types are
    // not compiled into tests.exe, so the view-model and ContentGate checks reach them by reflection.
    sealed class App
    {
        readonly Assembly asm;
        static App loaded;
        static bool tried;

        App(Assembly a) { asm = a; }

        public static App Load(string repo)
        {
            if (tried) return loaded;
            tried = true;
            string exe = Path.Combine(BinDir(repo), "DiskSpaceAnalyzer.exe");
            if (!File.Exists(exe))
            {
                Console.WriteLine("SKIP  the view-model and page checks (bin\\DiskSpaceAnalyzer.exe is not built)");
                return null;
            }
            loaded = new App(Assembly.Load(File.ReadAllBytes(exe)));
            return loaded;
        }

        public Type T(string name)
        {
            Type t = asm.GetType("DiskSpace." + name);
            if (t == null) throw new MissingMemberException("the built app has no type " + name + "; rebuild it with build.ps1");
            return t;
        }

        public object New(string type)
        {
            return Activator.CreateInstance(T(type), true);
        }

        public object Constant(string type, string name)
        {
            FieldInfo f = T(type).GetField(name, BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
            if (f == null) throw new MissingFieldException(type + "." + name + " is missing from the built app; rebuild it with build.ps1");
            return f.GetValue(null);
        }

        static MethodInfo Find(Type t, string name, object[] args, bool isStatic)
        {
            BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic | (isStatic ? BindingFlags.Static : BindingFlags.Instance);
            for (Type x = t; x != null; x = x.BaseType)
                foreach (MethodInfo m in x.GetMethods(flags | BindingFlags.DeclaredOnly))
                {
                    if (m.Name != name) continue;
                    ParameterInfo[] ps = m.GetParameters();
                    if (ps.Length != args.Length) continue;
                    bool ok = true;
                    for (int i = 0; i < ps.Length && ok; i++)
                        ok = args[i] == null ? !ps[i].ParameterType.IsValueType : ps[i].ParameterType.IsInstanceOfType(args[i]);
                    if (ok) return m;
                }
            throw new MissingMethodException(t.Name + "." + name + " with " + args.Length + " arguments is missing from the built app; rebuild it with build.ps1");
        }

        public object S(string type, string method, params object[] args)
        {
            return Find(T(type), method, args, true).Invoke(null, args);
        }

        public static object I(object target, string method, params object[] args)
        {
            return Find(target.GetType(), method, args, false).Invoke(target, args);
        }

        public static object Get(object target, string member)
        {
            const BindingFlags all = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
            for (Type t = target.GetType(); t != null; t = t.BaseType)
            {
                FieldInfo f = t.GetField(member, all | BindingFlags.DeclaredOnly);
                if (f != null) return f.GetValue(target);
                PropertyInfo p = t.GetProperty(member, all | BindingFlags.DeclaredOnly);
                if (p != null) return p.GetValue(target, null);
            }
            throw new MissingMemberException(target.GetType().Name + "." + member);
        }

        public static void Set(object target, string member, object value)
        {
            const BindingFlags all = BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic;
            for (Type t = target.GetType(); t != null; t = t.BaseType)
            {
                FieldInfo f = t.GetField(member, all | BindingFlags.DeclaredOnly);
                if (f != null) { f.SetValue(target, value); return; }
                PropertyInfo p = t.GetProperty(member, all | BindingFlags.DeclaredOnly);
                if (p != null) { p.SetValue(target, value, null); return; }
            }
            throw new MissingMemberException(target.GetType().Name + "." + member);
        }

        // Scan, Analyze with the pretend home, Plan and the content scan, with the findings merged into the result
        // the way the page merges them.
        public object ScanAndRead(string root, string home, object store)
        {
            object r = I(New("Scanner"), "Scan", root, CancellationToken.None);
            Set(r, "Protect", S("ProtectContext", "ForTree", home));
            I(r, "Analyze");
            object plan = S("SecretScan", "Plan", r, store, null);
            object consent = S("ContentConsent", "FromCommandLine", true);
            object res = S("SecretScan", "Run", consent, plan, New("ContentProgress"), CancellationToken.None);
            var findings = (IList)Get(r, "ContentFindings");
            var nodes = (IList)Get(r, "ContentNodes");
            foreach (object f in (IList)Get(res, "Findings")) findings.Add(f);
            foreach (object n in (IList)Get(res, "Nodes")) nodes.Add(n);
            return r;
        }

        public IList BuildCards(object r, object store)
        {
            foreach (Type t in asm.GetTypes())
                foreach (MethodInfo m in t.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                    if (m.Name == "BuildCards" && m.GetParameters().Length == 3) return (IList)m.Invoke(null, new object[] { r, store, true });
            throw new MissingMethodException("BuildCards(ScanResult, ProtectStore, bool) is missing from the built app; rebuild it with build.ps1");
        }

        // Every string a view model holds: its string properties, strings in its lists, and the same for the view
        // models and findings it holds.
        public static void Strings(object o, List<string> into, int depth)
        {
            if (o == null || depth > 6) return;
            var s = o as string;
            if (s != null) { into.Add(s); return; }
            var list = o as IEnumerable;
            if (list != null)
            {
                foreach (object x in list) Strings(x, into, depth + 1);
                return;
            }
            Type t = o.GetType();
            if (t.Namespace != "DiskSpace" || !(t.Name.EndsWith("Vm", StringComparison.Ordinal) || t.Name == "Finding")) return;
            foreach (PropertyInfo p in t.GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
            {
                if (p.GetIndexParameters().Length > 0 || !p.CanRead) continue;
                Strings(p.GetValue(o, null), into, depth + 1);
            }
            foreach (FieldInfo f in t.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
                Strings(f.GetValue(o), into, depth + 1);
        }

        // Runs a step on an STA thread, as WPF objects expect, and rethrows what it threw.
        public static void Sta(Action a)
        {
            Exception error = null;
            var th = new Thread(() =>
            {
                try { a(); }
                catch (Exception ex) { error = ex; }
            });
            th.SetApartmentState(ApartmentState.STA);
            th.Start();
            th.Join();
            while (error is TargetInvocationException && error.InnerException != null) error = error.InnerException;
            if (error != null) throw new InvalidOperationException(error.GetType().Name + ": " + error.Message, error);
        }
    }
}

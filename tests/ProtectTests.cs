using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using DiskSpace;

// Stage 0 tests for the Protect page: the Finding type, the store, the explanation text and the trust
// checker. Run with tests\run-tests.ps1, which compiles this with the app's source and tools\CheckTrust.cs.
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
        Directory.CreateDirectory(work);

        FindingHasNoRoomForAValue();
        StoreKeepsHashesOnly();
        TrustedFoldersCoverTheirContents();
        ExplanationComesFromTheConstants();
        CheckerCatchesNetworkCode(repo);
        CorpusFilesParse(repo);

        Console.WriteLine(fails == 0 ? "All checks passed." : fails + " check(s) failed.");
        return fails;
    }

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
}

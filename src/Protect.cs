using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// Protect: the model, settings and explanation text for the Protect page.
//
// This file is under the trust checks in tools\check-trust.ps1. It may not write, delete or move files,
// except where a line carries a "// trust:" marker, and the whole app may not reference any System.Net type.
// The PRD (Protect page PRD) states the principles these rules enforce.

namespace DiskSpace
{
    enum FindingTier { Confirmed, Likely, WorthALook }

    // Where a file sits changes how a finding is read: a dotfile in the home folder is normal, the same file
    // in Downloads is not.
    enum Place { UsualPlace, HomeFolder, Downloads, Desktop, Temp, Synced, ExternalDrive, Repository, Other }

    // One finding. By design it has no field for the matched text: a finding is a place, never a value.
    // ProtectTests checks the field list, so adding a field here is a deliberate act.
    sealed class Finding
    {
        public readonly string PatternId;
        public readonly FindingTier Tier;
        public readonly string Path;
        public readonly int Line;    // 1-based line of a content match; 0 for a finding by name
        public readonly int Column;  // 1-based column of a content match; 0 for a finding by name
        public readonly Place Place;

        public Finding(string patternId, FindingTier tier, string path, int line, int column, Place place)
        {
            PatternId = patternId;
            Tier = tier;
            Path = path;
            Line = line;
            Column = column;
            Place = place;
        }

        public string Kind
        {
            get
            {
                PatternInfo p = ProtectConstants.Pattern(PatternId);
                return p != null ? p.Kind : PatternId;
            }
        }
    }

    // What a pattern looks for, in words. The matcher itself arrives in a later stage; the table exists now so
    // the explanation screen and the tests are built from it from the start.
    sealed class PatternInfo
    {
        public readonly string Id, Kind, ReadsContent;  // ReadsContent: "name" or "content"
        public readonly FindingTier Tier;

        public PatternInfo(string id, string kind, string readsContent, FindingTier tier)
        {
            Id = id;
            Kind = kind;
            ReadsContent = readsContent;
            Tier = tier;
        }
    }

    // The numbers and lists the scanner uses. The explanation screen is generated from these, so what the
    // app says it reads and what it reads cannot drift apart.
    static class ProtectConstants
    {
        public const long MaxContentBytes = 1L << 20;
        public const int BinaryProbeBytes = 8 << 10;
        public const int ContentWorkers = 4;

        // Folders the content scan never opens: system files, and package caches full of vendors' sample keys.
        public static readonly string[] SkipFolders =
        {
            "Windows", "Program Files", "Program Files (x86)", "ProgramData", "WinSxS", "$Recycle.Bin",
            "node_modules", ".nuget", ".pnpm-store", "pnpm", "pip", "Yarn", ".gradle", ".m2", ".cargo", "go\\pkg",
            "ms-playwright", "electron", "node-gyp", ".cache"
        };

        // Stage 0 ships no matchers. Each later stage adds rows here, with a test case per row in the corpus.
        public static readonly PatternInfo[] Patterns = new PatternInfo[0];

        public static PatternInfo Pattern(string id)
        {
            foreach (PatternInfo p in Patterns)
                if (p.Id == id) return p;
            return null;
        }
    }

    // What the user chose: whether the content scan is on, which findings are dismissed and which folders are
    // trusted. Kept in protect.json as hashes, so the file holds no paths in clear and no values at all.
    sealed class ProtectStore
    {
        public bool ContentScan;
        readonly HashSet<string> dismissed = new HashSet<string>(StringComparer.Ordinal);
        readonly HashSet<string> trusted = new HashSet<string>(StringComparer.Ordinal);

        public static string DefaultPath
        {
            get
            {
                return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "DiskSpaceAnalyzer", "protect.json");
            }
        }

        public int DismissedCount { get { return dismissed.Count; } }
        public int TrustedCount { get { return trusted.Count; } }

        // A path as the store compares it: full, backslashes, no trailing separator, case folded.
        public static string Normalize(string path)
        {
            string full = System.IO.Path.GetFullPath(path.Trim()).Replace('/', '\\');
            if (full.Length > 3) full = full.TrimEnd('\\');
            return full.ToUpperInvariant();
        }

        public static string Hash(string kind, string value)
        {
            using (var sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes(kind + "\n" + value));
                var hex = new StringBuilder(digest.Length * 2);
                foreach (byte b in digest) hex.Append(b.ToString("x2"));
                return hex.ToString();
            }
        }

        static string DismissKey(string patternId, string path)
        {
            return Hash("dismiss", patternId + "\n" + Normalize(path));
        }

        static string TrustKey(string folder)
        {
            return Hash("trust", Normalize(folder));
        }

        public bool IsDismissed(Finding f)
        {
            return dismissed.Contains(DismissKey(f.PatternId, f.Path));
        }

        public void Dismiss(Finding f)
        {
            dismissed.Add(DismissKey(f.PatternId, f.Path));
        }

        public void Undismiss(Finding f)
        {
            dismissed.Remove(DismissKey(f.PatternId, f.Path));
        }

        public bool IsTrusted(string folder)
        {
            return trusted.Count > 0 && trusted.Contains(TrustKey(folder));
        }

        // True if the path is in a trusted folder or any folder above it.
        public bool IsUnderTrusted(string path)
        {
            if (trusted.Count == 0) return false;
            string p = Normalize(path);
            while (true)
            {
                if (trusted.Contains(Hash("trust", p))) return true;
                int cut = p.LastIndexOf('\\');
                if (cut <= 2) return false;
                p = p.Substring(0, cut);
            }
        }

        public void Trust(string folder)
        {
            trusted.Add(TrustKey(folder));
        }

        public void Untrust(string folder)
        {
            trusted.Remove(TrustKey(folder));
        }

        // The file is three fields of a fixed shape, so a few lines read and write it without a JSON library.
        public static ProtectStore Load(string file)
        {
            var store = new ProtectStore();
            if (!File.Exists(file)) return store;
            string text;
            try { text = File.ReadAllText(file, Encoding.UTF8); }
            catch (IOException) { return store; }
            catch (UnauthorizedAccessException) { return store; }
            store.ContentScan = text.Contains("\"contentScan\": true");
            foreach (string h in HexList(text, "dismissed")) store.dismissed.Add(h);
            foreach (string h in HexList(text, "trusted")) store.trusted.Add(h);
            return store;
        }

        public void Save(string file)
        {
            var sb = new StringBuilder();
            sb.Append("{\n  \"contentScan\": ").Append(ContentScan ? "true" : "false").Append(",\n");
            sb.Append("  \"dismissed\": ").Append(HexArray(dismissed)).Append(",\n");
            sb.Append("  \"trusted\": ").Append(HexArray(trusted)).Append("\n}\n");
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(file));  // trust: the store's own folder
            File.WriteAllText(file, sb.ToString(), new UTF8Encoding(false));    // trust: the only write in Protect
        }

        static string HexArray(HashSet<string> values)
        {
            var sorted = new List<string>(values);
            sorted.Sort(StringComparer.Ordinal);
            var sb = new StringBuilder("[");
            for (int i = 0; i < sorted.Count; i++)
            {
                if (i > 0) sb.Append(", ");
                sb.Append('"').Append(sorted[i]).Append('"');
            }
            return sb.Append(']').ToString();
        }

        // The quoted 64-digit hex strings inside the named array; anything else in the file is ignored.
        static IEnumerable<string> HexList(string text, string field)
        {
            int at = text.IndexOf("\"" + field + "\"", StringComparison.Ordinal);
            if (at < 0) yield break;
            int open = text.IndexOf('[', at), close = text.IndexOf(']', at);
            if (open < 0 || close < open) yield break;
            foreach (string part in text.Substring(open + 1, close - open - 1).Split(','))
            {
                string h = part.Trim().Trim('"');
                if (h.Length == 64 && IsHex(h)) yield return h;
            }
        }

        static bool IsHex(string s)
        {
            foreach (char c in s)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            return true;
        }
    }

    sealed class InfoSection
    {
        public readonly string Title;
        public readonly string[] Lines;

        public InfoSection(string title, params string[] lines)
        {
            Title = title;
            Lines = lines;
        }
    }

    // "What Protect reads": the trust principles as facts about this build, generated from the constants above.
    static class ProtectInfo
    {
        public static List<InfoSection> Describe()
        {
            var sections = new List<InfoSection>();
            sections.Add(new InfoSection("It runs only on this PC",
                "The program contains no network code. It is not switched off; it is absent.",
                "The build fails if the compiled program names any System.Net type. You can repeat the check yourself: " +
                "run tools\\check-trust.ps1 on DiskSpaceAnalyzer.exe.",
                "To see it from the outside, open Resource Monitor's Network tab while a scan runs: the app never appears."));

            sections.Add(new InfoSection("What every scan reads",
                "File names, folder names, sizes, dates and attributes. This is what the app reads to measure space, and " +
                "Protect uses the same scan.",
                "No file is opened for its contents in a normal scan."));

            int contentPatterns = 0, namePatterns = 0;
            foreach (PatternInfo p in ProtectConstants.Patterns)
            {
                if (p.ReadsContent == "content") contentPatterns++;
                else namePatterns++;
            }
            if (namePatterns > 0)
                sections.Add(new InfoSection("What is found by name alone",
                    namePatterns + " kinds of credential file, such as SSH keys, certificates and tool configs, matched by their " +
                    "names and where they sit. Nothing is opened."));

            if (contentPatterns > 0)
            {
                sections.Add(new InfoSection("What the content scan reads, only when you turn it on",
                    "Text files up to " + Fmt.Size(ProtectConstants.MaxContentBytes) + ". A file whose first " +
                    Fmt.Size(ProtectConstants.BinaryProbeBytes) + " contain a null byte is treated as binary and skipped.",
                    "It never opens anything under these folders: " + string.Join(", ", ProtectConstants.SkipFolders) + ".",
                    "It looks for " + contentPatterns + " kinds of secret with a known format. It does not score text for randomness.",
                    "Files are opened read-only and shared, so nothing you are working on is blocked.",
                    "Each file is read into one buffer that is cleared before the next file. When the scan ends, no content remains in memory."));
            }
            else
            {
                sections.Add(new InfoSection("The content scan",
                    "This build does not read file contents. The content scan is a later stage, and it will be off until you turn it on."));
            }

            sections.Add(new InfoSection("What a finding shows",
                "The file, its folder, what kind of thing it is, and for a content match the line number.",
                "Never the matched value, not even part of it, and never the surrounding text."));

            sections.Add(new InfoSection("What is kept, and where",
                "One file: " + ProtectStore.DefaultPath + ".",
                "It holds whether the content scan is on, and a hash for each finding you dismissed and each folder you " +
                "trusted. It contains no paths in clear and no values.",
                "Nothing else is written anywhere."));

            sections.Add(new InfoSection("What Protect never does",
                "Change, move or delete a file on its own. Its actions open folders and files, or hand off to the app's " +
                "copy, move and Recycle Bin flows, each of which asks first.",
                "Ask for administrator rights.",
                "Send anything anywhere."));
            return sections;
        }

        public static string AsText()
        {
            var sb = new StringBuilder();
            foreach (InfoSection s in Describe())
            {
                sb.Append(s.Title).Append('\n');
                foreach (string line in s.Lines) sb.Append("  - ").Append(line).Append('\n');
                sb.Append('\n');
            }
            return sb.ToString();
        }
    }
}

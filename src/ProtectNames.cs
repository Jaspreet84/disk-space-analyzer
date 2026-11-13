using System;
using System.Collections.Generic;

// Protect stage 1: findings by file name and location.
//
// Everything here works on names, sizes and the folder chain that Analyze already walks. No file is opened,
// and nothing touches the disk: the places of this PC arrive in a ProtectContext built by the caller.
//
// This file is under the trust checks in tools\check-trust.ps1: no writes, no content reads.

namespace DiskSpace
{
    [Flags]
    enum DirFlags : ushort
    {
        None = 0, Skip = 1, Fixture = 2, AppData = 4, Examined = 8, MailAttach = 16,
        DotOther = 32, BuildOut = 64, External = 128, VaultFolder = 256, ToolCache = 512
    }

    enum ToolHome : byte
    {
        None, Ssh, Aws, Azure, Kube, Docker, DockerMachines, Minikube, MinikubeMachines, Android, Gnupg,
        GnupgPrivate, ConfigGh, ConfigGcloud, VagrantD, Codex, Claude, Gcloud, GitHubCli, TerraformD, UserSecrets,
        Postgresql, CoinWallet, ElectrumWallets, EthKeystore
    }

    // What is known about one folder, computed once per folder from its parent's state and its own name.
    struct DirState
    {
        public DirFlags Flags;
        public ToolHome Tool;
        public PlaceMarks Marks;   // inherited known places
        public byte HomeDepth;     // 0 = not under Home; 1 = Home itself
        public byte DocsDepth;     // 0 = not under a Documents folder; 1 = the folder itself
        public byte ToolDepth;     // 1 = the tool home itself
        public byte AppDepth;      // 0 = not under Roaming or Local; 1 = Roaming, Local or LocalLow itself
        public byte MailStep;      // 0..7 through the Mail attachment path
        public int ScansSlot;      // 0 = none, else 1 + index of the pending Scanned Documents folder above
        public bool IsScansFolder; // this folder itself is named "Scanned Documents"
        public string Name, ParentName;
    }

    struct NameMatch { public string PatternId; public FindingTier Tier; public Place Place; }  // PatternId == null: no finding

    // Whether a candidate's folder is inside a repository. Analyze asks ProtectScan only when a row needs the
    // place, so most candidates never walk the folder chain.
    struct RepoQuery
    {
        public ProtectScan Scan;
        public DirNode Dir;
        public byte State;  // 0 = not asked yet, 1 = no, 2 = yes

        public bool Get()
        {
            if (State == 0) State = Scan != null && Scan.InRepo(Dir) ? (byte)2 : (byte)1;
            return State == 2;
        }

        public static RepoQuery Known(bool inRepo)
        {
            RepoQuery q = new RepoQuery();
            q.State = inRepo ? (byte)2 : (byte)1;
            return q;
        }
    }

    static class ProtectNames
    {
        public const byte HintNone = 0, HintCred = 1, HintDoc = 2, HintTaxFile = 3, HintName = 4;

        // The token buffer: lower-cased text first, then four chars per token (start, length, kind, segment).
        public const int BufferSize = 2048;
        const int TextCap = 1024;
        const int MaxTokens = (BufferSize - TextCap) / 4;
        const char KindRaw = (char)1, KindSub = (char)2, KindDigits = (char)4;
        const int SegStem = 0, SegDir = 1, SegParent = 2, SegOther = 3;
        const int MaskStem = 1, MaskAll = 1 | 2 | 4;

        const byte KindSkip = 1, KindFixture = 2, KindBuild = 4, KindPairSecond = 8;

        static readonly Dictionary<string, byte> folderKinds = new Dictionary<string, byte>(new QuickNoCase());
        static readonly Dictionary<string, List<string>> pairFirsts = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, ToolHome> homeTools = new Dictionary<string, ToolHome>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, ToolHome> roamingTools = new Dictionary<string, ToolHome>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, byte> extHints = new Dictionary<string, byte>(StringComparer.Ordinal);
        static readonly HashSet<string> exactNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        static readonly string[] dotNames = { ".git-credentials", ".netrc", "_netrc", ".npmrc", ".pypirc", ".pgpass", ".htpasswd" };
        static readonly string[] sshKeyNames = { "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk" };
        static readonly string[] sshNonKeyNames = { "known_hosts", "known_hosts.old", "authorized_keys", "authorized_keys2", "config", "environment" };
        static readonly string[] azureNames = { "msal_token_cache.json", "msal_token_cache.bin", "accessTokens.json",
            "service_principal_entries.json", "service_principal_entries.bin" };
        static readonly string[] gcloudNames = { "application_default_credentials.json", "credentials.db", "access_tokens.db" };
        static readonly string[] exportBrowsers = { "Chrome", "Microsoft Edge", "Edge", "Brave", "Opera", "Vivaldi", "Google", "Firefox" };
        static readonly string[] pkcs12Guard = { "sample", "example", "test", "demo", "dummy" };
        static readonly string[] keystoreGuard = { "trust", "truststore", "cacerts", "ca" };
        static readonly string[] tfstateGuard = { "example", "sample" };
        static readonly string[] envTemplateWords = { "example", "sample", "template", "tpl", "tmpl", "dist", "default", "defaults",
            "schema", "test", "ci", "docker", "vault" };
        static readonly string[] envNeverEnds = { ".ts", ".js", ".mjs", ".cjs", ".py", ".md", ".json", ".yml", ".yaml" };
        static readonly string[] envSecretWords = { "secret", "secrets", "credentials" };
        static readonly string[] pgpSecretWords = { "secret", "private", "sec" };
        static readonly string[] pgpPublicWords = { "pub", "public", "pubring", "release" };
        static readonly string[] imageExts = { ".jpg", ".jpeg", ".png", ".heic", ".heif", ".tif", ".tiff", ".bmp", ".webp" };

        static readonly string[] cameraFirst = { "img", "dsc", "dscn", "pxl", "mvimg", "vid", "screenshot", "photo", "image" };
        static readonly string[] taxStarts = { "taxreturn", "taxreport", "taxform" };
        static readonly string[] taxWords = { "tax", "taxes" };
        static readonly string[] taxCo = { "return", "returns", "form", "forms", "irs", "cra", "hmrc", "1040", "1099", "w2", "t4",
            "slip", "filing", "refund", "assessment" };
        static readonly string[] co1099 = { "form", "irs", "int", "div", "misc", "nec", "consolidated", "tax", "taxes", "brokerage" };
        static readonly string[] coW2 = { "form", "irs", "tax", "taxes", "wage", "wages", "employer" };
        static readonly string[] coT4 = { "slip", "tax", "taxes", "cra", "income", "employment" };
        static readonly string[] co1040 = { "irs", "form" };
        static readonly string[] statementWords = { "statement", "statements", "estatement" };
        static readonly string[] financialCo = { "bank", "banking", "account", "accounts", "checking", "chequing", "savings", "credit",
            "card", "brokerage", "ira", "401k", "mortgage", "loan", "investment", "portfolio",
            "chase", "citi", "wells", "fargo", "wellsfargo", "ally", "schwab", "fidelity", "vanguard", "amex", "capitalone",
            "hsbc", "barclays", "sbi", "hdfc", "icici", "usbank", "boa" };
        static readonly string[] payStarts = { "payslip", "paystub" };
        static readonly string[] payOrSalary = { "pay", "salary" };
        static readonly string[] slipWords = { "slip", "slips" };
        static readonly string[] stubWords = { "stub", "stubs" };
        static readonly string[] driverWords = { "driver", "drivers", "driving" };
        static readonly string[] licenseWords = { "license", "licence" };

        static ProtectNames()
        {
            foreach (string s in ProtectConstants.SkipFolders)
            {
                int cut = s.IndexOf('\\');
                if (cut < 0) { AddKind(s, KindSkip); continue; }
                string first = s.Substring(0, cut), second = s.Substring(cut + 1);
                AddKind(second, KindPairSecond);
                List<string> firsts;
                if (!pairFirsts.TryGetValue(second, out firsts)) { firsts = new List<string>(); pairFirsts[second] = firsts; }
                firsts.Add(first);
            }
            foreach (string s in ProtectConstants.FixtureFolders) AddKind(s, KindFixture);
            foreach (string s in ProtectConstants.BuildOutputFolders) AddKind(s, KindBuild);

            homeTools[".ssh"] = ToolHome.Ssh;
            homeTools[".aws"] = ToolHome.Aws;
            homeTools[".azure"] = ToolHome.Azure;
            homeTools[".kube"] = ToolHome.Kube;
            homeTools[".docker"] = ToolHome.Docker;
            homeTools[".minikube"] = ToolHome.Minikube;
            homeTools[".android"] = ToolHome.Android;
            homeTools[".gnupg"] = ToolHome.Gnupg;
            homeTools[".vagrant.d"] = ToolHome.VagrantD;
            homeTools[".codex"] = ToolHome.Codex;
            homeTools[".claude"] = ToolHome.Claude;

            roamingTools["gcloud"] = ToolHome.Gcloud;
            roamingTools["GitHub CLI"] = ToolHome.GitHubCli;
            roamingTools["terraform.d"] = ToolHome.TerraformD;
            roamingTools["gnupg"] = ToolHome.Gnupg;
            roamingTools["postgresql"] = ToolHome.Postgresql;
            roamingTools["Bitcoin"] = ToolHome.CoinWallet;
            roamingTools["Litecoin"] = ToolHome.CoinWallet;
            roamingTools["Dogecoin"] = ToolHome.CoinWallet;
            roamingTools["DashCore"] = ToolHome.CoinWallet;

            foreach (string e in ".pem .key .pfx .p12 .jks .keystore .ppk .kdbx .kdb .psafe3 .1pux .1pif .asc .gpg .pgp .kubeconfig .tfstate .backup .env .publishsettings".Split(' '))
                extHints[e] = HintCred;
            foreach (string e in ProtectConstants.DocExtensions) extHints[e] = HintDoc;
            foreach (string e in ".json .yml .yaml .csv .txt .dat .db .conf .toml .bin".Split(' ')) extHints[e] = HintName;
            extHints[Categories.NoExtension] = HintName;

            foreach (string n in sshKeyNames) exactNames.Add(n);
            foreach (string n in azureNames) exactNames.Add(n);
            foreach (string n in gcloudNames) exactNames.Add(n);
            foreach (string b in exportBrowsers) exactNames.Add(b + " Passwords.csv");
            foreach (string n in new[] { "insecure_private_key", "credentials", "config", "config.json", "hosts.yml", "adc.json",
                "kubeconfig", "kubeconfig.yaml", "kubeconfig.yml", "credentials.tfrc.json", "pgpass.conf", "wallet.dat",
                "default_wallet", "passwords.csv", "logins.csv", "rootkey.csv", "accessKeys.csv", "github-recovery-codes.txt",
                "gitlab-recovery-codes.txt", "secrets.json", "auth.json" })
                exactNames.Add(n);
            foreach (string n in exactNames) AddFirst(n[0]);
            AddFirst('b');
            AddFirst('l');

            for (int c = 0; c < 128; c++) lower[c] = (byte)(c >= 'A' && c <= 'Z' ? c + 32 : c);
            foreach (string root in docRoots)
            {
                foreach (char a in CaseVariants(root[0])) foreach (char z in CaseVariants(root[1])) rootPairs[(a << 7) | z] = true;
                rootStart[root[0]] = true;
                if (root[0] >= 'a' && root[0] <= 'z') rootStart[root[0] - 32] = true;
            }
            for (int c = 0; c < triCode.Length; c++)
                triCode[c] = (byte)(c >= 'a' && c <= 'z' ? c - 'a' : c >= 'A' && c <= 'Z' ? c - 'A' : c >= '0' && c <= '9' ? 26 + c - '0' :
                                    c == ' ' ? 36 : c == '-' ? 37 : c == '_' ? 38 : TriOther);
            foreach (string root in docRoots)
            {
                // A two-char root may be followed by anything, the name's end included.
                ulong third = root.Length == 2 ? ulong.MaxValue : 1UL << triCode[root[2]];
                foreach (char a in CaseVariants(root[0])) foreach (char z in CaseVariants(root[1])) rootTri[triCode[a] * TriCodes + triCode[z]] |= third;
            }
        }

        // The doc prefilter's quick test. triCode folds every char to one of 40 codes (letters either case, digits,
        // space, '-', '_', and TriOther for the rest); it covers every char value so the loop needs no range test,
        // and only its first 128 bytes are touched by ASCII names. rootTri holds, by the codes of a root's first
        // two chars, a mask of the codes of the third chars that can follow; TriEnd stands for the end of the name.
        // No root has a TriOther char in its first two places, so those pairs have an empty mask.
        const int TriCodes = 40, TriOther = 39, TriEnd = 63;
        static readonly ulong[] rootTri = new ulong[TriCodes * TriCodes];
        static readonly byte[] triCode = new byte[65536];

        // The doc prefilter's roots (section 2.1), plus "advice" for "pay advice". Lower case.
        static readonly string[] docRoots = { "tax", "t4", "t-4", "t_4", "t 4", "w2", "w-2", "w_2", "w 2", "1099", "1040",
            "statement", "slip", "stub", "social", "payslip", "paystub", "passport", "pan card", "licen", "idcard", "id-card",
            "id_card", "id card", "aadhaar", "advice", "birth", "green" };
        static readonly byte[] lower = new byte[128];
        static readonly bool[] rootPairs = new bool[128 * 128];  // by the raw (first, second) chars, every case mix

        static char[] CaseVariants(char c)
        {
            return c >= 'a' && c <= 'z' ? new[] { c, (char)(c - 32) } : new[] { c };
        }
        static readonly bool[] rootStart = new bool[128];  // by raw char, either case

        // The first chars (ASCII, lower-cased) of the exact names and the bitwarden_ and lastpass_ prefixes, as
        // two 64-bit masks, so most HintName files skip the hash lookup.
        static ulong firstLo, firstHi;

        static void AddFirst(char c)
        {
            if (c >= 128) { firstLo = firstHi = ulong.MaxValue; return; }
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            if (c < 64) firstLo |= 1UL << c;
            else firstHi |= 1UL << (c - 64);
        }

        static bool FirstMayMatch(char c)
        {
            if (c >= 128) return true;
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            return c < 64 ? ((firstLo >> c) & 1) != 0 : ((firstHi >> (c - 64)) & 1) != 0;
        }

        static void AddKind(string name, byte kind)
        {
            byte k;
            folderKinds.TryGetValue(name, out k);
            folderKinds[name] = (byte)(k | kind);
            kindEnds[EndsKey(name)] = true;
            kindEnds[0] = true;  // a name with a non-ASCII first or last char always asks the table
        }

        // The folder-name table's keys by (first, last) char, lower-cased, so most folder names skip the lookup.
        static readonly bool[] kindEnds = new bool[128 * 128];

        static int EndsKey(string s)
        {
            int a = s[0], z = s[s.Length - 1];
            if (a >= 128 || z >= 128) return 0;
            if (a >= 'A' && a <= 'Z') a += 32;
            if (z >= 'A' && z <= 'Z') z += 32;
            return (a << 7) | z;
        }

        // ---- The per-extension hint and the per-file gate -------------------------------------------------

        // Called once per distinct extension key (Categories.KeyFor form, including NoExtension).
        public static byte ExtHint(string extKey)
        {
            if (extKey == null) return HintNone;
            byte h;
            if (extHints.TryGetValue(extKey, out h)) return h;
            if (extKey.Length == 8 && string.CompareOrdinal(extKey, 0, ".tax", 0, 4) == 0)
            {
                int year = 0;
                for (int i = 4; i < 8; i++)
                {
                    char c = extKey[i];
                    if (c < '0' || c > '9') return HintNone;
                    year = year * 10 + (c - '0');
                }
                if (year >= 2000 && year <= 2039) return HintTaxFile;
            }
            return HintNone;
        }

        // The per-file gate. For most files this is one field read and one char compare. It must let through
        // every file that ClassifyFile can match; ClassifyFile itself is correct without it.
        public static bool IsCandidate(string name, byte hint, DirState dir)
        {
            return IsCandidate(name, hint, dir.Tool, dir.ToolDepth, dir.HomeDepth);
        }

        // The same gate with only the three fields it reads, so Analyze does not copy the whole DirState per file.
        internal static bool IsCandidate(string name, byte hint, ToolHome tool, byte toolDepth, byte homeDepth)
        {
            if (hint == HintCred || hint == HintTaxFile) return true;
            if (hint == HintDoc && (DocPrefilter(name) || StartsCI(name, "1Password Emergency Kit"))) return true;
            if (tool != ToolHome.None)
            {
                // In a tool home the rows name files by exact name (HintName) or by extension (HintCred), except
                // the three places where any file name can be a key.
                if (hint == HintName || TakesEveryFile(tool, toolDepth)) return true;
            }
            else if (hint == HintName && NameGate(name)) return true;
            if (name.Length == 0) return false;
            char c = name[0];
            if (c == '.' || c == '_') return DotGate(name, homeDepth);
            return c == 'U' && name.StartsWith("UTC--", StringComparison.Ordinal);
        }

        // True for a folder where ClassifyFile can find nothing at all: below a fixture folder, in a tool's cache,
        // in a dot folder of the profile that is not a tool home, or in AppData outside its examined exceptions.
        // Analyze asks it once per folder and then skips the per-file gate for the folder's files.
        public static bool NothingFoundIn(DirState dir)
        {
            if ((dir.Flags & (DirFlags.Skip | DirFlags.Fixture | DirFlags.ToolCache | DirFlags.DotOther)) != 0) return true;
            return (dir.Flags & DirFlags.AppData) != 0 && (dir.Flags & (DirFlags.Examined | DirFlags.MailAttach)) == 0 &&
                   dir.Tool == ToolHome.None;
        }

        // Directly in ~\.ssh (a key with a .pub sibling), in GnuPG's private-keys-v1.d, and in Electrum's wallets.
        static bool TakesEveryFile(ToolHome tool, byte toolDepth)
        {
            return (tool == ToolHome.Ssh && toolDepth == 1) || tool == ToolHome.GnupgPrivate || tool == ToolHome.ElectrumWallets;
        }

        // The dot and underscore names a row can match without help from the extension hint. A name such as
        // .gitignore or .DS_Store stops here, and so do .npmrc outside the profile folder itself (the only place
        // row 17 looks) and .env.<template> names such as .env.example, which the dotenv row never reports. Only
        // names whose extension gives no hint reach this test, so no extension row can match them either.
        static bool DotGate(string name, byte homeDepth)
        {
            if (StartsCI(name, ".env")) return !IsEnvTemplateName(name);
            for (int i = 0; i < dotNames.Length; i++)
                if (name.Length == dotNames[i].Length && EqCI(name, dotNames[i]))
                    return homeDepth == 1 || !EqCI(name, NpmrcName);
            return false;
        }

        const string NpmrcName = ".npmrc";

        // ".env." followed by a template word as the whole first raw token (IsDotenvName's test, written so it
        // answers true only when the tokenizer would give exactly that token: ASCII letters, no camel split,
        // ended by a char that is not a letter or digit, or by the end of the name).
        static bool IsEnvTemplateName(string name)
        {
            if (name.Length < 6 || name[4] != '.') return false;
            int end = 5;
            while (end < name.Length && char.IsLetterOrDigit(name[end])) end++;
            int len = end - 5;
            if (len == 0) return false;
            bool anyLower = false;
            for (int i = 5; i < end; i++)
            {
                char c = name[i];
                bool up = c >= 'A' && c <= 'Z', low = c >= 'a' && c <= 'z';
                if (!up && !low) return false;
                if (up && anyLower) return false;     // a lower-to-upper camel boundary
                if (up && i > 5 && i + 1 < end && name[i + 1] >= 'a' && name[i + 1] <= 'z') return false;  // "EXample"
                if (low) anyLower = true;
            }
            for (int w = 0; w < envTemplateWords.Length; w++)
            {
                string word = envTemplateWords[w];
                if (word.Length == len && string.Compare(name, 5, word, 0, len, StringComparison.OrdinalIgnoreCase) == 0) return true;
            }
            return false;
        }

        static bool NameGate(string name)
        {
            if (name.Length == 0) return false;
            char c = name[0];
            // Only two name rules have no fixed first char: the _accessKeys.csv suffix and the .publishsettings
            // extension, which is too long for an extension key and so arrives here as NoExtension.
            if (!FirstMayMatch(c))
                return EndsCI(name, ".publishsettings") || (EndsCI(name, ".csv") && EndsCI(BaseName(name), "_accessKeys.csv"));
            string bn = BaseName(name);
            if (exactNames.Contains(bn)) return true;
            if ((c == 'b' || c == 'B') && StartsCI(name, "bitwarden_")) return true;
            if ((c == 'l' || c == 'L') && StartsCI(name, "lastpass_")) return true;
            return EndsCI(bn, "_accessKeys.csv") || EndsCI(name, ".publishsettings");
        }

        // One forward pass over the name, switching on the lower-cased first letter of each root. A table of the
        // roots' first two chars rules out almost every position with one lookup. The extension never holds a
        // root (no DocExts extension does, and no root has a dot), so the whole name is scanned.
        static bool DocPrefilter(string name)
        {
            if (!AnyRootPair(name)) return false;
            int end = name.Length;
            for (int i = 0; i < end - 1; i++)
            {
                int c = name[i], n = name[i + 1];
                if ((c | n) >= 128)
                {
                    if (n >= 128) i++;  // no root starts with a non-ASCII char, so skip i + 1 too
                    continue;
                }
                if (!rootPairs[(c << 7) | n])
                {
                    if (!rootStart[n]) i++;  // the next position cannot start a root either
                    continue;
                }
                switch ((char)lower[c])
                {
                    case 't':
                        if (At(name, i, end, "tax")) return true;
                        // The T4 rule needs t4 to start a raw token, so "document-4" is not looked at.
                        if (TokenStart(name, i) && (At(name, i, end, "t4") || At(name, i, end, "t-4") || At(name, i, end, "t_4") ||
                            At(name, i, end, "t 4"))) return true;
                        break;
                    case 'w':
                        if (TokenStart(name, i) && (At(name, i, end, "w2") || At(name, i, end, "w-2") || At(name, i, end, "w_2") ||
                            At(name, i, end, "w 2"))) return true;
                        break;
                    case '1':
                        // 1099 and 1040 count only as a whole digit run.
                        if ((At(name, i, end, "1099") || At(name, i, end, "1040")) && (i == 0 || !IsDigitAt(name, i - 1)) &&
                            (i + 4 >= end || !IsDigitAt(name, i + 4))) return true;
                        break;
                    case 's':
                        if (At(name, i, end, "statement") || At(name, i, end, "slip") || At(name, i, end, "stub") ||
                            At(name, i, end, "social")) return true;
                        break;
                    case 'p':
                        if (At(name, i, end, "payslip") || At(name, i, end, "paystub") || At(name, i, end, "passport") ||
                            At(name, i, end, "pan card")) return true;
                        break;
                    case 'l':
                        if (At(name, i, end, "licen")) return true;
                        break;
                    case 'i':
                        if (At(name, i, end, "idcard") || At(name, i, end, "id-card") || At(name, i, end, "id_card") ||
                            At(name, i, end, "id card")) return true;
                        break;
                    case 'a':
                        if (At(name, i, end, "aadhaar") || At(name, i, end, "advice")) return true;
                        break;
                    case 'b':
                        if (At(name, i, end, "birth")) return true;
                        break;
                    case 'g':
                        if (At(name, i, end, "green")) return true;
                        break;
                }
            }
            return false;
        }

        // Whether any three neighbouring chars can be the start of a root (two chars and the end of the name, for
        // the two-char roots). This runs for every document-type file, so the loop has no branch: two table
        // lookups per char, both in tables small enough to stay in the cache.
        static bool AnyRootPair(string name)
        {
            // Only the stem: no root holds a dot, and no DocExts extension holds a root.
            int len = name.LastIndexOf('.');
            if (len < 0) len = name.Length;
            if (len < 2) return false;
            ulong[] tri = rootTri;
            byte[] code = triCode;
            ulong any = 0;
            int a = code[name[0]], b = code[name[1]];
            for (int i = 2; i < len; i++)
            {
                int t = code[name[i]];
                any |= tri[a * TriCodes + b] >> t;
                a = b;
                b = t;
            }
            any |= tri[a * TriCodes + b] >> TriEnd;
            return (any & 1) != 0;
        }

        // Whether a raw token starts at s[i] (the tokenizer's rule): at the start, after a char that is not a letter
        // or digit, or at a lower-to-upper camel boundary.
        static bool TokenStart(string s, int i)
        {
            if (i == 0) return true;
            char p = s[i - 1], c = s[i];
            if (!char.IsLetterOrDigit(p)) return true;
            return char.IsLower(p) && char.IsUpper(c);
        }

        static bool IsDigitAt(string s, int i)
        {
            return s[i] >= '0' && s[i] <= '9';
        }

        // Whether the lower-case ASCII root occurs in s at i, ignoring case, without reaching past end.
        static bool At(string s, int i, int end, string root)
        {
            if (i + root.Length > end) return false;
            for (int k = 1; k < root.Length; k++)
            {
                char c = s[i + k];
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                if (c != root[k]) return false;
            }
            return true;
        }

        // ---- Folder state ---------------------------------------------------------------------------------

        public static DirState Enter(DirState parent, string name, PlaceMarks marksHere, ProtectContext ctx)
        {
            DirState s = parent;
            s.ParentName = parent.Name;
            s.Name = name;
            s.IsScansFolder = false;
            s.Marks = parent.Marks | marksHere;
            if ((parent.Flags & DirFlags.Skip) != 0) return s;  // nothing below a skip folder is ever reported

            bool first = parent.Name == null;
            if (first && ctx != null && ctx.IsExternalRoot(CheapNorm(name))) s.Flags |= DirFlags.External;

            s.HomeDepth = (marksHere & PlaceMarks.Home) != 0 ? (byte)1 : Inc(parent.HomeDepth);
            s.DocsDepth = (marksHere & PlaceMarks.Documents) != 0 ? (byte)1 : Inc(parent.DocsDepth);
            s.AppDepth = (marksHere & (PlaceMarks.Roaming | PlaceMarks.Local)) != 0 ? (byte)1 : Inc(parent.AppDepth);
            s.ToolDepth = Inc(parent.ToolDepth);
            if (name.Length == 0) return s;
            if (marksHere == PlaceMarks.None && StaysEmpty(parent)) return s;  // nothing below can be found: skip the name tests

            byte kind;
            if (!first && kindEnds[EndsKey(name)] && folderKinds.TryGetValue(name, out kind))
            {
                // Fixture and build names are about folders inside projects. The user folder, and the folders
                // that hold it, can have any name: a profile called "Test" or "Demo" silences nothing.
                bool homePath = (marksHere & (PlaceMarks.Home | PlaceMarks.HomeAbove)) != 0;
                if ((kind & KindSkip) != 0) s.Flags |= DirFlags.Skip;
                if ((kind & KindFixture) != 0 && !homePath) s.Flags |= DirFlags.Fixture;
                if ((kind & KindBuild) != 0 && !homePath) s.Flags |= DirFlags.BuildOut;
                if ((kind & KindPairSecond) != 0 && parent.Name != null)
                {
                    List<string> firsts;
                    if (pairFirsts.TryGetValue(name, out firsts))
                        foreach (string f in firsts)
                            if (EqCI(parent.Name, f)) s.Flags |= DirFlags.Skip;
                }
            }
            char c0 = name[0];
            if (c0 == '$' && !first) s.Flags |= DirFlags.Skip;
            if ((s.Flags & DirFlags.Skip) != 0) return s;

            // AppData and its examined exceptions
            if ((marksHere & (PlaceMarks.Roaming | PlaceMarks.Local)) != 0) s.Flags |= DirFlags.AppData;
            else if (parent.HomeDepth == 1 && EqCI(name, "AppData")) s.Flags |= DirFlags.AppData;
            else if (parent.HomeDepth == 2 && EqCI(parent.Name, "AppData") && EqCI(name, "LocalLow"))
            {
                s.Flags |= DirFlags.AppData;
                s.AppDepth = 1;
            }
            if ((marksHere & PlaceMarks.Temp) != 0) s.Flags |= DirFlags.Examined;

            // Tool homes
            if (c0 == '.' && parent.HomeDepth == 1)
            {
                ToolHome t;
                if (homeTools.TryGetValue(name, out t)) { s.Tool = t; s.ToolDepth = 1; }
                else s.Flags |= DirFlags.DotOther;
            }
            else if (parent.Tool != ToolHome.None)
            {
                if (parent.ToolDepth == 1)
                {
                    if (parent.Tool == ToolHome.Kube && (EqCI(name, "cache") || EqCI(name, "http-cache"))) s.Flags |= DirFlags.ToolCache;
                    else if (parent.Tool == ToolHome.Docker && (EqCI(name, "contexts") || EqCI(name, "buildx"))) s.Flags |= DirFlags.ToolCache;
                    else if (parent.Tool == ToolHome.Minikube && EqCI(name, "machines")) s.Tool = ToolHome.MinikubeMachines;
                    else if (parent.Tool == ToolHome.Gnupg && EqCI(name, "private-keys-v1.d")) s.Tool = ToolHome.GnupgPrivate;
                }
                else if (parent.ToolDepth == 2 && parent.Tool == ToolHome.Docker && EqCI(parent.Name, "machine") && EqCI(name, "machines"))
                    s.Tool = ToolHome.DockerMachines;
            }
            else if (parent.HomeDepth == 2 && (parent.Flags & DirFlags.DotOther) != 0 && EqCI(parent.Name, ".config") &&
                     (EqCI(name, "gh") || EqCI(name, "gcloud")))
            {
                s.Tool = EqCI(name, "gh") ? ToolHome.ConfigGh : ToolHome.ConfigGcloud;
                s.ToolDepth = 1;
                s.Flags &= ~DirFlags.DotOther;
            }
            else if (parent.AppDepth == 1 && (parent.Marks & PlaceMarks.Roaming) != 0 && (parent.Marks & PlaceMarks.Local) == 0)
            {
                ToolHome t;
                if (roamingTools.TryGetValue(name, out t))
                {
                    s.Tool = t;
                    s.ToolDepth = 1;
                    s.Flags |= DirFlags.Examined;
                }
            }
            else if (parent.AppDepth == 2 && (parent.Marks & PlaceMarks.Roaming) != 0 && (parent.Marks & PlaceMarks.Local) == 0)
            {
                ToolHome t = ToolHome.None;
                if (EqCI(parent.Name, "Microsoft") && EqCI(name, "UserSecrets")) t = ToolHome.UserSecrets;
                else if (EqCI(parent.Name, "Electrum") && EqCI(name, "wallets")) t = ToolHome.ElectrumWallets;
                else if (EqCI(parent.Name, "Ethereum") && EqCI(name, "keystore")) t = ToolHome.EthKeystore;
                if (t != ToolHome.None)
                {
                    s.Tool = t;
                    s.ToolDepth = 1;
                    s.Flags |= DirFlags.Examined;
                }
            }

            // The retired Windows Mail app's attachment cache
            byte step = parent.MailStep;
            if (step == 7) s.MailStep = 7;
            else if (step == 0) s.MailStep = (byte)(parent.AppDepth == 1 && (parent.Marks & PlaceMarks.Local) != 0 && EqCI(name, "Packages") ? 1 : 0);
            else if (step == 1) s.MailStep = (byte)(StartsCI(name, "microsoft.windowscommunicationsapps_") ? 2 : 0);
            else if (step == 2) s.MailStep = (byte)(EqCI(name, "LocalState") ? 3 : 0);
            else if (step == 3) s.MailStep = (byte)(EqCI(name, "Files") ? 4 : 0);
            else if (step == 4 || step == 5) s.MailStep = (byte)(step + 1);
            else if (step == 6) s.MailStep = (byte)(EqCI(name, "Attachments") ? 7 : 0);
            if (s.MailStep == 7) s.Flags |= DirFlags.MailAttach;

            if (EndsCI(name, ".opvault") || EndsCI(name, ".agilekeychain")) s.Flags |= DirFlags.VaultFolder;
            if (c0 == 'S' || c0 == 's') s.IsScansFolder = EqCI(name, "Scanned Documents");
            return s;
        }

        // Whether every folder below this one is a folder where nothing can be found, whatever its name: below a
        // fixture folder or a tool cache, deep in a dot folder of the profile, or deep in AppData (the examined
        // exceptions and the Mail cache all start within two levels of Roaming or Local).
        static bool StaysEmpty(DirState parent)
        {
            if ((parent.Flags & (DirFlags.Fixture | DirFlags.ToolCache)) != 0) return true;
            if ((parent.Flags & DirFlags.DotOther) != 0 && parent.HomeDepth >= 3) return true;
            return (parent.Flags & DirFlags.AppData) != 0 && (parent.Flags & (DirFlags.Examined | DirFlags.MailAttach)) == 0 &&
                   parent.Tool == ToolHome.None && parent.AppDepth >= 3 && parent.MailStep == 0;
        }

        static byte Inc(byte b)
        {
            return b == 0 ? (byte)0 : b < 250 ? (byte)(b + 1) : b;
        }

        // Folds each segment of the scan root's own path through Enter, so a root inside node_modules, AppData or
        // a known folder gets the same state as it would below a scan of the whole drive.
        public static DirState RootState(string rootPath, ProtectContext ctx)
        {
            DirState s = new DirState();
            if (string.IsNullOrEmpty(rootPath)) return s;
            string p = rootPath.Replace('/', '\\');
            string first;
            int at;
            if (p.StartsWith("\\\\", StringComparison.Ordinal))
            {
                int server = p.IndexOf('\\', 2);
                int share = server < 0 ? -1 : p.IndexOf('\\', server + 1);
                first = share < 0 ? p : p.Substring(0, share);
                at = first.Length;
            }
            else if (p.Length >= 2 && p[1] == ':')
            {
                first = p.Substring(0, 2) + "\\";
                at = 2;
            }
            else
            {
                int cut = p.IndexOf('\\');
                first = cut < 0 ? p : p.Substring(0, cut);
                at = first.Length;
            }
            string prefix = first;
            s = Enter(s, first, ctx != null ? ctx.MarksOfPath(CheapNorm(prefix)) : PlaceMarks.None, ctx);
            foreach (string seg in p.Substring(at).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                prefix = prefix.EndsWith("\\", StringComparison.Ordinal) ? prefix + seg : prefix + "\\" + seg;
                s = Enter(s, seg, ctx != null ? ctx.MarksOfPath(CheapNorm(prefix)) : PlaceMarks.None, ctx);
            }
            return s;
        }

        // ProtectStore.Normalize for a path that is already full: upper case, backslashes, no trailing separator.
        internal static string CheapNorm(string path)
        {
            string p = path.Replace('/', '\\');
            if (p.Length > 3) p = p.TrimEnd('\\');
            if (p.Length == 2 && p[1] == ':') p += "\\";
            return p.ToUpperInvariant();
        }

        // ---- Place ----------------------------------------------------------------------------------------

        // adjust is 1 when dir is the state of a folder finding itself rather than of the folder holding a file.
        static Place PlaceOf(DirState dir, bool inRepo, int adjust)
        {
            RepoQuery q = RepoQuery.Known(inRepo);
            return PlaceOf(dir, ref q, adjust);
        }

        // The repository is asked last, and only when the earlier places did not match.
        static Place PlaceOf(DirState dir, ref RepoQuery repo, int adjust)
        {
            if ((dir.Marks & PlaceMarks.Sync) != 0) return Place.Synced;
            if ((dir.Flags & DirFlags.External) != 0) return Place.ExternalDrive;
            if ((dir.Marks & PlaceMarks.Temp) != 0) return Place.Temp;
            if ((dir.Marks & PlaceMarks.Downloads) != 0) return Place.Downloads;
            if ((dir.Marks & PlaceMarks.Desktop) != 0) return Place.Desktop;
            if (repo.Get()) return Place.Repository;
            int h = dir.HomeDepth - adjust, d = dir.DocsDepth - adjust;
            bool plain = (dir.Flags & (DirFlags.AppData | DirFlags.DotOther)) == 0 && dir.Tool == ToolHome.None &&
                         (dir.Marks & (PlaceMarks.Pictures | PlaceMarks.Videos | PlaceMarks.Music)) == 0;
            if (plain && (h == 1 || h == 2 || d == 1 || d == 2)) return Place.HomeFolder;
            return Place.Other;
        }

        static bool InE(Place p)
        {
            return p == Place.HomeFolder || p == Place.Downloads || p == Place.Desktop || p == Place.Synced || p == Place.ExternalDrive;
        }

        static bool InDocsUnsynced(DirState dir)
        {
            return dir.DocsDepth > 0 && (dir.Marks & PlaceMarks.Sync) == 0;
        }

        static NameMatch Hit(string id, FindingTier tier, Place place)
        {
            NameMatch m;
            m.PatternId = id;
            m.Tier = tier;
            m.Place = place;
            return m;
        }

        static NameMatch Likely(string id, Place place) { return Hit(id, FindingTier.Likely, place); }
        static NameMatch Confirmed(string id, Place place) { return Hit(id, FindingTier.Confirmed, place); }

        // ---- The core -------------------------------------------------------------------------------------

        // The place of a candidate, worked out only when a row has matched its name.
        struct Where
        {
            public DirState Dir;
            public RepoQuery Repo;
            bool known;
            Place value;

            public Place Get()
            {
                if (!known)
                {
                    value = PlaceOf(Dir, ref Repo, 0);
                    known = true;
                }
                return value;
            }

            public bool E()
            {
                return InE(Get());
            }
        }

        public static NameMatch ClassifyFile(string name, long size, bool onlineOnly, byte hint, DirState dir,
            bool inRepo, IList<string> siblings, ProtectContext ctx, char[] buffer)
        {
            RepoQuery q = RepoQuery.Known(inRepo);
            return ClassifyFile(name, size, onlineOnly, hint, dir, ref q, siblings, buffer);
        }

        // The core, with the repository test asked lazily (ProtectScan.InRepo walks the folder chain).
        internal static NameMatch ClassifyFile(string name, long size, bool onlineOnly, byte hint, DirState dir,
            ref RepoQuery repo, IList<string> siblings, char[] buffer)
        {
            NameMatch none = new NameMatch();
            if (string.IsNullOrEmpty(name)) return none;
            if ((dir.Flags & (DirFlags.Skip | DirFlags.Fixture | DirFlags.VaultFolder | DirFlags.ToolCache)) != 0) return none;
            if (EndsCI(name, ".lnk") || EndsCI(name, ".url")) return none;
            if (size <= 0 && !onlineOnly) return none;
            var t = new Toks(buffer);

            // Usual-place rows, by tool home or exact path. A tool home's files are never judged "elsewhere".
            if (dir.Tool != ToolHome.None) return InToolHome(name, size, onlineOnly, dir, siblings, ref t);
            NameMatch m;
            if (dir.HomeDepth == 1)
            {
                m = AtHomeRoot(name);
                if (m.PatternId != null) return m;
            }
            if ((dir.Flags & DirFlags.DotOther) != 0) return none;
            bool mail = (dir.Flags & DirFlags.MailAttach) != 0;
            if ((dir.Flags & DirFlags.AppData) != 0 && (dir.Flags & DirFlags.Examined) == 0 && !mail) return none;
            // No credential row has a document extension except the 1Password emergency kit (.pdf).
            if (!mail && (hint != HintDoc || StartsCI(name, "1Password Emergency Kit")) && hint != HintTaxFile)
            {
                Where w = new Where();
                w.Dir = dir;
                w.Repo = repo;
                m = Elsewhere(name, size, onlineOnly, dir, ref w, ref t);
                repo = w.Repo;
                if (m.PatternId != null) return m;
            }
            return Document(name, size, onlineOnly, hint, dir, ref repo, ref t);
        }

        static bool Within(long size, bool online, long min, long max)
        {
            return online || (size >= min && size <= max);
        }

        static NameMatch InToolHome(string name, long size, bool online, DirState dir, IList<string> siblings, ref Toks t)
        {
            NameMatch none = new NameMatch();
            // Exact names are compared after one copy suffix is removed ("id_ed25519 (1)", "config - Copy").
            string bn = BaseName(name);
            int depth = dir.ToolDepth;
            Place u = Place.UsualPlace;
            bool sshSize = Within(size, online, ProtectConstants.SshKeyMinBytes, ProtectConstants.SshKeyMaxBytes);
            switch (dir.Tool)
            {
                case ToolHome.Ssh:
                    if (depth <= 2 && IsSshKeyName(bn) && sshSize) return Confirmed("ssh-key", u);
                    if (depth == 1 && siblings != null && !IsSshNonKey(name) && sshSize && HasSibling(siblings, name + ".pub"))
                        return Confirmed("ssh-key", u);
                    if (EndsCI(name, ".ppk") && Within(size, online, 0, ProtectConstants.PpkMaxBytes)) return Confirmed("ssh-ppk", u);
                    return PemInToolHome(name, size, online, ref t);
                case ToolHome.MinikubeMachines:
                    if (depth == 3 && IsSshKeyName(bn) && sshSize) return Confirmed("ssh-key", u);
                    return PemInToolHome(name, size, online, ref t);
                case ToolHome.DockerMachines:
                    if (depth == 4 && IsSshKeyName(bn) && sshSize) return Confirmed("ssh-key", u);
                    return PemInToolHome(name, size, online, ref t);
                case ToolHome.VagrantD:
                    if ((IsSshKeyName(bn) || EqCI(bn, "insecure_private_key")) && sshSize) return Confirmed("ssh-key", u);
                    return PemInToolHome(name, size, online, ref t);
                case ToolHome.Aws:
                    if (depth == 1 && EqCI(bn, "credentials")) return Confirmed("aws-credentials", u);
                    return PemInToolHome(name, size, online, ref t);
                case ToolHome.Azure:
                    if (depth == 1 && EqAny(bn, azureNames)) return Confirmed("azure-tokens", u);
                    return PemInToolHome(name, size, online, ref t);
                case ToolHome.Kube:
                    if (depth == 1 && EqCI(bn, "config")) return Confirmed("kubeconfig", u);
                    return PemInToolHome(name, size, online, ref t);
                case ToolHome.Docker:
                    if (depth == 1 && EqCI(bn, "config.json")) return Likely("docker-config", u);
                    return PemInToolHome(name, size, online, ref t);
                case ToolHome.Minikube:
                    return PemInToolHome(name, size, online, ref t);
                case ToolHome.Android:
                    if (depth == 1 && EqCI(bn, "debug.keystore") && Within(size, online, 0, ProtectConstants.KeystoreMaxBytes))
                        return Confirmed("java-keystore", u);
                    return none;
                case ToolHome.Gcloud:
                case ToolHome.ConfigGcloud:
                    if (depth == 1 && EqAny(bn, gcloudNames)) return Confirmed("gcloud-credentials", u);
                    if (depth == 3 && EqCI(dir.ParentName, "legacy_credentials") && EqCI(bn, "adc.json")) return Confirmed("gcloud-credentials", u);
                    return none;
                case ToolHome.GitHubCli:
                case ToolHome.ConfigGh:
                    if (depth == 1 && EqCI(bn, "hosts.yml")) return Likely("gh-hosts", u);
                    return none;
                case ToolHome.Codex:
                    if (depth == 1 && EqCI(bn, "auth.json")) return Likely("cli-auth-file", u);
                    return none;
                case ToolHome.Claude:
                    if (depth == 1 && EqCI(bn, ".credentials.json")) return Likely("cli-auth-file", u);
                    return none;
                case ToolHome.UserSecrets:
                    if (depth == 2 && EqCI(bn, "secrets.json")) return Confirmed("dotnet-user-secrets", u);
                    return none;
                case ToolHome.TerraformD:
                    if (depth == 1 && EqCI(bn, "credentials.tfrc.json")) return Confirmed("terraform-credentials", u);
                    return none;
                case ToolHome.Gnupg:
                    if (depth == 1 && EqCI(bn, "secring.gpg")) return Confirmed("pgp-secret", u);
                    return none;
                case ToolHome.GnupgPrivate:
                    return Confirmed("pgp-secret", u);
                case ToolHome.Postgresql:
                    if (depth == 1 && EqCI(bn, "pgpass.conf")) return Confirmed("pgpass", u);
                    return none;
                case ToolHome.CoinWallet:
                    if (EqCI(bn, "wallet.dat") && Within(size, online, ProtectConstants.WalletMinBytes, ProtectConstants.WalletMaxBytes))
                        return Confirmed("crypto-wallet", u);
                    return none;
                case ToolHome.EthKeystore:
                    if (IsEthKeystoreName(name)) return Confirmed("eth-keystore", u);
                    return none;
                case ToolHome.ElectrumWallets:
                    return Confirmed("electrum-wallet", u);
            }
            return none;
        }

        // In a pem tool home: a .key extension, or a strong token in the stem.
        static NameMatch PemInToolHome(string name, long size, bool online, ref Toks t)
        {
            bool key = EndsCI(name, ".key");
            if (!key && !EndsCI(name, ".pem")) return new NameMatch();
            if (!Within(size, online, 0, ProtectConstants.PemMaxBytes)) return new NameMatch();
            if (key || StrongKeySignal(name, ref t)) return Confirmed("pem-key", Place.UsualPlace);
            return new NameMatch();
        }

        // Exact paths directly in the profile folder.
        static NameMatch AtHomeRoot(string name)
        {
            Place u = Place.UsualPlace;
            if (EqCI(name, ".git-credentials")) return Confirmed("git-credentials", u);
            if (EqCI(name, ".netrc") || EqCI(name, "_netrc")) return Confirmed("netrc", u);
            if (EqCI(name, ".npmrc")) return Likely("npm-rc", u);
            if (EqCI(name, ".pypirc")) return Likely("pypi-rc", u);
            if (EqCI(name, ".pgpass")) return Confirmed("pgpass", u);
            return new NameMatch();
        }

        // The credential rows outside their usual places, in table order.
        static NameMatch Elsewhere(string name, long size, bool online, DirState dir, ref Where w, ref Toks t)
        {
            NameMatch none = new NameMatch();
            string bn = BaseName(name);

            // 1 ssh-key
            if (IsSshKeyName(bn) && Within(size, online, ProtectConstants.SshKeyMinBytes, ProtectConstants.SshKeyMaxBytes))
                return Likely("ssh-key", w.Get());
            // 2 ssh-ppk
            if (EndsCI(name, ".ppk"))
                return Within(size, online, 0, ProtectConstants.PpkMaxBytes) ? Confirmed("ssh-ppk", w.Get()) : none;
            // 3 pem-key
            if (EndsCI(name, ".pem") || EndsCI(name, ".key"))
            {
                if (w.E() && Within(size, online, 0, ProtectConstants.PemMaxBytes) && PemElsewhere(name, size, online, dir, ref t))
                    return Likely("pem-key", w.Get());
                return none;
            }
            // 4 pkcs12
            if (EndsCI(name, ".pfx") || EndsCI(name, ".p12"))
            {
                if (!w.E() || (dir.Flags & DirFlags.BuildOut) != 0) return none;
                if (!Within(size, online, ProtectConstants.Pkcs12MinBytes, ProtectConstants.Pkcs12MaxBytes)) return none;
                StemTokens(name, ref t);
                if (t.HasAny(MaskStem, ProtectConstants.PublicKeyTokens) || t.HasAny(MaskStem, pkcs12Guard)) return none;
                return Likely("pkcs12", w.Get());
            }
            // 5 java-keystore
            if (EndsCI(name, ".jks") || EndsCI(name, ".keystore"))
            {
                if (!w.E() || (dir.Flags & DirFlags.BuildOut) != 0 || EqCI(bn, "debug.keystore")) return none;
                if (!Within(size, online, 0, ProtectConstants.KeystoreMaxBytes)) return none;
                StemTokens(name, ref t);
                if (t.HasAny(MaskStem, keystoreGuard)) return none;
                return Likely("java-keystore", w.Get());
            }
            // 6 password-vault
            if (EndsCI(name, ".kdbx") || EndsCI(name, ".kdb") || EndsCI(name, ".psafe3") ||
                (StartsCI(name, "bitwarden_encrypted_export_") && EndsCI(name, ".json")))
                return Confirmed("password-vault", InDocsUnsynced(dir) ? Place.UsualPlace : w.Get());
            // 7 password-export
            if (IsNamedExport(name, bn))
                return w.Get() == Place.Repository ? Likely("password-export", w.Get()) : Confirmed("password-export", w.Get());
            if (EqCI(bn, "passwords.csv") || EqCI(bn, "logins.csv"))
            {
                if (w.Get() == Place.Downloads || w.Get() == Place.Desktop || w.Get() == Place.Synced || w.Get() == Place.HomeFolder)
                    return Likely("password-export", w.Get());
                return none;
            }
            // 8 git-credentials
            if (EqCI(bn, ".git-credentials")) return Likely("git-credentials", w.Get());
            // 9 netrc
            if (EqCI(bn, ".netrc") || EqCI(bn, "_netrc")) return w.E() ? Likely("netrc", w.Get()) : none;
            // 10 aws-credentials
            if (EqCI(bn, "credentials"))
                return EqCI(dir.Name, ".aws") && w.Get() != Place.Temp ? Likely("aws-credentials", w.Get()) : none;
            // 11 aws-keys-csv
            if (EndsCI(bn, "_accessKeys.csv") || EqCI(bn, "accessKeys.csv") || EqCI(bn, "rootkey.csv"))
                return w.Get() != Place.Repository ? Likely("aws-keys-csv", w.Get()) : none;
            // 12 azure-tokens
            if (EqCI(dir.Name, ".azure") && EqAny(bn, azureNames)) return w.E() ? Likely("azure-tokens", w.Get()) : none;
            // 13 gcloud-credentials
            if (EqCI(bn, "application_default_credentials.json")) return w.E() ? Likely("gcloud-credentials", w.Get()) : none;
            // 15 kubeconfig
            if (EqCI(bn, "kubeconfig") || EqCI(bn, "kubeconfig.yaml") || EqCI(bn, "kubeconfig.yml") || EndsCI(name, ".kubeconfig"))
                return w.E() ? Likely("kubeconfig", w.Get()) : none;
            // 16 docker-config
            if (EqCI(bn, "config.json") && EqCI(dir.Name, ".docker")) return w.E() ? Likely("docker-config", w.Get()) : none;
            // 18 pypi-rc
            if (EqCI(bn, ".pypirc")) return w.E() ? Likely("pypi-rc", w.Get()) : none;
            // 21 terraform-credentials
            if (EqCI(bn, "credentials.tfrc.json")) return w.E() ? Likely("terraform-credentials", w.Get()) : none;
            // 22 tfstate
            int tf = EndsCI(name, ".tfstate") ? name.Length - 8 : EndsCI(name, ".tfstate.backup") ? name.Length - 15 : -1;
            if (tf >= 0)
            {
                if (w.Get() == Place.Temp || !Within(size, online, ProtectConstants.TfstateMinBytes, long.MaxValue)) return none;
                t.Clear();
                t.Add(name, 0, tf, SegStem);
                return t.HasAny(MaskStem, tfstateGuard) ? none : Likely("tfstate", w.Get());
            }
            // 23 dotenv (amendment A1: a repository .env is found, and listed in its own group)
            if (IsDotenvName(name, ref t))
            {
                if ((w.E() || w.Get() == Place.Repository) && Within(size, online, 1, ProtectConstants.DotenvMaxBytes))
                    return Likely("dotenv", w.Get());
                return none;
            }
            // 24 pgp-secret
            if (EqCI(bn, "secring.gpg") || EndsCI(name, ".asc") || EndsCI(name, ".gpg") || EndsCI(name, ".pgp"))
            {
                if (!w.E() || EndsCI(name, ".gpg.key") || EndsCI(name, ".pub.asc")) return none;
                StemTokens(name, ref t);
                if (t.HasAny(MaskStem, pgpPublicWords)) return none;
                if (EqCI(bn, "secring.gpg") || t.HasAny(MaskStem, pgpSecretWords)) return Likely("pgp-secret", w.Get());
                return none;
            }
            // 25 pgpass
            if (EqCI(bn, ".pgpass")) return w.E() ? Likely("pgpass", w.Get()) : none;
            // 26 crypto-wallet
            if (EqCI(bn, "wallet.dat"))
                return w.E() && Within(size, online, ProtectConstants.WalletMinBytes, ProtectConstants.WalletMaxBytes) ? Likely("crypto-wallet", w.Get()) : none;
            // 27 eth-keystore
            if (IsEthKeystoreName(name)) return Confirmed("eth-keystore", w.Get());
            // 28 electrum-wallet
            if (EqCI(bn, "default_wallet")) return w.E() ? Likely("electrum-wallet", w.Get()) : none;
            // 29 recovery-codes
            if (EqCI(bn, "github-recovery-codes.txt") || EqCI(bn, "gitlab-recovery-codes.txt"))
                return w.Get() != Place.Repository ? Confirmed("recovery-codes", w.Get()) : none;
            // 30 emergency-kit
            if (StartsCI(name, "1Password Emergency Kit") && EndsCI(name, ".pdf"))
                return w.Get() != Place.Repository ? Confirmed("emergency-kit", w.Get()) : none;
            // 31 publish-settings
            if (EndsCI(name, ".publishsettings")) return w.Get() != Place.Temp ? Likely("publish-settings", w.Get()) : none;
            // 32 htpasswd
            if (EqCI(bn, ".htpasswd")) return w.Get() != Place.Temp ? Likely("htpasswd", w.Get()) : none;
            return none;
        }

        static bool IsNamedExport(string name, string bn)
        {
            foreach (string b in exportBrowsers)
                if (bn.Length == b.Length + 14 && StartsCI(bn, b) && EndsCI(bn, " Passwords.csv")) return true;
            if (StartsCI(name, "bitwarden_export_") && (EndsCI(name, ".csv") || EndsCI(name, ".json"))) return true;
            if ((StartsCI(name, "lastpass_export") || StartsCI(name, "lastpass_vault_export")) && EndsCI(name, ".csv")) return true;
            return EndsCI(name, ".1pux") || EndsCI(name, ".1pif");
        }

        // Outside a pem tool home: no public token unless a strong one, and then a strong token, or a weak
        // signal together with a typical key size.
        static bool PemElsewhere(string name, long size, bool online, DirState dir, ref Toks t)
        {
            bool strong = StrongKeySignal(name, ref t);  // leaves the stem tokens in t
            if (strong) return true;
            if (t.HasAny(MaskStem, ProtectConstants.PublicKeyTokens)) return false;
            bool weak = t.HasAny(MaskStem, ProtectConstants.WeakKeyTokens) || IsKeyFolder(dir.Name);
            if (!weak || online) return false;
            return (size >= ProtectConstants.KeyWindowEcMin && size <= ProtectConstants.KeyWindowEcMax) ||
                   (size >= ProtectConstants.KeyWindowRsa2048Min && size <= ProtectConstants.KeyWindowRsa2048Max) ||
                   (size >= ProtectConstants.KeyWindowRsa4096Min && size <= ProtectConstants.KeyWindowRsa4096Max);
        }

        static bool StrongKeySignal(string name, ref Toks t)
        {
            int stemEnd = StemEnd(name);
            StemTokens(name, ref t);
            if (t.HasAny(MaskStem, ProtectConstants.StrongKeyTokens)) return true;
            if (stemEnd >= 4 && (EndsAtCI(name, stemEnd, "-key") || EndsAtCI(name, stemEnd, "_key"))) return true;
            return StartsCI(name, "id_");
        }

        static bool IsKeyFolder(string folder)
        {
            if (folder == null) return false;
            foreach (string k in ProtectConstants.KeyFolders)
            {
                if (k.StartsWith("*", StringComparison.Ordinal))
                {
                    if (folder.Length > k.Length - 1 && EndsCI(folder, k.Substring(1))) return true;
                }
                else if (EqCI(folder, k)) return true;
            }
            return false;
        }

        static bool IsDotenvName(string name, ref Toks t)
        {
            if (EqCI(name, ".env")) return true;
            if (name.Length < 5) return false;
            foreach (string end in envNeverEnds)
                if (EndsCI(name, end)) return false;
            if (StartsCI(name, ".env."))
            {
                t.Clear();
                t.Add(name, 5, name.Length, SegOther);
                int f = t.FirstRaw(SegOther);
                return f >= 0 && !t.EqAny(f, envTemplateWords);
            }
            if (EndsCI(name, ".env"))
            {
                t.Clear();
                t.Add(name, 0, name.Length - 4, SegStem);
                return t.HasAny(MaskStem, envSecretWords);
            }
            return false;
        }

        // ---- Documents ------------------------------------------------------------------------------------

        static NameMatch Document(string name, long size, bool online, byte hint, DirState dir, ref RepoQuery repo, ref Toks t)
        {
            NameMatch none = new NameMatch();
            if (hint != HintDoc && hint != HintTaxFile) return none;
            if (hint == HintDoc)
            {
                if (IsImage(name)) { if (online || size < ProtectConstants.DocImageMinBytes) return none; }
                else if (size <= 0 && !online) return none;
                if (!DocPrefilter(name)) return none;
            }
            t.Clear();
            t.Add(name, 0, StemEnd(name), SegStem);
            if (dir.Name != null) t.Add(dir.Name, 0, dir.Name.Length, SegDir);
            if (dir.ParentName != null) t.Add(dir.ParentName, 0, dir.ParentName.Length, SegParent);
            if (t.HasAny(MaskStem, ProtectConstants.DocGuardTokens)) return none;

            string id = hint == HintTaxFile ? "doc-tax-file" : DocumentRow(ref t);
            if (id == null || repo.Get()) return none;  // never in a repository
            Place place;
            if ((dir.Flags & DirFlags.MailAttach) != 0) place = Place.Other;
            else if ((dir.DocsDepth > 0 || (dir.Marks & PlaceMarks.Pictures) != 0) && (dir.Marks & PlaceMarks.Sync) == 0) place = Place.UsualPlace;
            else place = PlaceOf(dir, ref repo, 0);
            return Hit(id, id == "doc-tax-file" ? FindingTier.Confirmed : FindingTier.Likely, place);
        }

        static string DocumentRow(ref Toks t)
        {
            // doc-tax
            bool tax = t.RawStartsAny(SegStem, taxStarts) || t.Has(MaskStem, "turbotax") ||
                       (t.HasAny(MaskStem, taxWords) && t.HasAny(MaskAll, taxCo));
            if (!tax && !IsCameraName(ref t))
            {
                bool year = t.HasYear(SegStem);
                if (t.Has(MaskStem, "1099") && (year || t.HasAny(MaskAll, co1099))) tax = true;
                else if ((t.HasRaw(SegStem, "w2") || t.Adjacent(SegStem, "w", "2")) && (year || t.HasAny(MaskAll, coW2))) tax = true;
                else if ((t.HasRaw(SegStem, "t4") || t.HasRaw(SegStem, "t4a") || t.Adjacent(SegStem, "t", "4")) &&
                         (year || t.HasAny(MaskAll, coT4))) tax = true;
                else if (t.Has(MaskStem, "1040") && (year || t.HasAny(MaskAll, co1040))) tax = true;
            }
            if (tax) return "doc-tax";

            // doc-pay
            if (t.RawStartsAny(SegStem, payStarts) ||
                t.AdjacentAny(SegStem, "pay", slipWords) || t.AdjacentAny(SegStem, "pay", stubWords) ||
                t.AdjacentAny(SegStem, "salary", slipWords) || t.AdjacentAny(SegStem, "pay", statementWords) ||
                t.Adjacent(SegStem, "pay", "advice"))
                return "doc-pay";

            // doc-statement
            if (t.HasAny(MaskStem, statementWords) && t.HasAny(MaskAll, financialCo))
                return t.HasAny(MaskStem, payOrSalary) ? "doc-pay" : "doc-statement";

            // doc-id
            if (t.RawContains(SegStem, "passport") || t.Has(MaskStem, "aadhaar") || t.Has(MaskStem, "idcard") ||
                t.AdjacentAny2(SegStem, driverWords, licenseWords) || t.Adjacent(SegStem, "id", "card") ||
                t.Adjacent(SegStem, "birth", "certificate") || t.Adjacent(SegStem, "social", "security") ||
                t.Adjacent(SegStem, "green", "card") || t.Adjacent(SegStem, "pan", "card"))
                return "doc-id";
            return null;
        }

        // The numeric keywords (1099, 1040, w2, t4) are ignored in camera file names.
        static bool IsCameraName(ref Toks t)
        {
            int f = t.FirstRaw(SegStem);
            if (f < 0) return true;
            if (t.EqAny(f, cameraFirst)) return true;
            if (f + 1 < t.Count && t.IsSub(f + 1) && t.EqAny(f + 1, cameraFirst)) return true;  // IMG20230101 -> img
            return t.StemHasNoLetters(SegStem);
        }

        static bool IsImage(string name)
        {
            foreach (string e in imageExts)
                if (EndsCI(name, e)) return true;
            return false;
        }

        // Whether a file under a "Scanned Documents" folder makes the folder a finding.
        internal static bool CountsForScans(string name, long size, bool online)
        {
            if (IsImage(name)) return !online && size >= ProtectConstants.DocImageMinBytes;
            return size > 0 || online;
        }

        // ---- Folder findings ------------------------------------------------------------------------------

        public static NameMatch ClassifyFolder(string name, DirState self, bool inRepo, ProtectContext ctx)
        {
            NameMatch none = new NameMatch();
            if (name == null || !(EndsCI(name, ".opvault") || EndsCI(name, ".agilekeychain"))) return none;
            if ((self.Flags & (DirFlags.Skip | DirFlags.Fixture | DirFlags.ToolCache | DirFlags.DotOther)) != 0) return none;
            if (self.Tool != ToolHome.None) return none;
            if ((self.Flags & DirFlags.AppData) != 0 && (self.Flags & DirFlags.Examined) == 0) return none;
            return Confirmed("password-vault", InDocsUnsynced(self) ? Place.UsualPlace : PlaceOf(self, inRepo, 1));
        }

        public static NameMatch ClassifyScansFolder(DirState self, bool inRepo, ProtectContext ctx)
        {
            NameMatch none = new NameMatch();
            if (!self.IsScansFolder || inRepo) return none;
            if ((self.Flags & (DirFlags.Skip | DirFlags.Fixture | DirFlags.ToolCache | DirFlags.DotOther | DirFlags.VaultFolder)) != 0) return none;
            if (self.Tool != ToolHome.None) return none;
            bool mail = (self.Flags & DirFlags.MailAttach) != 0;
            if ((self.Flags & DirFlags.AppData) != 0 && (self.Flags & DirFlags.Examined) == 0 && !mail) return none;
            Place place;
            if (mail) place = Place.Other;
            else if ((self.DocsDepth > 0 || (self.Marks & PlaceMarks.Pictures) != 0) && (self.Marks & PlaceMarks.Sync) == 0) place = Place.UsualPlace;
            else place = PlaceOf(self, inRepo, 1);
            return Likely("doc-scans-folder", place);
        }

        // ---- Corpus entry point ---------------------------------------------------------------------------

        // Classifies one path without a tree: folds the parent's segments with MarksOfPath, takes the repository
        // from ctx.RepoRoots, and runs the same gate and core as Analyze.
        public static Finding MatchPath(ProtectContext ctx, string fullPath, long size, bool onlineOnly,
            bool isFolder, IList<string> siblings)
        {
            if (string.IsNullOrEmpty(fullPath)) return null;
            string p = fullPath.Replace('/', '\\');
            if (p.Length > 3) p = p.TrimEnd('\\');
            int cut = p.LastIndexOf('\\');
            if (cut <= 0 || cut == p.Length - 1) return null;
            string parentPath = cut == 2 && p[1] == ':' ? p.Substring(0, 3) : p.Substring(0, cut);
            string name = p.Substring(cut + 1);
            DirState dir = RootState(parentPath, ctx);
            bool inRepo = ctx.RootInRepo || ctx.UnderRepoRoot(CheapNorm(parentPath));
            NameMatch m;
            if (isFolder)
            {
                DirState self = Enter(dir, name, ctx.MarksOfPath(CheapNorm(p)), ctx);
                if ((self.Flags & DirFlags.Skip) != 0) return null;
                m = self.IsScansFolder ? ClassifyScansFolder(self, inRepo, ctx) : ClassifyFolder(name, self, inRepo, ctx);
            }
            else
            {
                byte hint = ExtHint(Categories.KeyFor(name));
                if ((dir.Flags & DirFlags.Skip) != 0 || !IsCandidate(name, hint, dir)) return null;
                IList<string> sib = dir.Tool == ToolHome.Ssh && dir.ToolDepth == 1 ? siblings : null;
                m = ClassifyFile(name, size, onlineOnly, hint, dir, inRepo, sib, ctx, new char[BufferSize]);
            }
            if (m.PatternId == null) return null;
            return new Finding(m.PatternId, m.Tier, p, 0, 0, m.Place);
        }

        // ---- Helpers for the UI ---------------------------------------------------------------------------

        public static bool IsMailAttachment(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string[] seg = path.Replace('/', '\\').Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i + 6 < seg.Length; i++)
            {
                if (EqCI(seg[i], "Packages") && StartsCI(seg[i + 1], "microsoft.windowscommunicationsapps_") &&
                    EqCI(seg[i + 2], "LocalState") && EqCI(seg[i + 3], "Files") && EqCI(seg[i + 6], "Attachments"))
                    return true;
            }
            return false;
        }

        // The nearest folder at or above n that holds a ".git" entry, or null. For the UI only.
        public static string RepoRootOf(Node n)
        {
            if (n == null) return null;
            DirNode d = n as DirNode;
            if (d == null) d = n.Parent;
            for (; d != null; d = d.Parent)
                if (HasGitChild(d)) return d.FullPath;
            return null;
        }

        internal static bool HasGitChild(DirNode d)
        {
            Node[] kids = d.Children;
            for (int i = 0; i < kids.Length; i++)
            {
                string n = kids[i].Name;
                if (n != null && n.Length == 4 && n[0] == '.' && EqCI(n, ".git")) return true;
            }
            return false;
        }

        // ---- Names ----------------------------------------------------------------------------------------

        // The name with one trailing copy suffix removed from the stem: " (n)", "(n)", " - Copy" or " - Copy (n)".
        // Allocates only when the stem ends in ")" or "y".
        public static string BaseName(string name)
        {
            if (string.IsNullOrEmpty(name)) return name;
            int end = StemEndForCopy(name);
            if (end <= 0) return name;
            char last = name[end - 1];
            if (last != ')' && last != 'y' && last != 'Y') return name;
            int cut = CopySuffixStart(name, end);
            if (cut <= 0) return name;
            return name.Substring(0, cut) + name.Substring(end);
        }

        static int StemEndForCopy(string name)
        {
            int dot = name.LastIndexOf('.');
            return dot > 0 ? dot : name.Length;
        }

        static int CopySuffixStart(string s, int end)
        {
            int cut;
            if (s[end - 1] == ')')
            {
                int open = s.LastIndexOf('(', end - 1);
                if (open < 0) return -1;
                int digits = end - 1 - open - 1;
                if (digits < 1 || digits > 3) return -1;
                for (int i = open + 1; i < end - 1; i++)
                    if (s[i] < '0' || s[i] > '9') return -1;
                cut = open;
                if (cut > 0 && s[cut - 1] == ' ') cut--;
                if (EndsAtCI(s, cut, " - Copy")) cut -= 7;
                return cut;
            }
            if (EndsAtCI(s, end, " - Copy")) return end - 7;
            return -1;
        }

        static int StemEnd(string name)
        {
            int dot = name.LastIndexOf('.');
            return dot > 0 ? dot : name.Length;
        }

        static void StemTokens(string name, ref Toks t)
        {
            t.Clear();
            t.Add(name, 0, StemEnd(name), SegStem);
        }

        static bool IsSshKeyName(string name)
        {
            return EqAny(name, sshKeyNames);
        }

        static bool IsSshNonKey(string name)
        {
            if (EndsCI(name, ".pub") || EndsCI(name, ".sock") || StartsCI(name, "agent.")) return true;
            return EqAny(name, sshNonKeyNames);
        }

        static bool HasSibling(IList<string> siblings, string want)
        {
            for (int i = 0; i < siblings.Count; i++)
                if (EqCI(siblings[i], want)) return true;
            return false;
        }

        // UTC--YYYY-MM-DDTHH-MM-SS[.fraction]Z--<40 hex>[.json], checked character by character.
        static bool IsEthKeystoreName(string s)
        {
            if (!s.StartsWith("UTC--", StringComparison.Ordinal)) return false;
            int i = 5;
            if (!Digits(s, ref i, 4) || !Ch(s, ref i, '-') || !Digits(s, ref i, 2) || !Ch(s, ref i, '-') || !Digits(s, ref i, 2) ||
                !Ch(s, ref i, 'T') || !Digits(s, ref i, 2) || !Ch(s, ref i, '-') || !Digits(s, ref i, 2) || !Ch(s, ref i, '-') ||
                !Digits(s, ref i, 2)) return false;
            if (i < s.Length && s[i] == '.')
            {
                i++;
                int start = i;
                while (i < s.Length && s[i] >= '0' && s[i] <= '9') i++;
                if (i == start) return false;
            }
            if (!Ch(s, ref i, 'Z') || !Ch(s, ref i, '-') || !Ch(s, ref i, '-')) return false;
            for (int k = 0; k < 40; k++, i++)
            {
                if (i >= s.Length) return false;
                char c = s[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
            }
            if (i == s.Length) return true;
            return i + 5 == s.Length && string.Compare(s, i, ".json", 0, 5, StringComparison.OrdinalIgnoreCase) == 0;
        }

        static bool Digits(string s, ref int i, int n)
        {
            for (int k = 0; k < n; k++, i++)
                if (i >= s.Length || s[i] < '0' || s[i] > '9') return false;
            return true;
        }

        static bool Ch(string s, ref int i, char c)
        {
            if (i >= s.Length || s[i] != c) return false;
            i++;
            return true;
        }

        internal static bool EqCI(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int k = a.Length - 1; k >= 0; k--)
                if (!SameCI(a[k], b[k])) return false;
            return true;
        }

        static bool EqAny(string a, string[] list)
        {
            foreach (string b in list)
                if (EqCI(a, b)) return true;
            return false;
        }

        // These run dozens of times per candidate, so they compare chars directly instead of going through
        // the framework's culture-aware string code. The result is the same as StringComparison.OrdinalIgnoreCase.
        static bool StartsCI(string s, string prefix)
        {
            if (s == null || s.Length < prefix.Length) return false;
            for (int k = 0; k < prefix.Length; k++)
                if (!SameCI(s[k], prefix[k])) return false;
            return true;
        }

        static bool EndsCI(string s, string suffix)
        {
            return s != null && EndsAtCI(s, s.Length, suffix);
        }

        // Whether s[0..end) ends with suffix, ignoring case. The last char is compared first.
        static bool EndsAtCI(string s, int end, string suffix)
        {
            int start = end - suffix.Length;
            if (start < 0) return false;
            for (int k = suffix.Length - 1; k >= 0; k--)
                if (!SameCI(s[start + k], suffix[k])) return false;
            return true;
        }

        static bool SameCI(char a, char b)
        {
            if (a == b) return true;
            if (a < 0x80 && b < 0x80)
            {
                int la = a | 0x20;
                return la == (b | 0x20) && la >= 'a' && la <= 'z';
            }
            return char.ToUpperInvariant(a) == char.ToUpperInvariant(b);
        }

        // ---- Tokens ---------------------------------------------------------------------------------------

        // Stem tokens over a caller-owned buffer, with no allocation. Each raw token (a letter-and-digit run, split at
        // camel boundaries) is followed by its sub-tokens (split at letter/digit boundaries) when it has more than one.
        struct Toks
        {
            readonly char[] b;
            int text;
            public int Count;

            public Toks(char[] buffer)
            {
                b = buffer != null && buffer.Length >= BufferSize ? buffer : new char[BufferSize];
                text = 0;
                Count = 0;
            }

            public void Clear()
            {
                text = 0;
                Count = 0;
            }

            int Start(int i) { return b[TextCap + 4 * i]; }
            int Len(int i) { return b[TextCap + 4 * i + 1]; }
            int Kind(int i) { return b[TextCap + 4 * i + 2]; }
            int Seg(int i) { return b[TextCap + 4 * i + 3]; }
            public bool IsSub(int i) { return (Kind(i) & KindSub) != 0; }

            public void Add(string s, int start, int end, int seg)
            {
                int i = start;
                while (i < end)
                {
                    while (i < end && !IsAlnum(s[i])) i++;
                    int run = i;
                    while (i < end && IsAlnum(s[i])) i++;
                    if (i == run) break;
                    int piece = run;
                    for (int k = run + 1; k < i; k++)
                    {
                        char p = s[k - 1], c = s[k];
                        bool split = (IsLow(p) && IsUp(c)) ||
                                     (IsUp(p) && IsUp(c) && k + 1 < i && IsLow(s[k + 1]));
                        if (split)
                        {
                            Raw(s, piece, k, seg);
                            piece = k;
                        }
                    }
                    Raw(s, piece, i, seg);
                }
            }

            void Raw(string s, int a, int z, int seg)
            {
                int len = z - a;
                if (len <= 0 || text + len > TextCap || Count >= MaxTokens) return;
                int at = text;
                bool digits = true, mixed = false;
                for (int k = 0; k < len; k++)
                {
                    char c = s[a + k];
                    b[at + k] = c < 0x80 ? (c >= 'A' && c <= 'Z' ? (char)(c + 32) : c) : char.ToLowerInvariant(c);
                    bool d = c >= '0' && c <= '9';
                    if (!d) digits = false;
                    if (k > 0 && d != (s[a + k - 1] >= '0' && s[a + k - 1] <= '9')) mixed = true;
                }
                text += len;
                Record(at, len, KindRaw | (digits ? KindDigits : 0), seg);
                if (!mixed) return;
                int piece = 0;
                for (int k = 1; k <= len; k++)
                {
                    if (k == len || IsDigit(b[at + k]) != IsDigit(b[at + k - 1]))
                    {
                        bool dd = IsDigit(b[at + piece]);
                        Record(at + piece, k - piece, KindSub | (dd ? KindDigits : 0), seg);
                        piece = k;
                    }
                }
            }

            static bool IsDigit(char c) { return c >= '0' && c <= '9'; }

            // ASCII first; the framework's Unicode tests only for other chars.
            static bool IsAlnum(char c)
            {
                if (c < 0x80) return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
                return char.IsLetterOrDigit(c);
            }

            static bool IsLow(char c) { return c < 0x80 ? c >= 'a' && c <= 'z' : char.IsLower(c); }

            static bool IsUp(char c) { return c < 0x80 ? c >= 'A' && c <= 'Z' : char.IsUpper(c); }

            void Record(int start, int len, int kind, int seg)
            {
                if (Count >= MaxTokens) return;
                int r = TextCap + 4 * Count;
                b[r] = (char)start;
                b[r + 1] = (char)len;
                b[r + 2] = (char)kind;
                b[r + 3] = (char)seg;
                Count++;
            }

            public bool Eq(int i, string w)
            {
                int len = Len(i);
                if (len != w.Length) return false;
                int s = Start(i);
                for (int k = 0; k < len; k++)
                    if (b[s + k] != w[k]) return false;
                return true;
            }

            bool StartsWith(int i, string w)
            {
                int len = Len(i);
                if (len < w.Length) return false;
                int s = Start(i);
                for (int k = 0; k < w.Length; k++)
                    if (b[s + k] != w[k]) return false;
                return true;
            }

            bool ContainsWord(int i, string w)
            {
                int len = Len(i), s = Start(i);
                for (int a = 0; a + w.Length <= len; a++)
                {
                    int k = 0;
                    while (k < w.Length && b[s + a + k] == w[k]) k++;
                    if (k == w.Length) return true;
                }
                return false;
            }

            public bool EqAny(int i, string[] ws)
            {
                foreach (string w in ws)
                    if (Eq(i, w)) return true;
                return false;
            }

            bool InMask(int i, int mask) { return (mask & (1 << Seg(i))) != 0; }

            public bool Has(int mask, string w)
            {
                for (int i = 0; i < Count; i++)
                    if (InMask(i, mask) && Eq(i, w)) return true;
                return false;
            }

            public bool HasAny(int mask, string[] ws)
            {
                for (int i = 0; i < Count; i++)
                    if (InMask(i, mask) && EqAny(i, ws)) return true;
                return false;
            }

            public bool HasRaw(int seg, string w)
            {
                for (int i = 0; i < Count; i++)
                    if (Seg(i) == seg && (Kind(i) & KindRaw) != 0 && Eq(i, w)) return true;
                return false;
            }

            public bool RawStartsAny(int seg, string[] ws)
            {
                for (int i = 0; i < Count; i++)
                {
                    if (Seg(i) != seg || (Kind(i) & KindRaw) == 0) continue;
                    foreach (string w in ws)
                        if (StartsWith(i, w)) return true;
                }
                return false;
            }

            public bool RawContains(int seg, string w)
            {
                for (int i = 0; i < Count; i++)
                    if (Seg(i) == seg && (Kind(i) & KindRaw) != 0 && ContainsWord(i, w)) return true;
                return false;
            }

            public int FirstRaw(int seg)
            {
                for (int i = 0; i < Count; i++)
                    if (Seg(i) == seg && (Kind(i) & KindRaw) != 0) return i;
                return -1;
            }

            int NextRaw(int i, int seg)
            {
                for (int k = i + 1; k < Count; k++)
                {
                    if (Seg(k) != seg) return -1;
                    if ((Kind(k) & KindRaw) != 0) return k;
                }
                return -1;
            }

            // Two raw tokens next to each other, in this order.
            public bool Adjacent(int seg, string a, string z)
            {
                for (int i = FirstRaw(seg); i >= 0; i = NextRaw(i, seg))
                {
                    if (!Eq(i, a)) continue;
                    int n = NextRaw(i, seg);
                    if (n >= 0 && Eq(n, z)) return true;
                }
                return false;
            }

            public bool AdjacentAny(int seg, string a, string[] zs)
            {
                foreach (string z in zs)
                    if (Adjacent(seg, a, z)) return true;
                return false;
            }

            public bool AdjacentAny2(int seg, string[] firsts, string[] zs)
            {
                foreach (string a in firsts)
                    if (AdjacentAny(seg, a, zs)) return true;
                return false;
            }

            // A year from 1990 to 2039, as a token or a sub-token of this segment.
            public bool HasYear(int seg)
            {
                for (int i = 0; i < Count; i++)
                {
                    if (Seg(i) != seg || (Kind(i) & KindDigits) == 0 || Len(i) != 4) continue;
                    int s = Start(i);
                    int y = (b[s] - '0') * 1000 + (b[s + 1] - '0') * 100 + (b[s + 2] - '0') * 10 + (b[s + 3] - '0');
                    if (y >= 1990 && y <= 2039) return true;
                }
                return false;
            }

            public bool StemHasNoLetters(int seg)
            {
                for (int i = 0; i < Count; i++)
                    if (Seg(i) == seg && (Kind(i) & KindDigits) == 0) return false;
                return true;
            }
        }
    }

    // A case-insensitive comparer for the folder-name table, which Enter asks once per folder. Its hash reads
    // only the length and three chars, so a lookup costs a few compares; Equals is OrdinalIgnoreCase.
    sealed class QuickNoCase : IEqualityComparer<string>
    {
        public bool Equals(string a, string b)
        {
            return ProtectNames.EqCI(a, b);
        }

        public int GetHashCode(string s)
        {
            int n = s.Length;
            if (n == 0) return 0;
            return n * 7919 ^ Low(s[0]) * 31 ^ Low(s[n / 2]) * 131 ^ Low(s[n - 1]) * 1031;
        }

        static int Low(char c)
        {
            if (c >= 0x80) c = char.ToUpperInvariant(c);
            return c < 0x80 ? c | 0x20 : c;
        }
    }

    // One per Analyze call; never shared between threads.
    sealed class ProtectScan
    {
        readonly ProtectContext ctx;
        readonly Dictionary<DirNode, PlaceMarks> marks = new Dictionary<DirNode, PlaceMarks>();
        DirNode[] markParents;  // the parents of the marked folders: only their children ask the map
        readonly Dictionary<DirNode, bool> repoMemo = new Dictionary<DirNode, bool>();
        readonly HashSet<DirNode> repoNodes = new HashSet<DirNode>();
        readonly bool rootInRepo;  // ctx.RootInRepo, or the scan root at or below one of ctx.RepoRoots
        readonly char[] buffer = new char[ProtectNames.BufferSize];
        readonly List<Finding> found = new List<Finding>();
        readonly List<Node> foundNodes = new List<Node>();
        readonly List<DirNode> scansNodes = new List<DirNode>();
        readonly List<NameMatch> scansMatches = new List<NameMatch>();
        readonly List<bool> scansHit = new List<bool>();
        DirNode siblingsOf;
        List<string> siblingNames;

        public DirState RootState;

        public ProtectScan(ScanResult r, ProtectContext ctx)
        {
            this.ctx = ctx;
            foreach (KeyValuePair<string, PlaceMarks> place in ctx.AllPlaces())
            {
                DirNode d = r.FindNode(place.Key) as DirNode;
                if (d == null || d == r.Root) continue;
                PlaceMarks m;
                marks.TryGetValue(d, out m);
                marks[d] = m | place.Value;
            }
            var parents = new List<DirNode>();
            foreach (DirNode d in marks.Keys)
                if (d.Parent != null && !parents.Contains(d.Parent)) parents.Add(d.Parent);
            markParents = parents.ToArray();
            rootInRepo = ctx.RootInRepo || ctx.UnderRepoRoot(ProtectNames.CheapNorm(r.Root.FullPath));
            foreach (string repoRoot in ctx.RepoRoots)
            {
                DirNode d = r.FindNode(repoRoot) as DirNode;
                if (d != null) repoNodes.Add(d);
            }
            RootState = ProtectNames.RootState(r.Root.Name, ctx);
            if (RootState.IsScansFolder && (RootState.Flags & DirFlags.Skip) == 0) Register(ref RootState, r.Root);
        }

        public DirState Enter(DirState parent, DirNode dir)
        {
            PlaceMarks m = PlaceMarks.None;
            if (marks.Count > 0 && UnderMarkParent(dir)) marks.TryGetValue(dir, out m);
            DirState s = ProtectNames.Enter(parent, dir.Name, m, ctx);
            if ((s.Flags & DirFlags.Skip) != 0) return s;
            if ((s.Flags & DirFlags.VaultFolder) != 0 && (parent.Flags & DirFlags.VaultFolder) == 0)
            {
                NameMatch v = ProtectNames.ClassifyFolder(dir.Name, s, InRepo(dir), ctx);
                if (v.PatternId != null) Add(v, dir);
            }
            if (s.IsScansFolder) Register(ref s, dir);
            return s;
        }

        bool UnderMarkParent(DirNode dir)
        {
            DirNode p = dir.Parent;
            for (int i = 0; i < markParents.Length; i++)
                if (markParents[i] == p) return true;
            return false;
        }

        void Register(ref DirState s, DirNode dir)
        {
            NameMatch sm = ProtectNames.ClassifyScansFolder(s, InRepo(dir), ctx);
            if (sm.PatternId == null) return;
            scansNodes.Add(dir);
            scansMatches.Add(sm);
            scansHit.Add(false);
            s.ScansSlot = scansNodes.Count;
        }

        public void File(FileNode f, byte hint, DirState dir)
        {
            bool online = (f.Flags & FileFlags.OnlineOnly) != 0;
            if (dir.ScansSlot != 0 && hint == ProtectNames.HintDoc && (dir.Flags & (DirFlags.Skip | DirFlags.Fixture)) == 0 &&
                !scansHit[dir.ScansSlot - 1] && ProtectNames.CountsForScans(f.Name, f.Size, online))
                scansHit[dir.ScansSlot - 1] = true;
            IList<string> sib = null;
            if (dir.Tool == ToolHome.Ssh && dir.ToolDepth == 1) sib = Siblings(f.Parent);
            RepoQuery repo = new RepoQuery();
            repo.Scan = this;
            repo.Dir = f.Parent;
            NameMatch m = ProtectNames.ClassifyFile(f.Name, f.Size, online, hint, dir, ref repo, sib, buffer);
            if (m.PatternId != null) Add(m, f);
        }

        void Add(NameMatch m, Node n)
        {
            found.Add(new Finding(m.PatternId, m.Tier, n.FullPath, 0, 0, m.Place));
            foundNodes.Add(n);
        }

        IList<string> Siblings(DirNode parent)
        {
            if (parent == null) return null;
            if (siblingsOf != parent)
            {
                siblingsOf = parent;
                siblingNames = new List<string>(parent.Children.Length);
                foreach (Node c in parent.Children) siblingNames.Add(c.Name);
            }
            return siblingNames;
        }

        // Whether d is inside a git repository: a ".git" child at d or above, or above the root ctx.RootInRepo.
        // The tests' ctx.RepoRoots count like a ".git" child: their nodes are looked up once in the constructor.
        public bool InRepo(DirNode d)
        {
            if (d == null) return rootInRepo;
            bool v;
            if (repoMemo.TryGetValue(d, out v)) return v;
            bool result = rootInRepo;
            DirNode stop = null;
            for (DirNode n = d; n != null; n = n.Parent)
            {
                if (repoMemo.TryGetValue(n, out v)) { result = v; stop = n; break; }
                if (ProtectNames.HasGitChild(n) || (repoNodes.Count > 0 && repoNodes.Contains(n))) { result = true; stop = n; break; }
            }
            for (DirNode w = d; w != null; w = w.Parent)
            {
                repoMemo[w] = result;
                if (w == stop) break;
            }
            return result;
        }

        public void Finish(List<Finding> findings, List<Node> nodes)
        {
            findings.AddRange(found);
            nodes.AddRange(foundNodes);
            for (int i = 0; i < scansNodes.Count; i++)
            {
                if (!scansHit[i]) continue;
                NameMatch m = scansMatches[i];
                findings.Add(new Finding(m.PatternId, m.Tier, scansNodes[i].FullPath, 0, 0, m.Place));
                nodes.Add(scansNodes[i]);
            }
        }
    }
}

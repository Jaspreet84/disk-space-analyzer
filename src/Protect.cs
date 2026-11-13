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

    // What a pattern looks for, in words. The explanation screen and the tests are built from this table; the
    // by-name matcher is in ProtectNames.cs. Tier is the highest tier the row can emit.
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

    // Where a by-name row looks, in words, for the explanation screen. One per Patterns row, in the same order.
    sealed class NameRuleInfo
    {
        public readonly string Id, Usual, Elsewhere;

        public NameRuleInfo(string id, string usual, string elsewhere)
        {
            Id = id;
            Usual = usual;
            Elsewhere = elsewhere;
        }
    }

    // The numbers and lists the scanner uses. The explanation screen is generated from these, so what the
    // app says it reads and what it reads cannot drift apart.
    static class ProtectConstants
    {
        // The registry keys ProtectContext reads (read-only) to find the folders your sync apps keep.
        public const string SyncRootManagerKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager";
        public const string OneDriveAccountsKey = @"Software\Microsoft\OneDrive\Accounts";

        public const long MaxContentBytes = 1L << 20;
        public const int BinaryProbeBytes = 8 << 10;
        public const int ContentWorkers = 4;

        // Size bounds of the by-name rows. An online-only file (size 0 here) passes them, except the image minimum
        // for documents and the key-size windows, which then give no signal.
        public const long SshKeyMinBytes = 100, SshKeyMaxBytes = 16 << 10;
        public const long PpkMaxBytes = 64 << 10;
        public const long PemMaxBytes = 16 << 10;
        public const long Pkcs12MinBytes = 256, Pkcs12MaxBytes = 64 << 10;
        public const long KeystoreMaxBytes = 1 << 20;
        public const long TfstateMinBytes = 100;
        public const long DotenvMaxBytes = 64 << 10;
        public const long WalletMinBytes = 4 << 10, WalletMaxBytes = 2L << 30;
        public const long DocImageMinBytes = 20 << 10;
        public const long KeyWindowEcMin = 200, KeyWindowEcMax = 400;
        public const long KeyWindowRsa2048Min = 1600, KeyWindowRsa2048Max = 1800;
        public const long KeyWindowRsa4096Min = 3150, KeyWindowRsa4096Max = 3350;

        // Folders whose contents Protect never reports: system files, and package caches and tool folders full of
        // vendors' sample keys. Shared with the content scan. Any folder whose name starts with "$" is skipped too.
        public static readonly string[] SkipFolders =
        {
            "Windows", "Program Files", "Program Files (x86)", "ProgramData", "WinSxS", "$Recycle.Bin",
            "node_modules", ".nuget", ".pnpm-store", "pnpm", "pip", "Yarn", ".gradle", ".m2", ".cargo", "go\\pkg",
            "ms-playwright", "electron", "node-gyp", ".cache",
            ".git", ".svn", ".hg", ".terraform", "site-packages", "dist-packages", ".venv", "venv", "__pycache__",
            "bower_components", ".yarn", ".npm", ".rustup", ".dotnet", ".conda", ".tox", "System Volume Information",
            "$WinREAgent", "vendor\\bundle"
        };

        // Test and sample folders: no by-name row fires below one.
        public static readonly string[] FixtureFolders =
        {
            "test", "tests", "__tests__", "testdata", "test-data", "testing", "fixture", "fixtures", "__fixtures__",
            "sample", "samples", "example", "examples", "demo", "mock", "mocks"
        };

        // Build output: only the certificate (.pfx/.p12) and keystore rows are silent below these.
        public static readonly string[] BuildOutputFolders = { "build", "bin", "obj", "target", "intermediates", "out" };

        // Tool folders directly in the user folder whose own files some rows name.
        public static readonly string[] ToolHomes =
        {
            ".ssh", ".aws", ".azure", ".kube", ".docker", ".minikube", ".android", ".gnupg", ".vagrant.d", ".config\\gh",
            ".config\\gcloud", ".codex", ".claude"
        };

        // The only AppData folders Protect looks in, each for its own rows.
        public static readonly string[] AppDataExamined =
        {
            "Roaming\\gcloud", "Roaming\\GitHub CLI", "Roaming\\terraform.d", "Roaming\\Microsoft\\UserSecrets",
            "Roaming\\gnupg", "Roaming\\postgresql", "Roaming\\Bitcoin", "Roaming\\Litecoin", "Roaming\\Dogecoin",
            "Roaming\\DashCore", "Roaming\\Electrum\\wallets", "Roaming\\Ethereum\\keystore", "Local\\Temp"
        };

        public const string MailAttachmentPattern =
            "AppData\\Local\\Packages\\microsoft.windowscommunicationsapps_*\\LocalState\\Files\\<x>\\<y>\\Attachments";

        public static readonly string[] DocExtensions =
        {
            ".pdf", ".doc", ".docx", ".odt", ".rtf", ".xls", ".xlsx", ".ods", ".zip", ".rar", ".7z", ".jpg", ".jpeg", ".png",
            ".heic", ".heif", ".tif", ".tiff", ".bmp", ".webp"
        };

        // Words in a .pem/.key/.pfx name that mean a certificate or a public key rather than a private key.
        public static readonly string[] PublicKeyTokens =
        {
            "chain", "fullchain", "ca", "cacert", "cacerts", "root", "roots", "cert", "certs", "certificate", "crt", "bundle",
            "intermediate", "pub", "public", "trust", "trusted", "truststore", "csr"
        };

        public static readonly string[] StrongKeyTokens = { "key", "private", "priv", "privkey", "secret" };
        public static readonly string[] WeakKeyTokens = { "aws", "gcp", "azure", "ssh", "signing", "deploy" };
        public static readonly string[] KeyFolders = { "keys", "private", "secrets", "ssh", "aws", "*-keys" };

        // A document whose name holds one of these words is never a finding.
        public static readonly string[] DocGuardTokens =
        {
            "sample", "example", "template", "blank", "specimen", "instructions", "instruction", "checklist", "guide",
            "invoice", "receipt", "test", "dummy", "mock", "fake", "demo", "icon", "icons", "logo", "thumb", "thumbnail"
        };

        public static readonly string[] LaterStages =
        {
            "NuGet API keys in %APPDATA%\\NuGet\\NuGet.Config: they sit in an encrypted section, so judging the file needs its contents.",
            "Project .npmrc files and .yarnrc.yml: these usually hold registry settings only, so they need their contents.",
            ".aws\\config, Docker config.json outside a .docker folder, and cloud service-account files with free-form names: they need their contents.",
            "Terraform .tfvars files, .pem and .key files inside your projects or in other folders, certificates in Temp, and keys under test folders: these need git status.",
            "Cargo's credentials.toml: .cargo stays a skipped folder in this stage.",
            "Notes holding wallet seed phrases or recovery codes under free-form names.",
            "Tax archives named only by a year, and .pem files with no hint in their name, such as a certificate download.",
            "Passwords saved in a browser are never looked for by name: that is the browser's own encrypted store."
        };

        static PatternInfo P(string id, string kind, FindingTier tier)
        {
            return new PatternInfo(id, kind, "name", tier);
        }

        // Stage 1: findings by file name and location. Content patterns arrive in stage 2.
        public static readonly PatternInfo[] Patterns =
        {
            P("ssh-key", "SSH private key", FindingTier.Confirmed),
            P("ssh-ppk", "PuTTY private key", FindingTier.Confirmed),
            P("pem-key", "Private key file (probably)", FindingTier.Confirmed),
            P("pkcs12", "Certificate with private key (.pfx/.p12)", FindingTier.Likely),
            P("java-keystore", "App signing keystore", FindingTier.Confirmed),
            P("password-vault", "Password vault (encrypted)", FindingTier.Confirmed),
            P("password-export", "Exported passwords (plain text)", FindingTier.Confirmed),
            P("git-credentials", "Saved Git passwords (plain text)", FindingTier.Confirmed),
            P("netrc", "Saved server passwords (netrc)", FindingTier.Confirmed),
            P("aws-credentials", "AWS access keys", FindingTier.Confirmed),
            P("aws-keys-csv", "AWS access key download", FindingTier.Likely),
            P("azure-tokens", "Azure CLI sign-in tokens", FindingTier.Confirmed),
            P("gcloud-credentials", "Google Cloud sign-in", FindingTier.Confirmed),
            P("gh-hosts", "GitHub CLI sign-in", FindingTier.Likely),
            P("kubeconfig", "Kubernetes cluster access", FindingTier.Confirmed),
            P("docker-config", "Docker registry sign-in", FindingTier.Likely),
            P("npm-rc", "npm registry sign-in", FindingTier.Likely),
            P("pypi-rc", "PyPI upload sign-in", FindingTier.Likely),
            P("cli-auth-file", "Sign-in file of a developer tool", FindingTier.Likely),
            P("dotnet-user-secrets", ".NET user secrets", FindingTier.Confirmed),
            P("terraform-credentials", "Terraform Cloud token", FindingTier.Confirmed),
            P("tfstate", "Terraform state (can hold passwords)", FindingTier.Likely),
            P("dotenv", "Environment file (may hold keys)", FindingTier.Likely),
            P("pgp-secret", "GnuPG private key", FindingTier.Confirmed),
            P("pgpass", "PostgreSQL saved passwords", FindingTier.Confirmed),
            P("crypto-wallet", "Crypto wallet file", FindingTier.Confirmed),
            P("eth-keystore", "Ethereum key file", FindingTier.Confirmed),
            P("electrum-wallet", "Electrum wallet", FindingTier.Confirmed),
            P("recovery-codes", "Two-factor recovery codes", FindingTier.Confirmed),
            P("emergency-kit", "Password manager emergency kit", FindingTier.Confirmed),
            P("publish-settings", "Web Deploy publish profile", FindingTier.Likely),
            P("htpasswd", "Web server password file", FindingTier.Likely),
            P("doc-tax-file", "Tax return file (TurboTax)", FindingTier.Confirmed),
            P("doc-tax", "Tax document", FindingTier.Likely),
            P("doc-statement", "Bank or account statement", FindingTier.Likely),
            P("doc-pay", "Payslip", FindingTier.Likely),
            P("doc-id", "ID document", FindingTier.Likely),
            P("doc-scans-folder", "Scanned documents folder", FindingTier.Likely)
        };

        const string E = "Likely on your Desktop, in Downloads, in synced folders, on external drives or loose in your user folder";

        public static readonly NameRuleInfo[] NameRules =
        {
            new NameRuleInfo("ssh-key", "id_rsa, id_ed25519 and similar names, and keys with a matching .pub file, in your .ssh folder and in minikube, Docker Machine and Vagrant folders: Confirmed",
                "Likely anywhere else"),
            new NameRuleInfo("ssh-ppk", ".ppk files in your .ssh folder: Confirmed", "Confirmed anywhere else, since the format is nothing else"),
            new NameRuleInfo("pem-key", ".pem and .key files up to 16 KB in .ssh, .aws, .azure, .kube, .docker, .minikube and .vagrant.d: Confirmed when the name says key",
                E + ", only when the name says private or key, or names a cloud or deploy key with a typical key size; never in projects or other folders in this stage"),
            new NameRuleInfo("pkcs12", "no usual place, since Windows keeps certificates in its own store",
                E + "; not in projects, build output or names that say test, sample or certificate chain"),
            new NameRuleInfo("java-keystore", "the Android debug.keystore in your .android folder: Confirmed",
                E + "; not in build output or for trust stores"),
            new NameRuleInfo("password-vault", ".kdbx, .kdb, .psafe3, Bitwarden encrypted exports and 1Password vault folders in your Documents folder: Confirmed",
                "Confirmed anywhere else"),
            new NameRuleInfo("password-export", "no usual place",
                "browser and password-manager exports: Confirmed anywhere (Likely in a project); a bare passwords.csv or logins.csv: Likely in Downloads, on your Desktop, in synced folders or your user folder"),
            new NameRuleInfo("git-credentials", ".git-credentials in your user folder: Confirmed", "Likely anywhere else"),
            new NameRuleInfo("netrc", ".netrc or _netrc in your user folder: Confirmed", E),
            new NameRuleInfo("aws-credentials", "credentials in your .aws folder: Confirmed", "Likely in any other .aws folder, except in Temp"),
            new NameRuleInfo("aws-keys-csv", "no usual place", "Likely anywhere except in a project"),
            new NameRuleInfo("azure-tokens", "the token caches in your .azure folder: Confirmed", E + ", only inside a .azure folder"),
            new NameRuleInfo("gcloud-credentials", "the sign-in files in %APPDATA%\\gcloud or .config\\gcloud: Confirmed",
                E + ", for application_default_credentials.json"),
            new NameRuleInfo("gh-hosts", "hosts.yml in %APPDATA%\\GitHub CLI or .config\\gh: Likely, since the token may be in Credential Manager instead",
                "not looked for anywhere else"),
            new NameRuleInfo("kubeconfig", "config in your .kube folder: Confirmed", E + ", for kubeconfig files; never in projects in this stage"),
            new NameRuleInfo("docker-config", "config.json in your .docker folder: Likely, since it often only points to Credential Manager",
                E + ", only inside a .docker folder"),
            new NameRuleInfo("npm-rc", ".npmrc in your user folder: Likely", "not looked for anywhere else; a project .npmrc needs its contents"),
            new NameRuleInfo("pypi-rc", ".pypirc in your user folder: Likely", E),
            new NameRuleInfo("cli-auth-file", ".codex\\auth.json and .claude\\.credentials.json: Likely", "not looked for anywhere else"),
            new NameRuleInfo("dotnet-user-secrets", "secrets.json in %APPDATA%\\Microsoft\\UserSecrets: Confirmed", "not looked for anywhere else"),
            new NameRuleInfo("terraform-credentials", "credentials.tfrc.json in %APPDATA%\\terraform.d: Confirmed", E),
            new NameRuleInfo("tfstate", "no usual place", "Likely anywhere except Temp, projects included; never for example folders"),
            new NameRuleInfo("dotenv", "no usual place in this stage",
                ".env files on your Desktop, in Downloads, synced folders, external drives or your user folder; .env files in your projects are listed separately and not counted"),
            new NameRuleInfo("pgp-secret", "private keys in .gnupg or %APPDATA%\\gnupg: Confirmed", E + ", when the name says secret or private"),
            new NameRuleInfo("pgpass", ".pgpass in your user folder and pgpass.conf in %APPDATA%\\postgresql: Confirmed", E + ", for .pgpass"),
            new NameRuleInfo("crypto-wallet", "wallet.dat in the Bitcoin, Litecoin, Dogecoin or Dash Core folders in %APPDATA%: Confirmed",
                E + ", since other apps use the name too"),
            new NameRuleInfo("eth-keystore", "%APPDATA%\\Ethereum\\keystore: Confirmed", "Confirmed anywhere else, since the name format is nothing else"),
            new NameRuleInfo("electrum-wallet", "%APPDATA%\\Electrum\\wallets: Confirmed", E + ", for default_wallet"),
            new NameRuleInfo("recovery-codes", "no usual place", "GitHub and GitLab recovery-code downloads: Confirmed anywhere except in a project"),
            new NameRuleInfo("emergency-kit", "no usual place", "1Password Emergency Kit PDFs: Confirmed anywhere except in a project"),
            new NameRuleInfo("publish-settings", "no usual place", "Likely anywhere except Temp"),
            new NameRuleInfo("htpasswd", "no usual place", "Likely anywhere except Temp"),
            new NameRuleInfo("doc-tax-file", "your Documents or Pictures folder", "Confirmed anywhere, for TurboTax .tax2000 to .tax2039 files"),
            new NameRuleInfo("doc-tax", "your Documents or Pictures folder", "Likely anywhere outside projects and AppData"),
            new NameRuleInfo("doc-statement", "your Documents or Pictures folder", "Likely anywhere outside projects and AppData"),
            new NameRuleInfo("doc-pay", "your Documents or Pictures folder", "Likely anywhere outside projects and AppData"),
            new NameRuleInfo("doc-id", "your Documents or Pictures folder", "Likely anywhere outside projects and AppData"),
            new NameRuleInfo("doc-scans-folder", "your Documents or Pictures folder", "Likely anywhere, when a Scanned Documents folder holds a document")
        };

        public static PatternInfo Pattern(string id)
        {
            foreach (PatternInfo p in Patterns)
                if (p.Id == id) return p;
            return null;
        }

        public static NameRuleInfo NameRule(string id)
        {
            foreach (NameRuleInfo r in NameRules)
                if (r.Id == id) return r;
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

        // Hidden from the page: dismissed by the user, or inside a folder they trust.
        public bool IsHidden(Finding f)
        {
            return IsDismissed(f) || IsUnderTrusted(f.Path);
        }

        // The trusted folder at or above path, in the path's own casing, or null.
        public string TrustedAncestor(string path)
        {
            if (trusted.Count == 0 || string.IsNullOrEmpty(path)) return null;
            string p = System.IO.Path.GetFullPath(path.Trim()).Replace('/', '\\');
            if (p.Length > 3) p = p.TrimEnd('\\');
            while (true)
            {
                if (trusted.Contains(TrustKey(p))) return p;
                int cut = p.LastIndexOf('\\');
                if (cut <= 2) return null;
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
            try { text = File.ReadAllText(file, Encoding.UTF8); }  // trust-read: protect.json
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
                "No file is opened for its contents in a normal scan.",
                "To know where your folders are, Protect also asks Windows for your known folders (Downloads, Documents and " +
                "the rest), reads two registry keys that list the folders your sync apps keep (HKLM and HKCU\\" +
                ProtectConstants.SyncRootManagerKey + ", and HKCU\\" + ProtectConstants.OneDriveAccountsKey + "), and " +
                "checks whether a .git folder exists above the folder you scan.",
                "After each scan it lists folders on your other connected drives, by name, to look for copies (see Copies on " +
                "other drives below)."));

            int contentPatterns = 0;
            var byName = new List<string>();
            var docKinds = new List<string>();
            foreach (PatternInfo p in ProtectConstants.Patterns)
            {
                if (p.ReadsContent == "content")
                {
                    contentPatterns++;
                    continue;
                }
                NameRuleInfo rule = ProtectConstants.NameRule(p.Id);
                byName.Add(p.Kind + ": " + (rule != null ? rule.Usual + "; " + rule.Elsewhere : "matched by name"));
                if (p.Id.StartsWith("doc-", StringComparison.Ordinal)) docKinds.Add(p.Kind.Length > 1 && char.IsLower(p.Kind[1]) ? char.ToLowerInvariant(p.Kind[0]) + p.Kind.Substring(1) : p.Kind);
            }
            if (byName.Count > 0)
            {
                byName.Insert(0, "Each kind of file below is matched by its name and the folder it sits in. Confirmed means " +
                    "Protect is sure what kind of file it is; Likely means the name and place strongly suggest it. Nothing is opened.");
                sections.Add(new InfoSection("What is found by name", byName.ToArray()));
            }
            if (docKinds.Count > 0)
            {
                sections.Add(new InfoSection("Personal documents by name",
                    "Files of these types: " + string.Join(" ", ProtectConstants.DocExtensions) + ", and TurboTax .tax2000 to .tax2039 " +
                    "files. Pictures must be at least " + Fmt.Size(ProtectConstants.DocImageMinBytes) + ".",
                    "Kinds: " + string.Join(", ", docKinds) + ".",
                    "A name must say what the document is, with a second word to back it up: \"tax\" with \"return\" or \"form\", a " +
                    "1099, W-2, T4 or 1040 with a year or a tax word, \"statement\" with a bank or account word, payslips, and " +
                    "passports, driving licences, ID cards and birth certificates. A year alone is not enough, and numbers in camera " +
                    "file names (IMG_1099) do not count. The two nearest folder names can back up a name but never make a finding.",
                    "Never a finding when the name also says: " + string.Join(", ", ProtectConstants.DocGuardTokens) + ".",
                    "Documents are never opened to read them. Open on a card hands a document to its own app, only when you click it."));
            }

            sections.Add(new InfoSection("Where Protect does not look",
                "Anything under these folders: " + string.Join(", ", ProtectConstants.SkipFolders) + ", and any folder whose name " +
                "starts with $.",
                "Test and sample folders: " + string.Join(", ", ProtectConstants.FixtureFolders) + ".",
                "Any other dot folder in your user folder.",
                "The tool folders it does look in, each for its own files only: " + string.Join(", ", ProtectConstants.ToolHomes) + ".",
                "AppData, except: " + string.Join(", ", ProtectConstants.AppDataExamined) + ".",
                "Windows Mail kept copies of attachments you opened; Protect checks their names. The new Outlook's cache is not checked."));

            sections.Add(new InfoSection("Copies on other drives",
                "Compared by file count and total size on the drives connected now. Nothing is opened; a byte-for-byte check is a " +
                "separate step on the Move page that asks first."));

            sections.Add(new InfoSection("Waits for later stages", ProtectConstants.LaterStages));

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
                "Never the matched value, not even part of it, and never the surrounding text.",
                "Paths are shown in clear on this page and in dsa --protect output. File names can contain names and account " +
                "numbers; take care when pasting them."));

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

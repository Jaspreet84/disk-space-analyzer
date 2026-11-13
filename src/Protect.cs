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

    // The content scan (stage 2). A candidate is a text file that Analyze picked by its name, size, flags and
    // folder; nothing is opened to pick it. Dotenv files also get the env-secret row.
    public enum ContentKind : byte { Text = 1, Dotenv = 2 }

    sealed class ContentCandidate
    {
        public readonly FileNode Node;
        public readonly long Size;      // the size when Analyze picked it; the reader checks the real length again
        public readonly Place Place;
        public readonly ContentKind Kind;

        public ContentCandidate(FileNode node, long size, Place place, ContentKind kind)
        {
            Node = node;
            Size = size;
            Place = place;
            Kind = kind;
        }
    }

    // One content row in words: the rule for the explanation screen, the reason shown on a card, and the plural
    // used by Hide ("Hide GitHub tokens in this file"). One per content row of Patterns, in the same order.
    sealed class ContentRuleInfo
    {
        public readonly string Id, Rule, Reason, Plural;

        public ContentRuleInfo(string id, string rule, string reason, string plural)
        {
            Id = id;
            Rule = rule;
            Reason = reason;
            Plural = plural;
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
        // A scan of a network drive or share reads no file contents (ProtectContext.IsNetworkPath).
        public const string NetworkDrivesNote = "Files on network drives and shares are not read, so nothing comes over the network.";

        // The content scan's table (section 1 of the stage 2 spec). A change to a row is a change to this version.
        public const int ContentTableVersion = 1;
        public const int ContentFindingsPerFile = 20;  // after this many matches in one file, matching stops for it
        public const int ContentRowsPerCard = 50;

        // The text files the content scan reads: these extensions, these exact names, and .env files.
        public static readonly string[] TextExtensions =
        {
            ".txt", ".md", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties", ".xml",
            ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".rb", ".go", ".java", ".kt", ".kts", ".cs", ".php", ".sh", ".bash", ".zsh",
            ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".sql", ".tf", ".tfvars", ".hcl", ".ipynb", ".pem", ".key", ".env"
        };

        public static readonly string[] TextNames =
        {
            "credentials", ".git-credentials", ".npmrc", ".pypirc", ".netrc", "_netrc", ".pgpass", ".gitconfig", ".bashrc",
            ".bash_profile", ".profile", ".zshrc", ".zprofile", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"
        };

        // A text extension with one of these endings is still not read: generated and bundled code.
        public static readonly string[] TextNeverEnds = { ".min.js", ".min.mjs", ".bundle.js", ".map", ".d.ts", ".lock" };

        // Never read, on purpose: logs and exports often hold test tokens and redacted look-alikes, and certificates
        // are public.
        public static readonly string[] TextNeverClasses =
        {
            "files with no extension (except the names above)", ".html", ".htm", ".svg", ".css", ".csv", ".log", ".crt", ".cer",
            ".der", ".pfx", ".p12", ".lnk", ".url"
        };

        // Folders the content scan never opens, on top of SkipFolders, wherever they are. The entries written in
        // words are the anchored rules, which hold only where the words say.
        public static readonly string[] ContentSkipFolders =
        {
            "site-packages", "dist-packages", "bower_components", "__pycache__", ".tox", ".venv", ".terraform", ".next", ".nuxt",
            ".svelte-kit", ".parcel-cache", ".angular", ".gradle", ".m2", ".rustup", ".cargo\\registry", "go\\pkg\\mod",
            ".vscode-server", "vendor beside a composer.json or go.mod", "env or venv holding a pyvenv.cfg"
        };

        // The tool folders in your user folder whose files the content scan reads. Other dot folders there, .codex
        // and .claude included, are not read.
        public static readonly string[] ContentToolHomes =
        {
            ".ssh", ".aws", ".azure", ".kube", ".docker", ".minikube", ".android", ".gnupg", ".vagrant.d", ".config\\gh", ".config\\gcloud"
        };

        // Formats the content scan does not look for yet, and why.
        public static readonly string[] ContentHeldBack =
        {
            "GitLab tokens: older ones have no checksum, and the newer format is still changing, so their matches cannot be measured yet.",
            "npm tokens: their checksum scheme is described only in a blog post, and there is no real token here to test against.",
            "Anthropic and PyPI tokens: they are outside this stage, and their structure has no checksum.",
            "AWS secret access keys found by the name of their setting outside .env files: that waits for a later stage.",
            "Older Slack tokens, and Slack workflow and trigger webhooks: their format is too loose to report with confidence.",
            "GitHub App installation tokens in the new form: they last about an hour and carry no checksum.",
            "The contents of PuTTY key files: .ppk files are already found by name.",
            "Settings with a secret-looking name outside .env files, web tokens and password.txt files: a later stage.",
            "Files over " + ProtectInfo.Limit(ProtectConstants.MaxContentBytes) + ", binary files and UTF-16 files: they are not read."
        };

        // The published Google sample keys, which are never reported. Copied from the gcp-api-key allowlist of the
        // gitleaks configuration (config/gitleaks.toml, release v8.28.0, MIT licence; its first entry is the
        // documentation dummy key). Each is split after its first four characters so that no line of this file
        // holds a whole key.
        public const int SampleKeyCount = 16;
        public static readonly string[] GoogleSampleKeys =
        {
            "AIza" + "Syabcdefghijklmnopqrstuvwxyz1234567",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",  // sample-key: gitleaks v8.28.0
            "AIza" + "yDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",  // sample-key: gitleaks v8.28.0
            "AIza" + "SyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY"   // sample-key: gitleaks v8.28.0
        };

        // One per content row of Patterns, in the same order.
        public static readonly ContentRuleInfo[] ContentRules =
        {
            new ContentRuleInfo("github-token",
                "GitHub token: a classic token prefix, 36 letters and digits, and a checksum that must verify. Confirmed.",
                "Its format and checksum match a GitHub token.", "GitHub tokens"),
            new ContentRuleInfo("github-fine-grained",
                "GitHub fine-grained token: the fine-grained token prefix, 22 letters and digits, an underscore and 59 more. Likely.",
                "It has the exact shape of a GitHub fine-grained token.", "GitHub fine-grained tokens"),
            new ContentRuleInfo("aws-access-key-id",
                "AWS access key ID: an access key prefix and 16 capital letters and digits from 2 to 7, not inside a longer run of base64 text; AWS's published example IDs are left out. Likely.",
                "It has the shape of an AWS access key ID. That is half a credential; the secret key is often nearby.", "AWS access key IDs"),
            new ContentRuleInfo("slack-token",
                "Slack token: a bot, user, app or rotating token prefix, followed by the exact groups of digits and letters Slack uses. Likely.",
                "It has the shape of a Slack token.", "Slack tokens"),
            new ContentRuleInfo("slack-webhook",
                "Slack webhook address: the hooks.slack.com services address with its team, channel and 24-character secret parts. Likely.",
                "It is a Slack webhook address. Anyone who has it can post to that channel.", "Slack webhook addresses"),
            new ContentRuleInfo("stripe-live-key",
                "Stripe live secret key: a live secret or restricted key prefix and 24 to 247 letters and digits; test-mode keys are never looked for. Likely.",
                "It has the shape of a Stripe live secret key.", "Stripe live secret keys"),
            new ContentRuleInfo("google-api-key",
                "Google API key: the Google key prefix and exactly 35 letters, digits, dashes and underscores; published sample keys are left out. Likely.",
                "It has the shape of a Google API key. Keys in website code are often public by design; server and Gemini keys are not.", "Google API keys"),
            new ContentRuleInfo("openai-key",
                "OpenAI API key: a project, service account, admin or older key prefix, with the fixed marker OpenAI puts in the middle of every key. Likely.",
                "It has the shape of an OpenAI API key.", "OpenAI API keys"),
            new ContentRuleInfo("pem-private-key",
                "Private key: a private key block with its begin line, at least 64 characters of base64 and the matching end line. Confirmed.",
                "The file holds a private key. Tools such as local clusters create these; it matters most if the file is shared or synced.", "Private keys"),
            new ContentRuleInfo("pem-private-key-encrypted",
                "Private key (passphrase-protected): a private key block marked as encrypted by its label or its Proc-Type line. Confirmed.",
                "The file holds a private key protected by a passphrase.", "Passphrase-protected private keys"),
            new ContentRuleInfo("env-secret",
                "Secret setting in a .env file: a setting whose name ends in a secret word such as PASSWORD, TOKEN, SECRET or API_KEY, with a value of 16 to 1024 characters that is not a placeholder or a reference to a secret manager. Likely.",
                "A setting in this .env file is named like a secret and has a value.", "Secret settings")
        };

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
            "Project .npmrc files and .yarnrc.yml: these usually hold registry settings only, and npm tokens are not looked for yet.",
            "Docker config.json outside a .docker folder: it is not found by name.",
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

        static PatternInfo C(string id, string kind, FindingTier tier)
        {
            return new PatternInfo(id, kind, "content", tier);
        }

        // The 38 rows found by file name and location (stage 1), then the 11 content rows (stage 2), in table order.
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
            P("doc-scans-folder", "Scanned documents folder", FindingTier.Likely),
            C("github-token", "GitHub token", FindingTier.Confirmed),
            C("github-fine-grained", "GitHub fine-grained token", FindingTier.Likely),
            C("aws-access-key-id", "AWS access key ID", FindingTier.Likely),
            C("slack-token", "Slack token", FindingTier.Likely),
            C("slack-webhook", "Slack webhook address", FindingTier.Likely),
            C("stripe-live-key", "Stripe live secret key", FindingTier.Likely),
            C("google-api-key", "Google API key", FindingTier.Likely),
            C("openai-key", "OpenAI API key", FindingTier.Likely),
            C("pem-private-key", "Private key", FindingTier.Confirmed),
            C("pem-private-key-encrypted", "Private key (passphrase-protected)", FindingTier.Confirmed),
            C("env-secret", "Secret setting in a .env file", FindingTier.Likely)
        };

        public const int NameRowCount = 38;  // the content rows follow the name rows in Patterns

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
        // A content-scan limit as Protect's texts write it: "1 MB" and "8 KB", not "1.00 MB". Only these texts
        // drop the decimals; every other size in the app keeps Fmt.Size's fixed precision.
        public static string Limit(long bytes)
        {
            string[] units = { "KB", "MB", "GB" };
            long v = bytes;
            int u = -1;
            while (v >= 1024 && v % 1024 == 0 && u < units.Length - 1)
            {
                v /= 1024;
                u++;
            }
            return u < 0 || v >= 1024 ? Fmt.Size(bytes) : v + " " + units[u];
        }

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
                "No file is opened for its contents unless you turn on the content scan.",
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

            sections.Add(new InfoSection("What the content scan reads, only when you turn it on", ContentReadsLines()));
            sections.Add(new InfoSection("What Protect does not look for yet", NotYetLines()));

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

        // ---- The content scan, in words (stage 2). Every number and list below comes from ProtectConstants. ----

        static int ContentRowCount()
        {
            return ProtectConstants.ContentRules.Length;
        }

        static string Plural(long n, string one, string many)
        {
            return Fmt.Count(n) + " " + (n == 1 ? one : many);
        }

        // ContentSkipFolders without the entries SkipFolders already lists, so no folder is named twice.
        static string[] ContentOnlyFolders()
        {
            var list = new List<string>();
            foreach (string s in ProtectConstants.ContentSkipFolders)
                if (Array.FindIndex(ProtectConstants.SkipFolders, x => string.Equals(x, s, StringComparison.OrdinalIgnoreCase)) < 0) list.Add(s);
            return list.ToArray();
        }

        // The AppData folders the content scan reads, besides Temp.
        static string[] AppDataReadByContent()
        {
            var list = new List<string>();
            foreach (string s in ProtectConstants.AppDataExamined)
                if (!string.Equals(s, "Local\\Temp", StringComparison.OrdinalIgnoreCase)) list.Add(s);
            return list.ToArray();
        }

        static string TextFilesSentence()
        {
            var never = new List<string>(ProtectConstants.TextNeverEnds);
            never.AddRange(ProtectConstants.TextNeverClasses);
            return "Text files with these extensions: " + string.Join(" ", ProtectConstants.TextExtensions) + "; these names: " +
                   string.Join(" ", ProtectConstants.TextNames) + " (and config in a tool folder); and .env files (not .env.example " +
                   "and other templates). Never: " + string.Join(", ", never) + ".";
        }

        static string BinarySentence()
        {
            return "A file is treated as binary and skipped if its first " + ProtectInfo.Limit(ProtectConstants.BinaryProbeBytes) +
                   " contain a zero byte. UTF-16 files are skipped.";
        }

        const string SharedSentence = "Files are opened read-only and shared for reading, writing and deleting, so no other program is " +
                                      "blocked. Windows may update their last-access time.";
        const string MatchSentence = "A match is shown as a file and a line number. The key itself is never shown, copied or saved.";
        public const string NothingKeptSentence = "Nothing read here is kept after the scan.";

        static string SampleSentence()
        {
            // The 2 counts the two AWS documentation IDs, which the EXAMPLE ending rule leaves out.
            return (ProtectConstants.SampleKeyCount + 2) + " published sample keys are never reported, and Stripe test-mode keys " +
                   "are never looked for.";
        }

        static string[] ContentReadsLines()
        {
            var lines = new List<string>();
            lines.Add(TextFilesSentence());
            lines.Add("Only files of " + ProtectInfo.Limit(ProtectConstants.MaxContentBytes) + " or less. Compressed files are re-checked when opened.");
            lines.Add(BinarySentence());
            lines.Add("Never opened: " + string.Join(", ", ProtectConstants.SkipFolders) + ", folders starting with $, " +
                      string.Join(", ", ContentOnlyFolders()) + ", test and example folders (" +
                      string.Join(", ", ProtectConstants.FixtureFolders) + "), AppData except Temp and " +
                      string.Join(", ", AppDataReadByContent()) + ", other dot folders in your user folder except " +
                      string.Join(", ", ProtectConstants.ContentToolHomes) + ", editor extension folders, Rust target folders, " +
                      "build output inside projects, and your trusted folders.");
            lines.Add("Online-only files and links are never opened, so nothing is downloaded.");
            lines.Add(ProtectConstants.NetworkDrivesNote);
            lines.Add(SharedSentence);
            lines.Add(ProtectConstants.ContentWorkers + " files are read at a time, at low priority. Each reader holds one " +
                      ProtectInfo.Limit(ProtectConstants.MaxContentBytes) + " buffer, cleared after every file.");
            lines.Add("No randomness scoring: a string is reported only if it has a known format.");
            foreach (ContentRuleInfo r in ProtectConstants.ContentRules) lines.Add(r.Rule);
            lines.Add(SampleSentence());
            lines.Add(MatchSentence);
            lines.Add(NothingKeptSentence);
            return lines.ToArray();
        }

        static string[] NotYetLines()
        {
            var lines = new List<string>(ProtectConstants.ContentHeldBack);
            lines.AddRange(ProtectConstants.LaterStages);
            return lines.ToArray();
        }

        // The folders the content scan never opens, one per line, for the consent dialog's list box.
        static string NeverOpenedList(int trustedFolders)
        {
            var lines = new List<string>(ProtectConstants.SkipFolders);
            lines.Add("folders starting with $");
            lines.AddRange(ContentOnlyFolders());
            lines.Add("test and example folders");
            lines.Add("AppData, except Temp and the tool folders Protect checks");
            lines.Add("other dot folders in your user folder");
            lines.Add("editor extension folders");
            lines.Add("Rust target folders");
            lines.Add("build output inside projects");
            lines.Add("network drives and shares");
            if (trustedFolders > 0) lines.Add("your " + Plural(trustedFolders, "trusted folder", "trusted folders"));
            return string.Join("\n", lines);
        }

        // The consent dialog's body (section 7.2 of the stage 2 spec). Always 8 entries, in order: [0] what is read,
        // [1] what is skipped, [2] the lead-in to the folder list, [3] the folder list for the list box (one folder per
        // line, separated by "\n"), [4] no guessing, [5] read-only and shared, [6] how a match is shown, [7] the
        // closing sentence, shown in bold.
        public static string[] ContentDialog(ContentPlan plan, string rootLabel)
        {
            int files = plan != null ? plan.Files.Length : 0;
            string first;
            if (files == 0) first = "No text files in this scan qualify.";
            else
            {
                first = "Protect will read " + Plural(files, "text file", "text files") + " (" + Fmt.Size(plan.TotalBytes) +
                        ") found by this scan of " + rootLabel + ", each up to " + ProtectInfo.Limit(ProtectConstants.MaxContentBytes) +
                        ". It looks for " + ContentRowCount() + " kinds of key with a known format, such as GitHub tokens, AWS " +
                        "access keys and private keys.";
            }
            string second = "A file is treated as binary and skipped if its first " + ProtectInfo.Limit(ProtectConstants.BinaryProbeBytes) +
                            " contain a zero byte. UTF-16 files are skipped too.";
            int large = plan != null ? plan.TooLarge : 0, online = plan != null ? plan.OnlineOnly : 0;
            if (large > 0 && online > 0)
                second += " " + Plural(large, "larger text file", "larger text files") + " and " +
                          Plural(online, "online-only file", "online-only files") + " are not read.";
            else if (large > 0) second += " " + Plural(large, "larger text file is", "larger text files are") + " not read.";
            else if (online > 0) second += " " + Plural(online, "online-only file is", "online-only files are") + " not read.";
            return new[]
            {
                first,
                second,
                "It never opens anything in these folders:",
                NeverOpenedList(plan != null ? plan.TrustedFolders : 0),
                "It does not guess from random-looking text. Published sample keys are never reported.",
                SharedSentence + " Online-only files are not opened, so nothing is downloaded.",
                MatchSentence,
                NothingKeptSentence
            };
        }

        // The clean page's state line (section 7.6). nameFiles: files whose names Protect checked; readFiles: text
        // files read in this scan; planFiles: text files in the plan.
        public static string ContentSummary(int nameFiles, long readFiles, long planFiles, int patterns, bool on, bool ran, bool stopped)
        {
            string head = "Nothing to review. Protect checked the names of " + Plural(nameFiles, "file", "files");
            if (!on) return head + ". The content scan is off.";
            if (stopped)
                return head + " and read " + Fmt.Count(readFiles) + " of " + Plural(planFiles, "text file", "text files") +
                       " before you stopped it.";
            if (!ran) return head + ". Text files are read after each scan.";
            return head + " and found no keys in " + Plural(readFiles, "text file", "text files") + " with " + patterns +
                   " patterns; content scan on.";
        }

        // The collapsed "What Protect does not look for" list under the clean state.
        public static string[] NotLookedFor(int tooLarge, int onlineOnly)
        {
            var lines = new List<string>();
            lines.Add("Keys without a fixed format.");
            lines.Add("Passwords in documents.");
            lines.Add("Files over " + ProtectInfo.Limit(ProtectConstants.MaxContentBytes) +
                      (tooLarge > 0 ? " (" + Fmt.Count(tooLarge) + " in this scan)." : "."));
            lines.Add("Binary and UTF-16 files.");
            lines.Add("Online-only files" + (onlineOnly > 0 ? " (" + Fmt.Count(onlineOnly) + " in this scan)." : "."));
            lines.Add("Files in the folders the content scan skips, listed under What Protect reads.");
            lines.AddRange(ProtectConstants.ContentHeldBack);
            return lines.ToArray();
        }

        // The first line of dsa --protect output.
        public static string CliHeader(bool contentRan, long files, int patterns)
        {
            if (!contentRan) return "Protect: found by file name and location. Nothing was opened.";
            return "Protect: found by name, and by reading " + Plural(files, "text file", "text files") + " with " + patterns + " patterns.";
        }

        // The groups of a card (one per file), shared by the page and dsa so they cannot drift (section 5.4).
        public const int GroupReview = 0, GroupUsual = 1, GroupProjects = 2;

        // f: the card's lead finding. hasUsual: the path has a finding in its usual place (by name, or a content
        // finding in a tool home). onlyEnvSecretInRepo: a repository dotenv file whose only content findings are
        // env-secret (a repository .env found by name only counts as this too). Only GroupReview is counted.
        public static int GroupOf(Finding f, bool hasUsual, bool onlyEnvSecretInRepo)
        {
            if (hasUsual || (f != null && f.Place == Place.UsualPlace)) return GroupUsual;
            if (onlyEnvSecretInRepo) return GroupProjects;
            return GroupReview;
        }
    }
}

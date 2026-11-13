using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;

// The Protect page's view models and its wording. This file is under tools\check-trust.ps1: it may not
// write, delete or move anything, and it reads no file contents. View models carry Variant strings, never
// brushes; the XAML picks the brush with a DataTrigger, so a theme switch needs no rebuild.

namespace DiskSpace
{
    // The numbers in the summary strip.
    sealed class ProtectSummaryVm
    {
        public int ToReview { get; set; }
        public int Keys { get; set; }
        public int Documents { get; set; }
        public int Files { get; set; }
        public string NoCopyText { get; set; }
        public string Note { get; set; }
    }

    // A small rounded label. Variant: "" (plain), "warn" or "good".
    sealed class ProtectChipVm
    {
        public string Text { get; set; }
        public string Variant { get; set; }

        public ProtectChipVm(string text, string variant)
        {
            Text = text;
            Variant = variant ?? "";
        }
    }

    // One card in the findings list: one credential file, one group of documents, or one of the two collapsed
    // groups ("In their usual places", "In your projects").
    sealed class ProtectCardVm
    {
        public string Group { get; set; }           // "cred", "doc", "vault", "usual" or "projects"
        public string Glyph { get; set; }
        public string Title { get; set; }
        public string Reason { get; set; }
        public List<string> Lines { get; set; }
        public Visibility LinesVisibility { get; set; }
        public List<ProtectChipVm> Chips { get; set; }
        public Visibility ChipsVisibility { get; set; }
        public string Path { get; set; }
        public Visibility PathVisibility { get; set; }
        public List<ProtectItemVm> Items { get; set; }
        public string ItemsLabel { get; set; }
        public Visibility ItemsVisibility { get; set; }
        public bool Expanded { get; set; }
        public string PrimaryText { get; set; }
        public string PrimaryTag { get; set; }
        public Visibility ShowLinkVisibility { get; set; }
        public Visibility ActionsVisibility { get; set; }

        // Not bound: what the actions work on.
        public string ActionPath { get; set; }      // the file, or the folder of a group card
        public Node Node { get; set; }
        public List<Finding> Findings { get; set; }
        public string TrustFolder { get; set; }
        public Place SortPlace { get; set; }
        public FindingTier SortTier { get; set; }
        public long SortBytes { get; set; }
    }

    // A row in a card's "Show N files" list.
    sealed class ProtectItemVm
    {
        public Node Node { get; set; }
        public string Path { get; set; }
        public ImageSource Icon { get; set; }
        public string Name { get; set; }
        public string Kind { get; set; }
        public string Folder { get; set; }
        public string SizeText { get; set; }
        public Visibility OpenVisibility { get; set; }
        public Visibility TrustVisibility { get; set; }
        public string TrustFolder { get; set; }
    }

    // One folder in "Copies of your folders".
    sealed class ProtectFolderVm
    {
        public FolderCoverage Coverage { get; set; }
        public string Name { get; set; }
        public string Subtitle { get; set; }
        public string Why { get; set; }
        public List<ProtectChipVm> Chips { get; set; }
        public List<string> Lines { get; set; }
        public string AccentText { get; set; }
        public Visibility AccentVisibility { get; set; }
        public string PlainText { get; set; }
        public Visibility PlainVisibility { get; set; }

        // Not bound: the drive a copy or check goes to.
        public DriveProfile Target { get; set; }
    }

    // A row in "Hidden by you".
    sealed class ProtectHiddenVm
    {
        public Finding Finding { get; set; }
        public string Kind { get; set; }
        public string Path { get; set; }
        public string Note { get; set; }
        public string TrustedFolder { get; set; }   // null for a finding hidden on its own
    }

    // Every sentence the page shows about a finding, keyed by pattern id and place. The rules: calm, factual,
    // no alarm words, and no claim about permissions or git status.
    static class ProtectWording
    {
        public const string GlyphKey = "", GlyphSignIn = "", GlyphVault = "", GlyphDocument = "";
        public const string GlyphFolder = "", GlyphProject = "";

        public const string UsualHeader = "These files are where their tools keep them. This is normal on a developer PC.";
        public const string ProjectsHeader = "Projects often keep .env files next to their code. Protect does not check git yet, " +
                                             "so it cannot tell which of these are committed. That arrives in a later stage.";

        // A card's reason never repeats its title ("<Kind> in <place>"): it starts with the explanation.
        static readonly Dictionary<string, string> Overrides = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            { "pem-key|HomeFolder", "Protect read only its name and size. " +
                                    "If you still use it, keeping it with your other keys in .ssh or in a password manager is tidier." },
            { "pem-key|Synced", "Protect read only its name and size. Syncing puts a copy of it on the provider's servers too." },
            { "dotenv|Desktop", "These files often hold API keys. Projects usually keep them in the project folder." },
            { "dotenv|Downloads", "These files often hold API keys. Projects usually keep them in the project folder." },
            { "dotenv|HomeFolder", "These files often hold API keys. Projects usually keep them in the project folder." },
            { "password-export|Downloads", "This is a plain-text list of saved passwords. " +
                                           "Exports are meant to be imported and then deleted." },
            { "password-export|Desktop", "This is a plain-text list of saved passwords. " +
                                         "Exports are meant to be imported and then deleted." }
        };

        static readonly Dictionary<string, string> What = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            { "ssh-ppk", "PuTTY uses this file to sign in to servers." },
            { "pkcs12", "A .pfx or .p12 file holds a certificate together with its private key." },
            { "java-keystore", "Keystores hold the keys used to sign apps." },
            { "password-export", "This is a plain-text list of saved passwords. Exports are meant to be imported and then deleted." },
            { "git-credentials", "Git's \"store\" helper keeps passwords in this file in plain text." },
            { "netrc", "This file can hold server passwords in plain text." },
            { "aws-credentials", "This file holds AWS access keys." },
            { "aws-keys-csv", "AWS offers this file once, when an access key is created. It holds the key in plain text." },
            { "azure-tokens", "The Azure CLI keeps its sign-in tokens in this file." },
            { "gcloud-credentials", "Google Cloud tools keep sign-in credentials in this file." },
            { "gh-hosts", "GitHub CLI keeps its sign-in here. It may hold only your user name, with the token in Credential Manager." },
            { "kubeconfig", "A kubeconfig file can give access to a Kubernetes cluster." },
            { "docker-config", "Docker keeps registry sign-ins here, often only as a pointer to Credential Manager." },
            { "npm-rc", "npm keeps registry settings here, and sometimes a sign-in token." },
            { "pypi-rc", "This file can hold a PyPI upload password or token." },
            { "cli-auth-file", "A developer tool keeps its sign-in in this file." },
            { "dotnet-user-secrets", "Visual Studio keeps a project's user secrets here, outside your code." },
            { "terraform-credentials", "Terraform keeps its Terraform Cloud token in this file." },
            { "tfstate", "State files can hold resource passwords in plain text. Remote state keeps them off this PC." },
            { "dotenv", "These files often hold API keys." },
            { "pgp-secret", "The name says it is a GnuPG private key." },
            { "pgpass", "PostgreSQL keeps saved passwords in this file in plain text." },
            { "crypto-wallet", "Wallet apps keep their keys in a file with this name. Other apps use the name too." },
            { "eth-keystore", "This name is the format Ethereum uses for an encrypted key file." },
            { "electrum-wallet", "Electrum keeps wallets under this name." },
            { "recovery-codes", "Recovery codes let whoever has them into the account without its second step." },
            { "emergency-kit", "An emergency kit holds what is needed to open the password manager account." },
            { "publish-settings", "A publish profile can hold a deployment password." },
            { "htpasswd", "A web server keeps its user passwords, usually hashed, in this file." }
        };

        static readonly Dictionary<string, string> Usual = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            { "ssh-key", "SSH keeps your key here. This is normal." },
            { "ssh-ppk", "PuTTY keys kept with your SSH keys. This is normal." },
            { "pem-key", "Kept in its tool's folder. This is normal." },
            { "java-keystore", "Android's debug signing key. This is normal." },
            { "password-vault", "Encrypted by design, so this is not exposed by itself." },
            { "git-credentials", "Git's \"store\" helper keeps passwords here in plain text. Git Credential Manager keeps them encrypted instead." },
            { "netrc", "Saved server passwords, kept where tools look for them. They are in plain text." },
            { "aws-credentials", "The AWS CLI keeps your access keys here. This is normal." },
            { "azure-tokens", "The Azure CLI keeps its sign-in here. This is normal." },
            { "gcloud-credentials", "Google Cloud tools keep their sign-in here. This is normal." },
            { "gh-hosts", "GitHub CLI keeps its sign-in here; the token may be in Credential Manager instead." },
            { "kubeconfig", "kubectl keeps cluster access here. This is normal." },
            { "docker-config", "Docker keeps registry sign-ins here, often only a pointer to Credential Manager." },
            { "npm-rc", "npm settings, and sometimes a registry token. This is the usual place." },
            { "pypi-rc", "PyPI upload settings, kept where the tools look for them." },
            { "cli-auth-file", "The tool keeps its sign-in here. This is normal." },
            { "dotnet-user-secrets", "Visual Studio keeps user secrets here, outside your code. This is normal." },
            { "terraform-credentials", "Terraform keeps its Terraform Cloud token here. This is normal." },
            { "pgp-secret", "GnuPG keeps your private keys here. This is normal." },
            { "pgpass", "PostgreSQL keeps saved passwords here, in plain text. This is the usual place." },
            { "crypto-wallet", "The wallet app keeps its wallet here. This is normal." },
            { "eth-keystore", "The wallet app keeps its key files here. This is normal." },
            { "electrum-wallet", "Electrum keeps its wallets here. This is normal." }
        };

        public static bool IsDocument(string id)
        {
            return id != null && id.StartsWith("doc-", StringComparison.Ordinal);
        }

        public static bool IsKey(string id)
        {
            return id == "ssh-key" || id == "ssh-ppk" || id == "pem-key" || id == "pkcs12" || id == "java-keystore" ||
                   id == "pgp-secret" || id == "eth-keystore";
        }

        // Documents and vaults may be opened with their own app; other kinds get only Show in Explorer, because
        // their association can run or import them.
        public static bool CanOpen(string id)
        {
            return IsDocument(id) || id == "password-vault";
        }

        public static string Glyph(string id)
        {
            if (IsDocument(id)) return GlyphDocument;
            if (id == "password-vault" || id == "crypto-wallet" || id == "electrum-wallet") return GlyphVault;
            if (IsKey(id)) return GlyphKey;
            return GlyphSignIn;
        }

        // Document families: the cards group by (top folder, family).
        public static string Family(string id)
        {
            switch (id)
            {
                case "doc-tax":
                case "doc-tax-file": return "tax";
                case "doc-statement": return "statements";
                case "doc-pay": return "pay";
                case "doc-id": return "id";
                case "doc-scans-folder": return "scans";
                case "password-vault": return "vault";
                default: return "other";
            }
        }

        // "6 bank statements", "1 tax document", "15 tax and bank documents".
        public static string FamilyCount(List<string> families, int n)
        {
            bool one = n == 1;
            if (families.Count == 1)
            {
                switch (families[0])
                {
                    case "tax": return n + (one ? " tax document" : " tax documents");
                    case "statements": return n + (one ? " bank statement" : " bank statements");
                    case "pay": return n + (one ? " payslip" : " payslips");
                    case "id": return n + (one ? " ID document" : " ID documents");
                    case "vault": return n + (one ? " password vault" : " password vaults");
                    case "scans": return n + (one ? " scanned document" : " scanned documents");
                }
            }
            var words = new List<string>();
            foreach (string f in new[] { "tax", "statements", "pay", "id", "scans" })
            {
                if (!families.Contains(f)) continue;
                words.Add(f == "statements" ? "bank" : f == "id" ? "ID" : f == "scans" ? "scanned" : f);
            }
            if (words.Count == 0) return n + (one ? " personal document" : " personal documents");
            string joined = words.Count == 1 ? words[0]
                : string.Join(", ", words.GetRange(0, words.Count - 1).ToArray()) + " and " + words[words.Count - 1];
            return n + " " + joined + (one ? " document" : " documents");
        }

        public static string TierText(FindingTier tier)
        {
            return tier == FindingTier.Confirmed ? "Confirmed" : tier == FindingTier.Likely ? "Likely" : "Worth a look";
        }

        static string Letter(string path)
        {
            string root = System.IO.Path.GetPathRoot(path) ?? "";
            return root.TrimEnd('\\');
        }

        // The place chip: "Downloads", "Home folder", "External drive F:", "On D:" and so on.
        public static string PlaceChip(Place place, string path, bool mail)
        {
            switch (place)
            {
                case Place.UsualPlace: return "Usual place";
                case Place.Downloads: return "Downloads";
                case Place.Desktop: return "Desktop";
                case Place.Synced: return "Synced";
                case Place.HomeFolder: return "Home folder";
                case Place.ExternalDrive: return "External drive " + Letter(path);
                case Place.Repository: return "In a project";
                case Place.Temp: return "Temp";
                default: return mail ? "Mail app attachments" : "On " + Letter(path);
            }
        }

        // "in Downloads", "on your Desktop": used in titles and in the first sentence of a reason.
        public static string PlacePhrase(Place place, string path, bool mail)
        {
            switch (place)
            {
                case Place.UsualPlace: return "in its usual place";
                case Place.Downloads: return "in Downloads";
                case Place.Desktop: return "on your Desktop";
                case Place.Synced: return "in a folder that syncs to the cloud";
                case Place.HomeFolder: return "in your user folder";
                case Place.ExternalDrive: return "on external drive " + Letter(path);
                case Place.Repository: return "in a project";
                case Place.Temp: return "in a temporary folder";
                default: return mail ? "in Mail app attachments" : "on " + Letter(path);
            }
        }

        static string Short(string id, string kind)
        {
            switch (id)
            {
                case "dotenv": return ".env file";
                case "tfstate": return "Terraform state";
                case "password-export": return "Exported passwords";
                case "password-vault": return "Password vault";
                default: return kind;
            }
        }

        // The title of a credential card: "<Kind> in <place name>".
        public static string CredentialTitle(string id, string kind, Place place, string path, bool mail)
        {
            string phrase = place == Place.Synced ? "in a synced folder" : PlacePhrase(place, path, mail);
            return (id == "dotenv" ? ".env file" : kind) + " " + phrase;
        }

        static string Advice(Place place, string id)
        {
            switch (place)
            {
                case Place.Downloads: return "A copy in Downloads is easy to forget.";
                case Place.Desktop: return "A copy on the Desktop is easy to forget, and easy to show in a screen share.";
                case Place.Synced: return "Syncing puts a copy of it on the provider's servers too.";
                case Place.HomeFolder:
                    return IsKey(id) ? "If you still use it, keeping it with your other keys in .ssh or in a password manager is tidier."
                        : "If you still use it, keeping it in its tool's folder or in a password manager is tidier.";
                case Place.Temp: return "Temporary folders are often left behind after an install or an unzip.";
                case Place.ExternalDrive: return "External drives are easy to lose or lend.";
                case Place.Repository: return "Protect does not check git yet, so it cannot tell whether this file is committed.";
                default: return "This is not where its tool keeps it.";
            }
        }

        // The reason on a credential card: one or two calm sentences about what the file is and where it is.
        public static string CredentialReason(string id, string kind, string name, Place place, string path, bool mail)
        {
            string fixedText;
            if (Overrides.TryGetValue(id + "|" + place, out fixedText)) return fixedText;
            string advice = Advice(place, id);
            if (id == "ssh-key")
                return name + " is the usual name for an SSH private key. Keys normally live in your .ssh folder. " + advice;
            // The title already says what and where, so the reason starts with the explanation.
            if (id == "pem-key") return "Protect read only its name and size. " + advice;
            if (id == "dotenv") return "These files often hold API keys. " + advice;
            string what;
            What.TryGetValue(id, out what);
            if (id == "password-export" && place != Place.Synced && !string.IsNullOrEmpty(what)) return what;
            return string.IsNullOrEmpty(what) ? advice : what + " " + advice;
        }

        public static string VaultReason(Place place, string path, bool keePass)
        {
            string what = (keePass ? "KeePass files" : "Vault files") + " are encrypted by design, so this is not exposed by itself.";
            switch (place)
            {
                case Place.Downloads: return what + " Downloads is a place where copies get forgotten.";
                case Place.Desktop: return what + " The Desktop is a place where copies get forgotten.";
                case Place.Temp: return what + " Temporary folders are a place where copies get forgotten.";
                case Place.Repository: return what + " Protect does not check git yet, so it cannot tell whether this file is committed.";
                default: return what;
            }
        }

        public static string DocumentReason(Place place, bool mail)
        {
            if (mail) return "Windows Mail kept a copy of attachments you opened.";
            const string lead = "Matched by file name. Nothing was opened. ";
            switch (place)
            {
                case Place.Downloads: return lead + "Downloads is often cleared or shared; Documents is a better home, and its copies are checked below.";
                case Place.Desktop: return lead + "The Desktop is often in view and easy to share; Documents is a better home, and its copies are checked below.";
                case Place.Temp: return lead + "Temporary folders are often left behind after an unzip; Documents is a better home.";
                case Place.Synced: return lead + "This folder syncs to your cloud account.";
                case Place.HomeFolder: return lead + "Documents is a better home than the user folder itself, and its copies are checked below.";
                case Place.ExternalDrive: return lead + "External drives are easy to lose or lend.";
                case Place.Repository: return lead + "Protect does not check git yet, so it cannot tell whether these files are committed.";
                default: return lead.TrimEnd();
            }
        }

        public static string UsualText(string id)
        {
            string text;
            if (Usual.TryGetValue(id, out text)) return text;
            return IsDocument(id) ? "Kept in your Documents or Pictures folder." : "This is where its tool keeps it. This is normal.";
        }

        // The tier chip is "warn" only for a named password export, or an SSH or pem key in Downloads, Desktop or a
        // synced folder. Nothing on the page uses the danger color.
        public static string TierVariant(Finding f, string baseName)
        {
            if (f.PatternId == "password-export")
            {
                string b = (baseName ?? "").ToLowerInvariant();
                return b == "passwords.csv" || b == "logins.csv" ? "" : "warn";
            }
            if ((f.PatternId == "ssh-key" || f.PatternId == "pem-key") &&
                (f.Place == Place.Downloads || f.Place == Place.Desktop || f.Place == Place.Synced))
                return "warn";
            return "";
        }

        // The order of cards in To review.
        public static int PlaceRank(Place place)
        {
            switch (place)
            {
                case Place.Downloads: return 0;
                case Place.Desktop: return 1;
                case Place.Temp: return 2;
                case Place.Synced: return 3;
                case Place.HomeFolder: return 4;
                case Place.ExternalDrive: return 5;
                case Place.Other: return 6;
                case Place.Repository: return 7;
                default: return 8;
            }
        }

        // Labels for the rows of the usual-place card, by the tool home a file sits in.
        public static string ToolLabel(string first, string second)
        {
            switch ((first ?? "").ToLowerInvariant())
            {
                case ".ssh": return ".ssh";
                case ".minikube": return "minikube";
                case ".aws": return "AWS CLI";
                case ".azure": return "Azure CLI";
                case ".kube": return ".kube";
                case ".docker": return "Docker";
                case ".android": return "Android";
                case ".gnupg": return "GnuPG";
                case ".vagrant.d": return "Vagrant";
                case ".codex": return "Codex";
                case ".claude": return "Claude Code";
                case ".config":
                    string s = (second ?? "").ToLowerInvariant();
                    return s == "gh" ? "GitHub CLI" : s == "gcloud" ? "Google Cloud CLI" : ".config";
                default: return first;
            }
        }

        public static string RoamingLabel(string first)
        {
            switch ((first ?? "").ToLowerInvariant())
            {
                case "gcloud": return "Google Cloud CLI";
                case "github cli": return "GitHub CLI";
                case "terraform.d": return "Terraform";
                case "microsoft": return ".NET user secrets";
                case "gnupg": return "GnuPG";
                case "postgresql": return "PostgreSQL";
                default: return first;
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Threading;

namespace DiskSpace
{
    // The Protect page: findings by name, grouped into cards, and whether the large personal folders have a copy
    // on another drive. This file is under tools\check-trust.ps1: it changes nothing on disk except protect.json
    // (through ProtectStore.Save), reads no file contents, and hands copies and checks to the Move page's flows.
    sealed partial class MainWindow
    {
        StackPanel protectInfo, protectResults, protectCoverageBusy, protectHiddenLine, protectHiddenPanel;
        Border protectNoScan;
        TextBlock protectToReview, protectNote, protectKeys, protectDocs, protectNoCopy, protectEmpty, protectHiddenText;
        TextBlock protectCoverageHeadline, protectCoverageNote;
        ItemsControl protectFindings, protectHiddenList, protectCoverageList;
        Button protectShowHidden;

        ProtectStore protectStore;
        CoverageReport coverage;
        CancellationTokenSource coverageCts;
        readonly Dictionary<string, CopyCheck> coverageCache = new Dictionary<string, CopyCheck>();
        bool showHidden;
        Task coverageTask;              // the snapshot waits on it
        bool coverageRunning;
        string protectHome;             // --protect-home <dir>: scan with ProtectContext.ForTree(dir)
        bool snapExpandFirst, snapExpandUsual;
        List<ProtectCardVm> protectCards = new List<ProtectCardVm>();

        // One finding as the page works with it, with the node it was found on (null after a partial rescan).
        sealed class ProtectEntry
        {
            public Finding F;
            public Node N;
            public string Path, Name, Base;
            public long Size = -1, LastWrite;
            public bool OnlineOnly, Mail;
            public readonly List<ProtectEntry> Twins = new List<ProtectEntry>();  // same name and size on other drives
        }

        void WireProtect()
        {
            ReadProtectArgs();
            protectStore = LoadProtectStore();
            protectInfo = E<StackPanel>("ProtectInfo");
            protectResults = E<StackPanel>("ProtectResults");
            protectCoverageBusy = E<StackPanel>("ProtectCoverageBusy");
            protectHiddenLine = E<StackPanel>("ProtectHiddenLine");
            protectHiddenPanel = E<StackPanel>("ProtectHiddenPanel");
            protectNoScan = E<Border>("ProtectNoScan");
            protectToReview = E<TextBlock>("ProtectToReview");
            protectNote = E<TextBlock>("ProtectNote");
            protectKeys = E<TextBlock>("ProtectKeys");
            protectDocs = E<TextBlock>("ProtectDocs");
            protectNoCopy = E<TextBlock>("ProtectNoCopy");
            protectEmpty = E<TextBlock>("ProtectEmpty");
            protectHiddenText = E<TextBlock>("ProtectHiddenText");
            protectCoverageHeadline = E<TextBlock>("ProtectCoverageHeadline");
            protectCoverageNote = E<TextBlock>("ProtectCoverageNote");
            protectFindings = E<ItemsControl>("ProtectFindings");
            protectHiddenList = E<ItemsControl>("ProtectHiddenList");
            protectCoverageList = E<ItemsControl>("ProtectCoverage");
            protectShowHidden = E<Button>("ProtectShowHidden");

            E<Button>("ProtectScanButton").Click += (s, e) => StartScan(SystemDriveRoot());
            protectShowHidden.Click += (s, e) =>
            {
                // Only the hidden list opens or closes; the cards are not drawn again.
                showHidden = !showHidden;
                protectShowHidden.Content = showHidden ? "Hide the list" : "Show hidden";
                protectHiddenPanel.Visibility = showHidden ? Visibility.Visible : Visibility.Collapsed;
            };
            protectFindings.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler(OnProtectClick));
            protectFindings.MouseRightButtonUp += OnProtectRightClick;
            protectHiddenList.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler(OnProtectHiddenClick));
            protectCoverageList.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler(OnCoverageClick));
            protectCoverageList.MouseRightButtonUp += (s, e) =>
            {
                var vm = DataOf<ProtectFolderVm>(e);
                if (vm == null || vm.Coverage == null || vm.Coverage.Source == null) return;
                DirNode d = vm.Coverage.Source.Node;
                if (d != null && Attached(d)) ShowMenu(d, protectCoverageList);
                e.Handled = true;
            };
            RenderProtectInfo();
            RefreshProtect();
        }

        // --protect-home is read from the raw command line, so App.cs stays unchanged. Its value would otherwise
        // be taken for the path to scan, so the scan path is worked out again without it.
        void ReadProtectArgs()
        {
            string[] args = Environment.GetCommandLineArgs();
            string scanPath = null;
            for (int i = 1; i < args.Length; i++)
            {
                string a = args[i];
                bool hasNext = i + 1 < args.Length;
                if (a == "--protect-home" && hasNext) { protectHome = args[++i]; continue; }
                if (hasNext && (a == "--snapshot" || a == "--page" || a == "--explore" || a == "--select" || a == "--dialog" ||
                                a == "--highlight" || a == "--theme")) { i++; continue; }
                if (!a.StartsWith("--", StringComparison.Ordinal)) scanPath = a;
            }
            if (protectHome != null) options.ScanPath = scanPath;
        }

        static ProtectStore LoadProtectStore()
        {
            try { return ProtectStore.Load(ProtectStore.DefaultPath); }
            catch (Exception) { return new ProtectStore(); }
        }

        void SaveProtectStore()
        {
            if (options.Snapshot != null) return;  // a snapshot never changes the user's settings
            Try(() => protectStore.Save(ProtectStore.DefaultPath));
        }

        static string SystemDriveRoot()
        {
            string root = System.IO.Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            return string.IsNullOrEmpty(root) ? "C:\\" : root;
        }

        // The context Analyze uses, built once per scan on the scan's worker thread.
        ProtectContext ProtectContextFor(string path, List<DriveProfile> drives)
        {
            try
            {
                if (protectHome != null) return ProtectContext.ForTree(protectHome);
                return ProtectContext.ForMachine(path, Placement.ExternalRoots(drives));
            }
            catch (Exception)
            {
                return null;  // Protect is off for this scan; the rest of the app is unaffected
            }
        }

        void RenderProtectInfo()
        {
            protectInfo.Children.Clear();
            foreach (InfoSection s in ProtectInfo.Describe())
            {
                var body = new StackPanel();
                body.Children.Add(new TextBlock { Text = s.Title, Style = (Style)Res("BodyStrong"), FontSize = 15 });
                foreach (string line in s.Lines)
                    body.Children.Add(new TextBlock
                    {
                        // A word joiner before each backslash keeps a folder name such as .config\gcloud on one line,
                        // and a zero-width space lets a list of dot names (", .ssh") wrap between its items, where
                        // WPF otherwise never breaks before a full stop.
                        Text = line.Replace("\\", "⁠\\").Replace(", .", ", ​."),
                        Style = (Style)Res("BodySecondary"),
                        FontSize = 13,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 8, 0, 0)
                    });
                protectInfo.Children.Add(new Border
                {
                    Style = (Style)Res("Card"),
                    Margin = new Thickness(0, 0, 0, 12),
                    Padding = new Thickness(20, 16, 20, 18),
                    Child = body
                });
            }
        }

        // ---------------------------------------------------------------- Drawing

        void RefreshProtect()
        {
            if (protectFindings == null) return;
            bool scanned = result != null;
            protectNoScan.Visibility = scanned ? Visibility.Collapsed : Visibility.Visible;
            protectResults.Visibility = scanned ? Visibility.Visible : Visibility.Collapsed;
            if (!scanned)
            {
                protectFindings.ItemsSource = null;
                protectCoverageList.ItemsSource = null;
                return;
            }

            ProtectContext ctx = result.Protect;
            List<ProtectEntry> hidden;
            List<ProtectEntry> visible = ProtectEntries(out hidden);

            var usual = new List<ProtectEntry>();
            var projects = new List<ProtectEntry>();
            var docs = new List<ProtectEntry>();
            var creds = new List<ProtectEntry>();
            foreach (ProtectEntry e in visible)
            {
                string id = e.F.PatternId;
                Place p = e.F.Place;
                bool vault = id == "password-vault";
                if (id == "dotenv" && p == Place.Repository) projects.Add(e);
                else if (p == Place.UsualPlace || (vault && p != Place.Downloads && p != Place.Desktop && p != Place.Temp && p != Place.Repository))
                    usual.Add(e);
                else if (vault || ProtectWording.IsDocument(id)) docs.Add(e);
                else creds.Add(e);
            }

            var review = new List<ProtectCardVm>();
            foreach (ProtectEntry e in MergeTwins(creds, true)) review.Add(CredentialCard(e, ctx));
            review.AddRange(DocumentCards(docs, ctx));
            review.Sort((a, b) =>
            {
                int c = ProtectWording.PlaceRank(a.SortPlace).CompareTo(ProtectWording.PlaceRank(b.SortPlace));
                if (c != 0) return c;
                c = ((int)a.SortTier).CompareTo((int)b.SortTier);
                return c != 0 ? c : b.SortBytes.CompareTo(a.SortBytes);
            });
            // --dialog protect-expand: the first card that has a list to open.
            if (snapExpandFirst)
                foreach (ProtectCardVm c in review)
                    if (c.ItemsVisibility == Visibility.Visible) { c.Expanded = true; break; }

            var summary = new ProtectSummaryVm { ToReview = review.Count };
            foreach (ProtectCardVm c in review)
            {
                if (c.Group == "doc") summary.Documents++;
                else summary.Keys++;
                summary.Files += c.Findings.Count;
            }
            summary.Note = summary.ToReview == 0 ? "Nothing needs a look."
                : "Found by file name and location in " + Fmt.Count(summary.Files) + (summary.Files == 1 ? " file" : " files") + ". Nothing was opened.";
            summary.NoCopyText = NoCopyText();

            var cards = new List<ProtectCardVm>(review);
            if (usual.Count > 0) cards.Add(UsualCard(usual, ctx));
            if (projects.Count > 0) cards.Add(ProjectsCard(projects));
            // A list the user opened stays open when the page is drawn again (after Hide, Trust, Undo, a theme
            // change or the backup check).
            var opened = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ProtectCardVm c in protectCards) if (c.Expanded) opened.Add(CardKey(c));
            foreach (ProtectCardVm c in cards)
            {
                if (opened.Contains(CardKey(c))) c.Expanded = true;
                if (c.ItemsVisibility != Visibility.Visible) c.Expanded = false;
            }
            protectCards = cards;
            protectFindings.ItemsSource = cards;

            protectToReview.Text = Fmt.Count(summary.ToReview);
            protectNote.Text = summary.Note;
            protectKeys.Text = Fmt.Count(summary.Keys);
            protectDocs.Text = Fmt.Count(summary.Documents);
            protectNoCopy.Text = summary.NoCopyText;
            protectCoverageBusy.Visibility = coverageRunning ? Visibility.Visible : Visibility.Collapsed;

            if (review.Count > 0) protectEmpty.Visibility = Visibility.Collapsed;
            else
            {
                protectEmpty.Visibility = Visibility.Visible;
                protectEmpty.Text = visible.Count == 0 && hidden.Count > 0
                    ? "Nothing to show. " + Fmt.Count(hidden.Count) + (hidden.Count == 1 ? " finding is" : " findings are") + " hidden by you."
                    : "Nothing to review. Protect checked the names of " + Fmt.Count(result.Root.FileCount) + " files.";
            }

            RefreshHidden(hidden);
            RefreshCoverageSection();
        }

        // What identifies a card from one drawing to the next.
        static string CardKey(ProtectCardVm c)
        {
            if (c.Group == "usual" || c.Group == "projects") return c.Group;
            return c.Group + "|" + (c.ActionPath ?? c.Path ?? c.Title);
        }

        List<ProtectEntry> ProtectEntries(out List<ProtectEntry> hidden)
        {
            var visible = new List<ProtectEntry>();
            hidden = new List<ProtectEntry>();
            if (result == null || result.Findings == null) return visible;
            for (int i = 0; i < result.Findings.Count; i++)
            {
                Finding f = result.Findings[i];
                if (f == null || f.Path == null) continue;
                Node n = result.FindingNodes != null && i < result.FindingNodes.Count ? result.FindingNodes[i] : null;
                if (n != null && !Attached(n)) n = null;
                var e = new ProtectEntry { F = f, N = n, Path = f.Path, Name = LastSegment(f.Path) };
                if (n != null)
                {
                    var file = n as FileNode;
                    e.Size = n.Size;
                    e.LastWrite = n.LastWrite;
                    e.OnlineOnly = file != null && (file.Flags & FileFlags.OnlineOnly) != 0;
                }
                e.Base = SafeBaseName(e.Name);
                e.Mail = SafeIsMail(f.Path);
                if (protectStore.IsHidden(f)) hidden.Add(e);
                else visible.Add(e);
            }
            return visible;
        }

        static string SafeBaseName(string name)
        {
            try { return ProtectNames.BaseName(name) ?? name; }
            catch (Exception) { return name; }
        }

        static bool SafeIsMail(string path)
        {
            try { return ProtectNames.IsMailAttachment(path); }
            catch (Exception) { return false; }
        }

        // Findings with the same base name and size on different drives become one card or row.
        static List<ProtectEntry> MergeTwins(List<ProtectEntry> list, bool samePattern)
        {
            // Primaries are indexed by size, name and (when asked) pattern, so each entry looks only at its own
            // bucket: thousands of same-size names (online-only files are all size 0) stay linear.
            var primary = new List<ProtectEntry>();
            var buckets = new Dictionary<string, List<ProtectEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (ProtectEntry e in list)
            {
                e.Twins.Clear();
                ProtectEntry home = null;
                List<ProtectEntry> bucket = null;
                if (e.Size >= 0)
                {
                    string key = e.Size.ToString(System.Globalization.CultureInfo.InvariantCulture) + "|" +
                                 (samePattern ? e.F.PatternId : "") + "|" + (e.Base ?? "");
                    if (!buckets.TryGetValue(key, out bucket))
                    {
                        bucket = new List<ProtectEntry>();
                        buckets.Add(key, bucket);
                    }
                    foreach (ProtectEntry p in bucket)
                    {
                        bool otherDrive = !SameDrive(p.Path, e.Path);
                        foreach (ProtectEntry t in p.Twins) otherDrive = otherDrive && !SameDrive(t.Path, e.Path);
                        if (!otherDrive) continue;
                        home = p;
                        break;
                    }
                }
                if (home != null) home.Twins.Add(e);
                else
                {
                    primary.Add(e);
                    if (bucket != null) bucket.Add(e);
                }
            }
            return primary;
        }

        static bool SameDrive(string a, string b)
        {
            return string.Equals(DriveLetter(a), DriveLetter(b), StringComparison.OrdinalIgnoreCase);
        }

        static string DriveLetter(string path)
        {
            if (path == null) return "";
            if (path.StartsWith("\\\\", StringComparison.Ordinal))
            {
                int cut = path.IndexOf('\\', 2);
                cut = cut < 0 ? -1 : path.IndexOf('\\', cut + 1);
                return cut < 0 ? path : path.Substring(0, cut);
            }
            return path.Length >= 2 && path[1] == ':' ? path.Substring(0, 2) : "";
        }

        // ---- Credential cards: one per file

        ProtectCardVm CredentialCard(ProtectEntry e, ProtectContext ctx)
        {
            Finding f = e.F;
            var all = new List<ProtectEntry> { e };
            all.AddRange(e.Twins);
            string kind = f.Kind;
            var card = new ProtectCardVm
            {
                Group = "cred",
                Glyph = ProtectWording.Glyph(f.PatternId),
                Title = ProtectWording.CredentialTitle(f.PatternId, kind, f.Place, f.Path, e.Mail),
                Reason = ProtectWording.CredentialReason(f.PatternId, kind, e.Name, f.Place, f.Path, e.Mail),
                Lines = new List<string>(),
                Chips = new List<ProtectChipVm>(),
                Path = f.Path,
                ActionPath = f.Path,
                Node = e.N,
                Findings = new List<Finding>(),
                SortPlace = f.Place,
                SortTier = f.Tier,
                SortBytes = Math.Max(0, e.Size)
            };
            foreach (ProtectEntry t in e.Twins) card.Lines.Add("Also at " + t.Path);
            foreach (ProtectEntry x in all)
            {
                card.Findings.Add(x.F);
                if ((int)x.F.Tier < (int)card.SortTier) card.SortTier = x.F.Tier;
            }
            card.Chips.Add(new ProtectChipVm(ProtectWording.TierText(card.SortTier), ProtectWording.TierVariant(f, e.Base)));
            card.Chips.Add(new ProtectChipVm(ProtectWording.PlaceChip(f.Place, f.Path, e.Mail), null));
            if (f.PatternId == "password-vault") card.Chips.Add(new ProtectChipVm("Encrypted", null));
            AddSizeChips(card.Chips, e);
            card.TrustFolder = f.Place == Place.Repository ? RepoRoot(e) : ParentOf(f.Path);
            SetPrimary(card, ProtectWording.CanOpen(f.PatternId));
            SetItems(card, all.Count > 1 ? Rows(all) : new List<ProtectItemVm>());
            return card;
        }

        void AddSizeChips(List<ProtectChipVm> chips, ProtectEntry e)
        {
            if (e.N == null) return;
            if (e.OnlineOnly) chips.Add(new ProtectChipVm("Online-only", null));
            else chips.Add(new ProtectChipVm(Fmt.Size(e.Size), null));
            string date = Fmt.Date(e.LastWrite);
            if (date.Length > 0) chips.Add(new ProtectChipVm("Modified " + date, null));
        }

        static void SetPrimary(ProtectCardVm card, bool open)
        {
            card.PrimaryText = open ? "Open" : "Show in Explorer";
            card.PrimaryTag = open ? "protect-open" : "protect-show";
            card.ShowLinkVisibility = open ? Visibility.Visible : Visibility.Collapsed;
            card.ActionsVisibility = Visibility.Visible;
        }

        static void SetItems(ProtectCardVm card, List<ProtectItemVm> items)
        {
            card.Items = items;
            card.ItemsLabel = "Show " + Fmt.Count(items.Count) + (items.Count == 1 ? " file" : " files");
            card.ItemsVisibility = items.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            card.LinesVisibility = card.Lines != null && card.Lines.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            card.ChipsVisibility = card.Chips != null && card.Chips.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            card.PathVisibility = string.IsNullOrEmpty(card.Path) ? Visibility.Collapsed : Visibility.Visible;
        }

        List<ProtectItemVm> Rows(List<ProtectEntry> entries)
        {
            var rows = new List<ProtectItemVm>();
            foreach (ProtectEntry e in entries)
            {
                string kind = e.F.Kind;
                if (e.Twins.Count > 0)
                {
                    var also = new List<string>();
                    foreach (ProtectEntry t in e.Twins) also.Add(t.Path);
                    kind += "  ·  also at " + string.Join(", ", also.ToArray());
                }
                rows.Add(new ProtectItemVm
                {
                    Node = e.N,
                    Path = e.Path,
                    Icon = e.N == null ? null : ShellIcons.For(e.N, false),
                    Name = e.Name,
                    Kind = kind,
                    Folder = ParentOf(e.Path),
                    SizeText = SizeText(e),
                    OpenVisibility = ProtectWording.CanOpen(e.F.PatternId) ? Visibility.Visible : Visibility.Collapsed,
                    TrustVisibility = Visibility.Collapsed
                });
            }
            return rows;
        }

        static string SizeText(ProtectEntry e)
        {
            if (e.N == null) return "";
            return e.OnlineOnly ? "online-only" : Fmt.Size(e.Size);
        }

        // ---- Document and vault cards: one per (top folder, family)

        List<ProtectCardVm> DocumentCards(List<ProtectEntry> docs, ProtectContext ctx)
        {
            var cards = new List<ProtectCardVm>();
            var order = new List<string>();
            var groups = new Dictionary<string, List<ProtectEntry>>(StringComparer.Ordinal);
            var folders = new Dictionary<string, ProtectEntry>(StringComparer.Ordinal);   // Scanned Documents folder findings

            foreach (ProtectEntry e in docs)
            {
                if (e.F.PatternId != "doc-scans-folder") continue;
                string key = "scans|" + Norm(e.Path);
                folders[key] = e;
                order.Add(key);
                groups[key] = new List<ProtectEntry>();
            }
            foreach (ProtectEntry e in docs)
            {
                if (e.F.PatternId == "doc-scans-folder") continue;
                string key = null;
                string np = Norm(e.Path);
                foreach (KeyValuePair<string, ProtectEntry> sf in folders)
                {
                    if (!np.StartsWith(Norm(sf.Value.Path) + "\\", StringComparison.Ordinal)) continue;
                    key = sf.Key;
                    break;
                }
                if (key == null)
                    key = e.Mail ? "mail" : Norm(TopFolder(e.Path, ctx)) + "|" + ProtectWording.Family(e.F.PatternId);
                List<ProtectEntry> list;
                if (!groups.TryGetValue(key, out list))
                {
                    list = new List<ProtectEntry>();
                    groups[key] = list;
                    order.Add(key);
                }
                list.Add(e);
            }

            foreach (string key in order)
            {
                ProtectEntry folder;
                folders.TryGetValue(key, out folder);
                cards.Add(DocumentCard(key, groups[key], folder, ctx));
            }
            return cards;
        }

        ProtectCardVm DocumentCard(string key, List<ProtectEntry> files, ProtectEntry scans, ProtectContext ctx)
        {
            List<ProtectEntry> rowsOf = MergeTwins(files, false);
            var all = new List<ProtectEntry>();
            if (scans != null) all.Add(scans);
            all.AddRange(files);
            ProtectEntry first = all[0];
            bool mail = key == "mail";
            bool vault = first.F.PatternId == "password-vault";

            string folderPath = scans != null ? scans.Path : mail ? CommonFolder(all) : TopFolder(first.Path, ctx);
            var families = new List<string>();
            Place place = first.F.Place;
            FindingTier tier = first.F.Tier;
            long bytes = 0, newest = 0;
            var findings = new List<Finding>();
            foreach (ProtectEntry e in all)
            {
                findings.Add(e.F);
                string fam = ProtectWording.Family(e.F.PatternId);
                if (fam != "scans" && !families.Contains(fam)) families.Add(fam);
                if (ProtectWording.PlaceRank(e.F.Place) < ProtectWording.PlaceRank(place)) place = e.F.Place;
                if ((int)e.F.Tier < (int)tier) tier = e.F.Tier;
                if (e != scans) bytes += Math.Max(0, e.Size);
                if (e.LastWrite > newest) newest = e.LastWrite;
            }
            if (scans != null && scans.N != null) bytes = Math.Max(bytes, scans.N.Size);

            string display = mail ? "Mail app attachments" : DisplayFolder(folderPath, ctx);
            string title;
            if (scans != null) title = "Scanned Documents folder in " + DisplayFolder(ParentOf(scans.Path), ctx);
            else if (vault && rowsOf.Count == 1) title = "Password vault " + ProtectWording.PlacePhrase(place, first.Path, false);
            else title = ProtectWording.FamilyCount(families, rowsOf.Count) + " in " + display;

            string reason;
            if (vault)
            {
                string ext = System.IO.Path.GetExtension(first.Name) ?? "";
                bool keePass = ext.Equals(".kdbx", StringComparison.OrdinalIgnoreCase) || ext.Equals(".kdb", StringComparison.OrdinalIgnoreCase);
                reason = ProtectWording.VaultReason(place, first.Path, keePass);
            }
            else reason = ProtectWording.DocumentReason(place, mail);

            var card = new ProtectCardVm
            {
                Group = vault ? "vault" : "doc",
                Glyph = vault ? ProtectWording.GlyphVault : ProtectWording.GlyphDocument,
                Title = title,
                Reason = reason,
                Lines = new List<string>(),
                Chips = new List<ProtectChipVm>(),
                Path = all.Count == 1 && !mail ? first.Path : folderPath,
                ActionPath = rowsOf.Count == 1 && scans == null ? rowsOf[0].Path : folderPath,
                Node = rowsOf.Count == 1 && scans == null ? rowsOf[0].N : FolderNode(folderPath),
                Findings = findings,
                TrustFolder = place == Place.Repository ? RepoRoot(first) : mail ? AttachmentsFolder(first.Path) : folderPath,
                SortPlace = place,
                SortTier = tier,
                SortBytes = bytes
            };
            if (scans != null && files.Count > 0)
                card.Lines.Add("It also holds " + ProtectWording.FamilyCount(families, rowsOf.Count) + " matched by name.");
            string copyLine = CoverageLine(folderPath);
            if (copyLine != null) card.Lines.Add(copyLine);

            card.Chips.Add(new ProtectChipVm(ProtectWording.TierText(tier), ProtectWording.TierVariant(first.F, first.Base)));
            card.Chips.Add(new ProtectChipVm(ProtectWording.PlaceChip(place, first.Path, mail), null));
            if (vault) card.Chips.Add(new ProtectChipVm("Encrypted", null));
            if (all.Count == 1) AddSizeChips(card.Chips, first);
            else
            {
                if (bytes > 0) card.Chips.Add(new ProtectChipVm(Fmt.Size(bytes), null));
                string date = Fmt.Date(newest);
                if (date.Length > 0) card.Chips.Add(new ProtectChipVm("Newest " + date, null));
            }
            SetPrimary(card, true);
            List<ProtectItemVm> rows = Rows(rowsOf);
            SetItems(card, rows.Count > 1 || scans != null ? rows : new List<ProtectItemVm>());
            if (rows.Count > 0) card.ItemsLabel = "Show " + Fmt.Count(rows.Count) + (rows.Count == 1 ? " file" : " files");
            return card;
        }

        // The card line that links a document folder to its backup check.
        string CoverageLine(string folderPath)
        {
            FolderCoverage fc = CoverageOf(folderPath);
            if (fc == null) return null;
            switch (fc.State)
            {
                case CoverageState.TwoDrives:
                    return "Second copy: on " + CopyDriveText(fc) + ", same files and sizes.";
                case CoverageState.CopyDiffers:
                    return "A copy on " + CopyDriveText(fc) + " differs from this folder.";
                case CoverageState.OneCopy:
                    return "No current copy on the drives connected now.";
                default:
                    return null;
            }
        }

        FolderCoverage CoverageOf(string folderPath)
        {
            if (coverage == null || coverage.Folders == null || folderPath == null) return null;
            string n = Norm(folderPath);
            foreach (FolderCoverage fc in coverage.Folders)
                if (fc.Source != null && fc.Source.Path != null && Norm(fc.Source.Path) == n) return fc;
            return null;
        }

        static string CopyDriveText(FolderCoverage fc)
        {
            CoverageDrive d = fc.Best == null ? null : fc.Best.Drive;
            string letter = d != null && d.Root != null ? d.Root.TrimEnd('\\') : fc.Best != null ? DriveLetter(fc.Best.Path) : "another drive";
            return letter + (d == null ? "" : d.External ? " (External)" : " (Internal)");
        }

        // ---- The two collapsed cards

        ProtectCardVm UsualCard(List<ProtectEntry> usual, ProtectContext ctx)
        {
            var order = new List<string>();
            var groups = new Dictionary<string, List<ProtectEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (ProtectEntry e in usual)
            {
                string label = UsualLabel(e, ctx);
                List<ProtectEntry> list;
                if (!groups.TryGetValue(label, out list))
                {
                    list = new List<ProtectEntry>();
                    groups[label] = list;
                    order.Add(label);
                }
                list.Add(e);
            }
            var rows = new List<ProtectItemVm>();
            var findings = new List<Finding>();
            foreach (string label in order)
            {
                List<ProtectEntry> list = groups[label];
                foreach (ProtectEntry e in list) findings.Add(e.F);
                rows.Add(UsualRow(label, list, ctx));
            }
            var card = new ProtectCardVm
            {
                Group = "usual",
                Glyph = ProtectWording.GlyphVault,
                Title = "In their usual places (" + Fmt.Count(usual.Count) + ")",
                Reason = ProtectWording.UsualHeader,
                Lines = new List<string>(),
                Chips = new List<ProtectChipVm>(),
                Findings = findings,
                Expanded = snapExpandUsual,
                ActionsVisibility = Visibility.Collapsed,
                ShowLinkVisibility = Visibility.Collapsed
            };
            SetItems(card, rows);
            card.ItemsLabel = "Show " + Fmt.Count(usual.Count) + (usual.Count == 1 ? " file" : " files");
            return card;
        }

        ProtectItemVm UsualRow(string label, List<ProtectEntry> list, ProtectContext ctx)
        {
            ProtectEntry first = list[0];
            if (list.Count == 1)
            {
                return new ProtectItemVm
                {
                    Node = first.N,
                    Path = first.Path,
                    Icon = first.N == null ? null : ShellIcons.For(first.N, false),
                    Name = string.Equals(label, first.Name, StringComparison.OrdinalIgnoreCase) ? first.Name : label + ": " + first.Name,
                    Kind = UsualRowText(first, ctx),
                    Folder = ParentOf(first.Path),
                    SizeText = SizeText(first),
                    OpenVisibility = ProtectWording.CanOpen(first.F.PatternId) ? Visibility.Visible : Visibility.Collapsed,
                    TrustVisibility = Visibility.Collapsed
                };
            }
            bool docs = true, keys = true, sameId = true;
            long bytes = 0;
            var names = new List<string>();
            foreach (ProtectEntry e in list)
            {
                docs = docs && ProtectWording.IsDocument(e.F.PatternId);
                keys = keys && ProtectWording.IsKey(e.F.PatternId);
                sameId = sameId && e.F.PatternId == first.F.PatternId;
                bytes += Math.Max(0, e.Size);
                if (names.Count < 6) names.Add(e.Name);
            }
            int n = list.Count;
            string what = docs ? n + " personal documents" : keys ? n + " keys" : n + " files";
            // The row's text speaks for every file in it, so the OneDrive and synced lines are used only when they
            // hold for all of them: otherwise an entry without them gives the text.
            ProtectEntry plain = first;
            foreach (ProtectEntry e in list)
                if (UsualRowText(e, ctx) != UsualRowText(first, ctx)) { plain = PlainEntry(list, ctx); break; }
            string kind = sameId || docs ? UsualRowText(plain, ctx)
                : label == ".ssh" && keys ? "SSH keeps your keys here. This is normal."
                : "Kept where their tools keep them. This is normal.";
            string folder = CommonFolder(list);
            Node node = FolderNode(folder);
            return new ProtectItemVm
            {
                Node = node,
                Path = folder,
                Icon = node == null ? null : ShellIcons.For(node, false),
                Name = label + ": " + what,
                Kind = kind,
                Folder = string.Join(", ", names.ToArray()) + (n > names.Count ? ", …" : ""),
                SizeText = Fmt.Size(bytes),
                OpenVisibility = Visibility.Collapsed,
                TrustVisibility = Visibility.Collapsed
            };
        }

        // An entry of the list whose row text is the tool's plain usual-place text, or the first one.
        static ProtectEntry PlainEntry(List<ProtectEntry> list, ProtectContext ctx)
        {
            foreach (ProtectEntry e in list)
                if (UsualRowText(e, ctx) == ProtectWording.UsualText(e.F.PatternId)) return e;
            return list[0];
        }

        static string UsualRowText(ProtectEntry e, ProtectContext ctx)
        {
            string id = e.F.PatternId;
            if (ProtectWording.IsDocument(id) && ctx != null && ctx.OneDriveHint != null && Under(Norm(e.Path), ctx.OneDriveHint))
                return "Kept in Documents, in OneDrive's folder. OneDrive is not set up to sync this folder on this PC.";
            if (id == "password-vault" && e.F.Place == Place.Synced)
                return "Encrypted by design, so this is not exposed by itself. This folder syncs to the cloud.";
            return ProtectWording.UsualText(id);
        }

        // The row label in the usual-place card: the tool home, the known folder, or the file's own name.
        static string UsualLabel(ProtectEntry e, ProtectContext ctx)
        {
            string id = e.F.PatternId;
            if (id == "password-vault") return "Password vaults";
            string np = Norm(e.Path);
            if (ctx != null)
            {
                if (ProtectWording.IsDocument(id))
                {
                    foreach (string d in ctx.Documents) if (Under(np, d)) return "Documents";
                    foreach (string d in ctx.Pictures) if (Under(np, d)) return "Pictures";
                }
                string[] rel = RelativeSegments(e.Path, np, ctx.Roaming);
                if (rel != null && rel.Length > 1) return ProtectWording.RoamingLabel(rel[0]);
                rel = RelativeSegments(e.Path, np, ctx.Local);
                if (rel != null && rel.Length > 1) return rel[0];
                rel = RelativeSegments(e.Path, np, ctx.Home);
                if (rel != null)
                {
                    if (rel.Length == 1) return rel[0];
                    if (rel[0].StartsWith(".", StringComparison.Ordinal)) return ProtectWording.ToolLabel(rel[0], rel.Length > 2 ? rel[1] : null);
                    return rel[0];
                }
            }
            string parent = ParentOf(e.Path);
            return parent == null ? e.Name : LastSegment(parent);
        }

        // The segments of path below root (both compared normalized), in the path's own casing; null if not below.
        static string[] RelativeSegments(string path, string normalized, string root)
        {
            if (root == null || !Under(normalized, root)) return null;
            int start = root.EndsWith("\\", StringComparison.Ordinal) ? root.Length : root.Length + 1;
            if (start >= path.Length) return null;
            return path.Substring(start).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
        }

        ProtectCardVm ProjectsCard(List<ProtectEntry> projects)
        {
            var order = new List<string>();
            var groups = new Dictionary<string, List<ProtectEntry>>(StringComparer.OrdinalIgnoreCase);
            var findings = new List<Finding>();
            foreach (ProtectEntry e in projects)
            {
                findings.Add(e.F);
                string root = RepoRoot(e);
                List<ProtectEntry> list;
                if (!groups.TryGetValue(root, out list))
                {
                    list = new List<ProtectEntry>();
                    groups[root] = list;
                    order.Add(root);
                }
                list.Add(e);
            }
            var rows = new List<ProtectItemVm>();
            foreach (string root in order)
            {
                List<ProtectEntry> list = groups[root];
                var names = new List<string>();
                foreach (ProtectEntry e in list) names.Add(e.Name);
                Node node = FolderNode(root);
                rows.Add(new ProtectItemVm
                {
                    Node = node,
                    Path = root,
                    Icon = node == null ? null : ShellIcons.For(node, false),
                    Name = RepoDisplay(root) + ": " + string.Join(", ", names.ToArray()),
                    Kind = list.Count == 1 ? "1 environment file" : list.Count + " environment files",
                    Folder = root,
                    SizeText = "",
                    OpenVisibility = Visibility.Collapsed,
                    TrustVisibility = Visibility.Visible,
                    TrustFolder = root
                });
            }
            var card = new ProtectCardVm
            {
                Group = "projects",
                Glyph = ProtectWording.GlyphProject,
                Title = "In your projects (" + Fmt.Count(projects.Count) + ")",
                Reason = ProtectWording.ProjectsHeader,
                Lines = new List<string>(),
                Chips = new List<ProtectChipVm>(),
                Findings = findings,
                Expanded = false,
                ActionsVisibility = Visibility.Collapsed,
                ShowLinkVisibility = Visibility.Collapsed
            };
            SetItems(card, rows);
            card.ItemsLabel = "Show " + Fmt.Count(projects.Count) + (projects.Count == 1 ? " file" : " files");
            return card;
        }

        static string RepoRoot(ProtectEntry e)
        {
            string root = null;
            if (e.N != null)
            {
                try { root = ProtectNames.RepoRootOf(e.N); }
                catch (Exception) { root = null; }
            }
            return root ?? ParentOf(e.Path) ?? e.Path;
        }

        // "warden\mvp": the last two folder names of a project root.
        static string RepoDisplay(string root)
        {
            string[] parts = root.TrimEnd('\\').Split('\\');
            if (parts.Length >= 2 && !(parts.Length == 2 && parts[0].EndsWith(":", StringComparison.Ordinal)))
                return parts[parts.Length - 2] + "\\" + parts[parts.Length - 1];
            return root;
        }

        // ---- Hidden by you

        void RefreshHidden(List<ProtectEntry> hidden)
        {
            int dismissed = 0;
            var trustedFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var rows = new List<ProtectHiddenVm>();
            foreach (ProtectEntry e in hidden)
            {
                var row = new ProtectHiddenVm { Finding = e.F, Kind = e.F.Kind, Path = e.Path };
                if (protectStore.IsDismissed(e.F))
                {
                    dismissed++;
                    row.Note = "Hidden by you";
                }
                else
                {
                    string folder = null;
                    try { folder = protectStore.TrustedAncestor(e.Path); }
                    catch (Exception) { folder = null; }
                    if (folder != null) trustedFolders.Add(folder);
                    row.TrustedFolder = folder;
                    row.Note = "In trusted folder " + (folder ?? "");
                }
                rows.Add(row);
            }
            protectHiddenLine.Visibility = hidden.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            if (hidden.Count == 0) showHidden = false;
            var parts = new List<string>();
            if (dismissed > 0) parts.Add("hid " + Fmt.Count(dismissed) + (dismissed == 1 ? " item" : " items"));
            if (trustedFolders.Count > 0) parts.Add("trust " + Fmt.Count(trustedFolders.Count) + (trustedFolders.Count == 1 ? " folder" : " folders"));
            protectHiddenText.Text = parts.Count == 0 ? "" : "You " + string.Join(" and ", parts.ToArray()) + ".";
            protectShowHidden.Content = showHidden ? "Hide the list" : "Show hidden";
            protectHiddenPanel.Visibility = showHidden ? Visibility.Visible : Visibility.Collapsed;
            protectHiddenList.ItemsSource = rows;
        }

        // ---------------------------------------------------------------- Actions

        void OnProtectClick(object sender, RoutedEventArgs e)
        {
            var b = e.OriginalSource as Button;
            if (b == null) return;
            string tag = b.Tag as string;
            var card = b.DataContext as ProtectCardVm;
            var item = b.DataContext as ProtectItemVm;
            if (card != null)
            {
                string path = card.ActionPath ?? card.Path;
                if (tag == "protect-show" && path != null) Try(() => ShellOps.ShowInExplorer(path));
                else if (tag == "protect-open" && path != null) Try(() => ShellOps.Open(path));
                else if (tag == "protect-dismiss") DismissCard(card);
                else if (tag == "protect-trust") TrustCard(card);
            }
            else if (item != null)
            {
                if (tag == "item-show" && item.Path != null) Try(() => ShellOps.ShowInExplorer(item.Path));
                else if (tag == "item-open" && item.Path != null) Try(() => ShellOps.Open(item.Path));
                else if (tag == "item-trust" && item.TrustFolder != null) TrustWithDialog(item.TrustFolder);
            }
        }

        // Right-click on a card or a row opens the usual menu. A finding whose node is gone (after a partial
        // rescan) gets a menu with only "Copy path".
        void OnProtectRightClick(object sender, MouseButtonEventArgs e)
        {
            var element = e.OriginalSource as FrameworkElement;
            if (element == null) return;
            Node n = null;
            string path = null;
            bool canOpen;
            var item = element.DataContext as ProtectItemVm;
            var card = element.DataContext as ProtectCardVm;
            // Open (the file's own app) is offered only where the card or row offers it: documents and vaults.
            // A key, certificate or sign-in file gets Show in Explorer, since its app can run or import it.
            if (item != null) { n = item.Node; path = item.Path; canOpen = item.OpenVisibility == Visibility.Visible; }
            else if (card != null) { n = card.Node; path = card.ActionPath ?? card.Path; canOpen = card.PrimaryTag == "protect-open"; }
            else return;
            e.Handled = true;
            if (n != null && Attached(n))
            {
                ShowMenu(n, protectFindings, canOpen || n is DirNode);
                return;
            }
            if (path == null) return;
            var menu = new ContextMenu { PlacementTarget = protectFindings, Placement = PlacementMode.MousePoint };
            AddMenuItem(menu, "\uE8C8", "Copy path", true, () => CopyText(path));
            menu.IsOpen = true;
        }

        void CopyText(string path)
        {
            try
            {
                Clipboard.SetText(path);
                Toast("Path copied");
            }
            catch (Exception ex) { ShowError("Couldn't copy to the clipboard. " + ex.Message); }
        }

        void DismissCard(ProtectCardVm card)
        {
            if (card.Findings == null || card.Findings.Count == 0) return;
            var findings = new List<Finding>(card.Findings);
            foreach (Finding f in findings) protectStore.Dismiss(f);
            SaveProtectStore();
            RefreshProtect();
            Toast("Hidden from this list. The file was not changed.", "\uED1A", "Undo", () =>
            {
                foreach (Finding f in findings) protectStore.Undismiss(f);
                SaveProtectStore();
                RefreshProtect();
            });
        }

        void TrustCard(ProtectCardVm card)
        {
            if (card.TrustFolder != null) TrustWithDialog(card.TrustFolder);
        }

        Task<bool> ShowTrustDialog(string folder)
        {
            return ShowDialog("Trust this folder?",
                Paragraph("Protect will stop listing anything it finds in " + folder + " and the folders inside it. " +
                          "Only this list changes. The files are not touched.", 14),
                "Trust folder", "Cancel", false);
        }

        async void TrustWithDialog(string folder)
        {
            if (!await ShowTrustDialog(folder)) return;
            protectStore.Trust(folder);
            SaveProtectStore();
            RefreshProtect();
            Toast("Protect no longer lists anything in " + LastSegment(folder) + ". The files were not changed.", "\uE73E", "Undo", () =>
            {
                protectStore.Untrust(folder);
                SaveProtectStore();
                RefreshProtect();
            });
        }

        void OnProtectHiddenClick(object sender, RoutedEventArgs e)
        {
            var b = e.OriginalSource as Button;
            var vm = b == null ? null : b.DataContext as ProtectHiddenVm;
            if (vm == null || !"hidden-show".Equals(b.Tag)) return;
            if (protectStore.IsDismissed(vm.Finding)) protectStore.Undismiss(vm.Finding);
            else if (vm.TrustedFolder != null) protectStore.Untrust(vm.TrustedFolder);
            SaveProtectStore();
            RefreshProtect();
        }

        // ---------------------------------------------------------------- Copies of your folders

        // Cancels any earlier run, snapshots the candidates on the UI thread, then lists the other drives on a
        // worker. Runs are chained, so two never use the cache at once.
        async void StartCoverage(string forgetSource = null, string forgetCopy = null)
        {
            if (coverageCts != null) coverageCts.Cancel();
            coverageCts = null;
            ScanResult r = result;
            if (r == null || r.Protect == null)
            {
                coverage = null;
                coverageRunning = false;
                return;
            }
            List<CoverageDrive> drives;
            List<CoverageSource> sources;
            try
            {
                // A fixture tree (--protect-home) is checked against no real drive, so its pages and snapshots
                // show nothing from outside the fixture.
                drives = protectHome != null ? new List<CoverageDrive>() : Placement.CoverageDrives(movePlan.Drives);
                sources = ProtectCoverage.Snapshot(r, r.Protect, movePlan.Personal, drives);
            }
            catch (Exception)
            {
                coverage = null;
                coverageRunning = false;
                return;
            }
            var cts = coverageCts = new CancellationTokenSource();
            CancellationToken token = cts.Token;
            Task previous = coverageTask;
            Dictionary<string, CopyCheck> cache = coverageCache;
            coverageRunning = true;
            Task<CoverageReport> run = Task.Run(() =>
            {
                if (previous != null)
                {
                    try { previous.Wait(); }
                    catch (Exception) { }
                }
                if (forgetSource != null || forgetCopy != null) ProtectCoverage.Forget(cache, forgetSource, forgetCopy);
                return ProtectCoverage.Compute(sources, drives, Placement.IsBackupName, cache, token);
            });
            coverageTask = run;
            CoverageReport report = null;
            try { report = await run; }
            catch (Exception) { report = null; }
            if (token.IsCancellationRequested || result != r) return;
            coverage = report;
            coverageRunning = false;
            coverageCts = null;
            RefreshProtect();
        }

        // A new scan checks every copy again: the cache only saves listings between edits within one scan.
        void ForgetAllCopies()
        {
            lock (coverageCache) coverageCache.Clear();
        }

        void CancelCoverage()
        {
            if (coverageCts != null) coverageCts.Cancel();
            coverageCts = null;
            coverageRunning = false;
        }

        string NoCopyText()
        {
            if (coverageRunning) return "…";
            if (coverage == null || coverage.Folders == null) return "–";
            if (coverage.Folders.Count - coverage.NotCheckedCount <= 0) return "–";
            return Fmt.Count(coverage.WithoutCurrentCopy);
        }

        void RefreshCoverageSection()
        {
            string drive = (DriveLetter(result.Root.FullPath) + "").TrimEnd('\\');
            if (coverage != null && coverage.ScanDrive != null) drive = coverage.ScanDrive.TrimEnd('\\');
            var notes = new List<string>();
            string headline;
            var items = new List<ProtectFolderVm>();
            if (coverage == null)
            {
                headline = coverageRunning ? "Checking other drives…"
                    : result.Protect == null ? "Copies were not checked for this scan." : "";
            }
            else if (coverage.Folders == null || coverage.Folders.Count == 0)
                headline = "No personal folders in this scan. Scan " + SystemDriveRoot().TrimEnd('\\') + " to check Documents, Pictures and Desktop.";
            else
            {
                int checkedCount = coverage.Folders.Count - coverage.NotCheckedCount;
                if (coverage.NoDrivesReason != null) headline = coverage.NoDrivesReason;
                else if (coverage.WithoutCurrentCopy > 0)
                    headline = "If " + drive + " stopped working, " + Fmt.Count(coverage.WithoutCurrentCopy) +
                               (coverage.WithoutCurrentCopy == 1 ? " folder (" : " folders (") + Fmt.Size(coverage.WithoutCurrentCopyBytes) +
                               (coverage.WithoutCurrentCopy == 1 ? ") has" : ") have") + " no current copy on the drives connected now.";
                else if (checkedCount > 0) headline = "Every folder checked has a copy on another drive connected now.";
                else headline = "";
                if (coverage.NotCheckedCount > 0 && coverage.NoDrivesReason == null)
                    notes.Add(Fmt.Count(coverage.NotCheckedCount) + (coverage.NotCheckedCount == 1 ? " folder was" : " folders were") + " not checked.");
                notes.Add("Checked just now, in " + Fmt.Duration(coverage.Took) + ".");
                if (coverageRunning) notes.Add("Checking again…");
                foreach (FolderCoverage fc in coverage.Folders) items.Add(FolderVm(fc));
            }
            protectCoverageHeadline.Text = headline;
            protectCoverageHeadline.Visibility = headline.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
            protectCoverageNote.Text = string.Join(" ", notes.ToArray());
            protectCoverageNote.Visibility = notes.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            protectCoverageList.ItemsSource = items;
        }

        ProtectFolderVm FolderVm(FolderCoverage fc)
        {
            CoverageSource x = fc.Source;
            var vm = new ProtectFolderVm
            {
                Coverage = fc,
                Name = x.Name,
                Subtitle = Fmt.Size(x.LogicalBytes) + "  ·  " + Fmt.Count(x.Files) + (x.Files == 1 ? " file" : " files") + "  ·  " + x.Path,
                Why = x.Why ?? "",
                Chips = new List<ProtectChipVm>(),
                Lines = new List<string>(),
                AccentVisibility = Visibility.Collapsed,
                PlainVisibility = Visibility.Collapsed
            };
            string here = (x.DriveRoot ?? DriveLetter(x.Path)).TrimEnd('\\');
            string copyDate = fc.Best == null || fc.Best.NewestUtc <= DateTime.MinValue.AddDays(1) ? ""
                : fc.Best.NewestUtc.ToLocalTime().ToString("d MMM yyyy");
            bool changedAfter = fc.Best != null && x.NewestWrite > 0 && copyDate.Length > 0 &&
                                SafeUtc(x.NewestWrite) > fc.Best.NewestUtc.AddDays(1);
            DriveProfile from = Drives.For(movePlan.Drives, x.Path);
            switch (fc.State)
            {
                case CoverageState.TwoDrives:
                    vm.Chips.Add(new ProtectChipVm("Two drives  ·  " + CopyDriveText(fc).Replace(" (", " ").Replace(")", ""), "good"));
                    vm.Lines.Add("Same files and sizes on " + fc.Best.Path + ", checked just now." +
                                 (copyDate.Length > 0 ? " Newest file in the copy: " + copyDate + "." : ""));
                    if (changedAfter) vm.Lines.Add("Files here changed after that.");
                    vm.Target = DriveOfCopy(fc);
                    if (vm.Target != null)
                    {
                        vm.PlainText = "Check byte for byte…";
                        vm.PlainVisibility = Visibility.Visible;
                    }
                    break;
                case CoverageState.CopyDiffers:
                    vm.Chips.Add(new ProtectChipVm("Copy differs", null));
                    if (fc.Best != null)
                    {
                        if (fc.Best.Files != x.Files)
                            vm.Lines.Add(fc.Best.Path + " has " + Fmt.Count(fc.Best.Files) + " files; this folder has " + Fmt.Count(x.Files) + ".");
                        else
                            vm.Lines.Add(fc.Best.Path + " has as many files, but they add up to " + Fmt.Size(fc.Best.Bytes) +
                                         "; here they add up to " + Fmt.Size(x.LogicalBytes) + ".");
                        if (changedAfter)
                            vm.Lines.Add(fc.Best.Files < x.Files ? "The copy is missing files added after " + copyDate + "."
                                                                 : "Files here changed after " + copyDate + ", the newest file in the copy.");
                        else if (copyDate.Length > 0 && x.NewestWrite > 0 && fc.Best.NewestUtc > SafeUtc(x.NewestWrite).AddDays(1))
                            vm.Lines.Add("The copy has newer files than this folder.");
                    }
                    vm.Target = DriveOfCopy(fc);
                    if (vm.Target != null)
                    {
                        vm.AccentText = "Update the copy…";
                        vm.AccentVisibility = Visibility.Visible;
                    }
                    break;
                case CoverageState.OneCopy:
                    vm.Chips.Add(new ProtectChipVm("One copy", null));
                    vm.Lines.Add("Only on " + here + "." + (x.Synced ? "" : " Not synced."));
                    vm.Target = from == null ? null : Placement.BestCopyTarget(movePlan.Drives, from);
                    if (vm.Target != null)
                    {
                        vm.AccentText = "Copy to " + vm.Target.Letter + "…";
                        vm.AccentVisibility = Visibility.Visible;
                    }
                    break;
                default:
                    vm.Chips.Add(new ProtectChipVm("Not checked", null));
                    break;
            }
            if (x.Synced)
            {
                vm.Chips.Add(new ProtectChipVm("Synced", null));
                vm.Lines.Add("Synced to your cloud account. Sync is not counted as a copy: deleting here deletes there.");
            }
            if (x.WasSynced)
                vm.Lines.Add("OneDrive is not set up to sync this folder on this PC." +
                             (x.OnlineOnlyFiles > 0 ? " " + Fmt.Count(x.OnlineOnlyFiles) + (x.OnlineOnlyFiles == 1 ? " file here is" : " files here are") +
                                                      " online-only and not stored on this PC." : ""));
            if (fc.State == CoverageState.NotChecked && !string.IsNullOrEmpty(fc.NotCheckedReason)) vm.Lines.Add(fc.NotCheckedReason);
            return vm;
        }

        static DateTime SafeUtc(long fileTime)
        {
            try { return DateTime.FromFileTimeUtc(fileTime); }
            catch (ArgumentOutOfRangeException) { return DateTime.MinValue; }
        }

        DriveProfile DriveOfCopy(FolderCoverage fc)
        {
            if (fc.Best == null || fc.Best.Path == null) return null;
            return Drives.For(movePlan.Drives, fc.Best.Path);
        }

        void OnCoverageClick(object sender, RoutedEventArgs e)
        {
            var b = e.OriginalSource as Button;
            var vm = b == null ? null : b.DataContext as ProtectFolderVm;
            if (vm == null || vm.Coverage == null || vm.Coverage.Source == null) return;
            FolderCoverage fc = vm.Coverage;
            string tag = b.Tag as string;
            if (tag == "cov-show")
            {
                Try(() => ShellOps.ShowInExplorer(fc.Source.Path));
                return;
            }
            if (tag != "cov-copy" && tag != "cov-check") return;
            DirNode node = fc.Source.Node;
            if (node == null || !Attached(node) || vm.Target == null)
            {
                Toast("Rescan to copy or check this folder.", "\uE7BA");
                return;
            }
            // An existing copy is updated or checked in place, not copied again under a new name. Updating it
            // never replaces a file that is newer in the copy without asking (the Move page's update flow), and
            // its dialog says which files can be replaced.
            string existing = null;
            bool identical = false;
            long existingBytes = 0;
            if (fc.Best != null && fc.Best.Path != null && (fc.State == CoverageState.CopyDiffers || fc.State == CoverageState.TwoDrives))
            {
                existing = fc.Best.Path;
                identical = fc.State == CoverageState.TwoDrives;
                existingBytes = fc.Best.Bytes;
            }
            RunCoverageAction(node, vm.Target, existing, identical, existingBytes, fc.Source.Path);
        }

        async void RunCoverageAction(DirNode node, DriveProfile target, string existing, bool identical, long existingBytes, string sourcePath)
        {
            // ForCopy may list a folder already on the target drive, so it runs on a worker.
            MoveSuggestion m;
            try { m = await Task.Run(() => Placement.ForCopy(node, target, existing, identical)); }
            catch (Exception ex)
            {
                ShowError(ex.Message);
                return;
            }
            if (m == null || result == null) return;
            if (existing != null && !identical) m.ExistingBytes = existingBytes;
            await RunSuggestionAsync(m, false);
            if (result == null) return;
            StartCoverage(sourcePath, m.Destination);
            RefreshProtect();
        }

        // ---------------------------------------------------------------- Snapshot (--page protect)

        void ApplyProtectSnapshot(string dialog)
        {
            if (dialog == "protect-expand") snapExpandFirst = snapExpandUsual = true;
            if (dialog == "protect-normal") snapExpandUsual = true;
            if (dialog == "protect-hidden" && result != null && result.Findings != null)
            {
                // Each snapshot is a fresh process, so something is hidden in memory only; nothing is saved.
                foreach (Finding f in result.Findings)
                {
                    if (f == null || protectStore.IsHidden(f)) continue;
                    protectStore.Dismiss(f);
                    break;
                }
                showHidden = true;
            }
            Navigate(protectPage);
            RefreshProtect();
            if (dialog == "protect-trust")
            {
                foreach (ProtectCardVm c in protectCards)
                {
                    if (c.TrustFolder == null || c.ActionsVisibility != Visibility.Visible) continue;
                    ShowTrustDialog(c.TrustFolder);
                    break;
                }
            }
        }

        // Before the capture: protect-expand scrolls to the first open list, protect-normal to the usual-place card,
        // and protect-hidden to the end of the cards, so the hidden list and the copies below are in the picture.
        void ScrollProtectSnapshot(string dialog)
        {
            var page = protectPage as ScrollViewer;
            if (page == null) return;
            page.UpdateLayout();
            FrameworkElement target = null;
            double above = 16;
            if (dialog == "protect-expand")
            {
                // The first card whose list is open (a review card if one has a list, else the usual-place card),
                // so the rows are in the picture.
                foreach (ProtectCardVm c in protectCards)
                {
                    if (!c.Expanded) continue;
                    target = protectFindings.ItemContainerGenerator.ContainerFromItem(c) as FrameworkElement;
                    break;
                }
            }
            if (dialog == "protect-info")
            {
                // "What Protect reads", from the section on where it does not look.
                foreach (UIElement el in protectInfo.Children)
                {
                    var card = el as Border;
                    var body = card == null ? null : card.Child as StackPanel;
                    var title = body == null || body.Children.Count == 0 ? null : body.Children[0] as TextBlock;
                    if (title == null || title.Text != "Where Protect does not look") continue;
                    target = card;
                    break;
                }
            }
            if (dialog == "protect-normal" || dialog == "protect-hidden")
            {
                foreach (ProtectCardVm c in protectCards)
                {
                    if (c.Group != "usual") continue;
                    target = protectFindings.ItemContainerGenerator.ContainerFromItem(c) as FrameworkElement;
                    break;
                }
            }
            if (dialog == "protect-hidden" && protectHiddenLine.Visibility == Visibility.Visible)
            {
                if (target == null) { target = protectHiddenLine; above = 160; }
            }
            if (target == null) return;
            try
            {
                Point at = target.TransformToAncestor(page).Transform(new Point(0, 0));
                page.ScrollToVerticalOffset(Math.Max(0, page.VerticalOffset + at.Y - above));
            }
            catch (InvalidOperationException) { }
        }

        // Calls back once the backup check is done, or after 20 s.
        void WhenCoverageDone(Action then)
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
            timer.Tick += (s, e) =>
            {
                bool done = !coverageRunning && (coverageTask == null || coverageTask.IsCompleted);
                if (!done && clock.Elapsed < TimeSpan.FromSeconds(20)) return;
                timer.Stop();
                then();
            };
            timer.Start();
        }

        // ---------------------------------------------------------------- Paths

        // A path as ProtectContext stores it: backslashes, no trailing separator, upper case.
        static string Norm(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            string p = path.Replace('/', '\\');
            if (p.Length > 3) p = p.TrimEnd('\\');
            return p.ToUpperInvariant();
        }

        static bool Under(string normalized, string root)
        {
            if (root == null || normalized == null) return false;
            if (normalized == root) return true;
            string prefix = root.EndsWith("\\", StringComparison.Ordinal) ? root : root + "\\";
            return normalized.StartsWith(prefix, StringComparison.Ordinal);
        }

        static string ParentOf(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            string p = path.Length > 3 ? path.TrimEnd('\\') : path;
            int cut = p.LastIndexOf('\\');
            if (cut < 0) return null;
            if (cut == 2 && p[1] == ':') return cut + 1 >= p.Length ? null : p.Substring(0, 3);
            return p.Substring(0, cut);
        }

        static string LastSegment(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            string p = path.TrimEnd('\\');
            int cut = p.LastIndexOf('\\');
            return cut < 0 ? p : p.Substring(cut + 1);
        }

        static bool IsDriveRoot(string path)
        {
            return path != null && path.TrimEnd('\\').Length == 2 && path[1] == ':';
        }

        static HashSet<string> KnownSet(ProtectContext ctx)
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            if (ctx == null) return set;
            foreach (string[] list in new[] { ctx.Downloads, ctx.Desktop, ctx.Documents, ctx.Pictures, ctx.Videos, ctx.Music })
                if (list != null) foreach (string p in list) set.Add(p);
            return set;
        }

        // The ancestor that is a direct child of a drive root, of Home, of a known folder or of Downloads. A file
        // directly in a known folder (Downloads and Desktop included) has that folder as its top folder.
        // Temp roots count as known folders here, so a file unzipped into Temp groups under that Temp folder and
        // not under AppData.
        static string TopFolder(string path, ProtectContext ctx)
        {
            string parent = ParentOf(path);
            if (parent == null) return path;
            HashSet<string> known = KnownSet(ctx);
            if (ctx != null && ctx.TempRoots != null) foreach (string t in ctx.TempRoots) known.Add(t);
            string home = ctx == null ? null : ctx.Home;
            if (known.Contains(Norm(parent)) || IsDriveRoot(parent) || Norm(parent) == home) return parent;
            string cur = parent;
            while (true)
            {
                string up = ParentOf(cur);
                if (up == null) return cur;
                string nu = Norm(up);
                if (known.Contains(nu) || nu == home || IsDriveRoot(up)) return cur;
                cur = up;
            }
        }

        // "Downloads\AccountStatements" for a folder in a known folder; the full path otherwise.
        static string DisplayFolder(string folder, ProtectContext ctx)
        {
            if (folder == null) return "";
            string n = Norm(folder);
            if (ctx != null)
            {
                string[][] lists = { ctx.Downloads, ctx.Desktop, ctx.Documents, ctx.Pictures, ctx.Videos, ctx.Music, ctx.TempRoots };
                string[] names = { "Downloads", "Desktop", "Documents", "Pictures", "Videos", "Music", "Temp" };
                for (int i = 0; i < lists.Length; i++)
                {
                    if (lists[i] == null) continue;
                    foreach (string k in lists[i])
                    {
                        if (n == k) return names[i];
                        if (Under(n, k)) return names[i] + folder.Substring(k.EndsWith("\\", StringComparison.Ordinal) ? k.Length - 1 : k.Length);
                    }
                }
                if (ctx.Home != null && n == ctx.Home) return "your user folder";
            }
            return folder;
        }

        // The deepest folder that holds every entry.
        static string CommonFolder(List<ProtectEntry> entries)
        {
            string common = null;
            foreach (ProtectEntry e in entries)
            {
                string dir = e.F.PatternId == "doc-scans-folder" ? e.Path : ParentOf(e.Path);
                if (dir == null) continue;
                if (common == null) { common = dir; continue; }
                while (common != null && !Under(Norm(dir), Norm(common))) common = ParentOf(common);
            }
            return common;
        }

        // The Mail app's Attachments folder that holds a cached attachment.
        static string AttachmentsFolder(string path)
        {
            int at = path.IndexOf("\\Attachments\\", StringComparison.OrdinalIgnoreCase);
            return at < 0 ? ParentOf(path) : path.Substring(0, at + "\\Attachments".Length);
        }

        Node FolderNode(string path)
        {
            if (result == null || path == null) return null;
            try { return result.FindNode(path); }
            catch (Exception) { return null; }
        }
    }
}

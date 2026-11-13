using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;

// The Protect page's view models, its wording and the code that groups findings into cards. This file is under
// tools\check-trust.ps1: it may not write, delete or move anything, and it reads no file contents. View models
// carry Variant strings, never brushes; the XAML picks the brush with a DataTrigger, so a theme switch needs no
// rebuild. Content findings arrive here as places only (pattern, path, line, column); no view model, tooltip or
// line of text ever holds a matched value.

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
        public string Secrets { get; set; }       // "Off", "…", "3 …", "3", "3 (partial)" or "–"
        public string SecretsNote { get; set; }   // "in 2 files", or empty
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

    // One card in the findings list: one credential file, one file with keys found in its text, one group of
    // documents, or one of the two collapsed groups ("In their usual places", "In your projects").
    sealed class ProtectCardVm
    {
        public string Group { get; set; }           // "cred", "secret", "doc", "vault", "usual" or "projects"
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
        public Visibility CopyVisibility { get; set; }
        public Visibility ActionsVisibility { get; set; }
        public string ShowAllText { get; set; }
        public Visibility ShowAllVisibility { get; set; }

        // Not bound: what the actions work on.
        public string ActionPath { get; set; }      // the file, or the folder of a group card
        public Node Node { get; set; }
        public List<Finding> Findings { get; set; }
        public string TrustFolder { get; set; }
        public Place SortPlace { get; set; }
        public FindingTier SortTier { get; set; }
        public long SortBytes { get; set; }
        public int Line { get; set; }               // the line Open at line goes to; 0 for a card found by name
        public int Column { get; set; }
        public bool CanOpenAtLine { get; set; }
        public int SecretPairs { get; set; }        // distinct (path, pattern) pairs of visible content findings
        public bool HasNameFinding { get; set; }

        public ProtectCardVm()
        {
            CopyVisibility = Visibility.Collapsed;
            ShowAllVisibility = Visibility.Collapsed;
        }
    }

    // A row in a card's "Show N files" list, or one match in a file with several.
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
        public Visibility OpenLineVisibility { get; set; }
        public Visibility HideVisibility { get; set; }
        public Visibility ShowVisibility { get; set; }
        public string HideTip { get; set; }

        // Not bound.
        public Finding Finding { get; set; }        // a content match row: the pattern Hide works on
        public int Line { get; set; }
        public int Column { get; set; }
        public bool CanOpenAtLine { get; set; }

        public ProtectItemVm()
        {
            OpenLineVisibility = Visibility.Collapsed;
            HideVisibility = Visibility.Collapsed;
            ShowVisibility = Visibility.Visible;
        }
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

    // One finding as the page works with it, with the node it was found on (null after a partial rescan).
    sealed class ProtectEntry
    {
        public Finding F;
        public Node N;
        public string Path, Name, Base, Key;
        public long Size = -1, LastWrite;
        public bool OnlineOnly, Mail, Content;
        public readonly List<ProtectEntry> Twins = new List<ProtectEntry>();  // same name and size on other drives
    }

    // Builds the cards of the Protect page from a scan result and the user's choices. RefreshProtect uses it with
    // icons, the backup check and the editor test filled in; ProtectCards.BuildCards uses it bare, for the tests.
    sealed class ProtectCardBuilder
    {
        // Inputs.
        public ScanResult R;
        public ProtectStore Store;
        public bool ContentRan;                     // false: content findings are left out
        public Func<Node, ImageSource> IconOf;      // null: no icons
        public Func<string, string> CoverageLineOf; // null: no backup line on document cards
        public Func<string, bool> CanOpenAt;        // null: no Open at line
        public bool ExpandFirst, ExpandUsual, ExpandSecret;
        public HashSet<string> ShowAll;             // keys of cards whose match rows are not capped

        // Outputs.
        public List<ProtectCardVm> Cards = new List<ProtectCardVm>();
        public List<ProtectCardVm> Review = new List<ProtectCardVm>();
        public List<ProtectEntry> Visible = new List<ProtectEntry>();
        public List<ProtectEntry> Hidden = new List<ProtectEntry>();
        public int VisibleContent;
        public ProtectSummaryVm Summary = new ProtectSummaryVm();

        ProtectContext ctx;
        readonly HashSet<string> pemRead = new HashSet<string>(StringComparer.Ordinal);
        readonly Dictionary<string, List<ProtectEntry>> alsoHolds = new Dictionary<string, List<ProtectEntry>>(StringComparer.Ordinal);
        readonly Dictionary<string, List<ProtectEntry>> envLines = new Dictionary<string, List<ProtectEntry>>(StringComparer.Ordinal);

        public void Build()
        {
            Cards = new List<ProtectCardVm>();
            Review = new List<ProtectCardVm>();
            Summary = new ProtectSummaryVm();
            if (R == null || Store == null) return;
            ctx = R.Protect;

            List<ProtectEntry> hiddenNames;
            Visible = Entries(R.Findings, R.FindingNodes, false, out hiddenNames);
            Hidden = hiddenNames;
            List<ProtectEntry> content = new List<ProtectEntry>();
            if (ContentRan)
            {
                List<ProtectEntry> hiddenContent;
                content = Entries(R.ContentFindings, R.ContentNodes, true, out hiddenContent);
                foreach (ProtectEntry e in hiddenContent)
                    if (ProtectWording.IsPemBlock(e.F.PatternId)) pemRead.Add(e.Key);
                Hidden.AddRange(hiddenContent);
            }
            foreach (ProtectEntry e in content)
                if (ProtectWording.IsPemBlock(e.F.PatternId)) pemRead.Add(e.Key);
            VisibleContent = content.Count;

            // Stage 1 groups, by name.
            var usual = new List<ProtectEntry>();
            var projects = new List<ProtectEntry>();
            var docs = new List<ProtectEntry>();
            var creds = new List<ProtectEntry>();
            foreach (ProtectEntry e in Visible)
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

            // Content findings join their path's by-name findings (section 5.3 of the stage 2 spec).
            var order = new List<string>();
            var byPath = new Dictionary<string, List<ProtectEntry>>(StringComparer.Ordinal);
            foreach (ProtectEntry e in content)
            {
                List<ProtectEntry> list;
                if (!byPath.TryGetValue(e.Key, out list))
                {
                    list = new List<ProtectEntry>();
                    byPath[e.Key] = list;
                    order.Add(e.Key);
                }
                list.Add(e);
            }
            // The keys of each group, kept up to date as entries join, so each content path is looked up in O(1).
            var usualKeys = KeysOf(usual);
            var projectKeys = KeysOf(projects);
            var namedKeys = KeysOf(creds);
            namedKeys.UnionWith(KeysOf(docs));
            var secretCards = new List<ProtectCardVm>();
            foreach (string key in order)
            {
                List<ProtectEntry> hits = byPath[key];
                bool hasUsual = usualKeys.Contains(key), onlyEnv = true, repo = projectKeys.Contains(key);
                foreach (ProtectEntry e in hits)
                {
                    if (e.F.Place == Place.UsualPlace) hasUsual = true;
                    if (e.F.PatternId != "env-secret") onlyEnv = false;
                    if (e.F.Place == Place.Repository && e.F.PatternId == "env-secret") repo = true;
                }
                // The same grouping rule as dsa's, so the page and the command line cannot drift.
                int group = ProtectInfo.GroupOf(hits[0].F, hasUsual, onlyEnv && repo);
                if (group == ProtectInfo.GroupUsual)
                {
                    alsoHolds[key] = hits;
                    if (usualKeys.Add(key)) usual.Add(hits[0]);
                    continue;
                }
                if (group == ProtectInfo.GroupProjects)
                {
                    envLines[key] = hits;
                    if (projectKeys.Add(key)) projects.Add(hits[0]);
                    continue;
                }
                // A counted card of its own: the path leaves every by-name group, so it is listed once.
                var named = new List<ProtectEntry>();
                if (namedKeys.Contains(key))
                {
                    TakeFrom(creds, key, named);
                    TakeFrom(docs, key, named);
                }
                if (projectKeys.Remove(key)) TakeFrom(projects, key, named);
                secretCards.Add(SecretCard(key, hits, named));
            }

            foreach (ProtectEntry e in ProtectPaths.MergeTwins(creds, true)) Review.Add(CredentialCard(e));
            Review.AddRange(DocumentCards(docs));
            Review.AddRange(secretCards);
            Review.Sort((a, b) =>
            {
                int c = ProtectWording.PlaceRank(a.SortPlace).CompareTo(ProtectWording.PlaceRank(b.SortPlace));
                if (c != 0) return c;
                c = ((int)a.SortTier).CompareTo((int)b.SortTier);
                return c != 0 ? c : b.SortBytes.CompareTo(a.SortBytes);
            });
            if (ExpandSecret)
                foreach (ProtectCardVm c in Review)
                    if (c.Group == "secret" && c.ItemsVisibility == Visibility.Visible) { c.Expanded = true; break; }
            if (ExpandFirst)
                foreach (ProtectCardVm c in Review)
                    if (c.ItemsVisibility == Visibility.Visible) { c.Expanded = true; break; }

            var summary = new ProtectSummaryVm { ToReview = Review.Count };
            foreach (ProtectCardVm c in Review)
            {
                if (c.Group == "doc") summary.Documents++;
                else if (c.Group != "secret" || c.HasNameFinding) summary.Keys++;
                foreach (Finding f in c.Findings) if (f.Line == 0) summary.Files++;
            }
            Summary = summary;

            Cards = new List<ProtectCardVm>(Review);
            if (usual.Count > 0) Cards.Add(UsualCard(usual));
            if (projects.Count > 0) Cards.Add(ProjectsCard(projects));
        }

        // Distinct (path, pattern) pairs among the visible content findings on counted cards, and their files.
        public int SecretPairs(out int files)
        {
            int pairs = 0;
            files = 0;
            foreach (ProtectCardVm c in Review)
            {
                if (c.Group != "secret") continue;
                pairs += c.SecretPairs;
                files++;
            }
            return pairs;
        }

        static HashSet<string> KeysOf(List<ProtectEntry> list)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (ProtectEntry e in list) keys.Add(e.Key);
            return keys;
        }

        static void TakeFrom(List<ProtectEntry> list, string key, List<ProtectEntry> into)
        {
            for (int i = list.Count - 1; i >= 0; i--)
            {
                if (list[i].Key != key) continue;
                into.Insert(0, list[i]);
                list.RemoveAt(i);
            }
        }

        List<ProtectEntry> Entries(List<Finding> findings, List<Node> nodes, bool content, out List<ProtectEntry> hidden)
        {
            var visible = new List<ProtectEntry>();
            hidden = new List<ProtectEntry>();
            if (findings == null) return visible;
            for (int i = 0; i < findings.Count; i++)
            {
                Finding f = findings[i];
                if (f == null || f.Path == null) continue;
                Node n = nodes != null && i < nodes.Count ? nodes[i] : null;
                if (n != null && !ProtectPaths.Attached(R, n)) n = null;
                // A content finding whose file left the tree (recycled, or replaced by a rescan) is not shown.
                if (content && n == null) continue;
                var e = new ProtectEntry { F = f, N = n, Path = f.Path, Name = ProtectPaths.LastSegment(f.Path), Key = ProtectPaths.Norm(f.Path), Content = content };
                if (n != null)
                {
                    var fnode = n as FileNode;
                    e.Size = n.Size;
                    e.LastWrite = n.LastWrite;
                    e.OnlineOnly = fnode != null && (fnode.Flags & FileFlags.OnlineOnly) != 0;
                }
                e.Base = ProtectPaths.SafeBaseName(e.Name);
                e.Mail = ProtectPaths.SafeIsMail(f.Path);
                if (Store.IsHidden(f)) hidden.Add(e);
                else visible.Add(e);
            }
            return visible;
        }

        ImageSource Icon(Node n)
        {
            if (n == null || IconOf == null) return null;
            try { return IconOf(n); }
            catch (Exception) { return null; }
        }

        bool Editor(string path)
        {
            if (CanOpenAt == null || path == null) return false;
            try { return CanOpenAt(path); }
            catch (Exception) { return false; }
        }

        // ---- Credential cards: one per file

        ProtectCardVm CredentialCard(ProtectEntry e)
        {
            Finding f = e.F;
            var all = new List<ProtectEntry> { e };
            all.AddRange(e.Twins);
            string kind = f.Kind;
            string reason = ProtectWording.CredentialReason(f.PatternId, kind, e.Name, f.Place, f.Path, e.Mail);
            if (f.PatternId == "pem-key" && pemRead.Contains(e.Key))
                reason = reason.Replace(ProtectWording.PemNameOnly, ProtectWording.PemRead);
            var card = new ProtectCardVm
            {
                Group = "cred",
                Glyph = ProtectWording.Glyph(f.PatternId),
                Title = ProtectWording.CredentialTitle(f.PatternId, kind, f.Place, f.Path, e.Mail),
                Reason = reason,
                Lines = new List<string>(),
                Chips = new List<ProtectChipVm>(),
                Path = f.Path,
                ActionPath = f.Path,
                Node = e.N,
                Findings = new List<Finding>(),
                SortPlace = f.Place,
                SortTier = f.Tier,
                SortBytes = Math.Max(0, e.Size),
                HasNameFinding = true
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
            card.TrustFolder = f.Place == Place.Repository ? RepoRoot(e) : ProtectPaths.ParentOf(f.Path);
            SetPrimary(card, ProtectWording.CanOpen(f.PatternId));
            SetItems(card, all.Count > 1 ? Rows(all) : new List<ProtectItemVm>());
            return card;
        }

        // ---- Content cards: one per file with a key found in its text

        ProtectCardVm SecretCard(string key, List<ProtectEntry> hits, List<ProtectEntry> named)
        {
            // The title names the strongest kind: by tier, then table order. The other lines go by line number.
            var strongest = new List<ProtectEntry>(hits);
            strongest.Sort((a, b) =>
            {
                int c = ((int)a.F.Tier).CompareTo((int)b.F.Tier);
                if (c != 0) return c;
                c = ProtectWording.TableOrder(a.F.PatternId).CompareTo(ProtectWording.TableOrder(b.F.PatternId));
                if (c != 0) return c;
                c = a.F.Line.CompareTo(b.F.Line);
                return c != 0 ? c : a.F.Column.CompareTo(b.F.Column);
            });
            ProtectEntry best = strongest[0];
            var byLine = new List<ProtectEntry>(hits);
            byLine.Sort((a, b) =>
            {
                int c = a.F.Line.CompareTo(b.F.Line);
                if (c != 0) return c;
                c = a.F.Column.CompareTo(b.F.Column);
                return c != 0 ? c : ProtectWording.TableOrder(a.F.PatternId).CompareTo(ProtectWording.TableOrder(b.F.PatternId));
            });

            Place place = best.F.Place;
            FindingTier tier = best.F.Tier;
            var findings = new List<Finding>();
            var patterns = new HashSet<string>(StringComparer.Ordinal);
            foreach (ProtectEntry e in hits)
            {
                findings.Add(e.F);
                patterns.Add(e.F.PatternId);
                if ((int)e.F.Tier < (int)tier) tier = e.F.Tier;
            }
            foreach (ProtectEntry e in named)
            {
                findings.Add(e.F);
                if ((int)e.F.Tier < (int)tier) tier = e.F.Tier;
            }

            bool open = best.N != null && Editor(best.Path);
            var card = new ProtectCardVm
            {
                Group = "secret",
                Glyph = ProtectWording.GlyphKey,
                Title = ProtectWording.ContentKind(best.F) + " in " + best.Name,
                Reason = ProtectWording.ContentReason(best.F.PatternId),
                Lines = new List<string>(),
                Chips = new List<ProtectChipVm>(),
                Path = best.Path,
                ActionPath = best.Path,
                Node = best.N,
                Findings = findings,
                SortPlace = place,
                SortTier = tier,
                SortBytes = Math.Max(0, best.Size),
                Line = best.F.Line,
                Column = best.F.Column,
                CanOpenAtLine = open,
                SecretPairs = patterns.Count,
                HasNameFinding = named.Count > 0,
                CopyVisibility = Visibility.Visible
            };

            card.Lines.Add(ProtectWording.PlaceNote(place, best.Path, best.Mail, place == Place.Repository ? ProtectPaths.RepoDisplay(RepoRoot(best)) : null));
            var others = new List<ProtectEntry>();
            foreach (ProtectEntry e in byLine) if (e != best) others.Add(e);
            for (int i = 0; i < others.Count && i < 3; i++)
                card.Lines.Add("Also: " + ProtectWording.ContentKind(others[i].F) + ", line " + others[i].F.Line);
            if (others.Count > 3) card.Lines.Add("and " + Fmt.Count(others.Count - 3) + " more");
            var namedKinds = new List<string>();
            foreach (ProtectEntry e in named)
            {
                string k = ProtectWording.ShortKind(e.F.Kind);
                if (!namedKinds.Contains(k)) namedKinds.Add(k);
            }
            if (namedKinds.Count > 0) card.Lines.Add("Also found by name: " + string.Join(", ", namedKinds.ToArray()));

            card.Chips.Add(new ProtectChipVm(ProtectWording.TierText(tier), ProtectWording.ContentTierVariant(tier, place)));
            card.Chips.Add(new ProtectChipVm(ProtectWording.PlaceChip(place, best.Path, best.Mail), null));
            card.Chips.Add(new ProtectChipVm("Line " + best.F.Line, null));
            card.TrustFolder = place == Place.Repository ? RepoRoot(best) : ProtectPaths.ParentOf(best.Path);

            card.PrimaryText = open ? "Open at line" : "Show in Explorer";
            card.PrimaryTag = open ? "protect-open-line" : "protect-show";
            card.ShowLinkVisibility = open ? Visibility.Visible : Visibility.Collapsed;
            card.ActionsVisibility = Visibility.Visible;

            var rows = new List<ProtectItemVm>();
            if (byLine.Count > 1)
            {
                bool all = ShowAll != null && ShowAll.Contains("secret|" + key);
                int cap = ProtectConstants.ContentRowsPerCard;
                foreach (ProtectEntry e in byLine)
                {
                    if (!all && rows.Count >= cap) break;
                    rows.Add(new ProtectItemVm
                    {
                        Node = e.N,
                        Path = e.Path,
                        Name = ProtectWording.ContentKind(e.F),
                        Kind = "line " + e.F.Line + ", column " + e.F.Column,
                        Folder = "",
                        SizeText = "",
                        OpenVisibility = Visibility.Collapsed,
                        TrustVisibility = Visibility.Collapsed,
                        ShowVisibility = Visibility.Collapsed,
                        OpenLineVisibility = open ? Visibility.Visible : Visibility.Collapsed,
                        HideVisibility = Visibility.Visible,
                        HideTip = "Hide " + ProtectWording.ContentPlural(e.F.PatternId) + " in this file",
                        Finding = e.F,
                        Line = e.F.Line,
                        Column = e.F.Column,
                        CanOpenAtLine = open
                    });
                }
                if (!all && byLine.Count > cap)
                {
                    card.ShowAllText = "Show all " + Fmt.Count(byLine.Count);
                    card.ShowAllVisibility = Visibility.Visible;
                }
            }
            SetItems(card, rows);
            card.ItemsLabel = "Show " + Fmt.Count(byLine.Count) + " matches";
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
                    Icon = Icon(e.N),
                    Name = e.Name,
                    Kind = kind,
                    Folder = ProtectPaths.ParentOf(e.Path),
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

        List<ProtectCardVm> DocumentCards(List<ProtectEntry> docs)
        {
            var cards = new List<ProtectCardVm>();
            var order = new List<string>();
            var groups = new Dictionary<string, List<ProtectEntry>>(StringComparer.Ordinal);
            var folders = new Dictionary<string, ProtectEntry>(StringComparer.Ordinal);   // Scanned Documents folder findings

            foreach (ProtectEntry e in docs)
            {
                if (e.F.PatternId != "doc-scans-folder") continue;
                string key = "scans|" + ProtectPaths.Norm(e.Path);
                folders[key] = e;
                order.Add(key);
                groups[key] = new List<ProtectEntry>();
            }
            foreach (ProtectEntry e in docs)
            {
                if (e.F.PatternId == "doc-scans-folder") continue;
                string key = null;
                string np = ProtectPaths.Norm(e.Path);
                foreach (KeyValuePair<string, ProtectEntry> sf in folders)
                {
                    if (!np.StartsWith(ProtectPaths.Norm(sf.Value.Path) + "\\", StringComparison.Ordinal)) continue;
                    key = sf.Key;
                    break;
                }
                if (key == null)
                    key = e.Mail ? "mail" : ProtectPaths.Norm(ProtectPaths.TopFolder(e.Path, ctx)) + "|" + ProtectWording.Family(e.F.PatternId);
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
                cards.Add(DocumentCard(key, groups[key], folder));
            }
            return cards;
        }

        ProtectCardVm DocumentCard(string key, List<ProtectEntry> files, ProtectEntry scans)
        {
            List<ProtectEntry> rowsOf = ProtectPaths.MergeTwins(files, false);
            var all = new List<ProtectEntry>();
            if (scans != null) all.Add(scans);
            all.AddRange(files);
            ProtectEntry first = all[0];
            bool mail = key == "mail";
            bool vault = first.F.PatternId == "password-vault";

            string folderPath = scans != null ? scans.Path : mail ? ProtectPaths.CommonFolder(all) : ProtectPaths.TopFolder(first.Path, ctx);
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

            string display = mail ? "Mail app attachments" : ProtectPaths.DisplayFolder(folderPath, ctx);
            string title;
            if (scans != null) title = "Scanned Documents folder in " + ProtectPaths.DisplayFolder(ProtectPaths.ParentOf(scans.Path), ctx);
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
                TrustFolder = place == Place.Repository ? RepoRoot(first) : mail ? ProtectPaths.AttachmentsFolder(first.Path) : folderPath,
                SortPlace = place,
                SortTier = tier,
                SortBytes = bytes,
                HasNameFinding = true
            };
            if (scans != null && files.Count > 0)
                card.Lines.Add("It also holds " + ProtectWording.FamilyCount(families, rowsOf.Count) + " matched by name.");
            string copyLine = CoverageLineOf == null ? null : CoverageLineOf(folderPath);
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

        // ---- The two collapsed cards

        ProtectCardVm UsualCard(List<ProtectEntry> usual)
        {
            var order = new List<string>();
            var groups = new Dictionary<string, List<ProtectEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (ProtectEntry e in usual)
            {
                string label = UsualLabel(e);
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
                foreach (ProtectEntry e in list)
                {
                    findings.Add(e.F);
                    List<ProtectEntry> hits;
                    if (alsoHolds.TryGetValue(e.Key, out hits))
                        foreach (ProtectEntry h in hits) if (h != e) findings.Add(h.F);
                }
                rows.Add(UsualRow(label, list));
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
                Expanded = ExpandUsual,
                ActionsVisibility = Visibility.Collapsed,
                ShowLinkVisibility = Visibility.Collapsed
            };
            SetItems(card, rows);
            card.ItemsLabel = "Show " + Fmt.Count(usual.Count) + (usual.Count == 1 ? " file" : " files");
            return card;
        }

        // "also holds: Private key, line 1, AWS access key ID, line 9 and 2 more" for a file in a usual place.
        string HoldsText(ProtectEntry e)
        {
            List<ProtectEntry> hits;
            if (!alsoHolds.TryGetValue(e.Key, out hits)) return null;
            var sorted = new List<ProtectEntry>(hits);
            sorted.Sort((a, b) => a.F.Line != b.F.Line ? a.F.Line.CompareTo(b.F.Line) : a.F.Column.CompareTo(b.F.Column));
            var parts = new List<string>();
            for (int i = 0; i < sorted.Count && i < 3; i++)
                parts.Add(ProtectWording.ContentKind(sorted[i].F) + ", line " + sorted[i].F.Line);
            string text = string.Join(", ", parts.ToArray());
            if (sorted.Count > 3) text += " and " + Fmt.Count(sorted.Count - 3) + " more";
            return (e.Content ? "holds: " : "also holds: ") + text;
        }

        ProtectItemVm UsualRow(string label, List<ProtectEntry> list)
        {
            ProtectEntry first = list[0];
            if (list.Count == 1)
            {
                string holds = HoldsText(first);
                string text = UsualRowText(first, ctx);
                return new ProtectItemVm
                {
                    Node = first.N,
                    Path = first.Path,
                    Icon = Icon(first.N),
                    Name = string.Equals(label, first.Name, StringComparison.OrdinalIgnoreCase) ? first.Name : label + ": " + first.Name,
                    Kind = holds == null ? text : text + "  ·  " + holds,
                    Folder = ProtectPaths.ParentOf(first.Path),
                    SizeText = SizeText(first),
                    OpenVisibility = ProtectWording.CanOpen(first.F.PatternId) ? Visibility.Visible : Visibility.Collapsed,
                    TrustVisibility = Visibility.Collapsed
                };
            }
            bool docs = true, keys = true, sameId = true;
            long bytes = 0;
            var names = new List<string>();
            var holdsAll = new List<string>();
            foreach (ProtectEntry e in list)
            {
                docs = docs && ProtectWording.IsDocument(e.F.PatternId);
                keys = keys && (ProtectWording.IsKey(e.F.PatternId) || ProtectWording.IsPemBlock(e.F.PatternId));
                sameId = sameId && e.F.PatternId == first.F.PatternId;
                bytes += Math.Max(0, e.Size);
                if (names.Count < 6) names.Add(e.Name);
                string holds = HoldsText(e);
                if (holds != null) holdsAll.Add(e.Name + " " + holds);
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
            if (holdsAll.Count > 0) kind += "  ·  " + string.Join("; ", holdsAll.ToArray());
            string folder = ProtectPaths.CommonFolder(list);
            Node node = FolderNode(folder);
            return new ProtectItemVm
            {
                Node = node,
                Path = folder,
                Icon = Icon(node),
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
            if (ProtectWording.IsDocument(id) && ctx != null && ctx.OneDriveHint != null && ProtectPaths.Under(ProtectPaths.Norm(e.Path), ctx.OneDriveHint))
                return "Kept in Documents, in OneDrive's folder. OneDrive is not set up to sync this folder on this PC.";
            if (id == "password-vault" && e.F.Place == Place.Synced)
                return "Encrypted by design, so this is not exposed by itself. This folder syncs to the cloud.";
            return ProtectWording.UsualText(id);
        }

        // The row label in the usual-place card: the tool home, the known folder, or the file's own name.
        string UsualLabel(ProtectEntry e)
        {
            string id = e.F.PatternId;
            if (id == "password-vault") return "Password vaults";
            string np = ProtectPaths.Norm(e.Path);
            if (ctx != null)
            {
                if (ProtectWording.IsDocument(id))
                {
                    foreach (string d in ctx.Documents) if (ProtectPaths.Under(np, d)) return "Documents";
                    foreach (string d in ctx.Pictures) if (ProtectPaths.Under(np, d)) return "Pictures";
                }
                string[] rel = ProtectPaths.RelativeSegments(e.Path, np, ctx.Roaming);
                if (rel != null && rel.Length > 1) return ProtectWording.RoamingLabel(rel[0]);
                rel = ProtectPaths.RelativeSegments(e.Path, np, ctx.Local);
                if (rel != null && rel.Length > 1) return rel[0];
                rel = ProtectPaths.RelativeSegments(e.Path, np, ctx.Home);
                if (rel != null)
                {
                    if (rel.Length == 1) return rel[0];
                    if (rel[0].StartsWith(".", StringComparison.Ordinal)) return ProtectWording.ToolLabel(rel[0], rel.Length > 2 ? rel[1] : null);
                    return rel[0];
                }
            }
            string parent = ProtectPaths.ParentOf(e.Path);
            return parent == null ? e.Name : ProtectPaths.LastSegment(parent);
        }

        ProtectCardVm ProjectsCard(List<ProtectEntry> projects)
        {
            var order = new List<string>();
            var groups = new Dictionary<string, List<ProtectEntry>>(StringComparer.OrdinalIgnoreCase);
            var findings = new List<Finding>();
            foreach (ProtectEntry e in projects)
            {
                findings.Add(e.F);
                List<ProtectEntry> hits;
                if (envLines.TryGetValue(e.Key, out hits))
                    foreach (ProtectEntry h in hits) if (h != e) findings.Add(h.F);
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
                var settings = new List<string>();
                foreach (ProtectEntry e in list)
                {
                    names.Add(e.Name);
                    string lines = SecretLines(e.Key);
                    if (lines != null) settings.Add(list.Count == 1 ? lines : e.Name + ": " + lines);
                }
                Node node = FolderNode(root);
                string kind = list.Count == 1 ? "1 environment file" : list.Count + " environment files";
                if (settings.Count > 0) kind += "  ·  " + string.Join("; ", settings.ToArray());
                rows.Add(new ProtectItemVm
                {
                    Node = node,
                    Path = root,
                    Icon = Icon(node),
                    Name = ProtectPaths.RepoDisplay(root) + ": " + string.Join(", ", names.ToArray()),
                    Kind = kind,
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

        // "secret settings on lines 3, 7" for a project .env file whose only content findings are env-secret.
        string SecretLines(string key)
        {
            List<ProtectEntry> hits;
            if (!envLines.TryGetValue(key, out hits) || hits.Count == 0) return null;
            var lines = new List<int>();
            foreach (ProtectEntry h in hits) if (!lines.Contains(h.F.Line)) lines.Add(h.F.Line);
            lines.Sort();
            var parts = new List<string>();
            foreach (int l in lines) parts.Add(l.ToString(System.Globalization.CultureInfo.InvariantCulture));
            return (lines.Count == 1 ? "secret setting on line " : "secret settings on lines ") + string.Join(", ", parts.ToArray());
        }

        string RepoRoot(ProtectEntry e)
        {
            string root = null;
            if (e.N != null)
            {
                try { root = ProtectNames.RepoRootOf(e.N); }
                catch (Exception) { root = null; }
            }
            return root ?? ProtectPaths.ParentOf(e.Path) ?? e.Path;
        }

        Node FolderNode(string path)
        {
            if (R == null || path == null) return null;
            try { return R.FindNode(path); }
            catch (Exception) { return null; }
        }
    }

    static class ProtectCards
    {
        // The cards the page shows for a scan, without icons, the backup check or the editor test. Used by
        // RefreshProtect (through ProtectCardBuilder) and by the tests, which search every string on them.
        internal static List<ProtectCardVm> BuildCards(ScanResult r, ProtectStore s, bool contentRan)
        {
            var b = new ProtectCardBuilder { R = r, Store = s, ContentRan = contentRan };
            b.Build();
            return b.Cards;
        }
    }

    // Path helpers shared by the cards and the page.
    static class ProtectPaths
    {
        // A path as ProtectContext stores it: backslashes, no trailing separator, upper case.
        public static string Norm(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            string p = path.Replace('/', '\\');
            if (p.Length > 3) p = p.TrimEnd('\\');
            return p.ToUpperInvariant();
        }

        public static bool Under(string normalized, string root)
        {
            if (root == null || normalized == null) return false;
            if (normalized == root) return true;
            string prefix = root.EndsWith("\\", StringComparison.Ordinal) ? root : root + "\\";
            return normalized.StartsWith(prefix, StringComparison.Ordinal);
        }

        public static string ParentOf(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            string p = path.Length > 3 ? path.TrimEnd('\\') : path;
            int cut = p.LastIndexOf('\\');
            if (cut < 0) return null;
            if (cut == 2 && p[1] == ':') return cut + 1 >= p.Length ? null : p.Substring(0, 3);
            return p.Substring(0, cut);
        }

        public static string LastSegment(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            string p = path.TrimEnd('\\');
            int cut = p.LastIndexOf('\\');
            return cut < 0 ? p : p.Substring(cut + 1);
        }

        public static bool IsDriveRoot(string path)
        {
            return path != null && path.TrimEnd('\\').Length == 2 && path[1] == ':';
        }

        public static string DriveLetter(string path)
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

        public static bool SameDrive(string a, string b)
        {
            return string.Equals(DriveLetter(a), DriveLetter(b), StringComparison.OrdinalIgnoreCase);
        }

        // False for nodes that were removed from the tree (deleted or replaced by a rescan).
        public static bool Attached(ScanResult r, Node n)
        {
            return r != null && r.IsAttached(n);
        }

        public static string SafeBaseName(string name)
        {
            try { return ProtectNames.BaseName(name) ?? name; }
            catch (Exception) { return name; }
        }

        public static bool SafeIsMail(string path)
        {
            try { return ProtectNames.IsMailAttachment(path); }
            catch (Exception) { return false; }
        }

        // Findings with the same base name and size on different drives become one card or row.
        public static List<ProtectEntry> MergeTwins(List<ProtectEntry> list, bool samePattern)
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

        // The segments of path below root (both compared normalized), in the path's own casing; null if not below.
        public static string[] RelativeSegments(string path, string normalized, string root)
        {
            if (root == null || !Under(normalized, root)) return null;
            int start = root.EndsWith("\\", StringComparison.Ordinal) ? root.Length : root.Length + 1;
            if (start >= path.Length) return null;
            return path.Substring(start).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
        }

        // "warden\mvp": the last two folder names of a project root.
        public static string RepoDisplay(string root)
        {
            if (root == null) return "";
            string[] parts = root.TrimEnd('\\').Split('\\');
            if (parts.Length >= 2 && !(parts.Length == 2 && parts[0].EndsWith(":", StringComparison.Ordinal)))
                return parts[parts.Length - 2] + "\\" + parts[parts.Length - 1];
            return root;
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
        public static string TopFolder(string path, ProtectContext ctx)
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
        public static string DisplayFolder(string folder, ProtectContext ctx)
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
        public static string CommonFolder(List<ProtectEntry> entries)
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
        public static string AttachmentsFolder(string path)
        {
            int at = path.IndexOf("\\Attachments\\", StringComparison.OrdinalIgnoreCase);
            return at < 0 ? ParentOf(path) : path.Substring(0, at + "\\Attachments".Length);
        }
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

        // The pem-key sentence, and what it becomes once the content scan found a private key block in the file.
        public const string PemNameOnly = "Protect read only its name and size.";
        public const string PemRead = "Protect also read it and found a private key block.";

        // A card's reason never repeats its title ("<Kind> in <place>"): it starts with the explanation.
        static readonly Dictionary<string, string> Overrides = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            { "pem-key|HomeFolder", PemNameOnly + " " +
                                    "If you still use it, keeping it with your other keys in .ssh or in a password manager is tidier." },
            { "pem-key|Synced", PemNameOnly + " Syncing puts a copy of it on the provider's servers too." },
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

        public static bool IsPemBlock(string id)
        {
            return id == "pem-private-key" || id == "pem-private-key-encrypted";
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

        // ---- Content rows (stage 2). The sentences come from ProtectConstants.ContentRules, never typed twice.

        // The position of a pattern in ProtectConstants.Patterns: the content rows come after the name rows, in
        // table order, which breaks ties between kinds of the same tier.
        public static int TableOrder(string id)
        {
            PatternInfo[] all = ProtectConstants.Patterns;
            for (int i = 0; i < all.Length; i++)
                if (all[i].Id == id) return i;
            return all.Length;
        }

        public static ContentRuleInfo ContentRule(string id)
        {
            ContentRuleInfo[] rules = ProtectConstants.ContentRules;
            if (rules == null) return null;
            foreach (ContentRuleInfo r in rules)
                if (r != null && r.Id == id) return r;
            return null;
        }

        public static string ContentReason(string id)
        {
            ContentRuleInfo r = ContentRule(id);
            return r == null ? "" : r.Reason;
        }

        // "GitHub tokens", for "Hide GitHub tokens in this file".
        public static string ContentPlural(string id)
        {
            ContentRuleInfo r = ContentRule(id);
            if (r != null && !string.IsNullOrEmpty(r.Plural)) return r.Plural;
            PatternInfo p = ProtectConstants.Pattern(id);
            return p == null ? "these keys" : p.Kind + "s";
        }

        public static string ContentKind(Finding f)
        {
            return f.Kind;
        }

        // "Environment file (may hold keys)" becomes "Environment file".
        public static string ShortKind(string kind)
        {
            if (kind == null) return "";
            int cut = kind.IndexOf(" (", StringComparison.Ordinal);
            return cut > 0 ? kind.Substring(0, cut) : kind;
        }

        // The warning colour is used only for a Confirmed match in a place where copies get forgotten or shared.
        public static string ContentTierVariant(FindingTier tier, Place place)
        {
            if (tier != FindingTier.Confirmed) return "";
            return place == Place.Downloads || place == Place.Desktop || place == Place.Temp || place == Place.Synced ||
                   place == Place.ExternalDrive ? "warn" : "";
        }

        // The place note of a content card: "In Downloads. A copy in Downloads is easy to forget."
        public static string PlaceNote(Place place, string path, bool mail, string project)
        {
            string phrase = place == Place.Repository && !string.IsNullOrEmpty(project) ? "in the project " + project
                : PlacePhrase(place, path, mail);
            string first = phrase.Length > 0 ? char.ToUpperInvariant(phrase[0]) + phrase.Substring(1) : phrase;
            return first + ". " + Advice(place, "");
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
                case Place.UsualPlace: return "This is where its tool keeps it.";
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
            if (id == "pem-key") return PemNameOnly + " " + advice;
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

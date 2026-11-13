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
    // The Protect page: findings by name and, once the user turns it on, by reading small text files, grouped into
    // cards; and whether the large personal folders have a copy on another drive. This file is under
    // tools\check-trust.ps1: it changes nothing on disk except protect.json (through ProtectStore.Save), reads no
    // file contents itself (the content scan runs in SecretScan and hands back places only), and hands copies and
    // checks to the Move page's flows.
    sealed partial class MainWindow
    {
        StackPanel protectInfo, protectResults, protectCoverageBusy, protectHiddenLine, protectHiddenPanel;
        StackPanel protectContentProgress, protectNotLooked;
        Border protectNoScan, protectContentCard;
        Grid protectContentTitleRow;
        TextBlock protectToReview, protectNote, protectKeys, protectDocs, protectNoCopy, protectEmpty, protectHiddenText;
        TextBlock protectCoverageHeadline, protectCoverageNote;
        TextBlock protectSecrets, protectSecretsNote, protectContentLine, protectContentText;
        ItemsControl protectFindings, protectHiddenList, protectCoverageList, protectNotLookedList;
        Button protectShowHidden, protectContentCancel, protectContentAgain;
        ToggleButton protectContentSwitch, protectNotLookedToggle;
        ProgressBar protectContentBar;

        // The content scan (stage 2). contentState is null (not run for this scan), "running", "done" or "stopped".
        CancellationTokenSource contentCts;
        Task contentTask;               // the snapshot waits on it
        ContentRun contentRun;          // copies findings while a run is going, when the engine hands one out
        ContentProgress contentProgress;
        bool contentRunning;
        DispatcherTimer contentTimer;
        ContentPlan contentPlan;
        ScanResult contentFor;          // the scan the current run reads
        DirNode contentUnder;           // the folder of a partial run after an edit; null for a full run
        string contentState;
        long contentPlanFiles, contentDoneFiles;
        int contentCopied, contentPairs, contentPairFiles;
        readonly System.Diagnostics.Stopwatch contentRefreshClock = new System.Diagnostics.Stopwatch();
        readonly List<KeyValuePair<double, double>> contentEstimates = new List<KeyValuePair<double, double>>();
        readonly HashSet<string> showAllCards = new HashSet<string>(StringComparer.Ordinal);
        string snapContent;             // --dialog protect-content-*
        bool snapFrozen;                // the snapshot's fixed progress numbers
        string contentPartialBase;      // the state before a chain of partial runs: "done", "stopped" or null
        bool contentFindingsPending;    // findings copied since the cards were last drawn
        const int CardsPerPage = 100;   // cards drawn at first; "Show more" adds this many again
        int protectCardLimit = CardsPerPage;
        string protectCardsShape;       // the drawn cards, to skip drawing the same list again during a run
        Button protectMoreCards;

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


        void WireProtect()
        {
            ReadProtectArgs();
            protectStore = LoadProtectStore();
            // A snapshot never reads real files: the stored choice is forced off (protect-content-run turns it on
            // in memory, for a fixture tree).
            if (options.Snapshot != null) protectStore.ContentScan = false;
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
            protectSecrets = E<TextBlock>("ProtectSecrets");
            protectSecretsNote = E<TextBlock>("ProtectSecretsNote");
            protectContentSwitch = E<ToggleButton>("ProtectContentSwitch");
            protectContentLine = E<TextBlock>("ProtectContentLine");
            protectContentProgress = E<StackPanel>("ProtectContentProgress");
            protectContentTitleRow = E<Grid>("ProtectContentTitleRow");
            protectContentBar = E<ProgressBar>("ProtectContentBar");
            protectContentText = E<TextBlock>("ProtectContentText");
            protectContentCancel = E<Button>("ProtectContentCancel");
            protectContentAgain = E<Button>("ProtectContentAgain");
            protectNotLooked = E<StackPanel>("ProtectNotLooked");
            protectNotLookedToggle = E<ToggleButton>("ProtectNotLookedToggle");
            protectNotLookedList = E<ItemsControl>("ProtectNotLookedList");
            protectContentCard = E<Border>("ProtectContentCard");
            protectMoreCards = E<Button>("ProtectMoreCards");
            protectMoreCards.Click += (s, e) =>
            {
                protectCardLimit += CardsPerPage;
                RefreshProtect();
            };

            contentTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
            contentTimer.Tick += (s, e) => OnContentTick();
            // Checked and Unchecked, not Click: a screen reader's Toggle sets IsChecked without a click.
            protectContentSwitch.Checked += OnContentSwitchToggled;
            protectContentSwitch.Unchecked += OnContentSwitchToggled;
            protectContentCancel.Click += (s, e) => StopContentScan();
            protectContentAgain.Click += (s, e) => ReadContentAgain();
            E<Button>("ProtectContentInfoLink").Click += (s, e) => ScrollProtectTo(protectInfo, 16);

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
                                a == "--highlight" || a == "--theme" || a == "--width")) { i++; continue; }
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
            RefreshProtect(false);
        }

        // fromTick: a refresh while the content scan runs. It leaves the drawn cards alone when the first page of
        // cards has not changed, since drawing many cards takes the UI thread a while.
        void RefreshProtect(bool fromTick)
        {
            if (protectFindings == null) return;
            contentFindingsPending = false;
            bool scanned = result != null;
            protectNoScan.Visibility = scanned ? Visibility.Collapsed : Visibility.Visible;
            protectResults.Visibility = scanned ? Visibility.Visible : Visibility.Collapsed;
            if (!scanned)
            {
                protectFindings.ItemsSource = null;
                protectCardsShape = null;
                protectMoreCards.Visibility = Visibility.Collapsed;
                protectCoverageList.ItemsSource = null;
                ShowContentCard();
                return;
            }

            var b = new ProtectCardBuilder
            {
                R = result,
                Store = protectStore,
                ContentRan = protectStore.ContentScan,
                IconOf = n => ShellIcons.For(n, false),
                CoverageLineOf = CoverageLine,
                CanOpenAt = ShellOps.CanOpenAt,
                ExpandFirst = snapExpandFirst,
                ExpandSecret = snapContent == "protect-content-run",
                ExpandUsual = snapExpandUsual,
                ShowAll = showAllCards
            };
            b.Build();
            List<ProtectCardVm> review = b.Review;
            ProtectSummaryVm summary = b.Summary;
            int secretFiles;
            contentPairs = b.SecretPairs(out secretFiles);
            contentPairFiles = secretFiles;
            summary.Note = SummaryNote(summary);
            summary.NoCopyText = NoCopyText();

            // A list the user opened stays open when the page is drawn again (after Hide, Trust, Undo, a theme
            // change or the backup check).
            var opened = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (ProtectCardVm c in protectCards) if (c.Expanded) opened.Add(CardKey(c));
            // Only the first protectCardLimit cards are drawn; the counts above still cover all of them.
            List<ProtectCardVm> shown = b.Cards.Count > protectCardLimit ? b.Cards.GetRange(0, protectCardLimit) : b.Cards;
            foreach (ProtectCardVm c in shown)
            {
                if (opened.Contains(CardKey(c))) c.Expanded = true;
                if (c.ItemsVisibility != Visibility.Visible) c.Expanded = false;
            }
            string shape = CardsShape(shown);
            if (!fromTick || shape != protectCardsShape)
            {
                protectCards = shown;
                protectFindings.ItemsSource = shown;
                protectCardsShape = shape;
            }
            int notShown = b.Cards.Count - shown.Count;
            protectMoreCards.Visibility = notShown > 0 ? Visibility.Visible : Visibility.Collapsed;
            if (notShown > 0)
                protectMoreCards.Content = "Show " + Fmt.Count(Math.Min(notShown, CardsPerPage)) + " more (" + Fmt.Count(notShown) + " not shown)";

            protectToReview.Text = Fmt.Count(summary.ToReview);
            protectNote.Text = summary.Note;
            protectKeys.Text = Fmt.Count(summary.Keys);
            protectDocs.Text = Fmt.Count(summary.Documents);
            protectNoCopy.Text = summary.NoCopyText;
            protectCoverageBusy.Visibility = coverageRunning ? Visibility.Visible : Visibility.Collapsed;
            ShowSecretsFigure();

            if (review.Count > 0)
            {
                protectEmpty.Visibility = Visibility.Collapsed;
                protectNotLooked.Visibility = Visibility.Collapsed;
            }
            else
            {
                protectEmpty.Visibility = Visibility.Visible;
                bool allHidden = b.Visible.Count + b.VisibleContent == 0 && b.Hidden.Count > 0;
                protectEmpty.Text = allHidden
                    ? "Nothing to show. " + Fmt.Count(b.Hidden.Count) + (b.Hidden.Count == 1 ? " finding is" : " findings are") + " hidden by you."
                    : CleanText();
                protectNotLooked.Visibility = allHidden ? Visibility.Collapsed : Visibility.Visible;
                protectNotLookedList.ItemsSource = NotLookedFor();
            }

            RefreshHidden(b.Hidden);
            RefreshCoverageSection();
            ShowContentCard();
        }

        // The drawn list in short: each card's key and how many findings and rows it has.
        static string CardsShape(List<ProtectCardVm> cards)
        {
            var sb = new System.Text.StringBuilder();
            foreach (ProtectCardVm c in cards)
            {
                sb.Append(CardKey(c)).Append('|').Append(c.Findings == null ? 0 : c.Findings.Count);
                sb.Append('|').Append(c.Items == null ? 0 : c.Items.Count).Append('|').Append(c.Expanded ? 1 : 0).Append('\n');
            }
            return sb.ToString();
        }

        // What identifies a card from one drawing to the next.
        static string CardKey(ProtectCardVm c)
        {
            if (c.Group == "usual" || c.Group == "projects") return c.Group;
            if (c.Group == "secret") return "secret|" + Norm(c.ActionPath ?? c.Path ?? c.Title);
            return c.Group + "|" + (c.ActionPath ?? c.Path ?? c.Title);
        }

        // "Found by name in 4 files; read 14,820 text files with 11 patterns."
        string SummaryNote(ProtectSummaryVm summary)
        {
            if (summary.ToReview == 0) return "Nothing needs a look.";
            string name = "Found by name in " + Fmt.Count(summary.Files) + (summary.Files == 1 ? " file" : " files");
            if (!protectStore.ContentScan) return name + ". The content scan is off.";
            switch (contentState)
            {
                case "running": return name + "; reading text files now.";
                case "done": return name + "; read " + Fmt.Count(contentPlanFiles) + " text files with " + PatternCount() + " patterns.";
                case "stopped":
                    return name + "; read " + Fmt.Count(contentDoneFiles) + " of " + Fmt.Count(contentPlanFiles) + " text files with " +
                           PatternCount() + " patterns.";
                default: return name + ". Text files are read after each scan.";
            }
        }

        static int PatternCount()
        {
            ContentRuleInfo[] rules = ProtectConstants.ContentRules;
            return rules == null ? 0 : rules.Length;
        }

        // The clean state: "Nothing to review. Protect checked the names of 418,380 files and found no keys in ..."
        string CleanText()
        {
            int names = (int)Math.Min(int.MaxValue, result.Root.FileCount);
            bool on = protectStore.ContentScan;
            bool ran = on && (contentState == "done" || contentState == "stopped");
            bool stopped = on && contentState == "stopped";
            try { return ProtectInfo.ContentSummary(names, contentDoneFiles, contentPlanFiles, PatternCount(), on, ran, stopped); }
            catch (Exception) { return "Nothing to review. Protect checked the names of " + Fmt.Count(result.Root.FileCount) + " files."; }
        }

        string[] NotLookedFor()
        {
            int tooLarge = result == null ? 0 : result.ContentTooLarge;
            int online = result == null ? 0 : result.ContentOnlineOnly;
            try { return ProtectInfo.NotLookedFor(tooLarge, online) ?? new string[0]; }
            catch (Exception) { return new string[0]; }
        }

        // The fourth figure of the summary strip. It follows the running job on every timer tick.
        void ShowSecretsFigure()
        {
            if (protectSecrets == null) return;
            string text, note = "";
            if (!protectStore.ContentScan) text = "Off";
            else if (contentState == "running")
            {
                // The same count as after the run (section 5.4), as of the last drawing of the cards.
                long found = contentPairs;
                text = found == 0 ? "…" : Fmt.Count(found) + " …";
            }
            else if (contentState == "stopped")
            {
                // "3 (partial)": the count in the figure and the word under it, so it fits the 120 px column.
                text = Fmt.Count(contentPairs);
                note = "(partial)";
            }
            else if (contentState == "done")
            {
                text = Fmt.Count(contentPairs);
                note = "in " + Fmt.Count(contentPairFiles) + (contentPairFiles == 1 ? " file" : " files");
            }
            else text = "–";
            protectSecrets.Text = text;
            protectSecretsNote.Text = note;
            protectSecretsNote.Visibility = note.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        // ---------------------------------------------------------------- The content scan

        // The page's own test for "the content scan may run": consent exists only when the user turned it on.
        internal bool ContentGate()
        {
            return ContentConsent.FromStore(protectStore) != null;
        }

        // The switch, the status line under its title, and the progress strip.
        void ShowContentCard()
        {
            if (protectContentSwitch == null) return;
            bool on = protectStore.ContentScan;
            SetContentSwitch(on);
            string line;
            if (!on) line = "Off. Protect has only checked file names and places.";
            else if (contentState == "running") line = "On. Reading text files now.";
            else if (contentState == "done")
                line = "On. Read " + Fmt.Count(contentPlanFiles) + " text files in this scan for " + PatternCount() + " kinds of key.";
            else if (contentState == "stopped")
                line = "On. Stopped after " + Fmt.Count(contentDoneFiles) + " of " + Fmt.Count(contentPlanFiles) + " text files.";
            else line = "On. Text files are read after each scan.";
            protectContentLine.Text = line;
            ShowContentProgress();
        }

        void ShowContentProgress()
        {
            if (protectContentProgress == null) return;
            bool running = contentState == "running" && protectStore.ContentScan;
            bool stopped = contentState == "stopped" && protectStore.ContentScan;
            protectContentProgress.Visibility = running || stopped ? Visibility.Visible : Visibility.Collapsed;
            protectContentTitleRow.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
            protectContentAgain.Visibility = stopped ? Visibility.Visible : Visibility.Collapsed;
            protectContentCancel.IsEnabled = running && (snapFrozen || (contentCts != null && !contentCts.IsCancellationRequested));
            if (!running && !stopped) return;

            long done, total, bytesRead, processed, totalBytes;
            TimeSpan elapsed;
            ContentProgress p = contentProgress;
            if (snapFrozen)
            {
                // --dialog protect-content-progress and protect-content-stopped: the numbers of section 7.3.
                done = SnapDone;
                total = SnapTotal;
                bytesRead = SnapRead;
                processed = SnapRead;
                totalBytes = SnapTotalBytes;
                elapsed = TimeSpan.FromSeconds(10);
            }
            else if (p != null)
            {
                done = Interlocked.Read(ref p.DoneFiles);
                total = Interlocked.Read(ref p.TotalFiles);
                bytesRead = Interlocked.Read(ref p.BytesRead);
                processed = Interlocked.Read(ref p.ProcessedBytes);
                totalBytes = Interlocked.Read(ref p.TotalBytes);
                elapsed = p.Clock.Elapsed;
            }
            else
            {
                done = contentDoneFiles;
                total = contentPlanFiles;
                bytesRead = processed = totalBytes = 0;
                elapsed = TimeSpan.Zero;
            }
            if (total <= 0 && contentPlan != null) total = contentPlan.Files.Length;
            if (totalBytes <= 0 && contentPlan != null) totalBytes = contentPlan.TotalBytes;

            // Both halves count: on this PC each open costs more than the bytes read.
            double f = 0;
            if (total > 0) f += 0.5 * Math.Min(1.0, (double)done / total);
            else f += 0.5;
            if (totalBytes > 0) f += 0.5 * Math.Min(1.0, (double)processed / totalBytes);
            else f += 0.5 * (total > 0 ? Math.Min(1.0, (double)done / total) : 1.0);
            protectContentBar.Value = Math.Max(0, Math.Min(1000, f * 1000));

            if (stopped)
            {
                protectContentText.Text = "Stopped after " + Fmt.Count(done) + " of " + Fmt.Count(total) + " files. Findings so far are shown.";
                return;
            }
            var parts = new List<string>();
            parts.Add(Fmt.Count(done) + " of " + Fmt.Count(total) + " files");
            parts.Add(Fmt.Size(bytesRead) + " read");
            if (snapFrozen)
            {
                parts.Add(Fmt.Size(SnapRate) + "/s");
                parts.Add("about " + LeftText(TimeSpan.FromSeconds(40)) + " left");
            }
            else if (elapsed.TotalSeconds >= 5)
            {
                double rate = bytesRead / Math.Max(0.001, elapsed.TotalSeconds);
                parts.Add(Fmt.Size((long)rate) + "/s");
                TimeSpan left = TimeLeft(elapsed, f);
                if (left > TimeSpan.Zero) parts.Add("about " + LeftText(left) + " left");
            }
            protectContentText.Text = string.Join(" · ", parts.ToArray());
        }

        const long SnapDone = 4100, SnapTotal = 14820, SnapRead = 52L << 20, SnapTotalBytes = 176L << 20, SnapRate = 21L << 20;

        // Time left in whole seconds ("about 40 s left"); a minute or more uses Fmt.Duration.
        static string LeftText(TimeSpan t)
        {
            if (t.TotalSeconds < 59.5) return Math.Max(1, (int)Math.Round(t.TotalSeconds)) + " s";
            return Fmt.Duration(t);
        }

        // elapsed × (1 − f) / f, averaged over the estimates of the last 10 s so it does not jump.
        TimeSpan TimeLeft(TimeSpan elapsed, double f)
        {
            if (f <= 0.001 || f >= 1) return TimeSpan.Zero;
            double estimate = elapsed.TotalSeconds * (1 - f) / f;
            double now = elapsed.TotalSeconds;
            contentEstimates.Add(new KeyValuePair<double, double>(now, estimate));
            while (contentEstimates.Count > 0 && contentEstimates[0].Key < now - 10) contentEstimates.RemoveAt(0);
            double sum = 0;
            foreach (KeyValuePair<double, double> e in contentEstimates) sum += e.Value;
            return TimeSpan.FromSeconds(Math.Max(0, sum / contentEstimates.Count));
        }

        void OnContentTick()
        {
            if (contentState != "running") return;
            ContentRun run = contentRun;
            ScanResult r = result;
            if (run != null && r == contentFor && !snapFrozen)
            {
                // New findings are copied under the run's lock. A file recycled or rescanned meanwhile is dropped.
                // They wait for the next refresh, at most every 2 s, even when nothing new arrives after them.
                int before = contentCopied;
                contentCopied = CopyContentFindings(run, contentCopied, r, null);
                if (contentCopied != before) contentFindingsPending = true;
                if (contentFindingsPending && contentRefreshClock.Elapsed >= TimeSpan.FromSeconds(2))
                {
                    contentRefreshClock.Restart();
                    RefreshProtect(true);
                    return;
                }
            }
            ShowContentProgress();
            ShowSecretsFigure();
        }

        bool contentSwitchSync;  // the page is setting the switch itself

        void SetContentSwitch(bool on)
        {
            contentSwitchSync = true;
            try { protectContentSwitch.IsChecked = on; }
            finally { contentSwitchSync = false; }
        }

        async void OnContentSwitchToggled(object sender, RoutedEventArgs e)
        {
            if (contentSwitchSync) return;
            // The switch never runs ahead of consent: it shows the stored choice until the dialog says yes.
            bool wanted = protectContentSwitch.IsChecked == true;
            SetContentSwitch(protectStore.ContentScan);
            if (wanted && !protectStore.ContentScan) await AskContentConsent();
            else if (!wanted && protectStore.ContentScan) TurnContentOff();
        }

        async Task AskContentConsent()
        {
            ScanResult r = result;
            if (r == null) return;
            ContentPlan plan;
            try { plan = SecretScan.Plan(r, protectStore, null); }
            catch (Exception ex)
            {
                ShowError(ex.Message);
                return;
            }
            bool none = plan.Files.Length == 0;
            if (!await ShowDialog("Read text files for keys?", ContentDialogBody(plan, r), none ? "Turn on" : "Turn on and read", "Cancel", false))
                return;
            protectStore.ContentScan = true;
            SaveProtectStore();
            if (result == null)
            {
                ShowContentCard();
                return;
            }
            if (result != r)
            {
                try { plan = SecretScan.Plan(result, protectStore, null); }
                catch (Exception) { plan = null; }
            }
            if (plan != null) StartContentScan(plan);
            else RefreshProtect();
        }

        // The consent dialog: ProtectInfo.ContentDialog's paragraphs, with the folder list in a small box. A line
        // ending with ":" introduces the list; the lines after it that are not sentences are the folders.
        UIElement ContentDialogBody(ContentPlan plan, ScanResult r)
        {
            var body = new StackPanel();
            string[] lines;
            try { lines = ProtectInfo.ContentDialog(plan, r.Root.FullPath) ?? new string[0]; }
            catch (Exception) { lines = new string[0]; }
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i] ?? "";
                TextBlock para = Paragraph(line, 14);
                para.Margin = new Thickness(0, i == 0 ? 0 : 10, 0, 0);
                if (line == "Nothing read here is kept after the scan.")
                {
                    para.Style = (Style)Res("BodyStrong");
                    para.FontSize = 14;
                    para.ClearValue(TextBlock.ForegroundProperty);
                }
                body.Children.Add(para);
                if (!line.TrimEnd().EndsWith(":", StringComparison.Ordinal)) continue;
                var folders = new List<string>();
                while (i + 1 < lines.Length && lines[i + 1] != null && !IsSentence(lines[i + 1]))
                {
                    i++;
                    foreach (string part in lines[i].Split('\n'))
                        if (part.Trim().Length > 0) folders.Add(part.Trim());
                }
                if (folders.Count == 0) continue;
                body.Children.Add(new TextBox
                {
                    Text = string.Join("\n", folders.ToArray()),
                    Style = (Style)Res("LogBox"),
                    MaxHeight = 110,
                    Margin = new Thickness(0, 8, 0, 0)
                });
            }
            return body;
        }

        static bool IsSentence(string s)
        {
            string t = s.TrimEnd();
            return t.EndsWith(".", StringComparison.Ordinal) && t.IndexOf('\n') < 0;
        }

        void TurnContentOff()
        {
            CancelContentScan();
            if (result != null)
            {
                result.ContentFindings.Clear();
                result.ContentNodes.Clear();
            }
            protectStore.ContentScan = false;
            SaveProtectStore();
            contentState = null;
            contentPlan = null;
            RefreshProtect();
            Toast("Content scan off. Its findings were cleared.");
        }

        void StartContentScan(ContentPlan plan)
        {
            StartContentScan(plan, null, null);
        }

        // Runs the content scan on its own threads. It does not set busy: Scan, Rescan, Recycle and Move stay
        // available, and leaving the page does not stop it. under is the folder of a partial run after an edit,
        // and partialBase the state the page had before that chain of partial runs ("done", "stopped" or null).
        // A new run first waits for the one before it to finish its last files, so at most ContentWorkers files
        // are read at a time and two runs never share the workers' buffer slots.
        async void StartContentScan(ContentPlan plan, DirNode under, string partialBase)
        {
            // A full run the user stopped, still finishing its last files: what it found is kept (below).
            ContentRun old = contentRun;
            bool oldStopped = old != null && contentRunning && contentUnder == null && contentCts != null && contentCts.IsCancellationRequested;
            ContentPlan oldPlan = contentPlan;
            ContentProgress oldProgress = contentProgress;
            ScanResult oldFor = contentFor;
            int oldCopied = contentCopied;
            Task drain = contentTask;
            CancelContentScan();
            ScanResult r = result;
            ContentConsent consent = ContentConsent.FromStore(protectStore);
            if (r == null || plan == null || consent == null) return;
            var cts = contentCts = new CancellationTokenSource();
            if (drain != null && !drain.IsCompleted)
            {
                try { await drain; }
                catch (Exception) { }
            }
            if (oldStopped && under != null && result == oldFor && oldFor != null)
            {
                // The stopped run counts as stopped: its findings outside the edited folder stay, with its numbers.
                CopyContentFindings(old, oldCopied, oldFor, Norm(under.FullPath));
                if (oldPlan != null) contentPlanFiles = oldPlan.Files.Length;
                if (oldProgress != null) contentDoneFiles = Interlocked.Read(ref oldProgress.DoneFiles);
            }
            // A newer run, a new scan or the switch turned off while waiting: this one does not start.
            if (contentCts != cts || result != r || ContentConsent.FromStore(protectStore) == null) return;
            CancellationToken token = cts.Token;
            var p = new ContentProgress();
            contentProgress = p;
            contentPlan = plan;
            contentFor = r;
            contentRun = null;
            contentCopied = 0;
            contentUnder = under;
            contentPartialBase = partialBase;
            contentEstimates.Clear();
            // A full run reads every file again, so its findings replace the earlier ones as they come in.
            if (under == null)
            {
                r.ContentFindings.Clear();
                r.ContentNodes.Clear();
            }
            ContentRun run;
            try { run = SecretScan.Begin(consent, plan, p, token); }
            catch (Exception ex)
            {
                contentCts = null;
                ShowError(ex.Message);
                return;
            }
            contentRun = run;
            contentState = "running";
            contentRunning = true;
            contentRefreshClock.Restart();
            contentTimer.Start();
            RefreshProtect();

            Task<ContentResult> job = Task.Run(() => run.Wait());
            contentTask = job;
            ContentResult res = null;
            try { res = await job; }
            catch (Exception) { res = null; }
            // A newer run, a new scan, the switch turned off or the window closing: this run's result is not used.
            if (contentCts != cts || result != r) return;
            contentTimer.Stop();
            contentRunning = false;
            contentCts = null;
            contentRun = null;

            // The findings the timer has not copied yet. A file recycled or rescanned meanwhile is dropped.
            bool cancelled = res == null || res.Cancelled || token.IsCancellationRequested;
            contentCopied = CopyContentFindings(run, contentCopied, r, null);
            long done = Interlocked.Read(ref p.DoneFiles);
            if (under == null || cancelled)
            {
                contentPlanFiles = plan.Files.Length;
                contentDoneFiles = cancelled ? done : plan.Files.Length;
                contentState = cancelled ? "stopped" : "done";
            }
            else contentState = partialBase == "stopped" ? "stopped" : "done";

            if (snapContent == "protect-content-progress" || snapContent == "protect-content-stopped")
            {
                // The snapshot shows a run in progress or stopped, with the fixed numbers of section 7.3.
                snapFrozen = true;
                contentPlanFiles = SnapTotal;
                contentDoneFiles = SnapDone;
                contentState = snapContent == "protect-content-progress" ? "running" : "stopped";
            }
            RefreshProtect();
            if (contentState != "done" || under != null) return;
            // The same count as the Secrets in text figure (section 5.4), so the toast and the strip agree.
            if (contentPairs > 0)
                Toast("Content scan done. " + Fmt.Count(contentPairs) + (contentPairs == 1 ? " key in " : " keys in ") +
                      Fmt.Count(contentPairFiles) + (contentPairFiles == 1 ? " file." : " files."));
            else
                Toast("Content scan done. No keys found in " + Fmt.Count(plan.Files.Length) + " text files.");
        }

        // Copies a run's findings from index `from` into r, and returns the index to copy from next time. A file
        // that left the tree is dropped, and so is one under skipUnder (a normalized folder about to be read again).
        int CopyContentFindings(ContentRun run, int from, ScanResult r, string skipUnder)
        {
            if (run == null || r == null) return from;
            var f = new List<Finding>();
            var n = new List<Node>();
            int next = run.CopyFindings(from, f, n);
            for (int i = 0; i < f.Count && i < n.Count; i++)
            {
                if (!r.IsAttached(n[i])) continue;
                if (skipUnder != null && f[i] != null && Under(Norm(f[i].Path), skipUnder)) continue;
                r.ContentFindings.Add(f[i]);
                r.ContentNodes.Add(n[i]);
            }
            return next;
        }

        // Stops the job for good: a new scan, the switch turned off, a newer run or the window closing. Its
        // result is dropped. The Cancel button uses StopContentScan instead, which keeps the findings.
        void CancelContentScan()
        {
            if (contentCts != null) contentCts.Cancel();
            contentCts = null;
            contentRun = null;
            contentRunning = false;
            if (contentTimer != null) contentTimer.Stop();
            if (contentState == "running") contentState = null;
        }

        void StopContentScan()
        {
            if (contentCts != null) contentCts.Cancel();
            protectContentCancel.IsEnabled = false;
        }

        // "Read all again": consent is stored, so there is no dialog.
        void ReadContentAgain()
        {
            if (result == null || !protectStore.ContentScan) return;
            ContentPlan plan;
            try { plan = SecretScan.Plan(result, protectStore, null); }
            catch (Exception ex)
            {
                ShowError(ex.Message);
                return;
            }
            StartContentScan(plan);
        }

        // After a full scan: the content scan runs again by itself when it is on, since consent is remembered.
        void ContentAfterScan()
        {
            contentState = null;
            contentPlan = null;
            contentPartialBase = null;
            contentPlanFiles = contentDoneFiles = 0;
            showAllCards.Clear();
            protectCardLimit = CardsPerPage;
            if (!protectStore.ContentScan || options.Snapshot != null || result == null) return;
            ReadContentAgain();
        }

        // True while a full run is reading and the user has not pressed Cancel.
        bool FullRunGoing()
        {
            return contentRunning && contentUnder == null && contentCts != null && !contentCts.IsCancellationRequested;
        }

        // After a partial rescan or a recycle: the findings under the edited folder are dropped and that folder
        // alone is read again. A full run that was still going starts over, so nothing is missed. A partial run
        // that is still going is replaced by one over the folder that holds both, so neither folder is missed,
        // and the state from before the first edit is kept: a stopped scan stays stopped.
        void ContentAfterEdit(DirNode edited)
        {
            if (result == null || !protectStore.ContentScan || options.Snapshot != null) return;
            if (FullRunGoing() || edited == null || !Attached(edited))
            {
                ReadContentAgain();
                return;
            }
            DirNode folder = edited;
            string partialBase;
            if (contentRunning && contentUnder != null)
            {
                partialBase = contentPartialBase;
                folder = CommonFolder(contentUnder, edited);
            }
            else if (contentRunning) partialBase = "stopped";  // a full run the user stopped, still finishing
            else partialBase = contentState;
            ReadFolderAgain(folder, partialBase);
        }

        void ReadFolderAgain(DirNode folder, string partialBase)
        {
            string root = Norm(folder.FullPath);
            for (int i = result.ContentFindings.Count - 1; i >= 0; i--)
            {
                Finding f = result.ContentFindings[i];
                if (f != null && !Under(Norm(f.Path), root)) continue;
                result.ContentFindings.RemoveAt(i);
                if (i < result.ContentNodes.Count) result.ContentNodes.RemoveAt(i);
            }
            ContentPlan plan;
            try { plan = SecretScan.Plan(result, protectStore, folder); }
            catch (Exception) { return; }
            StartContentScan(plan, folder, partialBase);
        }

        // The nearest folder of this scan that holds both a (which may have left the tree) and b.
        DirNode CommonFolder(DirNode a, DirNode b)
        {
            string pa = Norm(a.FullPath);
            for (DirNode d = b; d != null; d = d.Parent)
                if (Under(pa, Norm(d.FullPath))) return d;
            return result.Root;
        }

        // A folder trusted while a run is reading: the run starts again without it, so its files are not opened.
        void ContentAfterTrust()
        {
            if (result == null || !protectStore.ContentScan || options.Snapshot != null) return;
            if (!contentRunning || contentCts == null || contentCts.IsCancellationRequested) return;
            if (contentUnder == null) ReadContentAgain();
            else ContentAfterEdit(contentUnder.Detached || !Attached(contentUnder) ? null : contentUnder);
        }

        // A folder no longer trusted: its files were left out of the content scan, so that folder is read now.
        void ContentAfterUntrust(string folder)
        {
            if (result == null || !protectStore.ContentScan || options.Snapshot != null || folder == null) return;
            if (FullRunGoing()) { ReadContentAgain(); return; }
            Node n = null;
            try { n = result.FindNode(folder); }
            catch (Exception) { n = null; }
            var d = n as DirNode;
            if (d == null || !Attached(d)) return;
            ContentAfterEdit(d);
        }
        // ---- Hidden by you

        void RefreshHidden(List<ProtectEntry> hidden)
        {
            int dismissed = 0;
            var trustedFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var rows = new List<ProtectHiddenVm>();
            foreach (ProtectEntry e in hidden)
            {
                // A content finding is listed as "<Kind>, line N"; by-name findings have line 0.
                string kind = e.F.Line > 0 ? e.F.Kind + ", line " + e.F.Line : e.F.Kind;
                var row = new ProtectHiddenVm { Finding = e.F, Kind = kind, Path = e.Path };
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
                else if (tag == "protect-open-line" && path != null) OpenAtLine(path, card.Line, card.Column);
                else if (tag == "protect-copy" && path != null) CopyText(path);
                else if (tag == "protect-dismiss") DismissCard(card);
                else if (tag == "protect-trust") TrustCard(card);
                else if (tag == "protect-show-all")
                {
                    showAllCards.Add(CardKey(card));
                    RefreshProtect();
                }
            }
            else if (item != null)
            {
                if (tag == "item-show" && item.Path != null) Try(() => ShellOps.ShowInExplorer(item.Path));
                else if (tag == "item-open" && item.Path != null) Try(() => ShellOps.Open(item.Path));
                else if (tag == "item-open-line" && item.Path != null) OpenAtLine(item.Path, item.Line, item.Column);
                else if (tag == "item-hide" && item.Finding != null) DismissPattern(item.Finding);
                else if (tag == "item-trust" && item.TrustFolder != null) TrustWithDialog(item.TrustFolder);
            }
        }

        // Opens the file in a known text editor at the line. Never through the file's own association, which for
        // a script would run it.
        void OpenAtLine(string path, int line, int column)
        {
            bool opened = false;
            try { opened = ShellOps.OpenAt(path, line, column); }
            catch (Exception ex)
            {
                ShowError(ex.Message);
                return;
            }
            if (!opened) Toast("No text editor was found to open this file at its line.", "");
        }

        // Hide on a match row: that kind of key in that file, on every line. The dismissal key has no line in it.
        void DismissPattern(Finding f)
        {
            protectStore.Dismiss(f);
            SaveProtectStore();
            RefreshProtect();
            Toast(ProtectWording.ContentPlural(f.PatternId) + " in " + LastSegment(f.Path) + " hidden.", "", "Undo", () =>
            {
                protectStore.Undismiss(f);
                SaveProtectStore();
                RefreshProtect();
            });
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
            int line = 0, column = 0;
            bool atLine = false;
            var item = element.DataContext as ProtectItemVm;
            var card = element.DataContext as ProtectCardVm;
            // Open (the file's own app) is offered only where the card or row offers it: documents and vaults.
            // A key, certificate or sign-in file gets Show in Explorer, since its app can run or import it. A file
            // with a key in its text gets Open at line, in a text editor, when one is found.
            if (item != null)
            {
                n = item.Node;
                path = item.Path;
                canOpen = item.OpenVisibility == Visibility.Visible;
                atLine = item.CanOpenAtLine;
                line = item.Line;
                column = item.Column;
            }
            else if (card != null)
            {
                n = card.Node;
                path = card.ActionPath ?? card.Path;
                canOpen = card.PrimaryTag == "protect-open";
                atLine = card.CanOpenAtLine;
                line = card.Line;
                column = card.Column;
            }
            else return;
            e.Handled = true;
            if (n != null && Attached(n))
            {
                string at = path;
                Action openAt = atLine && at != null ? new Action(() => OpenAtLine(at, line, column)) : null;
                ShowMenu(n, protectFindings, canOpen || n is DirNode, openAt);
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
            ContentAfterTrust();
            Toast("Protect no longer lists anything in " + LastSegment(folder) + ". The files were not changed.", "\uE73E", "Undo", () =>
            {
                protectStore.Untrust(folder);
                SaveProtectStore();
                RefreshProtect();
                ContentAfterUntrust(folder);
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
            if (vm.TrustedFolder != null) ContentAfterUntrust(vm.TrustedFolder);
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
            if (dialog != null && dialog.StartsWith("protect-content", StringComparison.Ordinal)) snapContent = dialog;
            Navigate(protectPage);
            RefreshProtect();
            if (dialog == "protect-content") { Task asking = AskContentConsent(); }
            if ((dialog == "protect-content-run" || dialog == "protect-content-progress" || dialog == "protect-content-stopped") &&
                protectHome != null)
            {
                // In memory only (SaveProtectStore does nothing in a snapshot), and only on a --protect-home
                // fixture tree, so no capture reads real files. Without --protect-home the switch stays off.
                protectStore.ContentScan = true;
                ReadContentAgain();
            }
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
            if (dialog == "protect-content-progress" || dialog == "protect-content-stopped")
            {
                // The summary strip, the content-scan card with its progress, and the cards below.
                target = protectContentCard;
                above = 190;
            }
            if (dialog == "protect-content-run")
            {
                // The first card of a file with a key in its text.
                foreach (ProtectCardVm c in protectCards)
                {
                    if (c.Group != "secret" || !c.Expanded) continue;
                    target = protectFindings.ItemContainerGenerator.ContainerFromItem(c) as FrameworkElement;
                    break;
                }
            }
            ScrollProtectTo(target, above);
        }

        // Scrolls the Protect page so target sits "above" pixels below the top. Also used by "What Protect reads".
        void ScrollProtectTo(FrameworkElement target, double above)
        {
            var page = protectPage as ScrollViewer;
            if (page == null || target == null) return;
            page.UpdateLayout();
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
                // The content scan's result is merged on the UI thread after its task ends, so both are waited for.
                done = done && (contentTask == null || (contentTask.IsCompleted && !contentRunning));
                if (!done && clock.Elapsed < TimeSpan.FromSeconds(20)) return;
                timer.Stop();
                then();
            };
            timer.Start();
        }


        // ---------------------------------------------------------------- Paths (shared with the cards)

        static string Norm(string path)
        {
            return ProtectPaths.Norm(path);
        }

        static bool Under(string normalized, string root)
        {
            return ProtectPaths.Under(normalized, root);
        }

        static string ParentOf(string path)
        {
            return ProtectPaths.ParentOf(path);
        }

        static string LastSegment(string path)
        {
            return ProtectPaths.LastSegment(path);
        }

        static string DriveLetter(string path)
        {
            return ProtectPaths.DriveLetter(path);
        }
    }
}

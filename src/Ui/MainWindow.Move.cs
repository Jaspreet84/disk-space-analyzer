using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Threading;

namespace DiskSpace
{
    // The drives on this PC and the suggestions for one scan, worked out together on a background thread.
    sealed class MovePlan
    {
        public List<DriveProfile> Drives;
        public List<MoveSuggestion> Suggestions;

        public static MovePlan For(ScanResult r)
        {
            var plan = new MovePlan { Drives = DiskSpace.Drives.Load() };
            plan.Suggestions = Placement.Suggest(r, plan.Drives);
            return plan;
        }
    }

    sealed partial class MainWindow
    {
        // ---------------------------------------------------------------- Move to other drives

        ItemsControl moveDrives, moveList;
        TextBlock moveSummary, moveProgressTitle, moveProgressText;
        Border moveProgressCard;
        ProgressBar moveProgressBar;
        Button moveCancelButton;
        MovePlan movePlan = new MovePlan { Drives = new List<DriveProfile>(), Suggestions = new List<MoveSuggestion>() };
        CancellationTokenSource moveCancel;
        TransferProgress moveProgress;
        string moveTitle, movePhase;
        readonly Stopwatch movePhaseClock = new Stopwatch();
        readonly DispatcherTimer moveTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };

        void WireMove()
        {
            moveDrives = E<ItemsControl>("MoveDrives");
            moveList = E<ItemsControl>("MoveList");
            moveSummary = E<TextBlock>("MoveSummary");
            moveProgressCard = E<Border>("MoveProgressCard");
            moveProgressTitle = E<TextBlock>("MoveProgressTitle");
            moveProgressText = E<TextBlock>("MoveProgressText");
            moveProgressBar = E<ProgressBar>("MoveProgressBar");
            moveCancelButton = E<Button>("MoveCancel");
            moveCancelButton.Click += (s, e) => { if (moveCancel != null) moveCancel.Cancel(); };
            moveTimer.Tick += (s, e) => ShowMoveProgress();
            Window.Closing += (s, e) => { if (moveCancel != null) moveCancel.Cancel(); };
            moveList.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler((s, e) =>
            {
                var b = e.OriginalSource as Button;
                var vm = b == null ? null : b.DataContext as MoveVm;
                if (vm == null) return;
                MoveSuggestion m = vm.Suggestion;
                if ("move-show".Equals(b.Tag)) Try(() => ShellOps.ShowInExplorer(m.Item.FullPath));
                else if ("move-primary".Equals(b.Tag)) RunSuggestion(m, false);
                else if ("move-secondary".Equals(b.Tag)) RunSuggestion(m, true);
            }));
        }

        void RefreshMove()
        {
            if (result == null) return;
            DriveProfile scanned = Drives.For(movePlan.Drives, result.Root.FullPath);
            var driveItems = new List<MoveDriveVm>();
            foreach (DriveProfile d in movePlan.Drives)
            {
                driveItems.Add(new MoveDriveVm
                {
                    Glyph = d.Role == DriveRole.External ? "" : "",
                    Name = d.Name,
                    Kind = d.Kind + "  ·  " + d.FileSystem,
                    FreeText = Fmt.Size(d.Free) + " free of " + Fmt.Size(d.Total),
                    Purpose = d.Purpose,
                    ScannedVisibility = d == scanned ? Visibility.Visible : Visibility.Collapsed
                });
            }
            moveDrives.ItemsSource = driveItems;

            long freed = 0, copies = 0;
            int done = 0;
            var items = new List<MoveVm>();
            foreach (MoveSuggestion m in movePlan.Suggestions)
            {
                if (m.AlreadyCopied) done++;
                else if (m.Action == MoveAction.Copy) copies += m.Item.Size;
                else if (!InsideOtherSuggestion(m)) freed += m.Item.Size;
                items.Add(ToVm(m));
            }
            moveList.ItemsSource = items;

            var parts = new List<string>();
            if (freed > 0) parts.Add("Moving these would free about " + Fmt.Size(freed) + " on the " + scanned.Letter + " drive.");
            if (copies > 0) parts.Add(Fmt.Size(copies) + " of backups and photos would get a second copy.");
            if (done > 0) parts.Add(done + (done == 1 ? " item already has" : " items already have") + " a copy on another drive.");
            if (items.Count == 0)
                parts.Add(scanned == null ? "Suggestions need a scan of a local drive or a folder on one."
                    : scanned.Role == DriveRole.External ? scanned.Letter + " is an external drive, the place for archives and backups. Nothing here needs to move."
                    : movePlan.Drives.Count < 2 ? "This PC has only one drive, so there is nowhere else to move things."
                    : "Nothing in this scan would be better on another drive.");
            moveSummary.Text = string.Join(" ", parts);
        }

        // A file inside a folder that is also suggested (an image inside Downloads, say) must not be counted twice.
        bool InsideOtherSuggestion(MoveSuggestion m)
        {
            foreach (MoveSuggestion other in movePlan.Suggestions)
            {
                var dir = other.Item as DirNode;
                if (other != m && dir != null && m.Item.IsUnder(dir)) return true;
            }
            return false;
        }

        MoveVm ToVm(MoveSuggestion m)
        {
            string action, secondary = null;
            if (m.AlreadyCopied) action = "Check the copy";
            else if (m.Action == MoveAction.Copy) { action = "Copy to " + m.To.Letter; if (m.CanMoveInstead) secondary = "Move instead…"; }
            else if (m.Action == MoveAction.Move) action = "Move to " + m.To.Letter;
            else if (m.Action == MoveAction.WslMove) action = "Move to " + m.To.Letter + "…";
            else action = "How to move it";

            string target = m.AlreadyCopied ? "A copy is already at " + m.Destination
                : (m.Action == MoveAction.Copy ? "Copy to " : "Move to ") + m.Destination + "  ·  " + m.To.Kind.ToLowerInvariant();
            // Copies and moves the app does are the recommended action; optional moves and how-tos get a plain button.
            bool recommended = m.AlreadyCopied || m.Action == MoveAction.Copy || m.Action == MoveAction.Move;
            return new MoveVm
            {
                Suggestion = m,
                Glyph = KindGlyph(m.Kind),
                Name = m.Kind == MoveKind.WslDisk ? m.Distro + " (WSL)" : m.Kind == MoveKind.DockerDisk ? "Docker Desktop data" : m.Item.Name,
                ActionStyle = (Style)Res(recommended ? "AccentButton" : "StandardButton"),
                Folder = m.Item.Parent == null ? "" : m.Item.Parent.FullPath,
                KindName = m.KindName,
                Usage = m.Usage,
                UsageVisibility = string.IsNullOrEmpty(m.Usage) ? Visibility.Collapsed : Visibility.Visible,
                Reason = m.AlreadyCopied ? "There are two copies on two drives. Checking compares every file with the original." : m.Reason,
                TargetGlyph = m.AlreadyCopied ? "" : "",
                TargetText = target,
                TargetBrush = (Brush)Res(m.AlreadyCopied ? "Good" : "AccentText"),
                SizeText = Fmt.Size(m.Item.Size),
                ActionText = action,
                SecondaryText = secondary,
                SecondaryVisibility = secondary == null ? Visibility.Collapsed : Visibility.Visible
            };
        }

        static string KindGlyph(MoveKind kind)
        {
            switch (kind)
            {
                case MoveKind.Backup: return "";
                case MoveKind.Media: return "";
                case MoveKind.DiskImage:
                case MoveKind.OldInstaller: return "";
                case MoveKind.PersonalFolder: return "";
                case MoveKind.WslDisk: return "";
                case MoveKind.DockerDisk: return "";
                default: return "";
            }
        }

        async void RunSuggestion(MoveSuggestion m, bool moveInstead)
        {
            if (busy || moveCancel != null || result == null) return;
            if (m.AlreadyCopied) await CheckCopy(m);
            else if (m.Action == MoveAction.Copy && !moveInstead) await CopyOrMove(m, false);
            else if (m.Action == MoveAction.Copy || m.Action == MoveAction.Move) await CopyOrMove(m, true);
            else if (m.Action == MoveAction.WslMove) await MoveWsl(m);
            else await ShowMoveGuide(m);
        }

        async Task CopyOrMove(MoveSuggestion m, bool move)
        {
            string name = m.Item.Name, src = m.Item.FullPath;
            var dir = m.Item as DirNode;
            var body = new StackPanel();
            body.Children.Add(new TextBlock { Text = name, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis });
            body.Children.Add(new TextBlock
            {
                Text = Fmt.Size(m.Item.Size) + (dir != null ? " in " + Fmt.Count(dir.FileCount) + " files" : "") + "  ·  to " + m.Destination,
                Style = (Style)Res("Caption"),
                TextWrapping = TextWrapping.Wrap
            });
            body.Children.Add(Paragraph(move
                ? "It's copied first and every file is compared with the original. Only then does the original go to the Recycle Bin. " +
                  "If it's too big for the Recycle Bin, Windows asks before deleting it for good."
                : "It's copied and then every file is compared with the original. The original stays where it is.", 14));
            if (move && m.Action == MoveAction.Copy)
                body.Children.Add(Paragraph("Moving leaves a single copy, on " + m.To.Letter + ". If that drive fails or gets lost, so does this. " +
                                            "Copying keeps one on each drive.", 12));
            body.Children.Add(Paragraph(EstimateText(m.Item.Size) + " Keep both drives connected until it finishes. If it's interrupted, " +
                                        "starting again picks up where it stopped.", 12));
            string verb = move ? "Move" : "Copy";
            if (!await ShowDialog(verb + " to " + m.To.Letter + "?", body, verb, "Cancel", move && m.Action == MoveAction.Copy)) return;

            long free = new DriveInfo(m.To.Root).AvailableFreeSpace;
            if (free < m.Item.Size + (1L << 30))
            {
                ShowError(m.To.Letter + " has only " + Fmt.Size(free) + " free, which isn't enough for " + Fmt.Size(m.Item.Size) + ".");
                return;
            }

            if (!await CopyAndCheck(m, (move ? "Moving " : "Copying ") + name + " to " + m.To.Letter, true)) return;
            if (!move)
            {
                m.AlreadyCopied = true;
                RefreshMove();
                Toast("Copied " + name + " to " + m.To.Letter + " and checked every file");
                return;
            }

            bool gone;
            try { gone = ShellOps.MoveToRecycleBin(src, Handle); }
            catch (Exception ex)
            {
                ShowError("The copy is complete and checked, but the original couldn't be removed. " + ex.Message);
                return;
            }
            if (!gone)
            {
                Toast("The copy is complete and checked. The original was kept.", "");
                return;
            }
            DirNode parent = m.Item.Parent;
            result.Replace(m.Item, null);
            await AfterEdit(m.Item, null, parent);
            Toast("Moved " + name + " to " + m.To.Letter + " and checked every file");
        }

        async Task CheckCopy(MoveSuggestion m)
        {
            if (await CopyAndCheck(m, "Checking the copy of " + m.Item.Name, false))
                Toast("Every file in the copy on " + m.To.Letter + " matches the original");
        }

        // Copies (unless only checking), then compares every file with the original. If some files fail, it offers to
        // copy exactly those again and check once more. True once every file matches.
        async Task<bool> CopyAndCheck(MoveSuggestion m, string title, bool copyFirst)
        {
            string src = m.Item.FullPath;
            HashSet<string> recopy = null;
            while (true)
            {
                HashSet<string> again = recopy;
                bool copy = copyFirst || again != null;
                List<TransferProblem> problems = await RunTransfer(title, (p, token) =>
                {
                    if (copy)
                    {
                        List<TransferProblem> failed = Transfer.Copy(src, m.Destination, p, token, again);
                        if (failed.Count > 0 || token.IsCancellationRequested) return failed;
                    }
                    return Transfer.Verify(src, m.Destination, p, token);
                });
                if (problems == null) return false;  // cancelled or failed; already reported
                if (problems.Count == 0) return true;

                var lines = new List<string>();
                recopy = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (TransferProblem x in problems)
                {
                    lines.Add(x.ToString());
                    recopy.Add(x.Path);
                }
                string heading = Fmt.Count(problems.Count) + (problems.Count == 1 ? " file doesn't match" : " files don't match");
                if (!await ShowProblemList(heading, "The original wasn't touched. A full or disconnected drive is the usual cause. " +
                                           "Copying them again replaces just these files in the copy.", lines, "Copy them again"))
                    return false;
                title = "Copying " + Fmt.Count(problems.Count) + (problems.Count == 1 ? " file" : " files") + " again";
            }
        }

        // Runs a copy or check on a worker thread with the progress card showing. Returns null if it was cancelled.
        async Task<List<TransferProblem>> RunTransfer(string title, Func<TransferProgress, CancellationToken, List<TransferProblem>> work)
        {
            busy = true;
            UpdateSelectionBar();
            moveCancel = new CancellationTokenSource();
            CancellationToken token = moveCancel.Token;
            moveProgress = new TransferProgress();
            TransferProgress p = moveProgress;
            moveTitle = title;
            movePhase = null;
            moveProgressCard.Visibility = Visibility.Visible;
            moveList.IsEnabled = false;
            ShowMoveProgress();
            moveTimer.Start();
            List<TransferProblem> problems = null;
            Exception failure = null;
            try
            {
                problems = await Task.Run(() =>
                {
                    Transfer.StayAwake(true);
                    try { return work(p, token); }
                    finally { Transfer.StayAwake(false); }
                });
            }
            catch (Exception ex) { failure = ex; }
            moveTimer.Stop();
            bool cancelled = token.IsCancellationRequested;
            moveCancel = null;
            moveProgress = null;
            moveProgressCard.Visibility = Visibility.Collapsed;
            moveList.IsEnabled = true;
            busy = false;
            UpdateSelectionBar();
            if (failure != null)
            {
                ShowError(failure.Message);
                return null;
            }
            if (cancelled)
            {
                Toast("Stopped. Starting again picks up where it stopped.", "");
                return null;
            }
            return problems;
        }

        void ShowMoveProgress()
        {
            TransferProgress p = moveProgress;
            if (p == null) return;
            string phase = p.Phase;
            if (phase != movePhase)
            {
                movePhase = phase;
                movePhaseClock.Restart();
            }
            double share = p.TotalBytes > 0 ? (double)p.DoneBytes / p.TotalBytes : 0;
            moveProgressBar.Value = share * 1000;
            // A copy job has two phases worth naming; a check has only one.
            bool twoPhases = !moveTitle.StartsWith("Checking", StringComparison.Ordinal);
            moveProgressTitle.Text = string.IsNullOrEmpty(phase) || !twoPhases ? moveTitle
                : moveTitle + "  ·  " + (phase == "Checking" ? "step 2 of 2, checking the copy" : "step 1 of 2, copying");
            if (string.IsNullOrEmpty(phase))
            {
                moveProgressText.Text = "Listing files…";
                return;
            }
            var parts = new List<string>();
            parts.Add(Fmt.Size(p.DoneBytes) + " of " + Fmt.Size(p.TotalBytes));
            parts.Add(Fmt.Count(p.DoneFiles) + " of " + Fmt.Count(p.TotalFiles) + " files");
            double seconds = movePhaseClock.Elapsed.TotalSeconds;
            if (seconds > 5 && p.DoneBytes > 0)
            {
                double rate = p.DoneBytes / seconds;
                parts.Add(Fmt.Size((long)rate) + "/s");
                parts.Add("about " + Fmt.Duration(TimeSpan.FromSeconds((p.TotalBytes - p.DoneBytes) / rate)) + " left");
            }
            moveProgressText.Text = string.Join("  ·  ", parts) + "  ·  " + p.Current;
        }

        // Copying and checking both read at roughly hard-drive speed, so about 2 x size / 100 MB/s.
        static string EstimateText(long bytes)
        {
            double minutes = 2.0 * bytes / (100.0 * 1024 * 1024) / 60;
            if (minutes < 2) return "This takes a minute or two.";
            if (minutes < 90) return "This takes about " + (int)Math.Ceiling(minutes / 5) * 5 + " minutes.";
            return "This takes about " + Math.Round(minutes / 60, 1) + " hours.";
        }

        // Lists problems in a dialog. With actionText, it offers that action and returns true if it was chosen.
        Task<bool> ShowProblemList(string title, string text, List<string> lines, string actionText = null)
        {
            var body = new StackPanel();
            body.Children.Add(Paragraph(text, 14));
            string list = string.Join("\n", lines.GetRange(0, Math.Min(200, lines.Count)));
            if (lines.Count > 200) list += "\n… and " + Fmt.Count(lines.Count - 200) + " more";
            body.Children.Add(new TextBox { Text = list, Style = (Style)Res("LogBox"), MaxHeight = 260, Margin = new Thickness(0, 14, 0, 0) });
            return ShowDialog(title, body, actionText ?? "Close", actionText == null ? null : "Close", false);
        }

        async Task MoveWsl(MoveSuggestion m)
        {
            var body = new StackPanel();
            body.Children.Add(Paragraph(m.Reason, 14));
            body.Children.Add(Paragraph("WSL is shut down first, which closes Linux terminals and stops Docker Desktop. " + m.Distro + " then runs from " +
                                        m.Destination + ". " + EstimateText(m.Item.Size / 2), 12));
            if (!await ShowDialog("Move " + m.Distro + " to " + m.To.Letter + "?", body, "Move", "Cancel", false)) return;

            busy = true;
            moveProgress = new TransferProgress();
            moveTitle = "Moving " + m.Distro + " to " + m.To.Letter;
            movePhase = null;
            moveProgressTitle.Text = moveTitle;
            moveProgressCard.Visibility = Visibility.Visible;
            moveCancelButton.Visibility = Visibility.Collapsed;  // WSL can't stop a move halfway
            moveProgressBar.IsIndeterminate = true;
            moveProgressText.Text = "WSL copies the disk, then removes the old one.";
            moveList.IsEnabled = false;
            var log = new List<string>();
            bool ok = await Task.Run(() =>
            {
                Transfer.StayAwake(true);
                try
                {
                    VirtualDisks.Shutdown(line => { lock (log) log.Add(line); });
                    return VirtualDisks.MoveDistro(m.Distro, m.Destination, line => { lock (log) log.Add(line); });
                }
                finally { Transfer.StayAwake(false); }
            });
            moveProgressBar.IsIndeterminate = false;
            moveCancelButton.Visibility = Visibility.Visible;
            moveProgressCard.Visibility = Visibility.Collapsed;
            moveProgress = null;
            moveList.IsEnabled = true;
            busy = false;
            if (!ok)
            {
                await ShowProblemList("WSL couldn't move " + m.Distro, "Nothing was changed. This is what WSL reported:", log);
                return;
            }
            Toast(m.Distro + " now runs from " + m.Destination);
            if (m.Item.Parent != null) Rescan(m.Item.Parent);
        }

        async Task ShowMoveGuide(MoveSuggestion m)
        {
            string title, primary = null;
            var steps = new List<string>();
            Action open = null;
            switch (m.Kind)
            {
                case MoveKind.DockerDisk:
                    title = "Move Docker's data to " + m.To.Letter;
                    steps.Add("Open Docker Desktop and go to Settings, then Resources, then Advanced.");
                    steps.Add("Under \"Disk image location\", choose " + m.Destination + ".");
                    steps.Add("Select \"Apply & restart\". Docker moves the file itself.");
                    string desktop = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Docker\Docker\Docker Desktop.exe");
                    if (File.Exists(desktop)) { primary = "Open Docker Desktop"; open = () => Launch(desktop, null); }
                    break;
                case MoveKind.PersonalFolder:
                    title = "Move your " + m.Item.Name + " folder to " + m.To.Letter;
                    steps.Add("In the window that opens, go to the Location tab.");
                    steps.Add("Type " + m.Destination + " and select Move. Windows moves the files and keeps the folder in File Explorer.");
                    primary = "Open folder properties";
                    open = () => ShellOps.ShowProperties(m.Item.FullPath, Handle);
                    break;
                default:
                    title = "Move this virtual machine to " + m.To.Letter;
                    steps.Add("Shut down the virtual machine.");
                    steps.Add("Use its app's own move option, so the app keeps track of it. In VirtualBox: select the machine, then Machine, then Move.");
                    steps.Add("Choose " + m.Destination + " as the new place.");
                    break;
            }
            var body = new StackPanel();
            body.Children.Add(Paragraph(m.Reason, 14));
            for (int i = 0; i < steps.Count; i++)
                body.Children.Add(new TextBlock { Text = (i + 1) + ".  " + steps[i], TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0) });
            body.Children.Add(Paragraph("Rescan afterwards to see the space freed here.", 12));
            if (await ShowDialog(title, body, primary ?? "Close", primary == null ? null : "Close", false) && open != null) Try(open);
        }
    }
}

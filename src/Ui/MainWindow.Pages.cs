using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace DiskSpace
{
    sealed partial class MainWindow
    {
        const long GB = 1L << 30;

        // ---------------------------------------------------------------- Home

        ItemsControl driveList;
        WrapPanel folderShortcuts;

        void WireHome()
        {
            driveList = E<ItemsControl>("DriveList");
            folderShortcuts = E<WrapPanel>("FolderShortcuts");
            driveList.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler((s, e) =>
            {
                var b = e.OriginalSource as Button;
                if (b != null && "drive".Equals(b.Tag)) StartScan(((DriveVm)b.DataContext).Path);
            }));
            LoadDrives();
            BuildFolderShortcuts();
        }

        void LoadDrives()
        {
            var drives = new List<DriveVm>();
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                try
                {
                    if (!d.IsReady) continue;
                    string kind;
                    if (d.DriveType == DriveType.Fixed) kind = "Local drive";
                    else if (d.DriveType == DriveType.Removable) kind = "Removable drive";
                    else if (d.DriveType == DriveType.Network) kind = "Network drive";
                    else continue;
                    long total = d.TotalSize, free = d.TotalFreeSpace;
                    double used = total > 0 ? Math.Min(1, Math.Max(0, (double)(total - free) / total)) : 0;
                    string label = d.VolumeLabel;
                    if (string.IsNullOrEmpty(label)) label = d.DriveType == DriveType.Network ? "Network drive" : "Local Disk";
                    string letter = d.Name.TrimEnd('\\');
                    Brush fill = Meter(used);
                    drives.Add(new DriveVm
                    {
                        Path = d.Name,
                        Title = label + " (" + letter + ")",
                        Detail = kind + "  ·  " + d.DriveFormat,
                        FreeText = Fmt.Size(free) + " free of " + Fmt.Size(total),
                        Tooltip = "Scan " + letter,
                        UsedWidth = new GridLength(used, GridUnitType.Star),
                        FreeWidth = new GridLength(1 - used, GridUnitType.Star),
                        FillBrush = fill,
                        TrackBrush = MeterTrack(used),
                        WarningVisibility = used >= 0.9 ? Visibility.Visible : Visibility.Collapsed
                    });
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            driveList.ItemsSource = drives;
        }

        // A meter's fill carries severity; its track is a lighter step of the same color.
        static Brush Meter(double used)
        {
            return (Brush)Res(used >= 0.9 ? "MeterCritical" : used >= 0.8 ? "MeterWarning" : "MeterFill");
        }

        static Brush MeterTrack(double used)
        {
            if (used < 0.8) return (Brush)Res("MeterTrack");
            Color c = ((SolidColorBrush)Meter(used)).Color;
            var track = new SolidColorBrush(Color.FromArgb(0x48, c.R, c.G, c.B));
            track.Freeze();
            return track;
        }

        void BuildFolderShortcuts()
        {
            folderShortcuts.Children.Clear();
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            AddShortcut("", "Choose a folder…", null, true);
            AddShortcut("", "Downloads", WindowsInfo.Downloads(), false);
            AddShortcut("", "Documents", Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), false);
            AddShortcut("", "Pictures", Environment.GetFolderPath(Environment.SpecialFolder.MyPictures), false);
            AddShortcut("", "Videos", Environment.GetFolderPath(Environment.SpecialFolder.MyVideos), false);
            AddShortcut("", "Your user folder", profile, false);
            AddShortcut("", "AppData", Path.Combine(profile, "AppData"), false);
        }

        void AddShortcut(string glyph, string text, string path, bool accent)
        {
            if (path != null && !Directory.Exists(path)) return;
            var content = new StackPanel { Orientation = Orientation.Horizontal };
            content.Children.Add(new TextBlock { Text = glyph, Style = (Style)Res("Icon"), FontSize = 14 });
            content.Children.Add(new TextBlock { Text = text, Margin = new Thickness(9, 0, 0, 0) });
            var b = new Button
            {
                Content = content,
                Style = (Style)Res(accent ? "AccentButton" : "StandardButton"),
                Margin = new Thickness(0, 0, 8, 8),
                Padding = new Thickness(14, 6, 14, 7),
                ToolTip = path ?? "Pick any folder to scan"
            };
            b.Click += (s, e) =>
            {
                string target = path ?? FolderPicker.Pick(Window, "Choose a folder to scan", WindowsInfo.Downloads());
                if (target != null) StartScan(target);
            };
            folderShortcuts.Children.Add(b);
        }

        // ---------------------------------------------------------------- Scanning

        ArcGauge scanGauge;
        TextBlock scanTitle, scanStats, scanCurrent;
        Scanner scanner;
        CancellationTokenSource cancel;
        long expectedBytes;
        FrameworkElement pageBeforeScan;
        readonly Stopwatch scanClock = new Stopwatch();
        readonly DispatcherTimer progressTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };

        void WireScan()
        {
            scanGauge = E<ArcGauge>("ScanGauge");
            scanTitle = E<TextBlock>("ScanTitle");
            scanStats = E<TextBlock>("ScanStats");
            scanCurrent = E<TextBlock>("ScanCurrent");
            E<Button>("CancelScanButton").Click += (s, e) => { if (cancel != null) cancel.Cancel(); };
            progressTimer.Tick += (s, e) => ShowScanProgress();
        }

        async void StartScan(string path)
        {
            if (busy) return;
            try { path = Scanner.NormalizePath(path); }
            catch (Exception ex)
            {
                ShowError("That isn't a valid path. " + ex.Message);
                return;
            }
            if (!Directory.Exists(path))
            {
                await ShowDialog("Folder not found", path + " doesn't exist or can't be opened.", "Close", null, false);
                return;
            }

            busy = true;
            pageBeforeScan = currentPage == scanPage ? homePage : currentPage;
            expectedBytes = 0;
            ulong available, total, free;
            if (Scanner.IsVolumeRoot(path) && Native.GetDiskFreeSpaceExW(path, out available, out total, out free))
                expectedBytes = (long)(total - free);
            scanTitle.Text = "Scanning " + path;
            scanGauge.IsIndeterminate = expectedBytes == 0;
            scanGauge.Value = 0;
            scanGauge.Text = "";
            scanStats.Text = "Starting…";
            scanCurrent.Text = "";
            SetNavEnabled(false);
            Navigate(scanPage);

            Scanner sc = scanner = new Scanner();
            cancel = new CancellationTokenSource();
            CancellationToken token = cancel.Token;
            scanClock.Restart();
            progressTimer.Start();
            ScanResult r = null;
            List<Insight> found = null;
            MovePlan plan = null;
            Exception failure = null;
            try
            {
                r = await Task.Run(() =>
                {
                    ScanResult x = sc.Scan(path, token);
                    if (x != null) x.Analyze();
                    return x;
                });
                if (r != null) found = await Task.Run(() => Insights.Find(r, elevated));
                if (r != null) plan = await Task.Run(() => MovePlan.For(r));
            }
            catch (Exception ex) { failure = ex; }
            progressTimer.Stop();
            scanClock.Stop();
            scanner = null;
            cancel = null;
            busy = false;

            if (failure != null || r == null)
            {
                SetNavEnabled(true);
                Navigate(pageBeforeScan);
                if (failure != null) ShowError("The scan failed. " + failure.Message);
                else Toast("Scan stopped", "");
                return;
            }
            result = r;
            insights = found;
            movePlan = plan;
            scannedAt = DateTime.Now;
            selected = null;
            exploreFolder = r.Root;
            history.Clear();
            highlight = -1;
            fileFilter = -1;
            filesSearch.Text = "";
            SetNavEnabled(true);
            RefreshAll();
            Navigate(overviewPage);
            EventHandler h = ScanCompleted;
            if (h != null) h(this, EventArgs.Empty);
        }

        void ShowScanProgress()
        {
            Scanner s = scanner;
            if (s == null) return;
            long files = Interlocked.Read(ref s.FilesFound), bytes = Interlocked.Read(ref s.BytesFound);
            TimeSpan t = scanClock.Elapsed;
            scanStats.Text = Fmt.Count(files) + " files  ·  " + Fmt.Size(bytes) + "  ·  " + (int)t.TotalMinutes + ":" + t.Seconds.ToString("00");
            scanCurrent.Text = s.CurrentFolder;
            if (expectedBytes > 0)
            {
                double v = Math.Min(1, (double)bytes / expectedBytes);
                scanGauge.Value = v;
                scanGauge.Text = (int)(v * 100) + "%";
            }
        }

        // ---------------------------------------------------------------- Overview

        TextBlock overviewTitle, overviewSubtitle, heroLabel, heroValue, heroNote, statFreeLabel, statFree, statFiles, statFolders, noInsights;
        Grid capacityMeter, categoryBar;
        ItemsControl categoryLegend, topFolders, topInsights;
        Button problemsLink;

        void WireOverview()
        {
            overviewTitle = E<TextBlock>("OverviewTitle");
            overviewSubtitle = E<TextBlock>("OverviewSubtitle");
            heroLabel = E<TextBlock>("HeroLabel");
            heroValue = E<TextBlock>("HeroValue");
            heroNote = E<TextBlock>("HeroNote");
            statFreeLabel = E<TextBlock>("StatFreeLabel");
            statFree = E<TextBlock>("StatFree");
            statFiles = E<TextBlock>("StatFiles");
            statFolders = E<TextBlock>("StatFolders");
            noInsights = E<TextBlock>("NoInsights");
            capacityMeter = E<Grid>("CapacityMeter");
            categoryBar = E<Grid>("CategoryBar");
            categoryLegend = E<ItemsControl>("CategoryLegend");
            topFolders = E<ItemsControl>("TopFolders");
            topInsights = E<ItemsControl>("TopInsights");
            problemsLink = E<Button>("ProblemsLink");

            E<Button>("RescanButton").Click += (s, e) => { if (result != null) StartScan(result.Root.FullPath); };
            E<Button>("ExportButton").Click += (s, e) => ExportCsv();
            problemsLink.Click += (s, e) => ShowProblems();
            RoutedEventHandler exploreRoot = (s, e) =>
            {
                OpenExplore(result.Root, true);
                Navigate(explorePage);
            };
            E<Button>("ExploreTypesLink").Click += exploreRoot;
            E<Button>("ExploreFoldersLink").Click += exploreRoot;
            E<Button>("AllInsightsLink").Click += (s, e) => Navigate(cleanupPage);
            categoryLegend.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler((s, e) =>
            {
                var vm = DataOf<CategoryVm>(e);
                if (vm == null) return;
                OpenExplore(result.Root, true);
                SetHighlight(vm.Index);
                Navigate(explorePage);
            }));
            topFolders.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler((s, e) =>
            {
                var vm = DataOf<EntryVm>(e);
                if (vm == null) return;
                var dir = vm.Node as DirNode;
                if (dir != null && !dir.Unaccounted && dir.Children.Length > 0) OpenExplore(dir, true);
                else
                {
                    OpenExplore(result.Root, true);
                    Select(vm.Node, null);
                }
                Navigate(explorePage);
            }));
            topInsights.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler((s, e) => Navigate(cleanupPage)));
        }

        static T DataOf<T>(RoutedEventArgs e) where T : class
        {
            var element = e.OriginalSource as FrameworkElement;
            return element == null ? null : element.DataContext as T;
        }

        void RefreshOverview()
        {
            if (result == null) return;
            DirNode root = result.Root;
            overviewTitle.Text = root.FullPath;
            string subtitle = "Scanned " + Fmt.Ago(scannedAt) + " in " + Fmt.Duration(result.Elapsed);
            if (result.OnlineOnlyFiles > 0) subtitle += "  ·  " + Fmt.Size(result.OnlineOnlyBytes) + " of online-only files not counted";
            overviewSubtitle.Text = subtitle;
            problemsLink.Visibility = result.UnreadableCount > 0 ? Visibility.Visible : Visibility.Collapsed;
            problemsLink.Content = Fmt.Count(result.UnreadableCount) + (result.UnreadableCount == 1 ? " folder" : " folders") + " couldn't be read";

            if (result.IsDriveRoot && result.DriveTotal > 0)
            {
                long used = result.DriveTotal - result.DriveFree;
                double share = (double)used / result.DriveTotal;
                heroLabel.Text = "Space used on " + root.FullPath.TrimEnd('\\');
                heroValue.Text = Fmt.Size(used);
                BuildMeter(capacityMeter, share, Meter(share), MeterTrack(share));
                heroNote.Text = Fmt.Size(result.DriveFree) + " free of " + Fmt.Size(result.DriveTotal) + "  ·  " + (share * 100).ToString("0") + "% full";
                statFreeLabel.Text = "Free space";
                statFree.Text = Fmt.Size(result.DriveFree);
            }
            else
            {
                double share = result.DriveTotal > 0 ? (double)root.Size / result.DriveTotal : 0;
                heroLabel.Text = "Size of this folder";
                heroValue.Text = Fmt.Size(root.Size);
                BuildMeter(capacityMeter, share, (Brush)Res("MeterFill"), (Brush)Res("MeterTrack"));
                heroNote.Text = result.DriveTotal > 0 ? Fmt.Percent(root.Size, result.DriveTotal) + " of the drive (" + Fmt.Size(result.DriveTotal) + ")" : "";
                statFreeLabel.Text = "Free on the drive";
                statFree.Text = result.DriveTotal > 0 ? Fmt.Size(result.DriveFree) : "—";
            }
            statFiles.Text = Fmt.Compact(root.FileCount);
            statFiles.ToolTip = Fmt.Count(root.FileCount) + " files";
            statFolders.Text = Fmt.Compact(root.DirCount);
            statFolders.ToolTip = Fmt.Count(root.DirCount) + " folders";

            BuildCategoryBar();

            var folders = new List<EntryVm>();
            foreach (Node child in root.Children)
            {
                if (!(child is DirNode)) continue;
                folders.Add(new EntryVm(child, root.Size));
                if (folders.Count == 8) break;
            }
            topFolders.ItemsSource = folders;

            var top = new List<InsightVm>();
            foreach (Insight i in insights)
            {
                top.Add(ToVm(i));
                if (top.Count == 4) break;
            }
            topInsights.ItemsSource = top;
            noInsights.Visibility = top.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        static void BuildMeter(Grid meter, double share, Brush fill, Brush track)
        {
            share = Math.Min(1, Math.Max(0, share));
            meter.Children.Clear();
            meter.ColumnDefinitions.Clear();
            meter.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(share, GridUnitType.Star) });
            meter.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1 - share, GridUnitType.Star) });
            var trackBar = new Border { CornerRadius = new CornerRadius(4), Background = track };
            Grid.SetColumnSpan(trackBar, 2);
            meter.Children.Add(trackBar);
            meter.Children.Add(new Border { CornerRadius = new CornerRadius(4), Background = fill });
        }

        // A 100% stacked bar of space by category: 2 px surface gaps between segments, rounded only at the ends.
        void BuildCategoryBar()
        {
            categoryBar.Children.Clear();
            categoryBar.ColumnDefinitions.Clear();
            long total = result.Root.Size;
            var shown = new List<int>();
            for (int c = 0; c < Categories.Count; c++)
                if (result.CategoryBytes[c] > 0) shown.Add(c);
            var legend = new List<CategoryVm>();
            for (int i = 0; i < shown.Count; i++)
            {
                int c = shown[i];
                long bytes = result.CategoryBytes[c];
                bool first = i == 0, last = i == shown.Count - 1;
                categoryBar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(bytes, GridUnitType.Star) });
                var segment = new Border
                {
                    Background = (Brush)Res("Cat" + c),
                    Margin = new Thickness(0, 0, last ? 0 : 2, 0),
                    CornerRadius = new CornerRadius(first ? 4 : 0, last ? 4 : 0, last ? 4 : 0, first ? 4 : 0),
                    ToolTip = Categories.Names[c] + "  ·  " + Fmt.Size(bytes) + "  ·  " + Fmt.Percent(bytes, total)
                };
                Grid.SetColumn(segment, i);
                categoryBar.Children.Add(segment);
                legend.Add(new CategoryVm
                {
                    Index = c,
                    Swatch = (Brush)Res("Cat" + c),
                    Name = Categories.Names[c],
                    SizeText = Fmt.Size(bytes),
                    PercentText = Fmt.Percent(bytes, total)
                });
            }
            categoryLegend.ItemsSource = legend;
        }

        // ---------------------------------------------------------------- Explore

        ListBox entryList;
        TreemapView treemap;
        StackPanel breadcrumb;
        WrapPanel treemapLegend;
        TextBlock exploreSummary;
        Button backButton, upButton;
        DirNode exploreFolder;
        readonly Stack<DirNode> history = new Stack<DirNode>();
        int highlight = -1;
        bool syncingList;

        void WireExplore()
        {
            entryList = E<ListBox>("EntryList");
            treemap = E<TreemapView>("Treemap");
            breadcrumb = E<StackPanel>("Breadcrumb");
            treemapLegend = E<WrapPanel>("TreemapLegend");
            exploreSummary = E<TextBlock>("ExploreSummary");
            backButton = E<Button>("BackButton");
            upButton = E<Button>("UpButton");

            treemap.EmptyText = "This folder is empty";
            treemap.NodeClicked += n => Select(n, treemap);
            treemap.NodeActivated += ZoomToward;
            treemap.NodeContextRequested += n => ShowMenu(n, treemap);
            entryList.SelectionChanged += (s, e) =>
            {
                if (syncingList) return;
                var vm = entryList.SelectedItem as EntryVm;
                if (vm != null) Select(vm.Node, entryList);
            };
            entryList.MouseDoubleClick += (s, e) =>
            {
                var vm = entryList.SelectedItem as EntryVm;
                if (vm != null) Activate(vm.Node);
            };
            entryList.KeyDown += (s, e) =>
            {
                var vm = entryList.SelectedItem as EntryVm;
                if (e.Key == Key.Enter && vm != null)
                {
                    Activate(vm.Node);
                    e.Handled = true;
                }
            };
            entryList.MouseRightButtonUp += (s, e) =>
            {
                var vm = entryList.SelectedItem as EntryVm;
                if (vm != null) ShowMenu(vm.Node, entryList);
            };
            backButton.Click += (s, e) => GoBack();
            upButton.Click += (s, e) => GoUp();
        }

        void Activate(Node n)
        {
            var dir = n as DirNode;
            if (dir != null && !dir.Unaccounted && dir.Children.Length > 0) OpenExplore(dir, true);
        }

        // Double-clicking the treemap opens the folder one level down, on the way to what was clicked.
        void ZoomToward(Node hit)
        {
            for (Node n = hit; n != null; n = n.Parent)
            {
                if (n.Parent != exploreFolder) continue;
                Activate(n);
                return;
            }
        }

        void OpenExplore(DirNode folder, bool remember)
        {
            if (folder == null || result == null) return;
            if (remember && exploreFolder != null && exploreFolder != folder) history.Push(exploreFolder);
            exploreFolder = folder;
            RefreshExplore();
        }

        void GoBack()
        {
            while (history.Count > 0)
            {
                DirNode d = history.Pop();
                if (!Attached(d)) continue;
                exploreFolder = d;
                RefreshExplore();
                return;
            }
        }

        void GoUp()
        {
            if (exploreFolder != null && exploreFolder.Parent != null) OpenExplore(exploreFolder.Parent, true);
        }

        // False for nodes that were removed from the tree (deleted or replaced by a rescan).
        bool Attached(Node n)
        {
            if (result == null || n == null) return false;
            for (; n.Parent != null; n = n.Parent)
                if (Array.IndexOf(n.Parent.Children, n) < 0) return false;
            return n == result.Root;
        }

        void RefreshExplore()
        {
            if (result == null) return;
            if (!Attached(exploreFolder)) exploreFolder = result.Root;
            var items = new List<EntryVm>(exploreFolder.Children.Length);
            foreach (Node child in exploreFolder.Children) items.Add(new EntryVm(child, exploreFolder.Size));
            syncingList = true;
            entryList.ItemsSource = items;
            syncingList = false;
            treemap.SetData(result, exploreFolder, highlight);
            BuildBreadcrumb();
            BuildTreemapLegend();
            exploreSummary.Text = Fmt.Size(exploreFolder.Size) + "  ·  " + Fmt.Count(exploreFolder.FileCount) + " files  ·  " +
                                  Fmt.Count(exploreFolder.DirCount) + " folders";
            backButton.IsEnabled = history.Count > 0;
            upButton.IsEnabled = exploreFolder.Parent != null;
            if (selected != null && Attached(selected) && selected.IsUnder(exploreFolder) && selected != exploreFolder)
            {
                treemap.Selected = selected;
                SyncEntryList(selected);
            }
            else
            {
                selected = null;
                UpdateSelectionBar();
            }
        }

        // Highlights the row of the item, or of the folder in this list that contains it.
        void SyncEntryList(Node n)
        {
            syncingList = true;
            try
            {
                entryList.SelectedItem = null;
                if (n == null || exploreFolder == null) return;
                Node row = n;
                while (row != null && row.Parent != exploreFolder) row = row.Parent;
                if (row == null) return;
                var items = entryList.ItemsSource as List<EntryVm>;
                if (items == null) return;
                foreach (EntryVm vm in items)
                {
                    if (vm.Node != row) continue;
                    entryList.SelectedItem = vm;
                    entryList.ScrollIntoView(vm);
                    break;
                }
            }
            finally { syncingList = false; }
        }

        void BuildBreadcrumb()
        {
            breadcrumb.Children.Clear();
            var chain = new List<DirNode>();
            for (DirNode d = exploreFolder; d != null; d = d.Parent) chain.Add(d);
            chain.Reverse();
            for (int i = 0; i < chain.Count; i++)
            {
                if (i > 0) breadcrumb.Children.Add(new TextBlock { Text = "", Style = (Style)Res("Icon"), FontSize = 10, Margin = new Thickness(2, 1, 2, 0), Foreground = (Brush)Res("TextTertiary") });
                if (chain.Count > 5 && i == 1)
                {
                    // Long paths keep the first and last three levels; the rest are in a menu.
                    var hidden = chain.GetRange(1, chain.Count - 4);
                    var more = new Button { Content = "…", Style = (Style)Res("SubtleButton"), Padding = new Thickness(8, 2, 8, 3), MinHeight = 28, ToolTip = "More folders" };
                    more.Click += (s, e) =>
                    {
                        var menu = new ContextMenu { PlacementTarget = more, Placement = PlacementMode.Bottom };
                        foreach (DirNode h in hidden)
                        {
                            DirNode target = h;
                            var item = new MenuItem { Header = h.Name };
                            item.Click += (s2, e2) => OpenExplore(target, true);
                            menu.Items.Add(item);
                        }
                        menu.IsOpen = true;
                    };
                    breadcrumb.Children.Add(more);
                    i = chain.Count - 4;
                    continue;
                }
                DirNode folder = chain[i];
                bool last = i == chain.Count - 1;
                var b = new Button
                {
                    Content = folder.Parent == null ? folder.FullPath : folder.Name,
                    Style = (Style)Res("SubtleButton"),
                    Padding = new Thickness(8, 2, 8, 3),
                    MinHeight = 28,
                    FontWeight = last ? FontWeights.SemiBold : FontWeights.Normal,
                    IsHitTestVisible = !last
                };
                if (!last) b.Click += (s, e) => OpenExplore(folder, true);
                breadcrumb.Children.Add(b);
            }
        }

        // The treemap's color key for the folder on screen; each entry toggles a highlight.
        void BuildTreemapLegend()
        {
            treemapLegend.Children.Clear();
            if (result == null || exploreFolder == null) return;
            long[] bytes = result.CategoryBytesUnder(exploreFolder);
            for (int c = 0; c < Categories.Count; c++)
            {
                if (bytes[c] <= 0) continue;
                int category = c;
                var content = new StackPanel { Orientation = Orientation.Horizontal };
                content.Children.Add(new Border { Width = 9, Height = 9, CornerRadius = new CornerRadius(2), Background = (Brush)Res("Cat" + c), VerticalAlignment = VerticalAlignment.Center });
                content.Children.Add(new TextBlock { Text = Categories.Names[c], Margin = new Thickness(7, 0, 0, 0) });
                content.Children.Add(new TextBlock { Text = Fmt.Size(bytes[c]), Margin = new Thickness(7, 0, 0, 0), Foreground = (Brush)Res("TextSecondary") });
                var chip = new ToggleButton
                {
                    Content = content,
                    Style = (Style)Res("Chip"),
                    Height = 28,
                    Margin = new Thickness(0, 0, 6, 6),
                    IsChecked = highlight == c,
                    ToolTip = "Highlight " + Categories.Names[c].ToLowerInvariant()
                };
                chip.Click += (s, e) => SetHighlight(highlight == category ? -1 : category);
                treemapLegend.Children.Add(chip);
            }
        }

        void SetHighlight(int category)
        {
            highlight = category;
            treemap.Highlight = category;
            BuildTreemapLegend();
        }

        // ---------------------------------------------------------------- Largest files

        ListBox fileList;
        TextBox filesSearch;
        WrapPanel fileFilters;
        TextBlock filesCount, filesEmpty;
        int fileFilter = -1;
        readonly DispatcherTimer searchTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };

        void WireFiles()
        {
            fileList = E<ListBox>("FileList");
            filesSearch = E<TextBox>("FilesSearch");
            fileFilters = E<WrapPanel>("FileFilters");
            filesCount = E<TextBlock>("FilesCount");
            filesEmpty = E<TextBlock>("FilesEmpty");
            fileList.SelectionChanged += (s, e) =>
            {
                var vm = fileList.SelectedItem as FileVm;
                if (vm != null) Select(vm.Node, fileList);
            };
            fileList.MouseDoubleClick += (s, e) =>
            {
                var vm = fileList.SelectedItem as FileVm;
                if (vm == null) return;
                OpenExplore(vm.Node.Parent, true);
                Navigate(explorePage);
                Select(vm.Node, null);
            };
            fileList.MouseRightButtonUp += (s, e) =>
            {
                var vm = fileList.SelectedItem as FileVm;
                if (vm != null) ShowMenu(vm.Node, fileList);
            };
            searchTimer.Tick += (s, e) =>
            {
                searchTimer.Stop();
                RefreshFileList();
            };
            filesSearch.TextChanged += (s, e) =>
            {
                searchTimer.Stop();
                searchTimer.Start();
            };
        }

        void RefreshFiles()
        {
            if (result == null) return;
            fileFilters.Children.Clear();
            AddFileFilter(-1, "All files", null);
            for (int c = 0; c < Categories.Count; c++)
                if (result.CategoryFiles[c] > 0) AddFileFilter(c, Categories.Names[c], (Brush)Res("Cat" + c));
            RefreshFileList();
        }

        void AddFileFilter(int category, string text, Brush swatch)
        {
            var content = new StackPanel { Orientation = Orientation.Horizontal };
            if (swatch != null)
                content.Children.Add(new Border { Width = 9, Height = 9, CornerRadius = new CornerRadius(2), Background = swatch, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 7, 0) });
            content.Children.Add(new TextBlock { Text = text });
            var chip = new ToggleButton { Content = content, Style = (Style)Res("Chip"), IsChecked = fileFilter == category };
            chip.Click += (s, e) =>
            {
                fileFilter = category;
                foreach (UIElement other in fileFilters.Children) ((ToggleButton)other).IsChecked = other == chip;
                RefreshFileList();
            };
            fileFilters.Children.Add(chip);
        }

        void RefreshFileList()
        {
            if (result == null) return;
            List<FileNode> source = fileFilter < 0 ? result.LargestFiles : result.LargestByCategory[fileFilter];
            string query = filesSearch.Text.Trim();
            var items = new List<FileVm>();
            foreach (FileNode f in source)
            {
                string folder = f.Parent.FullPath;
                if (query.Length > 0 && f.Name.IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0 &&
                    folder.IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0)
                    continue;
                ExtInfo ext = f.Ext < result.Extensions.Count ? result.Extensions[f.Ext] : null;
                int category = ext == null ? (int)Category.Other : (int)ext.Category;
                items.Add(new FileVm
                {
                    Node = f,
                    Icon = ShellIcons.For(f, false),
                    Name = f.Name,
                    Folder = folder,
                    SizeText = Fmt.Size(f.Size),
                    DateText = Fmt.Date(f.LastWrite),
                    CategoryName = Categories.Names[category],
                    Swatch = (Brush)Res("Cat" + category)
                });
            }
            fileList.ItemsSource = items;
            filesEmpty.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            long all = fileFilter < 0 ? result.Root.FileCount : result.CategoryFiles[fileFilter];
            if (query.Length > 0)
                filesCount.Text = Fmt.Count(items.Count) + (items.Count == 1 ? " file matches" : " files match") + " \"" + query + "\"";
            else if (fileFilter < 0)
                filesCount.Text = "The " + Fmt.Count(source.Count) + " largest of " + Fmt.Count(all) + " files";
            else
                filesCount.Text = "The " + Fmt.Count(source.Count) + " largest of " + Fmt.Count(all) + " files in " + Categories.Names[fileFilter];
        }
    }
}

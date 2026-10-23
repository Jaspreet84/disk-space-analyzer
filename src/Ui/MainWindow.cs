using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace DiskSpace
{
    // The main window's behavior. The layout is in MainWindow.xaml; this class finds its named parts and wires
    // them up. The pages are in MainWindow.Pages.cs and MainWindow.Cleanup.cs.
    sealed partial class MainWindow
    {
        public readonly Window Window;
        readonly Options options;
        readonly bool elevated = VirtualDisks.IsElevated;
        readonly bool animate;

        Grid root, dialogLayer;
        RadioButton navHome, navOverview, navExplore, navFiles, navCleanup, navMove, navProtect, navDisks;
        FrameworkElement homePage, scanPage, overviewPage, explorePage, filesPage, cleanupPage, movePage, protectPage, disksPage, currentPage;
        Button maxButton, dialogPrimary, dialogSecondary;
        Button selOpen, selExplorer, selCopy, selRescan, selShrink, selRecycle;
        TextBlock themeIcon, themeLabel, scanContextPath, scanContextDetail, selName, selDetail, toastIcon, toastText, dialogTitle;
        Border scanContext, selectionBar, toast;
        Image selIcon;
        ContentControl dialogBody;
        TaskCompletionSource<bool> dialogResult;
        readonly DispatcherTimer toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };

        ScanResult result;
        List<Insight> insights = new List<Insight>();
        DateTime scannedAt;
        Node selected;
        bool busy;

        public event EventHandler ScanCompleted;

        public MainWindow(Options options)
        {
            this.options = options;
            animate = options.Snapshot == null && SystemParameters.ClientAreaAnimation;
            Window = UiApp.LoadXaml<Window>("MainWindow.xaml");
            if (options.Snapshot != null)
            {
                Window.WindowStartupLocation = WindowStartupLocation.Manual;
                Window.Left = -32000;
                Window.Top = -32000;
                Window.ShowActivated = false;
                Window.ShowInTaskbar = false;
            }
            Window.Icon = AppIconFrame(32);
            WireShell();
            WireHome();
            WireScan();
            WireOverview();
            WireExplore();
            WireFiles();
            WireCleanup();
            WireMove();
            WireProtect();
            WireDisks();
            ShowPage(homePage);
            Window.Loaded += (s, e) => OnLoaded();
        }

        T E<T>(string name) where T : class
        {
            var element = Window.FindName(name) as T;
            if (element == null) throw new InvalidOperationException("MainWindow.xaml has no " + typeof(T).Name + " named " + name);
            return element;
        }

        static object Res(string key)
        {
            return Application.Current.Resources[key];
        }

        IntPtr Handle
        {
            get { return new WindowInteropHelper(Window).Handle; }
        }

        static string ExePath
        {
            get { return Process.GetCurrentProcess().MainModule.FileName; }
        }

        static BitmapFrame AppIconFrame(int size)
        {
            var decoder = new IconBitmapDecoder(new MemoryStream(AppIcon.BuildIco(false)), BitmapCreateOptions.None, BitmapCacheOption.OnLoad);
            BitmapFrame best = decoder.Frames[0];
            foreach (BitmapFrame f in decoder.Frames)
                if (f.PixelWidth >= size && (best.PixelWidth < size || f.PixelWidth < best.PixelWidth)) best = f;
            return best;
        }

        void OnLoaded()
        {
            double scale = PresentationSource.FromVisual(Window).CompositionTarget.TransformToDevice.M11;
            E<Image>("AppIconImage").Source = AppIconFrame((int)Math.Round(16 * scale));
            if (options.Snapshot != null) BeginSnapshot();
            else if (options.ScanPath != null) StartScan(options.ScanPath);
        }

        // Title bar, navigation, theme, selection bar, dialogs and notifications.
        void WireShell()
        {
            root = E<Grid>("Root");
            maxButton = E<Button>("MaxButton");
            E<Button>("MinButton").Click += (s, e) => Window.WindowState = WindowState.Minimized;
            maxButton.Click += (s, e) =>
                Window.WindowState = Window.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            E<Button>("CloseButton").Click += (s, e) => Window.Close();
            Window.StateChanged += (s, e) =>
            {
                bool max = Window.WindowState == WindowState.Maximized;
                // A maximized window with a custom frame hangs over the screen edge by the resize border.
                root.Margin = max ? new Thickness(7) : new Thickness(0);
                maxButton.Content = max ? "\uE923" : "\uE922";
                maxButton.ToolTip = max ? "Restore" : "Maximize";
            };

            navHome = E<RadioButton>("NavHome");
            navOverview = E<RadioButton>("NavOverview");
            navExplore = E<RadioButton>("NavExplore");
            navFiles = E<RadioButton>("NavFiles");
            navCleanup = E<RadioButton>("NavCleanup");
            navMove = E<RadioButton>("NavMove");
            navProtect = E<RadioButton>("NavProtect");
            navDisks = E<RadioButton>("NavDisks");
            homePage = E<FrameworkElement>("HomePage");
            scanPage = E<FrameworkElement>("ScanPage");
            overviewPage = E<FrameworkElement>("OverviewPage");
            explorePage = E<FrameworkElement>("ExplorePage");
            filesPage = E<FrameworkElement>("FilesPage");
            cleanupPage = E<FrameworkElement>("CleanupPage");
            movePage = E<FrameworkElement>("MovePage");
            protectPage = E<FrameworkElement>("ProtectPage");
            disksPage = E<FrameworkElement>("DisksPage");
            navHome.Checked += (s, e) => ShowPage(homePage);
            navOverview.Checked += (s, e) => ShowPage(overviewPage);
            navExplore.Checked += (s, e) => ShowPage(explorePage);
            navFiles.Checked += (s, e) => ShowPage(filesPage);
            navCleanup.Checked += (s, e) => ShowPage(cleanupPage);
            navMove.Checked += (s, e) => ShowPage(movePage);
            navProtect.Checked += (s, e) => ShowPage(protectPage);
            navDisks.Checked += (s, e) => ShowPage(disksPage);

            scanContext = E<Border>("ScanContext");
            scanContextPath = E<TextBlock>("ScanContextPath");
            scanContextDetail = E<TextBlock>("ScanContextDetail");

            var admin = E<Button>("AdminButton");
            if (elevated)
            {
                admin.Visibility = Visibility.Collapsed;
                E<Border>("AdminBadge").Visibility = Visibility.Visible;
            }
            admin.Click += (s, e) => RestartElevated();
            themeIcon = E<TextBlock>("ThemeIcon");
            themeLabel = E<TextBlock>("ThemeLabel");
            E<Button>("ThemeButton").Click += (s, e) => CycleTheme();
            UpdateThemeButton();
            Theme.Changed += (s, e) => OnThemeChanged();

            selectionBar = E<Border>("SelectionBar");
            selIcon = E<Image>("SelIcon");
            selName = E<TextBlock>("SelName");
            selDetail = E<TextBlock>("SelDetail");
            selOpen = E<Button>("SelOpen");
            selExplorer = E<Button>("SelExplorer");
            selCopy = E<Button>("SelCopy");
            selRescan = E<Button>("SelRescan");
            selShrink = E<Button>("SelShrink");
            selRecycle = E<Button>("SelRecycle");
            selOpen.Click += (s, e) => Try(() => ShellOps.Open(selected.FullPath));
            selExplorer.Click += (s, e) => Try(() => ShellOps.ShowInExplorer(selected.FullPath));
            selCopy.Click += (s, e) => CopyPath(selected);
            selRescan.Click += (s, e) => Rescan(selected as DirNode);
            selShrink.Click += (s, e) => OpenDisks(selected.FullPath);
            selRecycle.Click += (s, e) => Recycle(selected);

            dialogLayer = E<Grid>("DialogLayer");
            dialogTitle = E<TextBlock>("DialogTitle");
            dialogBody = E<ContentControl>("DialogBody");
            dialogPrimary = E<Button>("DialogPrimary");
            dialogSecondary = E<Button>("DialogSecondary");
            dialogPrimary.Click += (s, e) => CloseDialog(true);
            dialogSecondary.Click += (s, e) => CloseDialog(false);

            toast = E<Border>("Toast");
            toastIcon = E<TextBlock>("ToastIcon");
            toastText = E<TextBlock>("ToastText");
            toastTimer.Tick += (s, e) => HideToast();

            Window.PreviewKeyDown += OnKeyDown;
            Window.Closing += (s, e) => { if (cancel != null) cancel.Cancel(); };
        }

        void ShowPage(FrameworkElement page)
        {
            if (currentPage == page) return;
            foreach (FrameworkElement p in new[] { homePage, scanPage, overviewPage, explorePage, filesPage, cleanupPage, movePage, protectPage, disksPage })
                p.Visibility = p == page ? Visibility.Visible : Visibility.Collapsed;
            currentPage = page;
            UpdateSelectionBar();
            UpdateScanContext();
            if (page == disksPage) OnDisksShown();
            if (!animate) return;
            var slide = new TranslateTransform(0, 12);
            page.RenderTransform = slide;
            slide.BeginAnimation(TranslateTransform.YProperty,
                new DoubleAnimation(12, 0, TimeSpan.FromMilliseconds(260)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
            page.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
        }

        // Shows a page by selecting its navigation item, so the two always agree.
        void Navigate(FrameworkElement page)
        {
            RadioButton item = page == homePage ? navHome : page == overviewPage ? navOverview : page == explorePage ? navExplore :
                page == filesPage ? navFiles : page == cleanupPage ? navCleanup : page == movePage ? navMove : page == protectPage ? navProtect : page == disksPage ? navDisks : null;
            if (item == null)
            {
                foreach (RadioButton r in new[] { navHome, navOverview, navExplore, navFiles, navCleanup, navMove, navProtect, navDisks }) r.IsChecked = false;
            }
            else item.IsChecked = true;
            ShowPage(page);
        }

        void SetNavEnabled(bool enabled)
        {
            bool scanned = result != null;
            navHome.IsEnabled = navDisks.IsEnabled = navProtect.IsEnabled = enabled;
            navOverview.IsEnabled = navExplore.IsEnabled = navFiles.IsEnabled = navCleanup.IsEnabled = navMove.IsEnabled = enabled && scanned;
        }

        void UpdateScanContext()
        {
            scanContext.Visibility = result == null ? Visibility.Collapsed : Visibility.Visible;
            if (result == null) return;
            scanContextPath.Text = result.Root.FullPath;
            scanContextDetail.Text = Fmt.Size(FoundBytes(result)) + "  ·  " + Fmt.Ago(scannedAt);
        }

        static long FoundBytes(ScanResult r)
        {
            DirNode unaccounted = r.UnaccountedNode;
            return r.Root.Size - (unaccounted == null ? 0 : unaccounted.Size);
        }

        void CycleTheme()
        {
            ThemeChoice next = Theme.Choice == ThemeChoice.System ? ThemeChoice.Light
                : Theme.Choice == ThemeChoice.Light ? ThemeChoice.Dark : ThemeChoice.System;
            Theme.Apply(Application.Current.Resources, next);
            Theme.SaveChoice(next);
        }

        void UpdateThemeButton()
        {
            themeIcon.Text = Theme.Choice == ThemeChoice.System ? "\uE7F4" : Theme.Choice == ThemeChoice.Light ? "\uE706" : "\uE708";
            themeLabel.Text = "Theme: " + (Theme.Choice == ThemeChoice.System ? "System" : Theme.Choice == ThemeChoice.Light ? "Light" : "Dark");
        }

        // Brushes held by list items do not follow the theme by themselves, so those lists are rebuilt.
        void OnThemeChanged()
        {
            UpdateThemeButton();
            LoadDrives();
            if (result != null)
            {
                RefreshOverview();
                BuildTreemapLegend();
                RefreshFiles();
            }
            RefreshDiskList();
        }

        // Selection: shared by Explore (list and treemap) and Largest files.
        void Select(Node n, object source)
        {
            selected = n;
            if (source != treemap) treemap.Selected = n;
            if (source != entryList) SyncEntryList(n);
            UpdateSelectionBar();
        }

        void UpdateSelectionBar()
        {
            bool show = selected != null && result != null && (currentPage == explorePage || currentPage == filesPage);
            selectionBar.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            if (!show) return;
            var dir = selected as DirNode;
            var file = selected as FileNode;
            bool real = dir == null || !dir.Unaccounted;
            selIcon.Source = ShellIcons.For(selected, true);
            selName.Text = selected.Name;
            var parts = new List<string>();
            parts.Add(file != null && file.Flags == FileFlags.OnlineOnly ? "Online-only, takes no space here" : Fmt.Size(selected.Size));
            if (result.Root.Size > 0) parts.Add(Fmt.Percent(selected.Size, result.Root.Size) + " of " + result.Root.FullPath);
            if (dir != null && real) parts.Add(Fmt.Count(dir.FileCount) + " files");
            if (dir != null && dir.Unaccounted) parts.Add("in use on the drive but not in any scanned file");
            string date = Fmt.Date(selected.LastWrite);
            if (file != null && date.Length > 0) parts.Add("modified " + date);
            if (selected.Parent != null && real) parts.Add(selected.Parent.FullPath);
            selDetail.Text = string.Join("  ·  ", parts);
            selOpen.IsEnabled = selExplorer.IsEnabled = selCopy.IsEnabled = real;
            selRescan.Visibility = dir != null && real ? Visibility.Visible : Visibility.Collapsed;
            selRescan.IsEnabled = !busy;
            selShrink.Visibility = file != null && VirtualDisks.IsDiskFile(file.Name) ? Visibility.Visible : Visibility.Collapsed;
            selRecycle.IsEnabled = real && selected.Parent != null && !busy;
        }

        void ShowMenu(Node n, UIElement target)
        {
            var dir = n as DirNode;
            var file = n as FileNode;
            bool real = dir == null || !dir.Unaccounted;
            var menu = new ContextMenu { PlacementTarget = target, Placement = PlacementMode.MousePoint };
            AddMenuItem(menu, "\uE8E5", "Open", real, () => ShellOps.Open(n.FullPath));
            AddMenuItem(menu, "\uEC50", "Show in Explorer", real, () => ShellOps.ShowInExplorer(n.FullPath));
            AddMenuItem(menu, "\uE8C8", "Copy path", real, () => CopyPath(n));
            AddMenuItem(menu, "\uE946", "Properties", real, () => ShellOps.ShowProperties(n.FullPath, Handle));
            menu.Items.Add(new Separator());
            if (dir != null && real && dir.Children.Length > 0 && dir != exploreFolder)
                AddMenuItem(menu, "\uE8DA", "Open in Explore", true, () => { OpenExplore(dir, true); Navigate(explorePage); });
            if (dir != null && real) AddMenuItem(menu, "\uE72C", "Rescan this folder", !busy, () => Rescan(dir));
            if (file != null && VirtualDisks.IsDiskFile(file.Name)) AddMenuItem(menu, "\uEDA2", "Shrink virtual disk…", true, () => OpenDisks(file.FullPath));
            if (menu.Items[menu.Items.Count - 1] is MenuItem) menu.Items.Add(new Separator());
            AddMenuItem(menu, "\uE74D", "Move to Recycle Bin…", real && n.Parent != null && !busy, () => Recycle(n));
            menu.IsOpen = true;
        }

        void AddMenuItem(ContextMenu menu, string glyph, string text, bool enabled, Action action)
        {
            var icon = new TextBlock { Text = glyph, Style = (Style)Res("Icon"), FontSize = 14 };
            var item = new MenuItem { Header = text, Icon = icon, IsEnabled = enabled };
            item.Click += (s, e) => Try(action);
            menu.Items.Add(item);
        }

        void Try(Action action)
        {
            try { action(); }
            catch (Exception ex) { ShowError(ex.Message); }
        }

        void CopyPath(Node n)
        {
            if (n == null) return;
            try
            {
                Clipboard.SetText(n.FullPath);
                Toast("Path copied");
            }
            catch (Exception ex) { ShowError("Couldn't copy to the clipboard. " + ex.Message); }
        }

        void Launch(string file, string arguments)
        {
            Try(() => Process.Start(new ProcessStartInfo(file, arguments ?? "") { UseShellExecute = true }));
        }

        async void Recycle(Node n)
        {
            if (n == null || n.Parent == null || busy || result == null) return;
            var dir = n as DirNode;
            string path = n.FullPath;
            var body = new StackPanel();
            body.Children.Add(new TextBlock { Text = n.Name, FontWeight = FontWeights.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis });
            body.Children.Add(new TextBlock { Text = n.Parent.FullPath, Style = (Style)Res("Caption"), TextTrimming = TextTrimming.CharacterEllipsis });
            body.Children.Add(new TextBlock
            {
                Text = Fmt.Size(n.Size) + (dir != null ? " in " + Fmt.Count(dir.FileCount) + " files" : ""),
                Margin = new Thickness(0, 8, 0, 0)
            });
            body.Children.Add(Paragraph("You can restore it from the Recycle Bin. The space is freed once you empty the Recycle Bin.", 12));
            if (!await ShowDialog("Move to the Recycle Bin?", body, "Move to Recycle Bin", "Cancel", true)) return;

            bool gone;
            try { gone = ShellOps.MoveToRecycleBin(path, Handle); }
            catch (Exception ex)
            {
                ShowError(ex.Message);
                return;
            }
            if (!gone)
            {
                Toast("Nothing was moved", "\uE7BA");
                return;
            }
            DirNode parent = n.Parent;
            result.Replace(n, null);
            await AfterEdit(n, null, parent);
            Toast("Moved " + n.Name + " to the Recycle Bin");
        }

        async void Rescan(DirNode dir)
        {
            if (busy || dir == null || dir.Unaccounted || result == null) return;
            if (dir.Parent == null)
            {
                StartScan(dir.FullPath);
                return;
            }
            busy = true;
            UpdateSelectionBar();
            Toast("Rescanning " + dir.Name + "…", "\uE72C");
            DirNode fresh = null;
            Exception failure = null;
            try { fresh = await Task.Run(() => new Scanner().Rescan(dir, CancellationToken.None)); }
            catch (Exception ex) { failure = ex; }
            busy = false;
            if (failure != null || fresh == null)
            {
                UpdateSelectionBar();
                ShowError("The rescan failed. " + (failure == null ? "" : failure.Message));
                return;
            }
            result.Replace(dir, fresh);
            await AfterEdit(dir, fresh, fresh);
            Toast("Rescanned " + dir.Name + "  ·  " + Fmt.Size(fresh.Size));
        }

        // Brings every view up to date after part of the tree was rescanned or removed.
        async Task AfterEdit(Node old, Node replacement, Node select)
        {
            ScanResult r = result;
            insights = await Task.Run(() => Insights.Find(r, elevated));
            movePlan = await Task.Run(() => MovePlan.For(r));
            var oldDir = old as DirNode;
            if (exploreFolder != null && oldDir != null && exploreFolder.IsUnder(oldDir))
                exploreFolder = replacement as DirNode ?? old.Parent;
            RefreshAll();
            Select(select, null);
        }

        void RefreshAll()
        {
            UpdateScanContext();
            RefreshOverview();
            RefreshExplore();
            RefreshFiles();
            RefreshCleanup();
            RefreshMove();
        }

        void ExportCsv()
        {
            if (result == null) return;
            string name = result.Root.FullPath.TrimEnd('\\').Replace(":", "").Replace("\\", "_");
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "CSV file (*.csv)|*.csv",
                FileName = "disk-usage-" + name + "-" + DateTime.Now.ToString("yyyyMMdd") + ".csv"
            };
            if (dialog.ShowDialog(Window) != true) return;
            try
            {
                int rows = Export.WriteFolderCsv(result.Root, dialog.FileName);
                Toast("Exported " + Fmt.Count(rows) + " folders to " + Path.GetFileName(dialog.FileName));
            }
            catch (Exception ex) { ShowError(ex.Message); }
        }

        void RestartElevated()
        {
            string target = result != null ? result.Root.FullPath : null;
            // A trailing backslash would escape the closing quote, so "C:\" is passed as "C:".
            string args = target == null ? "" : "\"" + target.TrimEnd('\\') + "\"";
            try
            {
                Process.Start(new ProcessStartInfo(ExePath, args) { UseShellExecute = true, Verb = "runas" });
                Window.Close();
            }
            catch (Win32Exception)
            {
                // The UAC prompt was declined.
            }
        }

        void ShowProblems()
        {
            if (result == null) return;
            var body = new StackPanel();
            body.Children.Add(Paragraph("These folders were skipped. On a whole-drive scan their space counts as unaccounted. " +
                                        "Most are protected system folders; run as administrator to include them.", 14));
            string list = string.Join("\n", result.Problems);
            if (result.UnreadableCount > result.Problems.Count)
                list += "\n… and " + Fmt.Count(result.UnreadableCount - result.Problems.Count) + " more";
            var box = new TextBox { Text = list, Style = (Style)Res("LogBox"), MaxHeight = 260, Margin = new Thickness(0, 14, 0, 0) };
            body.Children.Add(box);
            ShowDialog("Folders that couldn't be read", body, elevated ? "Close" : "Run as administrator", elevated ? null : "Close", false)
                .ContinueWith(t => { if (t.Result && !elevated) RestartElevated(); }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        // Dialogs: an in-window overlay in the Fluent "content dialog" style.
        Task<bool> ShowDialog(string title, object body, string primary, string secondary, bool danger)
        {
            if (dialogResult != null) dialogResult.TrySetResult(false);
            dialogTitle.Text = title;
            dialogBody.Content = body as UIElement ?? Paragraph(body as string, 14);
            dialogPrimary.Content = primary;
            dialogPrimary.Style = (Style)Res(danger ? "DangerButton" : "AccentButton");
            dialogSecondary.Content = secondary;
            dialogSecondary.Visibility = secondary == null ? Visibility.Collapsed : Visibility.Visible;
            Grid.SetColumnSpan(dialogPrimary, secondary == null ? 3 : 1);
            dialogLayer.Visibility = Visibility.Visible;
            if (animate) dialogLayer.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(140)));
            dialogResult = new TaskCompletionSource<bool>();
            // For a destructive action, start on the safe choice.
            Button first = danger && secondary != null ? dialogSecondary : dialogPrimary;
            Window.Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() => first.Focus()));
            return dialogResult.Task;
        }

        void CloseDialog(bool ok)
        {
            dialogLayer.Visibility = Visibility.Collapsed;
            TaskCompletionSource<bool> r = dialogResult;
            dialogResult = null;
            if (r != null) r.TrySetResult(ok);
        }

        void ShowError(string message)
        {
            ShowDialog("Something went wrong", message, "Close", null, false);
        }

        static TextBlock Paragraph(string text, double size)
        {
            return new TextBlock
            {
                Text = text ?? "",
                TextWrapping = TextWrapping.Wrap,
                FontSize = size,
                Margin = new Thickness(0, size < 14 ? 12 : 0, 0, 0),
                Foreground = (Brush)Res("TextSecondary")
            };
        }

        void Toast(string message, string glyph = "\uE73E")
        {
            toastText.Text = message;
            toastIcon.Text = glyph;
            toast.Visibility = Visibility.Visible;
            toast.BeginAnimation(UIElement.OpacityProperty, animate ? new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(150)) : null);
            toast.Opacity = 1;
            toastTimer.Stop();
            toastTimer.Start();
        }

        void HideToast()
        {
            toastTimer.Stop();
            if (!animate)
            {
                toast.Visibility = Visibility.Collapsed;
                return;
            }
            var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(200));
            fade.Completed += (s, e) => toast.Visibility = Visibility.Collapsed;
            toast.BeginAnimation(UIElement.OpacityProperty, fade);
        }

        void OnKeyDown(object sender, KeyEventArgs e)
        {
            Key key = e.Key == Key.System ? e.SystemKey : e.Key;
            if (dialogLayer.Visibility == Visibility.Visible)
            {
                if (key == Key.Escape)
                {
                    CloseDialog(false);
                    e.Handled = true;
                }
                return;
            }
            bool typing = Keyboard.FocusedElement is TextBox;
            ModifierKeys mods = Keyboard.Modifiers;
            if (currentPage == scanPage && key == Key.Escape && cancel != null)
            {
                cancel.Cancel();
                e.Handled = true;
            }
            else if (currentPage == explorePage && !typing && (key == Key.Back || (key == Key.Up && mods == ModifierKeys.Alt)))
            {
                GoUp();
                e.Handled = true;
            }
            else if (currentPage == explorePage && key == Key.Left && mods == ModifierKeys.Alt)
            {
                GoBack();
                e.Handled = true;
            }
            else if (key == Key.F && mods == ModifierKeys.Control && result != null)
            {
                Navigate(filesPage);
                filesSearch.Focus();
                e.Handled = true;
            }
            else if (key == Key.F5 && result != null && !busy)
            {
                StartScan(result.Root.FullPath);
                e.Handled = true;
            }
        }

        // --snapshot: run to the requested state, render the window to a PNG and exit.
        void BeginSnapshot()
        {
            if (options.ScanPath != null)
            {
                if (options.Page == "scan") After(1500, CaptureAndClose);  // mid-scan
                else ScanCompleted += (s, e) => After(700, ApplySnapshotState);
                StartScan(options.ScanPath);
                return;
            }
            if (options.Page == "disks")
            {
                DisksRefreshed += () => After(500, CaptureAndClose);
                Navigate(disksPage);
                return;
            }
            if (options.Page == "protect") Navigate(protectPage);
            After(500, CaptureAndClose);
        }

        void ApplySnapshotState()
        {
            Node exploreAt = options.Explore == null ? null : result.FindNode(Scanner.NormalizePath(options.Explore));
            if (exploreAt is DirNode) OpenExplore((DirNode)exploreAt, false);
            if (options.Highlight >= 0) SetHighlight(options.Highlight);
            switch (options.Page)
            {
                case "explore": Navigate(explorePage); break;
                case "files": Navigate(filesPage); break;
                case "cleanup": Navigate(cleanupPage); break;
                case "move": Navigate(movePage); break;
                case "protect": Navigate(protectPage); break;
                case "home": Navigate(homePage); break;
            }
            Node pick = options.Select == null ? null : result.FindNode(Scanner.NormalizePath(options.Select));
            if (pick != null) Select(pick, null);
            if (options.Dialog == "recycle" && pick != null) Recycle(pick);
            if (options.Dialog == "error") ShowError("This is what an error looks like.");
            if (options.Dialog == "move" && movePlan.Suggestions.Count > 0) RunSuggestion(movePlan.Suggestions[0], false);
            After(900, CaptureAndClose);
        }

        void After(int milliseconds, Action action)
        {
            var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(milliseconds) };
            timer.Tick += (s, e) =>
            {
                timer.Stop();
                action();
            };
            timer.Start();
        }

        void CaptureAndClose()
        {
            var visual = (FrameworkElement)Window.Content;
            double scale = PresentationSource.FromVisual(Window).CompositionTarget.TransformToDevice.M11;
            int w = (int)Math.Round(visual.ActualWidth * scale), h = (int)Math.Round(visual.ActualHeight * scale);
            var bitmap = new RenderTargetBitmap(w, h, 96 * scale, 96 * scale, PixelFormats.Pbgra32);
            var background = new DrawingVisual();
            using (DrawingContext dc = background.RenderOpen())
                dc.DrawRectangle(Window.Background, null, new Rect(0, 0, visual.ActualWidth, visual.ActualHeight));
            bitmap.Render(background);
            bitmap.Render(visual);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using (FileStream f = File.Create(options.Snapshot)) encoder.Save(f);
            Window.Close();
        }
    }
}

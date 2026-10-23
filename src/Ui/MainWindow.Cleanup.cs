using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;

namespace DiskSpace
{
    sealed partial class MainWindow
    {
        // ---------------------------------------------------------------- Clean up

        ItemsControl insightList;
        TextBlock cleanupTotal, cleanupNote;

        void WireCleanup()
        {
            insightList = E<ItemsControl>("InsightList");
            cleanupTotal = E<TextBlock>("CleanupTotal");
            cleanupNote = E<TextBlock>("CleanupNote");
            insightList.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler(OnInsightClick));
            E<Button>("DiskCleanupButton").Click += (s, e) => Launch("cleanmgr.exe", null);
            E<Button>("StorageSettingsButton").Click += (s, e) => Launch("ms-settings:storagesense", null);
        }

        void OnInsightClick(object sender, RoutedEventArgs e)
        {
            var b = e.OriginalSource as Button;
            if (b == null) return;
            string tag = b.Tag as string;
            var insight = b.DataContext as InsightVm;
            var item = b.DataContext as InsightItemVm;
            if (tag == "insight-action" && insight != null) RunInsightAction(insight.Insight);
            else if (tag == "item-show" && item != null) Try(() => ShellOps.ShowInExplorer(item.Node.FullPath));
            else if (tag == "item-recycle" && item != null) Recycle(item.Node);
        }

        void RunInsightAction(Insight insight)
        {
            switch (insight.Action)
            {
                case InsightAction.VirtualDisks: Navigate(disksPage); break;
                case InsightAction.DiskCleanup: Launch("cleanmgr.exe", null); break;
                case InsightAction.RecycleBin: Launch("explorer.exe", "shell:RecycleBinFolder"); break;
                case InsightAction.RunAsAdmin: RestartElevated(); break;
                case InsightAction.SystemProtection: Launch("SystemPropertiesProtection.exe", null); break;
            }
        }

        void RefreshCleanup()
        {
            if (result == null) return;
            long total = 0;
            int counted = 0;
            var items = new List<InsightVm>();
            foreach (Insight i in insights)
            {
                if (i.CountsTowardTotal)
                {
                    total += i.Bytes;
                    counted++;
                }
                items.Add(ToVm(i));
            }
            cleanupTotal.Text = Fmt.Size(total);
            cleanupNote.Text = counted == 0 ? "Nothing stands out in this scan."
                : "across " + counted + (counted == 1 ? " suggestion" : " suggestions") + " below";
            insightList.ItemsSource = items;
        }

        InsightVm ToVm(Insight i)
        {
            var items = new List<InsightItemVm>();
            foreach (Node n in i.Items)
            {
                items.Add(new InsightItemVm
                {
                    Insight = i,
                    Node = n,
                    Icon = ShellIcons.For(n, false),
                    Name = n.Name,
                    Folder = n.Parent == null ? "" : n.Parent.FullPath,
                    SizeText = Fmt.Size(n.Size),
                    RecycleVisibility = i.ItemsCanBeRecycled ? Visibility.Visible : Visibility.Collapsed
                });
            }
            string label = i.ItemCount > i.Items.Count ? "Show the largest " + i.Items.Count + " of " + Fmt.Count(i.ItemCount)
                : i.ItemCount == 1 ? "Show the item" : "Show " + i.ItemCount + " items";
            return new InsightVm
            {
                Insight = i,
                Glyph = i.Glyph,
                Title = i.Title,
                Description = i.Description,
                SizeText = Fmt.Size(i.Bytes),
                ActionText = i.ActionText,
                ActionVisibility = i.Action == InsightAction.None ? Visibility.Collapsed : Visibility.Visible,
                ItemsLabel = label,
                ItemsVisibility = items.Count > 0 ? Visibility.Visible : Visibility.Collapsed,
                Items = items
            };
        }

        // ---------------------------------------------------------------- Virtual disks

        ItemsControl diskList;
        StackPanel disksBusy;
        TextBlock disksBusyText, disksEmpty;
        Border diskLogCard;
        TextBox diskLog;
        Button disksRefresh;
        List<VirtualDisk> diskModels = new List<VirtualDisk>();
        bool disksLoaded, disksWorking;
        string diskFocus;
        event Action DisksRefreshed;

        void WireDisks()
        {
            diskList = E<ItemsControl>("DiskList");
            disksBusy = E<StackPanel>("DisksBusy");
            disksBusyText = E<TextBlock>("DisksBusyText");
            disksEmpty = E<TextBlock>("DisksEmpty");
            diskLogCard = E<Border>("DiskLogCard");
            diskLog = E<TextBox>("DiskLog");
            disksRefresh = E<Button>("DisksRefresh");
            disksRefresh.Click += (s, e) => RefreshDisks();
            diskList.AddHandler(ButtonBase.ClickEvent, new RoutedEventHandler((s, e) =>
            {
                var b = e.OriginalSource as Button;
                var vm = b == null ? null : b.DataContext as DiskVm;
                if (vm == null) return;
                if ("disk-clean".Equals(b.Tag)) CleanDisk(vm.Disk);
                else if ("disk-shrink".Equals(b.Tag)) ShrinkDisk(vm.Disk);
            }));
        }

        void OnDisksShown()
        {
            if (!disksLoaded) RefreshDisks();
        }

        // Opens Virtual disks with one disk file in view (from the selection bar or a context menu).
        void OpenDisks(string path)
        {
            diskFocus = path;
            Navigate(disksPage);
            if (disksLoaded) RefreshDisks();
        }

        async void RefreshDisks()
        {
            if (disksWorking) return;
            SetDisksWorking(true, "Looking for virtual disks…");
            List<VirtualDisk> found = await Task.Run(() =>
            {
                List<VirtualDisk> all = VirtualDisks.Find();
                foreach (VirtualDisk d in all) VirtualDisks.QueryUsage(d, LogDisk);
                return all;
            });
            // A disk file picked elsewhere that is not a WSL or Docker disk can still be compacted.
            if (diskFocus != null && File.Exists(diskFocus) && !found.Exists(d => string.Equals(d.Path, diskFocus, StringComparison.OrdinalIgnoreCase)))
                found.Add(new VirtualDisk { Name = Path.GetFileName(diskFocus), Path = diskFocus, Kind = DiskKind.Other, FileSize = new FileInfo(diskFocus).Length });
            diskModels = found;
            disksLoaded = true;
            SetDisksWorking(false, null);
            RefreshDiskList();
            Action h = DisksRefreshed;
            if (h != null) h();
        }

        void RefreshDiskList()
        {
            if (diskList == null) return;
            var items = new List<DiskVm>();
            DiskVm focus = null;
            foreach (VirtualDisk d in diskModels)
            {
                if (d.Kind == DiskKind.WslDistro && !d.IsUserDistro) continue;  // Docker's own small system disk
                bool docker = d.Kind == DiskKind.DockerData;
                string note = null;
                if (docker) note = "Docker's images, containers and volumes. \"Clean up Docker\" shows how much of it is in use.";
                else if (d.Kind == DiskKind.Other) note = "Close the program that uses this disk before shrinking it.";
                else if (d.UsedInside < 0) note = "Couldn't read how much space is used inside.";
                var vm = new DiskVm
                {
                    Disk = d,
                    Glyph = docker ? "" : "",
                    Name = docker ? "Docker Desktop data" : d.Kind == DiskKind.Other ? d.Name : d.Name + " (WSL)",
                    Path = d.Path,
                    FileSizeText = Fmt.Size(d.FileSize),
                    UsedText = d.UsedInside >= 0 ? Fmt.Size(d.UsedInside) : "—",
                    FreeText = d.Reclaimable >= 0 ? "About " + Fmt.Size(d.Reclaimable) : "—",
                    FreeBrush = (Brush)Res(d.Reclaimable >= GB ? "AccentText" : "TextPrimary"),
                    CleanText = docker ? "Clean up Docker…" : "Clean caches…",
                    CleanVisibility = d.Kind == DiskKind.Other ? Visibility.Collapsed : Visibility.Visible,
                    Note = note,
                    NoteVisibility = note == null ? Visibility.Collapsed : Visibility.Visible
                };
                items.Add(vm);
                if (diskFocus != null && string.Equals(d.Path, diskFocus, StringComparison.OrdinalIgnoreCase)) focus = vm;
            }
            diskList.ItemsSource = items;
            disksEmpty.Visibility = disksLoaded && items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            if (focus != null)
            {
                diskList.UpdateLayout();
                var container = diskList.ItemContainerGenerator.ContainerFromItem(focus) as FrameworkElement;
                if (container != null) container.BringIntoView();
            }
        }

        void SetDisksWorking(bool on, string text)
        {
            disksWorking = on;
            disksBusy.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
            if (text != null) disksBusyText.Text = text;
            diskList.IsEnabled = !on;
            disksRefresh.IsEnabled = !on;
        }

        // Safe to call from any thread.
        void LogDisk(string line)
        {
            if (!Window.Dispatcher.CheckAccess())
            {
                Window.Dispatcher.BeginInvoke(new Action<string>(LogDisk), line);
                return;
            }
            diskLogCard.Visibility = Visibility.Visible;
            diskLog.AppendText(line + "\n");
            diskLog.ScrollToEnd();
        }

        async void CleanDisk(VirtualDisk d)
        {
            if (disksWorking || busy) return;
            if (d.Kind == DiskKind.DockerData)
            {
                await CleanDocker();
                return;
            }
            var body = new StackPanel();
            body.Children.Add(Paragraph("These caches inside " + d.Name + " will be cleared:", 14));
            foreach (string line in new[] { "pnpm packages that no project uses", "npm, yarn and pip download caches", "Go module and build caches", "apt package downloads" })
                body.Children.Add(new TextBlock { Text = "•   " + line, Margin = new Thickness(6, 6, 0, 0) });
            body.Children.Add(Paragraph("Your projects keep working. Tools download what they need again the next time it's used.", 12));
            if (!await ShowDialog("Clean caches?", body, "Clean caches", "Cancel", false)) return;

            SetDisksWorking(true, "Cleaning caches in " + d.Name + "…");
            LogDisk("");
            LogDisk("Cleaning caches in " + d.Name + "...");
            long before = -1, after = -1;
            await Task.Run(() =>
            {
                VirtualDisks.QueryUsage(d, LogDisk);
                before = d.UsedInside;
                VirtualDisks.CleanCaches(d, LogDisk);
                VirtualDisks.QueryUsage(d, LogDisk);
                after = d.UsedInside;
            });
            SetDisksWorking(false, null);
            RefreshDiskList();
            if (before >= 0 && after >= 0)
                Toast("Freed " + Fmt.Size(Math.Max(0, before - after)) + " inside " + d.Name + ". Shrink the disk to give it back to Windows.");
        }

        async Task CleanDocker()
        {
            string docker = VirtualDisks.DockerExe;
            if (docker == null)
            {
                ShowError("docker.exe wasn't found, so Docker can't be cleaned up from here.");
                return;
            }
            var images = new CheckBox
            {
                IsChecked = true,
                Margin = new Thickness(0, 16, 0, 0),
                Content = new TextBlock { Text = "Also remove every image that no container uses. They download again when needed.", TextWrapping = TextWrapping.Wrap }
            };
            var volumes = new CheckBox
            {
                IsChecked = false,
                Margin = new Thickness(0, 12, 0, 0),
                Content = new TextBlock { Text = "Also remove volumes that no container uses. This deletes the data stored in them.", TextWrapping = TextWrapping.Wrap }
            };
            var body = new StackPanel();
            body.Children.Add(Paragraph("This runs \"docker system prune\", which removes stopped containers, networks that no container uses, " +
                                        "dangling images and the build cache. Docker Desktop is started first if it isn't running.", 14));
            body.Children.Add(images);
            body.Children.Add(volumes);
            if (!await ShowDialog("Clean up Docker?", body, "Clean up", "Cancel", false)) return;
            bool allImages = images.IsChecked == true, removeVolumes = volumes.IsChecked == true;
            if (removeVolumes && !await ShowDialog("Remove unused volumes?",
                    "Unused volumes often hold database files and other data that can't be downloaded again.", "Remove volumes", "Cancel", true))
                return;

            SetDisksWorking(true, "Cleaning up Docker…");
            LogDisk("");
            LogDisk("Cleaning up Docker...");
            bool ok = false;
            await Task.Run(() =>
            {
                if (!VirtualDisks.EnsureDockerRunning(docker, LogDisk)) return;
                LogDisk("Before:");
                VirtualDisks.DockerDiskUsage(docker, LogDisk);
                ok = VirtualDisks.DockerPrune(docker, allImages, removeVolumes, LogDisk);
                LogDisk("After:");
                VirtualDisks.DockerDiskUsage(docker, LogDisk);
            });
            SetDisksWorking(false, null);
            if (ok) Toast("Docker is cleaned up. Shrink its disk to give the space back to Windows.");
            else Toast("Docker clean-up didn't finish. The activity log has the details.", "");
        }

        async void ShrinkDisk(VirtualDisk d)
        {
            if (disksWorking || busy) return;
            string name = d.Kind == DiskKind.DockerData ? "Docker Desktop data" : d.Name;
            string body = d.Kind == DiskKind.Other
                ? "This compacts the " + Fmt.Size(d.FileSize) + " disk file. Close the program that uses it first. Windows will ask for administrator rights, and it can take several minutes."
                : "This shuts down WSL, which closes Linux terminals and stops Docker Desktop, then compacts the " + Fmt.Size(d.FileSize) +
                  " disk file. Windows will ask for administrator rights, and it can take several minutes.";
            if (!await ShowDialog("Shrink " + name + "?", body, "Shrink", "Cancel", false)) return;

            SetDisksWorking(true, "Shrinking " + name + "…");
            LogDisk("");
            long before = d.FileSize;
            bool ok = false;
            await Task.Run(() =>
            {
                if (d.IsUserDistro) VirtualDisks.Trim(d, LogDisk);
                if (d.Kind != DiskKind.Other) VirtualDisks.Shutdown(LogDisk);
                ok = VirtualDisks.CompactAsAdmin(d.Path, LogDisk);
            });
            d.FileSize = new FileInfo(d.Path).Length;
            if (d.UsedInside > d.FileSize) d.UsedInside = d.FileSize;
            SetDisksWorking(false, null);
            RefreshDiskList();
            if (ok) Toast(name + " went from " + Fmt.Size(before) + " to " + Fmt.Size(d.FileSize));
            else Toast("The disk wasn't compacted. The activity log has the details.", "");
            if (d.FileSize != before && result != null)
            {
                Node n = result.FindNode(d.Path);
                if (n != null && n.Parent != null) Rescan(n.Parent);
            }
        }
    }
}

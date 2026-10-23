using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;

namespace DiskSpace
{
    // Plain data objects that the XAML templates bind to.

    sealed class DriveVm
    {
        public string Path { get; set; }
        public string Title { get; set; }
        public string Detail { get; set; }
        public string FreeText { get; set; }
        public string Tooltip { get; set; }
        public GridLength UsedWidth { get; set; }
        public GridLength FreeWidth { get; set; }
        public Brush FillBrush { get; set; }
        public Brush TrackBrush { get; set; }
        public Visibility WarningVisibility { get; set; }
    }

    sealed class EntryVm
    {
        public Node Node { get; set; }
        public ImageSource Icon { get; set; }
        public string Name { get; set; }
        public string SizeText { get; set; }
        public string PercentText { get; set; }
        public GridLength ShareWidth { get; set; }
        public GridLength RestWidth { get; set; }
        public double Opacity { get; set; }

        public EntryVm(Node node, long whole)
        {
            Node = node;
            Icon = ShellIcons.For(node, false);
            var dir = node as DirNode;
            Name = node.Name + (dir != null && dir.Unreadable ? "  (could not be read)" : "");
            var file = node as FileNode;
            SizeText = file != null && file.Flags == FileFlags.OnlineOnly ? "online-only" : Fmt.Size(node.Size);
            double share = whole > 0 ? Math.Min(1, (double)node.Size / whole) : 0;
            PercentText = (share * 100).ToString("0.0") + "%";
            ShareWidth = new GridLength(share, GridUnitType.Star);
            RestWidth = new GridLength(1 - share, GridUnitType.Star);
            bool muted = (dir != null && (dir.Unaccounted || dir.Unreadable)) || (file != null && file.Flags == FileFlags.OnlineOnly);
            Opacity = muted ? 0.6 : 1;
        }
    }

    sealed class CategoryVm
    {
        public int Index { get; set; }
        public Brush Swatch { get; set; }
        public string Name { get; set; }
        public string SizeText { get; set; }
        public string PercentText { get; set; }
    }

    sealed class FileVm
    {
        public FileNode Node { get; set; }
        public ImageSource Icon { get; set; }
        public string Name { get; set; }
        public string Folder { get; set; }
        public string SizeText { get; set; }
        public string DateText { get; set; }
        public string CategoryName { get; set; }
        public Brush Swatch { get; set; }
    }

    sealed class InsightVm
    {
        public Insight Insight { get; set; }
        public string Glyph { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string SizeText { get; set; }
        public string ActionText { get; set; }
        public string ItemsLabel { get; set; }
        public Visibility ActionVisibility { get; set; }
        public Visibility ItemsVisibility { get; set; }
        public List<InsightItemVm> Items { get; set; }
    }

    sealed class InsightItemVm
    {
        public Insight Insight { get; set; }
        public Node Node { get; set; }
        public ImageSource Icon { get; set; }
        public string Name { get; set; }
        public string Folder { get; set; }
        public string SizeText { get; set; }
        public Visibility RecycleVisibility { get; set; }
    }

    sealed class MoveDriveVm
    {
        public string Glyph { get; set; }
        public string Name { get; set; }
        public string Kind { get; set; }
        public string FreeText { get; set; }
        public string Purpose { get; set; }
        public Visibility ScannedVisibility { get; set; }
    }

    sealed class MoveVm
    {
        public MoveSuggestion Suggestion { get; set; }
        public string Glyph { get; set; }
        public string Name { get; set; }
        public string Folder { get; set; }
        public string KindName { get; set; }
        public string Usage { get; set; }
        public Visibility UsageVisibility { get; set; }
        public string Reason { get; set; }
        public string TargetGlyph { get; set; }
        public string TargetText { get; set; }
        public Brush TargetBrush { get; set; }
        public string SizeText { get; set; }
        public string ActionText { get; set; }
        public Style ActionStyle { get; set; }
        public string SecondaryText { get; set; }
        public Visibility SecondaryVisibility { get; set; }
    }

    sealed class DiskVm
    {
        public VirtualDisk Disk { get; set; }
        public string Glyph { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }
        public string FileSizeText { get; set; }
        public string UsedText { get; set; }
        public string FreeText { get; set; }
        public Brush FreeBrush { get; set; }
        public string CleanText { get; set; }
        public Visibility CleanVisibility { get; set; }
        public string Note { get; set; }
        public Visibility NoteVisibility { get; set; }
    }
}

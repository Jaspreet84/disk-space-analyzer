using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace DiskSpace
{
    // A flat, squarified treemap. Folders large enough to read become panels with a header (name and size),
    // files become rounded tiles colored by category, and a 1 px gap separates everything. Tiles are rasterized
    // into a bitmap at device resolution; labels, hover and selection are drawn on top as vector layers.
    // Public because XAML loaded at runtime can only create public types; members that use the model are internal.
    public sealed class TreemapView : FrameworkElement
    {
        struct Cell
        {
            public Node Node;
            public int X0, Y0, X1, Y1;  // device pixels, end-exclusive

            public bool Contains(double x, double y) { return x >= X0 && x < X1 && y >= Y0 && y < Y1; }
        }

        struct Label
        {
            public int X0, Y0, X1, Y1;
            public string Name, Size;
            public bool Header;
            public Color Back;
        }

        const double HeaderHeight = 22, PanelMinWidth = 70, PanelMinHeight = 48, TileLabelMinWidth = 56, TileLabelMinHeight = 20;

        readonly VisualCollection layers;
        readonly DrawingVisual baseLayer = new DrawingVisual(), overlayLayer = new DrawingVisual();
        readonly List<Cell> cells = new List<Cell>();
        readonly List<Label> labels = new List<Label>();
        readonly DispatcherTimer resizeTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(90) };
        readonly Popup hoverCard;
        readonly TextBlock hoverName, hoverPath, hoverSize, hoverInfo;

        ScanResult result;
        DirNode root;
        Node selected;
        int hoverIndex = -1, selectedIndex = -1, highlight = -1;
        double scale = 1;
        int pw, ph;
        int[] pixels;
        Color gapColor, folderA, folderB, dimColor;
        Color[] categoryColors;

        public string EmptyText = "Nothing to show";
        internal event Action<Node> NodeClicked;
        internal event Action<Node> NodeActivated;
        internal event Action<Node> NodeContextRequested;

        public TreemapView()
        {
            layers = new VisualCollection(this) { baseLayer, overlayLayer };
            ClipToBounds = true;
            Focusable = true;
            FocusVisualStyle = null;
            resizeTimer.Tick += (s, e) => Render();
            Theme.Changed += (s, e) => Render();
            Loaded += (s, e) => Render();

            hoverName = new TextBlock { FontWeight = FontWeights.SemiBold, FontSize = 13, TextTrimming = TextTrimming.CharacterEllipsis };
            hoverPath = new TextBlock { FontSize = 12, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(0, 2, 0, 0) };
            hoverSize = new TextBlock { FontSize = 13, Margin = new Thickness(0, 8, 0, 0) };
            hoverInfo = new TextBlock { FontSize = 12, Margin = new Thickness(0, 2, 0, 0) };
            hoverPath.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondary");
            hoverInfo.SetResourceReference(TextBlock.ForegroundProperty, "TextSecondary");
            var stack = new StackPanel { MaxWidth = 380 };
            stack.Children.Add(hoverName);
            stack.Children.Add(hoverPath);
            stack.Children.Add(hoverSize);
            stack.Children.Add(hoverInfo);
            var card = new Border
            {
                CornerRadius = new CornerRadius(8),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(12, 10, 12, 10),
                Margin = new Thickness(4, 2, 12, 14),
                Child = stack,
                Effect = new DropShadowEffect { BlurRadius = 14, ShadowDepth = 3, Direction = 270, Opacity = 0.2 }
            };
            card.SetResourceReference(Border.BackgroundProperty, "FlyoutBg");
            card.SetResourceReference(Border.BorderBrushProperty, "CardBorder");
            card.SetResourceReference(TextElement.ForegroundProperty, "TextPrimary");
            card.SetResourceReference(TextElement.FontFamilyProperty, "BodyFont");
            hoverCard = new Popup
            {
                Child = card,
                AllowsTransparency = true,
                Placement = PlacementMode.Relative,
                PlacementTarget = this,
                IsHitTestVisible = false,
                StaysOpen = true
            };
        }

        internal DirNode Root { get { return root; } }

        internal void SetData(ScanResult r, DirNode folder, int highlightCategory)
        {
            result = r;
            root = folder;
            selected = null;
            highlight = highlightCategory;
            Render();
        }

        internal Node Selected
        {
            get { return selected; }
            set
            {
                selected = value;
                selectedIndex = FindCell(value);
                DrawOverlay();
            }
        }

        public int Highlight
        {
            get { return highlight; }
            set
            {
                if (highlight == value) return;
                highlight = value;
                Render();
            }
        }

        public void Refresh()
        {
            Render();
        }

        protected override int VisualChildrenCount { get { return layers.Count; } }

        protected override Visual GetVisualChild(int index) { return layers[index]; }

        protected override void OnRender(DrawingContext dc)
        {
            dc.DrawRectangle(Brushes.Transparent, null, new Rect(RenderSize));  // makes the whole area hit-testable
        }

        protected override void OnRenderSizeChanged(SizeChangedInfo info)
        {
            base.OnRenderSizeChanged(info);
            resizeTimer.Stop();
            resizeTimer.Start();
        }

        void Render()
        {
            resizeTimer.Stop();
            cells.Clear();
            labels.Clear();
            hoverIndex = selectedIndex = -1;
            PresentationSource source = PresentationSource.FromVisual(this);
            scale = source != null && source.CompositionTarget != null ? source.CompositionTarget.TransformToDevice.M11 : 1;
            int w = (int)Math.Round(ActualWidth * scale), h = (int)Math.Round(ActualHeight * scale);

            using (DrawingContext dc = baseLayer.RenderOpen())
            {
                if (root == null || result == null || root.Size <= 0 || w < 16 || h < 16)
                {
                    if (ActualWidth > 0 && ActualHeight > 0)
                    {
                        FormattedText empty = Text(EmptyText, 14, FontWeights.Normal, Theme.Brush("TextTertiary"));
                        dc.DrawText(empty, new Point((ActualWidth - empty.Width) / 2, (ActualHeight - empty.Height) / 2));
                    }
                }
                else
                {
                    LoadColors();
                    pw = w;
                    ph = h;
                    pixels = new int[w * h];
                    int gap = Pixel(gapColor);
                    for (int i = 0; i < pixels.Length; i++) pixels[i] = gap;
                    LayOut(root.Children, 0, 0, w, h, 0);

                    var bitmap = new WriteableBitmap(w, h, 96 * scale, 96 * scale, PixelFormats.Bgr32, null);
                    bitmap.WritePixels(new Int32Rect(0, 0, w, h), pixels, w * 4, 0);
                    bitmap.Freeze();
                    pixels = null;
                    dc.DrawImage(bitmap, new Rect(0, 0, w / scale, h / scale));
                    foreach (Label label in labels) DrawLabel(dc, label);
                }
            }
            selectedIndex = FindCell(selected);
            DrawOverlay();
        }

        void LoadColors()
        {
            categoryColors = Theme.CategoryColors;
            gapColor = Theme.ColorOf("CardBg");
            folderA = Theme.ColorOf("MapFolderA");
            folderB = Theme.ColorOf("MapFolderB");
            dimColor = Theme.ColorOf("MapDimmed");
        }

        // Squarified layout (Bruls, Huizing, van Wijk): fill rows along the shorter side while the worst aspect ratio improves.
        void LayOut(Node[] kids, double x, double y, double w, double h, int depth)
        {
            int n = kids.Length;
            while (n > 0 && kids[n - 1].Size <= 0) n--;  // sorted largest first, so empty items are at the end
            double remaining = 0;
            for (int k = 0; k < n; k++) remaining += kids[k].Size;

            int i = 0;
            while (i < n && w > 0 && h > 0 && remaining > 0)
            {
                double perByte = w * h / remaining;
                bool wide = w >= h;
                double side = wide ? h : w;
                int j = i;
                double rowBytes = 0, worst = double.MaxValue;
                while (j < n)
                {
                    double next = rowBytes + kids[j].Size;
                    double thick = next * perByte / side;
                    double big = kids[i].Size * perByte / thick, small = kids[j].Size * perByte / thick;
                    double ratio = Math.Max(Math.Max(thick / big, big / thick), Math.Max(thick / small, small / thick));
                    if (ratio > worst) break;
                    worst = ratio;
                    rowBytes = next;
                    j++;
                }

                double thickness = j == n ? (wide ? w : h) : rowBytes * perByte / side;
                double pos = wide ? y : x, end = wide ? y + h : x + w;
                for (int k = i; k < j; k++)
                {
                    double len = k == j - 1 ? end - pos : side * kids[k].Size / rowBytes;
                    if (wide) Place(kids[k], x, pos, thickness, len, depth);
                    else Place(kids[k], pos, y, len, thickness, depth);
                    pos += len;
                }
                if (wide) { x += thickness; w -= thickness; }
                else { y += thickness; h -= thickness; }
                remaining -= rowBytes;
                i = j;
            }
        }

        void Place(Node node, double x, double y, double w, double h, int depth)
        {
            int x0 = Clamp(x, pw), x1 = Clamp(x + w, pw), y0 = Clamp(y, ph), y1 = Clamp(y + h, ph);
            if (x1 <= x0 || y1 <= y0) return;  // covers no whole pixel, and neither can anything inside it
            int gap = Math.Max(1, (int)Math.Round(scale));
            bool spaced = x1 - x0 > gap * 3 && y1 - y0 > gap * 3;
            int tx1 = spaced ? x1 - gap : x1, ty1 = spaced ? y1 - gap : y1;

            var dir = node as DirNode;
            if (dir == null || dir.Unaccounted || dir.Children.Length == 0)
            {
                Color c = ColorFor(node);
                FillRounded(x0, y0, tx1, ty1, tx1 - x0 >= 10 * scale && ty1 - y0 >= 10 * scale ? (int)Math.Round(3 * scale) : 0, c);
                AddCell(node, x0, y0, tx1, ty1);
                if (tx1 - x0 >= TileLabelMinWidth * scale && ty1 - y0 >= TileLabelMinHeight * scale)
                    labels.Add(new Label { X0 = x0, Y0 = y0, X1 = tx1, Y1 = ty1, Name = node.Name, Size = Fmt.Size(node.Size), Back = c });
                return;
            }

            AddCell(node, x0, y0, tx1, ty1);
            if (tx1 - x0 >= PanelMinWidth * scale && ty1 - y0 >= PanelMinHeight * scale)
            {
                // A folder panel: a header strip with the name, then its contents inset by a small padding.
                Color panel = Dim(node) ? dimColor : depth % 2 == 0 ? folderA : folderB;
                FillRounded(x0, y0, tx1, ty1, (int)Math.Round(5 * scale), panel);
                int header = (int)Math.Round(HeaderHeight * scale), pad = Math.Max(2, (int)Math.Round(3 * scale));
                labels.Add(new Label { X0 = x0, Y0 = y0, X1 = tx1, Y1 = y0 + header, Name = node.Name, Size = Fmt.Size(node.Size), Header = true, Back = panel });
                LayOut(dir.Children, x0 + pad, y0 + header, (tx1 - pad) - (x0 + pad), (ty1 - pad) - (y0 + header), depth + 1);
            }
            else
            {
                // Too small for a header: its contents fill the whole area.
                LayOut(dir.Children, x0, y0, tx1 - x0, ty1 - y0, depth + 1);
            }
        }

        void AddCell(Node node, int x0, int y0, int x1, int y1)
        {
            if ((x1 - x0) * (y1 - y0) >= 4) cells.Add(new Cell { Node = node, X0 = x0, Y0 = y0, X1 = x1, Y1 = y1 });
        }

        bool Dim(Node node)
        {
            if (highlight < 0) return false;
            var file = node as FileNode;
            if (file != null) return file.Ext >= result.Extensions.Count || (int)result.Extensions[file.Ext].Category != highlight;
            var dir = node as DirNode;
            return dir == null || !(dir.Unaccounted && highlight == (int)Category.Unaccounted);
        }

        Color ColorFor(Node node)
        {
            if (Dim(node)) return dimColor;
            var file = node as FileNode;
            if (file == null)
            {
                var dir = (DirNode)node;
                return dir.Unaccounted ? categoryColors[(int)Category.Unaccounted] : folderB;
            }
            if (file.Ext >= result.Extensions.Count) return folderB;
            return categoryColors[(int)result.Extensions[file.Ext].Category];
        }

        // Fills a rectangle with rounded corners (radius in device pixels).
        void FillRounded(int x0, int y0, int x1, int y1, int radius, Color c)
        {
            int argb = Pixel(c);
            radius = Math.Min(radius, Math.Min((x1 - x0) / 2, (y1 - y0) / 2));
            for (int py = y0; py < y1; py++)
            {
                int inset = 0;
                int d = Math.Min(py - y0, y1 - 1 - py);
                if (d < radius)
                {
                    double t = radius - d - 0.5;
                    inset = (int)Math.Round(radius - Math.Sqrt(Math.Max(0, radius * radius - t * t)));
                }
                int row = py * pw;
                for (int px = x0 + inset; px < x1 - inset; px++) pixels[row + px] = argb;
            }
        }

        // A Bgr32 pixel: blue in the low byte.
        static int Pixel(Color c)
        {
            return (255 << 24) | (c.R << 16) | (c.G << 8) | c.B;
        }

        static int Clamp(double v, int max)
        {
            int i = (int)Math.Round(v);
            return i < 0 ? 0 : i > max ? max : i;
        }

        void DrawLabel(DrawingContext dc, Label l)
        {
            double x = l.X0 / scale, y = l.Y0 / scale, w = (l.X1 - l.X0) / scale, h = (l.Y1 - l.Y0) / scale;
            if (l.Header)
            {
                Brush ink = Theme.Brush("TextPrimary"), muted = Theme.Brush("TextSecondary");
                string text = l.Name + "   " + l.Size;
                FormattedText ft = Text(text, 12, FontWeights.SemiBold, ink);
                ft.SetForegroundBrush(muted, l.Name.Length, text.Length - l.Name.Length);
                ft.SetFontWeight(FontWeights.Normal, l.Name.Length, text.Length - l.Name.Length);
                ft.MaxTextWidth = Math.Max(1, w - 16);
                ft.MaxLineCount = 1;
                ft.Trimming = TextTrimming.CharacterEllipsis;
                dc.DrawText(ft, new Point(x + 8, y + (h - ft.Height) / 2 + 1));
                return;
            }
            var inkBrush = new SolidColorBrush(Theme.InkOn(l.Back));
            FormattedText name = Text(l.Name, 12, FontWeights.SemiBold, inkBrush);
            name.MaxTextWidth = Math.Max(1, w - 12);
            name.MaxLineCount = 1;
            name.Trimming = TextTrimming.CharacterEllipsis;
            dc.DrawText(name, new Point(x + 6, y + 4));
            if (h >= 38)
            {
                var sizeBrush = new SolidColorBrush(Theme.InkOn(l.Back)) { Opacity = 0.8 };
                FormattedText size = Text(l.Size, 11, FontWeights.Normal, sizeBrush);
                size.MaxTextWidth = Math.Max(1, w - 12);
                size.MaxLineCount = 1;
                dc.DrawText(size, new Point(x + 6, y + 4 + name.Height));
            }
        }

        FormattedText Text(string text, double size, FontWeight weight, Brush brush)
        {
            return new FormattedText(text, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
                new Typeface(new FontFamily("Segoe UI Variable Text, Segoe UI"), FontStyles.Normal, weight, FontStretches.Normal),
                size, brush, scale);
        }

        void DrawOverlay()
        {
            using (DrawingContext dc = overlayLayer.RenderOpen())
            {
                if (hoverIndex >= 0 && hoverIndex != selectedIndex && hoverIndex < cells.Count)
                    dc.DrawRoundedRectangle(null, new Pen(Theme.Brush("TextSecondary"), 1.5), CellRect(cells[hoverIndex], 0.75), 4, 4);
                if (selectedIndex >= 0 && selectedIndex < cells.Count)
                {
                    Rect r = CellRect(cells[selectedIndex], 1);
                    dc.DrawRoundedRectangle(null, new Pen(Theme.Brush("TextPrimary"), 2), r, 4, 4);
                    r.Inflate(-2, -2);
                    if (r.Width > 2 && r.Height > 2) dc.DrawRoundedRectangle(null, new Pen(Theme.Brush("CardBg"), 1), r, 3, 3);
                }
            }
        }

        Rect CellRect(Cell c, double inset)
        {
            var r = new Rect(c.X0 / scale, c.Y0 / scale, (c.X1 - c.X0) / scale, (c.Y1 - c.Y0) / scale);
            if (r.Width > inset * 2 && r.Height > inset * 2) r.Inflate(-inset, -inset);
            return r;
        }

        int FindCell(Node node)
        {
            for (Node n = node; n != null; n = n.Parent)
                for (int i = 0; i < cells.Count; i++)
                    if (cells[i].Node == n) return i;
            return -1;
        }

        int HitTest(Point p)
        {
            double x = p.X * scale, y = p.Y * scale;
            // Cells are in pre-order, so the last one containing the point is the deepest.
            for (int i = cells.Count - 1; i >= 0; i--)
                if (cells[i].Contains(x, y)) return i;
            return -1;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            Point p = e.GetPosition(this);
            int hit = HitTest(p);
            if (hit != hoverIndex)
            {
                hoverIndex = hit;
                DrawOverlay();
                if (hit >= 0) Describe(cells[hit].Node);
            }
            if (hit < 0)
            {
                hoverCard.IsOpen = false;
                return;
            }
            var card = (FrameworkElement)hoverCard.Child;
            card.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            double cx = p.X + 14, cy = p.Y + 18;
            if (cx + card.DesiredSize.Width > ActualWidth) cx = p.X - card.DesiredSize.Width - 6;
            if (cy + card.DesiredSize.Height > ActualHeight) cy = p.Y - card.DesiredSize.Height - 6;
            hoverCard.HorizontalOffset = cx;
            hoverCard.VerticalOffset = cy;
            hoverCard.IsOpen = true;
        }

        protected override void OnMouseLeave(MouseEventArgs e)
        {
            base.OnMouseLeave(e);
            hoverIndex = -1;
            hoverCard.IsOpen = false;
            DrawOverlay();
        }

        protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
        {
            base.OnMouseLeftButtonDown(e);
            Focus();
            int hit = HitTest(e.GetPosition(this));
            if (hit < 0) return;
            Node node = cells[hit].Node;
            if (e.ClickCount == 2)
            {
                Action<Node> activated = NodeActivated;
                if (activated != null) activated(node);
            }
            else
            {
                Action<Node> clicked = NodeClicked;
                if (clicked != null) clicked(node);
            }
        }

        protected override void OnMouseRightButtonUp(MouseButtonEventArgs e)
        {
            base.OnMouseRightButtonUp(e);
            int hit = HitTest(e.GetPosition(this));
            if (hit < 0) return;
            hoverCard.IsOpen = false;
            Action<Node> clicked = NodeClicked;
            if (clicked != null) clicked(cells[hit].Node);
            Action<Node> menu = NodeContextRequested;
            if (menu != null) menu(cells[hit].Node);
            e.Handled = true;
        }

        void Describe(Node n)
        {
            hoverName.Text = n.Name;
            hoverPath.Text = n.Parent == null ? "" : n.Parent.FullPath;
            string share = root != null && root.Size > 0 ? "   " + Fmt.Percent(n.Size, root.Size) + " of this folder" : "";
            hoverSize.Text = Fmt.Size(n.Size) + share;
            var file = n as FileNode;
            var dir = n as DirNode;
            if (dir != null && dir.Unaccounted)
                hoverInfo.Text = "In use on the drive but not found in any scanned file";
            else if (dir != null)
                hoverInfo.Text = Fmt.Count(dir.FileCount) + " files in " + Fmt.Count(dir.DirCount) + " folders";
            else if (file != null && file.Ext < result.Extensions.Count)
            {
                ExtInfo ext = result.Extensions[file.Ext];
                string date = Fmt.Date(n.LastWrite);
                hoverInfo.Text = Categories.Names[(int)ext.Category] + (date.Length > 0 ? "  ·  modified " + date : "");
            }
            else hoverInfo.Text = "";
        }
    }
}

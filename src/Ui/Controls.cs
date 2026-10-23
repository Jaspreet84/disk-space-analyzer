using System;
using System.Globalization;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace DiskSpace
{
    // A circular progress ring with an optional label in the middle. When indeterminate, a short arc spins.
    public sealed class ArcGauge : FrameworkElement
    {
        public static readonly DependencyProperty ValueProperty = DependencyProperty.Register("Value", typeof(double), typeof(ArcGauge),
            new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));
        public static readonly DependencyProperty TextProperty = DependencyProperty.Register("Text", typeof(string), typeof(ArcGauge),
            new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.AffectsRender));
        public static readonly DependencyProperty IsIndeterminateProperty = DependencyProperty.Register("IsIndeterminate", typeof(bool),
            typeof(ArcGauge), new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender, OnIndeterminateChanged));
        public static readonly DependencyProperty TrackBrushProperty = DependencyProperty.Register("TrackBrush", typeof(Brush), typeof(ArcGauge),
            new FrameworkPropertyMetadata(Brushes.LightGray, FrameworkPropertyMetadataOptions.AffectsRender));
        public static readonly DependencyProperty FillBrushProperty = DependencyProperty.Register("FillBrush", typeof(Brush), typeof(ArcGauge),
            new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));
        public static readonly DependencyProperty ForegroundProperty = TextElement.ForegroundProperty.AddOwner(typeof(ArcGauge),
            new FrameworkPropertyMetadata(Brushes.Black, FrameworkPropertyMetadataOptions.AffectsRender | FrameworkPropertyMetadataOptions.Inherits));
        static readonly DependencyProperty SpinProperty = DependencyProperty.Register("Spin", typeof(double), typeof(ArcGauge),
            new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

        public double Value { get { return (double)GetValue(ValueProperty); } set { SetValue(ValueProperty, value); } }
        public string Text { get { return (string)GetValue(TextProperty); } set { SetValue(TextProperty, value); } }
        public bool IsIndeterminate { get { return (bool)GetValue(IsIndeterminateProperty); } set { SetValue(IsIndeterminateProperty, value); } }
        public Brush TrackBrush { get { return (Brush)GetValue(TrackBrushProperty); } set { SetValue(TrackBrushProperty, value); } }
        public Brush FillBrush { get { return (Brush)GetValue(FillBrushProperty); } set { SetValue(FillBrushProperty, value); } }
        public Brush Foreground { get { return (Brush)GetValue(ForegroundProperty); } set { SetValue(ForegroundProperty, value); } }

        public double RingWidth = 8;

        static void OnIndeterminateChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var g = (ArcGauge)d;
            if ((bool)e.NewValue)
                g.BeginAnimation(SpinProperty, new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.1)) { RepeatBehavior = RepeatBehavior.Forever });
            else
                g.BeginAnimation(SpinProperty, null);
        }

        protected override void OnRender(DrawingContext dc)
        {
            double size = Math.Min(ActualWidth, ActualHeight);
            if (size <= RingWidth * 2) return;
            var center = new Point(ActualWidth / 2, ActualHeight / 2);
            double r = (size - RingWidth) / 2;
            var track = new Pen(TrackBrush, RingWidth);
            dc.DrawEllipse(null, track, center, r, r);
            var fill = new Pen(FillBrush, RingWidth) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            if (IsIndeterminate)
            {
                double start = (double)GetValue(SpinProperty) - 90;
                dc.DrawGeometry(null, fill, Arc(center, r, start, 100));
            }
            else if (Value >= 0.999)
            {
                dc.DrawEllipse(null, new Pen(FillBrush, RingWidth), center, r, r);
            }
            else if (Value > 0.002)
            {
                dc.DrawGeometry(null, fill, Arc(center, r, -90, 360 * Value));
            }
            if (!string.IsNullOrEmpty(Text))
            {
                var ft = new FormattedText(Text, CultureInfo.CurrentCulture, FlowDirection.LeftToRight,
                    new Typeface(new FontFamily("Segoe UI Variable Display, Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal),
                    size * 0.2, Foreground, VisualTreeHelper.GetDpi(this).PixelsPerDip);
                dc.DrawText(ft, new Point(center.X - ft.Width / 2, center.Y - ft.Height / 2));
            }
        }

        public static Geometry Arc(Point c, double r, double startDegrees, double sweepDegrees)
        {
            double a0 = startDegrees * Math.PI / 180, a1 = (startDegrees + sweepDegrees) * Math.PI / 180;
            var g = new StreamGeometry();
            using (StreamGeometryContext ctx = g.Open())
            {
                ctx.BeginFigure(new Point(c.X + r * Math.Cos(a0), c.Y + r * Math.Sin(a0)), false, false);
                ctx.ArcTo(new Point(c.X + r * Math.Cos(a1), c.Y + r * Math.Sin(a1)), new Size(r, r), 0, sweepDegrees > 180,
                    SweepDirection.Clockwise, true, false);
            }
            g.Freeze();
            return g;
        }
    }

    // A small spinning arc for "working" states. It only animates while visible.
    public sealed class Spinner : FrameworkElement
    {
        public static readonly DependencyProperty FillBrushProperty = DependencyProperty.Register("FillBrush", typeof(Brush), typeof(Spinner),
            new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));
        static readonly DependencyProperty SpinProperty = DependencyProperty.Register("Spin", typeof(double), typeof(Spinner),
            new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

        public Brush FillBrush { get { return (Brush)GetValue(FillBrushProperty); } set { SetValue(FillBrushProperty, value); } }

        public Spinner()
        {
            IsVisibleChanged += (s, e) =>
            {
                if (IsVisible) BeginAnimation(SpinProperty, new DoubleAnimation(0, 360, TimeSpan.FromSeconds(0.9)) { RepeatBehavior = RepeatBehavior.Forever });
                else BeginAnimation(SpinProperty, null);
            };
        }

        protected override void OnRender(DrawingContext dc)
        {
            double size = Math.Min(ActualWidth, ActualHeight);
            double thickness = Math.Max(2, size / 8);
            if (size <= thickness * 2) return;
            var pen = new Pen(FillBrush, thickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            dc.DrawGeometry(null, pen, ArcGauge.Arc(new Point(ActualWidth / 2, ActualHeight / 2), (size - thickness) / 2,
                (double)GetValue(SpinProperty) - 90, 110));
        }
    }
}

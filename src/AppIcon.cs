using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

namespace DiskSpace
{
    // Draws the app icon (a small four-block treemap) so the build needs no binary assets.
    static class AppIcon
    {
        public static Bitmap Draw(int size)
        {
            var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                bool tiny = size <= 20;
                float pad = tiny ? 0.5f : size * 0.06f;
                float gap = tiny ? 1f : size * 0.06f;
                float radius = tiny ? 1f : size * 0.08f;
                var r = new RectangleF(pad, pad, size - 2 * pad, size - 2 * pad);

                float leftWidth = (r.Width - gap) * 0.56f;
                Block(g, Categories.Colors[0], new RectangleF(r.X, r.Y, leftWidth, r.Height), radius);
                float rx = r.X + leftWidth + gap, rw = r.Right - rx;
                float topHeight = (r.Height - gap) * 0.56f;
                Block(g, Categories.Colors[1], new RectangleF(rx, r.Y, rw, topHeight), radius);
                float by = r.Y + topHeight + gap, bh = r.Bottom - by, half = (rw - gap) / 2;
                Block(g, Categories.Colors[2], new RectangleF(rx, by, half, bh), radius);
                Block(g, Categories.Colors[3], new RectangleF(rx + half + gap, by, rw - half - gap, bh), radius);
            }
            return bmp;
        }

        static void Block(Graphics g, Color color, RectangleF r, float radius)
        {
            using (GraphicsPath path = Rounded(r, radius))
            using (var brush = new SolidBrush(color))
                g.FillPath(brush, path);
        }

        static GraphicsPath Rounded(RectangleF r, float radius)
        {
            var p = new GraphicsPath();
            float d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        // An .ico with uncompressed 32-bit frames for the small sizes and, optionally, a PNG frame at 256 px.
        public static byte[] BuildIco(bool includeLarge)
        {
            int[] sizes = includeLarge ? new[] { 16, 20, 24, 32, 40, 48, 64, 256 } : new[] { 16, 20, 24, 32, 40, 48 };
            var frames = new List<byte[]>();
            foreach (int s in sizes)
                using (Bitmap bmp = Draw(s))
                    frames.Add(s >= 256 ? Png(bmp) : Dib(bmp));

            using (var ms = new MemoryStream())
            using (var w = new BinaryWriter(ms))
            {
                w.Write((short)0);
                w.Write((short)1);
                w.Write((short)sizes.Length);
                int offset = 6 + 16 * sizes.Length;
                for (int i = 0; i < sizes.Length; i++)
                {
                    byte dim = (byte)(sizes[i] >= 256 ? 0 : sizes[i]);
                    w.Write(dim);
                    w.Write(dim);
                    w.Write((byte)0);
                    w.Write((byte)0);
                    w.Write((short)1);
                    w.Write((short)32);
                    w.Write(frames[i].Length);
                    w.Write(offset);
                    offset += frames[i].Length;
                }
                foreach (byte[] f in frames) w.Write(f);
                w.Flush();
                return ms.ToArray();
            }
        }

        static byte[] Png(Bitmap bmp)
        {
            using (var ms = new MemoryStream())
            {
                bmp.Save(ms, ImageFormat.Png);
                return ms.ToArray();
            }
        }

        static byte[] Dib(Bitmap bmp)
        {
            int s = bmp.Width;
            int maskStride = (s + 31) / 32 * 4;
            using (var ms = new MemoryStream())
            using (var w = new BinaryWriter(ms))
            {
                w.Write(40);               // BITMAPINFOHEADER size
                w.Write(s);
                w.Write(s * 2);            // icon frames count the AND mask in the height
                w.Write((short)1);
                w.Write((short)32);
                w.Write(0);
                w.Write(s * s * 4 + maskStride * s);
                w.Write(0);
                w.Write(0);
                w.Write(0);
                w.Write(0);
                for (int y = s - 1; y >= 0; y--)
                {
                    for (int x = 0; x < s; x++)
                    {
                        Color c = bmp.GetPixel(x, y);
                        w.Write(c.B);
                        w.Write(c.G);
                        w.Write(c.R);
                        w.Write(c.A);
                    }
                }
                w.Write(new byte[maskStride * s]);  // all zero: the alpha channel carries transparency
                w.Flush();
                return ms.ToArray();
            }
        }

        public static Icon CreateIcon()
        {
            using (var ms = new MemoryStream(BuildIco(false)))
                return new Icon(ms);
        }

        public static void WriteIcoFile(string path)
        {
            File.WriteAllBytes(path, BuildIco(true));
        }
    }
}

using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace DiskSpace
{
    enum ThemeChoice { System, Light, Dark }

    // Colors for the light and dark themes. They are published as brush resources (used by Styles.xaml and
    // MainWindow.xaml through DynamicResource), so changing theme updates every control in place.
    static class Theme
    {
        public static bool IsDark { get; private set; }
        public static ThemeChoice Choice { get; private set; }
        public static event EventHandler Changed;

        // Data colors: the eight categorical slots of the reference data-viz palette in their validated order,
        // then the neutrals for "other" and "unaccounted". Each theme has its own validated steps.
        static readonly int[] CategoryLight = { 0x2a78d6, 0xeb6834, 0x1baf7a, 0xeda100, 0xe87ba4, 0x008300, 0x6250d6, 0xe34948, 0x898781, 0x52514e };
        static readonly int[] CategoryDark = { 0x3987e5, 0xd95926, 0x199e70, 0xc98500, 0xd55181, 0x008300, 0x9085e9, 0xe66767, 0x898781, 0x75746f };

        public static Color[] CategoryColors { get; private set; }

        public static void Apply(ResourceDictionary resources, ThemeChoice choice)
        {
            Choice = choice;
            IsDark = choice == ThemeChoice.Dark || (choice == ThemeChoice.System && SystemUsesDark());
            Color accent = SystemAccent();
            var c = new Dictionary<string, Color>();
            if (!IsDark)
            {
                Color fill = Mix(accent, Colors.Black, 0.25);
                c["WindowBg"] = Hex(0xF3F3F3);
                c["LayerBg"] = Hex(0xF9F9F9);
                c["LayerBorder"] = Hex(0xE5E5E5);
                c["CardBg"] = Hex(0xFFFFFF);
                c["CardBgHover"] = Hex(0xF9F9F9);
                c["CardBgPressed"] = Hex(0xF4F4F4);
                c["CardBorder"] = Hex(0xE5E5E5);
                c["CardBorderHover"] = Hex(0xD4D4D4);
                c["CardBgSecondary"] = Hex(0xF7F7F7);
                c["TextPrimary"] = Hex(0x1B1B1B);
                c["TextSecondary"] = Hex(0x5D5D5D);
                c["TextTertiary"] = Hex(0x8A8A8A);
                c["TextOnAccent"] = Colors.White;
                c["Accent"] = fill;
                c["AccentHover"] = Mix(fill, Colors.White, 0.1);
                c["AccentPressed"] = Mix(fill, Colors.White, 0.2);
                c["AccentText"] = fill;
                c["AccentTint"] = WithAlpha(accent, 0x1F);
                c["SubtleHover"] = Argb(0x0A, 0x000000);
                c["SubtlePressed"] = Argb(0x06, 0x000000);
                c["SubtleSelected"] = Argb(0x10, 0x000000);
                c["ControlFill"] = Hex(0xFEFEFE);
                c["ControlFillHover"] = Hex(0xF6F6F6);
                c["ControlFillPressed"] = Hex(0xF1F1F1);
                c["ControlBorder"] = Hex(0xDCDCDC);
                c["ControlBorderStrong"] = Hex(0x8A8A8A);
                c["Divider"] = Hex(0xEAEAEA);
                c["Danger"] = Hex(0xC42B1C);
                c["DangerHover"] = Hex(0xCE4335);
                c["DangerPressed"] = Hex(0xD6584B);
                c["Warning"] = Hex(0xFAB219);
                c["Good"] = Hex(0x0F7B0F);
                c["Smoke"] = Argb(0x4D, 0x000000);
                c["FlyoutBg"] = Hex(0xFAFAFA);
                c["DialogBg"] = Hex(0xFFFFFF);
                c["ToastBg"] = Hex(0x2B2B2B);
                c["ToastText"] = Hex(0xFFFFFF);
                c["ScrollThumb"] = Argb(0x88, 0x8A8A8A);
                c["FocusStroke"] = Hex(0x1B1B1B);
                c["MeterTrack"] = Hex(0xCDE2FB);   // blue ramp 100
                c["MeterFill"] = Hex(0x2A78D6);    // blue ramp 450
                c["MeterWarning"] = Hex(0xFAB219);
                c["MeterCritical"] = Hex(0xD03B3B);
                c["MapFolderA"] = Hex(0xEEEEEE);
                c["MapFolderB"] = Hex(0xE3E3E3);
                c["MapDimmed"] = Hex(0xE1E0D9);
                CategoryColors = ToColors(CategoryLight);
            }
            else
            {
                Color fill = Mix(accent, Colors.White, 0.45);
                c["WindowBg"] = Hex(0x202020);
                c["LayerBg"] = Hex(0x272727);
                c["LayerBorder"] = Hex(0x1C1C1C);
                c["CardBg"] = Hex(0x2C2C2C);
                c["CardBgHover"] = Hex(0x323232);
                c["CardBgPressed"] = Hex(0x292929);
                c["CardBorder"] = Hex(0x383838);
                c["CardBorderHover"] = Hex(0x444444);
                c["CardBgSecondary"] = Hex(0x303030);
                c["TextPrimary"] = Hex(0xFFFFFF);
                c["TextSecondary"] = Hex(0xC8C8C8);
                c["TextTertiary"] = Hex(0x9D9D9D);
                c["TextOnAccent"] = Hex(0x000000);
                c["Accent"] = fill;
                c["AccentHover"] = Mix(fill, Colors.Black, 0.1);
                c["AccentPressed"] = Mix(fill, Colors.Black, 0.2);
                c["AccentText"] = Mix(accent, Colors.White, 0.6);
                c["AccentTint"] = WithAlpha(fill, 0x2E);
                c["SubtleHover"] = Argb(0x0F, 0xFFFFFF);
                c["SubtlePressed"] = Argb(0x0A, 0xFFFFFF);
                c["SubtleSelected"] = Argb(0x15, 0xFFFFFF);
                c["ControlFill"] = Hex(0x2F2F2F);
                c["ControlFillHover"] = Hex(0x363636);
                c["ControlFillPressed"] = Hex(0x2A2A2A);
                c["ControlBorder"] = Hex(0x3F3F3F);
                c["ControlBorderStrong"] = Hex(0x9D9D9D);
                c["Divider"] = Hex(0x3A3A3A);
                c["Danger"] = Hex(0xC42B1C);
                c["DangerHover"] = Hex(0xB02718);
                c["DangerPressed"] = Hex(0x9C2215);
                c["Warning"] = Hex(0xFAB219);
                c["Good"] = Hex(0x6CCB5F);
                c["Smoke"] = Argb(0x80, 0x000000);
                c["FlyoutBg"] = Hex(0x2C2C2C);
                c["DialogBg"] = Hex(0x2B2B2B);
                c["ToastBg"] = Hex(0xF3F3F3);
                c["ToastText"] = Hex(0x1B1B1B);
                c["ScrollThumb"] = Argb(0x88, 0x9D9D9D);
                c["FocusStroke"] = Hex(0xFFFFFF);
                c["MeterTrack"] = Hex(0x104281);   // blue ramp 650
                c["MeterFill"] = Hex(0x3987E5);    // blue ramp 400
                c["MeterWarning"] = Hex(0xFAB219);
                c["MeterCritical"] = Hex(0xD03B3B);
                c["MapFolderA"] = Hex(0x363636);
                c["MapFolderB"] = Hex(0x3F3F3F);
                c["MapDimmed"] = Hex(0x383835);
                CategoryColors = ToColors(CategoryDark);
            }

            foreach (KeyValuePair<string, Color> pair in c)
                resources[pair.Key] = Frozen(pair.Value);
            for (int i = 0; i < CategoryColors.Length; i++)
                resources["Cat" + i] = Frozen(CategoryColors[i]);

            EventHandler h = Changed;
            if (h != null) h(null, EventArgs.Empty);
        }

        public static Brush Brush(string key)
        {
            return (Brush)Application.Current.Resources[key];
        }

        public static Color ColorOf(string key)
        {
            return ((SolidColorBrush)Application.Current.Resources[key]).Color;
        }

        public static bool SystemUsesDark()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                {
                    object v = k == null ? null : k.GetValue("AppsUseLightTheme");
                    return v is int && (int)v == 0;
                }
            }
            catch (Exception) { return false; }
        }

        // The user's Windows accent color (stored as ABGR), or Windows blue.
        static Color SystemAccent()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\DWM"))
                {
                    object v = k == null ? null : k.GetValue("AccentColor");
                    if (v is int)
                    {
                        int abgr = (int)v;
                        return System.Windows.Media.Color.FromRgb((byte)(abgr & 0xFF), (byte)((abgr >> 8) & 0xFF), (byte)((abgr >> 16) & 0xFF));
                    }
                }
            }
            catch (Exception) { }
            return Hex(0x0078D4);
        }

        public static ThemeChoice LoadChoice()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(@"Software\DiskSpaceAnalyzer"))
                {
                    var v = k == null ? null : k.GetValue("Theme") as string;
                    ThemeChoice choice;
                    if (v != null && Enum.TryParse(v, out choice)) return choice;
                }
            }
            catch (Exception) { }
            return ThemeChoice.System;
        }

        public static void SaveChoice(ThemeChoice choice)
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.CreateSubKey(@"Software\DiskSpaceAnalyzer"))
                    k.SetValue("Theme", choice.ToString());
            }
            catch (Exception) { }
        }

        // White or near-black text, whichever reads better on the given fill.
        public static Color InkOn(Color fill)
        {
            double l = (0.2126 * Linear(fill.R) + 0.7152 * Linear(fill.G) + 0.0722 * Linear(fill.B));
            return l > 0.33 ? Hex(0x1B1B1B) : Colors.White;
        }

        static double Linear(byte v)
        {
            double c = v / 255.0;
            return c <= 0.03928 ? c / 12.92 : Math.Pow((c + 0.055) / 1.055, 2.4);
        }

        public static Color Mix(Color a, Color b, double t)
        {
            return System.Windows.Media.Color.FromRgb((byte)(a.R + (b.R - a.R) * t), (byte)(a.G + (b.G - a.G) * t), (byte)(a.B + (b.B - a.B) * t));
        }

        static Color WithAlpha(Color c, byte alpha)
        {
            return System.Windows.Media.Color.FromArgb(alpha, c.R, c.G, c.B);
        }

        public static Color Hex(int rgb)
        {
            return System.Windows.Media.Color.FromRgb((byte)(rgb >> 16), (byte)(rgb >> 8), (byte)rgb);
        }

        static Color Argb(byte alpha, int rgb)
        {
            return System.Windows.Media.Color.FromArgb(alpha, (byte)(rgb >> 16), (byte)(rgb >> 8), (byte)rgb);
        }

        static Color[] ToColors(int[] rgb)
        {
            var result = new Color[rgb.Length];
            for (int i = 0; i < rgb.Length; i++) result[i] = Hex(rgb[i]);
            return result;
        }

        static SolidColorBrush Frozen(Color c)
        {
            var b = new SolidColorBrush(c);
            b.Freeze();
            return b;
        }
    }
}

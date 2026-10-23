using System;
using System.IO;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Threading;
using Microsoft.Win32;

namespace DiskSpace
{
    // Command-line options. A path scans it right away; the rest drive --snapshot, which renders the window
    // to a PNG without showing it (used to check the layout).
    sealed class Options
    {
        public string ScanPath, Snapshot, Page, Explore, Select, Dialog;
        public int Highlight = -1;
        public ThemeChoice? Theme;

        public static Options Parse(string[] args)
        {
            var o = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                string next = i + 1 < args.Length ? args[i + 1] : null;
                if (a == "--snapshot" && next != null) { o.Snapshot = next; i++; }
                else if (a == "--page" && next != null) { o.Page = next; i++; }
                else if (a == "--explore" && next != null) { o.Explore = next; i++; }
                else if (a == "--select" && next != null) { o.Select = next; i++; }
                else if (a == "--dialog" && next != null) { o.Dialog = next; i++; }
                else if (a == "--highlight" && next != null) { int.TryParse(next, out o.Highlight); i++; }
                else if (a == "--theme" && next != null)
                {
                    ThemeChoice t;
                    if (Enum.TryParse(next, true, out t)) o.Theme = t;
                    i++;
                }
                else if (!a.StartsWith("--", StringComparison.Ordinal)) o.ScanPath = a;
            }
            return o;
        }
    }

    static class UiApp
    {
        public static int Run(string[] args)
        {
            Options options = Options.Parse(args);
            try { return Start(options); }
            catch (Exception ex)
            {
                // Failures before the window is up (a broken layout file, for example) end up here.
                WriteError(ex);
                if (options.Snapshot == null)
                    MessageBox.Show("Disk Space Analyzer couldn't start:\n\n" + ex.Message, "Disk Space Analyzer", MessageBoxButton.OK, MessageBoxImage.Error);
                return 3;
            }
        }

        static void WriteError(Exception ex)
        {
            try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "DiskSpaceAnalyzer-error.txt"), ex.ToString()); }
            catch (IOException) { }
        }

        static int Start(Options options)
        {
            var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
            app.DispatcherUnhandledException += (s, e) => OnError(e, options);
            app.Resources.MergedDictionaries.Add(LoadXaml<ResourceDictionary>("Styles.xaml"));
            Theme.Apply(app.Resources, options.Theme ?? Theme.LoadChoice());

            // Follow Windows when it switches between light and dark, if the theme is set to System.
            SystemEvents.UserPreferenceChanged += (s, e) => app.Dispatcher.BeginInvoke(new Action(() =>
            {
                if (Theme.Choice == ThemeChoice.System && Theme.SystemUsesDark() != Theme.IsDark)
                    Theme.Apply(app.Resources, ThemeChoice.System);
            }));

            var main = new MainWindow(options);
            return app.Run(main.Window);
        }

        public static T LoadXaml<T>(string name)
        {
            using (Stream s = typeof(UiApp).Assembly.GetManifestResourceStream("DiskSpace." + name))
                return (T)XamlReader.Load(s);
        }

        static void OnError(DispatcherUnhandledExceptionEventArgs e, Options options)
        {
            WriteError(e.Exception);
            if (options.Snapshot != null)
            {
                Environment.Exit(3);  // a snapshot run has no one to show the error to
                return;
            }
            MessageBox.Show("Something went wrong:\n\n" + e.Exception.Message, "Disk Space Analyzer", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }
    }
}

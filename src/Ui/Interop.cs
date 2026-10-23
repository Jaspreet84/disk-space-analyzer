using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace DiskSpace
{
    // File-type icons from the shell, cached by extension. Must be used from the UI thread.
    static class ShellIcons
    {
        static readonly Dictionary<string, ImageSource> small = new Dictionary<string, ImageSource>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, ImageSource> large = new Dictionary<string, ImageSource>(StringComparer.OrdinalIgnoreCase);

        public static ImageSource For(Node node, bool big)
        {
            var dir = node as DirNode;
            string key, probe;
            uint attributes;
            if (dir != null)
            {
                if (dir.Unaccounted) return null;
                key = "<folder>";
                probe = "folder";
                attributes = Native.FILE_ATTRIBUTE_DIRECTORY;
            }
            else
            {
                int dot = node.Name.LastIndexOf('.');
                key = dot >= 0 ? node.Name.Substring(dot) : "";
                probe = "file" + key;
                attributes = Native.FILE_ATTRIBUTE_NORMAL;
            }
            Dictionary<string, ImageSource> cache = big ? large : small;
            ImageSource icon;
            if (!cache.TryGetValue(key, out icon))
            {
                icon = Load(probe, attributes, big);
                cache[key] = icon;
            }
            return icon;
        }

        static ImageSource Load(string probe, uint attributes, bool big)
        {
            var info = new Native.SHFILEINFO();
            uint flags = Native.SHGFI_ICON | Native.SHGFI_USEFILEATTRIBUTES | (big ? 0 : Native.SHGFI_SMALLICON);
            Native.SHGetFileInfo(probe, attributes, ref info, (uint)Marshal.SizeOf(info), flags);
            if (info.hIcon == IntPtr.Zero) return null;
            try
            {
                BitmapSource source = Imaging.CreateBitmapSourceFromHIcon(info.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                source.Freeze();
                return source;
            }
            finally
            {
                Native.DestroyIcon(info.hIcon);
            }
        }
    }

    // The Windows folder picker (the same dialog File Explorer uses), through IFileOpenDialog.
    static class FolderPicker
    {
        [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")]
        class FileOpenDialog { }

        [ComImport, Guid("42f85136-db7e-439c-85f1-e4075d135fc8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IFileDialog
        {
            [PreserveSig] int Show(IntPtr parent);
            void SetFileTypes(uint cFileTypes, IntPtr rgFilterSpec);
            void SetFileTypeIndex(uint iFileType);
            void GetFileTypeIndex(out uint piFileType);
            void Advise(IntPtr pfde, out uint pdwCookie);
            void Unadvise(uint dwCookie);
            void SetOptions(uint fos);
            void GetOptions(out uint pfos);
            void SetDefaultFolder(IShellItem psi);
            void SetFolder(IShellItem psi);
            void GetFolder(out IShellItem ppsi);
            void GetCurrentSelection(out IShellItem ppsi);
            void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszName);
            void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string pszName);
            void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
            void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string pszText);
            void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string pszLabel);
            void GetResult(out IShellItem ppsi);
        }

        [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IShellItem
        {
            void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
            void GetParent(out IShellItem ppsi);
            void GetDisplayName(uint sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string ppszName);
            void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
            void Compare(IShellItem psi, uint hint, out int piOrder);
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        static extern void SHCreateItemFromParsingName(string pszPath, IntPtr pbc, [In] ref Guid riid, out IShellItem ppv);

        const uint FOS_PICKFOLDERS = 0x20, FOS_FORCEFILESYSTEM = 0x40, FOS_PATHMUSTEXIST = 0x800;
        const uint SIGDN_FILESYSPATH = 0x80058000;

        // Returns the chosen folder, or null if the dialog was cancelled.
        public static string Pick(Window owner, string title, string initialFolder)
        {
            var dialog = (IFileDialog)new FileOpenDialog();
            try
            {
                uint options;
                dialog.GetOptions(out options);
                dialog.SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
                dialog.SetTitle(title);
                if (!string.IsNullOrEmpty(initialFolder) && Directory.Exists(initialFolder))
                {
                    try
                    {
                        Guid iid = typeof(IShellItem).GUID;
                        IShellItem folder;
                        SHCreateItemFromParsingName(initialFolder, IntPtr.Zero, ref iid, out folder);
                        dialog.SetFolder(folder);
                    }
                    catch (COMException) { }
                }
                if (dialog.Show(new WindowInteropHelper(owner).Handle) != 0) return null;
                IShellItem item;
                dialog.GetResult(out item);
                string path;
                item.GetDisplayName(SIGDN_FILESYSPATH, out path);
                return path;
            }
            finally
            {
                Marshal.ReleaseComObject(dialog);
            }
        }
    }

    static class WindowsInfo
    {
        [StructLayout(LayoutKind.Sequential)]
        struct SHQUERYRBINFO
        {
            public int cbSize;
            public long i64Size;
            public long i64NumItems;
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern int SHQueryRecycleBin(string pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        static extern int SHGetKnownFolderPath([In] ref Guid rfid, uint dwFlags, IntPtr hToken, [MarshalAs(UnmanagedType.LPWStr)] out string ppszPath);

        static readonly Guid DownloadsFolder = new Guid("374DE290-123F-4565-9164-39C4925E467B");

        // Total size of the Recycle Bin on all drives, or 0 if Windows does not say.
        public static long RecycleBinBytes()
        {
            var info = new SHQUERYRBINFO { cbSize = Marshal.SizeOf(typeof(SHQUERYRBINFO)) };
            return SHQueryRecycleBin(null, ref info) == 0 ? info.i64Size : 0;
        }

        public static string Downloads()
        {
            Guid id = DownloadsFolder;
            string path;
            if (SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out path) == 0 && !string.IsNullOrEmpty(path)) return path;
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        }
    }
}

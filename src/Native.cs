using System;
using System.IO;
using System.Runtime.InteropServices;

namespace DiskSpace
{
    static class Native
    {
        public const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        public const uint FILE_ATTRIBUTE_SPARSE_FILE = 0x200;
        public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        public const uint FILE_ATTRIBUTE_COMPRESSED = 0x800;
        public const uint FILE_ATTRIBUTE_OFFLINE = 0x1000;
        public const uint FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000;
        public const uint FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000;

        // Reparse tags, read from WIN32_FIND_DATA.dwReserved0 when FILE_ATTRIBUTE_REPARSE_POINT is set.
        public const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C;
        public const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;

        public const int FindExInfoBasic = 1;
        public const int FIND_FIRST_EX_LARGE_FETCH = 2;
        public const int ERROR_FILE_NOT_FOUND = 2;
        public const uint INVALID_FILE_SIZE = 0xFFFFFFFF;

        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        // FILETIME fields are split into two DWORDs so the struct keeps its native 4-byte packing.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public uint ftCreationTimeLow, ftCreationTimeHigh;
            public uint ftLastAccessTimeLow, ftLastAccessTimeHigh;
            public uint ftLastWriteTimeLow, ftLastWriteTimeHigh;
            public uint nFileSizeHigh, nFileSizeLow;
            public uint dwReserved0, dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr FindFirstFileExW(string lpFileName, int fInfoLevelId, out WIN32_FIND_DATA lpFindFileData,
            int fSearchOp, IntPtr lpSearchFilter, int dwAdditionalFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        public static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern bool FindClose(IntPtr hFindFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        public static extern uint GetCompressedFileSizeW(string lpFileName, out uint lpFileSizeHigh);

        public const uint FILE_SHARE_ALL = 7;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;  // required to open a folder

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        public static extern uint GetFinalPathNameByHandleW(Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
            System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        public static extern bool GetDiskFreeSpaceExW(string lpDirectoryName, out ulong freeBytesAvailable,
            out ulong totalNumberOfBytes, out ulong totalNumberOfFreeBytes);

        // Shell

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHFILEINFO
        {
            public IntPtr hIcon;
            public int iIcon;
            public uint dwAttributes;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
        }

        public const uint SHGFI_SMALLICON = 0x1;
        public const uint SHGFI_USEFILEATTRIBUTES = 0x10;
        public const uint SHGFI_ICON = 0x100;
        public const uint SHGFI_TYPENAME = 0x400;

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "SHGetFileInfoW")]
        public static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes, ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);

        [DllImport("user32.dll")]
        public static extern bool DestroyIcon(IntPtr hIcon);

        // The program registered for a file type, such as ".json". Used by ShellOps.OpenAt to pick an editor; the
        // result is only a path to compare, nothing is run through the association.
        public const uint ASSOCF_NONE = 0;
        public const uint ASSOCSTR_EXECUTABLE = 2;

        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, EntryPoint = "AssocQueryStringW")]
        public static extern int AssocQueryString(uint flags, uint str, string pszAssoc, string pszExtra,
            System.Text.StringBuilder pszOut, ref uint pcchOut);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHELLEXECUTEINFO
        {
            public int cbSize;
            public uint fMask;
            public IntPtr hwnd;
            public string lpVerb;
            public string lpFile;
            public string lpParameters;
            public string lpDirectory;
            public int nShow;
            public IntPtr hInstApp;
            public IntPtr lpIDList;
            public string lpClass;
            public IntPtr hkeyClass;
            public uint dwHotKey;
            public IntPtr hIcon;
            public IntPtr hProcess;
        }

        public const uint SEE_MASK_INVOKEIDLIST = 0xC;

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "ShellExecuteExW", SetLastError = true)]
        public static extern bool ShellExecuteEx(ref SHELLEXECUTEINFO lpExecInfo);

        // shellapi.h packs SHFILEOPSTRUCT to 1 byte on 32-bit Windows only, so there are two layouts.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHFILEOPSTRUCT
        {
            public IntPtr hwnd;
            public uint wFunc;
            public string pFrom;
            public string pTo;
            public ushort fFlags;
            public int fAnyOperationsAborted;
            public IntPtr hNameMappings;
            public string lpszProgressTitle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 1)]
        public struct SHFILEOPSTRUCT32
        {
            public IntPtr hwnd;
            public uint wFunc;
            public string pFrom;
            public string pTo;
            public ushort fFlags;
            public int fAnyOperationsAborted;
            public IntPtr hNameMappings;
            public string lpszProgressTitle;
        }

        public const uint FO_DELETE = 3;
        public const ushort FOF_NOCONFIRMATION = 0x10;
        public const ushort FOF_ALLOWUNDO = 0x40;
        public const ushort FOF_WANTNUKEWARNING = 0x4000;

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "SHFileOperationW")]
        public static extern int SHFileOperation(ref SHFILEOPSTRUCT lpFileOp);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "SHFileOperationW")]
        public static extern int SHFileOperation32(ref SHFILEOPSTRUCT32 lpFileOp);

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        public static extern int SetWindowTheme(IntPtr hwnd, string pszSubAppName, string pszSubIdList);

        [DllImport("user32.dll")]
        public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);

        public const uint NameSurrogateTag = 0x20000000;  // set on junctions, mount points and symbolic links

        // True when the folder at path is a junction, mount point or symbolic link: a name-surrogate reparse
        // point, the kind the scanner does not follow. Reads only the folder's own directory entry.
        public static bool IsNameSurrogate(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string p = path.Length > 3 ? path.TrimEnd('\\') : path;
            if (p.Length <= 3) return false;  // a drive root has no entry of its own
            WIN32_FIND_DATA fd;
            IntPtr h = FindFirstFileExW(Scanner.LongPath(p), FindExInfoBasic, out fd, 0, IntPtr.Zero, 0);
            if (h == INVALID_HANDLE_VALUE) return false;
            FindClose(h);
            return (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 && (fd.dwReserved0 & NameSurrogateTag) != 0;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern uint QueryDosDeviceW(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);

        // True for a drive letter made with SUBST (or DefineDosDevice): an alias for a folder on another drive,
        // which Windows reports as a "\??\C:\folder" target. Such a letter is not a drive of its own.
        public static bool IsSubstDrive(string root)
        {
            if (string.IsNullOrEmpty(root) || root.Length < 2 || root[1] != ':') return false;
            try
            {
                var sb = new System.Text.StringBuilder(1024);
                if (QueryDosDeviceW(root.Substring(0, 2), sb, sb.Capacity) == 0) return false;
                return sb.ToString().StartsWith(@"\??\", StringComparison.Ordinal);
            }
            catch (DllNotFoundException) { return false; }
            catch (EntryPointNotFoundException) { return false; }
        }
    }

    // The shell's known folders, which can be moved away from the user folder (Downloads on another drive,
    // Documents redirected into OneDrive). Each getter falls back to the usual folder under the profile.
    static class KnownFolders
    {
        public static readonly Guid DownloadsId = new Guid("374DE290-123F-4565-9164-39C4925E467B");
        public static readonly Guid DesktopId = new Guid("B4BFCC3A-DB2C-424C-B029-7FE99A87C641");
        public static readonly Guid DocumentsId = new Guid("FDD39AD0-238F-46AF-ADB4-6C85480369C7");
        public static readonly Guid PicturesId = new Guid("33E28130-4E1E-4676-835A-98395C3BC3BB");
        public static readonly Guid VideosId = new Guid("18989B1D-99B5-455B-841C-AB7C74E4DDFC");
        public static readonly Guid MusicId = new Guid("4BD8D571-6D19-48D3-BE97-422220080E43");

        [DllImport("shell32.dll", ExactSpelling = true)]
        static extern int SHGetKnownFolderPath([In] ref Guid rfid, uint dwFlags, IntPtr hToken,
            [MarshalAs(UnmanagedType.LPWStr)] out string ppszPath);

        public static string Get(Guid id, string fallback)
        {
            try
            {
                string path;
                if (SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out path) == 0 && !string.IsNullOrEmpty(path)) return path;
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
            return fallback;
        }

        static string Under(string leaf)
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), leaf);
        }

        public static string Downloads() { return Get(DownloadsId, Under("Downloads")); }
        public static string Desktop() { return Get(DesktopId, Under("Desktop")); }
        public static string Documents() { return Get(DocumentsId, Under("Documents")); }
        public static string Pictures() { return Get(PicturesId, Under("Pictures")); }
        public static string Videos() { return Get(VideosId, Under("Videos")); }
        public static string Music() { return Get(MusicId, Under("Music")); }
    }
}

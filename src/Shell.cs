using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace DiskSpace
{
    static class ShellOps
    {
        public static void Open(string path)
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }

        public static void ShowInExplorer(string path)
        {
            Process.Start("explorer.exe", "/select,\"" + path + "\"");
        }

        public static void ShowProperties(string path, IntPtr owner)
        {
            var info = new Native.SHELLEXECUTEINFO();
            info.cbSize = Marshal.SizeOf(info);
            info.fMask = Native.SEE_MASK_INVOKEIDLIST;
            info.hwnd = owner;
            info.lpVerb = "properties";
            info.lpFile = path;
            info.nShow = 5;  // SW_SHOW
            if (!Native.ShellExecuteEx(ref info)) throw new Win32Exception();
        }

        // Asks the shell to recycle the item. The shell warns on its own if the item is too big for the
        // Recycle Bin and would be deleted for good. Returns true when the item is gone afterwards.
        public static bool MoveToRecycleBin(string path, IntPtr owner)
        {
            const ushort flags = Native.FOF_ALLOWUNDO | Native.FOF_NOCONFIRMATION | Native.FOF_WANTNUKEWARNING;
            if (IntPtr.Size == 8)
            {
                var op = new Native.SHFILEOPSTRUCT { hwnd = owner, wFunc = Native.FO_DELETE, pFrom = path + "\0", fFlags = flags };
                Native.SHFileOperation(ref op);
            }
            else
            {
                var op = new Native.SHFILEOPSTRUCT32 { hwnd = owner, wFunc = Native.FO_DELETE, pFrom = path + "\0", fFlags = flags };
                Native.SHFileOperation32(ref op);
            }
            return !File.Exists(path) && !Directory.Exists(path);
        }
    }
}

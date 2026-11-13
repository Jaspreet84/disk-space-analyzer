using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

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

        // ---- Open at line (Protect's content findings)

        // Opens path in a known text editor at line and column. The editor is the program the extension is
        // associated with when that is VS Code, Notepad++, Sublime Text or Notepad; otherwise (and for .env and
        // extensionless files) VS Code on PATH, then Notepad. The default verb is never used, so a .js, .vbs,
        // .ps1, .bat, .cmd or .py association cannot run the file. Returns false, launching nothing, when no
        // known editor is found.
        public static bool OpenAt(string path, int line, int column)
        {
            string exe = EditorFor(path);
            if (exe == null) return false;
            if (line < 1) line = 1;
            if (column < 1) column = 1;
            string name = Path.GetFileName(exe).ToLowerInvariant();
            string args;
            if (name == "code.exe") args = "--goto \"" + path + ":" + line + ":" + column + "\"";
            else if (name == "notepad++.exe") args = "-n" + line + " -c" + column + " \"" + path + "\"";
            else if (name == "sublime_text.exe") args = "\"" + path + ":" + line + ":" + column + "\"";
            else args = "\"" + path + "\"";
            Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false });
            return true;
        }

        // Whether OpenAt would find an editor for this file. Cached by extension for the session.
        public static bool CanOpenAt(string path)
        {
            return EditorFor(path) != null;
        }

        static readonly Dictionary<string, string> editors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static readonly object editorLock = new object();
        static string fallback;
        static bool fallbackDone;

        static string EditorFor(string path)
        {
            string ext = "";
            try { ext = Path.GetExtension(path ?? "") ?? ""; }
            catch (ArgumentException) { ext = ""; }
            if (ext.Equals(".env", StringComparison.OrdinalIgnoreCase)) ext = "";
            lock (editorLock)
            {
                string exe;
                if (editors.TryGetValue(ext, out exe)) return exe;
                exe = ext.Length > 0 ? KnownEditor(Associated(ext)) : null;
                if (exe == null) exe = Fallback();
                editors[ext] = exe;
                return exe;
            }
        }

        static string KnownEditor(string exe)
        {
            if (string.IsNullOrEmpty(exe)) return null;
            string name;
            try { name = Path.GetFileName(exe).ToLowerInvariant(); }
            catch (ArgumentException) { return null; }
            if (name != "code.exe" && name != "notepad++.exe" && name != "sublime_text.exe" && name != "notepad.exe") return null;
            return File.Exists(exe) ? exe : null;
        }

        // VS Code on PATH (its bin folder holds code.cmd, with Code.exe one level up), then Notepad.
        static string Fallback()
        {
            if (fallbackDone) return fallback;
            fallbackDone = true;
            string pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string raw in pathVar.Split(';'))
            {
                string dir = raw.Trim().Trim('"');
                if (dir.Length == 0) continue;
                try
                {
                    string direct = Path.Combine(dir, "Code.exe");
                    if (File.Exists(direct)) { fallback = direct; return fallback; }
                    string parent = Path.GetDirectoryName(dir.TrimEnd('\\'));
                    if (parent != null && File.Exists(Path.Combine(dir, "code.cmd")) && File.Exists(Path.Combine(parent, "Code.exe")))
                    {
                        fallback = Path.Combine(parent, "Code.exe");
                        return fallback;
                    }
                }
                catch (ArgumentException) { }
                catch (IOException) { }
            }
            string notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
            fallback = File.Exists(notepad) ? notepad : null;
            return fallback;
        }

        // The program the shell would use for this extension, from AssocQueryString (no default verb is run).
        static string Associated(string ext)
        {
            try
            {
                uint size = 1024;
                var sb = new StringBuilder((int)size);
                int hr = AssocQueryString(ASSOCF_NONE, ASSOCSTR_EXECUTABLE, ext, null, sb, ref size);
                if (hr != 0) return null;
                string exe = sb.ToString();
                return exe.Length == 0 ? null : Environment.ExpandEnvironmentVariables(exe);
            }
            catch (Exception) { return null; }
        }

        const uint ASSOCF_NONE = 0;
        const uint ASSOCSTR_EXECUTABLE = 2;

        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, EntryPoint = "AssocQueryStringW")]
        static extern int AssocQueryString(uint flags, uint str, string pszAssoc, string pszExtra, StringBuilder pszOut, ref uint pcchOut);
    }
}

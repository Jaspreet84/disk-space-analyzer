using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace DiskSpace
{
    // Shared between the worker and the UI, which reads it on a timer.
    sealed class TransferProgress
    {
        public long TotalBytes, DoneBytes;
        public int TotalFiles, DoneFiles;
        public volatile string Phase = "", Current = "";
    }

    // A file that didn't copy, or whose copy doesn't match. Path is relative to the copied folder ("" for a single file).
    sealed class TransferProblem
    {
        public string Path, Name, Message;

        public override string ToString()
        {
            return Name + ": " + Message;
        }
    }

    // Copies a file or folder to another drive and then checks the copy byte for byte.
    static class Transfer
    {
        const int Chunk = 8 << 20;  // a multiple of every sector size, as unbuffered reads require
        const uint COPY_FILE_NO_BUFFERING = 0x1000;
        const uint PROGRESS_CONTINUE = 0, PROGRESS_CANCEL = 1;
        const int ERROR_REQUEST_ABORTED = 1235;

        delegate uint CopyProgressRoutine(long totalFileSize, long totalBytesTransferred, long streamSize, long streamBytesTransferred,
            uint streamNumber, uint callbackReason, IntPtr sourceFile, IntPtr destinationFile, IntPtr data);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CopyFileExW(string existing, string destination, CopyProgressRoutine progress, IntPtr data, ref int cancel, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadFile(SafeFileHandle h, IntPtr buffer, int toRead, out int read, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int memcmp(IntPtr a, IntPtr b, UIntPtr count);

        [DllImport("kernel32.dll")]
        static extern uint SetThreadExecutionState(uint flags);

        // Keeps the PC from sleeping while a long copy runs on the calling thread.
        public static void StayAwake(bool on)
        {
            const uint ES_CONTINUOUS = 0x80000000, ES_SYSTEM_REQUIRED = 0x1;
            SetThreadExecutionState(on ? ES_CONTINUOUS | ES_SYSTEM_REQUIRED : ES_CONTINUOUS);
        }

        // Relative paths and sizes of everything to copy. A single file is listed with an empty relative path.
        static List<KeyValuePair<string, long>> List(string source, List<string> folders)
        {
            var files = new List<KeyValuePair<string, long>>();
            string root = Scanner.LongPath(source);
            if (File.Exists(root))
            {
                files.Add(new KeyValuePair<string, long>("", new FileInfo(root).Length));
                return files;
            }
            foreach (string d in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
                folders.Add(d.Substring(root.Length + 1));
            foreach (string f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                files.Add(new KeyValuePair<string, long>(f.Substring(root.Length + 1), new FileInfo(f).Length));
            return files;
        }

        static string Join(string root, string relative)
        {
            return Scanner.LongPath(relative.Length == 0 ? root : Path.Combine(root, relative));
        }

        // Copies source to destination. Files already there with the same size and date are kept, so an interrupted
        // copy picks up where it stopped, except those in recopy (files a check found different). Returns the files
        // that could not be copied.
        public static List<TransferProblem> Copy(string source, string destination, TransferProgress p, CancellationToken cancel,
            HashSet<string> recopy)
        {
            var problems = new List<TransferProblem>();
            var folders = new List<string>();
            List<KeyValuePair<string, long>> files = List(source, folders);
            p.Phase = "Copying";
            p.TotalFiles = files.Count;
            p.DoneFiles = 0;
            p.DoneBytes = 0;
            p.TotalBytes = 0;
            foreach (var f in files) p.TotalBytes += f.Value;

            bool single = files.Count == 1 && files[0].Key.Length == 0;
            Directory.CreateDirectory(Scanner.LongPath(single ? Path.GetDirectoryName(destination) : destination));
            foreach (string d in folders) Directory.CreateDirectory(Join(destination, d));

            foreach (var f in files)
            {
                if (cancel.IsCancellationRequested) break;
                string from = Join(source, f.Key), to = Join(destination, f.Key);
                p.Current = single ? Path.GetFileName(source) : f.Key;
                long before = p.DoneBytes;
                if ((recopy != null && recopy.Contains(f.Key)) || !AlreadyCopied(from, to, f.Value))
                {
                    int cancelFlag = 0;
                    CopyProgressRoutine progress = (total, transferred, streamSize, streamDone, stream, reason, src, dst, data) =>
                    {
                        p.DoneBytes = before + transferred;
                        return cancel.IsCancellationRequested ? PROGRESS_CANCEL : PROGRESS_CONTINUE;
                    };
                    uint flags = f.Value >= (64 << 20) ? COPY_FILE_NO_BUFFERING : 0;
                    if (!CopyFileExW(from, to, progress, IntPtr.Zero, ref cancelFlag, flags))
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == ERROR_REQUEST_ABORTED) break;
                        problems.Add(new TransferProblem
                        {
                            Path = f.Key,
                            Name = f.Key.Length == 0 ? Path.GetFileName(source) : f.Key,
                            Message = new System.ComponentModel.Win32Exception(error).Message
                        });
                    }
                    GC.KeepAlive(progress);
                }
                p.DoneBytes = before + f.Value;
                p.DoneFiles++;
            }

            // Folders get their dates last, since copying files into them changes them.
            for (int i = folders.Count - 1; i >= 0 && !cancel.IsCancellationRequested; i--)
            {
                try { Directory.SetLastWriteTimeUtc(Join(destination, folders[i]), Directory.GetLastWriteTimeUtc(Join(source, folders[i]))); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            return problems;
        }

        static bool AlreadyCopied(string from, string to, long length)
        {
            var target = new FileInfo(to);
            if (!target.Exists || target.Length != length) return false;
            return Math.Abs((target.LastWriteTimeUtc - new FileInfo(from).LastWriteTimeUtc).TotalSeconds) <= 2;
        }

        // Compares every file with its copy. Reads bypass the Windows file cache, so a freshly written copy is
        // checked as it is on the disk. Returns a description of each file that is missing or different.
        public static List<TransferProblem> Verify(string source, string destination, TransferProgress p, CancellationToken cancel)
        {
            var problems = new List<TransferProblem>();
            List<KeyValuePair<string, long>> files = List(source, new List<string>());
            p.Phase = "Checking";
            p.TotalFiles = files.Count;
            p.DoneFiles = 0;
            p.DoneBytes = 0;
            p.TotalBytes = 0;
            foreach (var f in files) p.TotalBytes += f.Value;

            IntPtr a = VirtualAlloc(IntPtr.Zero, (UIntPtr)Chunk, 0x3000, 0x04), b = VirtualAlloc(IntPtr.Zero, (UIntPtr)Chunk, 0x3000, 0x04);
            try
            {
                foreach (var f in files)
                {
                    if (cancel.IsCancellationRequested) break;
                    string name = f.Key.Length == 0 ? Path.GetFileName(source) : f.Key;
                    p.Current = name;
                    long before = p.DoneBytes;
                    string status;
                    try { status = Compare(Join(source, f.Key), Join(destination, f.Key), f.Value, a, b, p, before, cancel); }
                    catch (Exception ex) { status = ex.Message; }
                    if (status != null) problems.Add(new TransferProblem { Path = f.Key, Name = name, Message = status });
                    p.DoneBytes = before + f.Value;
                    p.DoneFiles++;
                }
            }
            finally
            {
                VirtualFree(a, UIntPtr.Zero, 0x8000);
                VirtualFree(b, UIntPtr.Zero, 0x8000);
            }
            return problems;
        }

        static string Compare(string source, string copy, long length, IntPtr a, IntPtr b, TransferProgress p, long before, CancellationToken cancel)
        {
            var info = new FileInfo(copy);
            if (!info.Exists) return "missing from the copy";
            if (info.Length != length) return "the copy has a different size";
            using (SafeFileHandle hs = Open(source))
            using (SafeFileHandle hd = Open(copy))
            {
                if (hs.IsInvalid) return "couldn't read the original";
                if (hd.IsInvalid) return "couldn't read the copy";
                long done = 0;
                while (!cancel.IsCancellationRequested)
                {
                    // The original and the copy are on different disks, so read both at once.
                    int ra = 0, rb;
                    bool okA = false;
                    Task t = Task.Run(() => { okA = ReadFile(hs, a, Chunk, out ra, IntPtr.Zero); });
                    bool okB = ReadFile(hd, b, Chunk, out rb, IntPtr.Zero);
                    t.Wait();
                    if (!okA) return "couldn't read the original";
                    if (!okB) return "couldn't read the copy";
                    if (ra != rb) return "the copy is different";
                    if (ra == 0) return null;
                    if (memcmp(a, b, (UIntPtr)ra) != 0) return "the copy is different";
                    done += ra;
                    p.DoneBytes = before + done;
                }
                return null;
            }
        }

        static SafeFileHandle Open(string path)
        {
            const uint GENERIC_READ = 0x80000000, SHARE_READ = 1, OPEN_EXISTING = 3, NO_BUFFERING = 0x20000000, SEQUENTIAL_SCAN = 0x08000000;
            return CreateFileW(path, GENERIC_READ, SHARE_READ, IntPtr.Zero, OPEN_EXISTING, NO_BUFFERING | SEQUENTIAL_SCAN, IntPtr.Zero);
        }
    }
}

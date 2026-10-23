using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using System.Threading.Tasks;

namespace DiskSpace
{
    // Walks a folder tree with FindFirstFileEx (large fetch, no 8.3 names) and reads the first few
    // levels of branches in parallel. The public counters can be read from another thread mid-scan.
    sealed class Scanner
    {
        public long FilesFound, FoldersFound, BytesFound;
        public volatile string CurrentFolder = "";

        const int ParallelDepth = 4;
        const uint NameSurrogateTag = 0x20000000;  // set on junctions, mount points and symbolic links
        const uint OnlineOnlyAttributes = Native.FILE_ATTRIBUTE_OFFLINE | Native.FILE_ATTRIBUTE_RECALL_ON_OPEN |
                                          Native.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        const uint PackedAttributes = Native.FILE_ATTRIBUTE_COMPRESSED | Native.FILE_ATTRIBUTE_SPARSE_FILE;

        static readonly int Workers = Math.Max(4, Environment.ProcessorCount);

        CancellationToken cancel;
        ParallelOptions parallel;
        long onlineOnlyBytes, onlineOnlyFiles;
        int unreadable;
        readonly List<string> problems = new List<string>();

        public ScanResult Scan(string path, CancellationToken token)
        {
            Start(token);
            path = NormalizePath(path);
            var clock = Stopwatch.StartNew();
            DirNode root = ScanFolder(path, path, null, 0, 0);
            if (token.IsCancellationRequested) return null;

            var r = new ScanResult();
            r.Root = root;
            r.Elapsed = clock.Elapsed;
            r.OnlineOnlyBytes = onlineOnlyBytes;
            r.OnlineOnlyFiles = onlineOnlyFiles;
            r.UnreadableCount = unreadable;
            r.Problems = problems;
            r.IsDriveRoot = IsVolumeRoot(path);
            ulong available, total, free;
            if (Native.GetDiskFreeSpaceExW(path, out available, out total, out free))
            {
                r.DriveTotal = (long)total;
                r.DriveFree = (long)free;
            }
            if (r.IsDriveRoot && r.DriveTotal > 0) AddUnaccounted(r);
            return r;
        }

        // Rescans one folder of an existing tree. Returns null if cancelled.
        public DirNode Rescan(DirNode folder, CancellationToken token)
        {
            Start(token);
            DirNode fresh = ScanFolder(folder.FullPath, folder.Name, folder.Parent, 0, 0);
            return token.IsCancellationRequested ? null : fresh;
        }

        void Start(CancellationToken token)
        {
            cancel = token;
            parallel = new ParallelOptions { MaxDegreeOfParallelism = Workers };
            // Folder listing mostly waits on the disk, so let the pool start enough threads right away.
            int worker, io;
            ThreadPool.GetMinThreads(out worker, out io);
            if (worker < Workers * 2) ThreadPool.SetMinThreads(Workers * 2, io);
        }

        public static string NormalizePath(string path)
        {
            path = path.Trim().Trim('"');
            if (path.Length == 2 && path[1] == ':') path += "\\";
            path = Path.GetFullPath(path);
            string root = Path.GetPathRoot(path);
            if (path.Length > root.Length) path = path.TrimEnd('\\');
            if (path.Length >= 2 && path[1] == ':') path = char.ToUpperInvariant(path[0]) + path.Substring(1);
            return path;
        }

        public static bool IsVolumeRoot(string path)
        {
            string root = Path.GetPathRoot(path);
            return root != null && string.Equals(root.TrimEnd('\\'), path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        // Used space on the drive that the scan did not find in any file: protected folders, NTFS metadata,
        // shadow copies and cluster rounding. Shown as its own item so the drive's numbers add up.
        static void AddUnaccounted(ScanResult r)
        {
            DirNode root = r.Root;
            long missing = (r.DriveTotal - r.DriveFree) - root.Size;
            if (missing <= 0) return;
            var unaccounted = new DirNode { Name = "<Unaccounted space>", Parent = root, Size = missing, Unaccounted = true };
            var kids = new List<Node>(root.Children);
            kids.Add(unaccounted);
            root.Children = kids.ToArray();
            Array.Sort(root.Children, Node.CompareBySize);
            root.Size += missing;
        }

        DirNode ScanFolder(string path, string name, DirNode parent, long ownWrite, int depth)
        {
            var node = new DirNode { Name = name, Parent = parent, LastWrite = ownWrite };
            CurrentFolder = path;

            var files = new List<Node>();
            string appDataLeaf = AppDataLeaf(path);
            List<string> subNames = null;
            List<long> subWrites = null;
            long fileBytes = 0, cloudBytes = 0, cloudFiles = 0;

            Native.WIN32_FIND_DATA fd;
            IntPtr h = Native.FindFirstFileExW(SearchPattern(path), Native.FindExInfoBasic, out fd, 0, IntPtr.Zero,
                Native.FIND_FIRST_EX_LARGE_FETCH);
            if (h == Native.INVALID_HANDLE_VALUE)
            {
                int error = Marshal.GetLastWin32Error();
                // An empty drive root has no "." entry, so "file not found" there just means empty.
                if (error != Native.ERROR_FILE_NOT_FOUND)
                {
                    node.Unreadable = true;
                    Problem(path, error);
                }
                Interlocked.Increment(ref FoldersFound);
                return node;
            }
            try
            {
                do
                {
                    if (cancel.IsCancellationRequested) return node;
                    string fileName = fd.cFileName;
                    uint attributes = fd.dwFileAttributes;
                    long written = ((long)fd.ftLastWriteTimeHigh << 32) | fd.ftLastWriteTimeLow;
                    if ((attributes & Native.FILE_ATTRIBUTE_DIRECTORY) != 0)
                    {
                        if (fileName == "." || fileName == "..") continue;
                        // Junctions and symbolic links point at folders that live elsewhere; following them would
                        // count that space twice. Other reparse points (OneDrive folders, for one) are real folders.
                        if ((attributes & Native.FILE_ATTRIBUTE_REPARSE_POINT) != 0 && (fd.dwReserved0 & NameSurrogateTag) != 0)
                            continue;
                        if (appDataLeaf != null && IsRedirected(Join(path, fileName), appDataLeaf, fileName))
                            continue;
                        if (subNames == null)
                        {
                            subNames = new List<string>();
                            subWrites = new List<long>();
                        }
                        subNames.Add(fileName);
                        subWrites.Add(written);
                        continue;
                    }

                    var file = new FileNode { Name = fileName, Parent = node, LastWrite = written };
                    long size = ((long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                    if ((attributes & OnlineOnlyAttributes) != 0)
                    {
                        // Cloud placeholders report their full size but keep no data on this PC.
                        file.Flags = FileFlags.OnlineOnly;
                        cloudBytes += size;
                        cloudFiles++;
                        size = 0;
                    }
                    else if ((attributes & PackedAttributes) != 0)
                    {
                        uint high;
                        uint low = Native.GetCompressedFileSizeW(LongPath(Join(path, fileName)), out high);
                        if (low != Native.INVALID_FILE_SIZE || Marshal.GetLastWin32Error() == 0)
                        {
                            size = ((long)high << 32) | low;
                            file.Flags = FileFlags.Compressed;
                        }
                    }
                    file.Size = size;
                    fileBytes += size;
                    files.Add(file);
                } while (Native.FindNextFileW(h, out fd));
            }
            finally
            {
                Native.FindClose(h);
            }

            Interlocked.Add(ref FilesFound, files.Count);
            Interlocked.Add(ref BytesFound, fileBytes);
            Interlocked.Increment(ref FoldersFound);
            if (cloudFiles > 0)
            {
                Interlocked.Add(ref onlineOnlyBytes, cloudBytes);
                Interlocked.Add(ref onlineOnlyFiles, cloudFiles);
            }

            DirNode[] subs = null;
            if (subNames != null)
            {
                subs = new DirNode[subNames.Count];
                if (depth < ParallelDepth && subs.Length > 1)
                {
                    Parallel.For(0, subs.Length, parallel, i =>
                    {
                        subs[i] = ScanFolder(Join(path, subNames[i]), subNames[i], node, subWrites[i], depth + 1);
                    });
                }
                else
                {
                    for (int i = 0; i < subs.Length; i++)
                        subs[i] = ScanFolder(Join(path, subNames[i]), subNames[i], node, subWrites[i], depth + 1);
                }
            }

            var kids = new Node[files.Count + (subs == null ? 0 : subs.Length)];
            files.CopyTo(kids);
            long total = fileBytes, fileCount = files.Count, dirCount = 0, newest = ownWrite;
            foreach (Node f in files)
                if (f.LastWrite > newest) newest = f.LastWrite;
            if (subs != null)
            {
                for (int i = 0; i < subs.Length; i++)
                {
                    DirNode s = subs[i];
                    kids[files.Count + i] = s;
                    total += s.Size;
                    fileCount += s.FileCount;
                    dirCount += 1 + s.DirCount;
                    if (s.LastWrite > newest) newest = s.LastWrite;
                }
            }
            Array.Sort(kids, Node.CompareBySize);
            node.Children = kids;
            node.Size = total;
            node.FileCount = fileCount;
            node.DirCount = dirCount;
            node.LastWrite = newest;
            return node;
        }

        // Packaged (MSIX) apps such as Claude get folders like AppData\Roaming\Claude mapped onto their package's
        // LocalCache folder. Windows does this with a filter driver, so the folder is not marked as a link, and the
        // same files would be counted twice. Only the AppData folders themselves are checked, because asking for a
        // folder's real location means opening it, which is too slow to do for every folder.
        static string AppDataLeaf(string path)
        {
            foreach (string leaf in new[] { "Roaming", "Local", "LocalLow" })
                if (path.EndsWith(@"\AppData\" + leaf, StringComparison.OrdinalIgnoreCase)) return leaf;
            return null;
        }

        static bool IsRedirected(string folder, string appDataLeaf, string name)
        {
            using (SafeFileHandle h = Native.CreateFileW(LongPath(folder), 0, Native.FILE_SHARE_ALL, IntPtr.Zero,
                       Native.OPEN_EXISTING, Native.FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero))
            {
                if (h.IsInvalid) return false;
                var final = new StringBuilder(1024);
                uint length = Native.GetFinalPathNameByHandleW(h, final, (uint)final.Capacity, 0);
                if (length == 0 || length >= final.Capacity) return false;
                // Compare only the tail, so short (8.3) names earlier in the path cannot cause a false match.
                string tail = @"\AppData\" + appDataLeaf + @"\" + name;
                return !final.ToString().TrimEnd('\\').EndsWith(tail, StringComparison.OrdinalIgnoreCase);
            }
        }

        void Problem(string path, int error)
        {
            Interlocked.Increment(ref unreadable);
            lock (problems)
            {
                if (problems.Count < ScanResult.ProblemsKept)
                    problems.Add(path + "  (" + new Win32Exception(error).Message + ")");
            }
        }

        static string Join(string folder, string name)
        {
            return folder.EndsWith("\\", StringComparison.Ordinal) ? folder + name : folder + "\\" + name;
        }

        // The \\?\ prefix lifts the 260-character path limit.
        public static string LongPath(string path)
        {
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + path.Substring(2);
            return @"\\?\" + path;
        }

        static string SearchPattern(string folder)
        {
            return LongPath(folder.TrimEnd('\\')) + @"\*";
        }
    }
}

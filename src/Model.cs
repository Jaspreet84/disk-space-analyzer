using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;

namespace DiskSpace
{
    abstract class Node
    {
        public string Name;
        public DirNode Parent;
        public long Size;       // bytes this item takes up on disk
        public long LastWrite;  // newest modification time at or below this item, as a UTC FILETIME

        public string FullPath
        {
            get
            {
                if (Parent == null) return Name;
                string p = Parent.FullPath;
                return p.EndsWith("\\", StringComparison.Ordinal) ? p + Name : p + "\\" + Name;
            }
        }

        public bool IsUnder(DirNode ancestor)
        {
            for (Node n = this; n != null; n = n.Parent)
                if (n == ancestor) return true;
            return false;
        }

        // Largest first; ties are broken by name so the order is stable between runs.
        public static int CompareBySize(Node a, Node b)
        {
            int c = b.Size.CompareTo(a.Size);
            return c != 0 ? c : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        }
    }

    sealed class DirNode : Node
    {
        public static readonly Node[] NoChildren = new Node[0];

        public Node[] Children = NoChildren;  // sorted with CompareBySize
        public long FileCount;                // files anywhere below this folder
        public long DirCount;                 // folders anywhere below this folder
        public bool Unreadable;               // the folder could not be listed, usually because access was denied
        public bool Unaccounted;              // stand-in for used drive space that no scanned file explains
    }

    [Flags]
    enum FileFlags : byte { None = 0, OnlineOnly = 1, Compressed = 2 }

    sealed class FileNode : Node
    {
        public FileFlags Flags;
        public int Ext;  // index into ScanResult.Extensions, assigned by Analyze()
    }

    enum Category { Video, Images, Audio, Archives, Documents, Code, Programs, System, Other, Unaccounted }

    static class Categories
    {
        public const int Count = 10;
        public const string NoExtension = "(no extension)";

        public static readonly string[] Names =
        {
            "Video", "Images", "Audio", "Archives & disk images", "Documents", "Code & data",
            "Programs & libraries", "System, logs & temp", "Other", "Unaccounted"
        };

        // The eight categorical slots of the reference data-viz palette, in its validated order,
        // then neutral inks for "other" and for space the scan could not attribute.
        public static readonly Color[] Colors =
        {
            Hex(0x2a78d6), Hex(0xeb6834), Hex(0x1baf7a), Hex(0xeda100), Hex(0xe87ba4),
            Hex(0x008300), Hex(0x6250d6), Hex(0xe34948), Hex(0x898781), Hex(0x52514e)
        };

        // Used for folders too small to subdivide in the treemap, and for dimmed items.
        public static readonly Color SmallItems = Hex(0xc3c2b7);
        public static readonly Color Dimmed = Hex(0xe1e0d9);

        static readonly Dictionary<string, Category> byKey = new Dictionary<string, Category>(StringComparer.OrdinalIgnoreCase);

        // Files that are big enough and well known enough to be listed under their own name.
        static readonly HashSet<string> namedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "pagefile.sys", "hiberfil.sys", "swapfile.sys", "memory.dmp"
        };

        static Categories()
        {
            Add(Category.Video, ".mp4 .mkv .avi .mov .wmv .webm .m4v .mpg .mpeg .flv .m2ts .mts .vob .3gp");
            Add(Category.Images, ".jpg .jpeg .png .gif .bmp .tif .tiff .webp .heic .heif .raw .cr2 .cr3 .nef .arw .dng .psd .svg .ico .xcf .ai");
            Add(Category.Audio, ".mp3 .wav .flac .aac .m4a .ogg .opus .wma .aif .aiff .mid .midi");
            Add(Category.Archives, ".zip .7z .rar .tar .gz .tgz .bz2 .xz .zst .iso .img .vhd .vhdx .avhdx .vmdk .vdi .qcow2 .cab .wim .esd .dmg");
            Add(Category.Documents, ".pdf .doc .docx .xls .xlsx .ppt .pptx .odt .ods .odp .rtf .txt .md .epub .csv .one .pst .ost .msg .eml");
            Add(Category.Code, ".js .mjs .cjs .ts .tsx .jsx .py .pyc .pyd .java .class .cs .go .rs .c .h .cpp .hpp .json .xml .yaml .yml " +
                ".html .htm .css .scss .sql .db .sqlite .sqlite3 .mdb .accdb .mdf .ldf .parquet .pack .idx .map .wasm .whl .nupkg .ipynb");
            Add(Category.Programs, ".exe .dll .sys .msi .msix .msixbundle .appx .appxbundle .msp .ocx .so .lib .a .pdb .jar .apk .node .mui .drv");
            Add(Category.System, ".tmp .temp .log .etl .dmp .mdmp .hdmp .evtx .cache .bak .old .chk .wer .blf .regtrans-ms " +
                "pagefile.sys hiberfil.sys swapfile.sys memory.dmp");
        }

        static void Add(Category category, string keys)
        {
            foreach (string key in keys.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                byKey[key] = category;
        }

        // The key a file is grouped under: its lower-case extension, or its whole name for a few notable system files.
        public static string KeyFor(string fileName)
        {
            if (namedFiles.Contains(fileName)) return fileName.ToLowerInvariant();
            int dot = fileName.LastIndexOf('.');
            if (dot < 0 || dot == fileName.Length - 1 || fileName.Length - dot > 12) return NoExtension;
            string ext = fileName.Substring(dot).ToLowerInvariant();
            return ext.IndexOf(' ') >= 0 ? NoExtension : ext;
        }

        public static Category ForKey(string key)
        {
            Category c;
            return byKey.TryGetValue(key, out c) ? c : Category.Other;
        }

        static Color Hex(int rgb)
        {
            return Color.FromArgb(255, (rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255);
        }
    }

    sealed class ExtInfo
    {
        public readonly string Key;
        public readonly Category Category;
        public readonly int Index;
        public long Size;
        public long Count;

        public ExtInfo(string key, Category category, int index)
        {
            Key = key;
            Category = category;
            Index = index;
        }
    }

    sealed class ScanResult
    {
        public const int LargestFilesKept = 1000;
        public const int ProblemsKept = 1000;

        public DirNode Root;
        public TimeSpan Elapsed;
        public long DriveTotal, DriveFree;  // 0 when unknown
        public bool IsDriveRoot;
        public long OnlineOnlyBytes, OnlineOnlyFiles;
        public int UnreadableCount;
        public List<string> Problems = new List<string>();

        // Filled in by Analyze().
        public List<ExtInfo> Extensions = new List<ExtInfo>();
        public long[] CategoryBytes = new long[Categories.Count];
        public long[] CategoryFiles = new long[Categories.Count];
        public List<FileNode> LargestFiles = new List<FileNode>();
        public List<FileNode>[] LargestByCategory = new List<FileNode>[Categories.Count];

        // The node at a full path, or null if the path is not part of this scan.
        public Node FindNode(string path)
        {
            string rootPath = Root.FullPath;
            if (!path.StartsWith(rootPath, StringComparison.OrdinalIgnoreCase)) return null;
            string rest = path.Substring(rootPath.Length);
            if (rest.Length > 0 && !rootPath.EndsWith("\\", StringComparison.Ordinal) && rest[0] != '\\') return null;
            Node n = Root;
            foreach (string part in rest.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var dir = n as DirNode;
                if (dir == null) return null;
                Node next = null;
                foreach (Node child in dir.Children)
                {
                    if (string.Equals(child.Name, part, StringComparison.OrdinalIgnoreCase))
                    {
                        next = child;
                        break;
                    }
                }
                if (next == null) return null;
                n = next;
            }
            return n;
        }

        // Bytes per category below one folder (the whole scan uses CategoryBytes instead).
        public long[] CategoryBytesUnder(DirNode folder)
        {
            if (folder == Root) return CategoryBytes;
            var bytes = new long[Categories.Count];
            var stack = new Stack<DirNode>();
            stack.Push(folder);
            while (stack.Count > 0)
            {
                DirNode d = stack.Pop();
                if (d.Unaccounted)
                {
                    bytes[(int)Category.Unaccounted] += d.Size;
                    continue;
                }
                foreach (Node child in d.Children)
                {
                    var sub = child as DirNode;
                    if (sub != null) stack.Push(sub);
                    else
                    {
                        var f = (FileNode)child;
                        if (f.Ext < Extensions.Count) bytes[(int)Extensions[f.Ext].Category] += f.Size;
                    }
                }
            }
            return bytes;
        }

        public DirNode UnaccountedNode
        {
            get
            {
                foreach (Node n in Root.Children)
                {
                    var d = n as DirNode;
                    if (d != null && d.Unaccounted) return d;
                }
                return null;
            }
        }

        // One pass over every file: groups them by extension and category and keeps the largest ones.
        public void Analyze()
        {
            var keys = new Dictionary<string, int>(StringComparer.Ordinal);
            var exts = new List<ExtInfo>();
            var categoryBytes = new long[Categories.Count];
            var categoryFiles = new long[Categories.Count];
            var heap = new List<FileNode>(LargestFilesKept + 1);
            var heaps = new List<FileNode>[Categories.Count];
            for (int c = 0; c < heaps.Length; c++) heaps[c] = new List<FileNode>();
            var stack = new Stack<DirNode>();
            stack.Push(Root);
            while (stack.Count > 0)
            {
                DirNode dir = stack.Pop();
                if (dir.Unaccounted)
                {
                    categoryBytes[(int)Category.Unaccounted] += dir.Size;
                    continue;
                }
                foreach (Node child in dir.Children)
                {
                    var sub = child as DirNode;
                    if (sub != null)
                    {
                        stack.Push(sub);
                        continue;
                    }
                    var file = (FileNode)child;
                    string key = Categories.KeyFor(file.Name);
                    int index;
                    if (!keys.TryGetValue(key, out index))
                    {
                        index = exts.Count;
                        keys.Add(key, index);
                        exts.Add(new ExtInfo(key, Categories.ForKey(key), index));
                    }
                    file.Ext = index;
                    ExtInfo ext = exts[index];
                    ext.Size += file.Size;
                    ext.Count++;
                    categoryBytes[(int)ext.Category] += file.Size;
                    categoryFiles[(int)ext.Category]++;
                    OfferLargest(heap, file, LargestFilesKept);
                    OfferLargest(heaps[(int)ext.Category], file, LargestPerCategoryKept);
                }
            }
            heap.Sort(Node.CompareBySize);
            foreach (List<FileNode> h in heaps) h.Sort(Node.CompareBySize);
            Extensions = exts;
            CategoryBytes = categoryBytes;
            CategoryFiles = categoryFiles;
            LargestFiles = heap;
            LargestByCategory = heaps;
        }

        public const int LargestPerCategoryKept = 500;

        // Min-heap on size, so the smallest of the kept files is always at the top and cheap to replace.
        static void OfferLargest(List<FileNode> heap, FileNode file, int keep)
        {
            if (file.Size <= 0) return;
            if (heap.Count < keep)
            {
                heap.Add(file);
                int i = heap.Count - 1;
                while (i > 0)
                {
                    int parent = (i - 1) / 2;
                    if (heap[parent].Size <= heap[i].Size) break;
                    Swap(heap, i, parent);
                    i = parent;
                }
                return;
            }
            if (file.Size <= heap[0].Size) return;
            heap[0] = file;
            int at = 0;
            while (true)
            {
                int left = at * 2 + 1, right = left + 1, smallest = at;
                if (left < heap.Count && heap[left].Size < heap[smallest].Size) smallest = left;
                if (right < heap.Count && heap[right].Size < heap[smallest].Size) smallest = right;
                if (smallest == at) break;
                Swap(heap, at, smallest);
                at = smallest;
            }
        }

        static void Swap(List<FileNode> list, int a, int b)
        {
            FileNode t = list[a];
            list[a] = list[b];
            list[b] = t;
        }

        // Swaps `old` for `replacement` (or removes it when replacement is null), then fixes the totals
        // and sort order of every folder above it and refreshes the per-type figures.
        public void Replace(Node old, Node replacement)
        {
            DirNode parent = old.Parent;
            if (parent == null) throw new InvalidOperationException("The scan root cannot be replaced.");

            long sizeDelta = -old.Size, fileDelta, dirDelta;
            var oldDir = old as DirNode;
            if (oldDir != null) { fileDelta = -oldDir.FileCount; dirDelta = -(1 + oldDir.DirCount); }
            else { fileDelta = -1; dirDelta = 0; }

            var kids = new List<Node>(parent.Children);
            int at = kids.IndexOf(old);
            if (at < 0) return;
            if (replacement == null)
            {
                kids.RemoveAt(at);
            }
            else
            {
                kids[at] = replacement;
                replacement.Parent = parent;
                sizeDelta += replacement.Size;
                var newDir = replacement as DirNode;
                if (newDir != null) { fileDelta += newDir.FileCount; dirDelta += 1 + newDir.DirCount; }
                else fileDelta += 1;
            }
            parent.Children = kids.ToArray();

            for (DirNode p = parent; p != null; p = p.Parent)
            {
                p.Size += sizeDelta;
                p.FileCount += fileDelta;
                p.DirCount += dirDelta;
                Array.Sort(p.Children, Node.CompareBySize);
            }
            Analyze();
        }
    }

    static class Fmt
    {
        static readonly string[] Units = { "KB", "MB", "GB", "TB", "PB" };

        public static string Size(long bytes)
        {
            if (bytes < 1024) return bytes.ToString("N0") + " B";
            double v = bytes;
            int u = -1;
            while (v >= 1024 && u < Units.Length - 1)
            {
                v /= 1024;
                u++;
            }
            return v.ToString(v < 10 ? "0.00" : v < 100 ? "0.0" : "0") + " " + Units[u];
        }

        public static string Count(long n)
        {
            return n.ToString("N0");
        }

        // 1,284 / 12.9K / 4.2M, for stat tiles.
        public static string Compact(long n)
        {
            if (n < 10000) return n.ToString("N0");
            if (n < 1000000) return (n / 1000.0).ToString(n < 100000 ? "0.0" : "0") + "K";
            return (n / 1000000.0).ToString(n < 100000000 ? "0.0" : "0") + "M";
        }

        public static string Ago(DateTime when)
        {
            TimeSpan t = DateTime.Now - when;
            if (t.TotalSeconds < 60) return "just now";
            if (t.TotalMinutes < 60) return (int)t.TotalMinutes + (t.TotalMinutes < 2 ? " minute ago" : " minutes ago");
            if (t.TotalHours < 24) return (int)t.TotalHours + (t.TotalHours < 2 ? " hour ago" : " hours ago");
            return when.ToString("d MMM, HH:mm");
        }

        public static string Percent(long part, long whole)
        {
            return whole <= 0 ? "" : (part * 100.0 / whole).ToString("0.0") + "%";
        }

        public static string Date(long fileTime)
        {
            return Date(fileTime, "yyyy-MM-dd");
        }

        public static string Date(long fileTime, string format)
        {
            if (fileTime <= 0) return "";
            try { return DateTime.FromFileTimeUtc(fileTime).ToLocalTime().ToString(format); }
            catch (ArgumentOutOfRangeException) { return ""; }
        }

        public static string Duration(TimeSpan t)
        {
            if (t.TotalSeconds < 60) return t.TotalSeconds.ToString("0.0") + " s";
            return (int)t.TotalMinutes + " min " + t.Seconds + " s";
        }
    }

    static class Export
    {
        // Writes every folder, largest first within each level, as a CSV that Excel opens directly.
        public static int WriteFolderCsv(DirNode root, string file)
        {
            int rows = 0;
            using (var w = new StreamWriter(file, false, new UTF8Encoding(true)))
            {
                w.WriteLine("Path,Size (bytes),Size,Files,Folders,Last change");
                var stack = new Stack<KeyValuePair<DirNode, string>>();
                stack.Push(new KeyValuePair<DirNode, string>(root, root.Name));
                while (stack.Count > 0)
                {
                    var top = stack.Pop();
                    DirNode d = top.Key;
                    w.WriteLine(string.Join(",", Csv(top.Value), d.Size.ToString(), Csv(Fmt.Size(d.Size)),
                        d.FileCount.ToString(), d.DirCount.ToString(), Fmt.Date(d.LastWrite, "yyyy-MM-dd HH:mm")));
                    rows++;
                    string prefix = top.Value.EndsWith("\\", StringComparison.Ordinal) ? top.Value : top.Value + "\\";
                    for (int i = d.Children.Length - 1; i >= 0; i--)
                    {
                        var sub = d.Children[i] as DirNode;
                        if (sub != null && !sub.Unaccounted)
                            stack.Push(new KeyValuePair<DirNode, string>(sub, prefix + sub.Name));
                    }
                }
            }
            return rows;
        }

        static string Csv(string s)
        {
            return s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        }
    }
}

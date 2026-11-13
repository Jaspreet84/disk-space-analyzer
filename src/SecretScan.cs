using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

// Protect stage 2: the content scan, which runs only when the user turns it on.
//
// It reads small text files picked by Analyze and reports keys with a known format by place and line, never by
// value. The rules this file keeps, which tools\check-trust.ps1 enforces:
//
// - Every call that opens or reads a disk object is in the one marked region below (ContentReader), opened
//   read-only and shared for reading, writing and deleting.
// - The bytes read never become text or a copy. Each worker owns one pinned buffer, cleared after every item.
//   The matcher hands back only three ints per hit: the row, the line and the column.
// - A finding is built in exactly one place, from the pattern table and the candidate.
// - Nothing runs without a ContentConsent, which only the switch in the app or --content on the command line gives.

namespace DiskSpace
{
    // Proof that the user asked for the content scan. There is no other way to get one, and SecretScan refuses to
    // start without it.
    sealed class ContentConsent
    {
        private ContentConsent() { }

        // Null unless the switch on the Protect page is on.
        public static ContentConsent FromStore(ProtectStore s)
        {
            return s != null && s.ContentScan ? new ContentConsent() : null;
        }

        // Null unless --content was passed. Only the command line calls this, and it never changes protect.json.
        internal static ContentConsent FromCommandLine(bool contentFlag)
        {
            return contentFlag ? new ContentConsent() : null;
        }
    }

    // The work of one content scan, fixed on the UI thread before any reading starts.
    sealed class ContentPlan
    {
        public readonly ContentCandidate[] Files;   // largest first, so the large tail is spread across the workers
        public readonly string[] LongPaths;         // parallel to Files, taken on the UI thread
        public readonly long TotalBytes;
        public readonly int TrustedSkipped, TooLarge, OnlineOnly, SkippedFolders;
        public readonly int TrustedFolders;         // how many folders the user trusts, for the consent dialog
        public readonly ScanResult Source;

        internal ContentPlan(ContentCandidate[] files, string[] longPaths, long totalBytes, int trustedSkipped, int tooLarge,
            int onlineOnly, int skippedFolders, int trustedFolders, ScanResult source)
        {
            Files = files;
            LongPaths = longPaths;
            TotalBytes = totalBytes;
            TrustedSkipped = trustedSkipped;
            TooLarge = tooLarge;
            OnlineOnly = onlineOnly;
            SkippedFolders = skippedFolders;
            TrustedFolders = trustedFolders;
            Source = source;
        }
    }

    // Counters of a run. Written with Interlocked by the workers; read them with Interlocked.Read.
    sealed class ContentProgress
    {
        public long TotalFiles, TotalBytes, DoneFiles, ProcessedBytes, BytesRead, FilesOpened;
        public long SkippedBinary, SkippedUtf16, SkippedTooLarge, SkippedEmpty, SkippedUnreadable, SkippedNotDisk;
        public long CappedFiles, FindingCount;
        public readonly Stopwatch Clock;

        public ContentProgress()
        {
            Clock = new Stopwatch();
        }
    }

    sealed class ContentResult
    {
        public readonly List<Finding> Findings;
        public readonly List<Node> Nodes;  // parallel to Findings: the FileNode of each
        public readonly bool Cancelled;

        internal ContentResult(List<Finding> f, List<Node> n, bool cancelled)
        {
            Findings = f;
            Nodes = n;
            Cancelled = cancelled;
        }
    }

    // A run in progress. The UI copies new findings from it on a timer and waits for it off the UI thread.
    sealed class ContentRun
    {
        internal readonly ContentPlan Plan;
        internal readonly ContentProgress Progress;
        internal readonly CancellationToken Token;
        internal readonly object Sync = new object();
        internal readonly List<Finding> Found = new List<Finding>();
        internal readonly List<Node> FoundNodes = new List<Node>();
        internal readonly Thread[] Threads;
        internal int Next;     // the next index into Plan.Files, taken with Interlocked.Increment
        internal int Running;  // workers not finished yet

        internal ContentRun(ContentPlan plan, ContentProgress p, CancellationToken ct, int workers)
        {
            Plan = plan;
            Progress = p;
            Token = ct;
            Threads = new Thread[workers];
            Running = workers;
        }

        // Copies the findings from index `from` on into the two lists, under the run's lock, and returns the new
        // count. Call it again with the returned count to get only the newer ones.
        public int CopyFindings(int from, List<Finding> intoF, List<Node> intoN)
        {
            lock (Sync)
            {
                if (from < 0) from = 0;
                for (int i = from; i < Found.Count; i++)
                {
                    if (intoF != null) intoF.Add(Found[i]);
                    if (intoN != null) intoN.Add(FoundNodes[i]);
                }
                return Found.Count;
            }
        }

        // True once every worker has stopped.
        public bool IsDone
        {
            get { return Thread.VolatileRead(ref Running) == 0; }
        }

        // Blocks until every worker has stopped, then returns all findings. Call it off the UI thread.
        public ContentResult Wait()
        {
            foreach (Thread t in Threads) t.Join();
            Progress.Clock.Stop();
            lock (Sync)
                return new ContentResult(new List<Finding>(Found), new List<Node>(FoundNodes), Token.IsCancellationRequested);
        }
    }

    static class SecretScan
    {
        // ---- Test hooks and counters ----------------------------------------------------------------------

        internal static long openCalls;           // incremented only inside ContentReader, before each open
        internal static long OpenCalls { get { return Interlocked.Read(ref openCalls); } }
        internal static Action<string> OnOpen;    // test hook, null in production
        internal static Action<int> AfterFile;    // test hook: called with the worker index after its buffer is cleared
        internal static byte[][] WorkerBuffers;   // each worker's buffer while it runs, so tests can inspect it

        internal static bool WorkerBuffersClear()
        {
            byte[][] all = WorkerBuffers;
            for (int w = 0; w < all.Length; w++)
            {
                byte[] buf = all[w];
                if (buf == null) continue;
                for (int i = 0; i < buf.Length; i++)
                    if (buf[i] != 0) return false;
            }
            return true;
        }

        // ---- Tables ---------------------------------------------------------------------------------------

        // The content rows, by index: their ids and tiers, taken from ProtectConstants.Patterns.
        static readonly string[] rowIds;
        static readonly FindingTier[] rowTiers;
        const int RowGitHub = 0, RowGitHubFine = 1, RowAws = 2, RowSlack = 3, RowHook = 4, RowStripe = 5, RowGoogle = 6,
                  RowOpenAi = 7, RowPem = 8, RowPemEncrypted = 9, RowEnv = 10;

        // The constant tables below are made with Array.CreateInstance: the only byte array this file allocates
        // with the array syntax is each worker's buffer, which check 4 counts.
        static readonly byte[] PrefixTable;          // first byte of a match -> which row family to try (0 = none)
        static readonly byte[] Base62Alphabet;       // the digits, then upper case, then lower case
        static readonly byte[][] GoogleSampleBytes;  // ProtectConstants.GoogleSampleKeys as bytes
        static readonly uint[] crcTable = new uint[256];
        static readonly uint[] pow62 = new uint[6];
        static readonly ushort[] cls = new ushort[256];

        const int FamGh = 1, FamA = 2, FamX = 3, FamH = 4, FamS = 5, FamR = 6, FamDash = 7;

        // Byte classes, as bits in cls.
        const int Alnum = 1, Url = 2, B64 = 4, B32 = 8, Digit = 16, HexL = 32, UpNum = 64, Word = 128, AwsBefore = 256,
                  AwsAfter = 512, LowWord = 1024, UpWord = 2048;

        static readonly string[] pemLabels =
        {
            "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK", "PRIVATE KEY"
        };
        static readonly string[] pemHeaders = { "Proc-Type:", "DEK-Info:", "Comment:", "Version:" };
        static readonly string[] placeholderWords = { "example", "sample", "dummy", "placeholder", "your", "xxxx" };
        static readonly string[] envLastWords = { "SECRET", "SECRETS", "PASSWORD", "PASSWD", "PASSPHRASE", "TOKEN", "APIKEY", "CREDENTIALS" };
        static readonly string[] envLastPairs =
        {
            "API", "KEY", "SECRET", "KEY", "PRIVATE", "KEY", "ACCESS", "KEY", "SIGNING", "KEY", "ENCRYPTION", "KEY", "MASTER", "KEY",
            "CLIENT", "SECRET", "AUTH", "TOKEN"
        };
        static readonly string[] envPublicPrefixes = { "NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_", "GATSBY_", "NUXT_PUBLIC_" };
        static readonly string[] envPlaceholders =
        {
            "changeme", "change_me", "your_", "your-", "yourkey", "placeholder", "example", "sample", "dummy", "replace", "insert",
            "redacted", "todo", "fixme", "secret_here", "***", "..."
        };
        static readonly string[] envWordValues = { "true", "false", "null", "none" };
        // Values that start like a known format belong to that format's row, which decides them alone.
        static readonly string[] envFormatPrefixes =
        {
            "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "sk_live_", "rk_live_", "sk_test_", "rk_test_", "pk_", "AKIA", "ASIA",
            "AIza", "xox", "xapp-", "sk-", "-----BEGIN"
        };

        static SecretScan()
        {
            WorkerBuffers = (byte[][])Array.CreateInstance(typeof(byte[]), ProtectConstants.ContentWorkers);
            int rows = ProtectConstants.ContentRules.Length;
            rowIds = new string[rows];
            rowTiers = new FindingTier[rows];
            for (int i = 0; i < rows; i++)
            {
                string id = ProtectConstants.ContentRules[i].Id;
                PatternInfo p = ProtectConstants.Pattern(id);
                rowIds[i] = id;
                rowTiers[i] = p != null ? p.Tier : FindingTier.Likely;
            }

            for (uint n = 0; n < 256; n++)
            {
                uint c = n;
                for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                crcTable[n] = c;
            }
            pow62[0] = 1;
            for (int k = 1; k < 6; k++) pow62[k] = pow62[k - 1] * 62;

            Base62Alphabet = Table(62);
            for (int k = 0; k < 10; k++) Base62Alphabet[k] = (byte)('0' + k);
            for (int k = 0; k < 26; k++)
            {
                Base62Alphabet[10 + k] = (byte)('A' + k);
                Base62Alphabet[36 + k] = (byte)('a' + k);
            }

            string[] samples = ProtectConstants.GoogleSampleKeys;
            GoogleSampleBytes = (byte[][])Array.CreateInstance(typeof(byte[]), samples.Length);
            for (int i = 0; i < samples.Length; i++) GoogleSampleBytes[i] = Ascii(samples[i]);

            PrefixTable = Table(256);
            PrefixTable['g'] = FamGh;
            PrefixTable['A'] = FamA;
            PrefixTable['x'] = FamX;
            PrefixTable['h'] = FamH;
            PrefixTable['s'] = FamS;
            PrefixTable['r'] = FamR;
            PrefixTable['-'] = FamDash;

            for (int c = 0; c < 256; c++)
            {
                bool up = c >= 'A' && c <= 'Z', low = c >= 'a' && c <= 'z', dig = c >= '0' && c <= '9';
                int bits = 0;
                if (up || low || dig) bits |= Alnum | Url | B64 | Word | AwsBefore | AwsAfter;
                if (c == '_' || c == '-') bits |= Url | AwsBefore | AwsAfter | LowWord | UpWord;
                if (c == '_') bits |= Word;
                if (c == '+' || c == '/') bits |= B64 | AwsBefore | AwsAfter;
                if (c == '=') bits |= B64 | AwsAfter;
                if (up || (c >= '2' && c <= '7')) bits |= B32;
                if (dig) bits |= Digit;
                if (dig || (c >= 'a' && c <= 'f')) bits |= HexL;
                if (up || dig) bits |= UpNum;
                if (low) bits |= LowWord;
                if (up) bits |= UpWord;
                cls[c] = (ushort)bits;
            }
        }

        static byte[] Table(int n)
        {
            return (byte[])Array.CreateInstance(typeof(byte), n);
        }

        // Vendor constants to bytes, one char at a time. Only ASCII constants pass through here, never content.
        static byte[] Ascii(string s)
        {
            byte[] b = Table(s.Length);
            for (int i = 0; i < s.Length; i++) b[i] = (byte)s[i];
            return b;
        }

        // ---- Checksum -------------------------------------------------------------------------------------

        // CRC-32 (IEEE, reflected), as the GitHub token checksum uses it.
        internal static uint Crc32(byte[] b, int off, int len)
        {
            uint c = 0xFFFFFFFF;
            for (int i = off; i < off + len; i++) c = crcTable[(c ^ b[i]) & 0xFF] ^ (c >> 8);
            return c ^ 0xFFFFFFFF;
        }

        // Whether the 6 bytes at off are v in base62 (digits, upper case, lower case), most significant first,
        // padded with zeros. Each digit is worked out from v and compared in place.
        internal static bool Base62Matches(uint v, byte[] b, int off)
        {
            if (b == null || off < 0 || off + 6 > b.Length) return false;
            for (int k = 5; k >= 0; k--)
                if (b[off + 5 - k] != Base62Alphabet[(v / pow62[k]) % 62]) return false;
            return true;
        }

        internal static int RowIndex(string patternId)
        {
            for (int i = 0; i < rowIds.Length; i++)
                if (rowIds[i] == patternId) return i;
            return -1;
        }

        // ---- Plan -----------------------------------------------------------------------------------------

        // The work for a run, on the UI thread and with no disk access: the candidates Analyze picked, below `under`
        // when it is not null, without the ones in trusted folders, largest first, with their long paths.
        public static ContentPlan Plan(ScanResult r, ProtectStore store, DirNode under)
        {
            if (r == null) throw new ArgumentNullException("r");
            ContentCandidate[] all = r.ContentCandidates ?? new ContentCandidate[0];
            var kept = new List<ContentCandidate>(all.Length);
            int trustedSkipped = 0;
            bool anyTrusted = store != null && store.TrustedCount > 0;
            Dictionary<DirNode, bool> memo = anyTrusted ? new Dictionary<DirNode, bool>() : null;
            for (int i = 0; i < all.Length; i++)
            {
                ContentCandidate c = all[i];
                if (under != null && !c.Node.IsUnder(under)) continue;
                if (anyTrusted && Trusted(c.Node.Parent, store, memo))
                {
                    trustedSkipped++;
                    continue;
                }
                kept.Add(c);
            }

            var order = new int[kept.Count];
            for (int i = 0; i < order.Length; i++) order[i] = i;
            Array.Sort(order, (a, b) =>
            {
                int k = kept[b].Size.CompareTo(kept[a].Size);
                return k != 0 ? k : a.CompareTo(b);
            });
            // Workers take the next item from one shared index, so the largest files go out first, one to each
            // worker in turn, and the small ones fill in behind them.
            var files = new ContentCandidate[order.Length];
            var paths = new string[order.Length];
            long total = 0;
            for (int i = 0; i < order.Length; i++)
            {
                ContentCandidate c = kept[order[i]];
                files[i] = c;
                paths[i] = Scanner.LongPath(c.Node.FullPath);
                total += c.Size;
            }
            return new ContentPlan(files, paths, total, trustedSkipped, r.ContentTooLarge, r.ContentOnlineOnly,
                r.ContentSkippedFolders, store != null ? store.TrustedCount : 0, r);
        }

        // Whether d is in a trusted folder. Each folder is hashed at most once per plan.
        static bool Trusted(DirNode d, ProtectStore store, Dictionary<DirNode, bool> memo)
        {
            if (d == null) return false;
            bool v;
            if (memo.TryGetValue(d, out v)) return v;
            var chain = new List<DirNode>();
            bool result = false;
            for (DirNode n = d; n != null; n = n.Parent)
            {
                if (memo.TryGetValue(n, out v)) { result = v; break; }
                chain.Add(n);
            }
            for (int k = chain.Count - 1; k >= 0; k--)
            {
                DirNode c = chain[k];
                // The topmost folder of the scan also asks about the folders above it.
                if (!result) result = c.Parent == null ? store.IsUnderTrusted(c.FullPath) : store.IsTrusted(c.FullPath);
                memo[c] = result;
            }
            return result;
        }

        // ---- Run ------------------------------------------------------------------------------------------

        // Starts the workers and returns at once. Throws on a null consent before any thread starts.
        public static ContentRun Begin(ContentConsent consent, ContentPlan plan, ContentProgress p, CancellationToken ct)
        {
            if (consent == null) throw new ArgumentNullException("consent");
            if (plan == null) throw new ArgumentNullException("plan");
            if (p == null) throw new ArgumentNullException("p");
            Interlocked.Exchange(ref p.TotalFiles, plan.Files.Length);
            Interlocked.Exchange(ref p.TotalBytes, plan.TotalBytes);
            p.Clock.Start();
            int workers = ProtectConstants.ContentWorkers;
            var run = new ContentRun(plan, p, ct, workers);
            for (int w = 0; w < workers; w++)
            {
                int index = w;
                var t = new Thread(() => Work(index, run));
                t.IsBackground = true;
                t.Name = "Content scan " + index;
                run.Threads[w] = t;
            }
            foreach (Thread t in run.Threads) t.Start();
            return run;
        }

        // Begin, then wait for every worker. It blocks, so the UI calls it inside Task.Run.
        public static ContentResult Run(ContentConsent consent, ContentPlan plan, ContentProgress p, CancellationToken ct)
        {
            return Begin(consent, plan, p, ct).Wait();
        }

        static void Work(int w, ContentRun run)
        {
            ContentReader.Background(true);
            byte[] buf = null;
            GCHandle pin = default(GCHandle);
            ContentProgress p = run.Progress;
            ContentCandidate[] items = run.Plan.Files;
            string[] paths = run.Plan.LongPaths;
            try
            {
                buf = new byte[ProtectConstants.MaxContentBytes];
                pin = GCHandle.Alloc(buf, GCHandleType.Pinned);
                WorkerBuffers[w] = buf;
                IntPtr at = pin.AddrOfPinnedObject();
                int[] triples = new int[3 * ProtectConstants.ContentFindingsPerFile];
                int dirty = 0;
                while (!run.Token.IsCancellationRequested)
                {
                    int k = Interlocked.Increment(ref run.Next) - 1;
                    if (k >= items.Length) break;
                    ContentCandidate cand = items[k];
                    try
                    {
                        Array.Clear(triples, 0, triples.Length);
                        int n = ContentReader.Read(paths[k], buf, at, ref dirty, p);
                        if (n > 0)
                        {
                            int start = n >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF ? 3 : 0;
                            bool capped;
                            int hits = Match(buf, start, n, cand.Kind, triples, out capped);
                            if (capped) Interlocked.Increment(ref p.CappedFiles);
                            EmitFindings(run, cand, triples, hits);
                        }
                        else Skipped(p, n);
                    }
                    catch (Exception)
                    {
                        // The exception is dropped unread: nothing in it may reach a message or a log.
                        Interlocked.Increment(ref p.SkippedUnreadable);
                    }
                    finally
                    {
                        Array.Clear(buf, 0, Math.Min(dirty, buf.Length));
                        dirty = 0;
                        Action<int> hook = AfterFile;
                        if (hook != null) hook(w);
                    }
                    Interlocked.Increment(ref p.DoneFiles);
                    Interlocked.Add(ref p.ProcessedBytes, cand.Size);
                }
            }
            catch (Exception)
            {
                // Out of memory for the buffer, or a thread abort: the run ends early for this worker.
            }
            finally
            {
                if (buf != null) Array.Clear(buf, 0, buf.Length);
                if (pin.IsAllocated) pin.Free();
                // Only this worker's own buffer is taken out of the slot; a later run's worker may hold it now.
                Interlocked.CompareExchange(ref WorkerBuffers[w], null, buf);
                ContentReader.Background(false);
                Interlocked.Decrement(ref run.Running);
            }
        }

        static void Skipped(ContentProgress p, int code)
        {
            switch (code)
            {
                case -1: Interlocked.Increment(ref p.SkippedBinary); break;
                case -2: Interlocked.Increment(ref p.SkippedTooLarge); break;
                case -3: Interlocked.Increment(ref p.SkippedNotDisk); break;
                case -4: Interlocked.Increment(ref p.SkippedUtf16); break;
                case -6: Interlocked.Increment(ref p.SkippedEmpty); break;
                default: Interlocked.Increment(ref p.SkippedUnreadable); break;
            }
        }

        // The one place a finding is made. Every argument comes from the pattern table or the candidate; the line
        // and column are positions the matcher counted.
        static void EmitFindings(ContentRun run, ContentCandidate cand, int[] triples, int hits)
        {
            if (hits <= 0) return;
            string path = cand.Node.FullPath;
            lock (run.Sync)
            {
                for (int h = 0; h < hits; h++)
                {
                    int row = triples[3 * h];
                    run.Found.Add(new Finding(rowIds[row], rowTiers[row], path, triples[3 * h + 1], triples[3 * h + 2], cand.Place));
                    run.FoundNodes.Add(cand.Node);
                }
            }
            Interlocked.Add(ref run.Progress.FindingCount, hits);
        }

        // ---- Matching -------------------------------------------------------------------------------------

        // One forward pass over buf[start..len). Writes (row, line, column) for each hit into triples and returns
        // the number of hits. start is 3 after a UTF-8 byte order mark, else 0.
        internal static int MatchBuffer(byte[] buf, int start, int len, ContentKind kind, int[] triples)
        {
            bool capped;
            return Match(buf, start, len, kind, triples, out capped);
        }

        static int Match(byte[] b, int start, int len, ContentKind kind, int[] triples, out bool capped)
        {
            capped = false;
            int cap = Math.Min(ProtectConstants.ContentFindingsPerFile, triples.Length / 3);
            int count = 0;
            int line = 1, lineStart = start, skipTo = start;
            bool dotenv = kind == ContentKind.Dotenv;
            if (len > b.Length) len = b.Length;
            for (int i = start; i < len; i++)
            {
                byte c = b[i];
                if (i >= skipTo)
                {
                    if (dotenv && i == lineStart)
                    {
                        int vs = TryEnv(b, len, i);
                        if (vs >= 0 && !Add(triples, ref count, cap, RowEnv, line, Column(b, lineStart, vs), ref capped)) break;
                    }
                    int fam = PrefixTable[c];
                    if (fam != 0)
                    {
                        int row;
                        int end = TryAt(b, start, len, i, lineStart, fam, out row);
                        if (end > i)
                        {
                            if (!Add(triples, ref count, cap, row, line, Column(b, lineStart, i), ref capped)) break;
                            skipTo = end;
                        }
                    }
                }
                if (c == '\n')
                {
                    line++;
                    lineStart = i + 1;
                }
                else if (c == '\r' && (i + 1 >= len || b[i + 1] != '\n'))
                {
                    line++;
                    lineStart = i + 1;
                }
            }
            return count;
        }

        // Adds a hit unless the same row already has one on this line. Returns false when the cap is reached.
        static bool Add(int[] t, ref int count, int cap, int row, int line, int col, ref bool capped)
        {
            for (int k = 0; k < count; k++)
                if (t[3 * k] == row && t[3 * k + 1] == line) return true;
            if (count >= cap)
            {
                capped = true;
                return false;
            }
            t[3 * count] = row;
            t[3 * count + 1] = line;
            t[3 * count + 2] = col;
            count++;
            return true;
        }

        // 1 + the bytes before `at` on its line that start a character (UTF-8 continuation bytes are not counted).
        static int Column(byte[] b, int lineStart, int at)
        {
            int col = 1;
            for (int k = lineStart; k < at; k++)
                if (b[k] < 0x80 || b[k] > 0xBF) col++;
            return col;
        }

        static int TryAt(byte[] b, int s, int len, int i, int lineStart, int fam, out int row)
        {
            row = -1;
            int end;
            switch (fam)
            {
                case FamGh:
                    end = GitHubClassic(b, s, len, i);
                    if (end > 0) { row = RowGitHub; return end; }
                    end = GitHubFine(b, s, len, i);
                    if (end > 0) { row = RowGitHubFine; return end; }
                    return -1;
                case FamA:
                    end = Aws(b, s, len, i);
                    if (end > 0) { row = RowAws; return end; }
                    end = Google(b, s, len, i);
                    if (end > 0) { row = RowGoogle; return end; }
                    return -1;
                case FamX:
                    end = Slack(b, s, len, i);
                    if (end > 0) row = RowSlack;
                    return end;
                case FamH:
                    end = Hook(b, len, i);
                    if (end > 0) row = RowHook;
                    return end;
                case FamS:
                    end = Stripe(b, s, len, i);
                    if (end > 0) { row = RowStripe; return end; }
                    end = OpenAi(b, s, len, i);
                    if (end > 0) { row = RowOpenAi; return end; }
                    return -1;
                case FamR:
                    end = Stripe(b, s, len, i);
                    if (end > 0) row = RowStripe;
                    return end;
                case FamDash:
                    bool encrypted;
                    end = Pem(b, s, len, i, lineStart, out encrypted);
                    if (end > 0) row = encrypted ? RowPemEncrypted : RowPem;
                    return end;
            }
            return -1;
        }

        // ---- Byte helpers ---------------------------------------------------------------------------------

        static bool Is(byte c, int bit)
        {
            return (cls[c] & bit) != 0;
        }

        // How many bytes from `at` are in the class, counting at most max.
        static int Run(byte[] b, int at, int len, int bit, int max)
        {
            int n = 0;
            while (at + n < len && n < max && (cls[b[at + n]] & bit) != 0) n++;
            return n;
        }

        static bool Before(byte[] b, int s, int at, int bit)
        {
            return at <= s || (cls[b[at - 1]] & bit) == 0;
        }

        static bool After(byte[] b, int len, int at, int bit)
        {
            return at >= len || (cls[b[at]] & bit) == 0;
        }

        // Whether the ASCII constant lit sits at b[at].
        static bool Lit(byte[] b, int len, int at, string lit)
        {
            if (at < 0 || at + lit.Length > len) return false;
            for (int k = 0; k < lit.Length; k++)
                if (b[at + k] != lit[k]) return false;
            return true;
        }

        static byte Lower(byte c)
        {
            return c >= 'A' && c <= 'Z' ? (byte)(c | 0x20) : c;
        }

        // Whether b[from..to) holds the lower-case ASCII word, ignoring case.
        static bool HasWord(byte[] b, int from, int to, string word)
        {
            int n = word.Length;
            for (int i = from; i + n <= to; i++)
            {
                int k = 0;
                while (k < n && Lower(b[i + k]) == word[k]) k++;
                if (k == n) return true;
            }
            return false;
        }

        static bool HasRun(byte[] b, int from, int to, int runLength)
        {
            int run = 1;
            for (int i = from + 1; i < to; i++)
            {
                run = b[i] == b[i - 1] ? run + 1 : 1;
                if (run >= runLength) return true;
            }
            return false;
        }

        static bool AllSame(byte[] b, int from, int to)
        {
            for (int i = from + 1; i < to; i++)
                if (b[i] != b[from]) return false;
            return to > from;
        }

        static bool AllByte(byte[] b, int from, int to, byte v)
        {
            for (int i = from; i < to; i++)
                if (b[i] != v) return false;
            return true;
        }

        // The placeholder guard: no run of 6 identical bytes, and none of the placeholder words.
        static bool Placeholder(byte[] b, int from, int to)
        {
            if (HasRun(b, from, to, 6)) return true;
            foreach (string w in placeholderWords)
                if (HasWord(b, from, to, w)) return true;
            return false;
        }

        // ---- The rows -------------------------------------------------------------------------------------
        // Each returns the end of the match, or -1. The formats are described in words in ProtectConstants.

        // The classic GitHub prefixes, 30 letters and digits and a 6-digit base62 checksum of those 30.
        static int GitHubClassic(byte[] b, int s, int len, int i)
        {
            if (i + 40 > len || b[i + 1] != 'h' || b[i + 3] != '_') return -1;
            byte k = b[i + 2];
            if (k != 'p' && k != 'o' && k != 'u' && k != 's' && k != 'r') return -1;
            if (!Before(b, s, i, Word)) return -1;
            if (Run(b, i + 4, len, Alnum, 37) != 36 || !After(b, len, i + 40, Word)) return -1;
            return Base62Matches(Crc32(b, i + 4, 30), b, i + 34) ? i + 40 : -1;
        }

        // The fine-grained prefix, 22 letters and digits, an underscore and 59 more.
        static int GitHubFine(byte[] b, int s, int len, int i)
        {
            if (!Lit(b, len, i, "github_pat_") || !Before(b, s, i, Word)) return -1;
            int p = i + 11;
            if (Run(b, p, len, Alnum, 23) != 22 || p + 22 >= len || b[p + 22] != '_') return -1;
            if (Run(b, p + 23, len, Alnum, 60) != 59 || !After(b, len, p + 82, Word)) return -1;
            return Placeholder(b, p, p + 82) ? -1 : p + 82;
        }

        // The access key and temporary key prefixes, then 16 base32 capitals and digits, not inside base64.
        static int Aws(byte[] b, int s, int len, int i)
        {
            if (i + 20 > len || !(Lit(b, len, i, "AKIA") || Lit(b, len, i, "ASIA"))) return -1;
            if (!Before(b, s, i, AwsBefore)) return -1;
            if (Run(b, i + 4, len, B32, 16) != 16 || !After(b, len, i + 20, AwsAfter)) return -1;
            if (Lit(b, len, i + 13, "EXAMPLE")) return -1;  // the two IDs AWS publishes in its documentation
            return HasRun(b, i + 4, i + 20, 6) ? -1 : i + 20;
        }

        // The Google key prefix and exactly 35 URL-safe base64 characters, minus the published samples.
        static int Google(byte[] b, int s, int len, int i)
        {
            if (!Lit(b, len, i, "AIza") || !Before(b, s, i, Url)) return -1;
            if (Run(b, i + 4, len, Url, 36) != 35) return -1;
            int end = i + 39;
            for (int k = 0; k < GoogleSampleBytes.Length; k++)
            {
                byte[] sample = GoogleSampleBytes[k];
                if (sample.Length != 39) continue;
                int j = 0;
                while (j < 39 && b[i + j] == sample[j]) j++;
                if (j == 39) return -1;
            }
            if (HasRun(b, i + 4, end, 6)) return -1;
            // A straight alphabet run of 8 anywhere in the body is a placeholder. Real keys start the body with
            // "Sy", so a docs placeholder puts its run after those two characters, not at the first one.
            int straight = 1;
            for (int k = i + 5; k < end; k++)
            {
                straight = b[k] == b[k - 1] + 1 ? straight + 1 : 1;
                if (straight >= 8) return -1;
            }
            return end;
        }

        // Bot, user, app, rotating and refresh token forms, with Slack's exact groups.
        static int Slack(byte[] b, int s, int len, int i)
        {
            if (!Before(b, s, i, Url)) return -1;
            if (Lit(b, len, i, "xoxb-"))
            {
                int p = i + 5, d1, d2;
                if ((d1 = DigitGroup(b, len, p, 10, 13)) < 0) return -1;
                int p2 = p + d1 + 1;
                if ((d2 = DigitGroup(b, len, p2, 10, 13)) < 0) return -1;
                int p3 = p2 + d2 + 1;
                if (Run(b, p3, len, Alnum, 25) != 24 || !After(b, len, p3 + 24, Url)) return -1;
                return AllSame(b, p3, p3 + 24) ? -1 : p3 + 24;
            }
            if (Lit(b, len, i, "xoxp-"))
            {
                int p = i + 5;
                for (int g = 0; g < 3; g++)
                {
                    int d = DigitGroup(b, len, p, 10, 13);
                    if (d < 0) return -1;
                    p += d + 1;
                }
                if (Run(b, p, len, HexL, 33) != 32 || !AfterHex(b, len, p + 32)) return -1;
                return AllSame(b, p, p + 32) ? -1 : p + 32;
            }
            if (Lit(b, len, i, "xapp-1-"))
            {
                int p = i + 7;
                int g = Run(b, p, len, UpNum, 13);
                if (g < 9 || g > 12 || p + g >= len || b[p + g] != '-') return -1;
                p += g + 1;
                int d = DigitGroup(b, len, p, 10, 16);
                if (d < 0) return -1;
                p += d + 1;
                if (Run(b, p, len, HexL, 65) != 64 || !AfterHex(b, len, p + 64)) return -1;
                return AllSame(b, p, p + 64) ? -1 : p + 64;
            }
            if (Lit(b, len, i, "xoxe.xoxb-1-") || Lit(b, len, i, "xoxe.xoxp-1-"))
            {
                int p = i + 12;
                int a = Run(b, p, len, Alnum, 167);
                if (a < 163 || a > 166 || !After(b, len, p + a, Url)) return -1;
                return AllSame(b, p, p + a) ? -1 : p + a;
            }
            if (Lit(b, len, i, "xoxe-1-"))
            {
                int p = i + 7;
                if (Run(b, p, len, Alnum, 147) != 146 || !After(b, len, p + 146, Url)) return -1;
                return AllSame(b, p, p + 146) ? -1 : p + 146;
            }
            return -1;
        }

        // A run of min..max digits at p followed by '-', not all zeros. Returns the run's length or -1.
        static int DigitGroup(byte[] b, int len, int p, int min, int max)
        {
            int d = Run(b, p, len, Digit, max + 1);
            if (d < min || d > max || p + d >= len || b[p + d] != '-') return -1;
            return AllByte(b, p, p + d, (byte)'0') ? -1 : d;
        }

        static bool AfterHex(byte[] b, int len, int at)
        {
            return at >= len || !(Is(b[at], HexL) || b[at] == '_' || b[at] == '-');
        }

        // The Slack services webhook address: team and channel parts and a 24-character secret.
        static int Hook(byte[] b, int len, int i)
        {
            const string head = "https://hooks.slack.com/services/T";
            if (!Lit(b, len, i, head)) return -1;
            int p = i + head.Length;
            int t = Run(b, p, len, UpNum, 13);
            if (t < 8 || t > 12 || AllByte(b, p, p + t, (byte)'0')) return -1;
            p += t;
            if (!Lit(b, len, p, "/B")) return -1;
            p += 2;
            int c = Run(b, p, len, UpNum, 13);
            if (c < 8 || c > 12 || AllByte(b, p, p + c, (byte)'0')) return -1;
            p += c;
            if (p >= len || b[p] != '/') return -1;
            p++;
            if (Run(b, p, len, Alnum, 25) != 24 || !After(b, len, p + 24, Alnum)) return -1;
            return AllSame(b, p, p + 24) ? -1 : p + 24;
        }

        // The live secret and restricted key prefixes and 24 to 247 letters and digits. Test mode is never matched.
        static int Stripe(byte[] b, int s, int len, int i)
        {
            if (!Lit(b, len, i + 1, "k_live_") || !Before(b, s, i, Word)) return -1;
            int p = i + 8;
            int n = Run(b, p, len, Alnum, 248);
            if (n < 24 || n > 247) return -1;
            return Placeholder(b, p, p + n) ? -1 : p + n;
        }

        static readonly string[] openAiPrefixes = { "sk-proj-", "sk-svcacct-", "sk-admin-" };
        const string OpenAiMarker = "T3BlbkFJ";

        // The project, service account and admin forms (58 or 74 characters on each side of the marker), and the
        // older form (20 letters and digits on each side).
        static int OpenAi(byte[] b, int s, int len, int i)
        {
            if (!Lit(b, len, i, "sk-") || !Before(b, s, i, Url)) return -1;
            foreach (string prefix in openAiPrefixes)
            {
                if (!Lit(b, len, i, prefix)) continue;
                int p = i + prefix.Length;
                int r = Run(b, p, len, Url, 157);
                for (int a = 58; a <= 74; a += 16)
                {
                    int rest = r - a - 8;
                    if ((rest != 58 && rest != 74) || !Lit(b, len, p + a, OpenAiMarker)) continue;
                    if (Placeholder(b, p, p + a) || Placeholder(b, p + a + 8, p + r)) continue;
                    return p + r;
                }
                return -1;
            }
            int q = i + 3;
            if (Run(b, q, len, Url, 49) != 48 || Run(b, q, len, Alnum, 49) != 48) return -1;
            if (!Lit(b, len, q + 20, OpenAiMarker)) return -1;
            if (Placeholder(b, q, q + 20) || Placeholder(b, q + 28, q + 48)) return -1;
            return q + 48;
        }

        // A private key block: the begin line at a line start (after spaces or tabs), after a quote, or after an
        // escaped line break; optional header lines; at least 64 base64 characters; and the matching end line.
        static int Pem(byte[] b, int s, int len, int i, int lineStart, out bool encrypted)
        {
            encrypted = false;
            if (!Lit(b, len, i, "-----BEGIN ")) return -1;
            bool placed = (i > s && b[i - 1] == '"') || (i >= s + 2 && b[i - 2] == '\\' && b[i - 1] == 'n');
            if (!placed)
            {
                placed = true;
                for (int k = lineStart; k < i; k++)
                    if (b[k] != ' ' && b[k] != '\t') { placed = false; break; }
            }
            if (!placed) return -1;
            int p = i + 11;
            int li = -1;
            for (int k = 0; k < pemLabels.Length; k++)
            {
                string l = pemLabels[k];
                if (Lit(b, len, p, l) && Lit(b, len, p + l.Length, "-----")) { li = k; break; }
            }
            if (li < 0) return -1;
            string tag = pemLabels[li];
            p += tag.Length + 5;
            bool procEncrypted = false, headers = true;
            int body = 0;
            while (p < len)
            {
                byte c = b[p];
                if (c == '\r' || c == '\n' || c == ' ' || c == '\t') { p++; continue; }
                if (c == '\\' && p + 1 < len && b[p + 1] == 'n') { p += 2; continue; }
                if (c == '-')
                {
                    if (!Lit(b, len, p, "-----END ") || !Lit(b, len, p + 9, tag) || !Lit(b, len, p + 9 + tag.Length, "-----")) return -1;
                    if (body < 64) return -1;
                    // pemLabels: 0 is the encrypted form; 1 to 3 are RSA, EC and DSA, which mark encryption with Proc-Type.
                    encrypted = li == 0 || (procEncrypted && li >= 1 && li <= 3);
                    return p + 9 + tag.Length + 5;
                }
                if (headers)
                {
                    int h = HeaderAt(b, len, p);
                    if (h >= 0)
                    {
                        int e = p;
                        while (e < len && b[e] != '\r' && b[e] != '\n' && !(b[e] == '\\' && e + 1 < len && b[e + 1] == 'n')) e++;
                        if (h == 0 && HasWord(b, p, e, "encrypted")) procEncrypted = true;
                        p = e;
                        continue;
                    }
                }
                if (Is(c, B64))
                {
                    int n = Run(b, p, len, B64, int.MaxValue);
                    body += n;
                    p += n;
                    headers = false;
                    continue;
                }
                return -1;
            }
            return -1;
        }

        static int HeaderAt(byte[] b, int len, int p)
        {
            for (int k = 0; k < pemHeaders.Length; k++)
                if (Lit(b, len, p, pemHeaders[k])) return k;
            return -1;
        }

        // ---- env-secret -----------------------------------------------------------------------------------

        // A KEY=value line of a .env name whose key names a secret and whose value is not a placeholder. Returns the
        // index of the value's first byte, or -1.
        static int TryEnv(byte[] b, int len, int ls)
        {
            int p = SkipBlanks(b, len, ls);
            if (Lit(b, len, p, "export") && p + 6 < len && (b[p + 6] == ' ' || b[p + 6] == '\t')) p = SkipBlanks(b, len, p + 6);
            if (p >= len) return -1;
            byte c0 = b[p];
            if (!((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || c0 == '_')) return -1;
            int ks = p;
            while (p < len && (Is(b[p], Alnum) || b[p] == '_' || b[p] == '.' || b[p] == '-')) p++;
            int ke = p;
            p = SkipBlanks(b, len, p);
            if (p >= len || b[p] != '=') return -1;
            if (!SecretKey(b, ks, ke)) return -1;
            p = SkipBlanks(b, len, p + 1);
            int eol = p;
            while (eol < len && b[eol] != '\n' && b[eol] != '\r') eol++;
            if (p >= eol) return -1;
            int vs, ve;
            if (b[p] == '"' || b[p] == '\'')
            {
                byte q = b[p];
                vs = p + 1;
                ve = vs;
                while (ve < eol && b[ve] != q) ve++;
                if (ve >= eol) return -1;  // the quote does not close on this line
            }
            else
            {
                vs = p;
                ve = eol;
                for (int k = vs; k + 1 < eol; k++)
                    if ((b[k] == ' ' || b[k] == '\t') && b[k + 1] == '#') { ve = k; break; }
                while (ve > vs && (b[ve - 1] == ' ' || b[ve - 1] == '\t')) ve--;
            }
            return SecretValue(b, vs, ve) ? vs : -1;
        }

        static int SkipBlanks(byte[] b, int len, int p)
        {
            while (p < len && (b[p] == ' ' || b[p] == '\t')) p++;
            return p;
        }

        static bool SegIs(byte[] b, int from, int to, string upper)
        {
            if (to - from != upper.Length) return false;
            for (int k = 0; k < upper.Length; k++)
            {
                byte c = b[from + k];
                if (c >= 'a' && c <= 'z') c = (byte)(c - 32);
                if (c != upper[k]) return false;
            }
            return true;
        }

        static bool StartsUpper(byte[] b, int from, int to, string upper)
        {
            return to - from >= upper.Length && SegIs(b, from, from + upper.Length, upper);
        }

        static bool SecretKey(byte[] b, int ks, int ke)
        {
            foreach (string pre in envPublicPrefixes)
                if (StartsUpper(b, ks, ke, pre)) return false;
            int lastS = -1, lastE = -1, prevS = -1, prevE = -1;
            int segStart = ks;
            for (int k = ks; k <= ke; k++)
            {
                if (k < ke && b[k] != '_' && b[k] != '.' && b[k] != '-') continue;
                if (k > segStart)
                {
                    if (SegIs(b, segStart, k, "PUBLIC") || SegIs(b, segStart, k, "PUBLISHABLE")) return false;
                    prevS = lastS;
                    prevE = lastE;
                    lastS = segStart;
                    lastE = k;
                }
                segStart = k + 1;
            }
            if (lastS < 0) return false;
            foreach (string w in envLastWords)
                if (SegIs(b, lastS, lastE, w)) return true;
            if (prevS < 0) return false;
            for (int k = 0; k + 1 < envLastPairs.Length; k += 2)
                if (SegIs(b, prevS, prevE, envLastPairs[k]) && SegIs(b, lastS, lastE, envLastPairs[k + 1])) return true;
            return false;
        }

        static bool SecretValue(byte[] b, int vs, int ve)
        {
            int n = ve - vs;
            if (n < 16 || n > 1024) return false;
            bool digits = true, lowWords = true, upWords = true;
            int xRun = 0;
            for (int k = vs; k < ve; k++)
            {
                byte c = b[k];
                if (c == ' ' || c == '\t') return false;
                if (!Is(c, Digit)) digits = false;
                if (!Is(c, LowWord)) lowWords = false;  // only lower-case letters, _ and -: a phrase, not a key
                if (!Is(c, UpWord)) upWords = false;
                xRun = c == 'x' || c == 'X' ? xRun + 1 : 0;
                if (xRun >= 4) return false;
            }
            if (digits || lowWords || upWords || AllSame(b, vs, ve)) return false;
            byte f = b[vs];
            if (f == '$' || f == '%' || f == '<' || f == '[' || f == '@') return false;
            if (Lit(b, ve, vs, "{{")) return false;
            if (b[ve - 1] == '>' || (b[ve - 1] == '}' && b[ve - 2] == '}')) return false;
            foreach (string w in envPlaceholders)
                if (HasWord(b, vs, ve, w)) return false;
            foreach (string w in envWordValues)
                if (n == w.Length && HasWord(b, vs, ve, w)) return false;
            if (Lit(b, ve, vs, "op://") || Lit(b, ve, vs, "vault:") || Lit(b, ve, vs, "arn:aws:secretsmanager:")) return false;
            if (Lit(b, ve, vs, "projects/") && HasWord(b, vs, ve, "/secrets/")) return false;
            foreach (string pre in envFormatPrefixes)
                if (Lit(b, ve, vs, pre)) return false;
            for (int k = 0; k < GoogleSampleBytes.Length; k++)
            {
                byte[] sample = GoogleSampleBytes[k];
                if (sample.Length != n) continue;
                int j = 0;
                while (j < n && b[vs + j] == sample[j]) j++;
                if (j == n) return false;
            }
            return true;
        }

        // ---- The only code that opens and reads ----------------------------------------------------------

        // trust-read-begin: content
        private static class ContentReader
        {
            const uint GENERIC_READ = 0x80000000;
            const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000, FILE_FLAG_OPEN_NO_RECALL = 0x00100000, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            const uint FILE_TYPE_DISK = 1;
            const int THREAD_MODE_BACKGROUND_BEGIN = 0x00010000, THREAD_MODE_BACKGROUND_END = 0x00020000;

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            static extern bool ReadFile(SafeFileHandle h, IntPtr buffer, int count, out int read, IntPtr overlapped);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            static extern bool GetFileSizeEx(SafeFileHandle h, out long size);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            static extern uint GetFileType(SafeFileHandle h);

            [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
            static extern bool SetThreadPriority(IntPtr thread, int priority);

            [DllImport("kernel32.dll", ExactSpelling = true)]
            static extern IntPtr GetCurrentThread();

            // Background mode lowers this thread's disk, memory and processor priority until it is ended.
            internal static void Background(bool on)
            {
                try { SetThreadPriority(GetCurrentThread(), on ? THREAD_MODE_BACKGROUND_BEGIN : THREAD_MODE_BACKGROUND_END); }
                catch (EntryPointNotFoundException) { }
            }

            // Returns the bytes now in buf, or a negative code: -1 binary, -2 too large, -3 not a disk object,
            // -4 UTF-16, -5 cannot be opened, -6 empty. Before each read, dirty grows to cover the whole request,
            // so the caller's clear covers a partial or failed read too.
            internal static int Read(string longPath, byte[] buf, IntPtr pinned, ref int dirty, ContentProgress p)
            {
                Action<string> hook = SecretScan.OnOpen;
                if (hook != null) hook(longPath);
                Interlocked.Increment(ref SecretScan.openCalls);
                Interlocked.Increment(ref p.FilesOpened);
                if (pinned == IntPtr.Zero) return -5;
                using (SafeFileHandle h = CreateFileW(longPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero))
                {
                    if (h.IsInvalid) return -5;
                    if (GetFileType(h) != FILE_TYPE_DISK) return -3;
                    long len;
                    if (!GetFileSizeEx(h, out len)) return -5;
                    if (len == 0) return -6;  // also a link made after the scan: opened as itself, it has no data
                    if (len > ProtectConstants.MaxContentBytes || len > buf.Length) return -2;
                    int total = (int)len;
                    int probe = Math.Min(total, ProtectConstants.BinaryProbeBytes);
                    int n = Fill(h, pinned, 0, probe, ref dirty, p);
                    if (n >= 2 && ((buf[0] == 0xFF && buf[1] == 0xFE) || (buf[0] == 0xFE && buf[1] == 0xFF))) return -4;
                    for (int k = 0; k < n; k++)
                        if (buf[k] == 0) return -1;
                    // Reads stop at the length taken at open: a growing item is cut there, a shrinking one ends early.
                    if (n == probe && probe < total) n += Fill(h, pinned, probe, total - probe, ref dirty, p);
                    return n;
                }
            }

            static int Fill(SafeFileHandle h, IntPtr pinned, int offset, int count, ref int dirty, ContentProgress p)
            {
                int got = 0;
                while (got < count)
                {
                    int want = count - got;
                    if (offset + got + want > dirty) dirty = offset + got + want;
                    int read;
                    if (!ReadFile(h, IntPtr.Add(pinned, offset + got), want, out read, IntPtr.Zero) || read <= 0) break;
                    got += read;
                    Interlocked.Add(ref p.BytesRead, read);
                }
                return got;
            }
        }
        // trust-read-end
    }
}

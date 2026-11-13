using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

// The by-content corpus generator (Protect stage 2). The repository holds no key in a valid format: each
// template under tests\protect-corpus\by-content\files holds recipes written as <<kind:variant:seed>>, and this
// class turns them into real files at test time, in a folder the caller makes under %TEMP%\dsa-* and deletes.
//
// Rules this file keeps, so that it never holds a match itself (the tests run the app's matcher over it):
// - every vendor prefix, PEM label and marker is assembled from split strings;
// - every body comes from a seeded System.Random, so each run builds the same files;
// - the checksum and its base62 form are computed here with their own code (a bitwise CRC32 with no table),
//   independent of the app's, so a shared bug cannot pass.
//
// It uses nothing from the app, so tests\make-protect-tree.ps1 can load it with Add-Type. C# 5.
public static class ContentCorpus
{
    // The published Google sample keys (ProtectConstants.GoogleSampleKeys). The tests set this; the tree script
    // leaves it null, and the sample recipes then give a line that matches nothing.
    public static string[] SampleKeys;

    public sealed class Row
    {
        public int Line;
        public string File, Expect, Tier, Lc, Section;
        public bool Positive { get { return Expect != "none"; } }
    }

    public sealed class CaseFile
    {
        public string File;
        public string Encoding = "utf8";   // utf8, utf8bom, utf16le or utf16be
        public string Eol = "lf";          // lf, crlf or cr
        public long Pad = -1;              // the size to pad the file to with filler, or -1
        public long Nul = -1;              // the offset of one zero byte, or -1
        public readonly List<Row> Rows = new List<Row>();
    }

    public sealed class CaseSet
    {
        public readonly List<CaseFile> Files = new List<CaseFile>();
        public readonly List<Row> Rows = new List<Row>();
    }

    // ---------------------------------------------------------------------------------------------------
    // cases.tsv

    public static CaseSet Load(string tsv)
    {
        var set = new CaseSet();
        var byName = new Dictionary<string, CaseFile>(StringComparer.Ordinal);
        string enc = null, eol = null, section = null;
        long pad = -1, nul = -1;
        int n = 0;
        foreach (string line in File.ReadAllLines(tsv))
        {
            n++;
            if (line.Length == 0) continue;
            if (line.StartsWith("#!", StringComparison.Ordinal))
            {
                string rest = line.Substring(2).Trim();
                int cut = rest.IndexOf(' ');
                string word = cut < 0 ? rest : rest.Substring(0, cut);
                string arg = cut < 0 ? "" : rest.Substring(cut + 1).Trim();
                switch (word)
                {
                    case "encoding":
                        if (arg != "utf16le" && arg != "utf16be" && arg != "utf8bom")
                            throw new InvalidDataException("Unknown encoding on line " + n + ": " + arg);
                        enc = arg;
                        break;
                    case "pad": pad = long.Parse(arg); break;
                    case "nul": nul = long.Parse(arg); break;
                    case "crlf": eol = "crlf"; break;
                    case "cr": eol = "cr"; break;
                    default: throw new InvalidDataException("Unknown directive on line " + n + ": " + word);
                }
                continue;
            }
            if (line.StartsWith("# ---", StringComparison.Ordinal))
            {
                section = line.Substring(5).Trim();
                continue;
            }
            if (line.StartsWith("#", StringComparison.Ordinal)) continue;
            string[] cols = line.Split('\t');
            if (cols.Length != 4) throw new InvalidDataException("Line " + n + " does not have 4 columns.");
            var row = new Row { Line = n, File = cols[0], Expect = cols[1], Tier = cols[2], Lc = cols[3], Section = section };
            CaseFile f;
            bool pending = enc != null || eol != null || pad >= 0 || nul >= 0;
            if (!byName.TryGetValue(row.File, out f))
            {
                f = new CaseFile { File = row.File };
                if (enc != null) f.Encoding = enc;
                if (eol != null) f.Eol = eol;
                f.Pad = pad;
                f.Nul = nul;
                byName[row.File] = f;
                set.Files.Add(f);
            }
            else if (pending)
                throw new InvalidDataException("Line " + n + ": a directive must come before a file's first row.");
            enc = null;
            eol = null;
            pad = -1;
            nul = -1;
            f.Rows.Add(row);
            set.Rows.Add(row);
        }
        return set;
    }

    // ---------------------------------------------------------------------------------------------------
    // Building the files

    public static string TemplatePath(string filesDir, string file)
    {
        return Path.Combine(filesDir, file.Replace('/', '\\') + ".tpl");
    }

    // home/... goes to homeDir and proj/... to projDir.
    public static string LocalPath(string file, string homeDir, string projDir)
    {
        if (file.StartsWith("home/", StringComparison.Ordinal)) return Path.Combine(homeDir, file.Substring(5).Replace('/', '\\'));
        if (file.StartsWith("proj/", StringComparison.Ordinal)) return Path.Combine(projDir, file.Substring(5).Replace('/', '\\'));
        throw new InvalidDataException("A corpus file must start with home/ or proj/: " + file);
    }

    // Writes every file of the set. Each generated value is added to values, when it is not null.
    public static int WriteAll(CaseSet set, string filesDir, string homeDir, string projDir, List<string> values)
    {
        int written = 0;
        foreach (CaseFile f in set.Files)
        {
            string path = LocalPath(f.File, homeDir, projDir);
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllBytes(path, Build(f, filesDir, values));
            written++;
        }
        return written;
    }

    public static byte[] Build(CaseFile f, string filesDir, List<string> values)
    {
        byte[] raw = File.ReadAllBytes(TemplatePath(filesDir, f.File));
        foreach (byte b in raw)
            if (b == 13) throw new InvalidDataException("A template must use LF line endings: " + f.File);
        string text = Expand(new UTF8Encoding(false, true).GetString(raw), values);
        if (f.Eol == "crlf") text = text.Replace("\n", "\r\n");
        else if (f.Eol == "cr") text = text.Replace("\n", "\r");

        var body = new List<byte>();
        switch (f.Encoding)
        {
            case "utf16le":
                body.Add(0xFF); body.Add(0xFE);
                body.AddRange(System.Text.Encoding.Unicode.GetBytes(text));
                break;
            case "utf16be":
                body.Add(0xFE); body.Add(0xFF);
                body.AddRange(System.Text.Encoding.BigEndianUnicode.GetBytes(text));
                break;
            case "utf8bom":
                body.Add(0xEF); body.Add(0xBB); body.Add(0xBF);
                body.AddRange(new UTF8Encoding(false).GetBytes(text));
                break;
            default:
                body.AddRange(new UTF8Encoding(false).GetBytes(text));
                break;
        }
        // "#! nul N": N bytes of filler, one zero byte at offset N, then the template.
        if (f.Nul >= 0)
        {
            var withNul = new List<byte>(Filler(f.Nul));
            withNul.Add(0);
            withNul.AddRange(body);
            body = withNul;
        }
        // "#! pad N": filler after the template, up to N bytes in all.
        if (f.Pad > body.Count) body.AddRange(Filler(f.Pad - body.Count));
        return body.ToArray();
    }

    static byte[] Filler(long size)
    {
        byte[] unit = System.Text.Encoding.ASCII.GetBytes("not a secret ");
        var b = new byte[size];
        for (long i = 0; i < size; i++) b[i] = unit[i % unit.Length];
        return b;
    }

    // Replaces each <<recipe>> with its generated value.
    public static string Expand(string template, List<string> values)
    {
        var sb = new StringBuilder();
        int i = 0;
        while (true)
        {
            int open = template.IndexOf("<<", i, StringComparison.Ordinal);
            if (open < 0) { sb.Append(template, i, template.Length - i); break; }
            int close = template.IndexOf(">>", open + 2, StringComparison.Ordinal);
            if (close < 0) throw new InvalidDataException("An unclosed recipe in a template.");
            string recipe = template.Substring(open + 2, close - open - 2);
            foreach (char c in recipe)
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ':'))
                    throw new InvalidDataException("A recipe may hold only lower-case letters, digits and ':': " + recipe);
            string value = Recipe(recipe);
            if (values != null) values.Add(value);
            sb.Append(template, i, open - i).Append(value);
            i = close + 2;
        }
        return sb.ToString();
    }

    // ---------------------------------------------------------------------------------------------------
    // Alphabets and helpers

    static string Range(char a, char z)
    {
        var sb = new StringBuilder();
        for (char c = a; c <= z; c++) sb.Append(c);
        return sb.ToString();
    }

    static readonly string Digits = Range('0', '9'), Upper = Range('A', 'Z'), Lower = Range('a', 'z');
    static readonly string B62 = Digits + Upper + Lower;                  // also the base62 digit order
    static readonly string B64 = Upper + Lower + Digits + "+/";
    static readonly string UrlB64 = Upper + Lower + Digits + "-_";
    static readonly string B32Aws = Upper + "234567";
    static readonly string HexL = Digits + "abcdef";
    static readonly string HexU = Digits + "ABCDEF";
    static readonly string UpperDigits = Upper + Digits;

    static string Draw(Random r, string alphabet, int n)
    {
        var c = new char[n];
        for (int i = 0; i < n; i++) c[i] = alphabet[r.Next(alphabet.Length)];
        return new string(c);
    }

    static readonly string[] GuardWords = { "example", "sample", "dummy", "placeholder", "your", "xxxx" };

    // The placeholder guard: no run of 6 identical chars and none of the guard words.
    public static bool Clean(string s)
    {
        int run = 1;
        for (int i = 1; i < s.Length; i++)
        {
            run = s[i] == s[i - 1] ? run + 1 : 1;
            if (run >= 6) return false;
        }
        string low = s.ToLowerInvariant();
        foreach (string w in GuardWords)
            if (low.Contains(w)) return false;
        return true;
    }

    static string DrawClean(Random r, string alphabet, int n)
    {
        while (true)
        {
            string s = Draw(r, alphabet, n);
            if (Clean(s)) return s;
        }
    }

    static string DigitGroup(Random r, int min, int max)
    {
        int n = r.Next(min, max + 1);
        return Draw(r, "123456789", 1) + Draw(r, Digits, n - 1);
    }

    static int Int(string[] p, int i)
    {
        if (i >= p.Length) throw new InvalidDataException("The recipe " + string.Join(":", p) + " needs a number in part " + (i + 1) + ".");
        return int.Parse(p[i]);
    }

    static byte[] Ascii(string s)
    {
        var b = new byte[s.Length];
        for (int i = 0; i < s.Length; i++) b[i] = (byte)s[i];
        return b;
    }

    // IEEE CRC32, one bit at a time.
    public static uint Crc32(byte[] b, int off, int len)
    {
        uint c = 0xFFFFFFFF;
        for (int i = off; i < off + len; i++)
        {
            c ^= b[i];
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? (c >> 1) ^ 0xEDB88320 : c >> 1;
        }
        return c ^ 0xFFFFFFFF;
    }

    // Base62 with the digits 0-9, A-Z, a-z, most significant first, padded to 6 with '0'.
    public static string Base62(uint v)
    {
        var c = new char[6];
        ulong x = v;
        for (int i = 5; i >= 0; i--)
        {
            c[i] = B62[(int)(x % 62)];
            x /= 62;
        }
        return new string(c);
    }

    // ---------------------------------------------------------------------------------------------------
    // Recipes

    static string Recipe(string recipe)
    {
        string[] p = recipe.Split(':');
        switch (p[0])
        {
            case "gh": return GitHub(p);
            case "ghfg": return FineGrained(p);
            case "aws": return Aws(p);
            case "slack": return Slack(p);
            case "hook": return Hook(p);
            case "stripe": return Stripe(p);
            case "google": return Google(p);
            case "openai": return OpenAi(p);
            case "pem": return Pem(p);
            case "rand": return Rand(p);
            case "env": return Env(p);
        }
        throw new InvalidDataException("Unknown recipe: " + recipe);
    }

    static Exception Unknown(string[] p)
    {
        return new InvalidDataException("Unknown recipe: " + string.Join(":", p));
    }

    // 30 entropy chars and their checksum: 36 chars after the prefix.
    static string Classic(Random r, int entropy)
    {
        string e = Draw(r, B62, entropy);
        byte[] b = Ascii(e);
        return e + Base62(Crc32(b, 0, b.Length));
    }

    static string GitHub(string[] p)
    {
        string classic = "gh" + "p_";
        switch (p[1])
        {
            case "allx": return classic + new string('x', 36);
            case "ghp": case "gho": case "ghu": case "ghs": case "ghr":
                return p[1] + "_" + Classic(new Random(Int(p, 2)), 30);
            case "badcrc":
            {
                string t = classic + Classic(new Random(Int(p, 2)), 30);
                char last = t[t.Length - 1];
                return t.Substring(0, t.Length - 1) + B62[(B62.IndexOf(last) + 1) % 62];
            }
            case "len35": return classic + Classic(new Random(Int(p, 2)), 29);
            case "len37": return classic + Classic(new Random(Int(p, 2)), 31);
            case "jwt":
            {
                var r = new Random(Int(p, 2));
                return "gh" + "s_" + DigitGroup(r, 7, 7) + "_" + Jwt(r, 160, 300);
            }
        }
        throw Unknown(p);
    }

    static string FineGrained(string[] p)
    {
        string prefix = "git" + "hub_" + "pat_";
        if (p[1] == "allx") return prefix + new string('x', 22) + "_" + new string('x', 59);
        var r = new Random(Int(p, 2));
        int a, b;
        switch (p[1])
        {
            case "ok": a = 22; b = 59; break;
            case "split2160": a = 21; b = 60; break;
            case "len92": a = 22; b = 58; break;
            default: throw Unknown(p);
        }
        while (true)
        {
            string x = DrawClean(r, B62, a), y = DrawClean(r, B62, b);
            if (Clean(x + y)) return prefix + x + "_" + y;
        }
    }

    static string AwsBody(Random r)
    {
        while (true)
        {
            string s = DrawClean(r, B32Aws, 16);
            if (!s.EndsWith("EXAM" + "PLE", StringComparison.Ordinal)) return s;
        }
    }

    static string Aws(string[] p)
    {
        string akia = "AK" + "IA";
        switch (p[1])
        {
            case "akia": return akia + AwsBody(new Random(Int(p, 2)));
            case "asia": return "AS" + "IA" + AwsBody(new Random(Int(p, 2)));
            case "aida": return "AI" + "DA" + AwsBody(new Random(Int(p, 2)));
            // The two documentation-style ids: the structural allowlist is the EXAMPLE tail.
            case "sample1": return akia + Draw(new Random(1), B32Aws, 9) + "EXAM" + "PLE";
            case "sample2": return akia + Draw(new Random(2), B32Aws, 9) + "EXAM" + "PLE";
            case "allx": return akia + new string('X', 16);
            case "digit":
            {
                var r = new Random(Int(p, 2));
                char[] body = AwsBody(r).ToCharArray();
                body[r.Next(16)] = "0189"[r.Next(4)];
                return akia + new string(body);
            }
            case "b64":
            {
                var r = new Random(Int(p, 2));
                return Draw(r, B64, 40) + akia + AwsBody(r) + Draw(r, B64, 40);
            }
        }
        throw Unknown(p);
    }

    static string Slack(string[] p)
    {
        string bot = "xo" + "xb-", user = "xo" + "xp-";
        switch (p[1])
        {
            case "bot":
            {
                var r = new Random(Int(p, 2));
                return bot + DigitGroup(r, 10, 13) + "-" + DigitGroup(r, 10, 13) + "-" + DrawClean(r, B62, 24);
            }
            case "user":
            {
                var r = new Random(Int(p, 2));
                return user + DigitGroup(r, 10, 13) + "-" + DigitGroup(r, 10, 13) + "-" + DigitGroup(r, 10, 13) + "-" + Draw(r, HexL, 32);
            }
            case "app":
            {
                var r = new Random(Int(p, 2));
                return "xa" + "pp-1-" + Draw(r, UpperDigits, r.Next(9, 13)) + "-" + DigitGroup(r, 10, 16) + "-" + Draw(r, HexL, 64);
            }
            case "zeros": return bot + new string('0', 10) + "-" + new string('0', 10) + "-" + DrawClean(new Random(0), B62, 24);
            case "docs": return bot + "not-a-real-token-this-will-not-work";
            case "legacy":
            {
                var r = new Random(Int(p, 2));
                return "xo" + "xa-" + DigitGroup(r, 10, 13) + "-" + DigitGroup(r, 10, 13) + "-" + DigitGroup(r, 10, 13) + "-" + Draw(r, HexL, 32);
            }
        }
        throw Unknown(p);
    }

    static string Hook(string[] p)
    {
        string services = "https://hooks." + "slack.com/" + "services/";
        switch (p[1])
        {
            case "ok":
            {
                var r = new Random(Int(p, 2));
                return services + "T" + Draw(r, UpperDigits, r.Next(8, 13)) + "/B" + Draw(r, UpperDigits, r.Next(8, 13)) + "/" + DrawClean(r, B62, 24);
            }
            case "zeros": return services + "T" + new string('0', 8) + "/B" + new string('0', 8) + "/" + new string('X', 24);
            case "short":
            {
                var r = new Random(Int(p, 2));
                return services + "T" + Draw(r, UpperDigits, 9) + "/B" + Draw(r, UpperDigits, 9) + "/" + DrawClean(r, B62, 23);
            }
            case "workflows":
            {
                var r = new Random(Int(p, 2));
                return "https://hooks." + "slack.com/" + "workflows/T" + Draw(r, UpperDigits, 9) + "/A" + Draw(r, UpperDigits, 9) + "/" +
                    DigitGroup(r, 18, 18) + "/" + DrawClean(r, B62, 32);
            }
        }
        throw Unknown(p);
    }

    static string Stripe(string[] p)
    {
        string live = "_li" + "ve_", test = "_te" + "st_";
        switch (p[1])
        {
            case "sklive": return "sk" + live + DrawClean(new Random(Int(p, 3)), B62, Int(p, 2));
            case "rklive": return "rk" + live + DrawClean(new Random(Int(p, 3)), B62, Int(p, 2));
            case "sktest": return "sk" + test + DrawClean(new Random(Int(p, 2)), B62, 24);
            case "pklive": return "pk" + live + DrawClean(new Random(Int(p, 2)), B62, 24);
            case "short": return "sk" + live + DrawClean(new Random(Int(p, 2)), B62, 23);
        }
        throw Unknown(p);
    }

    static string Google(string[] p)
    {
        string aiza = "AI" + "za";
        switch (p[1])
        {
            case "ok":
            {
                var r = new Random(Int(p, 2));
                while (true)
                {
                    string k = aiza + DrawClean(r, UrlB64, 35);
                    if (SampleKeys == null || Array.IndexOf(SampleKeys, k) < 0) return k;
                }
            }
            case "len34": return aiza + DrawClean(new Random(Int(p, 2)), UrlB64, 34);
            case "alpha": return aiza + (Lower + Upper).Substring(0, 35);
            // Real keys start their body with "Sy", so a docs placeholder puts the alphabet after it.
            case "alphasy": return aiza + "S" + "y" + (Upper + Digits).Substring(0, 33);
            case "alphasylow": return aiza + "S" + "y" + (Lower + Digits).Substring(0, 33);
            case "sample":
            {
                int i = Int(p, 2);
                if (SampleKeys == null || i >= SampleKeys.Length) return "no sample key " + i;
                return SampleKeys[i];
            }
            // Every published sample key, one per line (the count lives in the app, not in a template).
            case "samples":
                if (SampleKeys == null || SampleKeys.Length == 0) return "no sample keys";
                return string.Join("\n", SampleKeys);
        }
        throw Unknown(p);
    }

    static string OpenAi(string[] p)
    {
        string marker = "T3Bl" + "bkFJ", proj = "sk-" + "proj-";
        switch (p[1])
        {
            case "proj":
            {
                int n = Int(p, 2);
                var r = new Random(Int(p, 3));
                return proj + DrawClean(r, UrlB64, n) + marker + DrawClean(r, UrlB64, n);
            }
            case "svcacct":
            {
                var r = new Random(Int(p, 2));
                return "sk-" + "svcacct-" + DrawClean(r, UrlB64, 58) + marker + DrawClean(r, UrlB64, 58);
            }
            case "legacy":
            {
                var r = new Random(Int(p, 2));
                return "sk-" + DrawClean(r, B62, 20) + marker + DrawClean(r, B62, 20);
            }
            case "nomarker":
            {
                var r = new Random(Int(p, 2));
                string mid;
                do mid = Draw(r, B62, 8); while (mid == marker);
                return proj + DrawClean(r, UrlB64, 58) + mid + DrawClean(r, UrlB64, 58);
            }
            case "half57":
            {
                var r = new Random(Int(p, 2));
                return proj + DrawClean(r, UrlB64, 57) + marker + DrawClean(r, UrlB64, 58);
            }
            case "ant":
            {
                var r = new Random(Int(p, 2));
                return "sk-" + "ant-" + "api03-" + DrawClean(r, UrlB64, 93) + "AA";
            }
        }
        throw Unknown(p);
    }

    static string Label(string v)
    {
        string pk = "PRI" + "VATE KEY";
        switch (v)
        {
            case "pkcs8": return pk;
            case "rsa": return "RSA " + pk;
            case "ec": return "EC " + pk;
            case "dsa": return "DSA " + pk;
            case "openssh": return "OPENSSH " + pk;
            case "pgp": return "PGP " + pk + " BLOCK";
            case "enc": return "ENCRYPTED " + pk;
            case "public": return "PUB" + "LIC KEY";
            case "cert": return "CERTI" + "FICATE";
        }
        throw new InvalidDataException("Unknown PEM label: " + v);
    }

    static string Begin(string label) { return "-----BEG" + "IN " + label + "-----"; }
    static string End(string label) { return "-----EN" + "D " + label + "-----"; }

    // 20 lines of 64 seeded base64 chars: random bytes, not a key.
    static string Body(Random r, string newline)
    {
        var lines = new string[20];
        for (int i = 0; i < lines.Length; i++) lines[i] = Draw(r, B64, 64);
        return string.Join(newline, lines);
    }

    static string Block(string label, Random r)
    {
        return Begin(label) + "\n" + Body(r, "\n") + "\n" + End(label);
    }

    static string Pem(string[] p)
    {
        switch (p[1])
        {
            case "pkcs8": case "rsa": case "ec": case "dsa": case "openssh":
                return Block(Label(p[1]), new Random(Int(p, 2)));
            case "pgp":
            {
                var r = new Random(Int(p, 2));
                string l = Label("pgp");
                return Begin(l) + "\n\n" + Body(r, "\n") + "\n=" + Draw(r, B64, 4) + "\n" + End(l);
            }
            case "enc": return Block(Label("enc"), new Random(Int(p, 2)));
            case "procenc":
            {
                var r = new Random(Int(p, 2));
                string l = Label("rsa");
                return Begin(l) + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC," + Draw(r, HexU, 32) + "\n\n" + Body(r, "\n") + "\n" + End(l);
            }
            case "json":
            {
                // The escaped form inside a JSON string: the two bytes \ and n between the lines.
                var r = new Random(Int(p, 2));
                string l = Label("pkcs8"), nl = "\\" + "n";
                return Begin(l) + nl + Body(r, nl) + nl + End(l) + nl;
            }
            case "headeronly": return Begin(Label(p[2]));
            case "public": return Block(Label("public"), new Random(Int(p, 2)));
            case "cert": return Block(Label("cert"), new Random(Int(p, 2)));
            case "mismatch":
            {
                var r = new Random(Int(p, 2));
                return Begin(Label("rsa")) + "\n" + Body(r, "\n") + "\n" + End(Label("pkcs8"));
            }
            case "short63":
            {
                // pem:short63:<seed> or pem:short63:<label>:<seed>
                string l = Label(p.Length > 3 ? p[2] : "pkcs8");
                var r = new Random(Int(p, p.Length - 1));
                return Begin(l) + "\n" + Draw(r, B64, 63) + "\n" + End(l);
            }
            case "noend":
            {
                var r = new Random(Int(p, 2));
                return Begin(Label("pkcs8")) + "\n" + Body(r, "\n");
            }
        }
        throw Unknown(p);
    }

    static string Jwt(Random r, int payloadMin, int payloadMax)
    {
        return "eyJ" + Draw(r, UrlB64, 33) + ".eyJ" + Draw(r, UrlB64, r.Next(payloadMin, payloadMax + 1)) + "." + Draw(r, UrlB64, 43);
    }

    static string Rand(string[] p)
    {
        var r = new Random(Int(p, 2));
        switch (p[1])
        {
            case "uuid": return Draw(r, HexL, 8) + "-" + Draw(r, HexL, 4) + "-" + Draw(r, HexL, 4) + "-" + Draw(r, HexL, 4) + "-" + Draw(r, HexL, 12);
            case "sha1": return Draw(r, HexL, 40);
            case "sha256": return Draw(r, HexL, 64);
            case "md5": return Draw(r, HexL, 32);
            case "b64":
            {
                // About 4 KB of base64 in lines of 76.
                var lines = new List<string>();
                for (int left = 4096; left > 0; left -= 76) lines.Add(Draw(r, B64, Math.Min(76, left)));
                return string.Join("\n", lines.ToArray());
            }
            case "jwt": return Jwt(r, 120, 160);
        }
        throw Unknown(p);
    }

    static readonly string[] EnvBanned =
    {
        "changeme", "change_me", "your_", "your-", "yourkey", "placeholder", "example", "sample", "dummy", "replace", "insert",
        "redacted", "todo", "fixme", "secret_here", "***", "...", "xxxx", "true", "false", "null", "none"
    };

    // A .env value of the given length that mixes upper case, lower case, digits and '-', and passes every
    // guard of the env-secret row (so a missed finding is the matcher's fault, not the value's).
    static string Env(string[] p)
    {
        if (p[1] != "mixed") throw Unknown(p);
        int len = Int(p, 2);
        var r = new Random(Int(p, 3));
        string first = "BCDEFHJKLMNQTUVWYZ" + "abcdefhijklmnoquvwyz";  // no letter that starts a vendor prefix
        string rest = Upper + Lower + Digits + "-";
        while (true)
        {
            string v = Draw(r, first, 1) + Draw(r, rest, len - 1);
            bool up = false, low = false, dig = false, dash = false;
            foreach (char c in v)
            {
                if (c >= 'A' && c <= 'Z') up = true;
                else if (c >= 'a' && c <= 'z') low = true;
                else if (c >= '0' && c <= '9') dig = true;
                else if (c == '-') dash = true;
            }
            if (!(up && low && dig && dash) || !Clean(v)) continue;
            string l = v.ToLowerInvariant();
            bool banned = false;
            foreach (string b in EnvBanned)
                if (l.Contains(b)) banned = true;
            if (!banned) return v;
        }
    }
}

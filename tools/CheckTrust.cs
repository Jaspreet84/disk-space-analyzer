using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

// Reads a compiled .NET program and reports every name in its metadata string heap that belongs to the
// System.Net namespace, plus every referenced assembly whose name starts with System.Net. A program that
// uses the network has to name those types, so an empty report means the program contains no network code.
//
// Usage: CheckTrust <program.exe> [...]   Exit code 1 if any program names a System.Net type.
public static class TrustCheck
{
    public static List<string> NetworkNames(string exe)
    {
        var found = new List<string>();
        byte[] b = File.ReadAllBytes(exe);
        foreach (string s in MetadataStrings(b))
            if (s.StartsWith("System.Net", StringComparison.Ordinal) && (s.Length == 10 || s[10] == '.'))
                found.Add("name: " + s);
        foreach (AssemblyName a in Assembly.ReflectionOnlyLoadFrom(exe).GetReferencedAssemblies())
            if (a.Name.StartsWith("System.Net", StringComparison.Ordinal))
                found.Add("reference: " + a.Name);
        return found;
    }

    // Every string in the #Strings heap: namespaces, type names, member names and assembly names.
    // User-visible text (string literals) lives in a different heap, so mentioning "System.Net" in a
    // sentence shown to the user does not count.
    public static IEnumerable<string> MetadataStrings(byte[] b)
    {
        int pe = BitConverter.ToInt32(b, 0x3C);
        if (BitConverter.ToUInt32(b, pe) != 0x00004550) throw new InvalidDataException("Not a PE file.");
        int coff = pe + 4;
        int sectionCount = BitConverter.ToUInt16(b, coff + 2);
        int optionalSize = BitConverter.ToUInt16(b, coff + 16);
        int optional = coff + 20;
        bool pe32Plus = BitConverter.ToUInt16(b, optional) == 0x20B;
        int directories = optional + (pe32Plus ? 112 : 96);
        int cliRva = BitConverter.ToInt32(b, directories + 14 * 8);
        if (cliRva == 0) throw new InvalidDataException("Not a .NET program.");
        int sections = optional + optionalSize;

        Func<int, int> offset = rva =>
        {
            for (int i = 0; i < sectionCount; i++)
            {
                int s = sections + i * 40;
                int virtualSize = BitConverter.ToInt32(b, s + 8), va = BitConverter.ToInt32(b, s + 12);
                int rawSize = BitConverter.ToInt32(b, s + 16), raw = BitConverter.ToInt32(b, s + 20);
                if (rva >= va && rva < va + Math.Max(virtualSize, rawSize)) return rva - va + raw;
            }
            throw new InvalidDataException("Address outside every section.");
        };

        int cli = offset(cliRva);
        int metadata = offset(BitConverter.ToInt32(b, cli + 8));
        if (BitConverter.ToUInt32(b, metadata) != 0x424A5342) throw new InvalidDataException("No metadata signature.");
        int versionLength = BitConverter.ToInt32(b, metadata + 12);
        int p = metadata + 16 + versionLength + 2;  // past the version string and the flags
        int streams = BitConverter.ToUInt16(b, p);
        p += 2;
        for (int i = 0; i < streams; i++)
        {
            int streamOffset = BitConverter.ToInt32(b, p), streamSize = BitConverter.ToInt32(b, p + 4);
            p += 8;
            int nameStart = p;
            while (b[p] != 0) p++;
            string name = Encoding.ASCII.GetString(b, nameStart, p - nameStart);
            int nameBytes = p - nameStart + 1;
            p = nameStart + nameBytes + (4 - nameBytes % 4) % 4;
            if (name != "#Strings") continue;
            int heap = metadata + streamOffset, end = heap + streamSize, start = heap;
            for (int q = heap; q < end; q++)
            {
                if (b[q] != 0) continue;
                if (q > start) yield return Encoding.UTF8.GetString(b, start, q - start);
                start = q + 1;
            }
        }
    }

    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: CheckTrust <program.exe> [...]");
            return 2;
        }
        int failures = 0;
        foreach (string exe in args)
        {
            List<string> names = NetworkNames(exe);
            if (names.Count == 0)
            {
                Console.WriteLine("  " + Path.GetFileName(exe) + ": no System.Net types");
                continue;
            }
            failures++;
            Console.WriteLine("  " + Path.GetFileName(exe) + ": names " + names.Count + " System.Net item(s):");
            foreach (string n in names) Console.WriteLine("      " + n);
        }
        return failures == 0 ? 0 : 1;
    }
}

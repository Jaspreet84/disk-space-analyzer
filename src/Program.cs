using System;
using System.Reflection;
using System.Runtime.Versioning;

// Opting in to 4.8 behavior turns on long-path support in System.IO.
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
[assembly: AssemblyTitle("Disk Space Analyzer")]
[assembly: AssemblyProduct("Disk Space Analyzer")]
[assembly: AssemblyVersion("2.0.0.0")]
[assembly: AssemblyFileVersion("2.0.0.0")]

namespace DiskSpace
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
#if CLI
            return Cli.Run(args);
#else
            // The elevated half of "Shrink": DiskSpaceAnalyzer.exe --compact-vhdx <log file> <disk file>
            if (args.Length >= 3 && args[0] == "--compact-vhdx")
                return VirtualDisks.CompactHelper(args);
            return UiApp.Run(args);
#endif
        }
    }
}

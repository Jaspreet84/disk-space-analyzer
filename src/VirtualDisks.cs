using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace DiskSpace
{
    enum DiskKind { WslDistro, DockerData, Other }

    // A virtual hard disk file that holds a whole Linux file system (WSL) or Docker's images and containers.
    sealed class VirtualDisk
    {
        public string Name;
        public string Path;
        public string Distro;          // WSL distribution name, or null
        public DiskKind Kind;
        public long FileSize;
        public long UsedInside = -1;   // bytes in use inside Linux; -1 when unknown

        // Docker Desktop's own distributions are managed by Docker, so they are not cleaned or started from here.
        public bool IsUserDistro
        {
            get { return Kind == DiskKind.WslDistro && !Distro.StartsWith("docker-desktop", StringComparison.OrdinalIgnoreCase); }
        }

        public long Reclaimable
        {
            get { return UsedInside < 0 ? -1 : Math.Max(0, FileSize - UsedInside); }
        }
    }

    // Finds WSL and Docker disk files, clears caches inside a distribution, and compacts disk files.
    // These disk files grow when Linux needs space but never shrink by themselves.
    static class VirtualDisks
    {
        // wsl.exe parses its own command line and keeps quotes as part of a distribution name, so names
        // (which cannot contain spaces) are passed without them.
        static readonly string Wsl = Path.Combine(Environment.SystemDirectory, "wsl.exe");
        static readonly string DiskPart = Path.Combine(Environment.SystemDirectory, "diskpart.exe");

        public static bool IsElevated
        {
            get { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
        }

        public static bool IsDiskFile(string name)
        {
            return name.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".vhd", StringComparison.OrdinalIgnoreCase);
        }

        public static List<VirtualDisk> Find()
        {
            var disks = new List<VirtualDisk>();
            using (RegistryKey lxss = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Lxss"))
            {
                if (lxss != null)
                {
                    foreach (string id in lxss.GetSubKeyNames())
                    {
                        using (RegistryKey k = lxss.OpenSubKey(id))
                        {
                            if (k == null) continue;
                            var name = k.GetValue("DistributionName") as string;
                            var basePath = k.GetValue("BasePath") as string;
                            if (name == null || basePath == null) continue;
                            if (basePath.StartsWith(@"\\?\", StringComparison.Ordinal)) basePath = basePath.Substring(4);
                            string path = Path.Combine(basePath, k.GetValue("VhdFileName") as string ?? "ext4.vhdx");
                            if (!File.Exists(path)) continue;  // WSL 1 distributions keep plain files, not a disk
                            disks.Add(new VirtualDisk { Name = name, Distro = name, Path = path, Kind = DiskKind.WslDistro });
                        }
                    }
                }
            }
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            foreach (string relative in new[] { @"Docker\wsl\disk\docker_data.vhdx", @"Docker\wsl\data\ext4.vhdx" })
            {
                string path = Path.Combine(local, relative);
                if (File.Exists(path))
                    disks.Add(new VirtualDisk { Name = "Docker Desktop data", Path = path, Kind = DiskKind.DockerData });
            }
            foreach (VirtualDisk d in disks) d.FileSize = new FileInfo(d.Path).Length;
            disks.Sort((a, b) => b.FileSize.CompareTo(a.FileSize));
            return disks;
        }

        // Asks Linux how much of its file system is in use. Starts the distribution if it is not running.
        public static void QueryUsage(VirtualDisk disk, Action<string> log)
        {
            if (!disk.IsUserDistro) return;
            string output;
            int code = Run(Wsl, "-d " + disk.Distro + " -- df -B1 --output=used /", null, null, out output);
            string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            long used;
            if (code == 0 && lines.Length >= 2 && long.TryParse(lines[lines.Length - 1].Trim(), out used)) disk.UsedInside = used;
            else log("Could not read the space used inside " + disk.Name + " (exit code " + code + "): " + output.Trim());
        }

        // Runs as the distribution's normal user. Each tool is only used if it is installed.
        const string UserCleanup =
            "export NVM_DIR=\"$HOME/.nvm\"; [ -s \"$NVM_DIR/nvm.sh\" ] && . \"$NVM_DIR/nvm.sh\" >/dev/null 2>&1\n" +
            "export PNPM_HOME=\"$HOME/.local/share/pnpm\"\n" +
            "export PATH=\"$PNPM_HOME:$HOME/.local/bin:$HOME/go/bin:/usr/local/go/bin:$PATH\"\n" +
            "cd \"$HOME\" || exit 1   # pnpm uses the store on the current drive, so stay on the Linux disk\n" +
            "step() { echo; echo \"== $1\"; }\n" +
            "if command -v pnpm >/dev/null; then step 'pnpm store (packages no project uses)'; pnpm store prune 2>&1 | tail -n 3; fi\n" +
            "if command -v npm >/dev/null; then step 'npm cache'; npm cache clean --force 2>&1 | grep -v '^npm warn'; echo done; fi\n" +
            "if command -v yarn >/dev/null; then step 'yarn cache'; yarn cache clean 2>&1 | tail -n 1; fi\n" +
            "if command -v go >/dev/null; then step 'Go module and build caches'; go clean -modcache -cache 2>&1; echo done; fi\n" +
            "if command -v pip3 >/dev/null; then step 'pip cache'; pip3 cache purge 2>&1 | tail -n 1; fi\n";

        const string RootCleanup =
            "if command -v apt-get >/dev/null; then echo; echo '== apt package downloads'; apt-get clean && echo done; fi\n";

        // .NET may start the script's stdin with a UTF-8 byte-order mark (when the console input encoding is UTF-8),
        // which bash would read as part of the first command. wsl runs this through the Linux shell, so sed strips it.
        const string RunScript = " -- sed '1s/^\\xEF\\xBB\\xBF//' | bash -s";

        public static void CleanCaches(VirtualDisk disk, Action<string> log)
        {
            string output;
            Run(Wsl, "-d " + disk.Distro + RunScript, UserCleanup, log, out output);
            Run(Wsl, "-d " + disk.Distro + " -u root" + RunScript, RootCleanup, log, out output);
        }

        // Docker

        static readonly string DockerDesktop = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Docker\Docker\Docker Desktop.exe");

        // docker.exe from PATH, or from Docker Desktop's install folder. Null when Docker is not installed.
        public static string DockerExe
        {
            get
            {
                foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
                {
                    try
                    {
                        string candidate = Path.Combine(dir.Trim().Trim('"'), "docker.exe");
                        if (dir.Trim().Length > 0 && File.Exists(candidate)) return candidate;
                    }
                    catch (ArgumentException) { }
                }
                string bundled = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    @"Docker\Docker\resources\bin\docker.exe");
                return File.Exists(bundled) ? bundled : null;
            }
        }

        public static bool DockerRunning(string docker)
        {
            string output;
            return Run(docker, "info --format {{.ServerVersion}}", null, null, out output) == 0;
        }

        // Starts Docker Desktop if needed and waits for its engine to answer. Returns false if it does not within 3 minutes.
        public static bool EnsureDockerRunning(string docker, Action<string> log)
        {
            if (DockerRunning(docker)) return true;
            if (!File.Exists(DockerDesktop))
            {
                log("Docker is not running, and Docker Desktop was not found to start it.");
                return false;
            }
            log("Starting Docker Desktop (this can take a minute)...");
            Process.Start(new ProcessStartInfo(DockerDesktop) { UseShellExecute = true });
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < TimeSpan.FromMinutes(3))
            {
                System.Threading.Thread.Sleep(3000);
                if (DockerRunning(docker))
                {
                    log("Docker is running.");
                    return true;
                }
            }
            log("Docker did not start within 3 minutes.");
            return false;
        }

        public static void DockerDiskUsage(string docker, Action<string> log)
        {
            string output;
            Run(docker, "system df", null, log, out output);
        }

        // Removes stopped containers, unused networks, dangling images and build cache. With allImages, also every
        // image no container uses; with volumes, also volumes no container uses (which can hold data).
        public static bool DockerPrune(string docker, bool allImages, bool volumes, Action<string> log)
        {
            string output;
            string args = "system prune --force" + (allImages ? " --all" : "") + (volumes ? " --volumes" : "");
            log("> docker " + args);
            return Run(docker, args, null, log, out output) == 0;
        }

        // Tells the disk which blocks Linux no longer uses, so compacting can release them.
        public static void Trim(VirtualDisk disk, Action<string> log)
        {
            string output;
            log("Marking free space inside " + disk.Name + "...");
            Run(Wsl, "-d " + disk.Distro + " -u root -- fstrim -v /", null, log, out output);
        }

        public static void Shutdown(Action<string> log)
        {
            string output;
            log("Shutting down WSL...");
            Run(Wsl, "--shutdown", null, log, out output);
            System.Threading.Thread.Sleep(3000);  // give WSL a moment to let go of the disk files
        }

        // Moves a distribution's disk to another folder (WSL 2.3 or later). WSL must be shut down first.
        public static bool MoveDistro(string distro, string folder, Action<string> log)
        {
            string output;
            log("Moving " + distro + " to " + folder + "...");
            // wsl.exe can keep quotes as part of a value (see Wsl above), so they are only added when needed.
            string target = folder.IndexOf(' ') >= 0 ? Quote(folder) : folder;
            return Run(Wsl, "--manage " + distro + " --move " + target, null, log, out output) == 0;
        }

        // Compacts with diskpart, which needs administrator rights. Asks for them through UAC when needed.
        public static bool CompactAsAdmin(string path, Action<string> log)
        {
            log("Compacting " + path + " (this can take several minutes)...");
            if (IsElevated) return Compact(path, log);
            string logFile = Path.GetTempFileName();
            try
            {
                Process p = Process.Start(new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,
                    "--compact-vhdx " + Quote(logFile) + " " + Quote(path)) { UseShellExecute = true, Verb = "runas" });
                p.WaitForExit();
                foreach (string line in File.ReadAllLines(logFile)) log(line);
                return p.ExitCode == 0;
            }
            catch (Win32Exception)
            {
                log("Administrator rights were not given, so the disk was not compacted.");
                return false;
            }
            finally
            {
                File.Delete(logFile);
            }
        }

        // The elevated half of CompactAsAdmin: DiskSpaceAnalyzer.exe --compact-vhdx <log file> <disk file>
        public static int CompactHelper(string[] args)
        {
            using (var w = new StreamWriter(args[1], true))
            {
                bool ok = Compact(args[2], line => { lock (w) w.WriteLine(line); });
                return ok ? 0 : 1;
            }
        }

        static bool Compact(string path, Action<string> log)
        {
            string output;
            int code = DiskPartScript(new[] { "select vdisk file=" + Quote(path), "attach vdisk readonly", "compact vdisk", "detach vdisk" }, log, out output);
            // If compacting failed after the disk was attached, make sure it is not left attached,
            // or WSL could not open it afterwards.
            if (code != 0) DiskPartScript(new[] { "select vdisk file=" + Quote(path), "detach vdisk noerr" }, null, out output);
            return code == 0;
        }

        static int DiskPartScript(string[] lines, Action<string> log, out string output)
        {
            string script = Path.GetTempFileName();
            try
            {
                File.WriteAllLines(script, lines, Encoding.Default);
                return Run(DiskPart, "/s " + Quote(script), null, log, out output);
            }
            finally
            {
                File.Delete(script);
            }
        }

        static int Run(string exe, string args, string input, Action<string> log, out string output)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,  // a GUI process has no console stdin, and wsl.exe fails without one
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            psi.EnvironmentVariables["WSL_UTF8"] = "1";  // wsl.exe's own messages are UTF-16 otherwise
            var text = new StringBuilder();
            using (var p = new Process { StartInfo = psi })
            {
                DataReceivedEventHandler onLine = (s, e) =>
                {
                    if (e.Data == null) return;
                    lock (text) text.AppendLine(e.Data);
                    if (log != null && e.Data.Trim().Length > 0) log(e.Data);
                };
                p.OutputDataReceived += onLine;
                p.ErrorDataReceived += onLine;
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                if (input != null) p.StandardInput.Write(input);  // bash reads the script from stdin, so no quoting is involved
                p.StandardInput.Close();
                p.WaitForExit();
                lock (text) output = text.ToString();
                return p.ExitCode;
            }
        }

        static string Quote(string s)
        {
            return "\"" + s + "\"";
        }
    }
}

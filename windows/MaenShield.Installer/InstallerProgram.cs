using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

namespace MaenShield.Installer
{
    internal static class InstallerProgram
    {
        private const string AppVersion = "1.1.1.10-windows";
        private const string TaskName = "Maen Shield\\Daily Intelligence Update";

        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            var silent = args != null && args.Any(x => string.Equals(x, "/silent", StringComparison.OrdinalIgnoreCase));
            var verifyOnly = args != null && args.Any(x => string.Equals(x, "/verify-only", StringComparison.OrdinalIgnoreCase));
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MaenShield", "Windows");
            if (verifyOnly)
            {
                try
                {
                    VerifyPayload();
                    Console.WriteLine("WINDOWS_INSTALLER_PAYLOAD_OK");
                    Environment.Exit(0);
                    return;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("WINDOWS_INSTALLER_PAYLOAD_FAILED: " + ex.Message);
                    Environment.Exit(1);
                    return;
                }
            }
            try
            {
                if (!silent)
                {
                    var answer = MessageBox.Show(
                        "Maen Shield for Windows " + AppVersion + " will be installed for the current Windows user.\n\nNo administrator permission is required.",
                        "Maen Shield Installer",
                        MessageBoxButtons.OKCancel,
                        MessageBoxIcon.Information);
                    if (answer != DialogResult.OK) return;
                }

                ExtractPayload(root);
                var executable = Path.Combine(root, "MaenShield.Windows.exe");
                InstallDailyTask(executable);

                if (!silent)
                {
                    MessageBox.Show(
                        "Installation completed. Maen Shield will check the signed GitHub intelligence package daily at 03:17 local time.",
                        "Maen Shield",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }

                Process.Start(new ProcessStartInfo
                {
                    FileName = executable,
                    UseShellExecute = true,
                    WorkingDirectory = root
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Installation failed safely. No threat file was deleted.\n\n" + ex.Message,
                    "Maen Shield Installer",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private static void VerifyPayload()
        {
            var required = new[]
            {
                "MaenShield.Windows.exe",
                "MaenShield.Core.dll",
                "MaenShield.Infrastructure.dll",
                "aman-threat-db-public.pem"
            };
            using (var resource = OpenPayload())
            using (var archive = new ZipArchive(resource, ZipArchiveMode.Read, false))
            {
                var names = archive.Entries.Select(x => x.FullName).ToArray();
                foreach (var file in required)
                    if (!names.Any(x => string.Equals(x, file, StringComparison.OrdinalIgnoreCase)))
                        throw new InvalidDataException("Installer payload is missing " + file + ".");
            }
        }

        private static void ExtractPayload(string root)
        {
            Directory.CreateDirectory(root);
            var rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            using (var resource = OpenPayload())
            using (var archive = new ZipArchive(resource, ZipArchiveMode.Read, false))
            {
                foreach (var entry in archive.Entries)
                {
                    var relative = entry.FullName.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
                    if (string.IsNullOrWhiteSpace(relative)) continue;
                    var destination = Path.GetFullPath(Path.Combine(root, relative));
                    if (!destination.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Unsafe installer payload path.");
                    if (string.IsNullOrEmpty(entry.Name))
                    {
                        Directory.CreateDirectory(destination);
                        continue;
                    }
                    Directory.CreateDirectory(Path.GetDirectoryName(destination));
                    using (var input = entry.Open())
                    using (var output = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        input.CopyTo(output);
                    }
                }
            }
        }

        private static Stream OpenPayload()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var name = assembly.GetManifestResourceNames().FirstOrDefault(x => x.EndsWith("InstallerPayload.zip", StringComparison.OrdinalIgnoreCase));
            if (name == null) throw new FileNotFoundException("Embedded installer payload is missing.");
            var stream = assembly.GetManifestResourceStream(name);
            if (stream == null) throw new FileNotFoundException("Embedded installer payload cannot be opened.");
            return stream;
        }

        private static void InstallDailyTask(string executable)
        {
            var arguments = "/Create /SC DAILY /TN \"" + TaskName + "\" /TR \"\\\"" + executable + "\\\" --update-only\" /ST 03:17 /F /RL LIMITED";
            using (var process = Process.Start(new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            }))
            {
                if (process == null) throw new InvalidOperationException("Task Scheduler could not start.");
                process.WaitForExit(15000);
                if (!process.HasExited || process.ExitCode != 0)
                    throw new InvalidOperationException("Daily update task could not be registered.");
            }
        }
    }
}

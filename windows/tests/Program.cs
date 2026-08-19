using MaenShield.Core;
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace MaenShield.Windows.Tests
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                var sample = args != null && args.Length > 0 ? args[0] : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AmanSecurity_cloud_sample");
                var package = Directory.Exists(Path.Combine(sample, "package")) ? Path.Combine(sample, "package") : sample;
                var manifestPath = Path.Combine(package, "manifest.json");
                if (!File.Exists(manifestPath)) throw new InvalidDataException("Sample manifest.json was not found: " + manifestPath);
                var snapshot = ThreatDatabaseLoader.LoadForWindows(package);
                Assert(snapshot != null, "database loaded");
                Assert(snapshot.Manifest.Schema == 1, "schema=1");
                Assert(snapshot.Manifest.Files.Count == 9, "nine required files");
                Assert(snapshot.MalwareFileHashes.Count >= 0, "malware index readable");
                Assert(snapshot.PackageIndicators.Count >= 0, "APK indicators readable");
                Assert(snapshot.DetectionRules.Count >= 0, "detection rules readable");

                var temp = Path.Combine(Path.GetTempPath(), "maenshield-tests-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(temp);
                try
                {
                    var safe = Path.Combine(temp, "normal.txt");
                    File.WriteAllText(safe, "This is a normal legal document.");
                    var scanner = new FileScanner(snapshot, ScanOptions.Default);
                    var safeResult = scanner.ScanPath(safe, null, () => false);
                    Assert(safeResult.ThreatFiles == 0, "safe file no confirmed threat");
                    Assert(safeResult.Findings.All(x => x.Severity != FindingSeverity.Confirmed), "safe file no confirmed finding");

                    var zip = Path.Combine(temp, "legal-archive.zip");
                    using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
                    {
                        var entry = archive.CreateEntry("readme.txt");
                        using (var writer = new StreamWriter(entry.Open())) writer.Write("legal archive content");
                    }
                    var zipResult = scanner.ScanPath(zip, null, () => false);
                    Assert(zipResult.ThreatFiles == 0, "legal archive no confirmed threat");

                    var unknown = UrlScanner.Scan("https://example.invalid/normal", snapshot);
                    Assert(unknown.Finding.Severity == FindingSeverity.Safe, "unknown URL is not escalated to red");
                }
                finally
                {
                    try { Directory.Delete(temp, true); } catch { }
                }
                Console.WriteLine("WINDOWS_CORE_TESTS_OK");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("WINDOWS_CORE_TESTS_FAILED: " + ex.Message);
                return 1;
            }
        }

        private static void Assert(bool condition, string name)
        {
            if (!condition) throw new InvalidOperationException("Assertion failed: " + name);
            Console.WriteLine("PASS " + name);
        }
    }
}

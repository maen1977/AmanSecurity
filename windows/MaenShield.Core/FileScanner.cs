using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MaenShield.Core
{
    public sealed class FileScanner
    {
        private readonly ThreatDatabaseSnapshot database;
        private readonly ScanOptions options;

        public FileScanner(ThreatDatabaseSnapshot database, ScanOptions options)
        {
            this.database = database;
            this.options = options ?? ScanOptions.Default;
        }

        public ScanSummary ScanPath(string path, Action<string, int, long> progress, Func<bool> cancellation)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A path is required.", "path");
            var summary = new ScanSummary { Target = path };
            var started = DateTime.UtcNow;
            if (File.Exists(path))
            {
                ScanOneFile(path, summary, progress, cancellation, 0);
            }
            else if (Directory.Exists(path))
            {
                foreach (var file in EnumerateFilesSafe(path, cancellation))
                {
                    if (IsCancelled(cancellation)) break;
                    ScanOneFile(file, summary, progress, cancellation, 0);
                }
            }
            else
            {
                throw new FileNotFoundException("The scan target does not exist.", path);
            }
            summary.Duration = DateTime.UtcNow - started;
            return summary;
        }

        private void ScanOneFile(string path, ScanSummary summary, Action<string, int, long> progress, Func<bool> cancellation, int archiveDepth)
        {
            if (IsCancelled(cancellation)) return;
            FileInfo info;
            try { info = new FileInfo(path); }
            catch { return; }
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0) return;
            if (info.Length > options.MaxFileBytes)
            {
                summary.ScannedFiles++;
                summary.ReviewFiles++;
                summary.Findings.Add(new ScanFinding
                {
                    Path = path,
                    Severity = FindingSeverity.Review,
                    Source = FindingSource.StaticHeuristic,
                    Reason = "The file was not fully inspected because it exceeds the configured size limit.",
                    Confidence = 20,
                    CanQuarantine = false
                });
                return;
            }

            string hash;
            try { hash = Hashing.Sha256File(path); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }
            summary.ScannedFiles++;
            summary.ScannedBytes += info.Length;
            progress?.Invoke(path, summary.ScannedFiles, summary.ScannedBytes);

            var finding = EvaluateFile(path, hash);
            if (finding == null && options.UseStaticHeuristics)
            {
                finding = EvaluateStaticHeuristics(path);
            }
            if (finding != null)
            {
                summary.Findings.Add(finding);
                if (finding.Severity >= FindingSeverity.Suspicious) summary.ThreatFiles++;
                else if (finding.Severity == FindingSeverity.Review) summary.ReviewFiles++;
            }
            else
            {
                summary.SafeFiles++;
            }

            if (options.IncludeArchives && options.InspectArchiveMembers && archiveDepth < options.MaxArchiveDepth && IsZipLike(path))
            {
                ScanArchive(path, summary, progress, cancellation, archiveDepth + 1);
            }
        }

        private ScanFinding EvaluateFile(string path, string hash)
        {
            if (ThreatDatabaseQueries.IsKnownFile(database, hash))
            {
                return NewFinding(path, hash, FindingSeverity.Confirmed, FindingSource.MalwareHash, "The file SHA-256 matches a confirmed malware indicator.", 100, true);
            }
            var package = ThreatDatabaseQueries.FindPackageIndicator(database, hash);
            if (package != null)
            {
                return NewFinding(path, hash, FindingSeverity.Confirmed, FindingSource.PackageIndicator, "The file matches a reviewed package or signer identity indicator: " + package.Identifier, 98, true);
            }
            return null;
        }

        private ScanFinding EvaluateStaticHeuristics(string path)
        {
            var extension = Path.GetExtension(path).ToLowerInvariant();
            if (extension == ".txt" || extension == ".jpg" || extension == ".jpeg" || extension == ".png" || extension == ".gif" || extension == ".mp3" || extension == ".mp4" || extension == ".pdf")
            {
                return null;
            }
            byte[] prefix;
            try { prefix = Hashing.ReadPrefix(path, 4 * 1024 * 1024); }
            catch { return null; }
            if (prefix.Length < 2) return null;
            var ascii = Encoding.ASCII.GetString(prefix);
            var markers = new[]
            {
                "powershell -enc", "powershell.exe -e", "frombase64string", "wscript.shell",
                "mshta.exe", "rundll32.exe", "createprocess", "createremotethread", "virtualalloc"
            };
            var matches = markers.Where(x => ascii.IndexOf(x, StringComparison.OrdinalIgnoreCase) >= 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (matches.Count < 2) return null;
            return new ScanFinding
            {
                Path = path,
                Severity = FindingSeverity.Review,
                Source = FindingSource.StaticHeuristic,
                Reason = "The file contains multiple execution-related markers and requires review; no automatic deletion was performed.",
                Confidence = Math.Min(75, 35 + matches.Count * 8),
                CanQuarantine = true
            };
        }

        private void ScanArchive(string path, ScanSummary summary, Action<string, int, long> progress, Func<bool> cancellation, int depth)
        {
            try
            {
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (var archive = new ZipArchive(stream, ZipArchiveMode.Read, false))
                {
                    foreach (var entry in archive.Entries)
                    {
                        if (IsCancelled(cancellation)) return;
                        if (string.IsNullOrEmpty(entry.Name) || entry.Length > options.MaxFileBytes) continue;
                        string hash;
                        using (var entryStream = entry.Open())
                        using (var sha = SHA256.Create())
                        {
                            hash = Hashing.ToHex(sha.ComputeHash(entryStream));
                        }
                        var virtualPath = path + "!" + entry.FullName;
                        var finding = EvaluateFile(virtualPath, hash);
                        if (finding != null)
                        {
                            finding.Source = FindingSource.ArchiveMember;
                            finding.Reason = "An archive member matches a confirmed indicator; the container itself is not labeled by format alone.";
                            summary.Findings.Add(finding);
                            summary.ThreatFiles++;
                        }
                        if (entry.Length <= 4L * 1024L * 1024L && IsZipName(entry.FullName) && depth < options.MaxArchiveDepth)
                        {
                            // Nested archive extraction is intentionally deferred in v1 to avoid writing untrusted members to disk.
                        }
                    }
                }
            }
            catch (InvalidDataException)
            {
                // A non-ZIP extension or malformed archive is not itself a threat.
            }
            catch (IOException)
            {
                // A file can disappear or be locked during a scan; keep the scan conservative.
            }
            catch (UnauthorizedAccessException)
            {
                // Access failures do not become malware verdicts.
            }
        }

        private static ScanFinding NewFinding(string path, string hash, FindingSeverity severity, FindingSource source, string reason, int confidence, bool quarantine)
        {
            return new ScanFinding
            {
                Path = path,
                Sha256 = hash,
                Severity = severity,
                Source = source,
                Reason = reason,
                Confidence = confidence,
                CanQuarantine = quarantine
            };
        }

        private static IEnumerable<string> EnumerateFilesSafe(string root, Func<bool> cancellation)
        {
            var pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                if (IsCancelled(cancellation)) yield break;
                var directory = pending.Pop();
                string[] files = new string[0];
                string[] directories = new string[0];
                try
                {
                    files = Directory.GetFiles(directory);
                    directories = Directory.GetDirectories(directory);
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
                foreach (var file in files) yield return file;
                foreach (var child in directories.Reverse())
                {
                    try
                    {
                        if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) == 0) pending.Push(child);
                    }
                    catch { }
                }
            }
        }

        private static bool IsZipLike(string path)
        {
            var extension = Path.GetExtension(path).ToLowerInvariant();
            return extension == ".zip" || extension == ".jar" || extension == ".apk" || extension == ".xapk" || extension == ".apkm" || HasZipMagic(path);
        }

        private static bool IsZipName(string name)
        {
            var extension = Path.GetExtension(name).ToLowerInvariant();
            return extension == ".zip" || extension == ".jar" || extension == ".apk" || extension == ".xapk" || extension == ".apkm";
        }

        private static bool HasZipMagic(string path)
        {
            try
            {
                var prefix = Hashing.ReadPrefix(path, 4);
                return prefix.Length >= 4 && prefix[0] == 0x50 && prefix[1] == 0x4b && prefix[2] == 0x03 && prefix[3] == 0x04;
            }
            catch { return false; }
        }

        private static bool IsCancelled(Func<bool> cancellation)
        {
            return cancellation != null && cancellation();
        }
    }
}

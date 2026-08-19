using System;
using System.Collections.Generic;

namespace MaenShield.Core
{
    public enum FindingSeverity
    {
        Safe = 0,
        Review = 1,
        Suspicious = 2,
        Confirmed = 3
    }

    public enum FindingSource
    {
        None = 0,
        MalwareHash = 1,
        UrlHost = 2,
        C2Host = 3,
        DetectionRule = 4,
        StaticHeuristic = 5,
        ArchiveMember = 6,
        PackageIndicator = 7,
        UpdateIntegrity = 8
    }

    public sealed class ScanFinding
    {
        public string Path { get; set; }
        public string Sha256 { get; set; }
        public FindingSeverity Severity { get; set; }
        public FindingSource Source { get; set; }
        public string RuleId { get; set; }
        public string Reason { get; set; }
        public int Confidence { get; set; }
        public bool CanQuarantine { get; set; }
        public List<string> Evidence { get; private set; }

        public ScanFinding()
        {
            Evidence = new List<string>();
            Confidence = 0;
        }
    }

    public sealed class ScanSummary
    {
        public string Target { get; set; }
        public int ScannedFiles { get; set; }
        public long ScannedBytes { get; set; }
        public int SafeFiles { get; set; }
        public int ReviewFiles { get; set; }
        public int ThreatFiles { get; set; }
        public TimeSpan Duration { get; set; }
        public List<ScanFinding> Findings { get; private set; }

        public ScanSummary()
        {
            Findings = new List<ScanFinding>();
        }
    }

    public sealed class ScanOptions
    {
        public bool IncludeArchives { get; set; }
        public bool InspectArchiveMembers { get; set; }
        public int MaxArchiveDepth { get; set; }
        public long MaxFileBytes { get; set; }
        public long MaxArchiveBytes { get; set; }
        public bool UseStaticHeuristics { get; set; }

        public static ScanOptions Default
        {
            get
            {
                return new ScanOptions
                {
                    IncludeArchives = true,
                    InspectArchiveMembers = true,
                    MaxArchiveDepth = 2,
                    MaxFileBytes = 256L * 1024L * 1024L,
                    MaxArchiveBytes = 512L * 1024L * 1024L,
                    UseStaticHeuristics = true
                };
            }
        }
    }

    public sealed class ThreatFileMeta
    {
        public string Name { get; set; }
        public string Sha256 { get; set; }
        public int Entries { get; set; }
        public long Bytes { get; set; }
    }

    public sealed class ThreatSourceMeta
    {
        public string Name { get; set; }
        public bool Ok { get; set; }
        public int Count { get; set; }
        public string Detail { get; set; }
    }

    public sealed class ThreatManifest
    {
        public int Schema { get; set; }
        public long Serial { get; set; }
        public string Version { get; set; }
        public DateTime GeneratedAtUtc { get; set; }
        public int MinAppVersionCode { get; set; }
        public string BundlePath { get; set; }
        public string BundleSha256 { get; set; }
        public long BundleBytes { get; set; }
        public Dictionary<string, ThreatFileMeta> Files { get; private set; }
        public List<ThreatSourceMeta> Sources { get; private set; }

        public ThreatManifest()
        {
            Files = new Dictionary<string, ThreatFileMeta>(StringComparer.Ordinal);
            Sources = new List<ThreatSourceMeta>();
        }
    }

    public sealed class ThreatDatabaseSnapshot
    {
        public string RootDirectory { get; private set; }
        public ThreatManifest Manifest { get; private set; }
        public HashSet<string> MalwareFileHashes { get; private set; }
        public HashSet<string> PhishingHashes { get; private set; }
        public HashSet<string> MalwareUrlHosts { get; private set; }
        public HashSet<string> C2Hosts { get; private set; }
        public Dictionary<string, PackageIndicator> PackageIndicators { get; private set; }
        public List<DetectionRule> DetectionRules { get; private set; }

        public ThreatDatabaseSnapshot(string rootDirectory, ThreatManifest manifest)
        {
            RootDirectory = rootDirectory;
            Manifest = manifest;
            MalwareFileHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            PhishingHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            MalwareUrlHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            C2Hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            PackageIndicators = new Dictionary<string, PackageIndicator>(StringComparer.OrdinalIgnoreCase);
            DetectionRules = new List<DetectionRule>();
        }
    }

    public sealed class PackageIndicator
    {
        public string Kind { get; set; }
        public string Sha256 { get; set; }
        public string Identifier { get; set; }
        public string Classification { get; set; }
    }

    public sealed class DetectionRule
    {
        public string Id { get; set; }
        public string Kind { get; set; }
        public string Value { get; set; }
        public string Classification { get; set; }
        public int Confidence { get; set; }
        public string Description { get; set; }
    }

    public sealed class CloudUpdateResult
    {
        public bool Updated { get; set; }
        public bool UsedExistingDatabase { get; set; }
        public string Version { get; set; }
        public string Detail { get; set; }
        public long BytesDownloaded { get; set; }
    }
}

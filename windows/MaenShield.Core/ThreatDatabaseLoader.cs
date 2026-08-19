using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace MaenShield.Core
{
    public static class ThreatDatabaseLoader
    {
        public static ThreatDatabaseSnapshot Load(string rootDirectory, int appVersionCode)
        {
            return LoadInternal(rootDirectory, bytes => ThreatManifestParser.Parse(bytes, appVersionCode));
        }

        public static ThreatDatabaseSnapshot LoadForWindows(string rootDirectory)
        {
            return LoadInternal(rootDirectory, ThreatManifestParser.ParseForWindows);
        }

        private static ThreatDatabaseSnapshot LoadInternal(string rootDirectory, Func<byte[], ThreatManifest> parseManifest)
        {
            if (string.IsNullOrWhiteSpace(rootDirectory) || !Directory.Exists(rootDirectory))
            {
                throw new DirectoryNotFoundException("Threat database directory does not exist.");
            }
            var manifestPath = Path.Combine(rootDirectory, "manifest.json");
            if (!File.Exists(manifestPath))
            {
                throw new FileNotFoundException("Threat database manifest is missing.", manifestPath);
            }
            var manifest = parseManifest(File.ReadAllBytes(manifestPath));
            foreach (var file in manifest.Files.Values)
            {
                var path = Path.Combine(rootDirectory, file.Name);
                if (!File.Exists(path))
                {
                    throw new FileNotFoundException("Threat database file is missing.", path);
                }
                var info = new FileInfo(path);
                if (info.Length != file.Bytes)
                {
                    throw new InvalidDataException("Threat database file size does not match manifest: " + file.Name);
                }
                var actualHash = Hashing.Sha256File(path);
                if (!string.Equals(actualHash, file.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Threat database file hash does not match manifest: " + file.Name);
                }
            }

            var snapshot = new ThreatDatabaseSnapshot(rootDirectory, manifest);
            LoadHashSet(snapshot.MalwareFileHashes, rootDirectory, "malware_files.sha256", manifest.Files["malware_files.sha256"].Entries);
            LoadHashSet(snapshot.PhishingHashes, rootDirectory, "phishing_primary.sha256", manifest.Files["phishing_primary.sha256"].Entries);
            LoadHashSet(snapshot.PhishingHashes, rootDirectory, "phishing_openphish.sha256", manifest.Files["phishing_openphish.sha256"].Entries);
            LoadHashSet(snapshot.PhishingHashes, rootDirectory, "phishing_community.sha256", manifest.Files["phishing_community.sha256"].Entries);
            LoadHashSet(snapshot.MalwareUrlHosts, rootDirectory, "malware_url_hosts.sha256", manifest.Files["malware_url_hosts.sha256"].Entries);
            LoadHashSet(snapshot.C2Hosts, rootDirectory, "c2_hosts.sha256", manifest.Files["c2_hosts.sha256"].Entries);
            LoadPackageIndicators(snapshot, Path.Combine(rootDirectory, "apk_indicators.csv"), manifest.Files["apk_indicators.csv"].Entries);
            LoadDetectionRules(snapshot, Path.Combine(rootDirectory, "detection_rules.csv"), manifest.Files["detection_rules.csv"].Entries);
            return snapshot;
        }

        private static void LoadHashSet(HashSet<string> target, string root, string name, int expectedEntries)
        {
            var count = 0;
            foreach (var raw in File.ReadLines(Path.Combine(root, name), Encoding.UTF8))
            {
                var value = (raw ?? string.Empty).Trim();
                if (value.Length == 0) continue;
                if (!Hashing.IsSha256(value)) throw new InvalidDataException("Invalid hash entry in " + name);
                target.Add(value.ToLowerInvariant());
                count++;
            }
            if (count != expectedEntries) throw new InvalidDataException("Entry count does not match manifest: " + name);
        }

        private static void LoadPackageIndicators(ThreatDatabaseSnapshot snapshot, string path, int expectedEntries)
        {
            var count = 0;
            foreach (var raw in File.ReadLines(path, Encoding.UTF8))
            {
                var fields = SplitPipe(raw);
                if (fields.Length == 0) continue;
                if (fields.Length != 4 || (fields[0] != "PACKAGE" && fields[0] != "SIGNER") || !Hashing.IsSha256(fields[1]))
                {
                    throw new InvalidDataException("Invalid APK indicator row.");
                }
                snapshot.PackageIndicators[fields[1].ToLowerInvariant()] = new PackageIndicator
                {
                    Kind = fields[0],
                    Sha256 = fields[1].ToLowerInvariant(),
                    Identifier = fields[2],
                    Classification = fields[3]
                };
                count++;
            }
            if (count != expectedEntries) throw new InvalidDataException("Entry count does not match manifest: apk_indicators.csv");
        }

        private static void LoadDetectionRules(ThreatDatabaseSnapshot snapshot, string path, int expectedEntries)
        {
            var count = 0;
            foreach (var raw in File.ReadLines(path, Encoding.UTF8))
            {
                var fields = SplitPipe(raw);
                if (fields.Length == 0) continue;
                var kind = fields[0];
                if (kind == "RULE")
                {
                    if (fields.Length != 7) throw new InvalidDataException("Invalid RULE row.");
                    int weight;
                    if (!int.TryParse(fields[4], out weight) || weight < 1 || weight > 100)
                    {
                        throw new InvalidDataException("Invalid RULE weight.");
                    }
                    snapshot.DetectionRules.Add(new DetectionRule
                    {
                        Id = fields[1],
                        Kind = fields[2],
                        Classification = fields[3],
                        Confidence = weight,
                        Description = fields[5],
                        Value = fields[6]
                    });
                }
                else if (kind == "BRAND")
                {
                    if (fields.Length != 4 || string.IsNullOrWhiteSpace(fields[1]) || string.IsNullOrWhiteSpace(fields[2]) || string.IsNullOrWhiteSpace(fields[3]))
                    {
                        throw new InvalidDataException("Invalid BRAND row.");
                    }
                    snapshot.DetectionRules.Add(new DetectionRule
                    {
                        Id = fields[1],
                        Kind = kind,
                        Classification = "SAFE_REFERENCE",
                        Confidence = 0,
                        Description = "Protected brand profile; not a malware verdict by itself.",
                        Value = fields[2] + "|" + fields[3]
                    });
                }
                else if (kind == "BRAND_SIGNER")
                {
                    if (fields.Length != 3 || !Hashing.IsSha256(fields[2])) throw new InvalidDataException("Invalid BRAND_SIGNER row.");
                    snapshot.DetectionRules.Add(new DetectionRule
                    {
                        Id = fields[1],
                        Kind = kind,
                        Classification = "SAFE_REFERENCE",
                        Confidence = 0,
                        Description = "Trusted signer reference; not a malware verdict by itself.",
                        Value = fields[2].ToLowerInvariant()
                    });
                }
                else if (kind == "REPUTATION")
                {
                    if (fields.Length != 7 || (fields[1] != "PACKAGE" && fields[1] != "SIGNER") || !Hashing.IsSha256(fields[2]))
                    {
                        throw new InvalidDataException("Invalid REPUTATION row.");
                    }
                    var reputationConfidence = ParseConfidence(fields[5]);
                    if (reputationConfidence < 0) throw new InvalidDataException("Invalid REPUTATION confidence.");
                    snapshot.PackageIndicators[fields[2].ToLowerInvariant()] = new PackageIndicator
                    {
                        Kind = fields[1],
                        Sha256 = fields[2].ToLowerInvariant(),
                        Identifier = fields[3],
                        Classification = fields[4] + ":" + fields[6]
                    };
                    snapshot.DetectionRules.Add(new DetectionRule
                    {
                        Id = fields[3],
                        Kind = kind,
                        Classification = fields[4],
                        Confidence = reputationConfidence,
                        Description = "Reputation record; evaluated only when the exact hash matches.",
                        Value = fields[1] + "|" + fields[2] + "|" + fields[6]
                    });
                }
                else if (kind == "MODEL" || kind == "REASONING")
                {
                    if (fields.Length != 3) throw new InvalidDataException("Invalid " + kind + " row.");
                    double weight;
                    if (!double.TryParse(fields[2], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out weight) || weight < -20.0 || weight > 20.0)
                    {
                        throw new InvalidDataException("Invalid " + kind + " weight.");
                    }
                    snapshot.DetectionRules.Add(new DetectionRule
                    {
                        Id = fields[1],
                        Kind = kind,
                        Classification = "MODEL_DATA",
                        Confidence = 0,
                        Description = "Model metadata; not a malware verdict by itself.",
                        Value = fields[2]
                    });
                }
                else if (kind == "META")
                {
                    if (fields.Length != 7) throw new InvalidDataException("Invalid META row.");
                    var metaConfidence = ParseConfidence(fields[4]);
                    if (metaConfidence < 0) throw new InvalidDataException("Invalid META confidence.");
                    snapshot.DetectionRules.Add(new DetectionRule
                    {
                        Id = fields[1],
                        Kind = kind,
                        Classification = fields[3],
                        Confidence = metaConfidence,
                        Description = "Threat metadata; not a verdict without a matching indicator.",
                        Value = fields[2] + "|" + fields[4] + "|" + fields[5] + "|" + fields[6]
                    });
                }
                else if (kind == "LINK")
                {
                    if (fields.Length != 6) throw new InvalidDataException("Invalid LINK row.");
                    var linkConfidence = ParseConfidence(fields[4]);
                    int weight;
                    if (linkConfidence < 0 || !int.TryParse(fields[5], out weight) || weight < 1 || weight > 24)
                    {
                        throw new InvalidDataException("Invalid LINK metadata.");
                    }
                    snapshot.DetectionRules.Add(new DetectionRule
                    {
                        Id = fields[1],
                        Kind = kind,
                        Classification = fields[3],
                        Confidence = linkConfidence,
                        Description = "Threat graph metadata; not a verdict without a matching indicator.",
                        Value = fields[2] + "|" + fields[5]
                    });
                }
                else
                {
                    throw new InvalidDataException("Unsupported detection rule type: " + kind);
                }
                count++;
            }
            if (count != expectedEntries) throw new InvalidDataException("Entry count does not match manifest: detection_rules.csv");
        }

        private static int ParseConfidence(string value)
        {
            switch ((value ?? string.Empty).Trim().ToUpperInvariant())
            {
                case "CONFIRMED": return 100;
                case "CRITICAL": return 100;
                case "HIGH": return 90;
                case "MEDIUM": return 65;
                case "LOW": return 35;
                case "REVIEW": return 40;
                case "SAFE": return 0;
                case "-": return 0;
                case "TEST": return 100;
                default: return -1;
            }
        }

        private static string[] SplitPipe(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return new string[0];
            return raw.Trim().Split(new[] { '|' }, StringSplitOptions.None);
        }
    }

    public static class ThreatDatabaseQueries
    {
        public static bool IsKnownFile(ThreatDatabaseSnapshot database, string sha256)
        {
            return database != null && !string.IsNullOrWhiteSpace(sha256) && database.MalwareFileHashes.Contains(sha256.ToLowerInvariant());
        }

        public static bool IsKnownHost(ThreatDatabaseSnapshot database, string host)
        {
            if (database == null || string.IsNullOrWhiteSpace(host)) return false;
            var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
            var hostHash = Hashing.Sha256Text(normalized);
            return database.MalwareUrlHosts.Contains(hostHash) || database.PhishingHashes.Contains(hostHash) || database.C2Hosts.Contains(hostHash);
        }

        public static bool IsKnownUrl(ThreatDatabaseSnapshot database, string normalizedUrl, string host)
        {
            if (database == null) return false;
            if (IsKnownHost(database, host)) return true;
            if (string.IsNullOrWhiteSpace(normalizedUrl)) return false;
            return database.PhishingHashes.Contains(Hashing.Sha256Text(normalizedUrl.ToLowerInvariant()));
        }

        public static PackageIndicator FindPackageIndicator(ThreatDatabaseSnapshot database, string sha256)
        {
            if (database == null || string.IsNullOrWhiteSpace(sha256)) return null;
            PackageIndicator indicator;
            return database.PackageIndicators.TryGetValue(sha256.ToLowerInvariant(), out indicator) ? indicator : null;
        }
    }
}

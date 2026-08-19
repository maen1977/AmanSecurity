using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Web.Script.Serialization;

namespace MaenShield.Core
{
    [DataContract]
    internal sealed class ManifestDto
    {
        [DataMember(Name = "schema")]
        public int Schema { get; set; }
        [DataMember(Name = "serial")]
        public long Serial { get; set; }
        [DataMember(Name = "version")]
        public string Version { get; set; }
        [DataMember(Name = "generatedAt")]
        public string GeneratedAt { get; set; }
        [DataMember(Name = "minAppVersionCode")]
        public int MinAppVersionCode { get; set; }
        [DataMember(Name = "bundlePath")]
        public string BundlePath { get; set; }
        [DataMember(Name = "bundleSha256")]
        public string BundleSha256 { get; set; }
        [DataMember(Name = "bundleBytes")]
        public long BundleBytes { get; set; }
        [DataMember(Name = "files")]
        public Dictionary<string, FileMetaDto> Files { get; set; }
        [DataMember(Name = "sources")]
        public List<SourceMetaDto> Sources { get; set; }
    }

    [DataContract]
    internal sealed class FileMetaDto
    {
        [DataMember(Name = "sha256")]
        public string Sha256 { get; set; }
        [DataMember(Name = "entries")]
        public int Entries { get; set; }
        [DataMember(Name = "bytes")]
        public long Bytes { get; set; }
    }

    [DataContract]
    internal sealed class SourceMetaDto
    {
        [DataMember(Name = "name")]
        public string Name { get; set; }
        [DataMember(Name = "ok")]
        public bool Ok { get; set; }
        [DataMember(Name = "count")]
        public int Count { get; set; }
        [DataMember(Name = "detail")]
        public string Detail { get; set; }
    }

    public static class ThreatManifestParser
    {
        private static readonly string[] RequiredFiles =
        {
            "malware_files.sha256",
            "phishing_primary.sha256",
            "phishing_openphish.sha256",
            "phishing_community.sha256",
            "malware_url_hosts.sha256",
            "c2_hosts.sha256",
            "android_cves.txt",
            "apk_indicators.csv",
            "detection_rules.csv"
        };

        private const long MaxBundleBytes = 24L * 1024L * 1024L;

        public static ThreatManifest Parse(byte[] bytes, int appVersionCode)
        {
            if (bytes == null || bytes.Length < 2 || bytes.Length > 64 * 1024)
            {
                throw new InvalidDataException("Cloud manifest size is invalid.");
            }

            ManifestDto dto;
            try
            {
                var serializer = new DataContractJsonSerializer(typeof(ManifestDto));
                using (var stream = new MemoryStream(bytes))
                {
                    dto = (ManifestDto)serializer.ReadObject(stream);
                }
            }
            catch (Exception ex)
            {
                throw new InvalidDataException("Cloud manifest JSON is invalid.", ex);
            }

            if (dto != null)
            {
                dto.Files = ReadFilesWithJavaScriptSerializer(bytes);
            }
            if (dto == null || dto.Schema != 1 || dto.Serial < 1 || string.IsNullOrWhiteSpace(dto.Version))
            {
                throw new InvalidDataException("Unsupported cloud threat manifest.");
            }
            if (dto.Version.Length > 64 || dto.MinAppVersionCode < 1 || dto.MinAppVersionCode > 100000)
            {
                throw new InvalidDataException("Cloud manifest version metadata is invalid.");
            }
            if (appVersionCode >= 0 && dto.MinAppVersionCode > appVersionCode)
            {
                throw new InvalidDataException("Cloud threat database requires a newer Maen Shield version.");
            }
            DateTime generatedAt;
            if (!DateTime.TryParse(dto.GeneratedAt, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out generatedAt))
            {
                throw new InvalidDataException("Cloud threat timestamp is invalid.");
            }
            var now = DateTime.UtcNow;
            if (generatedAt <= DateTime.MinValue || generatedAt > now.AddHours(24))
            {
                throw new InvalidDataException("Cloud threat timestamp is outside the accepted window.");
            }
            if (string.IsNullOrWhiteSpace(dto.BundlePath) || !System.Text.RegularExpressions.Regex.IsMatch(dto.BundlePath, "^aman-threat-db-[0-9]+\\.zip$"))
            {
                throw new InvalidDataException("Cloud bundle path is invalid.");
            }
            if (!Hashing.IsSha256(dto.BundleSha256) || dto.BundleBytes < 1 || dto.BundleBytes > MaxBundleBytes)
            {
                throw new InvalidDataException("Cloud bundle metadata is invalid.");
            }
            if (dto.Files == null || dto.Files.Count != RequiredFiles.Length || RequiredFiles.Any(x => !dto.Files.ContainsKey(x)))
            {
                throw new InvalidDataException("Cloud manifest file set is invalid.");
            }

            var manifest = new ThreatManifest
            {
                Schema = dto.Schema,
                Serial = dto.Serial,
                Version = dto.Version,
                GeneratedAtUtc = generatedAt.ToUniversalTime(),
                MinAppVersionCode = dto.MinAppVersionCode,
                BundlePath = dto.BundlePath,
                BundleSha256 = dto.BundleSha256.ToLowerInvariant(),
                BundleBytes = dto.BundleBytes
            };

            foreach (var name in RequiredFiles)
            {
                var file = dto.Files[name];
                if (file == null || !Hashing.IsSha256(file.Sha256) || file.Entries < 0 || file.Bytes < 0 || file.Bytes > MaxBytes(name) || file.Entries > MaxEntries(name))
                {
                    throw new InvalidDataException("Cloud file metadata is invalid: " + name);
                }
                if (name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase) && file.Bytes != file.Entries * 65L)
                {
                    throw new InvalidDataException("Cloud hash file length is inconsistent: " + name);
                }
                manifest.Files[name] = new ThreatFileMeta
                {
                    Name = name,
                    Sha256 = file.Sha256.ToLowerInvariant(),
                    Entries = file.Entries,
                    Bytes = file.Bytes
                };
            }

            if (dto.Sources != null)
            {
                if (dto.Sources.Count > 32)
                {
                    throw new InvalidDataException("Cloud source metadata is too large.");
                }
                foreach (var source in dto.Sources)
                {
                    if (source == null || string.IsNullOrWhiteSpace(source.Name) || source.Name.Length > 64 || source.Count < 0 || source.Count > 2000000 || (source.Detail ?? string.Empty).Length > 240)
                    {
                        throw new InvalidDataException("Cloud source metadata is invalid.");
                    }
                    manifest.Sources.Add(new ThreatSourceMeta
                    {
                        Name = source.Name,
                        Ok = source.Ok,
                        Count = source.Count,
                        Detail = source.Detail ?? string.Empty
                    });
                }
            }
            return manifest;
        }

        public static ThreatManifest ParseForWindows(byte[] bytes)
        {
            return Parse(bytes, -1);
        }

        private static Dictionary<string, FileMetaDto> ReadFilesWithJavaScriptSerializer(byte[] bytes)
        {
            var result = new Dictionary<string, FileMetaDto>(StringComparer.Ordinal);
            var serializer = new JavaScriptSerializer { MaxJsonLength = 256 * 1024 };
            var root = serializer.DeserializeObject(Encoding.UTF8.GetString(bytes)) as Dictionary<string, object>;
            object rawFiles;
            if (root == null || !root.TryGetValue("files", out rawFiles)) return result;
            var files = rawFiles as Dictionary<string, object>;
            if (files == null) return result;
            foreach (var item in files)
            {
                var values = item.Value as Dictionary<string, object>;
                if (values == null) continue;
                object sha256;
                object entries;
                object fileBytes;
                if (!values.TryGetValue("sha256", out sha256) || !values.TryGetValue("entries", out entries) || !values.TryGetValue("bytes", out fileBytes)) continue;
                result[item.Key] = new FileMetaDto
                {
                    Sha256 = sha256 as string,
                    Entries = Convert.ToInt32(entries, System.Globalization.CultureInfo.InvariantCulture),
                    Bytes = Convert.ToInt64(fileBytes, System.Globalization.CultureInfo.InvariantCulture)
                };
            }
            return result;
        }

        private static int MaxEntries(string name)
        {
            switch (name)
            {
                case "malware_files.sha256": return 100000;
                case "phishing_primary.sha256": return 120000;
                case "phishing_openphish.sha256": return 80000;
                case "phishing_community.sha256": return 60000;
                case "malware_url_hosts.sha256": return 200000;
                case "c2_hosts.sha256": return 50000;
                case "android_cves.txt": return 20000;
                case "apk_indicators.csv": return 100000;
                case "detection_rules.csv": return 50000;
                default: return 0;
            }
        }

        private static long MaxBytes(string name)
        {
            if (name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase))
            {
                return MaxEntries(name) * 65L;
            }
            if (name == "apk_indicators.csv") return 8L * 1024L * 1024L;
            if (name == "detection_rules.csv") return 16L * 1024L * 1024L;
            return 2L * 1024L * 1024L;
        }
    }
}

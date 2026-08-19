using MaenShield.Core;
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MaenShield.Infrastructure
{
    public sealed class CloudUpdateService
    {
        public const string DefaultBaseUrl = "https://raw.githubusercontent.com/maen1977/AmanSecurity-Threat-DB/main/latest";
        private const long MaxManifestBytes = 64L * 1024L;
        private const long MaxSignatureBytes = 4096L;
        private const long MaxBundleBytes = 24L * 1024L * 1024L;
        private readonly string storageRoot;
        private readonly string baseUrl;
        private readonly HttpClient httpClient;

        public CloudUpdateService(string storageRoot, int appVersionCode, string baseUrl)
        {
            if (string.IsNullOrWhiteSpace(storageRoot)) throw new ArgumentException("Storage root is required.", "storageRoot");
            this.storageRoot = storageRoot;
            this.baseUrl = string.IsNullOrWhiteSpace(baseUrl) ? DefaultBaseUrl : baseUrl.TrimEnd('/');
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("MaenShield-Windows/1.0");
        }

        public ThreatDatabaseSnapshot LoadActive()
        {
            var active = Path.Combine(storageRoot, "active");
            if (!Directory.Exists(active)) return null;
            try { return ThreatDatabaseLoader.LoadForWindows(active); }
            catch { return null; }
        }

        public async Task<CloudUpdateResult> UpdateAsync(CancellationToken cancellationToken)
        {
            var result = new CloudUpdateResult { UsedExistingDatabase = LoadActive() != null };
            string temp = null;
            try
            {
                Directory.CreateDirectory(storageRoot);
                var manifestBytes = await DownloadBoundedAsync(baseUrl + "/manifest.json", MaxManifestBytes, cancellationToken).ConfigureAwait(false);
                var signatureBytes = await DownloadBoundedAsync(baseUrl + "/manifest.sig", MaxSignatureBytes, cancellationToken).ConfigureAwait(false);
                if (!CloudSignatureVerifier.Verify(manifestBytes, signatureBytes, ResolvePublicKeyPath()))
                {
                    throw new InvalidDataException("Cloud manifest signature verification failed.");
                }
                var manifest = ThreatManifestParser.ParseForWindows(manifestBytes);
                var existing = LoadActive();
                if (existing != null && existing.Manifest != null && existing.Manifest.Serial >= manifest.Serial)
                {
                    result.Version = existing.Manifest.Version;
                    result.Detail = "The active threat database is already current.";
                    return result;
                }

                var bundle = await DownloadBoundedAsync(baseUrl + "/" + manifest.BundlePath, Math.Min(MaxBundleBytes, manifest.BundleBytes + 1), cancellationToken).ConfigureAwait(false);
                if (bundle.LongLength != manifest.BundleBytes || !string.Equals(Hashing.Sha256Bytes(bundle), manifest.BundleSha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Cloud bundle integrity verification failed.");
                }

                temp = Path.Combine(storageRoot, ".incoming-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(temp);
                ExtractZipSafely(bundle, temp);
                File.WriteAllBytes(Path.Combine(temp, "manifest.json"), manifestBytes);
                var extracted = ThreatDatabaseLoader.LoadForWindows(temp);
                if (extracted.Manifest.Serial != manifest.Serial)
                {
                    throw new InvalidDataException("Extracted threat database manifest mismatch.");
                }
                InstallAtomically(temp);
                temp = null;
                result.Updated = true;
                result.UsedExistingDatabase = true;
                result.Version = manifest.Version;
                result.BytesDownloaded = manifest.BundleBytes + manifestBytes.LongLength + signatureBytes.LongLength;
                result.Detail = "Threat database updated and validated atomically.";
                return result;
            }
            catch (OperationCanceledException)
            {
                result.Detail = "Cloud update was cancelled; the existing database remains active.";
                return result;
            }
            catch (Exception ex)
            {
                result.Detail = "Cloud update rejected safely: " + ex.Message;
                return result;
            }
            finally
            {
                if (!string.IsNullOrEmpty(temp)) TryDeleteDirectory(temp);
            }
        }

        private string ResolvePublicKeyPath()
        {
            var beside = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "aman-threat-db-public.pem");
            if (File.Exists(beside)) return beside;
            var resources = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "aman-threat-db-public.pem");
            if (File.Exists(resources)) return resources;
            throw new FileNotFoundException("Cloud public key is missing.", beside);
        }

        private async Task<byte[]> DownloadBoundedAsync(string url, long maxBytes, CancellationToken cancellationToken)
        {
            using (var response = await httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                if (response.Content.Headers.ContentLength.HasValue && response.Content.Headers.ContentLength.Value > maxBytes)
                {
                    throw new InvalidDataException("Cloud response exceeds the configured size limit.");
                }
                using (var input = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                using (var output = new MemoryStream())
                {
                    var buffer = new byte[64 * 1024];
                    long total = 0;
                    int read;
                    while ((read = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
                    {
                        total += read;
                        if (total > maxBytes) throw new InvalidDataException("Cloud response exceeds the configured size limit.");
                        output.Write(buffer, 0, read);
                    }
                    return output.ToArray();
                }
            }
        }

        private static void ExtractZipSafely(byte[] bytes, string destination)
        {
            using (var input = new MemoryStream(bytes, false))
            using (var archive = new ZipArchive(input, ZipArchiveMode.Read, false))
            {
                foreach (var entry in archive.Entries)
                {
                    var normalized = (entry.FullName ?? string.Empty).Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
                    var parts = normalized.Split(new[] { Path.DirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
                    if (string.IsNullOrWhiteSpace(normalized) || Path.IsPathRooted(normalized) || parts.Any(x => x == "." || x == ".."))
                    {
                        throw new InvalidDataException("Cloud archive contains an unsafe path.");
                    }
                    var target = Path.GetFullPath(Path.Combine(destination, normalized));
                    var root = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                    if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Cloud archive path escapes the destination.");
                    if (entry.FullName.EndsWith("/", StringComparison.Ordinal))
                    {
                        Directory.CreateDirectory(target);
                        continue;
                    }
                    Directory.CreateDirectory(Path.GetDirectoryName(target));
                    using (var source = entry.Open())
                    using (var targetStream = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        source.CopyTo(targetStream);
                    }
                }
            }
        }

        private void InstallAtomically(string incoming)
        {
            var active = Path.Combine(storageRoot, "active");
            var backup = Path.Combine(storageRoot, ".previous-" + Guid.NewGuid().ToString("N"));
            if (Directory.Exists(active)) Directory.Move(active, backup);
            try
            {
                Directory.Move(incoming, active);
                TryDeleteDirectory(backup);
            }
            catch
            {
                if (Directory.Exists(active)) TryDeleteDirectory(active);
                if (Directory.Exists(backup)) Directory.Move(backup, active);
                throw;
            }
        }

        private static void TryDeleteDirectory(string path)
        {
            try { if (Directory.Exists(path)) Directory.Delete(path, true); }
            catch { }
        }
    }

    internal static class CloudSignatureVerifier
    {
        public static bool Verify(byte[] manifest, byte[] signature, string pemPath)
        {
            try
            {
                if (manifest == null || manifest.Length == 0 || signature == null || signature.Length < 256 || signature.Length > 4096 || !File.Exists(pemPath)) return false;
                var pem = File.ReadAllText(pemPath, Encoding.ASCII);
                var base64 = pem.Replace("-----BEGIN PUBLIC KEY-----", string.Empty).Replace("-----END PUBLIC KEY-----", string.Empty);
                var der = Convert.FromBase64String(new string(base64.Where(c => !char.IsWhiteSpace(c)).ToArray()));
                var parameters = DerRsaParameters.Read(der);
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(parameters);
                    return rsa.VerifyData(manifest, CryptoConfig.MapNameToOID("SHA256"), signature);
                }
            }
            catch { return false; }
        }
    }

    internal static class DerRsaParameters
    {
        public static RSAParameters Read(byte[] subjectPublicKeyInfo)
        {
            var reader = new DerReader(subjectPublicKeyInfo);
            var sequence = reader.ReadTag(0x30);
            var outer = new DerReader(sequence);
            outer.ReadTag(0x30);
            var bitString = outer.ReadTag(0x03);
            if (bitString.Length < 2 || bitString[0] != 0) throw new InvalidDataException("Invalid RSA public key bit string.");
            var rsaReader = new DerReader(bitString, 1);
            var rsaSequence = rsaReader.ReadTag(0x30);
            var keyReader = new DerReader(rsaSequence);
            var modulus = TrimInteger(keyReader.ReadTag(0x02));
            var exponent = TrimInteger(keyReader.ReadTag(0x02));
            return new RSAParameters { Modulus = modulus, Exponent = exponent };
        }

        private static byte[] TrimInteger(byte[] value)
        {
            var index = 0;
            while (index < value.Length - 1 && value[index] == 0) index++;
            var result = new byte[value.Length - index];
            Buffer.BlockCopy(value, index, result, 0, result.Length);
            return result;
        }

        private sealed class DerReader
        {
            private readonly byte[] data;
            private int offset;
            public DerReader(byte[] data) : this(data, 0) { }
            public DerReader(byte[] data, int offset) { this.data = data; this.offset = offset; }
            public byte[] ReadTag(byte expectedTag)
            {
                if (offset >= data.Length || data[offset++] != expectedTag) throw new InvalidDataException("Invalid DER tag.");
                if (offset >= data.Length) throw new InvalidDataException("Invalid DER length.");
                int length = data[offset++];
                if ((length & 0x80) != 0)
                {
                    var count = length & 0x7f;
                    if (count == 0 || count > 4 || offset + count > data.Length) throw new InvalidDataException("Invalid DER long length.");
                    length = 0;
                    for (var i = 0; i < count; i++) length = (length << 8) | data[offset++];
                }
                if (length < 0 || offset + length > data.Length) throw new InvalidDataException("Invalid DER payload length.");
                var result = new byte[length];
                Buffer.BlockCopy(data, offset, result, 0, length);
                offset += length;
                return result;
            }
        }
    }
}

using MaenShield.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;

namespace MaenShield.Infrastructure
{
    [DataContract]
    public sealed class QuarantineRecord
    {
        [DataMember(Name = "id")]
        public string Id { get; set; }
        [DataMember(Name = "originalPath")]
        public string OriginalPath { get; set; }
        [DataMember(Name = "payloadPath")]
        public string PayloadPath { get; set; }
        [DataMember(Name = "sha256")]
        public string Sha256 { get; set; }
        [DataMember(Name = "createdUtc")]
        public DateTime CreatedUtc { get; set; }
    }

    public sealed class QuarantineService
    {
        private readonly string root;
        private readonly string recordsPath;
        private readonly object sync = new object();

        public QuarantineService(string storageRoot)
        {
            root = Path.Combine(storageRoot, "quarantine");
            recordsPath = Path.Combine(root, "records.json");
            Directory.CreateDirectory(root);
        }

        public IReadOnlyList<QuarantineRecord> List()
        {
            lock (sync)
            {
                return ReadRecords().AsReadOnly();
            }
        }

        public QuarantineRecord MoveToQuarantine(string path, string expectedSha256)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) throw new FileNotFoundException("The file to quarantine does not exist.", path);
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Reparse points are not quarantined.");
            var actual = Hashing.Sha256File(path);
            if (!string.IsNullOrWhiteSpace(expectedSha256) && !string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("The file changed before quarantine and was not moved.");
            }
            lock (sync)
            {
                var id = Guid.NewGuid().ToString("N");
                var payload = Path.Combine(root, id + ".payload");
                var record = new QuarantineRecord { Id = id, OriginalPath = path, PayloadPath = payload, Sha256 = actual, CreatedUtc = DateTime.UtcNow };
                File.Move(path, payload);
                try
                {
                    var records = ReadRecords();
                    records.Add(record);
                    WriteRecords(records);
                    return record;
                }
                catch
                {
                    if (File.Exists(payload) && !File.Exists(path)) File.Move(payload, path);
                    throw;
                }
            }
        }

        public void Restore(string id)
        {
            if (string.IsNullOrWhiteSpace(id)) throw new ArgumentException("Quarantine id is required.", "id");
            lock (sync)
            {
                var records = ReadRecords();
                var record = records.FirstOrDefault(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
                if (record == null) throw new InvalidOperationException("Quarantine record was not found.");
                if (!File.Exists(record.PayloadPath)) throw new FileNotFoundException("Quarantine payload is missing.", record.PayloadPath);
                var destination = record.OriginalPath;
                if (File.Exists(destination)) throw new IOException("The original path already contains a file.");
                var parent = Path.GetDirectoryName(destination);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                var restoredHash = Hashing.Sha256File(record.PayloadPath);
                if (!string.Equals(restoredHash, record.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Quarantine payload integrity check failed.");
                File.Move(record.PayloadPath, destination);
                records.Remove(record);
                WriteRecords(records);
            }
        }

        private List<QuarantineRecord> ReadRecords()
        {
            if (!File.Exists(recordsPath)) return new List<QuarantineRecord>();
            try
            {
                var serializer = new DataContractJsonSerializer(typeof(List<QuarantineRecord>));
                using (var stream = File.OpenRead(recordsPath)) return (List<QuarantineRecord>)serializer.ReadObject(stream);
            }
            catch { return new List<QuarantineRecord>(); }
        }

        private void WriteRecords(List<QuarantineRecord> records)
        {
            var temp = recordsPath + ".tmp-" + Guid.NewGuid().ToString("N");
            var serializer = new DataContractJsonSerializer(typeof(List<QuarantineRecord>));
            using (var stream = File.Create(temp)) serializer.WriteObject(stream, records);
            if (File.Exists(recordsPath)) File.Replace(temp, recordsPath, null);
            else File.Move(temp, recordsPath);
        }
    }
}

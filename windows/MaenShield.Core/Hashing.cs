using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MaenShield.Core
{
    public static class Hashing
    {
        public static string Sha256File(string path)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 64, FileOptions.SequentialScan))
            using (var sha = SHA256.Create())
            {
                return ToHex(sha.ComputeHash(stream));
            }
        }

        public static string Sha256Bytes(byte[] bytes)
        {
            using (var sha = SHA256.Create())
            {
                return ToHex(sha.ComputeHash(bytes));
            }
        }

        public static string Sha256Text(string text)
        {
            return Sha256Bytes(Encoding.UTF8.GetBytes(text ?? string.Empty));
        }

        public static string ToHex(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 2);
            foreach (var value in bytes)
            {
                builder.Append(value.ToString("x2"));
            }
            return builder.ToString();
        }

        public static bool IsSha256(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length != 64)
            {
                return false;
            }
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                var isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!isHex)
                {
                    return false;
                }
            }
            return true;
        }

        public static byte[] ReadPrefix(string path, int maxBytes)
        {
            if (maxBytes <= 0)
            {
                throw new ArgumentOutOfRangeException("maxBytes");
            }
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan))
            {
                var buffer = new byte[maxBytes];
                var offset = 0;
                while (offset < buffer.Length)
                {
                    var read = stream.Read(buffer, offset, buffer.Length - offset);
                    if (read == 0)
                    {
                        break;
                    }
                    offset += read;
                }
                if (offset == buffer.Length)
                {
                    return buffer;
                }
                var result = new byte[offset];
                Buffer.BlockCopy(buffer, 0, result, 0, offset);
                return result;
            }
        }
    }
}

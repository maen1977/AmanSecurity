using System;
using System.Collections.Generic;
using System.Linq;

namespace MaenShield.Core
{
    public sealed class UrlScanResult
    {
        public string Input { get; set; }
        public string NormalizedUrl { get; set; }
        public string Host { get; set; }
        public ScanFinding Finding { get; set; }
    }

    public static class UrlScanner
    {
        public static UrlScanResult Scan(string input, ThreatDatabaseSnapshot database)
        {
            var result = new UrlScanResult { Input = input ?? string.Empty };
            Uri uri;
            if (!TryNormalize(input, out uri))
            {
                result.Finding = new ScanFinding
                {
                    Path = input ?? string.Empty,
                    Severity = FindingSeverity.Review,
                    Source = FindingSource.StaticHeuristic,
                    Reason = "The text is not a complete, safely parseable URL.",
                    Confidence = 20,
                    CanQuarantine = false
                };
                return result;
            }

            result.NormalizedUrl = uri.AbsoluteUri;
            result.Host = uri.Host.TrimEnd('.').ToLowerInvariant();
            if (ThreatDatabaseQueries.IsKnownUrl(database, result.NormalizedUrl, result.Host))
            {
                var source = database.C2Hosts.Contains(Hashing.Sha256Text(result.Host)) ? FindingSource.C2Host : FindingSource.UrlHost;
                result.Finding = new ScanFinding
                {
                    Path = result.NormalizedUrl,
                    Severity = FindingSeverity.Confirmed,
                    Source = source,
                    Reason = "The URL host matches a high-confidence threat intelligence indicator.",
                    Confidence = 95,
                    CanQuarantine = false
                };
                result.Finding.Evidence.Add(result.Host);
                return result;
            }

            var suspiciousTokens = new[] { "@", "xn--", ".zip/", ".mov/", "login", "verify", "wallet", "secure-update" };
            var tokenMatches = suspiciousTokens.Where(x => result.NormalizedUrl.IndexOf(x, StringComparison.OrdinalIgnoreCase) >= 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (tokenMatches.Count >= 2)
            {
                result.Finding = new ScanFinding
                {
                    Path = result.NormalizedUrl,
                    Severity = FindingSeverity.Review,
                    Source = FindingSource.StaticHeuristic,
                    Reason = "The URL contains multiple review indicators; verify the sender and domain before opening it.",
                    Confidence = 45,
                    CanQuarantine = false
                };
                result.Finding.Evidence.AddRange(tokenMatches);
            }
            else
            {
                result.Finding = new ScanFinding
                {
                    Path = result.NormalizedUrl,
                    Severity = FindingSeverity.Safe,
                    Source = FindingSource.None,
                    Reason = "No matching threat intelligence indicator was found.",
                    Confidence = 70,
                    CanQuarantine = false
                };
            }
            return result;
        }

        public static bool TryNormalize(string input, out Uri uri)
        {
            uri = null;
            if (string.IsNullOrWhiteSpace(input)) return false;
            var value = input.Trim();
            if (!value.Contains("://")) value = "https://" + value;
            Uri parsed;
            if (!Uri.TryCreate(value, UriKind.Absolute, out parsed)) return false;
            if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps) return false;
            if (string.IsNullOrWhiteSpace(parsed.Host) || parsed.Host.Length > 253) return false;
            uri = parsed;
            return true;
        }
    }
}

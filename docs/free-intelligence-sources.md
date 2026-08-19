# Free intelligence source findings

## MalwareBazaar

Source: https://bazaar.abuse.ch/api/

The official MalwareBazaar Community API requires an Auth-Key sent in the `Auth-Key` HTTP header. It supports automated bulk queries for intelligence and provides endpoints for hash/sample metadata. The official submission policy says only confirmed/vetted malware should be submitted; suspicious or benign files should not be submitted. MalwareBazaar also documents that downloaded samples are ZIP/password protected and that the file-download API has a daily limit. For Maen Shield, the safe use is metadata/hash ingestion only, not downloading or executing samples during the daily GitHub Actions build.

The API documentation also shows that metadata can include tags, references, delivery method, and contextual relationships. These fields may support family/category labeling, but they must not be converted into APK signer or package identity indicators unless the source explicitly provides a verified signer or package identifier.

## Planned follow-up sources

ThreatFox official API: https://threatfox.abuse.ch/api/
OpenPhish free feed documentation: https://openphish.com/phishing_feeds.html

## ThreatFox

Source: https://threatfox.abuse.ch/api/

ThreatFox provides a free Community API under fair-use principles. The API exposes IOC types such as `domain`, `ip:port`, `url`, and `file`, and supports querying recent IOCs with `get_iocs` and a day window. Its documentation states that confidence is a 0–100 field and that IOCs older than six months are expired from API/export exposure under the current policy. Maen Shield should ingest only recent, non-expired IOCs meeting the existing high-confidence threshold and should keep file hashes in the file-signature index, domains/URLs in their respective indexes, and never reinterpret a raw IOC as an APK signer/package identity.

## OpenPhish Community Feed

Source: https://openphish.com/phishing_feeds.html

OpenPhish lists a Community feed with a 12-hour update frequency and limited phishing URLs, delivered as a text file. It does not provide the richer targeted-brand, IP/ASN, GeoIP, industry, archive, language, or SSL metadata shown for paid tiers. The build should therefore treat it as a URL feed only, normalize hosts carefully, respect its terms of use, and avoid claiming premium metadata or coverage.

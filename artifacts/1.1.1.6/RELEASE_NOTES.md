# Maen Shield 1.1.1.6

## Highlights

This release rebuilds archive classification around evidence rather than filenames alone.

- Ordinary ZIP/JAR/APK archives are no longer marked for review merely because they contain an APK, JAR, or DEX entry.
- Archive entries are hashed before optional nested inspection, preserving exact SHA-256 threat detection for executable payloads.
- A known threat signature inside an APK, JAR, or DEX is reported as **CONFIRMED THREAT** with a dedicated reason.
- Genuine misleading double extensions remain **REVIEW** signals, not high-severity malware alerts.
- Archive inspection limits alone no longer create a protection finding; they are treated as an internal scan limitation without evidence of infection.
- Manual storage-scan cache version was bumped so results generated under the previous archive policy are not reused.
- Arabic and English explanations were updated for the new archive finding reason.

## Classification model

| Classification | Meaning | Report behavior |
|---|---|---|
| CLEAN | No known threat signature or strong evidence was found by the local bounded scan. | Not shown as a protection finding. |
| REVIEW | A weak indicator exists, such as a genuine misleading double extension. | Shown as review context, without a confirmed-threat alarm. |
| CONFIRMED THREAT | An exact known signature or strong corroborated detection was found. | High-priority protection finding. |

## Validation

The release was checked with the project quality gate, unit tests, and release lint. The archive tests cover both an unsigned nested `setup.apk` that produces no finding and a nested executable whose SHA-256 matches a known threat signature.

## Attribution

Development and quality improvements were carried out with the assistance of **Manus AI**. Maen Shield remains a local-first, free Android security project designed to minimize data collection and device overhead.

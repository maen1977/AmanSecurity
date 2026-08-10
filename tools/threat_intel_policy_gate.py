#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
policy=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousFeedPolicy.kt').read_text()
store=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatStore.kt').read_text()
updater=(ROOT/'app/src/main/java/com/aman/security/autonomous/AutonomousThreatUpdater.kt').read_text()
required_policy=[
    'AutonomousFeedTrust.PRIMARY','AutonomousFeedTrust.COMMUNITY','canConfirmThreat = false',
    'lookupTtlMs = Long.MAX_VALUE','TimeUnit.DAYS.toMillis(7)','TimeUnit.HOURS.toMillis(36)',
    'maxEntries = 100_000','maxEntries = 250_000','maxEntries = 50_000','validateCount'
]
missing=[x for x in required_policy if x not in policy]
if missing: raise SystemExit(f'THREAT_INTEL_POLICY_GATE_FAILED policy_missing={missing}')
required_store=['consecutiveFailures','failedSourcesLastRun','recordRun','lastAttemptEpochMs','last-known-good','SUSPICIOUS_SOURCE']
missing=[x for x in required_store if x not in store]
if missing: raise SystemExit(f'THREAT_INTEL_POLICY_GATE_FAILED store_missing={missing}')
if updater.count('AutonomousFeedPolicy.validateCount') < 4:
    raise SystemExit('THREAT_INTEL_POLICY_GATE_FAILED ingestion_bounds')
print('THREAT_INTEL_POLICY_GATE_OK trust_tiers=3 source_bounds=1 per_source_health=1 persistent_file_hashes=1 transient_ttl=1 community_confirm=0')

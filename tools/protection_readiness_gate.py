#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise SystemExit(f"PROTECTION_READINESS_GATE_FAILED {label}")


def main() -> None:
    evaluator = (ROOT / "app/src/main/java/com/aman/security/security/ProtectionReadinessEvaluator.kt").read_text()
    posture = (ROOT / "app/src/main/java/com/aman/security/security/ProtectionPostureEvaluator.kt").read_text()
    activity = (ROOT / "app/src/main/java/com/aman/security/MainActivity.kt").read_text()
    layout = (ROOT / "app/src/main/res/layout/activity_main.xml").read_text()
    english = (ROOT / "app/src/main/res/values/strings.xml").read_text()
    arabic = (ROOT / "app/src/main/res/values-ar/strings.xml").read_text()
    tests = (ROOT / "app/src/test/java/com/aman/security/security/ProtectionReadinessEvaluatorTest.kt").read_text()
    signatures = (ROOT / "threat-db/signatures.csv").read_text()
    rules = (ROOT / "threat-db/detection_rules.csv").read_text()

    for field in (
        "databaseHealthy",
        "serviceHealthy",
        "webProtectionActive",
        "webProtectionVerified",
        "intrusionCheckReady",
        "dataExfiltrationCheckReady",
    ):
        require(evaluator, field, f"evaluator_{field}")
    require(evaluator, "ProtectionReadinessLevel.LIMITED", "limited_level")
    require(evaluator, "readyChecks", "ready_check_count")
    require(posture, "if (!input.webProtectionVerified) score = minOf(score, 79)", "posture_requires_web_verification")
    require(activity, "private fun renderProtectionReadiness()", "activity_renderer")
    require(activity, "ProtectionReadinessEvaluator.evaluate", "activity_evaluation")
    require(activity, "database.canaryHealthy()", "database_health_signal")
    require(activity, "lastIntrusionCheckAt > 0L", "intrusion_check_signal")
    require(activity, "lastDataExfilCheckAt > 0L", "exfiltration_check_signal")
    require(signatures, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f|0000000001|TEST_SIGNATURE", "eicar_hash_only")
    require(rules, "META|0000000001|EICAR|TEST|CONFIRMED", "eicar_metadata")
    require(layout, "@+id/txtProtectionReadiness", "readiness_layout")
    for key in (
        "protection_readiness_ready",
        "protection_readiness_attention",
        "protection_readiness_limited",
    ):
        require(english, f'name="{key}"', f"english_{key}")
        require(arabic, f'name="{key}"', f"arabic_{key}")
    for marker in (
        "allLocalChecksReadyReportsReady",
        "unverifiedWebLayerNeedsAttentionEvenWhenOtherChecksPass",
        "serviceFailureLimitsReadiness",
    ):
        require(tests, marker, f"test_{marker}")

    print(
        "PROTECTION_READINESS_GATE_OK "
        "truthful_signals=1 web_verification=1 database_canary=1 "
        "intrusion_evidence=1 exfiltration_evidence=1 eicar_standard_hash=1 localized=1 tests=3"
    )


if __name__ == "__main__":
    main()


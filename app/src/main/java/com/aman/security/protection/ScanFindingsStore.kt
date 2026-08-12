package com.aman.security.protection

import android.content.Context
import com.aman.security.scanner.AppRiskLevel
import com.aman.security.scanner.InstalledAppsScanSummary
import com.aman.security.security.SecurityAuditSeverity
import com.aman.security.security.SecurityAuditSummary
import com.aman.security.security.SpywareAuditSummary
import com.aman.security.security.SpywareReviewLevel
import org.json.JSONArray
import org.json.JSONObject

enum class StoredScanFindingKind { APP, SPYWARE, DEVICE, NETWORK, PRIVACY, FILE }
enum class StoredScanFindingSeverity { CONFIRMED, HIGH, REVIEW }

data class StoredScanFinding(
    val kind: StoredScanFindingKind,
    val severity: StoredScanFindingSeverity,
    val title: String,
    val packageName: String = "",
    val score: Int = -1,
    val reasonCodes: List<String> = emptyList(),
    val threatReference: String = "",
    val location: String = "",
    val sha256: String = "",
    val signerSha256: String = "",
    val sourceCode: String = ""
)

data class ScanFindingsSnapshot(
    val sessionId: String,
    val savedAt: Long,
    val findings: List<StoredScanFinding>
) {
    val highFindings: List<StoredScanFinding> = findings.filter {
        it.severity == StoredScanFindingSeverity.CONFIRMED || it.severity == StoredScanFindingSeverity.HIGH
    }
    val reviewFindings: List<StoredScanFinding> = findings.filter { it.severity == StoredScanFindingSeverity.REVIEW }
}

/**
 * Durable, local-only details for the latest persistent scan. The scan counter by itself is not
 * actionable, so this store keeps the exact app / security-audit evidence that produced it.
 * Nothing is uploaded and no payload/content is copied here.
 */
class ScanFindingsStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    @Synchronized
    fun save(
        sessionId: String,
        apps: InstalledAppsScanSummary,
        audit: SecurityAuditSummary,
        spyware: SpywareAuditSummary,
        files: SharedStorageScanSummary
    ) {
        if (sessionId.isBlank()) return
        val records = mutableListOf<StoredScanFinding>()

        apps.results.asSequence()
            .filter { it.riskLevel != AppRiskLevel.LOW }
            .forEach { app ->
                val severity = when (app.riskLevel) {
                    AppRiskLevel.KNOWN_THREAT -> StoredScanFindingSeverity.CONFIRMED
                    AppRiskLevel.HIGH -> StoredScanFindingSeverity.HIGH
                    AppRiskLevel.MEDIUM -> StoredScanFindingSeverity.REVIEW
                    AppRiskLevel.LOW -> return@forEach
                }
                records += StoredScanFinding(
                    kind = StoredScanFindingKind.APP,
                    severity = severity,
                    title = app.appName,
                    packageName = app.packageName,
                    score = app.riskScore,
                    reasonCodes = app.signals.map { it.name }.sorted(),
                    threatReference = app.threatReference.orEmpty(),
                    sha256 = app.apkSha256.orEmpty(),
                    signerSha256 = app.signingCertificateSha256.orEmpty(),
                    sourceCode = app.installSource.name
                )
            }

        spyware.findings.forEach { finding ->
            val severity = when (finding.assessment.level) {
                SpywareReviewLevel.HIGH -> StoredScanFindingSeverity.HIGH
                SpywareReviewLevel.REVIEW -> StoredScanFindingSeverity.REVIEW
                SpywareReviewLevel.LOW -> return@forEach
            }
            records += StoredScanFinding(
                kind = StoredScanFindingKind.SPYWARE,
                severity = severity,
                title = finding.appName,
                packageName = finding.packageName,
                score = finding.assessment.score,
                reasonCodes = finding.assessment.signals.map { it.name }.sorted()
            )
        }

        fun addAudit(kind: StoredScanFindingKind, id: String, severity: SecurityAuditSeverity) {
            val storedSeverity = when (severity) {
                SecurityAuditSeverity.HIGH -> StoredScanFindingSeverity.HIGH
                SecurityAuditSeverity.WARNING -> StoredScanFindingSeverity.REVIEW
                SecurityAuditSeverity.INFO -> return
            }
            records += StoredScanFinding(
                kind = kind,
                severity = storedSeverity,
                title = id,
                reasonCodes = listOf(id)
            )
        }
        audit.device.findings.forEach { addAudit(StoredScanFindingKind.DEVICE, it.id, it.severity) }
        audit.network.findings.forEach { addAudit(StoredScanFindingKind.NETWORK, it.id, it.severity) }
        audit.privacy.findings.forEach { addAudit(StoredScanFindingKind.PRIVACY, it.id, it.severity) }

        files.findings.forEach { finding ->
            records += StoredScanFinding(
                kind = StoredScanFindingKind.FILE,
                severity = if (finding.severity == ProtectionSeverity.KNOWN_THREAT) {
                    StoredScanFindingSeverity.CONFIRMED
                } else {
                    StoredScanFindingSeverity.HIGH
                },
                title = finding.displayName,
                location = finding.location,
                sha256 = finding.sha256
            )
        }

        val array = JSONArray()
        records
            .distinctBy { listOf(it.kind.name, it.severity.name, it.packageName, it.title, it.location, it.reasonCodes.joinToString("|")) }
            .sortedWith(compareBy<StoredScanFinding> { severityRank(it.severity) }.thenBy { it.title.lowercase() })
            .forEach { array.put(toJson(it)) }

        prefs.edit()
            .putString(KEY_SESSION, sessionId)
            .putLong(KEY_SAVED_AT, System.currentTimeMillis())
            .putString(KEY_FINDINGS, array.toString())
            .commit()
    }

    fun snapshot(expectedSessionId: String? = null): ScanFindingsSnapshot {
        val sessionId = prefs.getString(KEY_SESSION, "").orEmpty()
        if (!expectedSessionId.isNullOrBlank() && sessionId != expectedSessionId) {
            return ScanFindingsSnapshot(expectedSessionId, 0L, emptyList())
        }
        val raw = prefs.getString(KEY_FINDINGS, "[]").orEmpty()
        val findings = runCatching {
            val array = JSONArray(raw)
            buildList {
                for (i in 0 until array.length()) {
                    fromJson(array.optJSONObject(i) ?: continue)?.let(::add)
                }
            }
        }.getOrDefault(emptyList())
        return ScanFindingsSnapshot(sessionId, prefs.getLong(KEY_SAVED_AT, 0L), findings)
    }

    @Synchronized
    fun clearForSession(sessionId: String) {
        if (sessionId.isBlank()) return
        if (prefs.getString(KEY_SESSION, "") == sessionId) return
        prefs.edit().clear().commit()
    }

    private fun toJson(item: StoredScanFinding): JSONObject = JSONObject().apply {
        put("kind", item.kind.name)
        put("severity", item.severity.name)
        put("title", item.title)
        put("package", item.packageName)
        put("score", item.score)
        put("reasons", JSONArray(item.reasonCodes))
        put("threat", item.threatReference)
        put("location", item.location)
        put("sha256", item.sha256)
        put("signer", item.signerSha256)
        put("source", item.sourceCode)
    }

    private fun fromJson(obj: JSONObject): StoredScanFinding? = runCatching {
        val reasons = obj.optJSONArray("reasons")
        StoredScanFinding(
            kind = StoredScanFindingKind.valueOf(obj.getString("kind")),
            severity = StoredScanFindingSeverity.valueOf(obj.getString("severity")),
            title = obj.optString("title"),
            packageName = obj.optString("package"),
            score = obj.optInt("score", -1),
            reasonCodes = buildList {
                if (reasons != null) for (i in 0 until reasons.length()) add(reasons.optString(i))
            },
            threatReference = obj.optString("threat"),
            location = obj.optString("location"),
            sha256 = obj.optString("sha256"),
            signerSha256 = obj.optString("signer"),
            sourceCode = obj.optString("source")
        )
    }.getOrNull()

    private fun severityRank(severity: StoredScanFindingSeverity): Int = when (severity) {
        StoredScanFindingSeverity.CONFIRMED -> 0
        StoredScanFindingSeverity.HIGH -> 1
        StoredScanFindingSeverity.REVIEW -> 2
    }

    companion object {
        private const val PREFS = "aman_scan_findings_v1"
        private const val KEY_SESSION = "session"
        private const val KEY_SAVED_AT = "saved_at"
        private const val KEY_FINDINGS = "findings"
    }
}

package com.aman.security.detection

/**
 * On-device application relationship graph — the second pillar of the
 * "thinking AI" layer.
 *
 * Single apps are scanned in isolation, but coordinated surveillance
 * suites spread across several light-looking apps. This graph tracks the
 * installed-app population and raises an alert when the *combination* of
 * apps creates a suspicious capability mosaic (e.g., one app reads SMS,
 * another records audio, a third holds accessibility) — a pattern no
 * single-app scan can detect.
 *
 * 6.0.0 — AppRelationshipGraph
 */
class AppRelationshipGraph {

    data class AppNode(
        val packageName: String,
        val signals: Set<String> = emptySet()
    )

    data class MosaicAlert(
        val signal: String,
        val involvedApps: Set<String>,
        val severity: FindingConfidence,
        val score: Int
    )

    private var nodes = linkedMapOf<String, MutableSet<String>>()

    /** Register an installed app together with its capability signals. */
    fun observe(packageName: String, signals: Set<String>) {
        if (signals.isEmpty()) return
        val entry = nodes.getOrPut(packageName) { linkedSetOf() }
        entry += signals
    }

    fun clear() {
        nodes.clear()
    }

    /** Scan the observed population for coordinated capability mosaics. */
    fun analyze(): List<MosaicAlert> {
        val alerts = mutableListOf<MosaicAlert>()
        val surveillanceMosaic = linkedSetOf<String>(
            "SMS_READ", "INPUT_METHOD", "AUDIO_RECORD", "ACCESSIBILITY", "OVERLAY"
        )
        val privacyMosaic = linkedSetOf<String>(
            "CAMERA", "MICROPHONE", "LOCATION", "CONTACTS", "MEDIA_READ"
        )
        val telemetryMosaic = linkedSetOf<String>(
            "BILLING", "CALL_LOG", "QUERY_ALL_PACKAGES", "BOOT_PERSISTENCE"
        )

        fun involved(mosaic: Set<String>): Set<String> =
            nodes.filterValues { it.any { s -> s in mosaic } }.keys.toSet()

        fun raise(signal: String, mosaic: Set<String>, severity: FindingConfidence, score: Int) {
            val apps = involved(mosaic)
            if (apps.size >= 2) alerts += MosaicAlert(signal, apps, severity, score)
        }

        raise("SURVEILLANCE_MOSAIC", surveillanceMosaic, FindingConfidence.HIGH, 40)
        raise("PRIVACY_MOSAIC", privacyMosaic, FindingConfidence.MEDIUM, 25)
        raise("TELEMETRY_MOSAIC", telemetryMosaic, FindingConfidence.MEDIUM, 20)

        // A single app holding three or more high-capability signals is a
        // concentrated watcher on its own.
        for ((pkg, signals) in nodes) {
            val high = signals.count { it in surveillanceMosaic || it in privacyMosaic }
            if (high >= 3) {
                alerts += MosaicAlert(
                    "CONCENTRATED_WATCHER", setOf(pkg),
                    FindingConfidence.HIGH, 35
                )
            }
        }
        return alerts
    }

    fun size(): Int = nodes.size
}

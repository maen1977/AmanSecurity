package com.aman.security.runtime

import android.net.TrafficStats
import android.os.Build
import android.os.SystemClock

/**
 * NetworkTrafficInspector: watches background network activity per
 * app through TrafficStats (Android 5+) and flags apps that
 * periodically phone home with tiny payloads — the classic beaconing
 * fingerprint of command-and-control spyware.
 *
 * Pure on-device counters, no packet capture, no network calls,
 * no paid API.
 */
public class NetworkTrafficInspector(private val nowProvider: () -> Long = { SystemClock.elapsedRealtime() }) {

    fun inspect(
        counters: (uid: Int) -> CounterSample,
        uidToPackage: (uid: Int) -> String?
    ): BeaconReport {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return BeaconReport(emptyList())
        }
        val uids = knownUids(counters)
        val now = nowProvider()
        val findings = mutableListOf<BeaconFinding>()
        val history: MutableList<HistoryEntry> = mutableListOf()

        for (uid in uids) {
            val sample = counters(uid)
            val total = sample.rxBytes + sample.txBytes
            val prev = remember(uid, now, total)
            if (prev == null) continue
            val elapsed = now - prev.at
            if (elapsed <= 0) continue
            val rate = ((total - prev.total) * 1000L) / elapsed
            val beacons = periodicBeacons(uid, now, total)
            if (beacons) {
                val pkg = uidToPackage(uid) ?: continue
                findings += BeaconFinding(pkg, rate)
            }
            history += HistoryEntry(uid, now, total)
        }
        saveHistory(history)
        return BeaconReport(findings)
    }

    private fun remember(uid: Int, now: Long, total: Long): HistoryEntry? =
        history[uid]?.let { it }

    /**
     * Regular tiny-payload bursts (small deltas repeated at
     * near-equal intervals) indicate automated phone-home traffic.
     */
    private fun periodicBeacons(uid: Int, now: Long, total: Long): Boolean {
        val trail = beaconTrail[uid] ?: return false
        if (trail.size < MIN_SAMPLES) return false
        val deltas = mutableListOf<Long>()
        var lastAt = 0L
        var lastTotal = 0L
        var consistentCount = 0
        var expected = 0L
        for (entry in trail) {
            if (lastAt > 0 && entry.total - lastTotal in TINY_MIN..TINY_MAX) {
                val gap = entry.at - lastAt
                if (expected == 0L) {
                    expected = gap
                    consistentCount++
                } else if (kotlin.math.abs(gap - expected) <= INTERVAL_TOLERANCE_MS) {
                    consistentCount++
                }
            }
            lastAt = entry.at
            lastTotal = entry.total
        }
        if (expected in INTERVAL_MIN..INTERVAL_MAX && consistentCount >= MIN_BEACONS) {
            beaconTrail[uid] = trail.takeLast(4) + HistoryEntry(uid, now, total)
            return true
        }
        return false
    }

    private fun knownUids(counters: (uid: Int) -> CounterSample): List<Int> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) return emptyList()
        // Scan application uids (10000..MAX_UID). TrafficStats returns
        // NO_NETWORK_DATA_VALUE (-1) for inactive uids, which we skip.
        val found = mutableListOf<Int>()
        for (uid in FIRST_APP_UID..MAX_SCAN_UID) {
            if (counters(uid).rxBytes != TrafficStats.UNSUPPORTED.toLong()) {
                found += uid
            }
        }
        return found
    }

    internal fun feedHistory(uid: Int, entry: HistoryEntry) {
        val trail = beaconTrail.getOrDefault(uid, emptyList()).toMutableList()
        trail += entry
        beaconTrail[uid] = trail.takeLast(MAX_TRAIL)
    }

    private fun saveHistory(history: List<HistoryEntry>) {
        for (entry in history) {
            feedHistory(entry.uid, entry)
        }
    }

    private val beaconTrail = mutableMapOf<Int, List<HistoryEntry>>()
    private val history = mutableMapOf<Int, HistoryEntry>()

    companion object {
        private const val TINY_MIN = 64L
        private const val TINY_MAX = 2048L
        private const val INTERVAL_MIN = 55_000L
        private const val INTERVAL_MAX = 65_000L
        private const val INTERVAL_TOLERANCE_MS = 5_000L
        private const val MIN_SAMPLES = 4
        private const val MIN_BEACONS = 3
        private const val MAX_TRAIL = 6
        private const val FIRST_APP_UID = 10000
        private const val MAX_SCAN_UID = 19999
    }

    public data class CounterSample(
        val rxBytes: Long,
        val txBytes: Long
    )

    internal data class HistoryEntry(
        val uid: Int,
        val at: Long,
        val total: Long
    )
}

public data class BeaconFinding(
    val packageName: String,
    val recentRateBytesPerSec: Long
)

public data class BeaconReport(
    val findings: List<BeaconFinding>
) {
    val isClean: Boolean get() = findings.isEmpty()
}

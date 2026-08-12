package com.aman.security.web

/**
 * Process-local, bounded DNS metadata cache. Nothing is written to disk and no DNS content is
 * uploaded. The cache only helps correlate unusual background upload with recent destination
 * diversity while the local DNS shield process is alive.
 */
object RecentDnsObservationCache {
    private data class Observation(val host: String, val seenAt: Long)
    private val byUid = linkedMapOf<Int, ArrayDeque<Observation>>()

    @Synchronized
    fun record(uid: Int, host: String, now: Long = System.currentTimeMillis()) {
        if (uid <= 0 || host.isBlank()) return
        val queue = byUid.getOrPut(uid) { ArrayDeque() }
        queue.addLast(Observation(host.trim().trimEnd('.').lowercase(), now))
        prune(queue, now)
        while (queue.size > MAX_PER_UID) queue.removeFirst()
        while (byUid.size > MAX_UIDS) byUid.remove(byUid.keys.first())
    }

    @Synchronized
    fun distinctHostCount(uid: Int, since: Long, now: Long = System.currentTimeMillis()): Int {
        val queue = byUid[uid] ?: return 0
        prune(queue, now)
        return queue.asSequence().filter { it.seenAt >= since }.map { it.host }.distinct().count()
    }

    private fun prune(queue: ArrayDeque<Observation>, now: Long) {
        val cutoff = now - RETENTION_MS
        while (queue.firstOrNull()?.seenAt?.let { it < cutoff } == true) queue.removeFirst()
    }

    private const val RETENTION_MS = 2L * 60L * 60L * 1000L
    private const val MAX_PER_UID = 96
    private const val MAX_UIDS = 96
}

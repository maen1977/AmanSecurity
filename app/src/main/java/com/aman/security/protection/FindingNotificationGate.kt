package com.aman.security.protection

/**
 * Keeps persistent runtime findings useful without notifying the user on every
 * periodic audit while the same condition remains unchanged.
 */
internal class FindingNotificationGate(private val cooldownMs: Long) {
    private val lastNotifiedAt = linkedMapOf<String, Long>()

    @Synchronized
    fun shouldNotify(key: String, nowMs: Long): Boolean {
        if (key.isBlank()) return false
        val previous = lastNotifiedAt[key]
        if (previous != null && nowMs >= previous && nowMs - previous < cooldownMs) {
            return false
        }
        lastNotifiedAt[key] = nowMs
        if (lastNotifiedAt.size > MAX_KEYS) {
            val oldest = lastNotifiedAt.entries
                .sortedBy { it.value }
                .take(lastNotifiedAt.size - MAX_KEYS)
                .map { it.key }
            oldest.forEach(lastNotifiedAt::remove)
        }
        return true
    }

    companion object {
        private const val MAX_KEYS = 128
    }
}

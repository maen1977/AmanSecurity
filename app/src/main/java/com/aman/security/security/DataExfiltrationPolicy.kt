package com.aman.security.security

enum class DataExfiltrationLevel {
    CLEAR,
    REVIEW,
    HIGH
}

data class DataExfiltrationInput(
    val backgroundTxBytes: Long,
    val foregroundTxBytes: Long,
    val sideloaded: Boolean,
    val privilegedControlCount: Int,
    val surveillanceSignalCount: Int,
    val persistent: Boolean,
    val recentDnsHostCount: Int,
    val systemApp: Boolean
)

data class DataExfiltrationAssessment(
    val level: DataExfiltrationLevel,
    val score: Int
)

/**
 * Conservative local upload-anomaly policy.
 *
 * Upload volume by itself is never treated as theft: backups, messengers and cloud drives
 * legitimately move large amounts of data. Escalation therefore requires background upload
 * plus corroborating local-risk signals such as confirmed sideloading, privileged control,
 * surveillance access or persistence. This keeps false positives low while remaining cheap.
 */
object DataExfiltrationPolicy {
    private const val MIB = 1024L * 1024L

    fun evaluate(input: DataExfiltrationInput): DataExfiltrationAssessment {
        if (input.systemApp || input.backgroundTxBytes < 8 * MIB) {
            return DataExfiltrationAssessment(DataExfiltrationLevel.CLEAR, 0)
        }

        var score = 0
        score += when {
            input.backgroundTxBytes >= 128 * MIB -> 38
            input.backgroundTxBytes >= 64 * MIB -> 28
            input.backgroundTxBytes >= 32 * MIB -> 20
            input.backgroundTxBytes >= 16 * MIB -> 12
            else -> 4
        }
        if (input.sideloaded) score += 22
        score += (input.privilegedControlCount.coerceAtMost(3) * 12)
        score += (input.surveillanceSignalCount.coerceAtMost(5) * 5)
        if (input.persistent) score += 8
        if (input.recentDnsHostCount >= 12) score += 6

        val level = when {
            input.backgroundTxBytes >= 64 * MIB && input.sideloaded &&
                input.privilegedControlCount >= 1 && input.surveillanceSignalCount >= 2 -> DataExfiltrationLevel.HIGH
            input.backgroundTxBytes >= 128 * MIB && input.privilegedControlCount >= 2 &&
                input.surveillanceSignalCount >= 1 && input.persistent -> DataExfiltrationLevel.HIGH
            input.backgroundTxBytes >= 16 * MIB && input.sideloaded &&
                input.privilegedControlCount >= 1 && input.surveillanceSignalCount >= 1 -> DataExfiltrationLevel.REVIEW
            input.backgroundTxBytes >= 48 * MIB && input.sideloaded &&
                (input.surveillanceSignalCount >= 1 || input.recentDnsHostCount >= 8) -> DataExfiltrationLevel.REVIEW
            input.backgroundTxBytes >= 96 * MIB && input.privilegedControlCount >= 1 &&
                input.surveillanceSignalCount >= 1 -> DataExfiltrationLevel.REVIEW
            else -> DataExfiltrationLevel.CLEAR
        }

        val normalized = when (level) {
            DataExfiltrationLevel.HIGH -> maxOf(score, 75)
            DataExfiltrationLevel.REVIEW -> maxOf(score, 40)
            DataExfiltrationLevel.CLEAR -> minOf(score, 29)
        }.coerceIn(0, 100)
        return DataExfiltrationAssessment(level, normalized)
    }
}

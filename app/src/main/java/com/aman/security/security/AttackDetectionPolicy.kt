package com.aman.security.security

enum class AttackDetectionLevel {
    CLEAR,
    WATCH,
    CRITICAL,
    INCOMPLETE
}

data class AttackDetectionInput(
    val protectionEnabled: Boolean,
    val serviceHealthy: Boolean,
    val criticalSignals: Int,
    val watchSignals: Int
)

/** Pure policy kept Android-free so severity semantics are cheap and directly testable. */
object AttackDetectionPolicy {
    fun level(input: AttackDetectionInput): AttackDetectionLevel = when {
        !input.protectionEnabled || !input.serviceHealthy -> AttackDetectionLevel.INCOMPLETE
        input.criticalSignals > 0 -> AttackDetectionLevel.CRITICAL
        input.watchSignals > 0 -> AttackDetectionLevel.WATCH
        else -> AttackDetectionLevel.CLEAR
    }
}

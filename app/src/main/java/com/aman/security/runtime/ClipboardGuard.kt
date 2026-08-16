package com.aman.security.runtime

import android.content.ClipboardManager
import android.content.Context
import com.aman.security.banking.FinanceAppIdentityMatcher
import com.aman.security.protection.ProtectionPreferences

/**
 * Clipboard guard for sensitive sessions.
 *
 * Banking trojans read the clipboard to steal one-time passwords,
 * card numbers and transfer codes. This guard detects secret-like
 * content entering the clipboard during or right after a sensitive
 * session and clears it before a malicious reader can copy it.
 * Fully on-device, no network, no paid API.
 */
internal class ClipboardGuard(private val context: Context) {

    private val preferences = ProtectionPreferences(context)
    private var lastCheckHash: Int = 0
    private var clearScheduledAt = 0L
    private var lastProtectedAt = 0L

    /**
     * Call while a sensitive app is in the foreground (or within the
     * session window). Returns an alert when secret-like content appears.
     */
    fun probe(foreground: String, sessionActive: Boolean): ClipboardAlert? = runCatching {
        if (!preferences.enabled || !preferences.clipboardGuardEnabled) return@runCatching null
        if (foreground.isBlank()) return@runCatching null
        val secretCandidate = captureSecretCandidate() ?: return@runCatching null
        val hash = secretCandidate.hashCode()
        if (hash == lastCheckHash) return@runCatching null
        lastCheckHash = hash
        val inWindow = sessionActive || recentlySensitive(foreground)
        if (!inWindow) return@runCatching null
        val now = System.currentTimeMillis()
        if (now - lastProtectedAt < PROTECT_COOLDOWN_MS) return@runCatching null
        lastProtectedAt = now
        preferences.totalClipboardGuards = preferences.totalClipboardGuards + 1
        preferences.lastClipboardProtectAt = now
        scheduleClear()
        ClipboardAlert(secretCandidate)
    }.getOrDefault(null)

    private fun recentlySensitive(foreground: String): Boolean {
        val label = runCatching {
            val info = context.packageManager.getPackageInfo(foreground, 0)
            info.applicationInfo?.loadLabel(context.packageManager)?.toString().orEmpty()
        }.getOrDefault("")
        return FinanceAppIdentityMatcher.matches(foreground, label)
    }

    internal fun captureSecretCandidate(): String? {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return null
        val clip = runCatching { clipboard.primaryClip }.getOrNull() ?: return null
        val text = (0 until clip.itemCount).mapNotNull { clip.getItemAt(it)?.text?.toString() }.joinToString(" ")
        if (text.isBlank()) return null
        return SECRET_PATTERNS.firstOrNull { regex -> regex.containsMatchIn(text) }?.let { text }
    }

    private fun scheduleClear() {
        val now = System.currentTimeMillis()
        if (clearScheduledAt > now) return
        clearScheduledAt = now + CLEAR_AFTER_MS
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            runCatching {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                clipboard?.clearPrimaryClip()
            }
            clearScheduledAt = 0L
        }, CLEAR_AFTER_MS)
    }

    companion object {
        internal val SECRET_PATTERNS = listOf(
            Regex("\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"),
            Regex("\\b\\d{6}\\b"),
            Regex("\\b(otp|one.time|كود|رمز)[^a-zA-Z\\d]{0,20}\\d{4,}\\b", RegexOption.IGNORE_CASE),
            Regex("CVV[^a-zA-Z\\d]{0,10}\\d{3}"),
            Regex("IBAN[^a-zA-Z\\d]{0,10}[A-Z]{2}\\d+")
        )
        private const val CLEAR_AFTER_MS = 20_000L
        private const val PROTECT_COOLDOWN_MS = 10_000L
    }
}

internal data class ClipboardAlert(val contentSummary: String)

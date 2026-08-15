package com.aman.security.web

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.aman.security.R
import com.aman.security.databinding.ActivityLinkGuardBinding
import com.aman.security.protection.ProtectionActivityKind
import com.aman.security.protection.ProtectionActivityState
import com.aman.security.protection.ProtectionActivityStore
import com.aman.security.protection.ProtectionPreferences
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.scanner.OfficialWebTestIndicators
import com.aman.security.scanner.UrlRiskLevel
import com.aman.security.scanner.UrlRiskSignal
import com.aman.security.scanner.UrlScanResult
import com.aman.security.scanner.UrlScanner
import java.text.NumberFormat

class LinkGuardActivity : AppCompatActivity() {
    private lateinit var binding: ActivityLinkGuardBinding
    private lateinit var scanner: UrlScanner
    private var result: UrlScanResult? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLinkGuardBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val database = SignatureDatabase(this)
        scanner = UrlScanner(database::findUrl)
        binding.btnWebGuardBack.setOnClickListener { finish() }
        binding.btnWebGuardOpen.setOnClickListener { confirmOpen() }

        val candidate = incomingLink(intent)
        if (candidate == null) {
            render(scanner.scan(""))
            return
        }
        val scanned = scanner.scan(candidate)
        result = scanned
        render(scanned)
        recordOfficialWebTestIfMatched(scanned, WebGuardEvidencePolicy.provesExternalLinkInterception(intent?.action))

        if (WebProtectionPolicy.decide(scanned.riskLevel) == WebProtectionDecision.ALLOW) {
            binding.root.post { openExternal(scanned) }
        }
    }

    private fun incomingLink(intent: Intent?): String? = when (intent?.action) {
        Intent.ACTION_VIEW -> intent.dataString
        Intent.ACTION_PROCESS_TEXT -> intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
        Intent.ACTION_SEND -> intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
            ?: intent.clipData?.getItemAt(0)?.coerceToText(this)?.toString()
        else -> null
    }

    private fun render(scan: UrlScanResult) {
        val decision = WebProtectionPolicy.decide(scan.riskLevel)
        binding.txtWebGuardTitle.setText(when (decision) {
            WebProtectionDecision.ALLOW -> R.string.web_guard_safe_title
            WebProtectionDecision.CAUTION -> R.string.web_guard_caution_title
            WebProtectionDecision.BLOCK -> R.string.web_guard_blocked_title
            WebProtectionDecision.TEST -> R.string.web_guard_test_title
            WebProtectionDecision.INVALID -> R.string.web_guard_invalid_title
        })
        binding.txtWebGuardMessage.text = when (scan.riskLevel) {
            UrlRiskLevel.LOW -> getString(R.string.web_guard_safe_body)
            UrlRiskLevel.REVIEW, UrlRiskLevel.HIGH -> formatSignals(scan.signals)
            UrlRiskLevel.KNOWN_PHISHING, UrlRiskLevel.KNOWN_MALICIOUS -> getString(R.string.web_guard_blocked_body)
            UrlRiskLevel.TEST_SIGNATURE -> getString(R.string.web_guard_test_body)
            UrlRiskLevel.INVALID -> getString(R.string.web_guard_invalid_body)
        }
        binding.txtWebGuardTechnical.text = buildString {
            if (scan.host != null) append(getString(R.string.url_host_line, scan.host))
            if (scan.normalizedUrl != null) {
                if (isNotEmpty()) append('\n')
                append(getString(R.string.url_normalized_line, scan.normalizedUrl))
            }
            if (scan.riskLevel == UrlRiskLevel.REVIEW || scan.riskLevel == UrlRiskLevel.HIGH) {
                if (isNotEmpty()) append('\n')
                append(getString(R.string.url_score_line, NumberFormat.getIntegerInstance().format(scan.riskScore)))
            }
            if (scan.threatReference != null) {
                if (isNotEmpty()) append('\n')
                append(getString(R.string.url_threat_reference_line, scan.threatReference))
            }
        }
        binding.btnWebGuardOpen.visibility = if (WebProtectionPolicy.mayOpenAfterWarning(scan.riskLevel)) View.VISIBLE else View.GONE
    }

    private fun recordOfficialWebTestIfMatched(scan: UrlScanResult, externalViewIntercepted: Boolean) {
        // A shared link proves that Link Guard can scan text, but only ACTION_VIEW
        // proves Android routed a normal external web link through the browser role.
        if (!externalViewIntercepted ||
            scan.riskLevel != UrlRiskLevel.TEST_SIGNATURE ||
            scan.threatReference != OfficialWebTestIndicators.AMTSO_ANDROID_PHISHING_REFERENCE
        ) return

        val now = System.currentTimeMillis()
        ProtectionPreferences(this).apply {
            webGuardTestState = ProtectionPreferences.WEB_GUARD_TEST_PASSED
            lastWebGuardTestInterceptAt = now
            if (lastWebGuardTestAt <= 0L) lastWebGuardTestAt = now
        }
        ProtectionActivityStore(this).add(
            kind = ProtectionActivityKind.WEB_SHIELD,
            state = ProtectionActivityState.SAFE,
            title = getString(R.string.timeline_web_guard_test_passed),
            detail = getString(R.string.timeline_web_guard_test_passed_detail),
            dedupeKey = "web-guard:amtso:test"
        )
    }

    private fun confirmOpen() {
        val scan = result ?: return
        if (!WebProtectionPolicy.mayOpenAfterWarning(scan.riskLevel)) return
        AlertDialog.Builder(this)
            .setTitle(R.string.web_guard_open_warning_title)
            .setMessage(R.string.web_guard_open_warning_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.web_guard_open_anyway) { _, _ -> openExternal(scan) }
            .show()
    }

    private fun openExternal(scan: UrlScanResult) {
        val url = scan.normalizedUrl ?: return
        if (!BrowserForwarder.openExternal(this, url, getString(R.string.web_guard_choose_browser))) {
            AlertDialog.Builder(this)
                .setTitle(R.string.web_guard_no_browser_title)
                .setMessage(R.string.web_guard_no_browser_body)
                .setPositiveButton(R.string.ok, null)
                .show()
            return
        }
        finish()
    }

    private fun formatSignals(signals: Set<UrlRiskSignal>): String {
        if (signals.isEmpty()) return getString(R.string.web_guard_caution_body)
        return buildString {
            append(getString(R.string.web_guard_caution_body))
            signals.forEach { signal ->
                append('\n')
                append('•')
                append(' ')
                append(getString(signalString(signal)))
            }
        }
    }

    private fun signalString(signal: UrlRiskSignal): Int = when (signal) {
        UrlRiskSignal.PLAIN_HTTP -> R.string.url_signal_http
        UrlRiskSignal.IP_ADDRESS_HOST -> R.string.url_signal_ip_host
        UrlRiskSignal.PUNYCODE_HOST -> R.string.url_signal_punycode
        UrlRiskSignal.USER_INFO -> R.string.url_signal_user_info
        UrlRiskSignal.NON_STANDARD_PORT -> R.string.url_signal_port
        UrlRiskSignal.MANY_SUBDOMAINS -> R.string.url_signal_subdomains
        UrlRiskSignal.LONG_URL -> R.string.url_signal_long
        UrlRiskSignal.SUSPICIOUS_KEYWORDS -> R.string.url_signal_keywords
        UrlRiskSignal.COMMUNITY_THREAT_FEED -> R.string.url_signal_community_feed
    }
}

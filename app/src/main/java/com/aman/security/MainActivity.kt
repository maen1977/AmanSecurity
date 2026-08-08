package com.aman.security

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.lifecycleScope
import com.aman.security.databinding.ActivityMainBinding
import com.aman.security.databinding.ItemInstalledAppBinding
import com.aman.security.databinding.ItemExclusionBinding
import com.aman.security.databinding.ItemHistoryBinding
import com.aman.security.databinding.ItemQuarantineBinding
import com.aman.security.protection.ProtectedFolderScanner
import com.aman.security.protection.ProtectionEvent
import com.aman.security.protection.ProtectionEventStore
import com.aman.security.protection.ProtectionEventType
import com.aman.security.protection.ProtectionNotifier
import com.aman.security.protection.ProtectionPreferences
import com.aman.security.protection.ProtectionScheduler
import com.aman.security.protection.ProtectionSeverity
import com.aman.security.scanner.AppInstallSource
import com.aman.security.scanner.ApkAnalysisState
import com.aman.security.scanner.ApkIdentityClassification
import com.aman.security.scanner.ApkRiskLevel
import com.aman.security.scanner.ApkRiskSignal
import com.aman.security.scanner.ApkStaticAnalysis
import com.aman.security.scanner.ApkStaticAnalyzer
import com.aman.security.scanner.AppRiskLevel
import com.aman.security.scanner.AppRiskSignal
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.InstalledAppScanResult
import com.aman.security.scanner.InstalledAppScanner
import com.aman.security.scanner.InstalledAppsScanSummary
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.ScanDetectionReason
import com.aman.security.scanner.ScanResult
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.scanner.ThreatDatabaseUpdater
import com.aman.security.scanner.SharedUrlExtractor
import com.aman.security.scanner.UrlRiskLevel
import com.aman.security.scanner.UrlRiskSignal
import com.aman.security.scanner.UrlScanResult
import com.aman.security.scanner.UrlScanner
import com.aman.security.security.ExclusionEntry
import com.aman.security.security.QuarantineEntry
import com.aman.security.security.QuarantineManager
import com.aman.security.security.QuarantinePolicy
import com.aman.security.security.ScanHistoryEntry
import com.aman.security.security.SecurityRecordStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var database: SignatureDatabase
    private lateinit var scanner: FileScanner
    private lateinit var apkStaticAnalyzer: ApkStaticAnalyzer
    private lateinit var installedAppScanner: InstalledAppScanner
    private lateinit var updater: ThreatDatabaseUpdater
    private lateinit var urlScanner: UrlScanner
    private lateinit var recordStore: SecurityRecordStore
    private lateinit var quarantineManager: QuarantineManager
    private lateinit var protectionPreferences: ProtectionPreferences
    private lateinit var protectionEventStore: ProtectionEventStore
    private var selectedUri: Uri? = null
    private var lastScanResult: ScanResult? = null
    private var pendingRestoreId: String? = null

    private val filePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            selectedUri = uri
            runCatching {
                contentResolver.takePersistableUriPermission(
                    uri,
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            }
            runCatching {
                contentResolver.takePersistableUriPermission(
                    uri,
                    android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
            binding.txtSelectedFile.text = uri.lastPathSegment ?: getString(R.string.selected_file_title)
            binding.btnScanFile.isEnabled = true
            resetResult()
        }
    }

    private val restorePicker = registerForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val id = pendingRestoreId
        pendingRestoreId = null
        if (uri != null && id != null) restoreQuarantinedFile(id, uri)
    }

    private val protectedFolderPicker = registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) setProtectedFolder(uri)
    }

    private val notificationPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        renderProtectionStatus()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        database = SignatureDatabase(this)
        apkStaticAnalyzer = ApkStaticAnalyzer(this, database)
        scanner = FileScanner(contentResolver, database, apkStaticAnalyzer)
        installedAppScanner = InstalledAppScanner(this, database)
        updater = ThreatDatabaseUpdater(this, database)
        urlScanner = UrlScanner(database::findUrl)
        recordStore = SecurityRecordStore(this)
        quarantineManager = QuarantineManager(this, recordStore)
        protectionPreferences = ProtectionPreferences(this)
        protectionEventStore = ProtectionEventStore(this)
        ProtectionNotifier.ensureChannel(this)
        renderDatabaseInfo()
        renderSecurityManagement()
        renderProtectionStatus()

        binding.btnChooseFile.setOnClickListener { filePicker.launch(arrayOf("*/*")) }
        binding.btnScanFile.setOnClickListener { scanSelectedFile() }
        binding.btnScanInstalledApps.setOnClickListener { requestInstalledAppsScan() }
        binding.btnScanUrl.setOnClickListener { scanUrlInput() }
        binding.btnUpdateDatabase.setOnClickListener { updateThreatDatabase() }
        binding.btnLanguage.setOnClickListener { showLanguageDialog() }
        binding.btnQuarantine.setOnClickListener { confirmQuarantine() }
        binding.btnExclusion.setOnClickListener { toggleExclusion() }
        binding.btnClearHistory.setOnClickListener { confirmClearHistory() }
        binding.btnToggleProtection.setOnClickListener { toggleBackgroundProtection() }
        binding.btnChooseProtectedFolder.setOnClickListener { protectedFolderPicker.launch(protectionPreferences.protectedTreeUri) }
        binding.btnCheckProtectionNow.setOnClickListener { scanProtectedFolderNow() }
        binding.btnClearProtectionEvents.setOnClickListener {
            protectionEventStore.clear()
            renderProtectionStatus()
        }
        handleIncomingIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        if (::protectionPreferences.isInitialized) renderProtectionStatus()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun renderDatabaseInfo() {
        val info = database.info
        binding.txtDatabaseVersion.text = getString(R.string.database_version, info.version)
        binding.txtDatabaseEntries.text = getString(
            R.string.database_entries,
            NumberFormat.getIntegerInstance().format(info.fileEntries),
            NumberFormat.getIntegerInstance().format(info.urlEntries),
            NumberFormat.getIntegerInstance().format(info.apkIdentityEntries)
        )
    }

    private fun updateThreatDatabase() {
        binding.btnUpdateDatabase.isEnabled = false
        binding.txtUpdateStatus.setText(R.string.update_checking)
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { updater.update() }
            binding.btnUpdateDatabase.isEnabled = true
            when (result) {
                ThreatDatabaseUpdater.Result.UpToDate -> binding.txtUpdateStatus.setText(R.string.update_up_to_date)
                is ThreatDatabaseUpdater.Result.Updated -> {
                    renderDatabaseInfo()
                    binding.txtUpdateStatus.text = getString(
                        R.string.update_success,
                        result.version,
                        NumberFormat.getIntegerInstance().format(result.fileEntries),
                        NumberFormat.getIntegerInstance().format(result.urlEntries),
                        NumberFormat.getIntegerInstance().format(result.apkIdentityEntries)
                    )
                }
                ThreatDatabaseUpdater.Result.InvalidSignature -> binding.txtUpdateStatus.setText(R.string.update_invalid_signature)
                ThreatDatabaseUpdater.Result.InvalidDatabase -> binding.txtUpdateStatus.setText(R.string.update_invalid_database)
                ThreatDatabaseUpdater.Result.NetworkError -> binding.txtUpdateStatus.setText(R.string.update_network_error)
            }
        }
    }

    private fun handleIncomingIntent(incoming: Intent?) {
        if (incoming?.action != Intent.ACTION_SEND || incoming.type != "text/plain") return
        val candidate = SharedUrlExtractor.firstCandidate(incoming.getStringExtra(Intent.EXTRA_TEXT)) ?: return
        binding.edtUrl.setText(candidate)
        scanUrl(candidate)
    }

    private fun scanUrlInput() {
        scanUrl(binding.edtUrl.text?.toString().orEmpty())
    }

    private fun scanUrl(value: String) {
        val result = urlScanner.scan(value)
        renderUrlResult(result)
    }

    private fun renderUrlResult(result: UrlScanResult) {
        binding.txtUrlClassification.setText(
            when (result.riskLevel) {
                UrlRiskLevel.INVALID -> R.string.url_result_invalid
                UrlRiskLevel.LOW -> R.string.url_result_low
                UrlRiskLevel.REVIEW -> R.string.url_result_review
                UrlRiskLevel.HIGH -> R.string.url_result_high
                UrlRiskLevel.KNOWN_PHISHING -> R.string.url_result_phishing
                UrlRiskLevel.KNOWN_MALICIOUS -> R.string.url_result_malware
                UrlRiskLevel.TEST_SIGNATURE -> R.string.url_result_test
            }
        )

        binding.txtUrlReason.text = when (result.riskLevel) {
            UrlRiskLevel.INVALID -> getString(R.string.url_reason_invalid)
            UrlRiskLevel.LOW -> getString(R.string.url_reason_low)
            UrlRiskLevel.KNOWN_PHISHING, UrlRiskLevel.KNOWN_MALICIOUS -> getString(R.string.url_reason_known)
            UrlRiskLevel.TEST_SIGNATURE -> getString(R.string.url_reason_test)
            UrlRiskLevel.REVIEW, UrlRiskLevel.HIGH -> formatUrlSignals(result.signals)
        }

        if (result.normalizedUrl == null || result.host == null) {
            binding.txtUrlTechnical.text = ""
            return
        }

        binding.txtUrlTechnical.text = buildString {
            append(getString(R.string.url_host_line, result.host))
            append('\n')
            append(getString(R.string.url_score_line, NumberFormat.getIntegerInstance().format(result.riskScore)))
            append('\n')
            append(getString(R.string.url_normalized_line, result.normalizedUrl))
            if (result.threatReference != null) {
                append('\n')
                append(getString(R.string.url_threat_reference_line, result.threatReference))
            }
        }
    }

    private fun formatUrlSignals(signals: Set<UrlRiskSignal>): String {
        if (signals.isEmpty()) return getString(R.string.url_no_elevated_indicators)
        return buildString {
            append(getString(R.string.url_indicators_title))
            signals.forEach { signal ->
                append('\n')
                append('•')
                append(' ')
                append(getString(urlSignalString(signal)))
            }
        }
    }

    private fun urlSignalString(signal: UrlRiskSignal): Int = when (signal) {
        UrlRiskSignal.PLAIN_HTTP -> R.string.url_signal_http
        UrlRiskSignal.IP_ADDRESS_HOST -> R.string.url_signal_ip_host
        UrlRiskSignal.PUNYCODE_HOST -> R.string.url_signal_punycode
        UrlRiskSignal.USER_INFO -> R.string.url_signal_user_info
        UrlRiskSignal.NON_STANDARD_PORT -> R.string.url_signal_port
        UrlRiskSignal.MANY_SUBDOMAINS -> R.string.url_signal_subdomains
        UrlRiskSignal.LONG_URL -> R.string.url_signal_long
        UrlRiskSignal.SUSPICIOUS_KEYWORDS -> R.string.url_signal_keywords
    }

    private fun toggleBackgroundProtection() {
        if (protectionPreferences.enabled) {
            protectionPreferences.enabled = false
            ProtectionScheduler.disable(this)
            renderProtectionStatus()
            return
        }

        val preferences = getSharedPreferences(PRIVACY_PREFERENCES, MODE_PRIVATE)
        if (preferences.getInt(PROTECTION_DISCLOSURE_KEY, 0) >= PROTECTION_DISCLOSURE_VERSION) {
            enableBackgroundProtection()
            return
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.protection_disclosure_title)
            .setMessage(R.string.protection_disclosure_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.protection_continue_action) { _, _ ->
                preferences.edit()
                    .putInt(PROTECTION_DISCLOSURE_KEY, PROTECTION_DISCLOSURE_VERSION)
                    .apply()
                enableBackgroundProtection()
            }
            .show()
    }

    private fun enableBackgroundProtection() {
        protectionPreferences.enabled = true
        ProtectionNotifier.ensureChannel(this)
        ProtectionScheduler.enable(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        renderProtectionStatus()
    }

    private fun setProtectedFolder(uri: Uri) {
        val old = protectionPreferences.protectedTreeUri
        if (old != null && old != uri) {
            runCatching {
                contentResolver.releasePersistableUriPermission(old, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        }
        val granted = runCatching {
            contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            true
        }.getOrDefault(false)
        if (!granted) {
            showInfo(R.string.protection_check_failed)
            return
        }
        protectionPreferences.protectedTreeUri = uri
        protectionPreferences.folderPermissionLost = false
        protectionPreferences.clearLedger()
        if (protectionPreferences.enabled) ProtectionScheduler.enable(this)
        renderProtectionStatus()
    }

    private fun scanProtectedFolderNow() {
        val treeUri = protectionPreferences.protectedTreeUri
        if (treeUri == null) {
            showInfo(R.string.protection_choose_folder_first)
            return
        }
        binding.btnCheckProtectionNow.isEnabled = false
        binding.txtProtectionLastCheck.setText(R.string.protection_checking)
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    ProtectedFolderScanner(
                        resolver = contentResolver,
                        fileScanner = scanner,
                        preferences = protectionPreferences,
                        eventStore = protectionEventStore,
                        recordStore = recordStore,
                        notifier = { ProtectionNotifier.notifyEvent(applicationContext, it) }
                    ).scan(treeUri)
                }
            }
            binding.btnCheckProtectionNow.isEnabled = true
            outcome.onSuccess { summary ->
                renderProtectionStatus()
                if (summary.permissionLost) {
                    showInfo(R.string.protection_folder_permission_lost)
                } else {
                    binding.txtProtectionLastCheck.text = getString(
                        R.string.protection_check_result,
                        NumberFormat.getIntegerInstance().format(summary.scannedFiles),
                        NumberFormat.getIntegerInstance().format(summary.alerts)
                    )
                }
            }.onFailure {
                renderProtectionStatus()
                showInfo(R.string.protection_check_failed)
            }
        }
    }

    private fun renderProtectionStatus() {
        val enabled = protectionPreferences.enabled
        val notificationAllowed = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

        binding.txtProtectionState.setText(
            when {
                !enabled -> R.string.protection_state_disabled
                !notificationAllowed -> R.string.protection_state_notifications_off
                else -> R.string.protection_state_enabled
            }
        )
        binding.btnToggleProtection.setText(
            if (enabled) R.string.disable_protection_action else R.string.enable_protection_action
        )

        val treeUri = protectionPreferences.protectedTreeUri
        binding.txtProtectedFolder.text = if (treeUri == null) {
            getString(R.string.protected_folder_none)
        } else if (protectionPreferences.folderPermissionLost) {
            getString(R.string.protection_folder_permission_lost)
        } else {
            getString(R.string.protected_folder_line, treeUri.lastPathSegment ?: treeUri.toString())
        }

        binding.txtProtectionLastCheck.text = if (protectionPreferences.lastCheckAt <= 0L) {
            getString(R.string.protection_last_check_never)
        } else {
            getString(
                R.string.protection_last_check_line,
                formatDate(protectionPreferences.lastCheckAt),
                NumberFormat.getIntegerInstance().format(protectionPreferences.lastScannedCount),
                NumberFormat.getIntegerInstance().format(protectionPreferences.lastAlertCount)
            )
        }

        val events = protectionEventStore.events()
        binding.txtProtectionAlertCount.text = if (events.isEmpty()) {
            getString(R.string.protection_alert_count_zero)
        } else {
            getString(R.string.protection_alert_count, NumberFormat.getIntegerInstance().format(events.size))
        }
        binding.btnClearProtectionEvents.isEnabled = events.isNotEmpty()
        binding.protectionEventsContainer.removeAllViews()
        if (events.isEmpty()) {
            binding.protectionEventsContainer.addView(protectionEventText(getString(R.string.protection_no_recent_alerts)))
        } else {
            events.take(MAX_VISIBLE_PROTECTION_EVENTS).forEach { event ->
                binding.protectionEventsContainer.addView(protectionEventText(formatProtectionEvent(event)))
            }
        }
    }

    private fun formatProtectionEvent(event: ProtectionEvent): String {
        val type = getString(
            when (event.type) {
                ProtectionEventType.FILE -> R.string.protection_event_file
                ProtectionEventType.APP -> R.string.protection_event_app
            }
        )
        val severity = getString(
            when (event.severity) {
                ProtectionSeverity.HIGH_RISK -> R.string.protection_severity_high
                ProtectionSeverity.KNOWN_THREAT -> R.string.protection_severity_known
            }
        )
        return getString(R.string.protection_event_line, type, severity, event.displayName)
    }

    private fun protectionEventText(textValue: String): android.widget.TextView = android.widget.TextView(this).apply {
        text = textValue
        setTextColor(getColor(R.color.text_secondary))
        textSize = 12f
        val padding = (6 * resources.displayMetrics.density).toInt()
        setPadding(0, padding, 0, padding)
    }

    private fun requestInstalledAppsScan() {
        val preferences = getSharedPreferences(PRIVACY_PREFERENCES, MODE_PRIVATE)
        if (preferences.getInt(INSTALLED_SCAN_DISCLOSURE_KEY, 0) >= INSTALLED_SCAN_DISCLOSURE_VERSION) {
            scanInstalledApps()
            return
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.installed_apps_disclosure_title)
            .setMessage(R.string.installed_apps_disclosure_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.continue_scan) { _, _ ->
                preferences.edit()
                    .putInt(INSTALLED_SCAN_DISCLOSURE_KEY, INSTALLED_SCAN_DISCLOSURE_VERSION)
                    .apply()
                scanInstalledApps()
            }
            .show()
    }

    private fun scanInstalledApps() {
        binding.btnScanInstalledApps.isEnabled = false
        binding.txtInstalledSummary.setText(R.string.scanning_installed_apps)
        binding.txtInstalledEmpty.visibility = View.GONE
        binding.installedResultsContainer.removeAllViews()

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { installedAppScanner.scanUserApps() }
            }
            binding.btnScanInstalledApps.isEnabled = true
            result.onSuccess(::renderInstalledApps)
                .onFailure {
                    binding.txtInstalledSummary.setText(R.string.installed_scan_failed)
                }
        }
    }

    private fun renderInstalledApps(summary: InstalledAppsScanSummary) {
        val formatter = NumberFormat.getIntegerInstance()
        binding.txtInstalledSummary.text = getString(
            R.string.installed_scan_summary,
            formatter.format(summary.scannedApps),
            formatter.format(summary.reviewApps),
            formatter.format(summary.highRiskApps),
            formatter.format(summary.knownThreats)
        )

        val reviewResults = summary.results.filter { it.riskLevel != AppRiskLevel.LOW }
        binding.txtInstalledEmpty.visibility = if (reviewResults.isEmpty()) View.VISIBLE else View.GONE
        binding.installedResultsContainer.removeAllViews()

        reviewResults.take(MAX_VISIBLE_APP_RESULTS).forEach { app ->
            val item = ItemInstalledAppBinding.inflate(layoutInflater, binding.installedResultsContainer, false)
            renderInstalledAppItem(item, app)
            binding.installedResultsContainer.addView(item.root)
        }

        val hidden = reviewResults.size - MAX_VISIBLE_APP_RESULTS
        if (hidden > 0) {
            val item = android.widget.TextView(this).apply {
                text = getString(R.string.installed_scan_more, formatter.format(hidden))
                setTextColor(getColor(R.color.text_secondary))
                textSize = 12f
                val topPadding = (12 * resources.displayMetrics.density).toInt()
                setPadding(0, topPadding, 0, 0)
            }
            binding.installedResultsContainer.addView(item)
        }
    }

    private fun renderInstalledAppItem(binding: ItemInstalledAppBinding, app: InstalledAppScanResult) {
        binding.txtAppName.text = app.appName
        binding.txtRiskLevel.setText(
            when (app.riskLevel) {
                AppRiskLevel.LOW -> R.string.app_risk_low
                AppRiskLevel.MEDIUM -> R.string.app_risk_medium
                AppRiskLevel.HIGH -> R.string.app_risk_high
                AppRiskLevel.KNOWN_THREAT -> R.string.app_risk_known
            }
        )
        binding.txtPackageName.text = getString(R.string.package_name_line, app.packageName)
        binding.txtVersion.text = getString(R.string.version_name_line, app.versionName ?: "—")
        binding.txtInstallSource.text = getString(R.string.install_source_line, getString(installSourceString(app.installSource)))
        binding.txtRiskScore.text = getString(R.string.risk_score_line, NumberFormat.getIntegerInstance().format(app.riskScore))
        binding.txtIndicators.text = formatSignals(app.signals)
        binding.txtApkHash.text = getString(R.string.apk_hash_line, app.apkSha256 ?: "—")
        binding.txtCertificateHash.text = getString(R.string.certificate_hash_line, app.signingCertificateSha256 ?: "—")

        if (app.threatReference != null) {
            binding.txtThreatReference.visibility = View.VISIBLE
            binding.txtThreatReference.text = getString(R.string.threat_reference_line, app.threatReference)
        } else {
            binding.txtThreatReference.visibility = View.GONE
            binding.txtThreatReference.text = ""
        }
    }

    private fun formatSignals(signals: Set<AppRiskSignal>): String {
        if (signals.isEmpty()) return getString(R.string.no_indicators_detail)
        val lines = signals.map { getString(riskSignalString(it)) }
        return buildString {
            append(getString(R.string.indicators_title))
            lines.forEach {
                append('\n')
                append('•')
                append(' ')
                append(it)
            }
        }
    }

    private fun riskSignalString(signal: AppRiskSignal): Int = when (signal) {
        AppRiskSignal.ACCESSIBILITY_SERVICE -> R.string.indicator_accessibility
        AppRiskSignal.OVERLAY -> R.string.indicator_overlay
        AppRiskSignal.INSTALL_PACKAGES -> R.string.indicator_install_packages
        AppRiskSignal.SMS_ACCESS -> R.string.indicator_sms
        AppRiskSignal.CONTACTS_ACCESS -> R.string.indicator_contacts
        AppRiskSignal.CALL_LOG_ACCESS -> R.string.indicator_call_log
        AppRiskSignal.MICROPHONE -> R.string.indicator_microphone
        AppRiskSignal.CAMERA -> R.string.indicator_camera
        AppRiskSignal.PRECISE_LOCATION -> R.string.indicator_location
        AppRiskSignal.BOOT_START -> R.string.indicator_boot
        AppRiskSignal.NON_STORE_INSTALL -> R.string.indicator_non_store
    }

    private fun installSourceString(source: AppInstallSource): Int = when (source) {
        AppInstallSource.STORE -> R.string.source_store
        AppInstallSource.LOCAL_FILE -> R.string.source_local_file
        AppInstallSource.DOWNLOADED_FILE -> R.string.source_downloaded_file
        AppInstallSource.OTHER -> R.string.source_other
        AppInstallSource.UNKNOWN -> R.string.source_unknown
    }

    private fun resetResult() {
        lastScanResult = null
        binding.txtClassification.setText(R.string.result_not_scanned)
        binding.txtReason.text = ""
        binding.txtTechnical.text = ""
        binding.txtApkAnalysis.text = ""
        binding.txtApkAnalysis.visibility = View.GONE
        binding.resultActions.visibility = View.GONE
        binding.btnQuarantine.isEnabled = false
        binding.btnExclusion.isEnabled = false
    }

    private fun scanSelectedFile() {
        val uri = selectedUri ?: return
        binding.btnScanFile.isEnabled = false
        binding.btnChooseFile.isEnabled = false
        binding.txtClassification.setText(R.string.scanning)
        binding.txtReason.text = ""
        binding.txtTechnical.text = ""
        binding.txtApkAnalysis.text = ""
        binding.txtApkAnalysis.visibility = View.GONE
        binding.resultActions.visibility = View.GONE

        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) { runCatching { scanner.scan(uri) } }
            binding.btnScanFile.isEnabled = true
            binding.btnChooseFile.isEnabled = true
            outcome.onSuccess { result ->
                lastScanResult = result
                withContext(Dispatchers.IO) { recordStore.recordScan(result) }
                renderResult(result)
                renderSecurityManagement()
            }.onFailure {
                lastScanResult = null
                binding.txtClassification.setText(R.string.scan_failed)
                binding.txtReason.setText(R.string.file_access_error)
            }
        }
    }

    private fun renderResult(result: ScanResult) {
        val excluded = recordStore.isExcluded(result.sha256)
        val titleRes = when (result.classification) {
            ScanClassification.NO_KNOWN_THREAT -> R.string.result_no_known_threat
            ScanClassification.UNKNOWN_APK -> R.string.result_unknown_apk
            ScanClassification.SUSPICIOUS -> R.string.result_suspicious
            ScanClassification.KNOWN_THREAT -> R.string.result_threat
            ScanClassification.TEST_SIGNATURE -> R.string.result_test_signature
        }
        val reasonRes = when (result.detectionReason) {
            ScanDetectionReason.NO_SIGNATURE -> R.string.reason_no_signature
            ScanDetectionReason.UNKNOWN_APK -> R.string.reason_unknown_apk
            ScanDetectionReason.DOUBLE_EXTENSION -> R.string.reason_double_extension
            ScanDetectionReason.APK_STATIC_HIGH_RISK -> R.string.reason_apk_static_high_risk
            ScanDetectionReason.APK_INVALID -> R.string.reason_apk_invalid
            ScanDetectionReason.APK_IDENTITY_MATCH -> R.string.reason_apk_identity_match
            ScanDetectionReason.APK_IDENTITY_TEST -> R.string.reason_apk_identity_test
            ScanDetectionReason.KNOWN_FILE_SIGNATURE -> R.string.reason_signature_match
            ScanDetectionReason.TEST_SIGNATURE -> R.string.reason_eicar_test
        }

        binding.txtClassification.setText(titleRes)
        binding.txtReason.text = if (excluded) {
            getString(R.string.result_excluded_reason, getString(reasonRes))
        } else {
            getString(reasonRes)
        }
        val formattedSize = if (result.sizeBytes >= 0) {
            NumberFormat.getIntegerInstance().format(result.sizeBytes)
        } else {
            "—"
        }
        binding.txtTechnical.text = buildString {
            append(getString(R.string.file_size_label))
            append(": ")
            append(getString(R.string.bytes_value, formattedSize))
            append('\n')
            append(getString(R.string.sha256_label))
            append(": ")
            append(result.sha256)
            if (result.signatureId != null) {
                append('\n')
                append(getString(R.string.signature_id_label))
                append(": ")
                append(result.signatureId)
            }
        }

        renderApkAnalysis(result.apkAnalysis)

        binding.resultActions.visibility = View.VISIBLE
        binding.btnExclusion.isEnabled = true
        binding.btnExclusion.setText(if (excluded) R.string.remove_exclusion_action else R.string.add_exclusion_action)
        val quarantineEligible = QuarantinePolicy.canOfferQuarantine(result.classification, excluded)
        binding.btnQuarantine.isEnabled = quarantineEligible
        binding.btnQuarantine.visibility = if (quarantineEligible) View.VISIBLE else View.GONE
    }

    private fun renderApkAnalysis(analysis: ApkStaticAnalysis?) {
        if (analysis == null) {
            binding.txtApkAnalysis.text = ""
            binding.txtApkAnalysis.visibility = View.GONE
            return
        }
        binding.txtApkAnalysis.visibility = View.VISIBLE
        binding.txtApkAnalysis.text = when (analysis.state) {
            ApkAnalysisState.INVALID_APK -> getString(R.string.apk_analysis_invalid)
            ApkAnalysisState.LIMIT_EXCEEDED -> getString(R.string.apk_analysis_limit)
            ApkAnalysisState.SOURCE_CHANGED -> getString(R.string.apk_analysis_changed)
            ApkAnalysisState.FAILED -> getString(R.string.apk_analysis_failed)
            ApkAnalysisState.VALID -> buildString {
                append(getString(R.string.apk_analysis_title))
                append('\n')
                append(
                    getString(
                        when (analysis.riskLevel) {
                            ApkRiskLevel.LOW -> R.string.apk_analysis_low
                            ApkRiskLevel.REVIEW -> R.string.apk_analysis_review
                            ApkRiskLevel.HIGH -> R.string.apk_analysis_high
                        }
                    )
                )
                append('\n')
                append(
                    getString(
                        R.string.apk_analysis_summary,
                        NumberFormat.getIntegerInstance().format(analysis.riskScore),
                        NumberFormat.getIntegerInstance().format(analysis.requestedPermissionCount),
                        NumberFormat.getIntegerInstance().format(analysis.componentCount),
                        NumberFormat.getIntegerInstance().format(analysis.dexFileCount),
                        NumberFormat.getIntegerInstance().format(analysis.nativeLibraryCount)
                    )
                )
                analysis.signingCertificateSha256?.let {
                    append('\n')
                    append(getString(R.string.apk_analysis_signer_hash, it))
                }
                analysis.identityIndicator?.let { indicator ->
                    append('\n')
                    append(
                        getString(
                            if (indicator.classification == ApkIdentityClassification.KNOWN_THREAT) {
                                R.string.apk_analysis_identity_known
                            } else {
                                R.string.apk_analysis_identity_test
                            }
                        )
                    )
                }
                append('\n')
                append(formatApkSignals(analysis.signals))
                if (analysis.codeScanTruncated) {
                    append('\n')
                    append(getString(R.string.apk_analysis_truncated))
                }
                append('\n')
                append(getString(R.string.apk_analysis_note))
            }
        }
    }

    private fun formatApkSignals(signals: Set<ApkRiskSignal>): String {
        if (signals.isEmpty()) return getString(R.string.apk_analysis_no_indicators)
        return buildString {
            append(getString(R.string.apk_analysis_indicators_title))
            signals.forEach { signal ->
                append('\n')
                append('•')
                append(' ')
                append(getString(apkSignalString(signal)))
            }
        }
    }

    private fun apkSignalString(signal: ApkRiskSignal): Int = when (signal) {
        ApkRiskSignal.ACCESSIBILITY_SERVICE -> R.string.apk_signal_accessibility
        ApkRiskSignal.DEVICE_ADMIN_RECEIVER -> R.string.apk_signal_device_admin
        ApkRiskSignal.NOTIFICATION_LISTENER_SERVICE -> R.string.apk_signal_notification_listener
        ApkRiskSignal.VPN_SERVICE -> R.string.apk_signal_vpn
        ApkRiskSignal.OVERLAY_PERMISSION -> R.string.apk_signal_overlay
        ApkRiskSignal.REQUEST_INSTALL_PACKAGES -> R.string.apk_signal_install_packages
        ApkRiskSignal.SMS_ACCESS -> R.string.apk_signal_sms
        ApkRiskSignal.CONTACTS_ACCESS -> R.string.apk_signal_contacts
        ApkRiskSignal.CALL_LOG_ACCESS -> R.string.apk_signal_call_log
        ApkRiskSignal.MICROPHONE -> R.string.apk_signal_microphone
        ApkRiskSignal.CAMERA -> R.string.apk_signal_camera
        ApkRiskSignal.PRECISE_LOCATION -> R.string.apk_signal_location
        ApkRiskSignal.BOOT_START -> R.string.apk_signal_boot
        ApkRiskSignal.QUERY_ALL_PACKAGES -> R.string.apk_signal_query_packages
        ApkRiskSignal.DEBUGGABLE -> R.string.apk_signal_debuggable
        ApkRiskSignal.NATIVE_CODE -> R.string.apk_signal_native_code
        ApkRiskSignal.MANY_DEX_FILES -> R.string.apk_signal_many_code_files
        ApkRiskSignal.DYNAMIC_CODE_LOADING -> R.string.apk_signal_dynamic_loading
        ApkRiskSignal.RUNTIME_EXECUTION -> R.string.apk_signal_runtime_execution
        ApkRiskSignal.SMS_API -> R.string.apk_signal_sms_api
        ApkRiskSignal.DEVICE_IDENTIFIER_API -> R.string.apk_signal_device_identifier
    }

    private fun toggleExclusion() {
        val result = lastScanResult ?: return
        if (recordStore.isExcluded(result.sha256)) {
            recordStore.removeExclusion(result.sha256)
            renderResult(result)
            renderSecurityManagement()
            showInfo(R.string.exclusion_removed_success)
            return
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.exclusion_confirm_title)
            .setMessage(R.string.exclusion_confirm_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.add_exclusion_action) { _, _ ->
                recordStore.addExclusion(result)
                renderResult(result)
                renderSecurityManagement()
                showInfo(R.string.exclusion_added_success)
            }
            .show()
    }

    private fun confirmQuarantine() {
        val result = lastScanResult ?: return
        val uri = selectedUri ?: return
        if (recordStore.isExcluded(result.sha256)) return

        AlertDialog.Builder(this)
            .setTitle(R.string.quarantine_confirm_title)
            .setMessage(R.string.quarantine_confirm_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.quarantine_action) { _, _ -> quarantineSelectedFile(uri, result) }
            .show()
    }

    private fun quarantineSelectedFile(uri: Uri, result: ScanResult) {
        binding.btnQuarantine.isEnabled = false
        binding.btnChooseFile.isEnabled = false
        binding.btnScanFile.isEnabled = false
        binding.txtReason.setText(R.string.quarantine_progress)
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) { quarantineManager.quarantine(uri, result) }
            binding.btnChooseFile.isEnabled = true
            when (outcome) {
                is QuarantineManager.QuarantineResult.Success -> {
                    selectedUri = null
                    binding.txtSelectedFile.setText(R.string.no_file_selected)
                    binding.btnScanFile.isEnabled = false
                    resetResult()
                    renderSecurityManagement()
                    showInfo(R.string.quarantine_success)
                }
                QuarantineManager.QuarantineResult.SourceChanged -> {
                    binding.btnScanFile.isEnabled = true
                    renderResult(result)
                    showInfo(R.string.quarantine_source_changed)
                }
                QuarantineManager.QuarantineResult.SourceRemovalFailed -> {
                    binding.btnScanFile.isEnabled = true
                    renderResult(result)
                    showInfo(R.string.quarantine_source_remove_failed)
                }
                QuarantineManager.QuarantineResult.Failed -> {
                    binding.btnScanFile.isEnabled = true
                    renderResult(result)
                    showInfo(R.string.quarantine_failed)
                }
            }
        }
    }

    private fun renderSecurityManagement() {
        renderQuarantine()
        renderExclusions()
        renderHistory()
    }

    private fun renderQuarantine() {
        val entries = recordStore.quarantineEntries()
        binding.txtQuarantineCount.text = getString(
            R.string.quarantine_count,
            NumberFormat.getIntegerInstance().format(entries.size)
        )
        binding.txtQuarantineEmpty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
        binding.quarantineContainer.removeAllViews()
        entries.take(MAX_VISIBLE_SECURITY_RECORDS).forEach { entry ->
            val item = ItemQuarantineBinding.inflate(layoutInflater, binding.quarantineContainer, false)
            renderQuarantineItem(item, entry)
            binding.quarantineContainer.addView(item.root)
        }
    }

    private fun renderQuarantineItem(binding: ItemQuarantineBinding, entry: QuarantineEntry) {
        binding.txtQuarantineName.text = entry.fileName
        binding.txtQuarantineClassification.setText(classificationString(entry.classification))
        binding.txtQuarantineHash.text = getString(R.string.quarantine_item_hash, entry.sha256)
        binding.txtQuarantineDate.text = getString(R.string.quarantine_item_date, formatDate(entry.quarantinedAt))
        binding.btnRestore.setOnClickListener { confirmRestore(entry) }
        binding.btnDeleteQuarantine.setOnClickListener { confirmDeleteQuarantine(entry) }
    }

    private fun confirmRestore(entry: QuarantineEntry) {
        AlertDialog.Builder(this)
            .setTitle(R.string.restore_confirm_title)
            .setMessage(R.string.restore_confirm_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.restore_action) { _, _ ->
                pendingRestoreId = entry.id
                restorePicker.launch(entry.fileName)
            }
            .show()
    }

    private fun restoreQuarantinedFile(id: String, destination: Uri) {
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) { quarantineManager.restore(id, destination) }
            when (outcome) {
                QuarantineManager.RestoreResult.Success -> {
                    renderSecurityManagement()
                    showInfo(R.string.restore_success)
                }
                QuarantineManager.RestoreResult.IntegrityFailed -> showInfo(R.string.restore_integrity_failed)
                QuarantineManager.RestoreResult.Failed -> showInfo(R.string.restore_failed)
            }
        }
    }

    private fun confirmDeleteQuarantine(entry: QuarantineEntry) {
        AlertDialog.Builder(this)
            .setTitle(R.string.delete_quarantine_confirm_title)
            .setMessage(R.string.delete_quarantine_confirm_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.delete_action) { _, _ ->
                lifecycleScope.launch {
                    val deleted = withContext(Dispatchers.IO) { quarantineManager.deletePermanently(entry.id) }
                    renderSecurityManagement()
                    showInfo(if (deleted) R.string.delete_quarantine_success else R.string.delete_quarantine_failed)
                }
            }
            .show()
    }

    private fun renderExclusions() {
        val entries = recordStore.exclusions()
        binding.txtExclusionsCount.text = getString(
            R.string.exclusions_count,
            NumberFormat.getIntegerInstance().format(entries.size)
        )
        binding.txtExclusionsEmpty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
        binding.exclusionsContainer.removeAllViews()
        entries.take(MAX_VISIBLE_SECURITY_RECORDS).forEach { entry ->
            val item = ItemExclusionBinding.inflate(layoutInflater, binding.exclusionsContainer, false)
            renderExclusionItem(item, entry)
            binding.exclusionsContainer.addView(item.root)
        }
    }

    private fun renderExclusionItem(binding: ItemExclusionBinding, entry: ExclusionEntry) {
        binding.txtExclusionName.text = entry.fileName
        binding.txtExclusionHash.text = getString(R.string.exclusion_item_hash, entry.sha256)
        binding.txtExclusionDate.text = getString(R.string.exclusion_item_date, formatDate(entry.addedAt))
        binding.btnRemoveExclusion.setOnClickListener {
            recordStore.removeExclusion(entry.sha256)
            lastScanResult?.takeIf { it.sha256.equals(entry.sha256, ignoreCase = true) }?.let(::renderResult)
            renderSecurityManagement()
            showInfo(R.string.exclusion_removed_success)
        }
    }

    private fun renderHistory() {
        val entries = recordStore.history()
        binding.txtHistoryCount.text = getString(
            R.string.history_count,
            NumberFormat.getIntegerInstance().format(entries.size)
        )
        binding.txtHistoryEmpty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
        binding.btnClearHistory.isEnabled = entries.isNotEmpty()
        binding.historyContainer.removeAllViews()
        entries.take(MAX_VISIBLE_HISTORY).forEach { entry ->
            val item = ItemHistoryBinding.inflate(layoutInflater, binding.historyContainer, false)
            renderHistoryItem(item, entry)
            binding.historyContainer.addView(item.root)
        }
    }

    private fun renderHistoryItem(binding: ItemHistoryBinding, entry: ScanHistoryEntry) {
        binding.txtHistoryName.text = entry.fileName
        binding.txtHistoryClassification.setText(classificationString(entry.classification))
        binding.txtHistoryDate.text = getString(R.string.history_item_date, formatDate(entry.scannedAt))
        binding.txtHistoryHash.text = getString(R.string.history_item_hash, entry.sha256)
    }

    private fun confirmClearHistory() {
        AlertDialog.Builder(this)
            .setTitle(R.string.clear_history_confirm_title)
            .setMessage(R.string.clear_history_confirm_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.clear_history_action) { _, _ ->
                recordStore.clearHistory()
                renderHistory()
            }
            .show()
    }

    private fun classificationString(classification: ScanClassification): Int = when (classification) {
        ScanClassification.NO_KNOWN_THREAT -> R.string.result_no_known_threat
        ScanClassification.UNKNOWN_APK -> R.string.result_unknown_apk
        ScanClassification.SUSPICIOUS -> R.string.result_suspicious
        ScanClassification.KNOWN_THREAT -> R.string.result_threat
        ScanClassification.TEST_SIGNATURE -> R.string.result_test_signature
    }

    private fun formatDate(timestamp: Long): String = DateFormat.getDateTimeInstance(
        DateFormat.MEDIUM,
        DateFormat.SHORT
    ).format(Date(timestamp))

    private fun showInfo(messageRes: Int) {
        AlertDialog.Builder(this)
            .setMessage(messageRes)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun showLanguageDialog() {
        val items = arrayOf(getString(R.string.language_english), getString(R.string.language_arabic))
        val appLocales = AppCompatDelegate.getApplicationLocales()
        val currentLanguage = if (!appLocales.isEmpty) appLocales[0]?.language else resources.configuration.locales[0]?.language
        val checked = if (currentLanguage == "ar") 1 else 0
        AlertDialog.Builder(this)
            .setTitle(R.string.language_dialog_title)
            .setSingleChoiceItems(items, checked) { dialog, which ->
                val tag = if (which == 1) "ar" else "en"
                AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))
                dialog.dismiss()
            }
            .show()
    }

    companion object {
        private const val PRIVACY_PREFERENCES = "privacy_preferences"
        private const val INSTALLED_SCAN_DISCLOSURE_KEY = "installed_scan_disclosure_version"
        private const val INSTALLED_SCAN_DISCLOSURE_VERSION = 1
        private const val PROTECTION_DISCLOSURE_KEY = "background_protection_disclosure_version"
        private const val PROTECTION_DISCLOSURE_VERSION = 1
        private const val MAX_VISIBLE_PROTECTION_EVENTS = 8
        private const val MAX_VISIBLE_APP_RESULTS = 20
        private const val MAX_VISIBLE_SECURITY_RECORDS = 20
        private const val MAX_VISIBLE_HISTORY = 20
    }
}

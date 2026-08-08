package com.aman.security

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.lifecycleScope
import com.aman.security.databinding.ActivityMainBinding
import com.aman.security.databinding.ItemInstalledAppBinding
import com.aman.security.databinding.ItemExclusionBinding
import com.aman.security.databinding.ItemHistoryBinding
import com.aman.security.databinding.ItemQuarantineBinding
import com.aman.security.scanner.AppInstallSource
import com.aman.security.scanner.AppRiskLevel
import com.aman.security.scanner.AppRiskSignal
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.InstalledAppScanResult
import com.aman.security.scanner.InstalledAppScanner
import com.aman.security.scanner.InstalledAppsScanSummary
import com.aman.security.scanner.ScanClassification
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
    private lateinit var installedAppScanner: InstalledAppScanner
    private lateinit var updater: ThreatDatabaseUpdater
    private lateinit var urlScanner: UrlScanner
    private lateinit var recordStore: SecurityRecordStore
    private lateinit var quarantineManager: QuarantineManager
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        database = SignatureDatabase(this)
        scanner = FileScanner(contentResolver, database)
        installedAppScanner = InstalledAppScanner(this, database)
        updater = ThreatDatabaseUpdater(this, database)
        urlScanner = UrlScanner(database::findUrl)
        recordStore = SecurityRecordStore(this)
        quarantineManager = QuarantineManager(this, recordStore)
        renderDatabaseInfo()
        renderSecurityManagement()

        binding.btnChooseFile.setOnClickListener { filePicker.launch(arrayOf("*/*")) }
        binding.btnScanFile.setOnClickListener { scanSelectedFile() }
        binding.btnScanInstalledApps.setOnClickListener { requestInstalledAppsScan() }
        binding.btnScanUrl.setOnClickListener { scanUrlInput() }
        binding.btnUpdateDatabase.setOnClickListener { updateThreatDatabase() }
        binding.btnLanguage.setOnClickListener { showLanguageDialog() }
        binding.btnQuarantine.setOnClickListener { confirmQuarantine() }
        binding.btnExclusion.setOnClickListener { toggleExclusion() }
        binding.btnClearHistory.setOnClickListener { confirmClearHistory() }
        handleIncomingIntent(intent)
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
            NumberFormat.getIntegerInstance().format(info.urlEntries)
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
                        NumberFormat.getIntegerInstance().format(result.urlEntries)
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
        val reasonRes = when {
            result.classification == ScanClassification.TEST_SIGNATURE -> R.string.reason_eicar_test
            result.classification == ScanClassification.KNOWN_THREAT -> R.string.reason_signature_match
            result.classification == ScanClassification.SUSPICIOUS -> R.string.reason_double_extension
            result.classification == ScanClassification.UNKNOWN_APK -> R.string.reason_unknown_apk
            else -> R.string.reason_no_signature
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

        binding.resultActions.visibility = View.VISIBLE
        binding.btnExclusion.isEnabled = true
        binding.btnExclusion.setText(if (excluded) R.string.remove_exclusion_action else R.string.add_exclusion_action)
        val quarantineEligible = QuarantinePolicy.canOfferQuarantine(result.classification, excluded)
        binding.btnQuarantine.isEnabled = quarantineEligible
        binding.btnQuarantine.visibility = if (quarantineEligible) View.VISIBLE else View.GONE
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
        private const val MAX_VISIBLE_APP_RESULTS = 20
        private const val MAX_VISIBLE_SECURITY_RECORDS = 20
        private const val MAX_VISIBLE_HISTORY = 20
    }
}

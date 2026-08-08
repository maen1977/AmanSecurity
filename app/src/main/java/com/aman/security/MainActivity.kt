package com.aman.security

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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.NumberFormat

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var database: SignatureDatabase
    private lateinit var scanner: FileScanner
    private lateinit var installedAppScanner: InstalledAppScanner
    private lateinit var updater: ThreatDatabaseUpdater
    private var selectedUri: Uri? = null

    private val filePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            selectedUri = uri
            runCatching {
                contentResolver.takePersistableUriPermission(uri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            binding.txtSelectedFile.text = uri.lastPathSegment ?: getString(R.string.selected_file_title)
            binding.btnScanFile.isEnabled = true
            resetResult()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        database = SignatureDatabase(this)
        scanner = FileScanner(contentResolver, database)
        installedAppScanner = InstalledAppScanner(this, database)
        updater = ThreatDatabaseUpdater(this, database)
        renderDatabaseInfo()

        binding.btnChooseFile.setOnClickListener { filePicker.launch(arrayOf("*/*")) }
        binding.btnScanFile.setOnClickListener { scanSelectedFile() }
        binding.btnScanInstalledApps.setOnClickListener { requestInstalledAppsScan() }
        binding.btnUpdateDatabase.setOnClickListener { updateThreatDatabase() }
        binding.btnLanguage.setOnClickListener { showLanguageDialog() }
    }

    private fun renderDatabaseInfo() {
        val info = database.info
        binding.txtDatabaseVersion.text = getString(R.string.database_version, info.version)
        binding.txtDatabaseEntries.text = getString(R.string.database_entries, NumberFormat.getIntegerInstance().format(info.entries))
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
                        NumberFormat.getIntegerInstance().format(result.entries)
                    )
                }
                ThreatDatabaseUpdater.Result.InvalidSignature -> binding.txtUpdateStatus.setText(R.string.update_invalid_signature)
                ThreatDatabaseUpdater.Result.InvalidDatabase -> binding.txtUpdateStatus.setText(R.string.update_invalid_database)
                ThreatDatabaseUpdater.Result.NetworkError -> binding.txtUpdateStatus.setText(R.string.update_network_error)
            }
        }
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
        binding.txtClassification.setText(R.string.result_not_scanned)
        binding.txtReason.text = ""
        binding.txtTechnical.text = ""
    }

    private fun scanSelectedFile() {
        val uri = selectedUri ?: return
        binding.btnScanFile.isEnabled = false
        binding.btnChooseFile.isEnabled = false
        binding.txtClassification.setText(R.string.scanning)
        binding.txtReason.text = ""
        binding.txtTechnical.text = ""

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { runCatching { scanner.scan(uri) } }
            binding.btnScanFile.isEnabled = true
            binding.btnChooseFile.isEnabled = true
            result.onSuccess(::renderResult)
                .onFailure {
                    binding.txtClassification.setText(R.string.scan_failed)
                    binding.txtReason.setText(R.string.file_access_error)
                }
        }
    }

    private fun renderResult(result: ScanResult) {
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
        binding.txtReason.setText(reasonRes)
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
    }
}

package com.aman.security

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.role.RoleManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.widget.Toast
import android.view.View
import android.view.accessibility.AccessibilityManager
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.lifecycleScope
import com.aman.security.databinding.ActivityMainBinding
import com.aman.security.banking.BankingGuardAccessibilityService
import com.aman.security.databinding.ItemInstalledAppBinding
import com.aman.security.databinding.ItemExclusionBinding
import com.aman.security.databinding.ItemHistoryBinding
import com.aman.security.databinding.ItemQuarantineBinding
import com.aman.security.autonomous.AutonomousThreatScheduler
import com.aman.security.autonomous.AutonomousThreatUpdater
import com.aman.security.autonomous.AutonomousUpdateResult
import com.aman.security.protection.ProtectedFolderScanner
import com.aman.security.protection.ProtectedFolderScanSummary
import com.aman.security.protection.DownloadProtectionScanner
import com.aman.security.protection.LocalScanCacheStore
import com.aman.security.protection.DownloadScanSummary
import com.aman.security.protection.ProtectionAccess
import com.aman.security.protection.ProtectionActivityEntry
import com.aman.security.protection.ProtectionActivityKind
import com.aman.security.protection.ProtectionActivityState
import com.aman.security.protection.ProtectionActivityStore
import com.aman.security.protection.ProtectionServiceController
import com.aman.security.protection.SharedStorageScanner
import com.aman.security.protection.SharedStorageScanSummary
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
import com.aman.security.scanner.FileScanStage
import java.util.concurrent.CancellationException
import com.aman.security.scanner.InstalledAppScanResult
import com.aman.security.scanner.InstalledAppScanner
import com.aman.security.scanner.InstalledAppsScanSummary
import com.aman.security.scanner.ScanClassification
import com.aman.security.scanner.ScanDetectionReason
import com.aman.security.scanner.ScanResult
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.scanner.SharedUrlExtractor
import com.aman.security.scanner.UrlRiskLevel
import com.aman.security.scanner.UrlRiskSignal
import com.aman.security.scanner.UrlScanResult
import com.aman.security.scanner.UrlScanner
import com.aman.security.security.AttackDetectionCenter
import com.aman.security.security.AttackDetectionLevel
import com.aman.security.security.AppIntegrityInspector
import com.aman.security.security.DeviceSecurityAuditor
import com.aman.security.security.DataExfiltrationAccess
import com.aman.security.security.DataExfiltrationGuard
import com.aman.security.security.NetworkSecurityAuditor
import com.aman.security.security.NetworkTransportType
import com.aman.security.security.PrivacyPermissionAuditor
import com.aman.security.security.SecurityAuditSummary
import com.aman.security.security.SpywareAuditor
import com.aman.security.security.SpywareAuditSummary
import com.aman.security.security.IntrusionMonitor
import com.aman.security.security.integrityChangeLabel
import com.aman.security.security.privilegedAccessLabel
import com.aman.security.security.AppIntegrityStatus
import com.aman.security.security.ProtectionPostureEvaluator
import com.aman.security.security.ProtectionPostureInput
import com.aman.security.security.ProtectionPostureLevel
import com.aman.security.security.ExclusionEntry
import com.aman.security.security.QuarantineEntry
import com.aman.security.security.QuarantineManager
import com.aman.security.security.QuarantinePolicy
import com.aman.security.security.ScanHistoryEntry
import com.aman.security.security.SecurityRecordStore
import com.aman.security.detection.ThreatFamily
import com.aman.security.web.LocalWebShieldController
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date
import java.time.Instant

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var database: SignatureDatabase
    private lateinit var scanner: FileScanner
    private lateinit var apkStaticAnalyzer: ApkStaticAnalyzer
    private lateinit var installedAppScanner: InstalledAppScanner
    private lateinit var updater: AutonomousThreatUpdater
    private lateinit var urlScanner: UrlScanner
    private lateinit var recordStore: SecurityRecordStore
    private lateinit var quarantineManager: QuarantineManager
    private lateinit var protectionPreferences: ProtectionPreferences
    private lateinit var protectionEventStore: ProtectionEventStore
    private lateinit var protectionActivityStore: ProtectionActivityStore
    private var selectedUri: Uri? = null
    private var lastScanResult: ScanResult? = null
    private var lastInstalledSummary: InstalledAppsScanSummary? = null
    private var lastSecurityAudit: SecurityAuditSummary? = null
    private var lastSecurityAuditAt: Long = 0L
    private var securityAuditRunning: Boolean = false
    private var pendingRestoreId: String? = null
    @Volatile private var scanCancelRequested: Boolean = false
    private var activeScan: Boolean = false
    private var renderingProtectionControls: Boolean = false

    /**
     * Last-resort protection for unexpected exceptions in lifecycleScope jobs. A failed
     * background audit/update must never take down the whole Activity. Individual scan
     * operations still report their own detailed failure states when possible.
     */
    private val uiCoroutineErrorHandler = CoroutineExceptionHandler { _, throwable ->
        Log.e(TAG, "Unhandled UI coroutine failure", throwable)
        runOnUiThread {
            if (!::binding.isInitialized || isFinishing || isDestroyed) return@runOnUiThread
            securityAuditRunning = false
            activeScan = false
            scanCancelRequested = false
            binding.btnRunSecurityAudit.isEnabled = true
            binding.btnStopScan.isEnabled = false
            setScanControlsEnabled(true)
            binding.btnUpdateDatabase.isEnabled = true
            binding.btnCheckProtectionNow.isEnabled = true
            Toast.makeText(this, R.string.operation_failed_try_again, Toast.LENGTH_LONG).show()
        }
    }

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

    private val allFilesAccessLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        onAntivirusFileAccessReturn()
    }

    private val legacyStoragePermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        onAntivirusFileAccessReturn()
    }

    private val webGuardRoleLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        renderWebGuardStatus()
    }

    private val localWebShieldPermissionLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val granted = LocalWebShieldController.isPermissionGranted(this)
        protectionPreferences.localWebShieldEnabled = granted
        if (granted && protectionPreferences.enabled) {
            runCatching { LocalWebShieldController.start(this) }
        }
        binding.root.postDelayed({ if (!isFinishing && !isDestroyed) renderProtectionStatus() }, 700L)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        database = SignatureDatabase(this)
        apkStaticAnalyzer = ApkStaticAnalyzer(this, database)
        scanner = FileScanner(contentResolver, database, apkStaticAnalyzer)
        installedAppScanner = InstalledAppScanner(this, database)
        updater = AutonomousThreatUpdater(this, database)
        urlScanner = UrlScanner(database::findUrl)
        recordStore = SecurityRecordStore(this)
        quarantineManager = QuarantineManager(this, recordStore)
        protectionPreferences = ProtectionPreferences(this)
        protectionEventStore = ProtectionEventStore(this)
        protectionActivityStore = ProtectionActivityStore(this)
        ProtectionNotifier.ensureChannels(this)
        AutonomousThreatScheduler.schedule(this)
        renderDatabaseInfo()
        renderSecurityManagement()
        renderProtectionStatus()
        renderWebGuardStatus()
        setupNavigation()
        binding.txtHomeVersion.text = BuildConfig.VERSION_NAME

        binding.btnChooseFile.setOnClickListener { filePicker.launch(arrayOf("*/*")) }
        binding.btnScanFile.setOnClickListener { scanSelectedFile() }
        binding.btnScanInstalledApps.setOnClickListener { requestInstalledAppsScan() }
        binding.btnScanUrl.setOnClickListener { scanUrlInput() }
        binding.btnConfigureWebGuard.setOnClickListener { configureWebGuard() }
        binding.switchLocalWebShield.setOnCheckedChangeListener { _, checked ->
            if (renderingProtectionControls) return@setOnCheckedChangeListener
            if (checked) requestLocalWebShieldEnable() else {
                protectionPreferences.localWebShieldEnabled = false
                LocalWebShieldController.stop(this)
                renderProtectionStatus()
            }
        }
        binding.switchIntrusionMonitor.setOnCheckedChangeListener { _, checked ->
            if (renderingProtectionControls) return@setOnCheckedChangeListener
            protectionPreferences.intrusionMonitorEnabled = checked
            if (checked && protectionPreferences.enabled) ProtectionScheduler.intrusionCheckNow(this)
            renderProtectionStatus()
        }
        binding.btnRunIntrusionCheck.setOnClickListener { runIntrusionCheckNow() }
        binding.btnAttackCheckNow.setOnClickListener { runIntrusionCheckNow() }
        binding.switchDataExfilGuard.setOnCheckedChangeListener { _, checked ->
            if (renderingProtectionControls) return@setOnCheckedChangeListener
            if (checked) requestDataExfiltrationEnable() else {
                protectionPreferences.dataExfiltrationGuardEnabled = false
                renderProtectionStatus()
            }
        }
        binding.btnDataUsageAccess.setOnClickListener { openUsageAccessSettings() }
        binding.btnRunDataExfilCheck.setOnClickListener { runDataExfiltrationCheckNow() }
        binding.switchBankingProtection.setOnCheckedChangeListener { _, checked ->
            if (renderingProtectionControls) return@setOnCheckedChangeListener
            if (checked) requestBankingProtectionEnable() else {
                protectionPreferences.bankingProtectionEnabled = false
                renderProtectionStatus()
            }
        }
        binding.switchBankingBlockHighRisk.setOnCheckedChangeListener { _, checked ->
            if (renderingProtectionControls) return@setOnCheckedChangeListener
            protectionPreferences.blockBankingOnHighRisk = checked
        }
        binding.btnBankingAccessibility.setOnClickListener { openBankingAccessibilitySettings() }
        binding.btnChooseBankingApps.setOnClickListener { showBankingAppsDialog() }
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
            protectionActivityStore.clear()
            renderProtectionStatus()
        }
        binding.btnSmartScan.setOnClickListener { requestSmartScan() }
        binding.btnQuickScanMode.setOnClickListener { requestInstalledAppsScan() }
        binding.btnFullScan.setOnClickListener { requestFullScan() }
        binding.btnScanDownloads.setOnClickListener { runDownloadsScan() }
        binding.btnGrantFileAccess.setOnClickListener { requestAntivirusFileAccess() }
        binding.switchAppInstallMonitor.setOnCheckedChangeListener { _, checked ->
            if (renderingProtectionControls) return@setOnCheckedChangeListener
            protectionPreferences.appInstallMonitorEnabled = checked
            if (protectionPreferences.enabled) ProtectionServiceController.refresh(this)
            renderProtectionStatus()
        }
        binding.switchDownloadsProtection.setOnCheckedChangeListener { _, checked ->
            if (renderingProtectionControls) return@setOnCheckedChangeListener
            protectionPreferences.downloadsProtectionEnabled = checked
            if (checked && !ProtectionAccess.hasDownloadsReadAccess(this)) {
                requestAntivirusFileAccess()
            } else if (checked && protectionPreferences.enabled) {
                ProtectionScheduler.scanDownloadsNow(this)
            }
            if (protectionPreferences.enabled) ProtectionServiceController.refresh(this)
            renderProtectionStatus()
        }
        binding.switchPeriodicAppRescan.setOnCheckedChangeListener { _, checked ->
            if (renderingProtectionControls) return@setOnCheckedChangeListener
            protectionPreferences.periodicAppRescanEnabled = checked
            if (protectionPreferences.enabled) ProtectionScheduler.enable(this)
            renderProtectionStatus()
        }
        binding.btnQuickApps.setOnClickListener { showPage(PAGE_SCAN); requestInstalledAppsScan() }
        binding.btnQuickFile.setOnClickListener { showPage(PAGE_SCAN); filePicker.launch(arrayOf("*/*")) }
        binding.btnQuickWeb.setOnClickListener {
            showPage(PAGE_SCAN)
            scrollToSection(binding.webProtectionSection)
            binding.edtUrl.requestFocus()
        }
        binding.btnQuickProtection.setOnClickListener { showPage(PAGE_PROTECTION) }
        binding.btnQuickQuarantine.setOnClickListener { showPage(PAGE_PROTECTION) }
        binding.btnQuickUpdate.setOnClickListener { showPage(PAGE_SETTINGS); updateThreatDatabase() }
        binding.btnStopScan.setOnClickListener {
            if (activeScan) {
                scanCancelRequested = true
                binding.txtSmartScanState.setText(R.string.scan_cancel_requested)
                binding.btnStopScan.isEnabled = false
            }
        }
        binding.btnNotificationSettings.setOnClickListener { openNotificationSettings() }
        binding.btnRunSecurityAudit.setOnClickListener { runStandaloneSecurityAudit() }
        binding.btnPrivacyControl.setOnClickListener { startActivity(Intent(this, PrivacyControlActivity::class.java)) }
        binding.btnOpenSecuritySettings.setOnClickListener { openSecuritySettings() }
        binding.btnOpenPrivacySettings.setOnClickListener { openPrivacySettings() }
        binding.btnOpenNetworkSettings.setOnClickListener { openNetworkSettings() }
        runStandaloneSecurityAudit()
        handleIncomingIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        if (::database.isInitialized) {
            database.reloadAutonomous()
            renderDatabaseInfo()
        }
        if (::protectionPreferences.isInitialized) {
            if (protectionPreferences.enabled && ProtectionServiceController.needsRecovery(this)) {
                runCatching { ProtectionServiceController.start(this) }
                binding.root.postDelayed({ if (!isFinishing && !isDestroyed) renderProtectionStatus() }, 900L)
            }
            if (protectionPreferences.enabled && protectionPreferences.localWebShieldEnabled &&
                LocalWebShieldController.isPermissionGranted(this) && !LocalWebShieldController.isHealthy(this)
            ) {
                runCatching { LocalWebShieldController.start(this) }
            }
            renderProtectionStatus()
        }
        if (::binding.isInitialized) {
            renderWebGuardStatus()
            if (lastSecurityAudit == null || System.currentTimeMillis() - lastSecurityAuditAt > SECURITY_AUDIT_REFRESH_MS) {
                runStandaloneSecurityAudit()
            } else {
                renderSecurityAudit()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    private fun setupNavigation() {
        // IMPORTANT: never change selectedItemId from inside the selection listener.
        // Material NavigationBarView dispatches the listener before its checked state is
        // fully committed on some versions. Re-selecting from inside the listener can
        // recursively dispatch the same callback until StackOverflowError.
        binding.bottomNav.setOnItemSelectedListener { item ->
            val page = when (item.itemId) {
                R.id.nav_home -> PAGE_HOME
                R.id.nav_scan -> PAGE_SCAN
                R.id.nav_protection -> PAGE_PROTECTION
                R.id.nav_settings -> PAGE_SETTINGS
                else -> return@setOnItemSelectedListener false
            }
            renderPage(page)
            true
        }
        showPage(PAGE_HOME)
    }

    private fun showPage(page: Int): Boolean {
        val expected = navItemForPage(page)
        if (binding.bottomNav.selectedItemId == expected) {
            // If the item is already selected no callback is guaranteed, so render now.
            renderPage(page)
        } else {
            // This triggers the listener once; the listener only renders and never re-selects.
            binding.bottomNav.selectedItemId = expected
        }
        return true
    }

    private fun navItemForPage(page: Int): Int = when (page) {
        PAGE_SCAN -> R.id.nav_scan
        PAGE_PROTECTION -> R.id.nav_protection
        PAGE_SETTINGS -> R.id.nav_settings
        else -> R.id.nav_home
    }

    private fun renderPage(page: Int) {
        binding.pageHome.visibility = if (page == PAGE_HOME) View.VISIBLE else View.GONE
        binding.mainScroll.visibility = if (page == PAGE_SCAN) View.VISIBLE else View.GONE
        binding.pageProtection.visibility = if (page == PAGE_PROTECTION) View.VISIBLE else View.GONE
        binding.pageSettings.visibility = if (page == PAGE_SETTINGS) View.VISIBLE else View.GONE
    }

    private fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
        }
        runCatching { startActivity(intent) }.onFailure {
            startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
        }
    }

    private fun renderDatabaseInfo() {
        val info = database.info
        binding.txtAppVersion.text = getString(R.string.app_version, BuildConfig.VERSION_NAME)
        binding.txtHomeVersion.text = BuildConfig.VERSION_NAME
        binding.txtDatabaseVersion.text = getString(R.string.database_version, info.version)
        binding.txtDatabaseEntries.text = getString(
            R.string.database_entries,
            NumberFormat.getIntegerInstance().format(info.fileEntries),
            NumberFormat.getIntegerInstance().format(info.urlEntries),
            NumberFormat.getIntegerInstance().format(info.apkIdentityEntries),
            NumberFormat.getIntegerInstance().format(info.detectionEntries)
        )
        val generated = runCatching { Date.from(Instant.parse(info.generatedAt)) }.getOrNull()
        val formattedDate = generated?.let(DateFormat.getDateTimeInstance()::format) ?: getString(R.string.database_date_unknown)
        binding.txtDatabaseFreshness.text = getString(R.string.database_baseline_date, formattedDate)
        renderAutonomousIntel()
        renderProtectionPosture()
    }

    private fun updateThreatDatabase() {
        binding.btnUpdateDatabase.isEnabled = false
        binding.txtUpdateStatus.setText(R.string.update_checking)
        lifecycleScope.launch(uiCoroutineErrorHandler) {
            val result = withContext(Dispatchers.IO) { updater.update() }
            binding.btnUpdateDatabase.isEnabled = true
            val updateAttention = result is AutonomousUpdateResult.Partial || result == AutonomousUpdateResult.NoSourceAvailable
            protectionPreferences.markActivity(getString(if (updateAttention) R.string.activity_database_attention else R.string.activity_database_checked))
            protectionActivityStore.add(
                kind = ProtectionActivityKind.DATABASE_UPDATE,
                state = if (updateAttention) ProtectionActivityState.ATTENTION else ProtectionActivityState.SAFE,
                title = getString(if (updateAttention) R.string.activity_database_attention else R.string.activity_database_checked),
                detail = getString(if (updateAttention) R.string.timeline_database_attention_detail else R.string.timeline_database_checked_detail)
            )
            if (protectionPreferences.enabled && protectionPreferences.periodicAppRescanEnabled && !updateAttention) {
                ProtectionScheduler.rescanInstalledAppsNow(this@MainActivity)
            }
            ProtectionServiceController.refresh(this@MainActivity)
            renderAutonomousIntel()
            renderProtectionStatus()
            renderProtectionPosture()
            when (result) {
                is AutonomousUpdateResult.Success -> {
                    binding.txtUpdateStatus.text = if (result.changedSources == 0) {
                        getString(R.string.update_up_to_date)
                    } else {
                        getString(
                            R.string.update_success,
                            NumberFormat.getIntegerInstance().format(result.info.malwareFileHashes),
                            NumberFormat.getIntegerInstance().format(result.info.phishingHosts),
                            NumberFormat.getIntegerInstance().format(result.info.c2Hosts),
                            NumberFormat.getIntegerInstance().format(result.info.androidCveCount)
                        )
                    }
                }
                is AutonomousUpdateResult.Partial -> binding.txtUpdateStatus.text = getString(
                    R.string.update_partial,
                    NumberFormat.getIntegerInstance().format(result.successfulSources),
                    NumberFormat.getIntegerInstance().format(result.info.totalSources)
                )
                AutonomousUpdateResult.NoSourceAvailable -> binding.txtUpdateStatus.setText(R.string.update_network_error)
            }
        }
    }

    private fun renderAutonomousIntel() {
        val info = database.autonomousStore.info()
        binding.txtAutonomousIntel.text = getString(
            R.string.autonomous_intel_stats,
            NumberFormat.getIntegerInstance().format(info.malwareFileHashes),
            NumberFormat.getIntegerInstance().format(info.phishingHosts),
            NumberFormat.getIntegerInstance().format(info.c2Hosts),
            NumberFormat.getIntegerInstance().format(info.androidCveCount)
        )
        binding.txtSourceHealth.text = getString(
            R.string.source_health_summary,
            NumberFormat.getIntegerInstance().format(info.freshSources),
            NumberFormat.getIntegerInstance().format(info.staleSources),
            NumberFormat.getIntegerInstance().format(info.failedSourcesLastRun)
        )
        val devicePatch = Build.VERSION.SECURITY_PATCH.orEmpty()
        val latest = info.latestAndroidSecurityPatch
        binding.txtDevicePatchStatus.text = when {
            latest.isNullOrBlank() -> getString(R.string.device_patch_unknown)
            devicePatch.isBlank() -> getString(R.string.device_patch_unknown)
            devicePatch >= latest -> getString(R.string.device_patch_current, devicePatch, latest)
            else -> getString(R.string.device_patch_behind, devicePatch, latest)
        }
        binding.txtAutonomousLastUpdate.text = if (info.lastSuccessfulUpdateEpochMs > 0L) {
            val formatted = DateFormat.getDateTimeInstance().format(Date(info.lastSuccessfulUpdateEpochMs))
            getString(
                R.string.autonomous_last_update,
                formatted,
                info.successfulSourcesLastRun,
                info.totalSources,
                info.freshSources
            )
        } else {
            getString(R.string.autonomous_last_update_never)
        }
    }

    private fun handleIncomingIntent(incoming: Intent?) {
        val requestedPage = incoming?.getIntExtra(EXTRA_OPEN_PAGE, -1) ?: -1
        if (requestedPage in PAGE_HOME..PAGE_SETTINGS) {
            showPage(requestedPage)
        }
        if (incoming?.getBooleanExtra(EXTRA_START_SMART_SCAN, false) == true) {
            incoming.removeExtra(EXTRA_START_SMART_SCAN)
            binding.root.post { requestSmartScan() }
        }
        if (incoming?.action != Intent.ACTION_SEND || incoming.type != "text/plain") return
        val candidate = SharedUrlExtractor.firstCandidate(incoming.getStringExtra(Intent.EXTRA_TEXT)) ?: return
        showPage(PAGE_SCAN)
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
        val dashboardRiskRes = when (result.riskLevel) {
            UrlRiskLevel.INVALID -> R.string.url_result_invalid
            UrlRiskLevel.LOW -> R.string.url_result_low
            UrlRiskLevel.REVIEW -> R.string.url_result_review
            UrlRiskLevel.HIGH -> R.string.url_result_high
            UrlRiskLevel.KNOWN_PHISHING -> R.string.url_result_phishing
            UrlRiskLevel.KNOWN_MALICIOUS -> R.string.url_result_malware
            UrlRiskLevel.TEST_SIGNATURE -> R.string.url_result_test
        }
        val dashboardColor = when (result.riskLevel) {
            UrlRiskLevel.KNOWN_PHISHING, UrlRiskLevel.KNOWN_MALICIOUS, UrlRiskLevel.HIGH -> R.color.status_danger
            UrlRiskLevel.REVIEW, UrlRiskLevel.INVALID -> R.color.status_warn
            UrlRiskLevel.LOW, UrlRiskLevel.TEST_SIGNATURE -> R.color.status_ok
        }
        showSmartResult(
            R.string.url_result_dashboard_title,
            dashboardRiskRes,
            getString(R.string.url_result_dashboard_summary, getString(dashboardRiskRes)),
            dashboardColor
        )
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
        UrlRiskSignal.COMMUNITY_THREAT_FEED -> R.string.url_signal_community_feed
    }

    private fun requestLocalWebShieldEnable() {
        if (!protectionPreferences.enabled) {
            renderProtectionStatus()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.local_web_shield_disclosure_title)
            .setMessage(R.string.local_web_shield_disclosure_body)
            .setNegativeButton(R.string.cancel) { _, _ -> renderProtectionStatus() }
            .setPositiveButton(R.string.local_web_shield_enable_action) { _, _ ->
                val prepareIntent = LocalWebShieldController.prepareIntent(this)
                if (prepareIntent == null) {
                    protectionPreferences.localWebShieldEnabled = true
                    runCatching { LocalWebShieldController.start(this) }
                    binding.root.postDelayed({ if (!isFinishing && !isDestroyed) renderProtectionStatus() }, 700L)
                } else {
                    localWebShieldPermissionLauncher.launch(prepareIntent)
                }
            }
            .show()
    }

    private fun runIntrusionCheckNow() {
        if (!protectionPreferences.enabled || !protectionPreferences.intrusionMonitorEnabled) {
            renderProtectionStatus()
            return
        }
        binding.btnRunIntrusionCheck.isEnabled = false
        binding.btnAttackCheckNow.isEnabled = false
        lifecycleScope.launch(uiCoroutineErrorHandler) {
            val outcome = withContext(Dispatchers.IO) { runCatching { IntrusionMonitor(applicationContext).check() } }
            binding.btnRunIntrusionCheck.isEnabled = true
            binding.btnAttackCheckNow.isEnabled = true
            outcome.onSuccess { summary ->
                protectionPreferences.lastIntrusionCheckAt = System.currentTimeMillis()
                protectionPreferences.lastIntrusionReviewCount = summary.reviewChanges
                protectionPreferences.lastIntrusionHighCount = summary.highChanges
                val timeline = ProtectionActivityStore(applicationContext)
                when {
                    summary.baselineCreated -> timeline.add(
                        kind = ProtectionActivityKind.INTRUSION_MONITOR,
                        state = ProtectionActivityState.INFO,
                        title = getString(R.string.timeline_intrusion_baseline),
                        detail = getString(R.string.timeline_intrusion_baseline_detail, summary.scannedPrivilegedApps),
                        dedupeKey = "intrusion:baseline"
                    )
                    summary.totalChanges == 0 -> timeline.add(
                        kind = ProtectionActivityKind.INTRUSION_MONITOR,
                        state = ProtectionActivityState.SAFE,
                        title = getString(R.string.timeline_intrusion_clean),
                        detail = getString(R.string.timeline_intrusion_clean_detail),
                        dedupeKey = "intrusion:clean"
                    )
                    else -> {
                        timeline.add(
                            kind = ProtectionActivityKind.INTRUSION_MONITOR,
                            state = if (summary.highChanges > 0) ProtectionActivityState.THREAT else ProtectionActivityState.ATTENTION,
                            title = getString(R.string.timeline_intrusion_change, summary.totalChanges),
                            detail = buildList {
                                addAll(summary.changes.take(3).map { change ->
                                    "${change.appName}: ${change.addedKinds.joinToString { privilegedAccessLabel(it) }}"
                                })
                                addAll(summary.integrityChanges.take(2).map { integrityChangeLabel(it.kind) })
                            }.joinToString(" • ")
                        )
                        ProtectionNotifier.notifyIntrusionChange(applicationContext, summary)
                    }
                }
                protectionPreferences.markActivity(getString(R.string.activity_intrusion_checked))
                renderProtectionStatus()
            }.onFailure {
                renderProtectionStatus()
                showInfo(R.string.operation_failed_try_again)
            }
        }
    }

    private fun requestDataExfiltrationEnable() {
        if (!protectionPreferences.enabled) {
            renderProtectionStatus()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.data_exfil_disclosure_title)
            .setMessage(R.string.data_exfil_disclosure_body)
            .setNegativeButton(R.string.cancel) { _, _ -> renderProtectionStatus() }
            .setPositiveButton(R.string.data_exfil_usage_access_action) { _, _ ->
                protectionPreferences.dataExfiltrationGuardEnabled = true
                renderProtectionStatus()
                if (!DataExfiltrationAccess.isGranted(this)) openUsageAccessSettings()
            }
            .show()
    }

    private fun openUsageAccessSettings() {
        runCatching { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }
            .onFailure { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }

    private fun runDataExfiltrationCheckNow() {
        if (!protectionPreferences.enabled || !protectionPreferences.dataExfiltrationGuardEnabled) {
            renderProtectionStatus()
            return
        }
        if (!DataExfiltrationAccess.isGranted(this)) {
            showInfo(R.string.data_exfil_manual_needs_access)
            return
        }
        binding.btnRunDataExfilCheck.isEnabled = false
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) { runCatching { DataExfiltrationGuard(applicationContext).audit() } }
            binding.btnRunDataExfilCheck.isEnabled = true
            outcome.onSuccess { summary ->
                renderProtectionStatus()
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.data_exfil_manual_complete, summary.reviewCount, summary.highCount),
                    Toast.LENGTH_LONG
                ).show()
            }.onFailure {
                renderProtectionStatus()
                showInfo(R.string.operation_failed_try_again)
            }
        }
    }

    private fun requestBankingProtectionEnable() {
        if (!protectionPreferences.enabled) {
            renderProtectionStatus()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.banking_accessibility_disclosure_title)
            .setMessage(R.string.banking_accessibility_disclosure_body)
            .setNegativeButton(R.string.cancel) { _, _ -> renderProtectionStatus() }
            .setPositiveButton(R.string.banking_open_accessibility_settings) { _, _ ->
                protectionPreferences.bankingProtectionEnabled = true
                renderProtectionStatus()
                if (!isBankingAccessibilityEnabled()) openBankingAccessibilitySettings()
            }
            .show()
    }

    private fun openBankingAccessibilitySettings() {
        runCatching { startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }
            .onFailure { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }

    private fun isBankingAccessibilityEnabled(): Boolean {
        val manager = getSystemService(AccessibilityManager::class.java) ?: return false
        return runCatching {
            manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).any { info ->
                val serviceInfo = info.resolveInfo?.serviceInfo ?: return@any false
                serviceInfo.packageName == packageName &&
                    serviceInfo.name == BankingGuardAccessibilityService::class.java.name
            }
        }.getOrDefault(false)
    }

    private fun showBankingAppsDialog() {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        val apps = packageManager.queryIntentActivities(launcherIntent, 0)
            .filter { it.activityInfo?.packageName != packageName }
            .distinctBy { it.activityInfo?.packageName }
            .mapNotNull { resolve ->
                val packageName = resolve.activityInfo?.packageName ?: return@mapNotNull null
                val label = runCatching { resolve.loadLabel(packageManager)?.toString().orEmpty() }
                    .getOrDefault("").ifBlank { packageName }
                label to packageName
            }
            .sortedBy { it.first.lowercase() }
        if (apps.isEmpty()) {
            showInfo(R.string.banking_choose_apps_empty)
            return
        }
        val selected = protectionPreferences.protectedBankingPackages.toMutableSet()
        val labels = apps.map { it.first }.toTypedArray()
        val checked = BooleanArray(apps.size) { index -> apps[index].second in selected }
        AlertDialog.Builder(this)
            .setTitle(R.string.banking_choose_apps_title)
            .setMultiChoiceItems(labels, checked) { _, which, isChecked ->
                val packageName = apps[which].second
                if (isChecked) selected += packageName else selected -= packageName
            }
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.banking_save_apps) { _, _ ->
                protectionPreferences.protectedBankingPackages = selected
                renderProtectionStatus()
            }
            .show()
    }

    private fun renderAdvancedProtectionStatus() {
        val enabled = protectionPreferences.enabled
        val localShieldEnabled = enabled && protectionPreferences.localWebShieldEnabled
        val localShieldHealthy = localShieldEnabled && LocalWebShieldController.isHealthy(this)
        val localShieldPermission = LocalWebShieldController.isPermissionGranted(this)
        binding.txtLocalWebShieldStatus.setText(
            when {
                !localShieldEnabled -> R.string.local_web_shield_status_off
                !localShieldPermission -> R.string.local_web_shield_status_permission
                localShieldHealthy && protectionPreferences.localWebShieldPrivateDnsAtStart -> R.string.local_web_shield_status_private_dns
                localShieldHealthy -> R.string.local_web_shield_status_active
                else -> R.string.local_web_shield_status_starting
            }
        )

        val intrusionEnabled = enabled && protectionPreferences.intrusionMonitorEnabled
        binding.txtIntrusionStatus.text = when {
            !intrusionEnabled -> getString(R.string.intrusion_status_off)
            protectionPreferences.lastIntrusionCheckAt <= 0L -> getString(R.string.intrusion_status_never)
            protectionPreferences.lastIntrusionHighCount == 0 && protectionPreferences.lastIntrusionReviewCount == 0 ->
                getString(R.string.intrusion_status_clean, formatDate(protectionPreferences.lastIntrusionCheckAt))
            else -> getString(
                R.string.intrusion_status_review,
                formatDate(protectionPreferences.lastIntrusionCheckAt),
                protectionPreferences.lastIntrusionReviewCount,
                protectionPreferences.lastIntrusionHighCount
            )
        }

        val dataExfilEnabled = enabled && protectionPreferences.dataExfiltrationGuardEnabled
        val dataExfilAccess = DataExfiltrationAccess.isGranted(this)
        val dataExfilBaseStatus = when {
            !dataExfilEnabled -> getString(R.string.data_exfil_status_off)
            !dataExfilAccess -> getString(R.string.data_exfil_status_needs_access)
            protectionPreferences.lastDataExfilCheckAt <= 0L -> getString(R.string.data_exfil_status_never)
            protectionPreferences.lastDataExfilHighCount == 0 && protectionPreferences.lastDataExfilReviewCount == 0 ->
                getString(R.string.data_exfil_status_clean, formatDate(protectionPreferences.lastDataExfilCheckAt))
            else -> getString(
                R.string.data_exfil_status_review,
                formatDate(protectionPreferences.lastDataExfilCheckAt),
                protectionPreferences.lastDataExfilReviewCount,
                protectionPreferences.lastDataExfilHighCount
            )
        }
        binding.txtDataExfilStatus.text = if (dataExfilEnabled && dataExfilAccess) {
            "$dataExfilBaseStatus\n${getString(if (localShieldHealthy) R.string.data_exfil_dns_correlation_active else R.string.data_exfil_dns_correlation_off)}"
        } else dataExfilBaseStatus
        binding.btnDataUsageAccess.visibility = if (dataExfilEnabled && !dataExfilAccess) View.VISIBLE else View.GONE
        binding.btnRunDataExfilCheck.isEnabled = dataExfilEnabled && dataExfilAccess

        val bankingEnabled = enabled && protectionPreferences.bankingProtectionEnabled
        val bankingAccess = isBankingAccessibilityEnabled()
        val baseBankingStatus = when {
            !bankingEnabled -> getString(R.string.banking_status_off)
            !bankingAccess -> getString(R.string.banking_status_needs_access)
            else -> getString(R.string.banking_status_active, protectionPreferences.protectedBankingPackages.size)
        }
        binding.txtBankingProtectionStatus.text = if (bankingEnabled && protectionPreferences.lastBankingCheckAt > 0L) {
            val risk = when (protectionPreferences.lastBankingRiskLevel) {
                "SAFE" -> getString(R.string.banking_risk_safe)
                "REVIEW" -> getString(R.string.banking_risk_review)
                "BLOCK" -> getString(R.string.banking_risk_block)
                else -> getString(R.string.banking_risk_unknown)
            }
            "$baseBankingStatus\n${getString(R.string.banking_status_last_check, formatDate(protectionPreferences.lastBankingCheckAt), risk)}"
        } else baseBankingStatus
    }

    private fun renderAttackDetectionCenter() {
        val snapshot = AttackDetectionCenter(this).snapshot()
        val levelText = when (snapshot.level) {
            AttackDetectionLevel.CLEAR -> R.string.attack_center_clear
            AttackDetectionLevel.WATCH -> R.string.attack_center_watch
            AttackDetectionLevel.CRITICAL -> R.string.attack_center_critical
            AttackDetectionLevel.INCOMPLETE -> R.string.attack_center_incomplete
        }
        val homeText = when (snapshot.level) {
            AttackDetectionLevel.CLEAR -> R.string.attack_home_clear
            AttackDetectionLevel.WATCH -> R.string.attack_home_watch
            AttackDetectionLevel.CRITICAL -> R.string.attack_home_critical
            AttackDetectionLevel.INCOMPLETE -> R.string.attack_home_incomplete
        }
        val levelColor = when (snapshot.level) {
            AttackDetectionLevel.CLEAR -> R.color.status_ok
            AttackDetectionLevel.WATCH -> R.color.status_warn
            AttackDetectionLevel.CRITICAL -> R.color.status_danger
            AttackDetectionLevel.INCOMPLETE -> R.color.status_warn
        }
        binding.txtAttackDetectionLevel.setText(levelText)
        binding.txtAttackDetectionLevel.setTextColor(ContextCompat.getColor(this, levelColor))
        binding.txtAttackHome.setText(homeText)
        binding.txtAttackHome.setTextColor(ContextCompat.getColor(this, levelColor))
        binding.txtAttackDetectionSummary.text = when (snapshot.level) {
            AttackDetectionLevel.CLEAR -> getString(R.string.attack_center_clear_summary)
            AttackDetectionLevel.WATCH -> getString(R.string.attack_center_watch_summary, snapshot.watchSignals)
            AttackDetectionLevel.CRITICAL -> getString(
                R.string.attack_center_critical_summary,
                snapshot.criticalSignals,
                snapshot.watchSignals
            )
            AttackDetectionLevel.INCOMPLETE -> getString(R.string.attack_center_incomplete_summary)
        }
        fun layer(active: Boolean): String = getString(if (active) R.string.protection_layer_active else R.string.protection_layer_off)
        binding.txtAttackDetectionCoverage.text = getString(
            R.string.attack_center_coverage,
            layer(snapshot.serviceHealthy),
            layer(snapshot.webShieldActive),
            layer(snapshot.intrusionMonitorActive),
            layer(snapshot.bankingGuardActive),
            layer(snapshot.dataExfiltrationGuardActive)
        )
        binding.txtAttackDetectionLastSignal.text = snapshot.lastSignal?.let { signal ->
            getString(R.string.attack_center_last_signal, formatDate(signal.createdAt), signal.title)
        } ?: getString(R.string.attack_center_no_signal)
    }

    private fun isCombinedWebProtectionActive(): Boolean =
        LocalWebShieldController.isHealthy(this) || isWebGuardActive()

    private fun configureWebGuard() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = getSystemService(RoleManager::class.java)
            if (roleManager.isRoleAvailable(RoleManager.ROLE_BROWSER) && !roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)) {
                webGuardRoleLauncher.launch(roleManager.createRequestRoleIntent(RoleManager.ROLE_BROWSER))
                return
            }
        }
        runCatching {
            webGuardRoleLauncher.launch(Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
        }.onFailure {
            startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
        }
    }

    private fun renderWebGuardStatus() {
        val active = isWebGuardActive()
        binding.txtWebGuardStatus.setText(if (active) R.string.web_guard_status_active else R.string.web_guard_status_optional)
        binding.btnConfigureWebGuard.setText(if (active) R.string.web_guard_manage_action else R.string.web_guard_configure_action)
        if (::protectionPreferences.isInitialized) renderAdvancedProtectionStatus()
        if (::protectionPreferences.isInitialized && ::database.isInitialized) renderProtectionPosture()
    }

    private fun isWebGuardActive(): Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        val roleManager = getSystemService(RoleManager::class.java)
        roleManager.isRoleAvailable(RoleManager.ROLE_BROWSER) && roleManager.isRoleHeld(RoleManager.ROLE_BROWSER)
    } else {
        false
    }

    private fun renderProtectionPosture() {
        if (!::binding.isInitialized || !::database.isInitialized || !::protectionPreferences.isInitialized) return
        val intel = database.autonomousStore.info()
        val devicePatch = Build.VERSION.SECURITY_PATCH.orEmpty()
        val latestPatch = intel.latestAndroidSecurityPatch.orEmpty()
        val patchKnown = devicePatch.isNotBlank() && latestPatch.isNotBlank()
        val integrity = AppIntegrityInspector.inspect(this)
        val posture = ProtectionPostureEvaluator.evaluate(
            ProtectionPostureInput(
                databaseHealthy = database.canaryHealthy(),
                freshSources = intel.freshSources,
                totalSources = intel.totalSources,
                backgroundProtectionEnabled = protectionPreferences.enabled && ProtectionServiceController.isHealthy(this),
                webGuardActive = isCombinedWebProtectionActive(),
                devicePatchKnown = patchKnown,
                devicePatchCurrent = patchKnown && devicePatch >= latestPatch,
                integrityStatus = integrity.status
            )
        )
        val scoreText = NumberFormat.getIntegerInstance().format(posture.score)
        binding.txtProtectionPosture.text = getString(
            when (posture.level) {
                ProtectionPostureLevel.STRONG -> R.string.protection_posture_strong
                ProtectionPostureLevel.ATTENTION -> R.string.protection_posture_attention
                ProtectionPostureLevel.LIMITED -> R.string.protection_posture_limited
            },
            scoreText
        )
        binding.txtAppIntegrityStatus.setText(
            when (integrity.status) {
                AppIntegrityStatus.DEBUG_BUILD -> R.string.integrity_debug_build
                AppIntegrityStatus.VERIFIED_RELEASE -> R.string.integrity_verified_release
                AppIntegrityStatus.UNPINNED_RELEASE -> R.string.integrity_unpinned_release
                AppIntegrityStatus.SIGNATURE_MISMATCH -> R.string.integrity_signature_mismatch
                AppIntegrityStatus.UNKNOWN -> R.string.integrity_unknown
            }
        )
        renderSmartDashboard(posture.score, posture.level)
    }

    private fun toggleBackgroundProtection() {
        if (protectionPreferences.enabled) {
            protectionPreferences.enabled = false
            protectionPreferences.localWebShieldEnabled = false
            ProtectionScheduler.disable(this)
            ProtectionServiceController.stop(this)
            LocalWebShieldController.stop(this)
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
        ProtectionNotifier.ensureChannels(this)
        ProtectionScheduler.enable(this)
        runCatching { ProtectionServiceController.start(this) }
            .onSuccess { binding.root.postDelayed({ if (!isFinishing && !isDestroyed) renderProtectionStatus() }, 900L) }
            .onFailure { Log.e(TAG, "Unable to start real-time protection service", it) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        renderProtectionStatus()
    }

    private fun requestAntivirusFileAccess() {
        AlertDialog.Builder(this)
            .setTitle(R.string.file_access_disclosure_title)
            .setMessage(R.string.file_access_disclosure_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.grant_file_access_action) { _, _ ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val appSpecific = Intent(
                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:$packageName")
                    )
                    runCatching { allFilesAccessLauncher.launch(appSpecific) }
                        .onFailure {
                            allFilesAccessLauncher.launch(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                        }
                } else {
                    legacyStoragePermissionLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
                }
            }
            .show()
    }

    private fun onAntivirusFileAccessReturn() {
        val granted = ProtectionAccess.hasDownloadsReadAccess(this)
        if (granted) {
            protectionPreferences.clearDownloadLedger()
            if (protectionPreferences.enabled) {
                runCatching { ProtectionServiceController.start(this) }
                ProtectionScheduler.scanDownloadsNow(this)
            }
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
        lifecycleScope.launch(uiCoroutineErrorHandler) {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    ProtectedFolderScanner(
                        resolver = contentResolver,
                        fileScanner = scanner,
                        preferences = protectionPreferences,
                        eventStore = protectionEventStore,
                        recordStore = recordStore,
                        notifier = { ProtectionNotifier.notifyEvent(applicationContext, it) },
                        scanCacheStore = LocalScanCacheStore(applicationContext)
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
        val healthy = enabled && ProtectionServiceController.isHealthy(this)
        val downloadsAccess = ProtectionAccess.hasDownloadsReadAccess(this)
        val notificationAllowed = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

        binding.txtProtectionState.setText(
            when {
                !enabled -> R.string.protection_state_disabled
                !notificationAllowed -> R.string.protection_state_notifications_off
                !healthy -> R.string.protection_state_service_down
                else -> R.string.protection_state_enabled
            }
        )
        binding.txtProtectionServiceHealth.setText(
            when {
                !enabled -> R.string.realtime_service_stopped
                healthy -> R.string.realtime_service_active
                else -> R.string.realtime_service_starting
            }
        )
        binding.btnToggleProtection.setText(if (enabled) R.string.disable_protection_action else R.string.enable_protection_action)

        renderingProtectionControls = true
        try {
            binding.switchAppInstallMonitor.isChecked = protectionPreferences.appInstallMonitorEnabled
            binding.switchDownloadsProtection.isChecked = protectionPreferences.downloadsProtectionEnabled
            binding.switchPeriodicAppRescan.isChecked = protectionPreferences.periodicAppRescanEnabled
            binding.switchLocalWebShield.isChecked = enabled && protectionPreferences.localWebShieldEnabled
            binding.switchIntrusionMonitor.isChecked = enabled && protectionPreferences.intrusionMonitorEnabled
            binding.switchDataExfilGuard.isChecked = enabled && protectionPreferences.dataExfiltrationGuardEnabled
            binding.switchBankingProtection.isChecked = enabled && protectionPreferences.bankingProtectionEnabled
            binding.switchBankingBlockHighRisk.isChecked = protectionPreferences.blockBankingOnHighRisk
        } finally {
            renderingProtectionControls = false
        }
        binding.switchAppInstallMonitor.isEnabled = enabled
        binding.switchDownloadsProtection.isEnabled = enabled
        binding.switchPeriodicAppRescan.isEnabled = enabled
        binding.switchLocalWebShield.isEnabled = enabled
        binding.switchIntrusionMonitor.isEnabled = enabled
        binding.btnRunIntrusionCheck.isEnabled = enabled && protectionPreferences.intrusionMonitorEnabled
        binding.btnAttackCheckNow.isEnabled = enabled && protectionPreferences.intrusionMonitorEnabled
        binding.switchDataExfilGuard.isEnabled = enabled
        binding.btnDataUsageAccess.isEnabled = enabled && protectionPreferences.dataExfiltrationGuardEnabled
        binding.btnRunDataExfilCheck.isEnabled = enabled && protectionPreferences.dataExfiltrationGuardEnabled && DataExfiltrationAccess.isGranted(this)
        binding.switchBankingProtection.isEnabled = enabled
        binding.switchBankingBlockHighRisk.isEnabled = enabled && protectionPreferences.bankingProtectionEnabled
        binding.btnBankingAccessibility.isEnabled = enabled && protectionPreferences.bankingProtectionEnabled
        binding.btnChooseBankingApps.isEnabled = enabled && protectionPreferences.bankingProtectionEnabled

        binding.txtDownloadsAccess.setText(if (downloadsAccess) R.string.downloads_access_granted else R.string.downloads_access_missing)
        binding.btnGrantFileAccess.visibility = if (downloadsAccess) View.GONE else View.VISIBLE

        val formatter = NumberFormat.getIntegerInstance()
        binding.txtProtectionStats.text = getString(
            R.string.protection_stats_line,
            formatter.format(protectionPreferences.totalAppsChecked),
            formatter.format(protectionPreferences.totalFilesChecked),
            formatter.format(protectionPreferences.totalThreatsDetected)
        )
        val lastActivity = protectionPreferences.lastActivityLabel
        val lastActivityLine = if (protectionPreferences.lastActivityAt > 0L && !lastActivity.isNullOrBlank()) {
            getString(R.string.last_protection_activity_line, formatDate(protectionPreferences.lastActivityAt), lastActivity)
        } else {
            getString(R.string.last_protection_activity_none)
        }
        binding.txtProtectionLastActivity.text = lastActivityLine
        binding.txtLastProtectionActivityHome.text = lastActivityLine

        binding.txtRealtimeHome.setText(
            when {
                !enabled -> R.string.realtime_service_stopped
                healthy -> R.string.realtime_service_active
                else -> R.string.realtime_service_starting
            }
        )
        binding.txtAppMonitorHome.setText(if (enabled && protectionPreferences.appInstallMonitorEnabled) R.string.app_monitor_active else R.string.app_monitor_off)
        binding.txtDownloadsHome.setText(
            when {
                !enabled || !protectionPreferences.downloadsProtectionEnabled -> R.string.downloads_protection_off
                !downloadsAccess -> R.string.downloads_protection_access_needed
                else -> R.string.downloads_protection_active
            }
        )
        binding.txtWebProtectionHome.setText(if (isCombinedWebProtectionActive()) R.string.web_protection_active_short else R.string.web_protection_off_short)
        binding.txtSpywareHome.setText(if (enabled && protectionPreferences.appInstallMonitorEnabled) R.string.spyware_monitor_active else R.string.spyware_monitor_off)
        binding.txtLightweightEngineStatus.setText(R.string.local_engine_lightweight_status)

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
                formatter.format(protectionPreferences.lastScannedCount),
                formatter.format(protectionPreferences.lastAlertCount)
            )
        }

        val threatEvents = protectionEventStore.events()
        val timeline = protectionActivityStore.entries()
        binding.txtProtectionAlertCount.text = if (threatEvents.isEmpty()) {
            getString(R.string.protection_alert_count_zero)
        } else {
            getString(R.string.protection_alert_count, formatter.format(threatEvents.size))
        }
        binding.btnClearProtectionEvents.isEnabled = threatEvents.isNotEmpty() || timeline.isNotEmpty()
        binding.protectionEventsContainer.removeAllViews()
        if (timeline.isEmpty()) {
            binding.protectionEventsContainer.addView(protectionEventText(getString(R.string.protection_timeline_empty)))
        } else {
            timeline.take(MAX_VISIBLE_PROTECTION_EVENTS).forEach { entry ->
                binding.protectionEventsContainer.addView(protectionEventText(formatProtectionActivity(entry)))
            }
        }
        renderAdvancedProtectionStatus()
        renderAttackDetectionCenter()
        renderProtectionPosture()
    }

    private fun formatProtectionActivity(entry: ProtectionActivityEntry): String {
        val marker = when (entry.state) {
            ProtectionActivityState.SAFE -> "✓"
            ProtectionActivityState.THREAT -> "!"
            ProtectionActivityState.ATTENTION -> "•"
            ProtectionActivityState.INFO -> "•"
        }
        return buildString {
            append(marker)
            append(' ')
            append(formatDate(entry.createdAt))
            append("  ")
            append(entry.title)
            entry.detail?.takeIf { it.isNotBlank() }?.let {
                append('\n')
                append(it)
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

    private fun requestSmartScan() {
        val preferences = getSharedPreferences(PRIVACY_PREFERENCES, MODE_PRIVATE)
        if (preferences.getInt(INSTALLED_SCAN_DISCLOSURE_KEY, 0) >= INSTALLED_SCAN_DISCLOSURE_VERSION) {
            runSmartScan()
            return
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.smart_scan_disclosure_title)
            .setMessage(R.string.smart_scan_disclosure_body)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.continue_scan) { _, _ ->
                preferences.edit()
                    .putInt(INSTALLED_SCAN_DISCLOSURE_KEY, INSTALLED_SCAN_DISCLOSURE_VERSION)
                    .apply()
                runSmartScan()
            }
            .show()
    }

    private data class SmartScanBundle(
        val installedApps: InstalledAppsScanSummary,
        val securityAudit: SecurityAuditSummary,
        val spywareAudit: SpywareAuditSummary,
        val protectedFolder: ProtectedFolderScanSummary?
    )

    private fun runSmartScan() {
        showPage(PAGE_SCAN)
        scanCancelRequested = false
        activeScan = true
        binding.btnStopScan.isEnabled = true
        setScanControlsEnabled(false)
        showSmartScan(R.string.smart_scan_preparing, R.string.smart_scan_full_detail)
        updateScanProgress(1, R.string.smart_scan_preparing, getString(R.string.scan_target_preparing), getString(R.string.scan_scope_preparing))

        lifecycleScope.launch(uiCoroutineErrorHandler) {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val installed = installedAppScanner.scanUserApps { completed, total, appName, packageName ->
                        if (scanCancelRequested) throw CancellationException("scan cancelled")
                        val fraction = if (total <= 0) 0 else ((completed * 65) / total)
                        val percent = (8 + fraction).coerceIn(8, 73)
                        runOnUiThread {
                            updateScanProgress(
                                percent,
                                R.string.scan_stage_apps,
                                getString(R.string.scan_stage_app_progress, NumberFormat.getIntegerInstance().format(completed.coerceAtLeast(1)), NumberFormat.getIntegerInstance().format(total)),
                                "$appName\n${getString(R.string.scan_scope_package, packageName)}"
                            )
                        }
                    }
                    if (scanCancelRequested) throw CancellationException("scan cancelled")
                    runOnUiThread { updateScanProgress(78, R.string.scan_stage_device, getString(R.string.scan_stage_device), getString(R.string.scan_scope_device)) }
                    val device = DeviceSecurityAuditor(applicationContext).audit()
                    if (scanCancelRequested) throw CancellationException("scan cancelled")
                    runOnUiThread { updateScanProgress(84, R.string.scan_stage_network, getString(R.string.scan_stage_network), getString(R.string.scan_scope_device)) }
                    val audit = SecurityAuditSummary(
                        device = device,
                        network = NetworkSecurityAuditor(applicationContext).audit(),
                        privacy = PrivacyPermissionAuditor(applicationContext).audit()
                    )
                    if (scanCancelRequested) throw CancellationException("scan cancelled")
                    runOnUiThread { updateScanProgress(88, R.string.scan_stage_spyware, getString(R.string.scan_stage_spyware), getString(R.string.scan_scope_device)) }
                    val spywareAudit = SpywareAuditor(applicationContext).audit()
                    val folder = protectionPreferences.protectedTreeUri?.let { treeUri ->
                        runOnUiThread {
                            updateScanProgress(90, R.string.scan_stage_folder, getString(R.string.scan_stage_folder), treeUri.toString())
                        }
                        ProtectedFolderScanner(
                            resolver = contentResolver,
                            fileScanner = scanner,
                            preferences = protectionPreferences,
                            eventStore = protectionEventStore,
                            recordStore = recordStore,
                            notifier = { ProtectionNotifier.notifyEvent(applicationContext, it) },
                            scanCacheStore = LocalScanCacheStore(applicationContext)
                        ).scan(treeUri) { scanned, fileName, documentId ->
                            if (scanCancelRequested) throw CancellationException("scan cancelled")
                            runOnUiThread {
                                updateScanProgress(
                                    (90 + scanned.coerceAtMost(8)).coerceAtMost(98),
                                    R.string.scan_stage_folder,
                                    getString(R.string.scan_stage_folder_count, NumberFormat.getIntegerInstance().format(scanned)),
                                    "$fileName\n${getString(R.string.scan_scope_file, documentId)}"
                                )
                            }
                        }
                    }
                    if (scanCancelRequested) throw CancellationException("scan cancelled")
                    runOnUiThread { updateScanProgress(99, R.string.scan_stage_finishing, getString(R.string.scan_stage_finishing), getString(R.string.scan_scope_device)) }
                    SmartScanBundle(installed, audit, spywareAudit, folder)
                }
            }
            activeScan = false
            binding.btnStopScan.isEnabled = false
            setScanControlsEnabled(true)
            outcome.onSuccess { bundle ->
                updateScanProgress(100, R.string.scan_stage_finishing, getString(R.string.scan_complete_percent), getString(R.string.scan_stage_finishing))
                lastInstalledSummary = bundle.installedApps
                protectionPreferences.totalAppsChecked += bundle.installedApps.scannedApps.toLong()
                protectionPreferences.totalThreatsDetected += (bundle.installedApps.knownThreats + bundle.installedApps.highRiskApps).toLong()
                bundle.protectedFolder?.let { folderSummary ->
                    protectionPreferences.totalFilesChecked += folderSummary.scannedFiles.toLong()
                    protectionPreferences.totalThreatsDetected += folderSummary.alerts.toLong()
                }
                protectionPreferences.markActivity(getString(R.string.activity_apps_rescan_complete, bundle.installedApps.scannedApps))
                protectionActivityStore.add(
                    kind = ProtectionActivityKind.APP_SCAN,
                    state = if (bundle.installedApps.knownThreats > 0 || bundle.installedApps.highRiskApps > 0) ProtectionActivityState.THREAT else if (bundle.installedApps.reviewApps > 0) ProtectionActivityState.ATTENTION else ProtectionActivityState.SAFE,
                    title = getString(R.string.timeline_apps_rescan_complete, bundle.installedApps.scannedApps),
                    detail = getString(R.string.timeline_apps_rescan_detail, bundle.installedApps.knownThreats + bundle.installedApps.highRiskApps)
                )
                lastSecurityAudit = bundle.securityAudit
                lastSecurityAuditAt = System.currentTimeMillis()
                renderInstalledApps(bundle.installedApps)
                renderSecurityAudit()
                renderProtectionStatus()
                renderSmartFullResult(bundle)
                renderProtectionPosture()
            }.onFailure {
                hideSmartScan()
                if (scanCancelRequested || it is CancellationException) {
                    showSmartResult(R.string.scan_cancelled_title, R.string.scan_cancelled_title, getString(R.string.scan_cancelled_detail), R.color.status_warn)
                } else {
                    showSmartResult(R.string.smart_scan_failed_title, R.string.smart_scan_failed_title, getString(R.string.smart_scan_failed_full_detail), R.color.status_warn)
                }
            }
        }
    }

    private fun renderSmartFullResult(bundle: SmartScanBundle) {
        val apps = bundle.installedApps
        val audit = bundle.securityAudit
        val folder = bundle.protectedFolder
        val knownThreats = apps.knownThreats + (folder?.knownThreats ?: 0)
        val highRisk = apps.highRiskApps + (folder?.highRisk ?: 0)
        val warnings = audit.warningFindings + bundle.spywareAudit.reviewApps + bundle.spywareAudit.highRiskApps
        val highs = audit.highFindings
        val titleRes = when {
            knownThreats > 0 || highRisk > 0 || highs > 0 -> R.string.smart_scan_complete_danger
            apps.reviewApps > 0 || warnings > 0 -> R.string.smart_scan_complete_attention
            else -> R.string.smart_scan_complete_safe
        }
        val colorRes = when {
            knownThreats > 0 || highRisk > 0 || highs > 0 -> R.color.status_danger
            apps.reviewApps > 0 || warnings > 0 -> R.color.status_warn
            else -> R.color.status_ok
        }
        val formatter = NumberFormat.getIntegerInstance()
        val details = buildString {
            append(getString(
                R.string.smart_scan_result_summary,
                formatter.format(apps.scannedApps),
                formatter.format(apps.reviewApps),
                formatter.format(apps.highRiskApps),
                formatter.format(apps.knownThreats)
            ))
            append('\n')
            append(getString(
                R.string.smart_scan_audit_summary,
                formatter.format(highs),
                formatter.format(warnings),
                formatter.format(audit.privacy.elevatedPermissionApps)
            ))
            append('\n')
            append(getString(
                R.string.smart_scan_spyware_summary,
                formatter.format(bundle.spywareAudit.scannedApps),
                formatter.format(bundle.spywareAudit.reviewApps),
                formatter.format(bundle.spywareAudit.highRiskApps)
            ))
            if (folder != null) {
                append('\n')
                append(getString(
                    R.string.smart_scan_folder_summary,
                    formatter.format(folder.scannedFiles),
                    formatter.format(folder.alerts)
                ))
            } else {
                append('\n')
                append(getString(R.string.smart_scan_folder_not_configured))
            }
        }
        val summaryRes = if (knownThreats > 0 || highRisk > 0 || highs > 0 || apps.reviewApps > 0 || warnings > 0) {
            R.string.smart_scan_result_review_detail
        } else {
            R.string.smart_scan_result_safe_detail
        }
        showSmartResult(titleRes, summaryRes, details, colorRes)
    }

    private fun requestFullScan() {
        if (!ProtectionAccess.hasDownloadsReadAccess(this)) {
            AlertDialog.Builder(this)
                .setTitle(R.string.full_scan_access_required_title)
                .setMessage(R.string.full_scan_access_required_body)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.grant_file_access_action) { _, _ -> requestAntivirusFileAccess() }
                .show()
            return
        }
        val preferences = getSharedPreferences(PRIVACY_PREFERENCES, MODE_PRIVATE)
        if (preferences.getInt(INSTALLED_SCAN_DISCLOSURE_KEY, 0) < INSTALLED_SCAN_DISCLOSURE_VERSION) {
            AlertDialog.Builder(this)
                .setTitle(R.string.installed_apps_disclosure_title)
                .setMessage(R.string.installed_apps_disclosure_body)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.continue_scan) { _, _ ->
                    preferences.edit().putInt(INSTALLED_SCAN_DISCLOSURE_KEY, INSTALLED_SCAN_DISCLOSURE_VERSION).apply()
                    runFullScan()
                }
                .show()
            return
        }
        runFullScan()
    }

    private data class FullScanBundle(
        val apps: InstalledAppsScanSummary,
        val files: SharedStorageScanSummary
    )

    private fun runFullScan() {
        showPage(PAGE_SCAN)
        scanCancelRequested = false
        activeScan = true
        setScanControlsEnabled(false)
        binding.btnStopScan.isEnabled = true
        showSmartScan(R.string.full_scan_action, R.string.full_scan_running_detail)
        updateScanProgress(1, R.string.scan_stage_apps, getString(R.string.scan_target_preparing), getString(R.string.scan_scope_preparing))

        lifecycleScope.launch(uiCoroutineErrorHandler) {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val apps = installedAppScanner.scanAllApps { completed, total, appName, packageName ->
                        if (scanCancelRequested) throw CancellationException("scan cancelled")
                        val percent = if (total <= 0) 2 else (2 + ((completed * 33) / total)).coerceIn(2, 35)
                        runOnUiThread {
                            updateScanProgress(
                                percent,
                                R.string.scan_stage_apps,
                                getString(R.string.scan_stage_app_progress, NumberFormat.getIntegerInstance().format(completed.coerceAtLeast(1)), NumberFormat.getIntegerInstance().format(total)),
                                "$appName\n${getString(R.string.scan_scope_package, packageName)}"
                            )
                        }
                    }
                    if (scanCancelRequested) throw CancellationException("scan cancelled")
                    val files = SharedStorageScanner(applicationContext).scan(
                        cancelled = { scanCancelRequested },
                        onProgress = { completed, total, fileName, path ->
                            if (scanCancelRequested) throw CancellationException("scan cancelled")
                            val fraction = if (total <= 0) 0 else ((completed * 63) / total)
                            val percent = (36 + fraction).coerceIn(36, 99)
                            runOnUiThread {
                                updateScanProgress(
                                    percent,
                                    R.string.scan_stage_shared_storage,
                                    if (total > 0) getString(R.string.scan_stage_folder_count, NumberFormat.getIntegerInstance().format(completed.coerceAtLeast(0))) else fileName,
                                    getString(R.string.scan_scope_shared_storage, path)
                                )
                            }
                        }
                    )
                    if (scanCancelRequested) throw CancellationException("scan cancelled")
                    FullScanBundle(apps, files)
                }
            }
            activeScan = false
            scanCancelRequested = false
            setScanControlsEnabled(true)
            binding.btnStopScan.isEnabled = false
            outcome.onSuccess { bundle ->
                updateScanProgress(100, R.string.scan_stage_finishing, getString(R.string.scan_complete_percent), getString(R.string.scan_stage_finishing))
                lastInstalledSummary = bundle.apps
                protectionPreferences.totalAppsChecked += bundle.apps.scannedApps.toLong()
                protectionPreferences.totalThreatsDetected += (bundle.apps.knownThreats + bundle.apps.highRiskApps).toLong()
                protectionPreferences.markActivity(getString(R.string.activity_apps_rescan_complete, bundle.apps.scannedApps))
                protectionActivityStore.add(
                    kind = ProtectionActivityKind.APP_SCAN,
                    state = if (bundle.apps.knownThreats > 0 || bundle.apps.highRiskApps > 0) ProtectionActivityState.THREAT else if (bundle.apps.reviewApps > 0) ProtectionActivityState.ATTENTION else ProtectionActivityState.SAFE,
                    title = getString(R.string.timeline_apps_rescan_complete, bundle.apps.scannedApps),
                    detail = getString(R.string.timeline_apps_rescan_detail, bundle.apps.knownThreats + bundle.apps.highRiskApps)
                )
                renderInstalledApps(bundle.apps)
                renderProtectionStatus()
                val totalAlerts = bundle.apps.knownThreats + bundle.apps.highRiskApps + bundle.files.alerts
                val titleRes = when {
                    totalAlerts > 0 -> R.string.smart_scan_complete_danger
                    bundle.apps.reviewApps > 0 -> R.string.smart_scan_complete_attention
                    else -> R.string.smart_scan_complete_safe
                }
                val colorRes = when {
                    totalAlerts > 0 -> R.color.status_danger
                    bundle.apps.reviewApps > 0 -> R.color.status_warn
                    else -> R.color.status_ok
                }
                val detail = buildString {
                    append(getString(
                        R.string.full_scan_result,
                        NumberFormat.getIntegerInstance().format(bundle.apps.scannedApps),
                        NumberFormat.getIntegerInstance().format(bundle.files.scannedFiles),
                        NumberFormat.getIntegerInstance().format(totalAlerts)
                    ))
                    if (bundle.files.truncated) {
                        append('\n')
                        append(getString(R.string.full_scan_truncated_note))
                    }
                }
                showSmartResult(
                    titleRes,
                    if (totalAlerts > 0 || bundle.apps.reviewApps > 0) R.string.smart_scan_result_review_detail else R.string.smart_scan_result_safe_detail,
                    detail,
                    colorRes
                )
            }.onFailure { error ->
                hideSmartScan()
                if (error is CancellationException) {
                    showSmartResult(R.string.scan_cancelled_title, R.string.scan_cancelled_title, getString(R.string.scan_cancelled_detail), R.color.status_warn)
                } else {
                    showSmartResult(R.string.smart_scan_failed_title, R.string.smart_scan_failed_title, getString(R.string.smart_scan_failed_full_detail), R.color.status_warn)
                }
            }
        }
    }

    private fun runDownloadsScan() {
        if (!ProtectionAccess.hasDownloadsReadAccess(this)) {
            requestAntivirusFileAccess()
            return
        }
        showPage(PAGE_SCAN)
        scanCancelRequested = false
        activeScan = true
        setScanControlsEnabled(false)
        binding.btnStopScan.isEnabled = true
        showSmartScan(R.string.scan_stage_downloads, R.string.downloads_scan_running_detail)
        updateScanProgress(1, R.string.scan_stage_downloads, getString(R.string.scan_target_preparing), getString(R.string.scan_scope_shared_storage, "Downloads"))

        lifecycleScope.launch(uiCoroutineErrorHandler) {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    DownloadProtectionScanner(applicationContext).scanChangedFiles { completed, total, fileName, path ->
                        if (scanCancelRequested) throw CancellationException("scan cancelled")
                        val percent = if (total <= 0) 1 else ((completed * 99) / total).coerceIn(1, 99)
                        runOnUiThread {
                            updateScanProgress(
                                percent,
                                R.string.scan_stage_downloads,
                                fileName,
                                getString(R.string.scan_scope_shared_storage, path)
                            )
                        }
                    }
                }
            }
            activeScan = false
            scanCancelRequested = false
            setScanControlsEnabled(true)
            binding.btnStopScan.isEnabled = false
            outcome.onSuccess { summary ->
                updateScanProgress(100, R.string.scan_stage_finishing, getString(R.string.scan_complete_percent), getString(R.string.scan_stage_finishing))
                renderProtectionStatus()
                val titleRes = if (summary.alerts > 0) R.string.smart_scan_complete_danger else R.string.smart_scan_complete_safe
                val colorRes = if (summary.alerts > 0) R.color.status_danger else R.color.status_ok
                showSmartResult(
                    titleRes,
                    if (summary.alerts > 0) R.string.smart_scan_result_review_detail else R.string.smart_scan_result_safe_detail,
                    getString(
                        R.string.downloads_scan_result,
                        NumberFormat.getIntegerInstance().format(summary.scannedFiles),
                        NumberFormat.getIntegerInstance().format(summary.alerts)
                    ),
                    colorRes
                )
            }.onFailure { error ->
                hideSmartScan()
                if (error is CancellationException) {
                    showSmartResult(R.string.scan_cancelled_title, R.string.scan_cancelled_title, getString(R.string.scan_cancelled_detail), R.color.status_warn)
                } else {
                    showSmartResult(R.string.smart_scan_failed_title, R.string.smart_scan_failed_title, getString(R.string.smart_scan_failed_detail), R.color.status_warn)
                }
            }
        }
    }

    private fun setScanControlsEnabled(enabled: Boolean) {
        binding.btnSmartScan.isEnabled = enabled
        binding.btnScanInstalledApps.isEnabled = enabled
        binding.btnQuickScanMode.isEnabled = enabled
        binding.btnFullScan.isEnabled = enabled
        binding.btnScanDownloads.isEnabled = enabled
        binding.btnChooseFile.isEnabled = enabled
        binding.btnScanFile.isEnabled = enabled && selectedUri != null
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
        showPage(PAGE_SCAN)
        scanCancelRequested = false
        activeScan = true
        binding.btnStopScan.isEnabled = true
        setScanControlsEnabled(false)
        binding.txtInstalledSummary.setText(R.string.scanning_installed_apps)
        binding.txtInstalledEmpty.visibility = View.GONE
        binding.installedResultsContainer.removeAllViews()
        showSmartScan(R.string.scan_stage_apps, R.string.smart_scan_detail)
        updateScanProgress(1, R.string.scan_stage_apps, getString(R.string.scan_target_preparing), getString(R.string.scan_scope_preparing))

        lifecycleScope.launch(uiCoroutineErrorHandler) {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    installedAppScanner.scanUserApps { completed, total, appName, packageName ->
                        if (scanCancelRequested) throw CancellationException("scan cancelled")
                        val percent = if (total <= 0) 0 else ((completed * 100) / total).coerceIn(1, 99)
                        runOnUiThread {
                            updateScanProgress(
                                percent,
                                R.string.scan_stage_apps,
                                getString(R.string.scan_stage_app_progress, NumberFormat.getIntegerInstance().format(completed.coerceAtLeast(1)), NumberFormat.getIntegerInstance().format(total)),
                                "$appName\n${getString(R.string.scan_scope_package, packageName)}"
                            )
                        }
                    }
                }
            }
            activeScan = false
            binding.btnStopScan.isEnabled = false
            setScanControlsEnabled(true)
            result.onSuccess { summary ->
                updateScanProgress(100, R.string.scan_stage_finishing, getString(R.string.scan_complete_percent), getString(R.string.scan_stage_finishing))
                lastInstalledSummary = summary
                protectionPreferences.totalAppsChecked += summary.scannedApps.toLong()
                protectionPreferences.totalThreatsDetected += (summary.knownThreats + summary.highRiskApps).toLong()
                protectionPreferences.markActivity(getString(R.string.activity_apps_rescan_complete, summary.scannedApps))
                protectionActivityStore.add(
                    kind = ProtectionActivityKind.APP_SCAN,
                    state = if (summary.knownThreats > 0 || summary.highRiskApps > 0) ProtectionActivityState.THREAT else if (summary.reviewApps > 0) ProtectionActivityState.ATTENTION else ProtectionActivityState.SAFE,
                    title = getString(R.string.timeline_apps_rescan_complete, summary.scannedApps),
                    detail = getString(R.string.timeline_apps_rescan_detail, summary.knownThreats + summary.highRiskApps)
                )
                renderInstalledApps(summary)
                renderSmartInstalledResult(summary)
                renderProtectionStatus()
                renderProtectionPosture()
            }.onFailure {
                hideSmartScan()
                if (scanCancelRequested || it is CancellationException) {
                    binding.txtInstalledSummary.setText(R.string.scan_cancelled_title)
                    showSmartResult(R.string.scan_cancelled_title, R.string.scan_cancelled_title, getString(R.string.scan_cancelled_detail), R.color.status_warn)
                } else {
                    binding.txtInstalledSummary.setText(R.string.installed_scan_failed)
                    showSmartResult(R.string.smart_scan_failed_title, R.string.installed_scan_failed, getString(R.string.smart_scan_failed_detail), R.color.status_warn)
                }
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
        showPage(PAGE_SCAN)
        scanCancelRequested = false
        activeScan = true
        binding.btnStopScan.isEnabled = true
        setScanControlsEnabled(false)
        binding.txtClassification.setText(R.string.scanning)
        showSmartScan(R.string.file_scan_running_title, R.string.file_scan_running_detail)
        updateScanProgress(1, R.string.file_scan_running_title, binding.txtSelectedFile.text.toString(), uri.toString())
        binding.txtReason.text = ""
        binding.txtTechnical.text = ""
        binding.txtApkAnalysis.text = ""
        binding.txtApkAnalysis.visibility = View.GONE
        binding.resultActions.visibility = View.GONE

        lifecycleScope.launch(uiCoroutineErrorHandler) {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    scanner.scan(uri) { progress ->
                        if (scanCancelRequested) throw CancellationException("scan cancelled")
                        runOnUiThread {
                            val stage = when (progress.stage) {
                                FileScanStage.HASHING -> R.string.scan_stage_hashing
                                FileScanStage.REPUTATION -> R.string.scan_stage_reputation
                                FileScanStage.APK_ANALYSIS -> R.string.scan_stage_apk_analysis
                                FileScanStage.FINALIZING -> R.string.scan_stage_finishing
                            }
                            updateScanProgress(progress.percent, stage, progress.fileName, uri.toString())
                        }
                    }
                }
            }
            activeScan = false
            setScanControlsEnabled(true)
            binding.btnStopScan.isEnabled = false
            outcome.onSuccess { result ->
                updateScanProgress(100, R.string.scan_stage_finishing, result.fileName, uri.toString())
                lastScanResult = result
                recordStore.recordScan(result)
                protectionPreferences.totalFilesChecked += 1L
                protectionPreferences.markActivity(getString(R.string.activity_file_checked, result.fileName))
                protectionActivityStore.add(
                    kind = ProtectionActivityKind.FILE_SCAN,
                    state = when (result.classification) {
                        ScanClassification.KNOWN_THREAT -> ProtectionActivityState.THREAT
                        ScanClassification.SUSPICIOUS, ScanClassification.UNKNOWN_APK -> ProtectionActivityState.ATTENTION
                        else -> ProtectionActivityState.SAFE
                    },
                    title = getString(R.string.timeline_file_checked, result.fileName),
                    detail = uri.toString()
                )
                renderResult(result)
                renderSecurityManagement()
                renderSmartFileResult(result)
                renderProtectionStatus()
                renderProtectionPosture()
            }.onFailure {
                hideSmartScan()
                if (scanCancelRequested || it is CancellationException) {
                    binding.txtClassification.setText(R.string.scan_cancelled_title)
                    binding.txtReason.setText(R.string.scan_cancelled_detail)
                    showSmartResult(R.string.scan_cancelled_title, R.string.scan_cancelled_title, getString(R.string.scan_cancelled_detail), R.color.status_warn)
                } else {
                    binding.txtClassification.setText(R.string.scan_failed)
                    binding.txtReason.setText(R.string.file_access_error)
                    showSmartResult(R.string.smart_scan_failed_title, R.string.scan_failed, getString(R.string.file_access_error), R.color.status_warn)
                }
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
            ScanDetectionReason.APK_MULTI_ENGINE_KNOWN -> R.string.reason_apk_multi_engine_known
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
                analysis.advancedVerdict?.let { verdict ->
                    append('\n')
                    append(getString(R.string.detection_engine_summary,
                        NumberFormat.getIntegerInstance().format(verdict.score),
                        NumberFormat.getIntegerInstance().format(verdict.engineCount),
                        getString(threatFamilyString(verdict.family))))
                    append('\n')
                    append(getString(R.string.detection_engine_evidence,
                        NumberFormat.getIntegerInstance().format(analysis.matchedRuleCount),
                        NumberFormat.getIntegerInstance().format(analysis.networkIndicatorCount),
                        NumberFormat.getIntegerInstance().format(analysis.markerCount),
                        NumberFormat.getPercentInstance().format(analysis.localModelProbability)))
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

    private fun threatFamilyString(family: ThreatFamily): Int = when (family) {
        ThreatFamily.UNKNOWN -> R.string.family_unknown
        ThreatFamily.MALWARE -> R.string.family_malware
        ThreatFamily.TROJAN -> R.string.family_trojan
        ThreatFamily.SPYWARE -> R.string.family_spyware
        ThreatFamily.STALKERWARE -> R.string.family_stalkerware
        ThreatFamily.BANKER -> R.string.family_banker
        ThreatFamily.RAT -> R.string.family_rat
        ThreatFamily.DROPPER -> R.string.family_dropper
        ThreatFamily.RANSOMWARE -> R.string.family_ransomware
        ThreatFamily.PHISHING -> R.string.family_phishing
        ThreatFamily.RISKWARE -> R.string.family_riskware
        ThreatFamily.ADWARE -> R.string.family_adware
        ThreatFamily.TEST -> R.string.family_test
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
        lifecycleScope.launch(uiCoroutineErrorHandler) {
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
        lifecycleScope.launch(uiCoroutineErrorHandler) {
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
                lifecycleScope.launch(uiCoroutineErrorHandler) {
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

    private fun runStandaloneSecurityAudit() {
        if (securityAuditRunning) return
        securityAuditRunning = true
        binding.btnRunSecurityAudit.isEnabled = false
        lifecycleScope.launch(uiCoroutineErrorHandler) {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    SecurityAuditSummary(
                        device = DeviceSecurityAuditor(applicationContext).audit(),
                        network = NetworkSecurityAuditor(applicationContext).audit(),
                        privacy = PrivacyPermissionAuditor(applicationContext).audit()
                    )
                }
            }
            securityAuditRunning = false
            binding.btnRunSecurityAudit.isEnabled = true
            outcome.onSuccess { audit ->
                lastSecurityAudit = audit
                lastSecurityAuditAt = System.currentTimeMillis()
                renderSecurityAudit()
                renderProtectionPosture()
            }.onFailure { error ->
                Log.e(TAG, "Security audit failed", error)
                binding.txtSecurityAuditStatus.setText(R.string.security_audit_unavailable)
                binding.txtSecurityAuditCounts.text = getString(R.string.operation_failed_try_again)
            }
        }
    }

    private fun renderSecurityAudit() {
        val audit = lastSecurityAudit ?: return
        val device = audit.device
        binding.txtDeviceAudit.text = getString(
            R.string.security_audit_device_summary,
            getString(if (device.screenLockSecure) R.string.security_audit_enabled else R.string.security_audit_disabled),
            NumberFormat.getIntegerInstance().format(device.rootSignals),
            getString(if (device.adbEnabled) R.string.security_audit_enabled else R.string.security_audit_disabled)
        )

        val network = audit.network
        val transport = getString(when (network.transport) {
            NetworkTransportType.NONE -> R.string.network_transport_none
            NetworkTransportType.WIFI -> R.string.network_transport_wifi
            NetworkTransportType.CELLULAR -> R.string.network_transport_cellular
            NetworkTransportType.ETHERNET -> R.string.network_transport_ethernet
            NetworkTransportType.VPN -> R.string.network_transport_vpn
            NetworkTransportType.OTHER -> R.string.network_transport_other
        })
        binding.txtNetworkAudit.text = getString(
            R.string.security_audit_network_summary,
            transport,
            getString(if (network.validated) R.string.security_audit_validated else R.string.security_audit_unvalidated),
            getString(if (network.privateDnsActive) R.string.security_audit_active else R.string.security_audit_optional)
        )

        val privacy = audit.privacy
        binding.txtPrivacyAudit.text = getString(
            R.string.security_audit_privacy_summary,
            NumberFormat.getIntegerInstance().format(privacy.scannedApps),
            NumberFormat.getIntegerInstance().format(privacy.appsWithSensitivePermissions),
            NumberFormat.getIntegerInstance().format(privacy.elevatedPermissionApps)
        )
        val statusRes = when {
            audit.highFindings > 0 -> R.string.security_audit_status_action
            audit.warningFindings > 0 -> R.string.security_audit_status_review
            else -> R.string.security_audit_status_good
        }
        val colorRes = when {
            audit.highFindings > 0 -> R.color.status_danger
            audit.warningFindings > 0 -> R.color.status_warn
            else -> R.color.status_ok
        }
        binding.txtSecurityAuditStatus.setText(statusRes)
        binding.txtSecurityAuditStatus.setTextColor(getColor(colorRes))
        binding.txtSecurityAuditCounts.text = getString(
            R.string.security_audit_counts,
            NumberFormat.getIntegerInstance().format(audit.highFindings),
            NumberFormat.getIntegerInstance().format(audit.warningFindings)
        )
    }

    private fun openSecuritySettings() {
        runCatching { startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) }
            .onFailure { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }

    private fun openPrivacySettings() {
        val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Intent(Settings.ACTION_PRIVACY_SETTINGS)
        } else {
            Intent(Settings.ACTION_SETTINGS)
        }
        runCatching { startActivity(intent) }
            .onFailure { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }

    private fun openNetworkSettings() {
        runCatching { startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS)) }
            .onFailure { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }

    private fun renderSmartDashboard(baseScore: Int, level: ProtectionPostureLevel) {
        val installed = lastInstalledSummary
        val fileClassification = lastScanResult?.classification
        val hasKnownThreat = (installed?.knownThreats ?: 0) > 0 || fileClassification == ScanClassification.KNOWN_THREAT
        val hasHighRisk = (installed?.highRiskApps ?: 0) > 0 || fileClassification == ScanClassification.SUSPICIOUS
        val hasReview = (installed?.reviewApps ?: 0) > 0 || fileClassification == ScanClassification.UNKNOWN_APK
        val audit = lastSecurityAudit
        val auditHigh = (audit?.highFindings ?: 0) > 0
        val auditWarnings = (audit?.warningFindings ?: 0) > 0
        val auditedBaseScore = (baseScore - (audit?.posturePenalty ?: 0)).coerceAtLeast(0)
        val adjustedScore = when {
            hasKnownThreat -> minOf(auditedBaseScore, 35)
            hasHighRisk || auditHigh -> minOf(auditedBaseScore, 60)
            hasReview || auditWarnings -> minOf(auditedBaseScore, 82)
            else -> auditedBaseScore
        }
        binding.txtSecurityScore.text = NumberFormat.getIntegerInstance().format(adjustedScore)
        val colorRes: Int
        val headlineRes: Int
        val detailRes: Int
        when {
            hasKnownThreat -> {
                colorRes = R.color.status_danger
                headlineRes = R.string.dashboard_action_required
                detailRes = R.string.dashboard_action_detail
            }
            hasHighRisk || hasReview || auditHigh || auditWarnings || level == ProtectionPostureLevel.ATTENTION -> {
                colorRes = R.color.status_warn
                headlineRes = R.string.dashboard_attention
                detailRes = R.string.dashboard_attention_detail
            }
            level == ProtectionPostureLevel.LIMITED -> {
                colorRes = R.color.status_warn
                headlineRes = R.string.dashboard_limited
                detailRes = R.string.dashboard_limited_detail
            }
            else -> {
                colorRes = R.color.status_ok
                headlineRes = R.string.dashboard_protected
                detailRes = R.string.dashboard_protected_detail
            }
        }
        binding.txtSecurityScore.setTextColor(getColor(android.R.color.white))
        binding.homeHeroCard.setCardBackgroundColor(
            getColor(
                when (colorRes) {
                    R.color.status_danger -> R.color.status_danger
                    R.color.status_warn -> R.color.status_warn
                    else -> R.color.brand_primary
                }
            )
        )
        binding.txtDashboardHeadline.setText(headlineRes)
        binding.txtDashboardSubtitle.setText(detailRes)
    }

    private fun showSmartScan(titleRes: Int, detailRes: Int) {
        showPage(PAGE_SCAN)
        binding.smartResultCard.visibility = View.GONE
        binding.smartScanCard.visibility = View.VISIBLE
        binding.txtSmartScanState.setText(titleRes)
        binding.txtSmartScanDetail.setText(detailRes)
        binding.smartScanProgress.isIndeterminate = false
        binding.btnStopScan.visibility = if (activeScan) View.VISIBLE else View.GONE
    }

    private fun updateScanProgress(percent: Int, titleRes: Int, target: String, scope: String) {
        val safePercent = percent.coerceIn(0, 100)
        binding.smartScanProgress.isIndeterminate = false
        binding.smartScanProgress.progress = safePercent
        binding.txtSmartScanPercent.text = getString(R.string.scan_progress_percent, NumberFormat.getIntegerInstance().format(safePercent))
        binding.txtSmartScanState.setText(titleRes)
        binding.txtSmartScanTarget.text = target
        binding.txtSmartScanScope.text = scope
        binding.btnStopScan.visibility = if (activeScan) View.VISIBLE else View.GONE
    }

    private fun hideSmartScan() {
        binding.smartScanCard.visibility = View.GONE
    }

    private fun showSmartResult(titleRes: Int, summaryRes: Int, details: String, colorRes: Int) {
        hideSmartScan()
        binding.smartResultCard.visibility = View.VISIBLE
        binding.txtSmartResultTitle.setText(titleRes)
        binding.txtSmartResultTitle.setTextColor(getColor(colorRes))
        binding.txtSmartResultSummary.setText(summaryRes)
        binding.txtSmartResultDetails.text = details
    }

    private fun renderSmartInstalledResult(summary: InstalledAppsScanSummary) {
        val formatter = NumberFormat.getIntegerInstance()
        val titleRes = when {
            summary.knownThreats > 0 || summary.highRiskApps > 0 -> R.string.smart_scan_complete_danger
            summary.reviewApps > 0 -> R.string.smart_scan_complete_attention
            else -> R.string.smart_scan_complete_safe
        }
        val colorRes = when {
            summary.knownThreats > 0 || summary.highRiskApps > 0 -> R.color.status_danger
            summary.reviewApps > 0 -> R.color.status_warn
            else -> R.color.status_ok
        }
        val details = getString(
            R.string.smart_scan_result_summary,
            formatter.format(summary.scannedApps),
            formatter.format(summary.reviewApps),
            formatter.format(summary.highRiskApps),
            formatter.format(summary.knownThreats)
        )
        showSmartResult(
            titleRes,
            if (summary.knownThreats > 0 || summary.highRiskApps > 0 || summary.reviewApps > 0) R.string.smart_scan_result_review_detail else R.string.smart_scan_result_safe_detail,
            details,
            colorRes
        )
    }

    private fun renderSmartFileResult(result: ScanResult) {
        val titleRes = when (result.classification) {
            ScanClassification.KNOWN_THREAT -> R.string.file_result_danger
            ScanClassification.SUSPICIOUS, ScanClassification.UNKNOWN_APK -> R.string.file_result_attention
            ScanClassification.NO_KNOWN_THREAT, ScanClassification.TEST_SIGNATURE -> R.string.file_result_safe
        }
        val colorRes = when (result.classification) {
            ScanClassification.KNOWN_THREAT -> R.color.status_danger
            ScanClassification.SUSPICIOUS, ScanClassification.UNKNOWN_APK -> R.color.status_warn
            ScanClassification.NO_KNOWN_THREAT, ScanClassification.TEST_SIGNATURE -> R.color.status_ok
        }
        val classification = getString(classificationString(result.classification))
        showSmartResult(
            titleRes,
            classificationString(result.classification),
            getString(R.string.file_result_summary, classification),
            colorRes
        )
    }

    private fun scrollToSection(section: View) {
        binding.mainScroll.post {
            binding.mainScroll.smoothScrollTo(0, section.top)
        }
    }

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
        private const val TAG = "AmanSecurity"
        private const val PRIVACY_PREFERENCES = "privacy_preferences"
        private const val INSTALLED_SCAN_DISCLOSURE_KEY = "installed_scan_disclosure_version"
        private const val INSTALLED_SCAN_DISCLOSURE_VERSION = 1
        private const val PROTECTION_DISCLOSURE_KEY = "background_protection_disclosure_version"
        private const val PROTECTION_DISCLOSURE_VERSION = 1
        private const val MAX_VISIBLE_PROTECTION_EVENTS = 8
        private const val SECURITY_AUDIT_REFRESH_MS = 60_000L
        private const val MAX_VISIBLE_APP_RESULTS = 20
        private const val MAX_VISIBLE_SECURITY_RECORDS = 20
        private const val MAX_VISIBLE_HISTORY = 20
        const val EXTRA_OPEN_PAGE = "open_page"
        const val EXTRA_START_SMART_SCAN = "start_smart_scan"
        const val OPEN_PAGE_SCAN = 1
        const val OPEN_PAGE_PROTECTION = 2
        private const val PAGE_HOME = 0
        private const val PAGE_SCAN = OPEN_PAGE_SCAN
        private const val PAGE_PROTECTION = OPEN_PAGE_PROTECTION
        private const val PAGE_SETTINGS = 3
    }
}

package com.aman.security.protection

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.ServiceCompat
import com.aman.security.R
import com.aman.security.scanner.ApkStaticAnalyzer
import com.aman.security.scanner.AppRiskLevel
import com.aman.security.scanner.FileScanner
import com.aman.security.scanner.InstalledAppScanner
import com.aman.security.scanner.InstalledAppsScanSummary
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.runtime.CameraMicGuard
import com.aman.security.runtime.ClipboardGuard
import com.aman.security.runtime.ForegroundAppScanner
import com.aman.security.runtime.ForegroundKind
import com.aman.security.runtime.HardeningReport
import com.aman.security.runtime.OverlayWatchdog
import com.aman.security.runtime.IntegrityLevel
import com.aman.security.runtime.PackageIntegrityGuard
import com.aman.security.runtime.SystemHardeningAuditor
import com.aman.security.security.DataExfiltrationGuard
import com.aman.security.security.DeviceSecurityAuditor
import com.aman.security.security.NetworkSecurityAuditor
import com.aman.security.security.PrivacyPermissionAuditor
import com.aman.security.security.SecurityAuditSummary
import com.aman.security.security.SpywareAuditor
import com.aman.security.security.SpywareAuditSummary
import com.aman.security.security.SecurityRecordStore
import java.io.File
import java.util.concurrent.CancellationException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * User-visible real-time protection coordinator and durable manual-scan runtime.
 *
 * Manual scans are deliberately owned by this foreground service instead of MainActivity.
 * Leaving/recreating the UI therefore cannot cancel a scan. Scan state is persisted by
 * [ScanSessionStore], and START_STICKY lets Android recreate this service after process pressure.
 */
class ProtectionService : Service() {
    private lateinit var preferences: ProtectionPreferences
    private lateinit var activityStore: ProtectionActivityStore
    private lateinit var scanStore: ScanSessionStore
    private val handler = Handler(Looper.getMainLooper())
    private var downloadsObserver: FileObserver? = null
    private var securityControlWatcher: SecurityControlChangeWatcher? = null

    private val exfilExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "AmanDataExfilGuard").apply { priority = Thread.MIN_PRIORITY }
    }
    private val exfilAuditRunning = AtomicBoolean(false)

    private val scanExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "AmanPersistentScan").apply { priority = Thread.NORM_PRIORITY - 1 }
    }
    private val scanRunning = AtomicBoolean(false)
    private val scanCancelRequested = AtomicBoolean(false)
    private var lastScanNotificationAt = 0L
    private var lastScanNotificationProgress = -1
    private var overlayWatchdog: OverlayWatchdog? = null
    private var cameraMicGuard: CameraMicGuard? = null
    private var clipboardGuard: ClipboardGuard? = null
    private var foregroundScanner: ForegroundAppScanner? = null
    private var runtimeInitialized = false

    private val heartbeat = object : Runnable {
        override fun run() {
            if (!preferences.enabled) {
                stopBackgroundSurfaces()
                maybeStopWhenIdle()
                return
            }
            preferences.serviceHeartbeatAt = System.currentTimeMillis()
            ProtectionNotifier.updateProtectionStatus(this@ProtectionService)
            ensureDownloadsObserver()
            ensureSecurityControlWatcher()
            maybeRunDataExfiltrationGuard()
            runRuntimeShieldTick()
            handler.postDelayed(this, HEARTBEAT_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        preferences = ProtectionPreferences(this)
        activityStore = ProtectionActivityStore(this)
        scanStore = ScanSessionStore(this)
        ProtectionNotifier.ensureChannels(this)
        securityControlWatcher = SecurityControlChangeWatcher(this) {
            if (preferences.enabled && preferences.intrusionMonitorEnabled) {
                ProtectionScheduler.intrusionCheckNow(applicationContext)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopBackgroundSurfaces()
                maybeStopWhenIdle()
                return if (scanStore.snapshot().isActive) START_STICKY else START_NOT_STICKY
            }
            ACTION_CANCEL_SCAN -> {
                val id = intent.getStringExtra(EXTRA_SCAN_SESSION_ID).orEmpty()
                if (id.isNotBlank()) {
                    scanStore.requestCancel(id)
                    scanCancelRequested.set(true)
                    ensureForeground()
                }
                return START_STICKY
            }
            ACTION_SCAN -> {
                ensureForeground()
                startOrResumeScan(
                    intent.getStringExtra(EXTRA_SCAN_SESSION_ID).orEmpty(),
                    intent.getStringExtra(EXTRA_SCAN_MODE)
                )
                if (preferences.enabled) startBackgroundSurfaces()
                return START_STICKY
            }
        }

        val activeScan = scanStore.snapshot().isActive
        if (!preferences.enabled && !activeScan) {
            stopSelf()
            return START_NOT_STICKY
        }

        ensureForeground()
        if (preferences.enabled) startBackgroundSurfaces()
        if (activeScan) {
            // Covers Android recreating a START_STICKY service with a null Intent.
            val snapshot = scanStore.snapshot()
            startOrResumeScan(snapshot.sessionId, snapshot.mode.name)
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        if (preferences.enabled || scanStore.snapshot().isActive) {
            ensureForeground()
            ProtectionNotifier.refreshForegroundStatus(applicationContext)
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        downloadsObserver?.stopWatching()
        downloadsObserver = null
        securityControlWatcher?.stop()
        exfilExecutor.shutdownNow()
        if (scanStore.snapshot().isActive) scanExecutor.shutdown() else scanExecutor.shutdownNow()
        // Keep an active durable session marked active. START_STICKY recreation can resume it.
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun ensureForeground() {
        val notification = ProtectionNotifier.buildProtectionStatusNotification(this)
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else 0
        ServiceCompat.startForeground(
            this,
            ProtectionNotifier.STATUS_NOTIFICATION_ID,
            notification,
            type
        )
    }

    private fun startBackgroundSurfaces() {
        val now = System.currentTimeMillis()
        if (preferences.serviceStartedAt <= 0L || now - preferences.serviceHeartbeatAt > STALE_RESTART_MS) {
            preferences.serviceStartedAt = now
            activityStore.add(
                kind = ProtectionActivityKind.SERVICE,
                state = ProtectionActivityState.INFO,
                title = getString(R.string.timeline_realtime_started),
                detail = getString(R.string.timeline_realtime_started_detail),
                dedupeKey = "${ProtectionActivityKind.SERVICE}:${getString(R.string.timeline_realtime_started)}:${getString(R.string.timeline_realtime_started_detail)}"
            )
        }
        preferences.serviceHeartbeatAt = now
        preferences.markActivity(getString(R.string.activity_realtime_active))
        ensureDownloadsObserver()
        ensureSecurityControlWatcher()
        handler.removeCallbacks(heartbeat)
        handler.postDelayed(heartbeat, HEARTBEAT_MS)
    }

    private fun stopBackgroundSurfaces() {
        handler.removeCallbacks(heartbeat)
        downloadsObserver?.stopWatching()
        downloadsObserver = null
        securityControlWatcher?.stop()
        preferences.serviceHeartbeatAt = 0L
        preferences.serviceStartedAt = 0L
    }

    private fun maybeStopWhenIdle() {
        if (preferences.enabled || scanStore.snapshot().isActive || scanRunning.get()) {
            ensureForeground()
            return
        }
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startOrResumeScan(sessionId: String, rawMode: String?) {
        if (sessionId.isBlank() || scanRunning.get()) return
        val snapshot = scanStore.snapshot()
        if (snapshot.sessionId != sessionId || !snapshot.isActive) return
        val mode = runCatching { PersistentScanMode.valueOf(rawMode ?: snapshot.mode.name) }.getOrDefault(snapshot.mode)
        if (!scanRunning.compareAndSet(false, true)) return
        scanCancelRequested.set(snapshot.cancelledRequested)
        scanExecutor.execute {
            runPersistentScan(sessionId, mode)
        }
    }

    private fun runPersistentScan(sessionId: String, mode: PersistentScanMode) {
        scanStore.markRunning(sessionId)
        updateScanProgress(sessionId, 1, "preparing", "", mode.name.lowercase())
        val database = SignatureDatabase(applicationContext)
        val appScanner = InstalledAppScanner(applicationContext, database)
        var apps = InstalledAppsScanSummary(0, 0, 0, 0, emptyList())
        var files = SharedStorageScanSummary(0, 0, 0, 0, 0, 0, false, false)
        var audit = SecurityAuditSummary(
            DeviceSecurityAuditor(applicationContext).audit(),
            NetworkSecurityAuditor(applicationContext).audit(),
            PrivacyPermissionAuditor(applicationContext).audit()
        )
        var spyware = SpywareAuditSummary(0, 0, 0, emptyList())

        try {
            throwIfCancelled(sessionId)
            when (mode) {
                PersistentScanMode.QUICK -> {
                    apps = appScanner.scanUserApps(deep = true) { completed, total, appName, packageName ->
                        throwIfCancelled(sessionId)
                        val p = if (total <= 0) 5 else (5 + (completed * 72 / total)).coerceIn(5, 77)
                        updateScanProgress(sessionId, p, "apps", appName, packageName)
                    }
                    throwIfCancelled(sessionId)
                    audit = runSecurityAudit(sessionId, 80, 90)
                    spyware = runSpywareAudit(sessionId, 92)
                }
                PersistentScanMode.SMART -> {
                    apps = appScanner.scanUserApps(deep = true) { completed, total, appName, packageName ->
                        throwIfCancelled(sessionId)
                        val p = if (total <= 0) 5 else (5 + (completed * 62 / total)).coerceIn(5, 67)
                        updateScanProgress(sessionId, p, "apps", appName, packageName)
                    }
                    audit = runSecurityAudit(sessionId, 70, 80)
                    spyware = runSpywareAudit(sessionId, 82)
                    val treeUri = preferences.protectedTreeUri
                    if (treeUri != null) {
                        val fileScanner = FileScanner(contentResolver, database, ApkStaticAnalyzer(applicationContext, database))
                        val folder = ProtectedFolderScanner(
                            resolver = contentResolver,
                            fileScanner = fileScanner,
                            preferences = preferences,
                            eventStore = ProtectionEventStore(applicationContext),
                            recordStore = SecurityRecordStore(applicationContext),
                            notifier = { ProtectionNotifier.notifyEvent(applicationContext, it) },
                            scanCacheStore = LocalScanCacheStore(applicationContext)
                        ).scan(treeUri) { scanned, fileName, documentId ->
                            throwIfCancelled(sessionId)
                            updateScanProgress(sessionId, (86 + scanned.coerceAtMost(11)).coerceAtMost(97), "folder", fileName, documentId)
                        }
                        files = SharedStorageScanSummary(
                            scannedFiles = folder.scannedFiles,
                            alerts = folder.alerts,
                            knownThreats = folder.knownThreats,
                            highRisk = folder.highRisk,
                            inaccessible = 0,
                            candidates = folder.scannedFiles,
                            truncated = false,
                            accessMissing = folder.permissionLost,
                            findings = folder.findings.map { finding ->
                                SharedStorageAlertFinding(
                                    displayName = finding.displayName,
                                    location = finding.location,
                                    sha256 = finding.sha256,
                                    severity = finding.severity
                                )
                            }
                        )
                    }
                }
                PersistentScanMode.FULL -> {
                    apps = appScanner.scanAllApps(deep = true) { completed, total, appName, packageName ->
                        throwIfCancelled(sessionId)
                        val p = if (total <= 0) 3 else (3 + (completed * 37 / total)).coerceIn(3, 40)
                        updateScanProgress(sessionId, p, "apps", appName, packageName)
                    }
                    throwIfCancelled(sessionId)
                    files = SharedStorageScanner(applicationContext).scan(
                        cancelled = { isCancelled(sessionId) },
                        onProgress = { completed, total, name, path ->
                            throwIfCancelled(sessionId)
                            val p = if (total <= 0) 42 else (42 + (completed * 43 / total)).coerceIn(42, 85)
                            updateScanProgress(sessionId, p, "files", name, path)
                        }
                    )
                    audit = runSecurityAudit(sessionId, 88, 94)
                    spyware = runSpywareAudit(sessionId, 96)
                }
            }
            throwIfCancelled(sessionId)
            updateScanProgress(sessionId, 99, "finishing", "", "")

            preferences.totalAppsChecked += apps.scannedApps.toLong()
            preferences.totalThreatsDetected += (apps.knownThreats + apps.highRiskApps).toLong()
            preferences.markActivity(getString(R.string.activity_apps_rescan_complete, apps.scannedApps))
            activityStore.add(
                kind = ProtectionActivityKind.APP_SCAN,
                state = if (apps.knownThreats > 0 || apps.highRiskApps > 0 || files.alerts > 0 || audit.highFindings > 0 || spyware.highRiskApps > 0) {
                    ProtectionActivityState.THREAT
                } else if (apps.reviewApps > 0 || audit.warningFindings > 0 || spyware.reviewApps > 0) {
                    ProtectionActivityState.ATTENTION
                } else {
                    ProtectionActivityState.SAFE
                },
                title = getString(R.string.timeline_apps_rescan_complete, apps.scannedApps),
                detail = getString(R.string.timeline_apps_rescan_detail, apps.knownThreats + apps.highRiskApps + files.alerts)
            )

            ScanFindingsStore(applicationContext).save(
                sessionId = sessionId,
                apps = apps,
                audit = audit,
                spyware = spyware,
                files = files
            )

            scanStore.complete(
                sessionId = sessionId,
                scannedApps = apps.scannedApps,
                reviewApps = apps.reviewApps,
                highRiskApps = apps.highRiskApps,
                knownThreats = apps.knownThreats,
                scannedFiles = files.scannedFiles,
                fileAlerts = files.alerts,
                securityWarnings = audit.warningFindings,
                securityHighs = audit.highFindings,
                spywareReview = spyware.reviewApps,
                spywareHigh = spyware.highRiskApps
            )
            ProtectionNotifier.notifyScanFinished(applicationContext, scanStore.snapshot())
        } catch (_: CancellationException) {
            scanStore.cancel(sessionId)
            ProtectionNotifier.notifyScanFinished(applicationContext, scanStore.snapshot())
        } catch (t: Throwable) {
            scanStore.fail(sessionId, t.message ?: t.javaClass.simpleName)
            ProtectionNotifier.notifyScanFinished(applicationContext, scanStore.snapshot())
        } finally {
            scanRunning.set(false)
            scanCancelRequested.set(false)
            lastScanNotificationAt = 0L
            lastScanNotificationProgress = -1
            if (preferences.enabled) {
                ensureForeground()
                startBackgroundSurfaces()
            } else {
                handler.post { maybeStopWhenIdle() }
            }
        }
    }

    private fun runSecurityAudit(sessionId: String, startProgress: Int, endProgress: Int): SecurityAuditSummary {
        throwIfCancelled(sessionId)
        updateScanProgress(sessionId, startProgress, "device", "", "")
        val device = DeviceSecurityAuditor(applicationContext).audit()
        throwIfCancelled(sessionId)
        updateScanProgress(sessionId, (startProgress + endProgress) / 2, "network", "", "")
        val network = NetworkSecurityAuditor(applicationContext).audit()
        throwIfCancelled(sessionId)
        updateScanProgress(sessionId, endProgress, "privacy", "", "")
        val privacy = PrivacyPermissionAuditor(applicationContext).audit()
        return SecurityAuditSummary(device, network, privacy)
    }

    private fun runSpywareAudit(sessionId: String, progress: Int): SpywareAuditSummary {
        throwIfCancelled(sessionId)
        updateScanProgress(sessionId, progress, "spyware", "", "")
        return SpywareAuditor(applicationContext).audit()
    }

    private fun updateScanProgress(sessionId: String, progress: Int, stage: String, target: String, scope: String) {
        scanStore.updateProgress(sessionId, progress, stage, target, scope)
        val now = System.currentTimeMillis()
        if (progress >= lastScanNotificationProgress + 4 || now - lastScanNotificationAt >= 2_500L || progress >= 99) {
            lastScanNotificationProgress = progress
            lastScanNotificationAt = now
            ProtectionNotifier.refreshForegroundStatus(applicationContext)
        }
    }

    private fun isCancelled(sessionId: String): Boolean =
        scanCancelRequested.get() || scanStore.isCancelRequested(sessionId)

    private fun throwIfCancelled(sessionId: String) {
        if (isCancelled(sessionId)) throw CancellationException("scan cancelled")
    }

    private fun maybeRunDataExfiltrationGuard() {
        if (!preferences.enabled || !preferences.dataExfiltrationGuardEnabled) return
        if (!exfilAuditRunning.compareAndSet(false, true)) return
        exfilExecutor.execute {
            try {
                DataExfiltrationGuard(applicationContext).lightweightHeartbeat()
            } finally {
                exfilAuditRunning.set(false)
            }
        }
    }

    private fun ensureSecurityControlWatcher() {
        if (preferences.enabled && preferences.intrusionMonitorEnabled) {
            securityControlWatcher?.start()
        } else {
            securityControlWatcher?.stop()
        }
    }

    private fun ensureDownloadsObserver() {
        if (!preferences.enabled || !preferences.downloadsProtectionEnabled ||
            !ProtectionAccess.hasDownloadsReadAccess(this)
        ) {
            downloadsObserver?.stopWatching()
            downloadsObserver = null
            return
        }
        if (downloadsObserver != null) return

        @Suppress("DEPRECATION")
        val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!downloads.exists() || !downloads.canRead()) return
        downloadsObserver = object : FileObserver(
            downloads.absolutePath,
            FileObserver.CREATE or FileObserver.MOVED_TO or FileObserver.CLOSE_WRITE
        ) {
            override fun onEvent(event: Int, relativePath: String?) {
                val child = relativePath?.takeIf { it.isNotBlank() } ?: return
                val file = File(downloads, child)
                if (!file.isFile || !file.canRead()) return
                preferences.markActivity(getString(R.string.activity_download_detected, file.name))
                ProtectionScheduler.scanDownloadedFile(applicationContext, file.absolutePath)
            }
        }.also { it.startWatching() }
    }

    private fun runRuntimeShieldTick() {
        if (!preferences.enabled) return
        ensureRuntimeGuards()
        val scanner = foregroundScanner ?: return
        val findings = runCatching { scanner.tick() }.getOrDefault(emptyList())
        for (finding in findings) {
            when (finding.kind) {
                ForegroundKind.ENTERED_SESSION -> {
                    val integrity = runCatching { PackageIntegrityGuard(this).verify(finding.detail) }.getOrNull()
                    if (integrity != null && integrity.level == IntegrityLevel.MODIFIED) {
                        ProtectionNotifier.notifyPackageModified(this, finding.detail)
                    }
                }
                ForegroundKind.OVERLAY_ATTACK -> {
                    val label = packageLabel(finding.detail)
                    ProtectionNotifier.notifyOverlayAttack(this, label, finding.detail)
                }
                ForegroundKind.MEDIA_ACCESS -> {
                    val label = packageLabel(finding.detail)
                    ProtectionNotifier.notifyMediaAccess(this, label, finding.detail)
                }
                ForegroundKind.CLIPBOARD_GUARD ->
                    ProtectionNotifier.notifyClipboardGuard(this, finding.detail)
                ForegroundKind.HARDENING_WEAK -> {
                    val report = SystemHardeningAuditor(this).audit()
                    ProtectionNotifier.notifyHardeningWeakness(this, report)
                }
            }
        }
    }

    private fun ensureRuntimeGuards() {
        if (runtimeInitialized) return
        val watchdog = OverlayWatchdog(this)
        val cameraMic = CameraMicGuard(this)
        val clipboard = ClipboardGuard(this)
        val scanner = ForegroundAppScanner(this)
        scanner.attach(watchdog, cameraMic, clipboard)
        overlayWatchdog = watchdog
        cameraMicGuard = cameraMic
        clipboardGuard = clipboard
        foregroundScanner = scanner
        runtimeInitialized = true
    }

    private fun packageLabel(packageName: String): String = runCatching {
        val info = packageManager.getPackageInfo(packageName, 0)
        info.applicationInfo?.loadLabel(packageManager)?.toString().orEmpty()
    }.getOrDefault(packageName)

    companion object {
        const val ACTION_START = "com.aman.security.action.START_PROTECTION"
        const val ACTION_STOP = "com.aman.security.action.STOP_PROTECTION"
        const val ACTION_REFRESH = "com.aman.security.action.REFRESH_PROTECTION"
        const val ACTION_SCAN = "com.aman.security.action.PERSISTENT_SCAN"
        const val ACTION_CANCEL_SCAN = "com.aman.security.action.CANCEL_PERSISTENT_SCAN"
        const val EXTRA_SCAN_SESSION_ID = "scan_session_id"
        const val EXTRA_SCAN_MODE = "scan_mode"
        private const val HEARTBEAT_MS = 10 * 60_000L
        private const val STALE_RESTART_MS = 25 * 60_000L
    }
}

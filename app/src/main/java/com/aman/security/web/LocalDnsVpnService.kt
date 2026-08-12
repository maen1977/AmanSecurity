package com.aman.security.web

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.ServiceCompat
import com.aman.security.R
import com.aman.security.protection.ProtectionActivityKind
import com.aman.security.protection.ProtectionActivityState
import com.aman.security.protection.ProtectionActivityStore
import com.aman.security.protection.ProtectionNotifier
import com.aman.security.protection.ProtectionPreferences
import com.aman.security.scanner.SignatureDatabase
import com.aman.security.scanner.UrlScanner
import com.aman.security.security.PrivateDnsCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.LinkedHashMap

/**
 * Lightweight DNS-only local VPN. It does not proxy normal app traffic and does not
 * decrypt HTTPS. Only DNS packets directed at the VPN's synthetic DNS address enter
 * the TUN interface; all other traffic stays on the underlying Android network.
 */
class LocalDnsVpnService : VpnService() {
    private lateinit var preferences: ProtectionPreferences
    private lateinit var database: SignatureDatabase
    private lateinit var scanner: UrlScanner
    private lateinit var activityStore: ProtectionActivityStore
    private val running = AtomicBoolean(false)
    private val mainHandler = Handler(Looper.getMainLooper())
    private var tunnel: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private var upstreamDns: InetAddress? = null
    private var lastIntelUpdateAt: Long = 0L
    private val verdictCache = object : LinkedHashMap<String, CachedVerdict>(128, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CachedVerdict>?): Boolean =
            size > VERDICT_CACHE_MAX
    }

    private val heartbeat = object : Runnable {
        override fun run() {
            if (!running.get() || !preferences.localWebShieldEnabled) return
            preferences.localWebShieldHeartbeatAt = System.currentTimeMillis()
            refreshThreatIntelIfNeeded()
            mainHandler.postDelayed(this, HEARTBEAT_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        preferences = ProtectionPreferences(this)
        database = SignatureDatabase(this)
        scanner = UrlScanner(database::findUrl)
        activityStore = ProtectionActivityStore(this)
        lastIntelUpdateAt = database.autonomousStore.info().lastSuccessfulUpdateEpochMs
        ProtectionNotifier.ensureChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP || !preferences.enabled || !preferences.localWebShieldEnabled) {
            stopShield()
            return Service.START_NOT_STICKY
        }
        if (intent?.action == ACTION_REFRESH && running.get()) {
            refreshThreatIntelIfNeeded(force = true)
            return Service.START_STICKY
        }
        if (prepare(this) != null) {
            preferences.localWebShieldHeartbeatAt = 0L
            stopSelf()
            return Service.START_NOT_STICKY
        }
        if (running.compareAndSet(false, true)) startShield()
        return Service.START_STICKY
    }

    override fun onRevoke() {
        preferences.localWebShieldEnabled = false
        stopShield()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopShield()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun startShield() {
        upstreamDns = selectUnderlyingDns()
        preferences.localWebShieldPrivateDnsAtStart = detectUnderlyingPrivateDns()

        val notification = ProtectionNotifier.buildWebShieldStatusNotification(this)
        val foregroundType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
        } else 0
        ServiceCompat.startForeground(
            this,
            ProtectionNotifier.WEB_SHIELD_NOTIFICATION_ID,
            notification,
            foregroundType
        )

        val descriptor = runCatching {
            val builder = Builder()
                .setSession(getString(R.string.local_web_shield_vpn_session))
                .setMtu(1500)
                .addAddress(VPN_ADDRESS, 32)
                .addDnsServer(VPN_DNS_ADDRESS)
                .addRoute(VPN_DNS_ADDRESS, 32)
                .allowFamily(OsConstants.AF_INET6)
                .setBlocking(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
            builder.establish()
        }.getOrNull()

        if (descriptor == null) {
            running.set(false)
            preferences.localWebShieldHeartbeatAt = 0L
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        tunnel = descriptor
        preferences.localWebShieldHeartbeatAt = System.currentTimeMillis()
        activityStore.add(
            kind = ProtectionActivityKind.WEB_SHIELD,
            state = ProtectionActivityState.INFO,
            title = getString(R.string.timeline_web_shield_started),
            detail = getString(R.string.timeline_web_shield_started_detail),
            dedupeKey = "web-shield:started"
        )
        mainHandler.removeCallbacks(heartbeat)
        mainHandler.postDelayed(heartbeat, HEARTBEAT_MS)
        worker = Thread({ packetLoop(descriptor) }, "AmanLocalDnsShield").also { it.start() }
    }

    private fun packetLoop(descriptor: ParcelFileDescriptor) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val output = FileOutputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(MAX_PACKET_SIZE)
        try {
            while (running.get()) {
                val length = input.read(buffer)
                if (length <= 0) continue
                val query = DnsPacketCodec.parseIpv4UdpDns(buffer, length) ?: continue
                if (query.destinationPort != DNS_PORT || query.destinationAddress.hostAddress != VPN_DNS_ADDRESS) continue
                val host = query.host
                val blocked = host != null && isBlockedHost(host)
                val dnsResponse = when {
                    blocked -> DnsPacketCodec.nxdomainResponse(query.dnsPayload)
                    else -> forwardDns(query.dnsPayload) ?: DnsPacketCodec.servFailResponse(query.dnsPayload)
                }
                output.write(DnsPacketCodec.buildIpv4UdpResponse(query, dnsResponse))
                if (blocked && host != null) recordBlockedHost(host)
                preferences.localWebShieldHeartbeatAt = System.currentTimeMillis()
            }
        } catch (_: Exception) {
            // Service lifecycle or interface revocation closes the descriptor; restart is handled by UI/boot.
        } finally {
            runCatching { input.close() }
            runCatching { output.close() }
        }
    }

    private fun forwardDns(payload: ByteArray): ByteArray? {
        var server = upstreamDns ?: selectUnderlyingDns()?.also { upstreamDns = it } ?: return null
        forwardDnsUdp(payload, server)?.let { return it }
        // Wi-Fi/cellular transitions can invalidate the resolver captured at VPN startup.
        val refreshed = selectUnderlyingDns() ?: return null
        upstreamDns = refreshed
        if (refreshed == server) return null
        server = refreshed
        return forwardDnsUdp(payload, server)
    }

    private fun forwardDnsUdp(payload: ByteArray, server: InetAddress): ByteArray? = runCatching {
        DatagramSocket().use { socket ->
            if (!protect(socket)) return null
            socket.soTimeout = DNS_TIMEOUT_MS
            socket.send(DatagramPacket(payload, payload.size, server, DNS_PORT))
            val response = ByteArray(MAX_DNS_SIZE)
            val packet = DatagramPacket(response, response.size)
            socket.receive(packet)
            val result = response.copyOf(packet.length)
            if (isTruncatedDns(result)) forwardDnsTcp(payload, server) ?: result else result
        }
    }.getOrNull()

    private fun forwardDnsTcp(payload: ByteArray, server: InetAddress): ByteArray? = runCatching {
        Socket().use { socket ->
            if (!protect(socket)) return null
            socket.soTimeout = DNS_TIMEOUT_MS
            socket.connect(java.net.InetSocketAddress(server, DNS_PORT), DNS_TIMEOUT_MS)
            val output = DataOutputStream(socket.getOutputStream())
            output.writeShort(payload.size)
            output.write(payload)
            output.flush()
            val input = DataInputStream(socket.getInputStream())
            val size = input.readUnsignedShort()
            if (size <= 0 || size > MAX_DNS_SIZE) return null
            ByteArray(size).also { input.readFully(it) }
        }
    }.getOrNull()

    private fun isTruncatedDns(payload: ByteArray): Boolean = payload.size >= 4 &&
        (payload[2].toInt() and 0x02) != 0

    private fun refreshThreatIntelIfNeeded(force: Boolean = false) {
        val newest = runCatching { database.autonomousStore.info().lastSuccessfulUpdateEpochMs }.getOrDefault(0L)
        if (!force && (newest <= 0L || newest == lastIntelUpdateAt)) return
        database.reloadAutonomous()
        lastIntelUpdateAt = newest
        synchronized(verdictCache) { verdictCache.clear() }
    }

    private fun isBlockedHost(host: String): Boolean {
        val normalized = host.trim().trimEnd('.').lowercase()
        val now = System.currentTimeMillis()
        synchronized(verdictCache) {
            verdictCache[normalized]?.takeIf { now - it.checkedAt <= VERDICT_CACHE_TTL_MS }?.let {
                return it.blocked
            }
        }
        val blocked = WebProtectionPolicy.decide(
            scanner.scan("https://$normalized/").riskLevel
        ) == WebProtectionDecision.BLOCK
        synchronized(verdictCache) { verdictCache[normalized] = CachedVerdict(blocked, now) }
        return blocked
    }

    private fun recordBlockedHost(host: String) {
        val now = System.currentTimeMillis()
        val duplicate = preferences.lastWebBlockedHost == host && now - preferences.lastWebBlockedAt < BLOCK_DEDUPE_MS
        preferences.lastWebBlockedHost = host
        preferences.lastWebBlockedAt = now
        preferences.totalWebThreatsBlocked += 1L
        preferences.markActivity(getString(R.string.activity_web_threat_blocked, host))
        if (duplicate) return
        activityStore.add(
            kind = ProtectionActivityKind.WEB_SHIELD,
            state = ProtectionActivityState.THREAT,
            title = getString(R.string.timeline_web_threat_blocked, host),
            detail = getString(R.string.timeline_web_threat_blocked_detail)
        )
        ProtectionNotifier.notifyWebThreatBlocked(this, host)
    }

    private fun selectUnderlyingDns(): InetAddress? {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return null
        val networks = manager.allNetworks.toList()
        val network = networks.firstOrNull { candidate ->
            val capabilities = manager.getNetworkCapabilities(candidate)
            capabilities != null && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        } ?: manager.activeNetwork
        return manager.getLinkProperties(network)?.dnsServers
            ?.firstOrNull { !it.isLoopbackAddress && it.hostAddress != VPN_DNS_ADDRESS }
    }

    private fun detectUnderlyingPrivateDns(): Boolean {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return false
        return manager.allNetworks.any { network ->
            val caps = manager.getNetworkCapabilities(network) ?: return@any false
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@any false
            runCatching { PrivateDnsCompat.isActive(manager.getLinkProperties(network)) }.getOrDefault(false)
        }
    }

    private fun stopShield() {
        if (!running.getAndSet(false) && tunnel == null) return
        mainHandler.removeCallbacksAndMessages(null)
        preferences.localWebShieldHeartbeatAt = 0L
        runCatching { tunnel?.close() }
        tunnel = null
        worker?.interrupt()
        worker = null
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private data class CachedVerdict(val blocked: Boolean, val checkedAt: Long)

    companion object {
        const val ACTION_START = "com.aman.security.action.START_LOCAL_WEB_SHIELD"
        const val ACTION_STOP = "com.aman.security.action.STOP_LOCAL_WEB_SHIELD"
        const val ACTION_REFRESH = "com.aman.security.action.REFRESH_LOCAL_WEB_SHIELD"
        private const val VPN_ADDRESS = "10.73.0.1"
        private const val VPN_DNS_ADDRESS = "10.73.0.2"
        private const val DNS_PORT = 53
        private const val DNS_TIMEOUT_MS = 2500
        private const val MAX_PACKET_SIZE = 32767
        private const val MAX_DNS_SIZE = 8192
        private const val HEARTBEAT_MS = 10 * 60_000L
        private const val BLOCK_DEDUPE_MS = 60_000L
        private const val VERDICT_CACHE_TTL_MS = 5 * 60_000L
        private const val VERDICT_CACHE_MAX = 512
    }
}

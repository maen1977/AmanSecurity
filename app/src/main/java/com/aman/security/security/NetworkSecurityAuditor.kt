package com.aman.security.security

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

class NetworkSecurityAuditor(private val context: Context) {
    fun audit(): NetworkSecurityAudit {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val active = manager?.activeNetwork
        val capabilities = if (manager != null && active != null) manager.getNetworkCapabilities(active) else null
        val linkProperties = if (manager != null && active != null) manager.getLinkProperties(active) else null
        val connected = active != null && capabilities != null
        val validated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        val captivePortal = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true
        val vpnActive = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val privateDnsActive = PrivateDnsCompat.isActive(linkProperties)
        val metered = manager?.isActiveNetworkMetered == true
        val transport = when {
            capabilities == null -> NetworkTransportType.NONE
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> NetworkTransportType.VPN
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkTransportType.WIFI
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkTransportType.CELLULAR
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkTransportType.ETHERNET
            else -> NetworkTransportType.OTHER
        }
        val findings = buildList {
            if (captivePortal) add(SecurityAuditFinding("captive_portal", SecurityAuditSeverity.WARNING))
            if (connected && !validated && !captivePortal) {
                add(SecurityAuditFinding("network_unvalidated", SecurityAuditSeverity.WARNING))
            }
            if (connected && !privateDnsActive) add(SecurityAuditFinding("private_dns_optional", SecurityAuditSeverity.INFO))
        }
        return NetworkSecurityAudit(
            connected = connected,
            validated = validated,
            captivePortal = captivePortal,
            vpnActive = vpnActive,
            privateDnsActive = privateDnsActive,
            metered = metered,
            transport = transport,
            findings = findings
        )
    }
}

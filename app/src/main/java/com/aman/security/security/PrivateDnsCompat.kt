package com.aman.security.security

import android.annotation.TargetApi
import android.net.LinkProperties
import android.os.Build

/**
 * API-safe access to Android Private DNS state while Aman continues to support API 26+.
 * Keep newer LinkProperties APIs isolated here so release lint and older devices remain safe.
 */
object PrivateDnsCompat {
    fun isActive(linkProperties: LinkProperties?): Boolean {
        if (linkProperties == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false
        return isActiveApi28(linkProperties)
    }

    @TargetApi(Build.VERSION_CODES.P)
    private fun isActiveApi28(linkProperties: LinkProperties): Boolean =
        linkProperties.isPrivateDnsActive
}

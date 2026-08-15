package com.aman.security.web

import android.content.Intent

/**
 * Defines what evidence is strong enough to mark the browser-role interception test as passed.
 * Sharing or processing text proves scanning only; ACTION_VIEW proves Android routed a normal
 * external web link through Link Guard.
 */
object WebGuardEvidencePolicy {
    fun provesExternalLinkInterception(action: String?): Boolean = action == Intent.ACTION_VIEW
}

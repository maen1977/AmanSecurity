package com.aman.security.security

import android.content.Context
import com.aman.security.R

fun Context.privilegedAccessLabel(kind: PrivilegedAccessKind): String = getString(
    when (kind) {
        PrivilegedAccessKind.ACCESSIBILITY -> R.string.privilege_accessibility
        PrivilegedAccessKind.NOTIFICATION_LISTENER -> R.string.privilege_notification_listener
        PrivilegedAccessKind.DEVICE_ADMIN -> R.string.privilege_device_admin
        PrivilegedAccessKind.OVERLAY -> R.string.privilege_overlay
    }
)

fun Context.integrityChangeLabel(kind: IntegrityChangeKind): String = getString(
    when (kind) {
        IntegrityChangeKind.ROOT_SIGNAL_ADDED -> R.string.integrity_root_added
        IntegrityChangeKind.ADB_ENABLED -> R.string.integrity_adb_enabled
        IntegrityChangeKind.DEVELOPER_OPTIONS_ENABLED -> R.string.integrity_developer_options_enabled
        IntegrityChangeKind.SCREEN_LOCK_DISABLED -> R.string.integrity_screen_lock_disabled
    }
)

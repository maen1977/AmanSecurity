package com.aman.security.web

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri

object BrowserForwarder {
    fun openExternal(context: Context, normalizedUrl: String, chooserTitle: String): Boolean {
        val uri = runCatching { Uri.parse(normalizedUrl) }.getOrNull() ?: return false
        if (uri.scheme != "http" && uri.scheme != "https") return false

        val base = Intent(Intent.ACTION_VIEW, uri).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        val genericWeb = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com/")).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
        }
        val genericHandlers = context.packageManager.queryIntentActivities(genericWeb, 0)
            .map { it.activityInfo.packageName to it.activityInfo.name }
            .toSet()

        val candidates = context.packageManager.queryIntentActivities(base, 0)
            .asSequence()
            .filter { it.activityInfo.packageName != context.packageName }
            .filter { (it.activityInfo.packageName to it.activityInfo.name) in genericHandlers }
            .distinctBy { it.activityInfo.packageName to it.activityInfo.name }
            .map { resolveInfo ->
                Intent(base).apply {
                    component = ComponentName(resolveInfo.activityInfo.packageName, resolveInfo.activityInfo.name)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            }
            .toList()

        if (candidates.isEmpty()) return false
        val chooser = Intent.createChooser(candidates.first(), chooserTitle).apply {
            if (candidates.size > 1) {
                putExtra(Intent.EXTRA_INITIAL_INTENTS, candidates.drop(1).toTypedArray())
            }
        }
        context.startActivity(chooser)
        return true
    }
}

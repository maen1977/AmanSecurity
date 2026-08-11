package com.aman.security

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.aman.security.databinding.ActivityPrivacyControlBinding
import com.aman.security.security.PrivacyAppExposure
import com.aman.security.security.PrivacyPermissionAuditor
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.NumberFormat

class PrivacyControlActivity : AppCompatActivity() {
    private lateinit var binding: ActivityPrivacyControlBinding
    private val auditor by lazy { PrivacyPermissionAuditor(applicationContext) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPrivacyControlBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.btnRefreshPrivacyControl.setOnClickListener { refresh() }
        refresh()
    }

    private fun refresh() {
        binding.btnRefreshPrivacyControl.isEnabled = false
        binding.txtPrivacyControlSummary.setText(R.string.privacy_control_loading)
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) { runCatching { auditor.appsForReview() } }
            binding.btnRefreshPrivacyControl.isEnabled = true
            outcome.onSuccess(::renderApps).onFailure {
                binding.txtPrivacyControlSummary.setText(R.string.operation_failed_try_again)
            }
        }
    }

    private fun renderApps(apps: List<PrivacyAppExposure>) {
        val formatter = NumberFormat.getIntegerInstance()
        binding.txtPrivacyControlSummary.text = if (apps.isEmpty()) {
            getString(R.string.privacy_control_none)
        } else {
            getString(R.string.privacy_control_summary, formatter.format(apps.size))
        }
        binding.privacyAppsContainer.removeAllViews()
        apps.take(MAX_VISIBLE_APPS).forEach { app ->
            binding.privacyAppsContainer.addView(createAppCard(app))
        }
        val hidden = apps.size - MAX_VISIBLE_APPS
        if (hidden > 0) {
            binding.privacyAppsContainer.addView(TextView(this).apply {
                text = getString(R.string.privacy_control_more, formatter.format(hidden))
                setTextColor(getColor(R.color.text_secondary))
                textSize = 12f
                setPadding(0, dp(12), 0, 0)
            })
        }
    }

    private fun createAppCard(app: PrivacyAppExposure): MaterialCardView = MaterialCardView(this).apply {
        radius = dp(20).toFloat()
        cardElevation = dp(1).toFloat()
        setCardBackgroundColor(getColor(R.color.surface_card))
        val params = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        params.bottomMargin = dp(10)
        layoutParams = params
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(14))
            addView(TextView(context).apply {
                text = app.appName
                setTextColor(getColor(R.color.text_primary))
                textSize = 16f
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            })
            addView(TextView(context).apply {
                text = getString(
                    R.string.privacy_control_permission_count,
                    NumberFormat.getIntegerInstance().format(app.grantedSensitivePermissions)
                )
                setTextColor(getColor(R.color.text_secondary))
                textSize = 12f
                setPadding(0, dp(4), 0, 0)
            })
            addView(MaterialButton(context).apply {
                setText(R.string.privacy_control_manage)
                setOnClickListener { openAppSettings(app.packageName) }
                val buttonParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                buttonParams.topMargin = dp(8)
                layoutParams = buttonParams
            })
        })
    }

    private fun openAppSettings(packageName: String) {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))
        runCatching { startActivity(intent) }
            .onFailure { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val MAX_VISIBLE_APPS = 80
    }
}

package com.aman.security

import android.net.Uri
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.lifecycleScope
import com.aman.security.databinding.ActivityMainBinding
import com.aman.security.scanner.FileScanner
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
        updater = ThreatDatabaseUpdater(this, database)
        renderDatabaseInfo()

        binding.btnChooseFile.setOnClickListener { filePicker.launch(arrayOf("*/*")) }
        binding.btnScanFile.setOnClickListener { scanSelectedFile() }
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
            result.classification == ScanClassification.TEST_SIGNATURE -> R.string.reason_signature_match
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
}

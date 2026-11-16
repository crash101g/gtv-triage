package com.crash101g.gtvtriage.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.core.content.FileProvider
import com.crash101g.gtvtriage.core.ReportFormatter
import com.crash101g.gtvtriage.core.TriageReport
import java.io.File

/**
 * Export / share the triage report. On a TV there may be no share targets at all,
 * so this degrades gracefully:
 *   1. Write the report to a file and fire ACTION_SEND with it attached (+ the text
 *      inline) via a FileProvider content:// URI.
 *   2. If nothing can handle the share (common on bare TVs), copy the report to the
 *      clipboard and also drop a copy in external files so it can be pulled over ADB.
 */
object ReportShare {

    fun share(context: Context, report: TriageReport) {
        val text = ReportFormatter.toText(report)
        val name = ReportFormatter.fileName()

        val uri = runCatching {
            val dir = File(context.cacheDir, "reports").apply { mkdirs() }
            val file = File(dir, name)
            file.writeText(text)
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        }.getOrNull()

        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "GTV triage report — ${report.deviceLabel}")
            putExtra(Intent.EXTRA_TEXT, text)
            if (uri != null) {
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

        try {
            context.startActivity(
                Intent.createChooser(send, "Share triage report")
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        } catch (e: ActivityNotFoundException) {
            fallback(context, report, text, name)
        }
    }

    private fun fallback(context: Context, report: TriageReport, text: String, name: String) {
        // Clipboard: lets the user paste it somewhere if an app is open.
        runCatching {
            val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            cb?.setPrimaryClip(ClipData.newPlainText("GTV triage report", text))
        }
        // External files dir: readable over `adb pull` without root.
        val saved = runCatching {
            val dir = context.getExternalFilesDir(null) ?: context.filesDir
            File(dir, name).apply { writeText(text) }.absolutePath
        }.getOrNull()

        val msg = if (saved != null) {
            "No share target. Copied to clipboard and saved:\n$saved"
        } else {
            "No share target. Report copied to clipboard."
        }
        Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
    }
}

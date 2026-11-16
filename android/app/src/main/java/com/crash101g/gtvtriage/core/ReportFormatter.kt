package com.crash101g.gtvtriage.core

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Renders a [TriageReport] as a plain-text report for export/sharing — the
 * on-device analogue of gtv-triage.py's summary.txt. Deterministic and self-
 * contained so it can be dropped into an email, a note, or a ticket.
 */
object ReportFormatter {

    fun toText(report: TriageReport): String = buildString {
        val now = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        line("================================================================")
        line(" GTV Sideload Checker — on-device triage report")
        line(" generated: $now")
        line("================================================================")
        blank()

        line("DEVICE : ${report.deviceLabel}")
        if (report.fireOs) line("         [Fire OS — Amazon Appstore treated as a trusted store]")
        line("SCORE  : ${report.score}/100   grade ${report.grade}")
        line("VERDICT: ${report.verdict}")
        line(
            "APPS   : ${report.apps.size} total · ${report.sideloadedApps.size} sideloaded · " +
                "${report.iocFlaggedApps.size} IOC · ${report.yaraFlaggedApps.size} YARA",
        )
        blank()

        section("FINDINGS")
        if (report.findings.isEmpty()) {
            line("  (none)")
        } else {
            report.findings
                .sortedBy { it.severity.ordinal }
                .forEach { line("  [${it.severity.name.padEnd(8)}] ${it.message}") }
        }
        blank()

        section("FIRMWARE INTEGRITY (non-root, best-effort)")
        report.firmware.forEach {
            val mark = if (it.ok) "ok " else "!! "
            line("  $mark ${it.key} = ${it.value}  (expected ${it.expected})")
        }
        blank()

        section("PERSISTENCE (non-root view)")
        val p = report.persistence
        line("  boot receivers      : ${p.bootReceiverTotal} total, ${p.thirdPartyBootReceivers.size} third-party")
        line("  accessibility svcs  : ${listOrNone(p.accessibility.map { it.component })}")
        line("  device admins       : ${listOrNone(p.deviceAdmins.map { it.component })}")
        line("  notification listen : ${listOrNone(p.notificationListeners.map { it.component })}")
        line("  input methods       : ${listOrNone(p.inputMethods.map { it.component + if (it.isDefault) " (default)" else "" })}")
        blank()

        section("SIDELOADED / FLAGGED APPS")
        val notable = report.apps.filter { it.sideloaded || it.iocHits.isNotEmpty() || it.yaraHits.isNotEmpty() }
        if (notable.isEmpty()) {
            line("  (no sideloaded or flagged apps)")
        } else {
            notable.forEach { app ->
                val tags = buildList {
                    if (app.yaraHits.isNotEmpty()) add("YARA")
                    if (app.iocHits.isNotEmpty()) add("IOC")
                    if (app.sideloaded) add("sideloaded")
                }.joinToString(",")
                line("  • ${app.label}  [$tags]")
                line("      package  : ${app.packageName}")
                app.installer?.let { line("      installer: $it") }
                app.sha256?.let { line("      sha256   : $it") }
                app.virusTotalUrl?.let { line("      virustotal: $it") }
                if (app.yaraHits.isNotEmpty()) line("      YARA     : ${app.yaraHits.joinToString(", ")}")
                if (app.iocHits.isNotEmpty()) line("      IOC      : ${app.iocHits.joinToString(", ")}")
            }
        }
        blank()

        line("----------------------------------------------------------------")
        line("Non-root triage: a clean result means \"nothing visible from here,\"")
        line("not a guarantee. Treat findings as leads for a human analyst.")
        line("Tool: https://github.com/crash101g/gtv-triage")
    }

    /** A filesystem-safe name like gtv-report-20261116-143001.txt */
    fun fileName(): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        return "gtv-report-$stamp.txt"
    }

    private fun StringBuilder.line(s: String) = append(s).append('\n')
    private fun StringBuilder.blank() = append('\n')
    private fun StringBuilder.section(title: String) {
        line("── $title ──")
    }

    private fun listOrNone(items: List<String>): String =
        if (items.isEmpty()) "none" else items.joinToString("; ")
}

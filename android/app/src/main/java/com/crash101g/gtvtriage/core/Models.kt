package com.crash101g.gtvtriage.core

/**
 * Severity levels carry the same weights/caps as the Python triage scorer
 * (gtv-triage.py): a per-severity weight plus a cap on how much any one severity
 * class can contribute, so e.g. dozens of LOW hygiene items can't masquerade as a
 * compromise.
 */
enum class Severity(val weight: Int, val cap: Int) {
    CRITICAL(100, 1_000_000),
    HIGH(30, 180),
    MEDIUM(10, 40),
    LOW(3, 15),
}

data class Finding(val severity: Severity, val message: String)

/** One installed application and everything we could determine about it on-device. */
data class AppEntry(
    val packageName: String,
    val label: String,
    val sourceDir: String?,
    val installer: String?,
    val isSystem: Boolean,
    val sideloaded: Boolean,
    val sha256: String?,
    val iocHits: List<String> = emptyList(),
) {
    /** VirusTotal GUI link — works in any browser, no API key needed. */
    val virusTotalUrl: String?
        get() = sha256?.let { "https://www.virustotal.com/gui/file/$it" }
}

data class FirmwareCheck(
    val key: String,
    val value: String,
    val expected: String,
    val ok: Boolean,
)

data class TriageReport(
    val deviceLabel: String,
    val fireOs: Boolean,
    val firmware: List<FirmwareCheck>,
    val apps: List<AppEntry>,
    val findings: List<Finding>,
    val score: Int,
    val grade: String,
    val verdict: String,
) {
    val sideloadedApps: List<AppEntry> get() = apps.filter { it.sideloaded }
    val iocFlaggedApps: List<AppEntry> get() = apps.filter { it.iocHits.isNotEmpty() }
}

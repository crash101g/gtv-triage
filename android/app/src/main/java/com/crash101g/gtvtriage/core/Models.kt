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
    val yaraHits: List<String> = emptyList(),
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

/** A persistence / auto-start foothold visible to a sandboxed app. */
enum class PersistenceKind(val label: String) {
    BOOT_RECEIVER("boot receiver"),
    ACCESSIBILITY("accessibility service"),
    NOTIFICATION_LISTENER("notification listener"),
    DEVICE_ADMIN("device admin"),
    INPUT_METHOD("input method"),
}

data class PersistenceItem(
    val kind: PersistenceKind,
    /** Flattened ComponentName (pkg/cls) or bare package. */
    val component: String,
    val owningPackage: String,
    /** True when the owning package is NOT a system/preinstalled app. */
    val thirdParty: Boolean,
    /** True for an enabled IME that is also the current default. */
    val isDefault: Boolean = false,
)

/**
 * The persistence-lite readout: auto-start and privileged-listener footholds a
 * non-root app can enumerate. Mirrors the ADB tool's "== Persistence ==" section,
 * minus native init services (root-only).
 */
data class PersistenceReport(
    val items: List<PersistenceItem>,
    val bootReceiverTotal: Int,
    val lockedBootReceiverTotal: Int,
    val defaultIme: String?,
) {
    fun of(kind: PersistenceKind): List<PersistenceItem> = items.filter { it.kind == kind }
    val thirdPartyBootReceivers: List<PersistenceItem>
        get() = of(PersistenceKind.BOOT_RECEIVER).filter { it.thirdParty }
    val accessibility: List<PersistenceItem> get() = of(PersistenceKind.ACCESSIBILITY)
    val deviceAdmins: List<PersistenceItem> get() = of(PersistenceKind.DEVICE_ADMIN)
    val notificationListeners: List<PersistenceItem> get() = of(PersistenceKind.NOTIFICATION_LISTENER)
    val inputMethods: List<PersistenceItem> get() = of(PersistenceKind.INPUT_METHOD)
}

data class TriageReport(
    val deviceLabel: String,
    val fireOs: Boolean,
    val firmware: List<FirmwareCheck>,
    val apps: List<AppEntry>,
    val persistence: PersistenceReport,
    val findings: List<Finding>,
    val score: Int,
    val grade: String,
    val verdict: String,
) {
    val sideloadedApps: List<AppEntry> get() = apps.filter { it.sideloaded }
    val iocFlaggedApps: List<AppEntry> get() = apps.filter { it.iocHits.isNotEmpty() }
    val yaraFlaggedApps: List<AppEntry> get() = apps.filter { it.yaraHits.isNotEmpty() }
}

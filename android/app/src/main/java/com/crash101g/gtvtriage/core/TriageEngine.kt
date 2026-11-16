package com.crash101g.gtvtriage.core

import android.content.Context
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Runs the full on-device triage: inventory -> installer classification (Fire OS
 * aware) -> APK hashing -> IOC matching -> firmware checks -> severity-gated score.
 *
 * This is the "plain sideload-vetting" tier: everything here works in a normal
 * sandboxed app with QUERY_ALL_PACKAGES. The process/socket/dumpsys depth of the
 * ADB tool needs Shizuku or root and is intentionally out of scope for this tier.
 */
class TriageEngine(private val context: Context) {

    suspend fun run(): TriageReport = withContext(Dispatchers.Default) {
        val fireOs = InstallerClassifier.isFireOs()
        val ioc = IocMatcher.fromAsset(context)

        val rawApps = PackageInventory(context).collect()
        val systemPackages = rawApps.filter { it.isSystem }.map { it.packageName }.toSet()

        val apps = rawApps.map { raw ->
            val sideloaded = !raw.isSystem &&
                !InstallerClassifier.isStoreInstaller(raw.installer, fireOs)
            // Hash third-party apps (sideloaded first-class, store apps for reference).
            val sha = if (!raw.isSystem) ApkHasher.sha256(raw.sourceDir) else null
            val hits = ioc.match(raw.packageName, raw.installer, raw.sourceDir)
            AppEntry(
                packageName = raw.packageName,
                label = raw.label,
                sourceDir = raw.sourceDir,
                installer = raw.installer,
                isSystem = raw.isSystem,
                sideloaded = sideloaded,
                sha256 = sha,
                iocHits = hits,
            )
        }.sortedWith(
            compareByDescending<AppEntry> { it.iocHits.isNotEmpty() }
                .thenByDescending { it.sideloaded }
                .thenBy { it.label.lowercase() },
        )

        val firmware = FirmwareIntegrity.checks()
        val persistence = PersistenceSweep(context, systemPackages).run()

        val findings = buildFindings(firmware, apps, persistence, fireOs)
        val scored = Scoring.score(findings)

        val label = "${Build.MANUFACTURER} ${Build.MODEL}" +
            if (fireOs) "  [Fire OS]" else ""

        TriageReport(
            deviceLabel = label,
            fireOs = fireOs,
            firmware = firmware,
            apps = apps,
            persistence = persistence,
            findings = findings,
            score = scored.score,
            grade = scored.grade,
            verdict = scored.verdict,
        )
    }

    private fun buildFindings(
        firmware: List<FirmwareCheck>,
        apps: List<AppEntry>,
        persistence: PersistenceReport,
        fireOs: Boolean,
    ): List<Finding> {
        val findings = mutableListOf<Finding>()

        for (fw in firmware) {
            if (!fw.ok) {
                // test-keys is a stronger signal than a single unexpected prop.
                val sev = if (fw.key.contains("test-keys")) Severity.MEDIUM else Severity.MEDIUM
                findings += Finding(sev, "firmware: ${fw.key}=${fw.value} (expected ${fw.expected})")
            }
        }

        val sideLabel = if (fireOs) "sideloaded (not from Appstore/Play)" else "sideloaded / non-Play"
        for (app in apps.filter { it.sideloaded }) {
            findings += Finding(Severity.LOW, "$sideLabel app: ${app.packageName}")
        }

        for (app in apps) {
            for (hit in app.iocHits) {
                findings += Finding(Severity.HIGH, "IOC '$hit' matched ${app.packageName}")
            }
        }

        // Persistence findings — same severities as the ADB tool's scorer.
        // Accessibility + device admin are genuine high-value footholds; third-party
        // boot receivers are ubiquitous on media boxes, so they score as a single
        // low-weight attack-surface note, not per-item.
        for (svc in persistence.accessibility) {
            findings += Finding(Severity.HIGH, "accessibility service enabled: ${svc.component}")
        }
        for (admin in persistence.deviceAdmins) {
            findings += Finding(Severity.HIGH, "device admin / policy component: ${admin.component}")
        }
        val tpBoot = persistence.thirdPartyBootReceivers.size
        if (tpBoot > 0) {
            findings += Finding(Severity.LOW, "$tpBoot third-party boot receiver(s) (normal for media apps)")
        }
        // A sideloaded IME can keylog everything typed on the TV — worth a MEDIUM
        // review flag (the ADB tool records it as a note; on-device we surface it).
        for (ime in persistence.inputMethods.filter { it.thirdParty }) {
            findings += Finding(Severity.MEDIUM, "third-party input method enabled: ${ime.component}")
        }
        return findings
    }
}

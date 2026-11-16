package com.crash101g.gtvtriage.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

/** Raw package data straight from PackageManager, before classification/hashing. */
data class RawApp(
    val packageName: String,
    val label: String,
    val sourceDir: String?,
    val installer: String?,
    val isSystem: Boolean,
)

/**
 * Enumerates installed packages via PackageManager. Requires the QUERY_ALL_PACKAGES
 * permission on Android 11+ to see packages beyond this app's own visibility.
 */
class PackageInventory(private val context: Context) {

    fun collect(): List<RawApp> {
        val pm = context.packageManager
        val self = context.packageName
        val packages = pm.getInstalledPackages(0)
        return packages.asSequence()
            // Never triage ourselves: this app bundles the YARA rules and IOC feed as
            // assets, so scanning its own APK would match every indicator and self-
            // report as "malicious". The checker is not a subject of the scan.
            .filter { it.packageName != self }
            .map { pi ->
            val ai: ApplicationInfo? = pi.applicationInfo
            val isSystem = ai != null && (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            RawApp(
                packageName = pi.packageName,
                label = ai?.let { pm.getApplicationLabel(it).toString() } ?: pi.packageName,
                sourceDir = ai?.publicSourceDir,
                installer = installerOf(pm, pi.packageName),
                isSystem = isSystem,
            )
        }.toList()
    }

    private fun installerOf(pm: PackageManager, pkg: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(pkg)
        }
    } catch (e: Exception) {
        null
    }
}

package com.crash101g.gtvtriage.core

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings

/**
 * Persistence-lite readout: the auto-start and privileged-listener footholds a
 * non-root, sandboxed app can still enumerate on Android TV / Google TV / Fire TV.
 *
 * This mirrors the ADB tool's "== Persistence ==" section as far as the app
 * sandbox allows:
 *   - BOOT_COMPLETED / LOCKED_BOOT_COMPLETED receivers   (PackageManager query)
 *   - enabled accessibility services                     (Settings.Secure)
 *   - enabled notification listeners                     (Settings.Secure)
 *   - active device-admin / device-policy components     (DevicePolicyManager)
 *   - enabled input methods (IMEs) + the current default (Settings.Secure)
 *
 * Native init services and job/alarm dumps from `dumpsys` are NOT here — they need
 * the shell uid or root and live in the ADB tool (or a future Shizuku mode).
 *
 * @param systemPackages package names flagged FLAG_SYSTEM by the inventory, used to
 *   split "third-party" footholds (the ones worth a look) from stock OS components.
 */
class PersistenceSweep(
    private val context: Context,
    private val systemPackages: Set<String>,
) {

    fun run(): PersistenceReport {
        val items = mutableListOf<PersistenceItem>()

        val (boot, locked) = bootReceivers(items)
        accessibilityServices(items)
        notificationListeners(items)
        deviceAdmins(items)
        val defaultIme = inputMethods(items)

        return PersistenceReport(
            items = items.sortedWith(
                compareByDescending<PersistenceItem> { it.thirdParty }
                    .thenBy { it.kind.ordinal }
                    .thenBy { it.component.lowercase() },
            ),
            bootReceiverTotal = boot,
            lockedBootReceiverTotal = locked,
            defaultIme = defaultIme,
        )
    }

    private fun pkgOf(component: String): String = component.substringBefore('/')

    private fun isThirdParty(pkg: String): Boolean =
        pkg.isNotEmpty() && pkg !in systemPackages

    /** Returns (total BOOT_COMPLETED receivers, total LOCKED_BOOT_COMPLETED receivers). */
    private fun bootReceivers(out: MutableList<PersistenceItem>): Pair<Int, Int> {
        val pm = context.packageManager
        val seen = HashSet<String>()

        fun queryAction(action: String): Int {
            val infos = try {
                pm.queryBroadcastReceivers(Intent(action), 0)
            } catch (e: Exception) {
                emptyList()
            }
            for (ri in infos) {
                val ai = ri.activityInfo ?: continue
                val comp = "${ai.packageName}/${ai.name}"
                if (!seen.add(comp)) continue
                out += PersistenceItem(
                    kind = PersistenceKind.BOOT_RECEIVER,
                    component = comp,
                    owningPackage = ai.packageName,
                    thirdParty = isThirdParty(ai.packageName),
                )
            }
            return infos.size
        }

        val boot = queryAction(Intent.ACTION_BOOT_COMPLETED)
        val locked = queryAction("android.intent.action.LOCKED_BOOT_COMPLETED")
        return boot to locked
    }

    private fun accessibilityServices(out: MutableList<PersistenceItem>) {
        secureList(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).forEach { comp ->
            out += PersistenceItem(
                kind = PersistenceKind.ACCESSIBILITY,
                component = comp,
                owningPackage = pkgOf(comp),
                thirdParty = isThirdParty(pkgOf(comp)),
            )
        }
    }

    private fun notificationListeners(out: MutableList<PersistenceItem>) {
        // No public constant pre-API 21 name; the key is stable across versions.
        secureList("enabled_notification_listeners").forEach { comp ->
            out += PersistenceItem(
                kind = PersistenceKind.NOTIFICATION_LISTENER,
                component = comp,
                owningPackage = pkgOf(comp),
                thirdParty = isThirdParty(pkgOf(comp)),
            )
        }
    }

    private fun deviceAdmins(out: MutableList<PersistenceItem>) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        val admins: List<ComponentName> = try {
            dpm?.activeAdmins ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
        for (cn in admins) {
            val comp = cn.flattenToString()
            out += PersistenceItem(
                kind = PersistenceKind.DEVICE_ADMIN,
                component = comp,
                owningPackage = cn.packageName,
                thirdParty = isThirdParty(cn.packageName),
            )
        }
    }

    /** Returns the default IME component string (or null). */
    private fun inputMethods(out: MutableList<PersistenceItem>): String? {
        val default = secureString(Settings.Secure.DEFAULT_INPUT_METHOD)
        val defaultPkg = default?.let { pkgOf(it) }
        // enabled_input_methods entries can carry ";subtype" suffixes — strip them.
        secureList(Settings.Secure.ENABLED_INPUT_METHODS).map { it.substringBefore(';') }
            .distinct()
            .forEach { comp ->
                val pkg = pkgOf(comp)
                out += PersistenceItem(
                    kind = PersistenceKind.INPUT_METHOD,
                    component = comp,
                    owningPackage = pkg,
                    thirdParty = isThirdParty(pkg),
                    isDefault = defaultPkg != null && pkg == defaultPkg,
                )
            }
        return default
    }

    private fun secureString(key: String): String? = try {
        Settings.Secure.getString(context.contentResolver, key)
            ?.takeIf { it.isNotBlank() && it != "null" }
    } catch (e: Exception) {
        null
    }

    /** Settings.Secure multi-value lists are ':'-separated component names. */
    private fun secureList(key: String): List<String> =
        secureString(key)?.split(':')?.map { it.trim() }?.filter { it.isNotEmpty() }
            ?: emptyList()
}

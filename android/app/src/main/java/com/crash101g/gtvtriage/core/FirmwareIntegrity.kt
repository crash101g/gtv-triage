package com.crash101g.gtvtriage.core

import android.annotation.SuppressLint
import android.os.Build
import java.io.File

/**
 * Best-effort firmware-integrity checks available to a non-privileged app. Build
 * fields are public API; ro.boot.* come from SystemProperties via reflection and
 * may be unavailable on some devices (reported only when readable). SELinux state
 * is read from the world-readable /sys/fs/selinux/enforce.
 *
 * NOTE: a sandboxed app sees less than the ADB `shell` user — treat a clean result
 * as "nothing visible from here," not proof. (Same caveat as the ADB tool, more so.)
 */
object FirmwareIntegrity {

    fun checks(): List<FirmwareCheck> {
        val out = mutableListOf<FirmwareCheck>()

        val tags = Build.TAGS ?: ""
        out += FirmwareCheck(
            "ro.build.tags", tags.ifEmpty { "(unset)" }, "release-keys",
            tags.contains("release-keys"),
        )

        val fp = Build.FINGERPRINT ?: ""
        val testKeys = fp.contains("test-keys")
        out += FirmwareCheck(
            "fingerprint test-keys", if (testKeys) "present" else "none", "none", !testKeys,
        )

        prop("ro.boot.verifiedbootstate")?.let {
            out += FirmwareCheck("ro.boot.verifiedbootstate", it, "green", it == "green")
        }
        prop("ro.boot.flash.locked")?.let {
            out += FirmwareCheck("ro.boot.flash.locked", it, "1", it == "1")
        }
        prop("ro.debuggable")?.let {
            out += FirmwareCheck("ro.debuggable", it, "0", it == "0")
        }
        prop("ro.secure")?.let {
            out += FirmwareCheck("ro.secure", it, "1", it == "1")
        }
        selinux()?.let {
            out += FirmwareCheck("SELinux", it, "Enforcing", it == "Enforcing")
        }
        return out
    }

    @SuppressLint("PrivateApi")
    private fun prop(key: String): String? = try {
        val clazz = Class.forName("android.os.SystemProperties")
        val get = clazz.getMethod("get", String::class.java)
        (get.invoke(null, key) as? String)?.takeIf { it.isNotEmpty() }
    } catch (e: Exception) {
        null
    }

    private fun selinux(): String? = try {
        when (File("/sys/fs/selinux/enforce").readText().trim()) {
            "1" -> "Enforcing"
            "0" -> "Permissive"
            else -> null
        }
    } catch (e: Exception) {
        null
    }
}

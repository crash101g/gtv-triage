package com.crash101g.gtvtriage.core

import java.io.File
import java.security.MessageDigest

/** SHA-256 of an APK file, matching the on-device hashing the ADB tool does. */
object ApkHasher {

    fun sha256(path: String?): String? {
        if (path.isNullOrEmpty()) return null
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            File(path).inputStream().use { input ->
                val buffer = ByteArray(1 shl 16)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    md.update(buffer, 0, n)
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            null // unreadable APK (permissions / path) — reported as UNREADABLE upstream
        }
    }
}

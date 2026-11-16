package com.crash101g.gtvtriage.core

import android.content.Context

/**
 * Local store for the optional VirusTotal API key. Kept in app-private
 * SharedPreferences (not world-readable); it never leaves the device except as the
 * `x-apikey` header on requests the user explicitly triggers.
 *
 * Note: SharedPreferences is private-but-plaintext. A future hardening step is
 * EncryptedSharedPreferences (androidx.security) — tracked in the roadmap.
 */
object ApiKeyStore {
    private const val PREFS = "gtv_prefs"
    private const val KEY_VT = "vt_api_key"

    fun get(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_VT, null)
            ?.trim()
            ?.takeIf { it.isNotEmpty() }

    fun set(context: Context, key: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY_VT, key.trim()).apply()
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().remove(KEY_VT).apply()
    }
}

package com.crash101g.gtvtriage.core

import android.os.Build

/**
 * Decides whether an app's installer counts as a trusted first-party store (so the
 * app is NOT "sideloaded"). Direct port of is_fireos() / is_store_installer() from
 * gtv-triage.py: Google Play everywhere, plus the Amazon Appstore / Amazon-signed
 * updaters on Fire OS (which has no Play Store).
 */
object InstallerClassifier {
    const val PLAY_INSTALLER = "com.android.vending"
    const val AMAZON_STORE_PREFIX = "com.amazon."

    /** True on Amazon Fire OS (a non-Google AOSP fork). */
    fun isFireOs(): Boolean {
        val mfr = (Build.MANUFACTURER ?: "").trim().lowercase()
        val brand = (Build.BRAND ?: "").trim().lowercase()
        val fingerprint = Build.FINGERPRINT ?: ""
        return mfr == "amazon" || brand.contains("amazon") || fingerprint.contains("/Amazon/")
    }

    fun isStoreInstaller(installer: String?, fireOs: Boolean): Boolean {
        if (installer.isNullOrEmpty()) return false
        if (installer == PLAY_INSTALLER) return true
        if (fireOs && installer.startsWith(AMAZON_STORE_PREFIX)) return true
        return false
    }
}

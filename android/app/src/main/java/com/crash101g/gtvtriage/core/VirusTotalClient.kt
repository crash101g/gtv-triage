package com.crash101g.gtvtriage.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Minimal VirusTotal API v3 client — looks up a file by its SHA-256 and returns the
 * last-analysis stats. Only the hash leaves the device (never a package list, serial,
 * or anything identifying); a file hash is exactly what VirusTotal is keyed on.
 *
 * Public API limits apply (≈4 req/min, 500/day), so the UI queries ON DEMAND for a
 * single app rather than enriching every hash automatically.
 */
object VirusTotalClient {

    sealed interface VtResult {
        data class Found(
            val malicious: Int,
            val suspicious: Int,
            val harmless: Int,
            val undetected: Int,
            val timeout: Int,
        ) : VtResult {
            val engines: Int get() = malicious + suspicious + harmless + undetected + timeout
            val flagged: Int get() = malicious + suspicious
        }
        data object NotFound : VtResult        // 404 — VT has never seen this hash
        data object Unauthorized : VtResult    // 401 — missing/invalid key
        data object RateLimited : VtResult     // 429 — quota exceeded
        data class Error(val message: String) : VtResult
    }

    suspend fun lookup(sha256: String, apiKey: String): VtResult = withContext(Dispatchers.IO) {
        var con: HttpsURLConnection? = null
        try {
            con = (URL("https://www.virustotal.com/api/v3/files/$sha256").openConnection()
                as HttpsURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("x-apikey", apiKey)
                setRequestProperty("Accept", "application/json")
                connectTimeout = 15_000
                readTimeout = 20_000
            }
            when (val code = con.responseCode) {
                200 -> parse(con.inputStream.bufferedReader().use { it.readText() })
                401 -> VtResult.Unauthorized
                404 -> VtResult.NotFound
                429 -> VtResult.RateLimited
                else -> VtResult.Error("HTTP $code")
            }
        } catch (e: Exception) {
            VtResult.Error(e.message ?: "network error")
        } finally {
            con?.disconnect()
        }
    }

    private fun parse(body: String): VtResult = try {
        val stats = JSONObject(body)
            .getJSONObject("data")
            .getJSONObject("attributes")
            .getJSONObject("last_analysis_stats")
        VtResult.Found(
            malicious = stats.optInt("malicious"),
            suspicious = stats.optInt("suspicious"),
            harmless = stats.optInt("harmless"),
            undetected = stats.optInt("undetected"),
            timeout = stats.optInt("timeout"),
        )
    } catch (e: Exception) {
        VtResult.Error("unexpected response")
    }
}

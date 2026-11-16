package com.crash101g.gtvtriage.core

/**
 * Severity-gated 0–100 score, ported from gtv-triage.py. Each severity contributes
 * weight per finding, capped per class; the verdict is GATED on severity so a device
 * with zero CRITICAL/HIGH findings can never read as "compromised" just because it
 * accumulated many LOW hygiene items.
 */
object Scoring {

    data class Result(val score: Int, val grade: String, val verdict: String)

    fun score(findings: List<Finding>): Result {
        val perClass = mutableMapOf<Severity, Int>()
        for (f in findings) {
            perClass[f.severity] = (perClass[f.severity] ?: 0) + f.severity.weight
        }
        var risk = 0
        for (sev in Severity.entries) {
            risk += minOf(perClass[sev] ?: 0, sev.cap)
        }
        val score = (100 - risk).coerceIn(0, 100)

        val hasCrit = findings.any { it.severity == Severity.CRITICAL }
        val hasHigh = findings.any { it.severity == Severity.HIGH }
        val hasMed = findings.any { it.severity == Severity.MEDIUM }

        val (grade, verdict) = when {
            hasCrit -> "F" to "MALICIOUS — known-bad indicator present"
            hasHigh -> when {
                score >= 70 -> "C" to "ELEVATED — highly-suspicious finding, review now"
                score >= 40 -> "D" to "HIGH RISK — multiple suspicious findings"
                else -> "E" to "SEVERE — multiple suspicious findings"
            }
            score >= 90 && !hasMed -> "A" to "CLEAN — no notable findings"
            score >= 70 -> "B" to "LOW–MODERATE — minor hygiene / sideloaded-app review"
            else -> "C" to "MODERATE — review findings"
        }
        return Result(score, grade, verdict)
    }
}

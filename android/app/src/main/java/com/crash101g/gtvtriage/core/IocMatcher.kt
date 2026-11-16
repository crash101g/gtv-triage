package com.crash101g.gtvtriage.core

import android.content.Context

/**
 * Case-insensitive substring IOC matcher — same semantics as gtv-triage.py's
 * matcher against the bundled gtv-iocs.txt (one indicator per line, '#' comments).
 */
class IocMatcher(indicators: List<String>) {

    private val needles: List<String> = indicators
        .map { it.substringBefore('#').trim().lowercase() }
        .filter { it.isNotEmpty() }
        .distinct()

    val size: Int get() = needles.size

    /** Returns the indicators that appear as a substring of any haystack. */
    fun match(vararg haystacks: String?): List<String> {
        val hay = haystacks.filterNotNull().joinToString("\n").lowercase()
        if (hay.isEmpty()) return emptyList()
        return needles.filter { hay.contains(it) }
    }

    companion object {
        fun fromAsset(context: Context, name: String = "gtv-iocs.txt"): IocMatcher {
            val lines = context.assets.open(name).bufferedReader().use { it.readLines() }
            return IocMatcher(lines)
        }
    }
}

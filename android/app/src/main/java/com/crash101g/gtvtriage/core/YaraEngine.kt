package com.crash101g.gtvtriage.core

import android.content.Context
import java.io.File
import java.util.zip.ZipFile

/**
 * A small, self-contained matcher for the *subset* of YARA that gtv-malware.yar
 * uses. It is NOT a full YARA engine — it supports exactly what these rules need:
 *
 *   - text strings:  $x = "literal" ascii [nocase]
 *   - condition ops: `and`, `or`, `not`, parentheses
 *   - string sets:   `any of (...)`, `all of (...)`, `N of (...)`, `of them`,
 *                    wildcard items like `$p*`, and mixed lists `($j*, $o*)`
 *   - presence:      a bare `$id`
 *   - counts:        `#id > N` (and >=, <, <=, ==, !=)
 *
 * Why not libyara? Full YARA means an NDK native build and shipping libyara.so per
 * ABI. These rules are pure string/path indicators with no modules, so a faithful
 * interpreter is far lighter and keeps the app pure-JVM. If the rules ever grow to
 * need real YARA features, swap this for a Shizuku-invoked `yara` or an NDK build.
 *
 * Scanning: APKs are ZIP archives, and the indicator strings live inside compressed
 * entries (classes.dex, lib/*.so, the manifest, resources). So we decompress each
 * entry and match against its bytes — scanning the raw .apk bytes would miss them.
 */
class YaraEngine private constructor(private val rules: List<YaraRule>) {

    companion object {
        private const val PER_ENTRY_CAP = 32 * 1024 * 1024        // 32 MiB / entry
        private const val TOTAL_CAP = 96L * 1024 * 1024           // 96 MiB / apk

        fun fromAsset(context: Context, name: String = "gtv-malware.yar"): YaraEngine {
            val text = context.assets.open(name).bufferedReader().use { it.readText() }
            return fromText(text)
        }

        fun fromText(text: String): YaraEngine = YaraEngine(YaraParser(text).parse())
    }

    /** @return the names of the rules that match this APK file (empty if none). */
    fun scanApk(path: String?): List<String> {
        val file = path?.let { File(it) } ?: return emptyList()
        if (!file.isFile) return emptyList()
        val counts = HashMap<String, Int>()
        val anyNocase = rules.any { r -> r.strings.any { it.nocase } }
        var scanned = 0L

        try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements() && scanned < TOTAL_CAP) {
                    val e = entries.nextElement()
                    if (e.isDirectory) continue
                    val bytes = zip.getInputStream(e).use { readBounded(it, PER_ENTRY_CAP) }
                    scanned += bytes.size
                    accumulate(bytes, anyNocase, counts)
                }
            }
        } catch (ex: Exception) {
            // Not a valid ZIP (or unreadable) — fall back to scanning raw bytes.
            try {
                val bytes = file.inputStream().use { readBounded(it, PER_ENTRY_CAP) }
                accumulate(bytes, anyNocase, counts)
            } catch (_: Exception) {
                return emptyList()
            }
        }

        return rules.filter { it.matches(counts) }.map { it.name }
    }

    private fun accumulate(bytes: ByteArray, anyNocase: Boolean, counts: HashMap<String, Int>) {
        // Latin-1 keeps a 1:1 byte<->char mapping, so binary content matches cleanly.
        val hay = String(bytes, Charsets.ISO_8859_1)
        val hayLower = if (anyNocase) hay.lowercase() else hay
        for (rule in rules) {
            for (s in rule.strings) {
                val h = if (s.nocase) hayLower else hay
                val n = if (s.nocase) s.literal.lowercase() else s.literal
                val c = countOcc(h, n)
                // Key by rule as well as id: YARA string ids are rule-scoped, so e.g.
                // $p1 in two rules must not share a count (would cause false matches).
                if (c > 0) {
                    val key = rule.key(s.id)
                    counts[key] = (counts[key] ?: 0) + c
                }
            }
        }
    }

    private fun countOcc(hay: String, needle: String): Int {
        if (needle.isEmpty()) return 0
        var i = hay.indexOf(needle)
        var c = 0
        while (i >= 0) {
            c++
            i = hay.indexOf(needle, i + needle.length)
        }
        return c
    }

    private fun readBounded(input: java.io.InputStream, cap: Int): ByteArray {
        val buf = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(64 * 1024)
        var total = 0
        while (total < cap) {
            val r = input.read(chunk)
            if (r < 0) break
            buf.write(chunk, 0, r)
            total += r
        }
        return buf.toByteArray()
    }
}

/** One parsed rule: its strings, its condition AST, and its family (from meta). */
class YaraRule(
    val name: String,
    val family: String,
    val strings: List<YaraString>,
    private val condition: Cond,
) {
    /** Rule-scoped key for a string id in the shared counts map. */
    fun key(id: String): String = "$name\u0000$id"

    fun matches(counts: Map<String, Int>): Boolean {
        // Restrict the global counts to this rule's own ids, then unprefix.
        val sub = HashMap<String, Int>(strings.size)
        for (s in strings) counts[key(s.id)]?.let { sub[s.id] = it }
        return condition.eval(sub)
    }
}

data class YaraString(val id: String, val literal: String, val nocase: Boolean)

/** Condition AST. Every node evaluates to a Boolean against a counts map. */
sealed interface Cond {
    fun eval(c: Map<String, Int>): Boolean

    class And(val a: Cond, val b: Cond) : Cond {
        override fun eval(c: Map<String, Int>) = a.eval(c) && b.eval(c)
    }
    class Or(val a: Cond, val b: Cond) : Cond {
        override fun eval(c: Map<String, Int>) = a.eval(c) || b.eval(c)
    }
    class Not(val a: Cond) : Cond {
        override fun eval(c: Map<String, Int>) = !a.eval(c)
    }
    /** A bare `$id` — present when it matched at least once. */
    class Present(val id: String) : Cond {
        override fun eval(c: Map<String, Int>) = (c[id] ?: 0) > 0
    }
    /** `#id OP n` — a count comparison. */
    class CountCmp(val id: String, val op: String, val n: Int) : Cond {
        override fun eval(c: Map<String, Int>): Boolean {
            val v = c[id] ?: 0
            return when (op) {
                ">" -> v > n; ">=" -> v >= n; "<" -> v < n
                "<=" -> v <= n; "==" -> v == n; "!=" -> v != n
                else -> false
            }
        }
    }
    /** `N of (set)` — at least [need] of the [ids] present. */
    class OfSet(val need: Int, val ids: List<String>) : Cond {
        override fun eval(c: Map<String, Int>) = ids.count { (c[it] ?: 0) > 0 } >= need
    }
}

/**
 * Hand-written recursive-descent parser for the YARA subset above. Tolerant: a rule
 * whose condition it can't parse is dropped (logged nowhere, just skipped) rather
 * than failing the whole scan.
 */
private class YaraParser(private val src: String) {

    fun parse(): List<YaraRule> {
        val rules = mutableListOf<YaraRule>()
        val ruleRegex = Regex("""rule\s+(\w+)\s*\{""")
        var m = ruleRegex.find(src)
        while (m != null) {
            val name = m.groupValues[1]
            val bodyStart = m.range.last + 1
            val bodyEnd = matchBrace(src, m.range.last)
            if (bodyEnd < 0) break
            val body = src.substring(bodyStart, bodyEnd)
            runCatching { parseRule(name, body) }.getOrNull()?.let { rules += it }
            m = ruleRegex.find(src, bodyEnd + 1)
        }
        return rules
    }

    /** Given the index of a `{`, return the index of its matching `}` (or -1). */
    private fun matchBrace(s: String, open: Int): Int {
        var depth = 0
        var i = open
        while (i < s.length) {
            when (s[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) return i }
            }
            i++
        }
        return -1
    }

    private fun parseRule(name: String, body: String): YaraRule {
        val family = Regex("""family\s*=\s*"([^"]*)"""").find(body)?.groupValues?.get(1) ?: ""
        val strings = parseStrings(body)
        val condText = sectionAfter(body, "condition:") ?: error("no condition")
        val ids = strings.map { it.id }
        val cond = CondParser(condText, ids).parse()
        return YaraRule(name, family, strings, cond)
    }

    /** Text of a `strings:`/`condition:` section up to the next section or end. */
    private fun sectionAfter(body: String, header: String): String? {
        val idx = body.indexOf(header)
        if (idx < 0) return null
        var rest = body.substring(idx + header.length)
        // Trim at the next known section header if one follows.
        for (h in listOf("condition:", "strings:", "meta:")) {
            val j = rest.indexOf(h)
            if (j > 0) rest = rest.substring(0, j)
        }
        return rest
    }

    private fun parseStrings(body: String): List<YaraString> {
        val section = sectionAfter(body, "strings:") ?: return emptyList()
        val out = mutableListOf<YaraString>()
        for (rawLine in section.lines()) {
            val line = rawLine.trim()
            if (!line.startsWith("$")) continue
            val eq = line.indexOf('=')
            if (eq < 0) continue
            val id = line.substring(1, eq).trim()
            if (id.isEmpty()) continue
            val (literal, afterQuote) = extractLiteral(line, eq + 1) ?: continue
            val mods = afterQuote.substringBefore("//")
            val nocase = Regex("""\bnocase\b""").containsMatchIn(mods)
            out += YaraString(id, literal, nocase)
        }
        return out
    }

    /** Reads the first "double-quoted" literal starting at/after [from]. */
    private fun extractLiteral(line: String, from: Int): Pair<String, String>? {
        val open = line.indexOf('"', from)
        if (open < 0) return null
        val sb = StringBuilder()
        var i = open + 1
        while (i < line.length) {
            val ch = line[i]
            if (ch == '\\' && i + 1 < line.length) {
                when (val next = line[i + 1]) {
                    'n' -> sb.append('\n'); 't' -> sb.append('\t')
                    'r' -> sb.append('\r'); '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    'x' -> {
                        if (i + 3 < line.length) {
                            val hex = line.substring(i + 2, i + 4)
                            hex.toIntOrNull(16)?.let { sb.append(it.toChar()) }
                            i += 2
                        }
                    }
                    else -> sb.append(next)
                }
                i += 2
            } else if (ch == '"') {
                return sb.toString() to line.substring(i + 1)
            } else {
                sb.append(ch)
                i++
            }
        }
        return null
    }
}

/** Recursive-descent parser for a single condition expression. */
private class CondParser(text: String, private val stringIds: List<String>) {

    private val tokens = tokenize(text)
    private var pos = 0

    fun parse(): Cond {
        val c = parseOr()
        return c
    }

    private fun peek(): String? = tokens.getOrNull(pos)
    private fun next(): String = tokens[pos++]
    private fun eat(tok: String) { if (peek() == tok) pos++ else error("expected '$tok' got '${peek()}'") }

    private fun parseOr(): Cond {
        var left = parseAnd()
        while (peek() == "or") { next(); left = Cond.Or(left, parseAnd()) }
        return left
    }

    private fun parseAnd(): Cond {
        var left = parseNot()
        while (peek() == "and") { next(); left = Cond.And(left, parseNot()) }
        return left
    }

    private fun parseNot(): Cond {
        if (peek() == "not") { next(); return Cond.Not(parseNot()) }
        return parsePrimary()
    }

    private fun parsePrimary(): Cond {
        val t = peek() ?: error("unexpected end of condition")
        return when {
            t == "(" -> { next(); val e = parseOr(); eat(")"); e }
            t == "any" || t == "all" || t.toIntOrNull() != null -> parseOf()
            t.startsWith("#") -> parseCountCmp()
            t.startsWith("$") -> Cond.Present(next().substring(1))
            else -> error("unexpected token '$t'")
        }
    }

    private fun parseCountCmp(): Cond {
        val id = next().substring(1)
        val op = next()
        val n = next().toIntOrNull() ?: error("expected number after '$op'")
        return Cond.CountCmp(id, op, n)
    }

    private fun parseOf(): Cond {
        val quant = next() // any | all | N
        eat("of")
        val ids = parseSet()
        val need = when (quant) {
            "any" -> 1
            "all" -> ids.size
            else -> quant.toIntOrNull() ?: 1
        }
        return Cond.OfSet(need, ids)
    }

    private fun parseSet(): List<String> {
        if (peek() == "them") { next(); return stringIds }
        eat("(")
        val ids = mutableListOf<String>()
        while (true) {
            val item = next()            // like  $p*  or  $lib
            require(item.startsWith("$")) { "expected string ref in set, got '$item'" }
            val base = item.substring(1)
            if (base.endsWith("*")) {
                val prefix = base.dropLast(1)
                ids += stringIds.filter { it.startsWith(prefix) }
            } else {
                ids += base
            }
            when (peek()) {
                "," -> next()
                ")" -> { next(); break }
                else -> error("expected ',' or ')' in set, got '${peek()}'")
            }
        }
        return ids.distinct()
    }

    companion object {
        /** Splits a condition into tokens; `$p*` becomes the single token "$p*". */
        private fun tokenize(text: String): List<String> {
            val out = mutableListOf<String>()
            var i = 0
            val s = text
            while (i < s.length) {
                val ch = s[i]
                when {
                    ch.isWhitespace() -> i++
                    ch == '(' || ch == ')' || ch == ',' -> { out += ch.toString(); i++ }
                    ch == '$' || ch == '#' -> {
                        val sb = StringBuilder().append(ch); i++
                        while (i < s.length && (s[i].isLetterOrDigit() || s[i] == '_')) { sb.append(s[i]); i++ }
                        if (i < s.length && s[i] == '*') { sb.append('*'); i++ } // wildcard
                        out += sb.toString()
                    }
                    ch == '>' || ch == '<' || ch == '=' || ch == '!' -> {
                        val sb = StringBuilder().append(ch); i++
                        if (i < s.length && s[i] == '=') { sb.append('='); i++ }
                        out += sb.toString()
                    }
                    ch.isDigit() -> {
                        val sb = StringBuilder(); while (i < s.length && s[i].isDigit()) { sb.append(s[i]); i++ }
                        out += sb.toString()
                    }
                    ch.isLetter() -> {
                        val sb = StringBuilder(); while (i < s.length && (s[i].isLetterOrDigit() || s[i] == '_')) { sb.append(s[i]); i++ }
                        out += sb.toString()
                    }
                    else -> i++ // skip anything unexpected (e.g. stray comment residue)
                }
            }
            return out
        }
    }
}

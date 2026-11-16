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
 * entries (classes.dex, native libs, the manifest, resources). So we decompress each
 * entry and match against its bytes — scanning the raw .apk bytes would miss them.
 */
class YaraEngine private constructor(private val rules: List<YaraRule>) {

    companion object {
        // Per-APK budget across all decompressed entries. Streamed in ~1 MiB chunks,
        // so memory stays bounded regardless of this cap.
        private const val TOTAL_CAP = 64L * 1024 * 1024           // 64 MiB / apk

        fun fromAsset(context: Context, name: String = "gtv-malware.yar"): YaraEngine {
            val text = context.assets.open(name).bufferedReader().use { it.readText() }
            return fromText(text)
        }

        fun fromText(text: String): YaraEngine = YaraEngine(YaraParser(text).parse())
    }

    /**
     * Needles precomputed once: rule-scoped key, the literal as raw bytes (Latin-1,
     * ASCII in practice), and a nocase flag. For nocase the bytes are pre-lowercased
     * so matching only has to fold the haystack byte. Kept as bytes so scanning never
     * allocates a UTF-16 String (which doubled memory and caused GC thrash on a TV).
     */
    private class Needle(val key: String, val bytes: ByteArray, val nocase: Boolean)

    private val needles: List<Needle> by lazy {
        rules.flatMap { rule ->
            rule.strings.map { s ->
                val raw = s.literal.toByteArray(Charsets.ISO_8859_1)
                val bytes = if (s.nocase) ByteArray(raw.size) { lc(raw[it]) } else raw
                Needle(rule.key(s.id), bytes, s.nocase)
            }
        }
    }
    private val maxNeedle: Int by lazy { needles.maxOfOrNull { it.bytes.size } ?: 0 }

    // First-byte dispatch tables so the buffer is scanned ONCE for all needles
    // instead of once per needle. csTable[b] holds case-sensitive needles starting
    // with byte b; ncTable[lb] holds nocase needles whose (lowercased) first byte is
    // lb. At each position we only test the few needles whose first byte can match.
    private val csTable: Array<List<Needle>?> by lazy { buildTable(caseSensitive = true) }
    private val ncTable: Array<List<Needle>?> by lazy { buildTable(caseSensitive = false) }

    private fun buildTable(caseSensitive: Boolean): Array<List<Needle>?> {
        val buckets = arrayOfNulls<MutableList<Needle>>(256)
        for (nd in needles) {
            if (nd.bytes.isEmpty() || nd.nocase == caseSensitive) continue
            val b = nd.bytes[0].toInt() and 0xFF
            (buckets[b] ?: ArrayList<Needle>().also { buckets[b] = it }).add(nd)
        }
        @Suppress("UNCHECKED_CAST")
        return Array(256) { buckets[it] as List<Needle>? }
    }

    /** @return the names of the rules that match this APK file (empty if none). */
    fun scanApk(path: String?): List<String> {
        val file = path?.let { File(it) } ?: return emptyList()
        if (!file.isFile || maxNeedle == 0) return emptyList()
        val counts = HashMap<String, Int>()
        var scanned = 0L

        try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements() && scanned < TOTAL_CAP) {
                    val e = entries.nextElement()
                    if (e.isDirectory) continue
                    // Each entry is its own byte stream, so a needle can't span two
                    // entries — scan each independently, bounded, in small chunks.
                    scanned += zip.getInputStream(e).use { scanStream(it, counts, TOTAL_CAP - scanned) }
                }
            }
        } catch (ex: Exception) {
            // Not a valid ZIP (or unreadable) — scan the raw bytes instead.
            try {
                file.inputStream().use { scanStream(it, counts, TOTAL_CAP) }
            } catch (_: Exception) {
                return emptyList()
            }
        }

        return rules.filter { it.matches(counts) }.map { it.name }
    }

    /**
     * Streams one source in ~1 MiB chunks, carrying (maxNeedle-1) bytes across chunk
     * boundaries so a match split across chunks is still found. Memory stays bounded
     * (~1 MiB) regardless of entry size. Returns bytes consumed.
     */
    private fun scanStream(input: java.io.InputStream, counts: HashMap<String, Int>, budget: Long): Long {
        val chunkSize = 1 shl 20
        val overlap = maxNeedle - 1
        val chunk = ByteArray(chunkSize)
        var carry = ByteArray(0)
        var consumed = 0L
        while (consumed < budget) {
            val r = input.read(chunk)
            if (r < 0) break
            consumed += r
            val bufLen = carry.size + r
            val buf = ByteArray(bufLen)
            System.arraycopy(carry, 0, buf, 0, carry.size)
            System.arraycopy(chunk, 0, buf, carry.size, r)
            scanBuffer(buf, bufLen, carry.size, counts)
            val keep = if (overlap < bufLen) overlap else bufLen
            carry = buf.copyOfRange(bufLen - keep, bufLen)
        }
        return consumed
    }

    /**
     * Single pass over buf[0,bufLen): at each position consult the first-byte dispatch
     * tables and test only the needles that could start there. A match is counted when
     * it extends past [carryLen] (so carried bytes aren't counted twice across chunks).
     */
    private fun scanBuffer(buf: ByteArray, bufLen: Int, carryLen: Int, counts: HashMap<String, Int>) {
        for (i in 0 until bufLen) {
            val b = buf[i].toInt() and 0xFF
            csTable[b]?.let { for (nd in it) tally(buf, bufLen, i, carryLen, nd, counts) }
            val lb = lc(buf[i]).toInt() and 0xFF
            ncTable[lb]?.let { for (nd in it) tally(buf, bufLen, i, carryLen, nd, counts) }
        }
    }

    private fun tally(buf: ByteArray, bufLen: Int, i: Int, carryLen: Int, nd: Needle, counts: HashMap<String, Int>) {
        val L = nd.bytes.size
        if (i + L > bufLen) return
        if (i + L <= carryLen) return      // wholly inside the carry — already counted
        if (!matchAt(buf, i, nd)) return
        counts[nd.key] = (counts[nd.key] ?: 0) + 1
    }

    private fun matchAt(buf: ByteArray, pos: Int, nd: Needle): Boolean {
        val n = nd.bytes
        if (nd.nocase) {
            for (k in n.indices) if (lc(buf[pos + k]) != n[k]) return false
        } else {
            for (k in n.indices) if (buf[pos + k] != n[k]) return false
        }
        return true
    }

    /** ASCII lower-case a single byte (A-Z -> a-z); leaves everything else as-is. */
    private fun lc(b: Byte): Byte {
        val v = b.toInt()
        return if (v in 65..90) (v + 32).toByte() else b
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

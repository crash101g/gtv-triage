package com.crash101g.gtvtriage.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.crash101g.gtvtriage.core.ApiKeyStore
import com.crash101g.gtvtriage.core.AppEntry
import com.crash101g.gtvtriage.core.PersistenceReport
import com.crash101g.gtvtriage.core.TriageReport
import com.crash101g.gtvtriage.core.VirusTotalClient
import com.crash101g.gtvtriage.core.VirusTotalClient.VtResult
import kotlinx.coroutines.launch

private val Bg = Color(0xFF1E2127)
private val Green = Color(0xFF4EC9B0)
private val Yellow = Color(0xFFE5C07B)
private val Red = Color(0xFFF14C4C)
private val Dim = Color(0xFF9AA0A6)

@Composable
fun TriageScreen(vm: TriageViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    Column(
        Modifier.fillMaxSize().padding(32.dp),
    ) {
        Text(
            "GTV Sideload Checker",
            color = Color.White,
            fontSize = 26.sp,
            fontWeight = FontWeight.Bold,
        )
        Text(
            "Work in progress • plain (non-root) sideload vetting",
            color = Dim,
            fontSize = 13.sp,
        )
        Spacer(Modifier.width(1.dp).padding(8.dp))

        when (val s = state) {
            is TriageUiState.Loading -> Loading()
            is TriageUiState.Error -> Text("Error: ${s.message}", color = Red)
            is TriageUiState.Ready -> Report(s.report)
        }
    }
}

@Composable
private fun Loading() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(color = Green)
        Spacer(Modifier.width(16.dp))
        Text("Scanning installed apps…", color = Dim)
    }
}

@Composable
private fun Report(report: TriageReport) {
    var vtApp by remember { mutableStateOf<AppEntry?>(null) }
    var showKeyDialog by remember { mutableStateOf(false) }

    vtApp?.let { app ->
        VirusTotalDialog(app, onDismiss = { vtApp = null })
    }
    if (showKeyDialog) {
        ApiKeyDialog(onDismiss = { showKeyDialog = false })
    }

    val context = LocalContext.current
    val shareFocus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { shareFocus.requestFocus() } }
    val gradeColor = when (report.grade) {
        "A", "B" -> Green
        "C", "D" -> Yellow
        else -> Red
    }
    Column {
        Row(verticalAlignment = Alignment.Bottom) {
            Text("${report.score}/100", color = gradeColor, fontSize = 34.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.width(12.dp))
            Text("grade ${report.grade}", color = gradeColor, fontSize = 18.sp)
            Spacer(Modifier.weight(1f))
            TextButton(onClick = { showKeyDialog = true }) {
                Text("⚙ VT key", color = Dim)
            }
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = { ReportShare.share(context, report) },
                modifier = Modifier.focusRequester(shareFocus),
            ) {
                Text("Export / Share")
            }
        }
        Text(report.verdict, color = Color.White, fontSize = 15.sp)
        Text(report.deviceLabel, color = Dim, fontSize = 13.sp)
        Text(
            "${report.apps.size} apps • ${report.sideloadedApps.size} sideloaded • " +
                "${report.iocFlaggedApps.size} IOC • ${report.yaraFlaggedApps.size} YARA",
            color = Dim, fontSize = 13.sp,
        )
        Spacer(Modifier.padding(8.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            item(key = "__persistence") { PersistenceCard(report.persistence) }
            item(key = "__apps_header") {
                Text(
                    "Installed apps",
                    color = Dim, fontSize = 13.sp, fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp, bottom = 2.dp),
                )
            }
            items(report.apps, key = { it.packageName }) { app ->
                AppRow(app, onOpenVt = { if (app.virusTotalUrl != null) vtApp = app })
            }
        }
    }
}

@Composable
private fun PersistenceCard(p: PersistenceReport) {
    val hasHigh = p.accessibility.isNotEmpty() || p.deviceAdmins.isNotEmpty()
    val accent = if (hasHigh) Red else Dim
    Card(
        Modifier
            .fillMaxWidth()
            .border(1.dp, accent.copy(alpha = 0.4f), RoundedCornerShape(8.dp)),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("Persistence", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 15.sp)
            Text(
                "non-root view: boot receivers, a11y, notif listeners, device admins, IMEs",
                color = Dim, fontSize = 11.sp,
            )
            Spacer(Modifier.padding(3.dp))

            PersistLine(
                "Boot receivers",
                "${p.bootReceiverTotal} total • ${p.thirdPartyBootReceivers.size} third-party",
                warn = false,
            )
            p.accessibility.forEach {
                PersistLine("⚠ Accessibility", it.component, warn = true)
            }
            if (p.accessibility.isEmpty()) {
                PersistLine("Accessibility", "none enabled", warn = false)
            }
            p.deviceAdmins.forEach {
                PersistLine("⚠ Device admin", it.component, warn = true)
            }
            p.notificationListeners.forEach {
                PersistLine("Notif listener", it.component, warn = it.thirdParty)
            }
            p.inputMethods.forEach {
                val tag = buildString {
                    append(it.component)
                    if (it.isDefault) append("  (default)")
                }
                PersistLine(
                    if (it.thirdParty) "⚠ Input method" else "Input method",
                    tag, warn = it.thirdParty,
                )
            }
        }
    }
}

@Composable
private fun VtResultText(r: VtResult) {
    when (r) {
        is VtResult.Found -> {
            val bad = r.flagged > 0
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    "${r.malicious} malicious / ${r.engines} engines",
                    color = if (bad) Red else Green,
                    fontWeight = FontWeight.Bold, fontSize = 14.sp,
                )
                Text(
                    "suspicious ${r.suspicious} • harmless ${r.harmless} • undetected ${r.undetected}",
                    color = Dim, fontSize = 11.sp,
                )
            }
        }
        VtResult.NotFound -> Text("VirusTotal has no record of this hash.", color = Yellow, fontSize = 12.sp)
        VtResult.Unauthorized -> Text("API key rejected (401) — check the key.", color = Red, fontSize = 12.sp)
        VtResult.RateLimited -> Text("Rate limited (429) — try again in a minute.", color = Yellow, fontSize = 12.sp)
        is VtResult.Error -> Text("Lookup failed: ${r.message}", color = Red, fontSize = 12.sp)
    }
}

@Composable
private fun ApiKeyDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    var key by remember { mutableStateOf(ApiKeyStore.get(context) ?: "") }
    Dialog(onDismissRequest = onDismiss) {
        Card(Modifier.width(440.dp).border(1.dp, Dim.copy(alpha = 0.5f), RoundedCornerShape(12.dp))) {
            Column(Modifier.background(Color(0xFF14171C)).padding(20.dp)) {
                Text("VirusTotal API key", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text(
                    "Stored locally (app-private). Only file hashes are ever sent, " +
                        "and only when you press “Check detections”.",
                    color = Dim, fontSize = 11.sp,
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = key,
                    onValueChange = { key = it },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(16.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = {
                        if (key.isBlank()) ApiKeyStore.clear(context) else ApiKeyStore.set(context, key)
                        onDismiss()
                    }) { Text("Save") }
                    TextButton(onClick = {
                        ApiKeyStore.clear(context); onDismiss()
                    }) { Text("Clear", color = Dim) }
                    TextButton(onClick = onDismiss) { Text("Cancel", color = Dim) }
                }
            }
        }
    }
}

@Composable
private fun PersistLine(label: String, value: String, warn: Boolean) {
    val c = if (warn) Red else Dim
    Row(Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(label, color = c, fontSize = 12.sp, modifier = Modifier.width(140.dp))
        Text(value, color = if (warn) Red else Color(0xFFBFC5CB), fontSize = 12.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun AppRow(app: AppEntry, onOpenVt: () -> Unit) {
    val accent = when {
        app.yaraHits.isNotEmpty() || app.iocHits.isNotEmpty() -> Red
        app.sideloaded -> Yellow
        else -> Dim
    }
    val hasVt = app.virusTotalUrl != null
    val interaction = remember { MutableInteractionSource() }
    val focused by interaction.collectIsFocusedAsState()
    // D-pad focus highlight: a focused card brightens its border and lifts slightly.
    val scale by animateFloatAsState(if (focused) 1.025f else 1f, label = "cardScale")
    val borderColor by animateColorAsState(
        if (focused) Color.White else accent.copy(alpha = 0.4f),
        label = "cardBorder",
    )
    Card(
        Modifier
            .fillMaxWidth()
            .scale(scale)
            .border(if (focused) 2.dp else 1.dp, borderColor, RoundedCornerShape(8.dp))
            .then(
                if (hasVt) {
                    Modifier.clickable(interactionSource = interaction, indication = null) { onOpenVt() }
                } else {
                    Modifier
                },
            ),
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(app.label, color = Color.White, fontWeight = FontWeight.Medium, fontSize = 15.sp)
                Text(
                    when {
                        app.yaraHits.isNotEmpty() -> "YARA"
                        app.iocHits.isNotEmpty() -> "IOC"
                        app.sideloaded -> "SIDELOADED"
                        app.isSystem -> "system"
                        else -> "store"
                    },
                    color = accent, fontSize = 12.sp, fontWeight = FontWeight.Bold,
                )
            }
            Text(app.packageName, color = Dim, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            app.installer?.let { Text("installer: $it", color = Dim, fontSize = 11.sp) }
            app.sha256?.let {
                Text("sha256: ${it.take(16)}…", color = Dim, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            }
            if (app.yaraHits.isNotEmpty()) {
                Text("☣ YARA: ${app.yaraHits.joinToString(", ")}", color = Red, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
            if (app.iocHits.isNotEmpty()) {
                Text("⚠ IOC: ${app.iocHits.joinToString(", ")}", color = Red, fontSize = 12.sp)
            }
            app.virusTotalUrl?.let {
                Text(
                    "▶ Press to check on VirusTotal (QR / browser)",
                    color = Color(0xFF569CD6), fontSize = 11.sp, fontWeight = FontWeight.Medium,
                )
            }
        }
    }
}

/**
 * VirusTotal link dialog. On a TV there's usually no browser and only a D-pad, so
 * the primary path is a QR code to scan with a phone. An "Open in browser" button
 * covers devices that do have one (and degrades to a helpful message if they don't).
 */
@Composable
private fun VirusTotalDialog(app: AppEntry, onDismiss: () -> Unit) {
    val url = app.virusTotalUrl ?: return
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val qr = remember(url) { QrCodes.encode(url, 512) }
    var noBrowser by remember { mutableStateOf(false) }
    val apiKey = remember { ApiKeyStore.get(context) }
    var vt by remember { mutableStateOf<VtResult?>(null) }
    var vtLoading by remember { mutableStateOf(false) }

    Dialog(onDismissRequest = onDismiss) {
        Card(Modifier.width(420.dp).border(1.dp, Dim.copy(alpha = 0.5f), RoundedCornerShape(12.dp))) {
            Column(
                Modifier.background(Color(0xFF14171C)).padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(app.label, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                Text("VirusTotal lookup", color = Dim, fontSize = 12.sp)
                Spacer(Modifier.height(12.dp))

                if (qr != null) {
                    Image(
                        bitmap = qr,
                        contentDescription = "VirusTotal QR code",
                        modifier = Modifier
                            .size(220.dp)
                            .background(Color.White)
                            .padding(8.dp),
                    )
                    Spacer(Modifier.height(6.dp))
                    Text("Scan with your phone", color = Dim, fontSize = 12.sp)
                } else {
                    Text("Could not render QR — use the URL below.", color = Yellow, fontSize = 12.sp)
                }

                Spacer(Modifier.height(10.dp))
                app.sha256?.let {
                    Text("sha256", color = Dim, fontSize = 10.sp)
                    Text(it, color = Color(0xFFBFC5CB), fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                    Spacer(Modifier.height(8.dp))
                }
                Text(url, color = Color(0xFF569CD6), fontSize = 11.sp, fontFamily = FontFamily.Monospace)

                if (noBrowser) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "No browser on this device — scan the QR code instead.",
                        color = Yellow, fontSize = 12.sp,
                    )
                }

                // Optional API enrichment (only when a key is configured).
                Spacer(Modifier.height(10.dp))
                when {
                    apiKey == null -> Text(
                        "Tip: add a VirusTotal API key (⚙) to show detections here.",
                        color = Dim, fontSize = 11.sp,
                    )
                    vtLoading -> Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(color = Green, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Querying VirusTotal…", color = Dim, fontSize = 12.sp)
                    }
                    vt != null -> VtResultText(vt!!)
                    else -> TextButton(onClick = {
                        val sha = app.sha256 ?: return@TextButton
                        vtLoading = true
                        scope.launch {
                            vt = VirusTotalClient.lookup(sha, apiKey)
                            vtLoading = false
                        }
                    }) { Text("Check detections via API", color = Color(0xFF569CD6)) }
                }

                Spacer(Modifier.height(16.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = {
                        try {
                            context.startActivity(
                                Intent(Intent.ACTION_VIEW, Uri.parse(url))
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                            )
                        } catch (e: ActivityNotFoundException) {
                            noBrowser = true
                        }
                    }) { Text("Open in browser") }
                    TextButton(onClick = onDismiss) { Text("Close", color = Dim) }
                }
            }
        }
    }
}

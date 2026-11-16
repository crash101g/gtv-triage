package com.crash101g.gtvtriage.ui

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.crash101g.gtvtriage.core.AppEntry
import com.crash101g.gtvtriage.core.TriageReport

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
        }
        Text(report.verdict, color = Color.White, fontSize = 15.sp)
        Text(report.deviceLabel, color = Dim, fontSize = 13.sp)
        Text(
            "${report.apps.size} apps • ${report.sideloadedApps.size} sideloaded • " +
                "${report.iocFlaggedApps.size} IOC-flagged",
            color = Dim, fontSize = 13.sp,
        )
        Spacer(Modifier.padding(8.dp))

        LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            items(report.apps, key = { it.packageName }) { app ->
                AppRow(app)
            }
        }
    }
}

@Composable
private fun AppRow(app: AppEntry) {
    val accent = when {
        app.iocHits.isNotEmpty() -> Red
        app.sideloaded -> Yellow
        else -> Dim
    }
    Card(
        Modifier
            .fillMaxWidth()
            .border(1.dp, accent.copy(alpha = 0.4f), RoundedCornerShape(8.dp)),
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(app.label, color = Color.White, fontWeight = FontWeight.Medium, fontSize = 15.sp)
                Text(
                    when {
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
            if (app.iocHits.isNotEmpty()) {
                Text("⚠ matched: ${app.iocHits.joinToString(", ")}", color = Red, fontSize = 12.sp)
            }
            app.virusTotalUrl?.let {
                Text(it, color = Color(0xFF569CD6), fontSize = 11.sp, fontFamily = FontFamily.Monospace)
            }
        }
    }
}

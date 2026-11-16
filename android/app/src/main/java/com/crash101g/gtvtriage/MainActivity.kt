package com.crash101g.gtvtriage

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.crash101g.gtvtriage.ui.TriageScreen
import com.crash101g.gtvtriage.ui.TriageViewModel

class MainActivity : ComponentActivity() {

    private val vm: TriageViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(
                    modifier = Modifier.fillMaxSize().background(Color(0xFF1E2127)),
                    color = Color(0xFF1E2127),
                ) {
                    TriageScreen(vm)
                }
            }
        }
    }
}

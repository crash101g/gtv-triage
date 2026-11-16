package com.crash101g.gtvtriage.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.crash101g.gtvtriage.core.TriageEngine
import com.crash101g.gtvtriage.core.TriageReport
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed interface TriageUiState {
    data object Loading : TriageUiState
    data class Ready(val report: TriageReport) : TriageUiState
    data class Error(val message: String) : TriageUiState
}

class TriageViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow<TriageUiState>(TriageUiState.Loading)
    val state: StateFlow<TriageUiState> = _state.asStateFlow()

    init {
        scan()
    }

    fun scan() {
        _state.value = TriageUiState.Loading
        viewModelScope.launch {
            try {
                val report = TriageEngine(getApplication()).run()
                _state.value = TriageUiState.Ready(report)
            } catch (e: Exception) {
                _state.value = TriageUiState.Error(e.message ?: e.toString())
            }
        }
    }
}

package com.crash101g.gtvtriage.ui

import android.graphics.Bitmap
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Encodes a string (a VirusTotal GUI URL) to a QR [ImageBitmap] so it can be
 * scanned with a phone — the primary "open this link" path on a TV, which usually
 * has no browser and only a D-pad. Pure ZXing, no network, no Play services.
 */
object QrCodes {

    fun encode(text: String, sizePx: Int = 512): ImageBitmap? = try {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
        )
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        val w = matrix.width
        val h = matrix.height
        val black = 0xFF000000.toInt()
        val white = 0xFFFFFFFF.toInt()
        val pixels = IntArray(w * h)
        for (y in 0 until h) {
            val row = y * w
            for (x in 0 until w) {
                pixels[row + x] = if (matrix.get(x, y)) black else white
            }
        }
        Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).also {
            it.setPixels(pixels, 0, w, 0, 0, w, h)
        }.asImageBitmap()
    } catch (e: Exception) {
        null
    }
}

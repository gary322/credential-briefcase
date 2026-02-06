package com.credentialbriefcase.mobilesigner

import android.util.Base64

object Base64Url {
    fun encode(bytes: ByteArray): String {
        // URL-safe, no padding.
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    fun decode(s: String): ByteArray? {
        return try {
            Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            null
        }
    }
}


package com.credentialbriefcase.mobilesigner

import android.net.Uri
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class PairingPayload(
    val base_url: String,
    val pairing_id: String,
    val pairing_code: String,
) {
    fun validated(): Triple<String, String, String>? {
        if (base_url.isBlank() || pairing_id.isBlank() || pairing_code.isBlank()) return null
        return Triple(base_url, pairing_id, pairing_code)
    }
}

object PairingPayloadParser {
    private val json = Json { ignoreUnknownKeys = true }

    fun parse(raw: String): PairingPayload? {
        val s = raw.trim()
        if (s.isEmpty()) return null

        val uri = runCatching { Uri.parse(s) }.getOrNull()
        if (uri != null) {
            val scheme = uri.scheme?.lowercase()
            if (scheme != null && scheme.startsWith("briefcase")) {
                val base = uri.getQueryParameter("base_url")
                val pid = uri.getQueryParameter("pairing_id")
                val code = uri.getQueryParameter("pairing_code")
                if (!base.isNullOrBlank() && !pid.isNullOrBlank() && !code.isNullOrBlank()) {
                    return PairingPayload(base, pid, code)
                }
            }
        }

        return runCatching { json.decodeFromString(PairingPayload.serializer(), s) }.getOrNull()
    }
}


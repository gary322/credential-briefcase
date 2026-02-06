package com.credentialbriefcase.mobilesigner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.HttpUrl.Companion.toHttpUrl

class BriefcasedClient(baseUrl: String) {
    private val http = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }
    private val base = baseUrl.toHttpUrl()

    suspend fun completePairing(pairingId: String, req: SignerPairCompleteRequest): SignerPairCompleteResponse {
        return post("/v1/signer/pair/$pairingId/complete", req)
    }

    suspend fun listApprovals(req: SignerSignedRequest): ListApprovalsResponse {
        return post("/v1/signer/approvals", req)
    }

    suspend fun approve(approvalId: String, req: SignerSignedRequest): ApproveResponse {
        return post("/v1/signer/approvals/$approvalId/approve", req)
    }

    private suspend inline fun <reified Req, reified Res> post(path: String, body: Req): Res {
        val media = "application/json; charset=utf-8".toMediaType()
        val bodyJson = json.encodeToString(body)
        val url = base.resolve(path) ?: throw IllegalArgumentException("bad url")

        val request = Request.Builder()
            .url(url)
            .post(bodyJson.toRequestBody(media))
            .build()

        return withContext(Dispatchers.IO) {
            http.newCall(request).execute().use { resp ->
                val bytes = resp.body?.bytes() ?: ByteArray(0)
                val text = bytes.toString(Charsets.UTF_8)
                if (!resp.isSuccessful) {
                    val err = runCatching { json.decodeFromString<ErrorResponse>(text) }.getOrNull()
                    throw IllegalStateException(err?.let { "${it.code}: ${it.message}" } ?: "HTTP ${resp.code}")
                }
                json.decodeFromString<Res>(text)
            }
        }
    }
}

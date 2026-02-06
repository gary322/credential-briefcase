package com.credentialbriefcase.mobilesigner

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
data class SignerPairCompleteRequest(
    val msg1_b64: String,
    val algorithm: String,
    val signer_pubkey_b64: String,
    val device_name: String? = null,
)

@Serializable
data class SignerPairCompleteResponse(
    val msg2_b64: String,
)

@Serializable
data class SignerSignedRequest(
    val signer_id: String,
    val ts_rfc3339: String,
    val nonce: String,
    val sig_b64: String,
)

@Serializable
data class ApprovalRequest(
    val id: String,
    val created_at: String,
    val expires_at: String,
    val tool_id: String,
    val reason: String,
    val summary: JsonElement,
)

@Serializable
data class ListApprovalsResponse(
    val approvals: List<ApprovalRequest>,
)

@Serializable
data class ApproveResponse(
    val approval_id: String,
    val approval_token: String,
)

@Serializable
data class ErrorResponse(
    val code: String,
    val message: String,
)


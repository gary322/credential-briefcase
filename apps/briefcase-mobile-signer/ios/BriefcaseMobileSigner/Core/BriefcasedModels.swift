import Foundation

struct SignerPairCompleteRequest: Codable {
    let msg1_b64: String
    let algorithm: String
    let signer_pubkey_b64: String
    let device_name: String?
}

struct SignerPairCompleteResponse: Codable {
    let msg2_b64: String
}

struct SignerSignedRequest: Codable {
    let signer_id: UUID
    let ts_rfc3339: String
    let nonce: String
    let sig_b64: String
}

struct ApprovalRequest: Codable, Identifiable, Hashable {
    let id: UUID
    let created_at: String
    let expires_at: String
    let tool_id: String
    let reason: String
    let summary: JSONValue
}

struct ListApprovalsResponse: Codable {
    let approvals: [ApprovalRequest]
}

struct ApproveResponse: Codable {
    let approval_id: UUID
    let approval_token: String
}

struct ErrorResponse: Codable, Error {
    let code: String
    let message: String
}


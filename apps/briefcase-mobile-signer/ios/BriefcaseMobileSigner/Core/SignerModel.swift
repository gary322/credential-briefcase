import Combine
import Foundation
import Security

@MainActor
final class SignerModel: ObservableObject {
    @Published var baseURL: String = ""
    @Published var pairingId: String = ""
    @Published var pairingCode: String = ""
    @Published var deviceName: String = "iOS signer"

    @Published private(set) var isPaired: Bool = false
    @Published private(set) var signerId: UUID?
    @Published private(set) var approvals: [ApprovalRequest] = []
    @Published var statusMessage: String?
    @Published var isBusy: Bool = false

    private var signingKey: SecKey?

    private static let defaultsBaseURLKey = "briefcase.signer.base_url"
    private static let defaultsSignerIdKey = "briefcase.signer.signer_id"

    init() {
        baseURL = UserDefaults.standard.string(forKey: Self.defaultsBaseURLKey) ?? ""
        if let raw = UserDefaults.standard.string(forKey: Self.defaultsSignerIdKey),
           let id = UUID(uuidString: raw)
        {
            signerId = id
            isPaired = true
        }
    }

    func applyPairingPayload(_ payload: PairingPayload) {
        guard let (u, id, code) = payload.validated() else {
            statusMessage = "Invalid pairing payload"
            return
        }
        baseURL = u.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        pairingId = id.uuidString
        pairingCode = code
    }

    func unpair() {
        approvals = []
        signerId = nil
        isPaired = false
        statusMessage = nil

        UserDefaults.standard.removeObject(forKey: Self.defaultsSignerIdKey)
    }

    func pair() async {
        statusMessage = nil
        isBusy = true
        defer { isBusy = false }

        guard let base = URL(string: baseURL),
              let pid = UUID(uuidString: pairingId)
        else {
            statusMessage = "Invalid base URL or pairing ID"
            return
        }

        guard let psk = Base64URL.decode(pairingCode), psk.count == 32 else {
            statusMessage = "Invalid pairing code"
            return
        }

        do {
            let key = try SignerKey.loadOrCreateP256SigningKey()
            signingKey = key
            let pub = try SignerKey.publicKeySec1Bytes(privateKey: key)

            var noise = try NoiseNNpsk0Initiator(psk: psk)
            let msg1 = try noise.writeMessage1()

            let client = BriefcasedClient(baseURL: base)
            let resp = try await client.completePairing(
                pairingId: pid,
                req: SignerPairCompleteRequest(
                    msg1_b64: Base64URL.encode(msg1),
                    algorithm: "p256",
                    signer_pubkey_b64: Base64URL.encode(pub),
                    device_name: deviceName.isEmpty ? nil : deviceName
                )
            )

            guard let msg2 = Base64URL.decode(resp.msg2_b64) else {
                statusMessage = "Invalid pairing response"
                return
            }
            let payload = try noise.readMessage2(msg2)

            struct PairingAck: Codable { let signer_id: String }
            let ack = try JSONDecoder().decode(PairingAck.self, from: payload)
            guard let sid = UUID(uuidString: ack.signer_id) else {
                statusMessage = "Invalid signer_id in response"
                return
            }

            signerId = sid
            isPaired = true
            approvals = []
            pairingCode = "" // don't keep secrets around after pairing

            UserDefaults.standard.set(base.absoluteString, forKey: Self.defaultsBaseURLKey)
            UserDefaults.standard.set(sid.uuidString, forKey: Self.defaultsSignerIdKey)

            statusMessage = "Paired"
        } catch {
            statusMessage = "Pairing failed: \(error)"
        }
    }

    func refreshApprovals() async {
        statusMessage = nil
        guard let signerId else {
            statusMessage = "Not paired"
            return
        }
        guard let key = signingKey ?? (try? SignerKey.loadOrCreateP256SigningKey()) else {
            statusMessage = "Missing signing key"
            return
        }
        signingKey = key

        guard let base = URL(string: baseURL) else {
            statusMessage = "Invalid base URL"
            return
        }

        isBusy = true
        defer { isBusy = false }

        do {
            let req = try signedRequest(
                signerId: signerId,
                key: key,
                kind: "list_approvals",
                approvalId: nil
            )
            let client = BriefcasedClient(baseURL: base)
            let resp = try await client.listApprovals(req: req)
            approvals = resp.approvals
        } catch {
            statusMessage = "List failed: \(error)"
        }
    }

    func approve(_ approvalId: UUID) async {
        statusMessage = nil
        guard let signerId else {
            statusMessage = "Not paired"
            return
        }
        guard let key = signingKey ?? (try? SignerKey.loadOrCreateP256SigningKey()) else {
            statusMessage = "Missing signing key"
            return
        }
        signingKey = key

        guard let base = URL(string: baseURL) else {
            statusMessage = "Invalid base URL"
            return
        }

        isBusy = true
        defer { isBusy = false }

        do {
            let req = try signedRequest(
                signerId: signerId,
                key: key,
                kind: "approve",
                approvalId: approvalId
            )
            let client = BriefcasedClient(baseURL: base)
            _ = try await client.approve(approvalId: approvalId, req: req)
            await refreshApprovals()
        } catch {
            statusMessage = "Approve failed: \(error)"
        }
    }

    private func signedRequest(
        signerId: UUID,
        key: SecKey,
        kind: String,
        approvalId: UUID?
    ) throws -> SignerSignedRequest {
        let ts = Self.rfc3339Now()
        let nonce = UUID().uuidString
        let approvalLine = approvalId?.uuidString ?? "-"
        let msg = "\(kind)\n\(signerId.uuidString)\n\(approvalLine)\n\(ts)\n\(nonce)\n"

        let sig = try SignerKey.sign(privateKey: key, message: Data(msg.utf8))

        return SignerSignedRequest(
            signer_id: signerId,
            ts_rfc3339: ts,
            nonce: nonce,
            sig_b64: Base64URL.encode(sig)
        )
    }

    private static func rfc3339Now() -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: Date())
    }
}


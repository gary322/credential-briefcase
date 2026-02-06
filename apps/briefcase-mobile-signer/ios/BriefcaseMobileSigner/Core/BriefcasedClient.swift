import Foundation

final class BriefcasedClient {
    private let baseURL: URL
    private let session: URLSession

    init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    func completePairing(pairingId: UUID, req: SignerPairCompleteRequest) async throws -> SignerPairCompleteResponse {
        try await post("/v1/signer/pair/\(pairingId.uuidString)/complete", body: req)
    }

    func listApprovals(req: SignerSignedRequest) async throws -> ListApprovalsResponse {
        try await post("/v1/signer/approvals", body: req)
    }

    func approve(approvalId: UUID, req: SignerSignedRequest) async throws -> ApproveResponse {
        try await post("/v1/signer/approvals/\(approvalId.uuidString)/approve", body: req)
    }

    private func post<Req: Encodable, Res: Decodable>(_ path: String, body: Req) async throws -> Res {
        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL else {
            throw URLError(.badURL)
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONEncoder().encode(body)

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        if (200 ..< 300).contains(http.statusCode) {
            return try JSONDecoder().decode(Res.self, from: data)
        }
        if let err = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
            throw err
        }
        throw URLError(.badServerResponse)
    }
}

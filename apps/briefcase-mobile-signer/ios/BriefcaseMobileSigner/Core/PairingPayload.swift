import Foundation

struct PairingPayload: Codable, Hashable {
    let base_url: String
    let pairing_id: String
    let pairing_code: String

    func validated() -> (URL, UUID, String)? {
        guard let baseURL = URL(string: base_url),
              let pairingId = UUID(uuidString: pairing_id),
              !pairing_code.isEmpty
        else {
            return nil
        }
        return (baseURL, pairingId, pairing_code)
    }
}

enum PairingPayloadParser {
    static func parse(_ s: String) -> PairingPayload? {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return nil
        }

        if let u = URL(string: trimmed),
           let scheme = u.scheme,
           scheme.lowercased().hasPrefix("briefcase"),
           let comps = URLComponents(url: u, resolvingAgainstBaseURL: false),
           let items = comps.queryItems
        {
            // Newer Swift compilers can struggle to infer the generic arguments for
            // `Dictionary(uniqueKeysWithValues:)` here. Build the map explicitly.
            // If duplicate keys exist, the last occurrence wins.
            var m: [String: String] = [:]
            for qi in items {
                guard let v = qi.value else { continue }
                m[qi.name] = v
            }

            if let base = m["base_url"],
               let pid = m["pairing_id"],
               let code = m["pairing_code"]
            {
                return PairingPayload(base_url: base, pairing_id: pid, pairing_code: code)
            }
        }

        if let data = trimmed.data(using: .utf8),
           let p = try? JSONDecoder().decode(PairingPayload.self, from: data)
        {
            return p
        }

        return nil
    }
}

import Foundation

enum JSONValue: Codable, Hashable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
            return
        }
        if let b = try? c.decode(Bool.self) {
            self = .bool(b)
            return
        }
        if let n = try? c.decode(Double.self) {
            self = .number(n)
            return
        }
        if let s = try? c.decode(String.self) {
            self = .string(s)
            return
        }
        if let a = try? c.decode([JSONValue].self) {
            self = .array(a)
            return
        }
        if let o = try? c.decode([String: JSONValue].self) {
            self = .object(o)
            return
        }
        throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unsupported JSON value")
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case let .string(s):
            try c.encode(s)
        case let .number(n):
            try c.encode(n)
        case let .bool(b):
            try c.encode(b)
        case let .object(o):
            try c.encode(o)
        case let .array(a):
            try c.encode(a)
        case .null:
            try c.encodeNil()
        }
    }

    func prettyPrinted() -> String {
        let obj: Any = toAny()
        guard JSONSerialization.isValidJSONObject(obj),
              let data = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted]),
              let s = String(data: data, encoding: .utf8)
        else {
            return String(describing: self)
        }
        return s
    }

    private func toAny() -> Any {
        switch self {
        case let .string(s):
            return s
        case let .number(n):
            return n
        case let .bool(b):
            return b
        case let .object(o):
            return o.mapValues { $0.toAny() }
        case let .array(a):
            return a.map { $0.toAny() }
        case .null:
            return NSNull()
        }
    }
}


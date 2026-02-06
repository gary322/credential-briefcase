import CryptoKit
import Foundation

// Minimal Noise implementation for a single handshake pattern:
//
//   Noise_NNpsk0_25519_ChaChaPoly_SHA256
//
// This is intentionally not a generic Noise framework. It exists so the mobile
// signer can pair with `briefcased` without shipping extra dependencies.

enum NoiseNNpsk0Error: Error {
    case invalidPskLength
    case invalidMessage
    case cryptoFailure
}

private func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

private func hmacSha256(key: Data, data: Data) -> Data {
    let symKey = SymmetricKey(data: key)
    let mac = HMAC<SHA256>.authenticationCode(for: data, using: symKey)
    return Data(mac)
}

private func hkdf(
    chainingKey: Data,
    inputKeyMaterial: Data,
    numOutputs: Int
) -> [Data] {
    // HKDF from the Noise spec (RFC5869 with salt=chainingKey, info empty).
    let tempKey = hmacSha256(key: chainingKey, data: inputKeyMaterial)
    let output1 = hmacSha256(key: tempKey, data: Data([0x01]))
    let output2 = hmacSha256(key: tempKey, data: output1 + Data([0x02]))
    if numOutputs == 2 {
        return [output1, output2]
    }
    let output3 = hmacSha256(key: tempKey, data: output2 + Data([0x03]))
    return [output1, output2, output3]
}

private struct CipherState {
    // If keyBytes is nil, encryption is a no-op (plaintext).
    private var keyBytes: Data?
    private var nonce: UInt64 = 0

    mutating func initializeKey(_ key: Data?) {
        keyBytes = key
        nonce = 0
    }

    private func nonceBytes() throws -> ChaChaPoly.Nonce {
        // Noise nonce: 96-bit nonce = 4 zero bytes || little_endian(nonce64)
        var n = nonce.littleEndian
        var out = Data(repeating: 0, count: 4)
        out.append(Data(bytes: &n, count: 8))
        return try ChaChaPoly.Nonce(data: out)
    }

    mutating func encryptWithAd(ad: Data, plaintext: Data) throws -> Data {
        guard let keyBytes else {
            return plaintext
        }
        let key = SymmetricKey(data: keyBytes)
        let n = try nonceBytes()
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: n, authenticating: ad)
        nonce &+= 1
        return box.ciphertext + box.tag
    }

    mutating func decryptWithAd(ad: Data, ciphertext: Data) throws -> Data {
        guard let keyBytes else {
            return ciphertext
        }
        guard ciphertext.count >= 16 else {
            throw NoiseNNpsk0Error.invalidMessage
        }
        let key = SymmetricKey(data: keyBytes)
        let n = try nonceBytes()
        let ct = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)
        let box = try ChaChaPoly.SealedBox(nonce: n, ciphertext: ct, tag: tag)
        let pt = try ChaChaPoly.open(box, using: key, authenticating: ad)
        nonce &+= 1
        return pt
    }
}

private struct SymmetricState {
    private(set) var ck: Data
    private(set) var h: Data
    private var cipher: CipherState

    init(protocolName: String) {
        let pn = Data(protocolName.utf8)
        if pn.count <= 32 {
            var padded = pn
            padded.append(Data(repeating: 0, count: 32 - pn.count))
            h = padded
        } else {
            h = sha256(pn)
        }
        ck = h
        cipher = CipherState()
        cipher.initializeKey(nil)
    }

    mutating func mixHash(_ data: Data) {
        h = sha256(h + data)
    }

    mutating func mixKey(_ inputKeyMaterial: Data) {
        let outs = hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 2)
        ck = outs[0]
        cipher.initializeKey(outs[1])
    }

    mutating func mixKeyAndHash(_ inputKeyMaterial: Data) {
        let outs = hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 3)
        ck = outs[0]
        mixHash(outs[1])
        cipher.initializeKey(outs[2])
    }

    mutating func encryptAndHash(_ plaintext: Data) throws -> Data {
        let ciphertext = try cipher.encryptWithAd(ad: h, plaintext: plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    mutating func decryptAndHash(_ ciphertext: Data) throws -> Data {
        let plaintext = try cipher.decryptWithAd(ad: h, ciphertext: ciphertext)
        mixHash(ciphertext)
        return plaintext
    }
}

struct NoiseNNpsk0Initiator {
    private var symmetric = SymmetricState(protocolName: "Noise_NNpsk0_25519_ChaChaPoly_SHA256")
    private let psk: Data
    private var e: Curve25519.KeyAgreement.PrivateKey?

    init(psk: Data) throws {
        guard psk.count == 32 else {
            throw NoiseNNpsk0Error.invalidPskLength
        }
        self.psk = psk
    }

    mutating func writeMessage1(payload: Data = Data()) throws -> Data {
        // message1 pattern: psk, e
        symmetric.mixKeyAndHash(psk)

        let eph = Curve25519.KeyAgreement.PrivateKey()
        e = eph
        let ePub = eph.publicKey.rawRepresentation
        symmetric.mixHash(ePub)
        // PSK mode: MixKey(e.public_key) after MixHash(e.public_key).
        symmetric.mixKey(ePub)

        let ciphertext = try symmetric.encryptAndHash(payload)
        return ePub + ciphertext
    }

    mutating func readMessage2(_ message: Data) throws -> Data {
        // message2 pattern: e, ee
        guard message.count >= 32 + 16 else {
            throw NoiseNNpsk0Error.invalidMessage
        }
        guard let eph = e else {
            throw NoiseNNpsk0Error.invalidMessage
        }

        let rePub = message.prefix(32)
        let rest = message.dropFirst(32)

        symmetric.mixHash(rePub)
        symmetric.mixKey(rePub) // PSK mode.

        let re = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rePub)
        let ss = try eph.sharedSecretFromKeyAgreement(with: re)
        let dh = ss.withUnsafeBytes { Data($0) }
        symmetric.mixKey(dh)

        return try symmetric.decryptAndHash(Data(rest))
    }
}


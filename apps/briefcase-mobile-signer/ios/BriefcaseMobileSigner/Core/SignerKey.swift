import Foundation
import Security

enum SignerKeyError: Error {
    case keyGenerationFailed(String)
    case keyLoadFailed(String)
    case publicKeyExportFailed(String)
    case signFailed(String)
}

enum SignerKey {
    private static let keyTag = "com.credentialbriefcase.mobile-signer.p256".data(using: .utf8)!

    static func loadOrCreateP256SigningKey() throws -> SecKey {
        if let k = try? loadP256SigningKey() {
            return k
        }

        // Try Secure Enclave first; fall back to software key for simulators / unsupported devices.
        do {
            return try createP256SigningKey(secureEnclave: true)
        } catch {
            return try createP256SigningKey(secureEnclave: false)
        }
    }

    static func publicKeySec1Bytes(privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SignerKeyError.publicKeyExportFailed("missing public key")
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            let msg = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "unknown"
            throw SignerKeyError.publicKeyExportFailed(msg)
        }
        return data
    }

    static func sign(privateKey: SecKey, message: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            let msg = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "unknown"
            throw SignerKeyError.signFailed(msg)
        }
        return sig
    }

    private static func loadP256SigningKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status != errSecItemNotFound else {
            throw SignerKeyError.keyLoadFailed("not found")
        }
        guard status == errSecSuccess, let key = item as! SecKey? else {
            throw SignerKeyError.keyLoadFailed("SecItemCopyMatching status=\(status)")
        }
        return key
    }

    private static func createP256SigningKey(secureEnclave: Bool) throws -> SecKey {
        var error: Unmanaged<CFError>?

        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &error
        )
        if access == nil {
            let msg = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "unknown"
            throw SignerKeyError.keyGenerationFailed("accessControl: \(msg)")
        }

        var privateKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrAccessControl as String: access as Any,
        ]

        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateKeyAttrs,
        ]

        if secureEnclave {
            attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }

        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            let msg = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "unknown"
            throw SignerKeyError.keyGenerationFailed(msg)
        }
        return key
    }
}


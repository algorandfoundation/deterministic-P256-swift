import CommonCrypto
import CryptoKit
import Foundation
import MnemonicSwift

class DeterministicP256 {
    func genDerivedMainKeyWithBIP39(phrase: String, salt: [UInt8] = Array("liquid".utf8), iterationCount: Int = 210_000, keyLength: Int = 512) throws -> Data {
        try Mnemonic.validate(mnemonic: phrase)
        return try genDerivedMainKey(entropy: Array(phrase.utf8), salt: salt, iterationCount: iterationCount, keyLength: keyLength / 8)
    }

    func genDerivedMainKey(entropy: [UInt8], salt: [UInt8], iterationCount: Int, keyLength: Int) throws -> Data {
        var derivedKey = [UInt8](repeating: 0, count: keyLength)
        let status = CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            String(bytes: entropy, encoding: .utf8)!,
            entropy.count,
            salt,
            salt.count,
            CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512),
            UInt32(iterationCount),
            &derivedKey,
            keyLength
        )

        guard status == kCCSuccess else {
            throw NSError(domain: "CommonCryptoError", code: Int(status), userInfo: nil)
        }

        return Data(derivedKey)
    }

    func genDomainSpecificKeyPair(derivedMainKey: Data, origin: String, userId: String, counter: UInt32 = 0) -> P256.Signing.PrivateKey {
        var concat = Data()
        concat.append(derivedMainKey)
        concat.append(contentsOf: Array(origin.utf8))
        concat.append(contentsOf: Array(userId.utf8))

        let counterBytes = withUnsafeBytes(of: counter.bigEndian, Array.init)
        concat.append(contentsOf: counterBytes)

        // Calculate SHA-512 hash using CommonCrypto
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        concat.withUnsafeBytes {
            _ = CC_SHA512($0.baseAddress, CC_LONG(concat.count), &hash)
        }

        // Keeping the first 32 bytes of the digest as with BouncyCastle
        let seed = Data(hash.prefix(32))

        let privateKey = try! P256.Signing.PrivateKey(rawRepresentation: seed)
        return privateKey
    }

    func signWithDomainSpecificKeyPair(keyPair: P256.Signing.PrivateKey, payload: Data) throws -> P256.Signing.ECDSASignature {
        try keyPair.signature(for: payload)
    }

    // Method introduced to have API parity with the Kotlin implementation
    // In the current Swift implementation, the public key is simple to retrieve in raw represetnation as opposed to DER representation.
    // This method will return the exact same bytes as the equivalent getPurePKBytes in the Kotlin implementation will return.
    func getPurePKBytes(keyPair: P256.Signing.PrivateKey) -> [UInt8] {
        [UInt8](keyPair.publicKey.rawRepresentation)
    }
}

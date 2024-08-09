import CommonCrypto
import CryptoKit
import Foundation
import MnemonicSwift

class DeterministicP256 {
    /**
     Generates a derived main key using a BIP39 mnemonic phrase.

     This function validates the provided BIP39 mnemonic phrase and then derives a main key using the specified parameters.
     The derived key is generated using the PBKDF2 key derivation function with HMAC-SHA256.

     - Parameters:
        - phrase: A BIP39 mnemonic phrase used as the entropy source for key derivation.
        - salt: An optional salt value used in the key derivation process. Defaults to the UTF-8 encoded string "liquid".
        - iterationCount: The number of iterations to perform in the key derivation process. Defaults to 210,000.
        - keyLength: The desired length of the derived key in bits. Defaults to 512 bits.

     - Returns: A `Data` object containing the derived key.

     - Throws: An error if the mnemonic phrase is invalid or if the key derivation process fails.

     - Note: The `keyLength` parameter is integer divided by 8 internally to convert the length from bits to full bytes.
     */
    func genDerivedMainKeyWithBIP39(
        phrase: String,
        salt: [UInt8] = Array("liquid".utf8),
        iterationCount: Int = 210_000,
        keyLength: Int = 512
    ) throws -> Data {
        // Validate the key length
        guard keyLength % 8 == 0 else {
            throw NSError(
                domain: "InvalidKeyLength",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Key length must be divisible by 8.",
                ]
            )
        }
        try Mnemonic.validate(mnemonic: phrase)
        return try genDerivedMainKey(
            entropy: Array(phrase.utf8),
            salt: salt,
            iterationCount: iterationCount,
            keyLengthBytes: keyLength / 8
        )
    }

    /**
     Generates a derived key using the PBKDF2 key derivation function with HMAC-SHA512.

     This function derives a key from the provided entropy and salt using the specified iteration count and key length.
     The derived key is generated using the PBKDF2 key derivation function with HMAC-SHA512.

     - Parameters:
        - entropy: An array of bytes representing the entropy source for key derivation.
        - salt: An array of bytes representing the salt value used in the key derivation process.
        - iterationCount: The number of iterations to perform in the key derivation process.
        - keyLength: The desired length of the derived key in bytes.

     - Returns: A `Data` object containing the derived key.

     - Throws: An error if the key derivation process fails.

     - Note: The `keyLength` parameter specifies the length of the derived key in bytes.
     */
    func genDerivedMainKey(
        entropy: [UInt8],
        salt: [UInt8],
        iterationCount: Int,
        keyLengthBytes: Int
    ) throws -> Data {
        var derivedKey = [UInt8](repeating: 0, count: keyLengthBytes)
        let status = CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            String(bytes: entropy, encoding: .utf8)!,
            entropy.count,
            salt,
            salt.count,
            CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512),
            UInt32(iterationCount),
            &derivedKey,
            keyLengthBytes
        )

        guard status == kCCSuccess else {
            throw NSError(
                domain: "CommonCryptoError",
                code: Int(status),
                userInfo: nil
            )
        }

        return Data(derivedKey)
    }

    /**
     Generates a domain-specific key pair using a derived main key, origin, user ID, and an optional counter.

     This function concatenates the provided derived main key, origin, user ID, and counter to create a unique input.
     It then calculates the SHA-512 hash of this input and uses the first 32 bytes of the hash as the seed to
     generate a P256 private key. The origin and userId are meant to correspond to their WebAuthn counterparts
     but they can be any strings that help to uniquely identify the key pair.

     - Parameters:
        - derivedMainKey: A `Data` object representing the derived main key.
        - origin: A `String` representing the origin or domain for which the key pair is being generated.
        - userId: A `String` representing the user ID.
        - counter: An optional `UInt32` counter to ensure uniqueness. Defaults to 0.

     - Returns: A `P256.Signing.PrivateKey` object representing the generated private key.

     - Throws: This function uses a force-try (`try!`) when creating the private key, which will cause
     a runtime error if the key generation fails.

     - Note: The SHA-512 hash is calculated using the CommonCrypto library, and only the first 32 bytes of the hash
     are used as the seed for the private key, similar to BC in the Kotlin implementation. Certain java.security providers
     accept 40 bytes of seed but we explictly ensure it is 32 bytes.
     */
    func genDomainSpecificKeyPair(
        derivedMainKey: Data,
        origin: String,
        userId: String,
        counter: UInt32 = 0
    ) -> P256.Signing.PrivateKey {
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

    /**
      Signs a payload using a domain-specific key pair.

      This function takes a P256 private key and a payload, and generates an ECDSA signature for the
      payload using the private key.

      We call P256.Signing.PrivateKey a keypair because it can produce its own public key.
      In general, it is good to minimize the risk of pairing a private key with the wrong public key.

     - Parameters:
     - keyPair: A `P256.Signing.PrivateKey` object representing the domain-specific private key.
     - payload: A `Data` object representing the payload to be signed.

     - Returns: A `P256.Signing.ECDSASignature` object representing the generated signature.

     - Throws: An error if the signing process fails.

     - Note: The signature is generated using the ECDSA algorithm with the P256 curve.
     */
    func signWithDomainSpecificKeyPair(keyPair: P256.Signing.PrivateKey,
                                       payload: Data) throws -> P256.Signing
        .ECDSASignature
    {
        try keyPair.signature(for: payload)
    }

    /**
     Retrieves the raw public key bytes from a P256 private key.

     This method provides API parity with the Kotlin implementation.

     In the current Swift implementation, the public key is simple to retrieve in raw representation
     as opposed to DER representation. This method returns the exact same bytes as the equivalent `getPurePKBytes`
     method in the Kotlin implementation.

     - Parameters:
        - keyPair: A `P256.Signing.PrivateKey` object representing the private key from which to extract the public key bytes.

     - Returns: An array of `UInt8` containing the raw public key bytes.
     */
    func getPurePKBytes(keyPair: P256.Signing.PrivateKey) -> [UInt8] {
        [UInt8](keyPair.publicKey.rawRepresentation)
    }
}

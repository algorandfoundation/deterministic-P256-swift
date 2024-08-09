import CryptoKit
import MnemonicSwift
import XCTest

@testable import deterministicP256_swift

class DeterministicP256Test: XCTestCase {
    var D: DeterministicP256!

    override func setUp() {
        super.setUp()
        D = DeterministicP256()
    }

    func testValidSeedPhrase() throws {
        let derivedMainKey = try D.genDerivedMainKeyWithBIP39(
            phrase: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
        )

        XCTAssertEqual(
            derivedMainKey.map { $0 },
            [26, 210, 186, 151, 53, 65, 255, 61, 98, 59, 90, 130, 148, 59, 107, 10, 194, 93, 176, 122, 14, 170, 38, 239, 224, 214, 228, 123, 221, 66, 119, 214, 69, 38, 18, 110, 77, 232, 226, 226, 217, 153, 123, 0, 219, 119, 52, 218, 43, 42, 24, 225, 70, 188, 11, 77, 200, 199, 211, 141, 75, 164, 35, 226]
        )
        //  Kotlin: [26,-46,-70,-105,53,65,-1,61,98,59,90,-126,-108,59,107,10,-62,93,-80,122,14,-86,38,-17,-32,-42,-28,123,-35,66,119,-42,69,38,18,110,77,-24,-30,-30,-39,-103,123,0,-37,119,52,-38,43,42,24,-31,70,-68,11,77,-56,-57,-45,-115,75,-92,35,-30]

        // Test default parameters
        let derivedMainKeyFixedParams = try D.genDerivedMainKeyWithBIP39(
            phrase: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice",
            salt: Array("liquid".utf8),
            iterationCount: 210_000,
            keyLength: 512
        )

        XCTAssertEqual(
            derivedMainKey.map { $0 },
            derivedMainKeyFixedParams.map { $0 }
        )

        // Test with non-default parameters
        let derivedMainKeyNonDef = try D.genDerivedMainKeyWithBIP39(
            phrase: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice",
            iterationCount: 600_000
        )

        XCTAssertEqual(
            derivedMainKeyNonDef.map { $0 },
            [169, 35, 83, 123, 147, 61, 98, 116, 221, 56, 176, 155, 108, 205, 5, 194, 85, 56, 156, 40, 182, 57, 121, 85, 226, 240, 37, 224, 34, 154, 143, 28, 111, 253, 160, 88, 220, 119, 255, 18, 63, 171, 78, 83, 183, 188, 177, 187, 64, 136, 187, 58, 230, 94, 173, 119, 190, 168, 180, 248, 173, 189, 58, 250]
        )
        //  Kotlin:  [-87, 35, 83, 123, -109, 61, 98, 116, -35, 56, -80, -101, 108, -51, 5, -62, 85, 56, -100, 40, -74, 57, 121, 85, -30, -16, 37, -32, 34, -102, -113, 28, 111, -3, -96, 88, -36, 119, -1, 18, 63, -85, 78, 83, -73, -68, -79, -69, 64, -120, -69, 58, -26, 94, -83, 119, -66, -88, -76, -8, -83, -67, 58, -6]
    }

    func testInvalidSeedPhrases() {
        XCTAssertThrowsError(try D.genDerivedMainKeyWithBIP39(
            phrase: "zoo zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
        )) { error in
            XCTAssertEqual(error as? MnemonicSwift.MnemonicError, MnemonicSwift.MnemonicError.checksumError)
        }

        XCTAssertThrowsError(try D.genDerivedMainKeyWithBIP39(
            phrase: "algorand zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
        )) { error in
            XCTAssertEqual(error as? MnemonicSwift.MnemonicError, MnemonicSwift.MnemonicError.unsupportedLanguage)
        }
    }

    func testGenDerivedMainKeyThrowsError() {
        // Invalid parameters to trigger the error
        XCTAssertThrowsError(try D.genDerivedMainKey(entropy: [], salt: [], iterationCount: 0, keyLengthBytes: 32)) { error in
            // Verify that the error is of the expected type and domain
            let nsError = error as NSError
            XCTAssertEqual(nsError.domain, "CommonCryptoError")
        }

        XCTAssertThrowsError(try D.genDerivedMainKey(entropy: [], salt: [], iterationCount: 1000, keyLengthBytes: 0)) { error in
            // Verify that the error is of the expected type and domain
            let nsError = error as NSError
            XCTAssertEqual(nsError.domain, "CommonCryptoError")
        }

        // Invalid key length, not multiple of 8
        XCTAssertThrowsError(try D.genDerivedMainKeyWithBIP39(
            phrase: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice", salt: Array("liquid".utf8), iterationCount: 210_000, keyLength: 511
        )) { error in
            // Verify that the error is of the expected type and domain
            let nsError = error as NSError
            XCTAssertEqual(nsError.domain, "InvalidKeyLength")
        }
    }

    func testKeyPairGeneration() throws {
        let derivedMainKey = try D.genDerivedMainKeyWithBIP39(
            phrase: "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
        )

        // Example values taken from: https://webauthn.guide/#registration
        let origin = "https://webauthn.guide"
        let userId = "a2bd8bf7-2145-4a5a-910f-8fdc9ef421d3"

        let keyPair = D.genDomainSpecificKeyPair(derivedMainKey: derivedMainKey, origin: origin, userId: userId)
        let keyPair0 = D.genDomainSpecificKeyPair(derivedMainKey: derivedMainKey, origin: origin, userId: userId, counter: 0)
        let keyPair1 = D.genDomainSpecificKeyPair(derivedMainKey: derivedMainKey, origin: origin, userId: userId, counter: 1)

        // Check generated public key against hardcoded value
        XCTAssertEqual(
            keyPair.publicKey.rawRepresentation.map { $0 },
            [55, 133, 168, 32, 86, 59, 61, 35, 82, 221, 57, 185, 59, 244, 100, 95, 233, 134, 87, 60, 213, 197, 188, 118, 182, 82, 171, 97, 186, 196, 228, 183, 222, 170, 59, 65, 219, 148, 165, 120, 41, 161, 169, 255, 220, 188, 184, 178, 144, 95, 134, 97, 105, 144, 174, 152, 235, 19, 98, 207, 114, 59, 129, 76],
            "Public key should match hardcoded value!"
        )

        // Test getPurePKBytes is the exact same as the hardcoded value, which needs to match what is defined in the Kotlin implementation
        XCTAssertEqual(
            D.getPurePKBytes(keyPair: keyPair),
            [55, 133, 168, 32, 86, 59, 61, 35, 82, 221, 57, 185, 59, 244, 100, 95, 233, 134, 87, 60, 213, 197, 188, 118, 182, 82, 171, 97, 186, 196, 228, 183, 222, 170, 59, 65, 219, 148, 165, 120, 41, 161, 169, 255, 220, 188, 184, 178, 144, 95, 134, 97, 105, 144, 174, 152, 235, 19, 98, 207, 114, 59, 129, 76],
            "getPurePKBytes output should match hardcoded value!"
        )

        // Test to ensure that the SHA256 hash of the public key is the same as the hardcoded value
        // This is important because we calculate the FIDO2 Credential ID wiht the SHA256 hash of the public key,
        // and we need to be sure that it is detereministically produced the same way across implementations.
        // The hardcoded value must be the same as in the Kotlin implementation.
        let credentialId = SHA256.hash(data: D.getPurePKBytes(keyPair: keyPair)).withUnsafeBytes { Array($0) }
        XCTAssertEqual(
            credentialId,
            [68, 16, 96, 30, 9, 106, 51, 209, 13, 172, 129, 212, 92, 243, 104, 10, 187, 137, 127, 0, 116, 65, 39, 241, 213, 70, 2, 152, 6, 21, 128, 2],
            "SHA256 (CredentialId) digest must match hardcoded output!"
        )

        // Check default counter value and that the same key is generated deterministically twice in a row
        XCTAssertEqual(
            keyPair.publicKey.rawRepresentation.map { $0 },
            keyPair0.publicKey.rawRepresentation.map { $0 },
            "Keys with the same counter value should be the same!"
        )

        // Check that different counter values produce different keys
        XCTAssertNotEqual(
            keyPair.publicKey.rawRepresentation.map { $0 },
            keyPair1.publicKey.rawRepresentation.map { $0 },
            "Keys with different counter values should be different!"
        )

        // Additional check of the same key generation
        XCTAssertEqual(
            keyPair1.publicKey.rawRepresentation.map { $0 },
            D.genDomainSpecificKeyPair(derivedMainKey: derivedMainKey, origin: origin, userId: userId, counter: 1).publicKey.rawRepresentation.map { $0 },
            "Keys with the same counter value should be the same!"
        )

        let message = "Hello, World!".data(using: .utf8)!
        let signature = try D.signWithDomainSpecificKeyPair(keyPair: keyPair, payload: message)

        // Note that ECDSA signatures are non-deterministic (see ECDSA nonce-reuse attack) so they cannot be compared across rounds of tests.

        // Check that the signature is valid
        let isValidSignature = keyPair.publicKey.isValidSignature(signature, for: message)
        XCTAssertTrue(isValidSignature, "Signature should be valid!")

        // Check that signature is invalid
        let isInvalidSignature = keyPair.publicKey.isValidSignature(signature, for: message + Data([0]))
        XCTAssertTrue(!isInvalidSignature, "Signature should be invalid!")

        // Check that signature from Kotlin implementation is valid
        // The following is a raw representation of a signature produced by the Kotlin library
        let kotlinEncodedSignatureRaw = Data([65, 164, 226, 18, 183, 119, 96, 135, 8, 19, 123, 131, 32, 119, 160, 173, 128, 63, 145, 106, 124, 69, 48, 89, 188, 36, 160, 255, 222, 39, 63, 174, 96, 119, 49, 105, 241, 166, 95, 231, 87, 58, 17, 145, 182, 41, 230, 145, 106, 86, 97, 179, 191, 186, 241, 254, 167, 134, 75, 43, 18, 248, 145, 76])
        let kotlinSignatureRaw = try P256.Signing.ECDSASignature(rawRepresentation: kotlinEncodedSignatureRaw)
        let isValidKotlinSignatureRaw = keyPair.publicKey.isValidSignature(kotlinSignatureRaw, for: message)
        XCTAssertTrue(isValidKotlinSignatureRaw, "Kotlin Signature should be valid!")

        // The following is a Distinguished Encoding Rules (DER) presentation of a signature produced by the Kotlin library
        let kotlinEncodedSignatureDER = Data([48, 70, 2, 33, 0, 197, 237, 187, 26, 0, 188, 188, 165, 237, 199, 171, 162, 180, 37, 159, 47, 137, 106, 13, 161, 205, 197, 103, 36, 26, 159, 134, 203, 164, 240, 188, 20, 2, 33, 0, 197, 35, 129, 35, 19, 199, 158, 157, 191, 92, 151, 174, 163, 161, 250, 27, 237, 203, 45, 51, 25, 124, 229, 215, 223, 230, 18, 252, 194, 39, 140, 49])
        let kotlinSignatureDER = try P256.Signing.ECDSASignature(derRepresentation: kotlinEncodedSignatureDER)
        let isValidKotlinSignatureDER = keyPair.publicKey.isValidSignature(kotlinSignatureDER, for: message)
        XCTAssertTrue(isValidKotlinSignatureDER, "Kotlin Signature should be valid!")
    }
}

// Makes MnemonicError from MnemonicSwift equatable for testing, so it can be used in XCTAssertEqual
extension MnemonicSwift.MnemonicError: Equatable {
    public static func == (lhs: MnemonicSwift.MnemonicError, rhs: MnemonicSwift.MnemonicError) -> Bool {
        switch (lhs, rhs) {
        case (.checksumError, .checksumError):
            true
        case (.unsupportedLanguage, .unsupportedLanguage):
            true
        // Add other cases if there are more error types
        default:
            false
        }
    }
}

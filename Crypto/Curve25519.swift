//
//  Curve25519.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/11.
//

import Foundation
import CryptoKit


extension Data {
    /// Returns cryptographically secure random data.
    ///
    /// - Parameter length: Length of the data in bytes.
    /// - Returns: Generated data of the specified length.
    static func random(length: Int) throws -> Data {
        return Data((0 ..< length).map { _ in UInt8.random(in: UInt8.min ... UInt8.max) })
    }
}


class Curve25519Test {
    func sign() {
        
        let signingKey = Curve25519.Signing.PrivateKey()
        
        // Get a data representation of the public key.
        let signingPublicKey = signingKey.publicKey
        let signingPublicKeyData = signingPublicKey.rawRepresentation
        
        // Initialize a public key from its raw representation.
        let initializedSigningPublicKey = try! Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKeyData)
        
        // Use the private key to generate a signature.
        let dataToSign = "Some sample Data to sign.".data(using: .utf8)!
        let signature = try! signingKey.signature(for: dataToSign)
        
        // Verify the signature with the public key.
        if initializedSigningPublicKey.isValidSignature(signature, for: dataToSign) {
            print("The signature is valid.")
        }
    }
    
    private func testKey() throws {
        let keys = try Data.random(length: 32)
        let bytes = keys.bytes
        
        print(keys)
        
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: keys)
        let publicKey2 = try Curve25519.Signing.PublicKey(rawRepresentation: bytes)
        
        print(publicKey)
        print(publicKey2)
    }
    
    func generateKeys() -> (publicKey: String, privateKey: String){
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let clientPublicKeyString = "-----BEGIN PUBLIC KEY-----\(publicKey.rawRepresentation.base64EncodedString())-----END PUBLIC KEY-----"
        print(clientPublicKeyString)
        let clientPrivateKeyString = "-----BEGIN PRIVATE KEY-----\(privateKey.rawRepresentation.base64EncodedString(options: .lineLength64Characters))-----END PRIVATE KEY-----\r\n"
        print(clientPrivateKeyString)
        return (clientPublicKeyString,clientPrivateKeyString)
    }
}

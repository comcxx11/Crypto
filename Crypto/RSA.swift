//
//  RSA.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/11.
//

import Foundation
import CryptoSwift

class RSATest {
    
    private func rsaInit() throws {
        let input: Array<UInt8> = [0,1,2,3,4,5,6,7,8,9]

        let n: Array<UInt8> = "0".bytes // RSA modulus
        let e: Array<UInt8> = "0".bytes // RSA public exponent
        let d: Array<UInt8> = "0".bytes // RSA private exponent

        let rsa = RSA(n: n, e: e, d: d)

        do {
            let encrypted = try rsa.encrypt(input)
            let decrypted = try rsa.decrypt(encrypted)
            print(decrypted)
        } catch {
            print(error)
        }
    }
    
    private func rsaEncryptionAndDecryption() throws {
        // Alice Generates a Private Key
        let alicesPrivateKey = try RSA(keySize: 1024)
        
        // Alice shares her **public** key with Bob
        let alicesPublicKeyData = try alicesPrivateKey.publicKeyExternalRepresentation()
        
        // Bob receives the raw external representation of Alices public key and imports it
        let bobsImportOfAlicesPublicKey = try RSA(rawRepresentation: alicesPublicKeyData)
        
        // Bob can now encrypt a message for Alice using her public key
        let message = "Hi Alice! This is Bob!"
        let privateMessage = try bobsImportOfAlicesPublicKey.encrypt(message.bytes)
        
        // This results in some encrypted output like this
        // URcRwG6LfH63zOQf2w+HIllPri9Rb6hFlXbi/bh03zPl2MIIiSTjbAPqbVFmoF3RmDzFjIarIS7ZpT57a1F+OFOJjx50WYlng7dioKFS/rsuGHYnMn4csjCRF6TAqvRQcRnBueeINRRA8SLaLHX6sZuQkjIE5AoHJwgavmiv8PY=
        
        // Bob can now send this encrypted message to Alice without worrying about people being able to read the original contents
        
        // Alice receives the encrypted message and uses her private key to decrypt the data and recover the original message
        let originalDecryptedMessage = try alicesPrivateKey.decrypt(privateMessage)
        
        print(String(data: Data(originalDecryptedMessage), encoding: .utf8) ?? "")
        // "Hi Alice! This is Bob!"
    }
    
    private func rsaSignatureAndVerification() throws {
        // Alice Generates a Private Key
        let alicesPrivateKey = try RSA(keySize: 1024)
        
        // Alice wants to sign a message that she agrees with
        let messageAliceSupports = "Hi my name is Alice!"
        let alicesSignature = try alicesPrivateKey.sign(messageAliceSupports.bytes)
        
        // Alice shares her Public key and the signature with Bob
        let alicesPublicKeyData = try alicesPrivateKey.publicKeyExternalRepresentation()
        
        // Bob receives the raw external representation of Alices Public key and imports it!
        let bobsImportOfAlicesPublicKey = try RSA(rawRepresentation: alicesPublicKeyData)
        
        // Bob can now verify that Alice signed the message using the Private key associated with her shared Public key.
        let verifiedSignature = try bobsImportOfAlicesPublicKey.verify(signature: alicesSignature, for: "Hi my name is Alice!".bytes)
        
        if verifiedSignature == true {
            // Bob knows that the signature Alice provided is valid for the message and was signed using the Private key associated with Alices shared Public key.
            print("true")
        } else {
            // The signature was invalid, so either
            // - the message Alice signed was different then what we expected.
            // - or Alice used a Private key that isn't associated with the shared Public key that Bob has.
            print("false")
        }
    }
    
    private func cryptoRsaToAppleRsa() throws {
        /// Starting with a CryptoSwift RSA Key
        let rsaKey = try RSA(keySize: 1024)

        /// Define your Keys attributes
        let attributes: [String:Any] = [
          kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
          kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, // or kSecAttrKeyClassPublic
          kSecAttrKeySizeInBits as String: 1024, // The appropriate bits
          kSecAttrIsPermanent as String: false
        ]
        var error:Unmanaged<CFError>? = nil
        guard let rsaSecKey = try SecKeyCreateWithData(rsaKey.externalRepresentation() as CFData, attributes as CFDictionary, &error) else {
          /// Error constructing SecKey from raw key data
          return
        }

        /// You now have an RSA SecKey for use with Apple's Security framework
        
        print(rsaSecKey)
    }
    
    private func appleRsaToCryptoRsa() throws {
//        /// Starting with a SecKey RSA Key
//        let rsaSecKey:SecKey
//
//        /// Copy External Representation
//        var externalRepError:Unmanaged<CFError>?
//        guard let cfdata = SecKeyCopyExternalRepresentation(rsaSecKey, &externalRepError) else {
//          /// Failed to copy external representation for RSA SecKey
//          return
//        }
//
//        /// Instantiate the RSA Key from the raw external representation
//        let rsaKey = try RSA(rawRepresentation: cfdata as Data)
//
//        /// You now have a CryptoSwift RSA Key
//
//        print(rsaKey)
    }
}

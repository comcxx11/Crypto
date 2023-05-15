//
//  P256Curve_Test.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/15.
//

import Foundation
import CryptoKit

// P256, P348, P521, Curve25519 알고리즘

class Test {
    static func run() throws {
        let privateKey = P521.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let messageDigest = "aewfkajwekfj".data(using: .utf8)!
        
        let signature = try privateKey.signature(for: messageDigest)
        let b = publicKey.isValidSignature(signature, for: messageDigest)
        
        print(b)
        
        let hashedPassword = SHA256.hash(data: messageDigest)
        print(hashedPassword)
        
        // 대칭키 생성
        print("01234567890123450123456789012345".count) // 32
        let base64EncodedKeyString = "01234567890123450123456789012345".data(using: .utf8)?.base64EncodedData()
        let keyData = Data(base64Encoded: base64EncodedKeyString!)!
        let symmetricKey = SymmetricKey(data: keyData)
        
        let msg = "hello Word!!!".data(using: .utf8)!
        
        // ChaCha20-Poly 1305
        let encryptedData = try ChaChaPoly.seal(msg, using: symmetricKey).combined
        let sealedBox = try ChaChaPoly.SealedBox(combined: encryptedData)
        let decrytedData = try ChaChaPoly.open(sealedBox, using: symmetricKey)
        
        // AES-GCM
        let encryptedData2 = (try AES.GCM.seal(msg, using: symmetricKey).combined)!
        let sealedBox2 = try AES.GCM.SealedBox(combined: encryptedData2)
        let decrytedData2 = try AES.GCM.open(sealedBox2, using: symmetricKey)
        
        if let myMsg = String(data: decrytedData, encoding: .utf8) {
            print(myMsg)
        }
        
        if let myMsg = String(data: decrytedData2, encoding: .utf8) {
            print(myMsg)
        }
        
//        let authenticationCode = HMAC<SHA512>.authenticationCode(for: msg, using: symmetricKey)
//
//        let isValid = HMAC<SHA512>.isValidAuthenticationCode(<#T##mac: HMAC<SHA512>.MAC##HMAC<SHA512>.MAC#>, authenticating: <#T##UnsafeRawBufferPointer#>, using: <#T##SymmetricKey#>)
    }
}

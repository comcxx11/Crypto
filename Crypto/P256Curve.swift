//
//  P256Curve.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/12.
//

import Foundation
import CryptoKit

class P256Curve {
    static func run() throws {
    
        // Alice와 Bob의 비밀키 생성
        let alicePrivateKey = P256.KeyAgreement.PrivateKey()
        let bobPrivateKey = P256.KeyAgreement.PrivateKey()

        // Alice와 Bob의 공개키 생성
        let alicePublicKey = alicePrivateKey.publicKey
        let bobPublicKey = bobPrivateKey.publicKey
        
        print(alicePublicKey.rawRepresentation.base64EncodedString())
        print(bobPublicKey.rawRepresentation.base64EncodedString())
        
        // Create a shared secret using someone else's public key.
        let base64String = alicePublicKey.rawRepresentation.base64EncodedString()

        if let publicKeyData = Data(base64Encoded: base64String),
           let publicKey = try? P256.KeyAgreement.PublicKey(x963Representation: publicKeyData) {
            // publicKey 사용
            print(publicKey)
        } else {
            // base64 디코딩 실패 또는 PublicKey 생성 실패
            print("base64 디코딩 실패 또는 PublicKey 생성 실패")
        }
        
        let shared1 = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
        
        let shared2 = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey)
        
        // 공유 비밀키 확인
        print(shared1)
        print(shared2)
        print("shared1 == shared2 동일한 공유키 : \(shared1 == shared2)")
        
        // Derive a symmetric key from the shared secret.
        // HKDF(HMAC-based Key Derivation Function)
        let symmetricKey = shared1.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        )
        
        print(symmetricKey)
        
        do {
            try printPayload(symmetricKey: symmetricKey)
        } catch {
            print(error)
        }
        
        // 단방향 암호화 (signature)
        let message = "This is a test message."
        let hmac = HMAC<SHA256>.authenticationCode(for: message.data(using: .utf8)!, using: SymmetricKey(data: shared1))
        let hmacData = Data(hmac)
        let hmacBase64 = hmacData.base64EncodedString()
        
        print("===========hmacBase64============")
        print(hmacBase64)
        print("===========hmacBase64============")
    }
    
    static func printPayload(symmetricKey: SymmetricKey) throws {
        let plaintext = "Encrypt me"
        
        // Generate a random 96-bit IV(Nonce).
        let iv = AES.GCM.Nonce()
        
        // Encrypt the plaintext using AES-GCM.
        let sealedBox = try AES.GCM.seal(
            plaintext.data(using: .utf8)!,
            using: symmetricKey,
            nonce: iv
        )
        
        let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)
        
        print("===========plaintext============")
        print(plaintext)
        print("===========ciphertext============")
        
        print("===========ciphertext============")
        print(sealedBox.ciphertext.base64EncodedString())
        print("===========ciphertext============")
        
        let decryptedText = String(data: decrypted, encoding: .utf8) ?? ""
        
        print("==========decryptedText==========")
        print(decryptedText)
        print("==========decryptedText==========")
        
        let ciphertext = sealedBox.ciphertext
        let tag = sealedBox.tag
        let message = ciphertext + tag + iv
        let base64SealedBox = message.base64EncodedString()
        
        print("===========printPayload============")
        print(base64SealedBox)
        print("===========printPayload============")
        
        // Decrypt the message using the same key
        let sealedBoxFromMessage = try AES.GCM.SealedBox(combined: message)
        let decryptedData = try AES.GCM.open(sealedBoxFromMessage, using: symmetricKey)

        // Decode the decrypted plaintext
        let decryptedPlaintext = String(data: decryptedData, encoding: .utf8)!
        print(decryptedPlaintext) // "My secret message"
    }
}

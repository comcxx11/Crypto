//
//  ViewController.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/11.
//

import UIKit
import Security
import CryptoKit
import CryptoSwift

// https://www.kodeco.com/10846296-introducing-cryptokit
// Curve25519

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        do {
            try CBC()
        } catch {
            print(error)
        }
    }
    
    private func CBC() throws {
        let plainText = "Hello World"
        
        // 사용자 1와 사용자 2의 비밀키 생성
        let user1_privateKey = P256.KeyAgreement.PrivateKey()
        let user2_privateKey = P256.KeyAgreement.PrivateKey()

        // 사용자 2의 공개키 생성
        let user2_publicKey = user2_privateKey.publicKey

        // ECDH 공유키 계산
        let sharedSecret = try user1_privateKey.sharedSecretFromKeyAgreement(with: user2_publicKey)
        
        // HKDF 인스턴스 생성 (대칭키 32바이트 문자열 생성)
        let symmetricKeyData = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32
        ).withUnsafeBytes { Data(Array($0)) }
        
        do {
            let ivDecodes : Array<UInt8> = Array("0123456789012345".utf8)
            let a = try AES(key: symmetricKeyData.bytes, blockMode: CryptoSwift.CBC(iv: ivDecodes), padding: .pkcs5)
            let b = try a.encrypt(plainText.bytes)
            print(b.toBase64())
            let datas = Data(base64Encoded: b.toBase64())
            let result = try a.decrypt(datas!.bytes)
            
            print(String(bytes: result, encoding: .utf8) ?? "")
        } catch {
            print(error)
        }
    }
    
    private func CBC_prefix() {
        // Alice와 Bob의 비밀키 생성
        let alicePrivateKey = P256.KeyAgreement.PrivateKey()
        let bobPrivateKey = P256.KeyAgreement.PrivateKey()

        // Alice와 Bob의 공개키 생성
        // let alicePublicKey = alicePrivateKey.publicKey
        let bobPublicKey = bobPrivateKey.publicKey
        
        let iv = "0123456789012345"
        let protocolSalt = "Hello, playground".data(using: .utf8)!
        let message = "A"
        
        // AES.CBC
        do {
            let shared1 = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
            
            let symmetricKey = shared1.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: protocolSalt,
                sharedInfo: Data(),
                outputByteCount: 32
            )
            
            // 스위프트에서 공유 비밀키를 사용하여 대칭형 문자열을 만드는 방법은 여러가지가 있습니다.
            // 대표적으로 HMAC, AES, ChaCha20등의 알고리즘이 있습니다.
            let symmetricKeyData = symmetricKey.withUnsafeBytes { Data(Array($0)) }
            let symmetricKeyString = symmetricKeyData.base64EncodedString().prefix(32)
            
            print(symmetricKeyString.count)
            print(symmetricKeyString)
            
            let chiperText = AES256Util.encrypt(string: message, key: String(symmetricKeyString), iv: iv)
            let plainText = AES256Util.decrypt(encoded: chiperText, key: String(symmetricKeyString), iv: iv)
            
            print("AES.CBC chiper text  : \(chiperText)")
            print("AES.CBC plain text   : \(plainText)")
        } catch {
            print(error)
        }
        
    }
    
    private func GCM(withNonce: Bool) {
        // Alice와 Bob의 비밀키 생성
        let alicePrivateKey = P256.KeyAgreement.PrivateKey()
        let bobPrivateKey = P256.KeyAgreement.PrivateKey()

        // Alice와 Bob의 공개키 생성
        // let alicePublicKey = alicePrivateKey.publicKey
        let bobPublicKey = bobPrivateKey.publicKey
        
        let protocolSalt = "Hello, playground".data(using: .utf8)!
        let message = "A"
        
        // AES.GCM
        do {
            let shared1 = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
            
            let symmetricKey = shared1.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: protocolSalt,
                sharedInfo: Data(),
                outputByteCount: 32
            )
            
            var encryptData: CryptoKit.AES.GCM.SealedBox?
            if withNonce {
                // Generate a random 96-bit IV(Nonce).
                let iv = AES.GCM.Nonce()
                encryptData = try AES.GCM.seal(message.data(using: .utf8)!, using: symmetricKey, nonce: iv)
            } else {
                encryptData = try AES.GCM.seal(message.data(using: .utf8)!, using: symmetricKey)
            }
            
            // 암호문 추출
            let chiperText = encryptData!.ciphertext
            
            // 인증 태그 추출
            let authenticationTag = encryptData!.tag
            
            let sealedBox = try AES.GCM.open(encryptData!, using: symmetricKey)
            
            let plainText = String(data: sealedBox, encoding: .utf8) ?? ""
            
            print("Ciphertext: \(chiperText.base64EncodedString())")
            print("Authentication Tag: \(authenticationTag.base64EncodedString())")
            print("AES.GCM plain text   : \(plainText)")
        } catch {
            print(error)
        }
        
    }
    
}



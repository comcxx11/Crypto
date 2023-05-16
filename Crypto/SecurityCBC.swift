//
//  SecurityCBC.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/16.
//

import Foundation
import CryptoSwift

class SecurityCBC {
    
    // ECDH 키 쌍 생성 (Security 사용)
    func generateECDHKeyPair() throws -> (privateKey: SecKey, publicKey: SecKey) {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, nil) else {
            throw NSError(domain: "com.example", code: -1, userInfo: [NSLocalizedDescriptionKey: "ECDH 키 쌍 생성에 실패했습니다."])
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw NSError(domain: "com.example", code: -1, userInfo: [NSLocalizedDescriptionKey: "공개 키를 가져올 수 없습니다."])
        }

        return (privateKey, publicKey)
    }

    
    // 공유 키 생성
    func generateSharedKey(privateKey: SecKey, publicKey: SecKey) throws -> Data {
        // let keySize = 256 // 원하는 공유 키의 비트 길이

//        let parameters: [CFString: Any] = [
//            kSecKeyKeyExchangeParameterRequestedSize : keySize
//        ]
        
//        let parameters: [String: Any] = [
//            kSecKeyKeyExchangeParameterRequestedSize as String: 256
//        ]

        var error: Unmanaged<CFError>?
        guard let sharedSecret = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeStandard, publicKey, [:] as CFDictionary, &error) else {
            if let error = error?.takeRetainedValue() {
                throw error as Error
            } else {
                throw NSError(domain: "com.example", code: -1, userInfo: [NSLocalizedDescriptionKey: "공유 키 생성에 실패했습니다."])
            }
        }
        
        return sharedSecret as Data
    }
    
    
    // 16비트 난수 생성
    func generateRandomUInt16() -> UInt16 {
        return UInt16(arc4random_uniform(UInt32(UInt16.max)))
    }
    
    public func HMAC_Test2(key: Array<UInt8>) throws {
        // 테스트
        let randomValue = generateRandomUInt16()
        print("16비트 난수: \(randomValue)")
        
        let hmac = CryptoSwift.HMAC(key: key, variant: HMAC.Variant.sha2(SHA2.Variant.sha256))
        let hashedData = try hmac.authenticate(key)
        
        let hashedString = hashedData.toHexString()
        
        print(hashedString)
    }
}


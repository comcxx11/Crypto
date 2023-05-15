//
//  iOS_Android.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/15.
//

import Foundation
import CommonCrypto
import CryptoSwift
import CryptoKit

class iOS_Android {
    static let sharedKey = "f8jdsd5fhk9d1r5jkx1sh7d"
    
    static let message = "Send Patrick 1000€"
    
    static func run() {
        let hash = message.hmac(key: sharedKey)
        print(hash)
    }
    
    static func test() {
        
    }
}

extension String {
    func hmac(key: String) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA512), key, key.count, self, self.count, &digest)
        let data = Data(digest)
        return data.base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0))
    }
}


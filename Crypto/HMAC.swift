//
//  HMAC.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/12.
//

import Foundation
import CommonCrypto

class HMAC_TEST {
    static let secretKey = "my_secret_key"
    static let payload = "Hello, world!"
    
    static func run() {
        guard let data = payload.data(using: .utf8) else { return }
        guard let key = secretKey.data(using: .utf8) else { return }
        
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), (key as NSData).bytes, key.count, (data as NSData).bytes, data.count, &digest)

        let signature = Data.init(bytes: digest, count: digest.count).base64EncodedString()
        
        print(signature)
        
        //AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
        //Yq7fASUlKSJYG/EJ5u/AHuL775f51g9cBlzkol51Jzs=
    }
}

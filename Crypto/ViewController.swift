//
//  ViewController.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/11.
//

import UIKit
import Security

// https://www.kodeco.com/10846296-introducing-cryptokit
// Curve25519

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        do {
            try P256Curve.run()
        } catch {
            print(error)
        }
    }
    
    
    func mm() {
        
        
        let parameters: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        
        var publicKey, privateKey: SecKey?
        let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
        guard status == errSecSuccess else {
            print("Failed to generate key pair")
            return
        }
        
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey!, &error) as Data? else {
            print("Failed to get public key data: \(error!.takeRetainedValue())")
            return
        }
        
        let remotePublicKeyData: Data = "...".data(using: .utf8)!
        let remotePublicKey = SecKeyCreateWithData(remotePublicKeyData as CFData, [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ] as CFDictionary, nil)!
        
        let sharedSecret = SecKeyCopyKeyExchangeResult(privateKey!, .ecdhKeyExchangeStandard, remotePublicKey, [:] as CFDictionary, nil)!
        
        var sharedSecretData = CFDataCreateMutable(nil, 0)
        CFDataAppendBytes(sharedSecretData, CFDataGetBytePtr(sharedSecret), CFDataGetLength(sharedSecret))
        
        print(sharedSecretData)
    }
}



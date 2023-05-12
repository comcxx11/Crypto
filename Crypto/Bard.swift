//
//  Bard.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/12.
//

import Foundation
import CryptoKit

func generateECDHKeys() -> (publicKey: Curve25519.KeyAgreement.PublicKey, privateKey: Curve25519.KeyAgreement.PrivateKey) {
    let privateKey = Curve25519.KeyAgreement.PrivateKey()
    let publicKey = privateKey.publicKey
    return (publicKey: publicKey, privateKey: privateKey)
}

func generateSharedKey(publicKey: Curve25519.KeyAgreement.PublicKey, privateKey: Curve25519.KeyAgreement.PrivateKey) -> SharedSecret {
    let sharedKey = try! privateKey.sharedSecretFromKeyAgreement(with: publicKey)
    return sharedKey
}

//
//  AES_CBC_Example2.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/12.
//

import Foundation
import CommonCrypto

let inputMessage = "hello world"
let inputData:[UInt8] = Data(inputMessage.utf8).bytes

func generateRandomBytes(count: Int) -> Data? {
    var data = Data(count: count)
    let result = data.withUnsafeMutableBytes {
        SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
    }
    return result == errSecSuccess ? data : nil
}

func CBC() {
    guard let keyData = generateRandomBytes(count: kCCKeySizeAES256) else { return }
    guard let ivData = generateRandomBytes(count: kCCBlockSizeAES128) else { return }
    
    var encryptedData = Data(count: inputData.count + kCCBlockSizeAES128).bytes
    var encryptedDataCount = 0
    
    let operation = CCOperation(kCCEncrypt)
    let algorithm = CCAlgorithm(kCCAlgorithmAES)
    let options = CCOptions(kCCOptionPKCS7Padding)
    
    var keyBytes = [UInt8](keyData)
    let keyLength = size_t(kCCKeySizeAES128)
    var ivBytes = [UInt8](ivData)
    
    let dataBytes = UnsafeRawPointer(inputData)
    let dataLength = size_t(inputData.count)
    let buffer = UnsafeMutableRawPointer(mutating: encryptedData)
    
    let bufferLength = size_t(encryptedData.count)

    let status = CCCrypt(operation,
                         algorithm,
                         options,
                         &keyBytes,
                         keyLength,
                         &ivBytes,
                         dataBytes,
                         dataLength,
                         buffer,
                         bufferLength,
                         &encryptedDataCount)

//    if status == kCCSuccess {
//        encryptedData.count = encryptedDataCount
//        let encryptedMessage = encryptedData.base64EncodedString()
//        print("Encrypted message: \(encryptedMessage)")
//    } else {
//        print("Error encrypting message: \(status)")
//    }
}




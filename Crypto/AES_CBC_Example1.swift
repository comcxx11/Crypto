//
//  AES_CBC.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/12.
//

import Foundation
import CommonCrypto

enum CryptoError: Error {
    case encryptionFailed(status: Int)
    case decryptionFailed(status: Int)
}

// CBC 모드 암호화
func encryptCBC(data: Data, key: Data, iv: Data) throws -> Data {
    var outLength = 0
    var outData = Data(count: data.count + kCCBlockSizeAES128)
    let status = key.withUnsafeBytes { keyBytes in
        iv.withUnsafeBytes { ivBytes in
            data.withUnsafeBytes { dataBytes in
                outData.withUnsafeMutableBytes { outBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),                  // 암호화
                        CCAlgorithm(kCCAlgorithmAES128),         // AES 알고리즘 사용
                        CCOptions(kCCOptionPKCS7Padding),      // PKCS7 패딩 사용
                        keyBytes.baseAddress,       // 암호화에 사용할 키
                        key.count,                  // 키 길이
                        ivBytes.baseAddress,        // CBC 모드에서 사용할 초기화 벡터
                        dataBytes.baseAddress,      // 암호화할 데이터
                        data.count,                 // 데이터 길이
                        outBytes.baseAddress,       // 출력 버퍼
                        outBytes.count,             // 출력 버퍼 크기
                        &outLength                  // 출력 데이터 길이
                    )
                }
            }
        }
    }
    guard status == kCCSuccess else {
        throw CryptoError.encryptionFailed(status: Int(status))
    }
    outData.removeSubrange(outLength..<outData.count)
    return outData
}

// CBC 모드 복호화
func decryptCBC(data: Data, key: Data, iv: Data) throws -> Data {
    var outLength = 0
    var outData = Data(count: data.count + kCCBlockSizeAES128)
    let status = key.withUnsafeBytes { keyBytes in
        iv.withUnsafeBytes { ivBytes in
            data.withUnsafeBytes { dataBytes in
                outData.withUnsafeMutableBytes { outBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),                  // 복호화
                        CCAlgorithm(kCCAlgorithmAES128),         // AES 알고리즘 사용
                        CCOptions(kCCOptionPKCS7Padding),      // PKCS7 패딩 사용
                        keyBytes.baseAddress,       // 복호화에 사용할 키
                        key.count,                  // 키 길이
                        ivBytes.baseAddress,        // CBC 모드에서 사용할 초기화 벡터
                        dataBytes.baseAddress,      // 복호화할 데이터
                        data.count,                 // 데이터 길이
                        outBytes.baseAddress,       // 출력 버퍼
                        outBytes.count,             // 출력 버퍼 크기
                        &outLength                  // 출력 데이터 길이
                    )
                }
            }
        }
    }
    guard status == kCCSuccess else {
        throw CryptoError.decryptionFailed(status: Int(status))
    }
    outData.removeSubrange(outLength..<outData.count)
    return outData
}

//
//  BigLittle.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/12.
//

import Foundation

func bigLittle() {
    // 10진수 정수 값을 UInt32로 변환
    let decimalValue: UInt32 = 123

    // 16진수 문자열 값을 UInt32로 변환
    let hexValue: UInt32 = UInt32("0x1F", radix: 16) ?? 0 // 31

    // 바이너리 데이터로부터 UInt32로 변환
    let binaryData = Data([0x01, 0x02, 0x03, 0x04])
    let binaryValue: UInt32 = binaryData.withUnsafeBytes { $0.load(as: UInt32.self) } // 0x01020304

    // 빅 엔디안/리틀 엔디안으로부터 UInt32로 변환
    let bigEndianData = Data([0x12, 0x34, 0x56, 0x78])
    let bigEndianValue = bigEndianData.withUnsafeBytes { $0.load(as: UInt32.self) } // 0x12345678

    let littleEndianData = Data([0x78, 0x56, 0x34, 0x12])
    let littleEndianValue = littleEndianData.withUnsafeBytes { $0.load(as: UInt32.self) } // 0x12345678
    
    print(decimalValue, hexValue, binaryData, binaryValue)
    print(bigEndianValue, littleEndianValue)
}

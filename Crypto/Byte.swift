//
//  Byte.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/12.
//

import Foundation

func byte() {
    let data = Data([0x01, 0x02, 0x03])
    let data2 = Data([0x0A, 0x0F, 0x81, 0xFF])
    let hello = "hello".data(using: .utf8)
    let HELLO = "HELLO".data(using: .utf8)
    let 한글 = "한글".data(using: .utf8)
    print(data.bytes, data2.bytes, hello!.bytes, HELLO!.bytes, 한글!.bytes)
    
    let array = [UInt8](repeating: 255, count: 10)
    print(array) // [255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
    
    let arr: [UInt8] = Array(0...255)
    print(arr)
    
    let d = Data(arr)
    print(d) // 256byte
    
    let number = Data([255, 0xFF, 3])
    print(number, number.bytes)
}

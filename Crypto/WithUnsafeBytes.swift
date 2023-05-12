//
//  WithUnsafeBytes.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/12.
//

import Foundation

func ok() {
    let data = Data([0x01, 0x02, 0x03, 0x04])
    
    // 클로저의 인자로는 UnsafeRawBufferPointer 타입의 포인터가 전달됩니다.
    let result = data.withUnsafeBytes { (pointer: UnsafeRawBufferPointer) -> Int in
        let bytes = pointer.bindMemory(to: UInt8.self)
        print("UnsafeBufferPointer \(bytes)")
        let value = Int(bytes[0]) + Int(bytes[1]) + Int(bytes[2]) + Int(bytes[3])
        
        return value
    }
    
    print(result) // 10
}

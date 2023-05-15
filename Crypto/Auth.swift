//
//  Auth.swift
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/15.
//

import Foundation
import CryptoKit

// Custom X.509/Certificate parser
class Auth: NSObject {
    public enum AuthHashType: String {
        case MD5 = "MD5"
        case SHA1 = "SHA1"
        case SHA256 = "SHA256"
        case SHA386 = "SHA386"
        case SHA512 = "SHA512"
    }
    
    // MARK: - Object Properties
    internal static let shared = Auth()
    private let privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()
    
    // MARK: - Init
    private override init() { super.init() }
    
    // MARK: - Authentication Method
    internal func createSignature(message: Data) -> P256.Signing.ECDSASignature? {
        do {
            let authData: NSData = NSData(data: message)
            return try self.privateKey.signature(for: authData)
        } catch let error {
            print("Error, Faily Signature to Data. - \(error.localizedDescription)")
        }
        
        return nil
    }
    
    internal func createPublicKey() -> P256.Signing.PublicKey {
        return self.privateKey.publicKey
    }
    
    internal func authenticationDataWithHMAC(resource: Data, key: SymmetricKey, type: AuthHashType) -> Data {
        switch type {
            
        case .MD5:
            let authenticationCode = HMAC<Insecure.MD5>.authenticationCode(for: NSData(data: resource), using: key)
            return Data(authenticationCode)
        case .SHA1:
            let authenticationCode = HMAC<Insecure.SHA1>.authenticationCode(for: NSData(data: resource), using: key)
            return Data(authenticationCode)
        case .SHA256:
            let authenticationCode = HMAC<SHA256>.authenticationCode(for: NSData(data: resource), using: key)
            return Data(authenticationCode)
        case .SHA386:
            let authenticationCode = HMAC<SHA384>.authenticationCode(for: NSData(data: resource), using: key)
            return Data(authenticationCode)
        case .SHA512:
            let authenticationCode = HMAC<SHA512>.authenticationCode(for: NSData(data: resource), using: key)
            return Data(authenticationCode)
        }
    }
    
    @available(iOS 13.2, *)
    internal func checkValidAuthenticationDataWithHMAC(authCode: Data, resource: Data, key: SymmetricKey, type: AuthHashType) -> Bool {
        switch type {
            
        case .MD5:
            return HMAC<Insecure.MD5>.isValidAuthenticationCode(authCode, authenticating: NSData(data: resource), using: key)
        case .SHA1:
            return HMAC<Insecure.SHA1>.isValidAuthenticationCode(authCode, authenticating: NSData(data: resource), using: key)
        case .SHA256:
            return HMAC<SHA256>.isValidAuthenticationCode(authCode, authenticating: NSData(data: resource), using: key)
        case .SHA386:
            return HMAC<SHA384>.isValidAuthenticationCode(authCode, authenticating: NSData(data: resource), using: key)
        case .SHA512:
            return HMAC<SHA512>.isValidAuthenticationCode(authCode, authenticating: NSData(data: resource), using: key)
        }
    }
}

class Crypto: NSObject {
    
    // MARK: - Typealias
    public typealias CryptoReturnType = (encryptedData: Any?, key: SymmetricKey?)
    
    // MARK: Enum
    public enum CryptoType: String {
        case AES = "AES"
        case ChaChaPoly = "ChaChaPoly"
    }
    
    // MARK: - Object Properties
    internal static let shared = Crypto()
    
    private override init() {
        super.init()
    }
    
    internal func encryptChiper(message: String, keySize: SymmetricKeySize, type: CryptoType) -> CryptoReturnType {
        let cipherKey = SymmetricKey(size: keySize)
        guard let data = message.data(using: .utf8) else { return CryptoReturnType(nil, nil) }
        
        do {
            var encryptedData: Any?
            let cipherData = NSData(data: data)
            
            switch type {
            case .AES:
                encryptedData = try AES.GCM.seal(cipherData, using: cipherKey)
            case .ChaChaPoly:
                encryptedData = try ChaChaPoly.seal(cipherData, using: cipherKey)
            }
            
            return CryptoReturnType(encryptedData, cipherKey)
        } catch {
            print("Error, Failly encrypt chiper message. - \(error.localizedDescription)")
        }
        
        return CryptoReturnType(nil, nil)
    }
    
    internal func decryptChiper(encrypedMessage: Any, key: SymmetricKey, type: CryptoType) -> Data? {
        do {
            switch type {
            case .AES:
                guard let sealed = encrypedMessage as? AES.GCM.SealedBox else { return nil }
                return try AES.GCM.open(sealed, using: key)
            case .ChaChaPoly:
                guard let sealed = encrypedMessage as? ChaChaPoly.SealedBox else { return nil }
                return try ChaChaPoly.open(sealed, using: key)
            }
        } catch {
            print("Error, Failly decrypt chiper message. - \(error.localizedDescription)")
        }
        
        return nil
    }
}

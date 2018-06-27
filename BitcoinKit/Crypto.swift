//
//  Crypto.swift
//  BitcoinKit
//
//  Created by Kishikawa Katsumi on 2018/01/30.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import Foundation
import BitcoinKit.Private
import secp256k1

public struct Crypto {
	/// Returns SHA3 256-bit (32-byte) hash of the data
	///
	/// - Parameter data: data to be hashed
	/// - Returns: 256-bit (32-byte) hash
	public static func hashSHA3_256(_ data: Data) -> Data {
		return data.sha3(.keccak256)
	}
	
    public static func sha256(_ data: Data) -> Data {
        return _Hash.sha256(data)
    }
    
    public static func sha256sha256(_ data: Data) -> Data {
        return sha256(sha256(data))
    }

    public static func ripemd160(_ data: Data) -> Data {
        return _Hash.ripemd160(data)
    }

    public static func sha256ripemd160(_ data: Data) -> Data {
        return ripemd160(sha256(data))
    }

    public static func hmacsha512(data: Data, key: Data) -> Data {
        return _Hash.hmacsha512(data, key: key)
    }

    public static func sign(_ data: Data, privateKey: Data) throws -> Data {
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN))!
        defer { secp256k1_context_destroy(ctx) }

        let signature = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { signature.deallocate(capacity: 1) }
        let status = data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) in
            privateKey.withUnsafeBytes { secp256k1_ecdsa_sign(ctx, signature, ptr, $0, nil, nil) }
        }
        guard status == 1 else { throw CryptoError.signFailed }

        let normalizedsig = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1)
        defer { normalizedsig.deallocate(capacity: 1) }
        secp256k1_ecdsa_signature_normalize(ctx, normalizedsig, signature)

        var length: size_t = 128
        var der = Data(count: length)
        guard der.withUnsafeMutableBytes({ return secp256k1_ecdsa_signature_serialize_der(ctx, $0, &length, normalizedsig) }) == 1 else { throw CryptoError.noEnoughSpace }
        der.count = length

        return der
    }
}

public enum CryptoError : Error {
    case signFailed
    case noEnoughSpace
}

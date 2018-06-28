//
//  DeterministicKey.swift
//  BitcoinKit
//
//  Created by Kishikawa Katsumi on 2018/02/04.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import Foundation
import BitcoinKit.Private

public class HDPrivateKey {
    public var network: Network
    public let depth: UInt8
    public let fingerprint: UInt32
    public let childIndex: UInt32

    let raw: Data
    let chainCode: Data

    public init(privateKey: Data, chainCode: Data, network: Network) {
        self.raw = privateKey
        self.chainCode = chainCode
        self.network = network
        self.depth = 0
        self.fingerprint = 0
        self.childIndex = 0
    }
	
	init(privateKey: Data, chainCode: Data, network: Network, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
		self.raw = privateKey
		self.chainCode = chainCode
		self.network = network
		self.depth = depth
		self.fingerprint = fingerprint
		self.childIndex = childIndex
	}

    public convenience init(seed: Data, network: Network) {
        let hmac = Crypto.hmacsha512(data: seed, key: "Bitcoin seed".data(using: .ascii)!)
        let privateKey = hmac[0..<32]
        let chainCode = hmac[32..<64]
        self.init(privateKey: privateKey, chainCode: chainCode, network: network)
    }

	public convenience init?(password: String, network: Network, user: String) {
		let userDefauts = UserDefaults.standard
		
		let salt = "Ut3Opm78U76VbwoP4Vx6UdfN234Esaz9"
		let pbkdf2Password = try! PKCS5.PBKDF2(password: password.bytes, salt: salt.bytes, keyLength: 16).calculate()
		
		let keys = HDPrivateKey.getStorageKey(network: network, user: user)

		let readPbkdf2Password = userDefauts.string(forKey: keys.passwordKey)
		
		if pbkdf2Password.toHexString() != readPbkdf2Password {
			
			return nil
		}
		
		let hdPrivateKeyRaw = userDefauts.data(forKey: keys.privateKey)
		let hdPrivateKeyChainCode = userDefauts.data(forKey: keys.chainCodeKey)

		let theRaw = HDPrivateKey.Decode_AES(dataToDecode: hdPrivateKeyRaw!, key: pbkdf2Password)
		let theChainCode = HDPrivateKey.Decode_AES(dataToDecode: hdPrivateKeyChainCode!, key: pbkdf2Password)
		
		self.init(privateKey: theRaw, chainCode: theChainCode, network: network)
	}
	
	//hdPublicKey
	public func hdPublicKey() -> HDPublicKey {
		return HDPublicKey(privateKey: self, chainCode: chainCode, network: network, depth: depth, fingerprint: fingerprint, childIndex: childIndex)
	}

	//PrivateKey
	public func ethPrivateKey() -> PrivateKey {
		return PrivateKey(data: Data(hex: "0x") + raw, network: network)
	}
	public func btcPrivateKey() -> PrivateKey {
		return PrivateKey(data: raw, network: network)
	}
	
	//保存
	public func save(password: String, user: String) {
		
		let salt = "Ut3Opm78U76VbwoP4Vx6UdfN234Esaz9"
		let pbkdf2Password = try! PKCS5.PBKDF2(password: password.bytes, salt: salt.bytes,
											   keyLength: 16).calculate()
		
		
		
		let userDefauts = UserDefaults.standard
		let keys = HDPrivateKey.getStorageKey(network: network, user: user)

		userDefauts.setValue(pbkdf2Password.toHexString(), forKey: keys.passwordKey)
		
		let hdPrivateKeyRaw = HDPrivateKey.endcode_AES(dataToEncode: raw, key: pbkdf2Password)
		let hdPrivateKeyChainCode = HDPrivateKey.endcode_AES(dataToEncode: chainCode, key: pbkdf2Password)
		
		userDefauts.set(hdPrivateKeyRaw, forKey: keys.privateKey)
		userDefauts.set(hdPrivateKeyChainCode, forKey: keys.chainCodeKey)
	}


    public func extended() -> String {
        var data = Data()
        data += network.hdPrivateKeyPrefix.bigEndian
        data += depth.littleEndian
        data += fingerprint.littleEndian
        data += childIndex.littleEndian
        data += chainCode
        data += UInt8(0)
        data += raw
        let checksum = Crypto.sha256sha256(data).prefix(4)
        return Base58.encode(data + checksum)
    }

    public func derived(at index: UInt32, hardened: Bool = false) throws -> HDPrivateKey {
        // As we use explicit parameter "hardened", do not allow higher bit set.
        if (0x80000000 & index) != 0 {
            fatalError("invalid child index")
        }

        guard let derivedKey = _HDKey(privateKey: raw, publicKey: hdPublicKey().raw, chainCode: chainCode, depth: depth, fingerprint: fingerprint, childIndex: childIndex).derived(at: index, hardened: hardened) else {
            throw DerivationError.derivateionFailed
        }
        return HDPrivateKey(privateKey: derivedKey.privateKey!, chainCode: derivedKey.chainCode, network: network, depth: derivedKey.depth, fingerprint: derivedKey.fingerprint, childIndex: derivedKey.childIndex)
    }
}

public enum DerivationError : Error {
    case derivateionFailed
}

extension HDPrivateKey {
	private static	func getStorageKey(network: Network, user: String) -> (privateKey: String, chainCodeKey: String, passwordKey: String) {
		var keyPrefix = user + "TestNet"
		
		switch network {
		case .btcMainnet:
			keyPrefix = "BtcMainnet"
			break
		case .ethMainnet:
			keyPrefix = "EthMainnet"
			break
		default: break
		}
		
		return (keyPrefix +  "HDPrivateKeyRaw", keyPrefix + "HDPrivateKeyChainCode", keyPrefix + "pbkdf2Password")
	}
	
	private static func endcode_AES(dataToEncode: Data, key: [UInt8]) -> Data {
		var result: [UInt8] = []
		do {
			let aes = try AES(key: Padding.zeroPadding.add(to: key, blockSize: AES.blockSize), blockMode: ECB())
			result = try aes.encrypt(dataToEncode.bytes)
		} catch { }
		
		let data = Data(bytes: result)
		
		return data
	}
	
	//  MARK:  AES-128解密
	private static func Decode_AES(dataToDecode: Data, key: [UInt8]) -> Data {
		// decode AES
		var decrypted: [UInt8] = []
		do {
			let aes = try AES(key: Padding.zeroPadding.add(to: key, blockSize: AES.blockSize), blockMode: ECB())
			
			decrypted = try aes.decrypt(dataToDecode.bytes)
		} catch {
			
		}
		// byte 转换成NSData
		let data = Data(decrypted)
		
		return data
	}
}

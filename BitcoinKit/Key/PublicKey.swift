//
//  PublicKey.swift
//  BitcoinKit
//
//  Created by Kishikawa Katsumi on 2018/02/01.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import Foundation
import BitcoinKit.Private

public struct PublicKey {
    public let raw: Data
    public let network: Network

	init(btcPrivateKey: PrivateKey, network: Network) {
		self.network = network
		self.raw = PublicKey.from(privateKey: btcPrivateKey.raw, compression: true)
	}
	
	public init(ethPrivateKey: PrivateKey, network: Network) {
		self.network = network
		self.raw = Data(hex: "0x") + PublicKey.from(privateKey: ethPrivateKey.raw, compression: false)
	}

    init(bytes raw: Data, network: Network) {
        self.raw = raw
        self.network = network
    }

    /// Version = 1 byte of 0 (zero); on the test network, this is 1 byte of 111
    /// Key hash = Version concatenated with RIPEMD-160(SHA-256(public key))
    /// Checksum = 1st 4 bytes of SHA-256(SHA-256(Key hash))
    /// Bitcoin Address = Base58Encode(Key hash concatenated with Checksum)
    public func toAddress() -> String {
        let hash = Data([network.version]) + Crypto.sha256ripemd160(raw)
        return publicKeyHashToAddress(hash)
    }
	/// generates address from its public key
	///
	/// - Returns: address in string format
	public func generateEthAddress() -> String {
		return EthAddress(data: ethAddressData).string
	}
	/// Version = 1 byte of 0 (zero); on the test network, this is 1 byte of 111
	/// Key hash = Version concatenated with RIPEMD-160(SHA-256(public key))
	/// Checksum = 1st 4 bytes of SHA-256(SHA-256(Key hash))
	/// Bitcoin Address = Base58Encode(Key hash concatenated with Checksum)
	public func generateBtcAddress() -> String {
		let hash = Data([network.version]) + Crypto.sha256ripemd160(raw)
		return publicKeyHashToAddress(hash)
	}
	
	/// Address data generated from public key in data format
	private var ethAddressData: Data {
		return Crypto.hashSHA3_256(raw.dropFirst()).suffix(20)
	}
	
    static func from(privateKey raw: Data, compression: Bool = false) -> Data {
        return _Key.computePublicKey(fromPrivateKey: raw, compression: compression)
    }
}

extension PublicKey : Equatable {
    public static func ==(lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.network == rhs.network && lhs.raw == rhs.raw
    }
}

extension PublicKey : CustomStringConvertible {
    public var description: String {
        return raw.hex
    }
}

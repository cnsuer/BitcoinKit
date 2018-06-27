//
//  PrivateKey.swift
//  BitcoinKit
//
//  Created by Kishikawa Katsumi on 2018/02/01.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import Foundation

public struct PrivateKey {
	
	// Private key in data format
	public let raw: Data
	public let network: Network
	
	public init(ethPrivateKey: String) throws {
		self.raw = Data(hex: ethPrivateKey)
		self.network = Network.ethMainnet
	}
	
	public init(btcWif: String) throws {
        let decoded = Base58.decode(btcWif)
        let checksumDropped = decoded.prefix(decoded.count - 4)

		let addressPrefix = checksumDropped[0]
		switch addressPrefix {
		case Network.btcMainnet.btcPrivatekeyPrefix:
			network = .btcMainnet
		case Network.testnet.btcPrivatekeyPrefix:
			network = .testnet
		default:
			throw PrivateKeyError.invalidFormat
		}

        let h = Crypto.sha256sha256(checksumDropped)
        let calculatedChecksum = h.prefix(4)
        let originalChecksum = decoded.suffix(4)
        guard calculatedChecksum == originalChecksum else {
            throw PrivateKeyError.invalidFormat
        }
        let privateKey = checksumDropped.dropFirst()
        raw = Data(privateKey)
    }

    public init(data: Data, network: Network = .testnet) {
        raw = data
        self.network = network
    }

	/// Publish key derived from private key
	public func ethPublicKey() -> PublicKey {
		return PublicKey(ethPrivateKey: self, network: network)
	}
	public func btcPublicKey() -> PublicKey {
		return PublicKey(btcPrivateKey: self, network: network)
	}

    public func toWIF() -> String {
        let data = Data([network.btcPrivatekeyPrefix]) + raw
        let checksum = Crypto.sha256sha256(data).prefix(4)
        return Base58.encode(data + checksum)
    }
	
	/// Sign signs provided hash data with private key by Elliptic Curve, Secp256k1
	///
	/// - Parameter hash: hash in data format
	/// - Returns: signiture in data format
	/// - Throws: .cryptoError(.failedToSign) when failed to sign
	public func signEth(hash: Data) throws -> Data {
		return try Crypto.sign(hash, privateKey: raw)

//		return try Crypto.sign(hash, privateKey: raw)
	}
}

extension PrivateKey : Equatable {
    public static func ==(lhs: PrivateKey, rhs: PrivateKey) -> Bool {
        return lhs.network == rhs.network && lhs.raw == rhs.raw
    }
}

extension PrivateKey : CustomStringConvertible {
    public var description: String {
        return raw.hex
    }
}

public enum PrivateKeyError : Error {
    case invalidFormat
}

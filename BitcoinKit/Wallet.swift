//
//  Wallet.swift
//  BitcoinKit
//
//  Created by Kishikawa Katsumi on 2018/01/31.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import Foundation

final public class Wallet {
    public let privateKey: PrivateKey
    public let publicKey: PublicKey

    public let network: Network

	public init(ethPrivateKey: String, network: Network) {
		self.network = network
		self.privateKey = PrivateKey(data: Data(hex: ethPrivateKey), network: network)
		self.publicKey = privateKey.ethPublicKey()
	}
	
//    public init(privateKey: PrivateKey) {
//        self.privateKey = privateKey
//        self.publicKey = privateKey.publicKey()
//        self.network = privateKey.network
//    }

    public init(btcWif: String) throws {
        self.privateKey = try PrivateKey(btcWif: btcWif)
        self.publicKey = privateKey.btcPublicKey()
        self.network = privateKey.network
    }
	
	public init(ethPrivateKey: String) throws {
		self.privateKey = try PrivateKey(ethPrivateKey: ethPrivateKey)
		self.publicKey = privateKey.ethPublicKey()
		self.network = privateKey.network
	}

    public func serialized() -> Data {
        var data = Data()
		data += privateKey.raw
		data += publicKey.raw
        return data
    }
	/// Sign signs rlp encoding hash of specified raw transaction
	///
	/// - Parameter rawTransaction: raw transaction to hash
	/// - Returns: signiture in hex format
	/// - Throws: EthereumKitError.failedToEncode when failed to encode
	public func signEth(rawTransaction: EthRawTransaction) throws -> String {
		let signer = EIP155Signer(chainID: network.ethChainID)
		
		let rawData = try signer.sign(rawTransaction, privateKey: privateKey)
		let hash = rawData.toHexString().addHexPrefix()
		
		return hash
	}
	
	/// Sign calculates an Ethereum ECDSA signature for: keccack256("\x19Ethereum Signed Message:\n" + len(message) + message))
	/// See also: https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_sign
	///
	/// - Parameter hex: message in hex format to sign
	/// - Returns: signiture in hex format
	/// - Throws: EthereumKitError.failedToEncode when failed to encode
	public func signEth(hex: String) throws -> String {
		let prefix = "\u{19}Ethereum Signed Message:\n"
		
		let messageData = Data(hex: hex.stripHexPrefix())
		
		guard let prefixData = (prefix + String(messageData.count)).data(using: .ascii) else {
			throw EthereumKitError.cryptoError(.failedToEncode(prefix + String(messageData.count)))
		}
		
		let hash = Crypto.hashSHA3_256(prefixData + messageData)
		
		var signiture = try privateKey.signEth(hash: hash)
		
		// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
		// where the V value will be 27 or 28 for legacy reasons.
		signiture[64] += 27
		
		let signedHash = signiture.toHexString().addHexPrefix()
		
		return signedHash
	}
	
	/// Sign calculates an Ethereum ECDSA signature for: keccack256("\x19Ethereum Signed Message:\n" + len(message) + message))
	/// See also: https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_sign
	///
	/// - Parameter hex: message to sign
	/// - Returns: signiture in hex format
	/// - Throws: EthereumKitError.failedToEncode when failed to encode
	public func signEth(message: String) throws -> String {
		return try signEth(hex: message.toHexString())
	}
}

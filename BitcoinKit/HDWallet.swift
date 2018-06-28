//
//  HDWallet.swift
//  BitcoinKit
//
//  Created by Kishikawa Katsumi on 2018/02/13.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import Foundation

public final class HDWallet {

	public var network: Network{
		willSet{
			masterPrivateKey.network = newValue
		}
	}
	
	private let masterPrivateKey: HDPrivateKey

    public init(seed: Data, network: Network) {
        self.network = network
        masterPrivateKey = HDPrivateKey(seed: seed, network: network)

        // m / purpose' / coin_type' / account' / change / address_index
        //
        // Purpose is a constant set to 44' (or 0x8000002C) following the BIP43 recommendation.
        // It indicates that the subtree of this node is used according to this specification.
        // Hardened derivation is used at this level.

		
        // One master node (seed) can be used for unlimited number of independent cryptocoins such as Bitcoin, Litecoin or Namecoin. However, sharing the same space for various cryptocoins has some disadvantages.
        // This level creates a separate subtree for every cryptocoin, avoiding reusing addresses across cryptocoins and improving privacy issues.
        // Coin type is a constant, set for each cryptocoin. Cryptocoin developers may ask for registering unused number for their project.
        // The list of already allocated coin types is in the chapter "Registered coin types" below.
        // Hardened derivation is used at this level.

		
        // This level splits the key space into independent user identities, so the wallet never mixes the coins across different accounts.
        // Users can use these accounts to organize the funds in the same fashion as bank accounts; for donation purposes (where all addresses are considered public), for saving purposes, for common expenses etc.
        // Accounts are numbered from index 0 in sequentially increasing manner. This number is used as child index in BIP32 derivation.
        // Hardened derivation is used at this level.
        // Software should prevent a creation of an account if a previous account does not have a transaction history (meaning none of its addresses have been used before).
        // Software needs to discover all used accounts after importing the seed from an external source. Such an algorithm is described in "Account discovery" chapter.

		
        // Constant 0 is used for external chain and constant 1 for internal chain (also known as change addresses).
        // External chain is used for addresses that are meant to be visible outside of the wallet (e.g. for receiving payments).
        // Internal chain is used for addresses which are not meant to be visible outside of the wallet and is used for return transaction change.
        // Public derivation is used at this level.

        // Addresses are numbered from index 0 in sequentially increasing manner. This number is used as child index in BIP32 derivation.
        // Public derivation is used at this level.

    }
	public init?(password: String, network: Network = .testnet, user: String = "default") {
		guard let masterPrivateKey = HDPrivateKey(password: password, network: network, user: user) else { return nil }
		self.masterPrivateKey = masterPrivateKey
		self.network = network
	}
	
	// MARK: - Public Methods
	//PrivateKey
	public func generateEthPrivateKey(at index: UInt32) throws -> PrivateKey {
		return try hdPrivateKey(change: .external).derived(at: index).ethPrivateKey()
	}
	public func dumpEthPrivateKey(at index: UInt32) throws -> String {
		return try generateEthPrivateKey(at: index).raw.toHexString()
	}
	public func generateBtcPrivateKey(at index: UInt32) throws -> PrivateKey {
		return try hdPrivateKey(change: .external).derived(at: index).btcPrivateKey()
	}
	
	//hdPrivateKey
    public func hdPrivateKey() throws -> HDPrivateKey {
        return try hdPrivateKey(change: .external)
    }
	private func hdPrivateKey(change: Change) throws -> HDPrivateKey {
		return try masterPrivateKey
			.derived(at: 44, hardened: true)
			.derived(at: network.coinType, hardened: true)
			.derived(at: 0, hardened: true)
			.derived(at: change.rawValue)

	}

	// address
	public func generateEthAddress(at index: UInt32) throws -> String {
		return try generateEthPrivateKey(at: index).ethPublicKey().generateEthAddress()
	}
	public func generateBtcAddress(at index: UInt32) throws -> String {
		return try generateBtcPrivateKey(at: index).btcPublicKey().generateBtcAddress()
	}

	//保存
	public func saveHDPrivateKey(password: String, user: String = "default") {
		self.masterPrivateKey.save(password: password, user: user)
	}
	
	/// Sign signs rlp encoding hash of specified raw transaction
	///
	/// - Parameter rawTransaction: raw transaction to hash
	/// - Returns: signiture in hex format
	/// - Throws: EthereumKitError.failedToEncode when failed to encode
	public func signEth(rawTransaction: EthRawTransaction) throws -> String {
		let signer = EIP155Signer(chainID: network.ethChainID)
		
		let privateKey = try! generateEthPrivateKey(at: 0)
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
		
		let privateKey = try! generateEthPrivateKey(at: 0)
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

	
	
//	public func generateAddress(at index: UInt32) throws -> String {
//		return try generatePrivateKey(at: index).publicKey().generateBtcAddress()
//	}
//	public func receiveAddress() throws -> Address {
//		return Address(try hdPublicKey())
//	}
//
//	public func receiveAddress(index: UInt32) throws -> Address {
//		return Address(try hdPublicKey(index: index))
//	}
//
//	public func changeAddress() throws -> Address {
//		return try changeAddress(index: internalIndex)
//	}
//
//	public func changeAddress(index: UInt32) throws -> Address {
//		let privateKey = try keychain.derivedKey(path: "m/\(purpose)'/\(coinType)'/\(account)'/\(Chain.internal.rawValue)/\(index)")
//		return Address(privateKey.hdPublicKey())
//	}

    enum Change : UInt32 {
		case external = 0
		case `internal` = 1
    }
}

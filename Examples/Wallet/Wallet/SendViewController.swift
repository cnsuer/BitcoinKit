//
//  SendViewController.swift
//  Wallet
//
//  Created by Kishikawa Katsumi on 2018/02/05.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import UIKit
import BitcoinKit

class SendViewController: UIViewController {
	override func viewDidLoad() {
		super.viewDidLoad()
		
	}
	
	override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
		creatWallet()
	}
	
	func creatWallet()  {
		
		let m = UserDefaults.standard.array(forKey: "mnemonics")
		
		if m != nil {
			
			getHDWallet()
			
			return
		}
		let mnemonic: [String] = ["pattern", "run", "stay", "perfect", "swim", "grow", "win", "nasty", "digital", "feel", "labor", "good"]
		UserDefaults.standard.set(mnemonic, forKey: "mnemonics")

		let seed = Mnemonic.seed(mnemonic: mnemonic)
		
		//btcMainnet
		let wallet = HDWallet(seed: seed, network: Network.testnet)
		var address = try! wallet.generateBtcAddress(at: 0)
		print("creatWallet BtcAddress: " + address) //121x5Nj7KKjSTZLprRxd1rRA9UkQA9iNTw
		wallet.saveHDPrivateKey(password: "123456")
		
		//ethMainnet
		wallet.network = Network.ethMainnet
		address = try! wallet.generateEthAddress(at: 0)
		print("creatWallet EthAddress: " + address) //0x5A17F8d55e18e8f67250125DA3025d32633f8Bc9
		wallet.saveHDPrivateKey(password: "123456")
		
		//let privateKey = try! PrivateKey(wif: "cMfWomdtnUdar3gYyWKaSUEuNKh7sU4U4WEWXJ4xqFPS4htEsjy7")
		//let address = privateKey.publicKey().toAddress();
	}
	
	func getHDWallet() {
		let password = "123456"
		
		if let wallet = HDWallet(password: password, network: .btcMainnet) {
			var address = try! wallet.generateBtcAddress(at: 0)
			print("getHDWallet BtcAddress:" + address)
			wallet.network = Network.ethMainnet
			address = try! wallet.generateEthAddress(at: 0)
			print("getHDWallet EthAddress: " + address)
		}else{
			print("密码错误!!!")
		}
	}
	
	func btcRawTransaction() {
//		let wallet = AppController.shared.wallet!
//		
//		// Transaction in testnet3
//		// https://api.blockcypher.com/v1/btc/test3/txs/28bac52467d509b06ef76886f9136857146b62a7a70e6e24818cc16c96f6c449
//		let hash = BitcoinKit.hexToData(hex: "31baf4ee9c88232c6a016af0871f3dbd6a0d470dd0f65c963109f469e241aadc")
//		let index: UInt32 = 0
//		let outpoint = TransactionOutPoint(hash: hash, index: index)
//		
//		let balance: Int64 = 59293124
//		let amount: Int64  =  1000000
//		let fee: Int64     =  1000000
//		let toAddress = "mxsQmW8AiifZfGpRuh5ZRkonsjo8eWaUAp" // https://testnet.coinfaucet.eu/en/
//		
//		let privateKey = try! wallet.privateKey().privateKey()
//		
//		let fromPublicKey = try! wallet.publicKey()
//		let fromPubKeyHash = Crypto.sha256ripemd160(fromPublicKey.raw)
//		let toPubKeyHash = Base58.decode(toAddress).dropFirst().dropLast(4)
//
//		
//		let lockingScript1 = Script.buildPublicKeyHashOut(pubKeyHash: toPubKeyHash)
//		let lockingScript2 = Script.buildPublicKeyHashOut(pubKeyHash: fromPubKeyHash)
//		
//		let sending = TransactionOutput(value: amount, scriptLength: VarInt(lockingScript1.count), lockingScript: lockingScript1)
//		let payback = TransactionOutput(value: balance - amount - fee, scriptLength: VarInt(lockingScript2.count), lockingScript: lockingScript2)
//		
//		// copy transaction (set script to empty)
//		// if there are correspond output transactions, set script to copy
//		let subScript = BitcoinKit.hexToData(hex: "76a91473f0538729ce835099ef9c2ac206902eb308a68288ac")
//		let inputForSign = TransactionInput(previousOutput: outpoint, scriptLength: VarInt(subScript.count), signatureScript: subScript, sequence: UInt32.max)
//		let _tx = Transaction(version: 1, txInCount: 1, inputs: [inputForSign], txOutCount: 2, outputs: [sending, payback], lockTime: 0)
//		
//		var shawanyier = UInt32(Signature.SIGHASH_ALL).littleEndian
//		let data = Data(buffer: UnsafeBufferPointer(start: &shawanyier, count: 1))
//		
//		let _txHash = Crypto.sha256sha256(_tx.serialized() + data)
//		
//		
//		guard let signature: Data = try? Crypto.sign(_txHash, privateKey: privateKey) else {
//			return
//		}
//		
//		var shawanyier2 = Signature.SIGHASH_ALL
//		let data2 = Data(buffer: UnsafeBufferPointer(start: &shawanyier2, count: 1))
//		
//		var shawanyier3 = UInt8(fromPublicKey.raw.count)
//		let data3 = Data(buffer: UnsafeBufferPointer(start: &shawanyier3, count: 1))
//		
//		let unlockingScript: Data = Data([UInt8(signature.count + 1)]) + signature + data2 + data3 + fromPublicKey.raw
//		
//		let input = TransactionInput(previousOutput: outpoint, scriptLength: VarInt(unlockingScript.count), signatureScript: unlockingScript, sequence: UInt32.max)
//		let transaction = Transaction(version: 1, txInCount: 1, inputs: [input], txOutCount: 2, outputs: [sending, payback], lockTime: 0)
//		
//		
//		print(BitcoinKit.dataToHex(transaction.serialized()))
		
		
	}
}

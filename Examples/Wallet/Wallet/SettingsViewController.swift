//
//  SettingsViewController.swift
//  Wallet
//
//  Created by Kishikawa Katsumi on 2018/02/05.
//  Copyright © 2018 Kishikawa Katsumi. All rights reserved.
//

import UIKit
import BitcoinKit
import WebKit

class SettingsViewController: UIViewController {
	
	static let BITCOIN_SIGNED_MESSAGE_HEADER = "Bitcoin Signed Message:\n".data(using: String.Encoding.utf8)!
	
	class func formatMessageForBitcoinSigning(_ message: String) -> Data {
		let data = NSMutableData()
		var messageHeaderCount = UInt8(BITCOIN_SIGNED_MESSAGE_HEADER.count)
		data.append(NSData(bytes: &messageHeaderCount, length: MemoryLayout<UInt8>.size) as Data)
		data.append(BITCOIN_SIGNED_MESSAGE_HEADER)
		let msgBytes = message.data(using: String.Encoding.utf8)!
		data.appendVarInt(i: UInt64(msgBytes.count))
		data.append(msgBytes)
		return data as Data
	}
//	ECDSA_SIG
	// sign a message with a key and return a base64 representation
	class func signMessage(_ message: String, usingKey key: PrivateKey) {
		let signingData = formatMessageForBitcoinSigning(message)
		
		let	signingData1 = Crypto.sha256sha256(signingData)
		_ = try! Crypto.sign(signingData1, privateKey: key.raw)
//		let signature = signingData2.compactSign(key: key)
//		return String(bytes: signature.base64EncodedData(options: []), encoding: String.Encoding.utf8) ?? ""
	}
	

	@IBOutlet weak var test: UIView!
	var webView: WKWebView!
	
    override func viewDidLoad() {
        super.viewDidLoad()
		view.backgroundColor = UIColor.gray
		
		webviewAdd()

    }
	
	func webviewAdd() {
		
		// 根据生成的WKUserScript对象，初始化WKWebViewConfiguration
		let config = WKWebViewConfiguration()
		let uer = WKUserContentController()
		uer.add(self, name: "getSign")
		config.userContentController = uer
		webView = WKWebView(frame: test.bounds, configuration: config)
		test.addSubview(webView)
		
		let path = Bundle.main.path(forResource: "index", ofType: "html")!
		let html = try! String(contentsOfFile: path, encoding: .utf8)
		
		webView.loadHTMLString(html, baseURL: nil)
		
	}
	
	@IBAction func signMessage(_ sender: UIButton) {
		testSignMessage()
	}
	
	@IBAction func verifySign(_ sender: UIButton) {
		
	}
	
	func testSignMessage() {
		let password = "123456"
		
		if let wallet = HDWallet(password: password, network: .testnet) {
			
			let privateKey = try! wallet.generateBtcPrivateKey(at: 0)
			let address1 = privateKey.btcPublicKey().generateBtcAddress()
			print("getHDWallet BtcAddress1:" + address1)
			
			let address = try! wallet.generateBtcAddress(at: 0)
			print("getHDWallet BtcAddress:" + address)

			let str = "getPrivateKey(\"\(privateKey.raw.toHexString())\",\"123456\")"
			
			webView.evaluateJavaScript(str) { (res, err) in
				print(res ?? "成功")
				print(err ?? "成功")
			}
		}else{
			print("密码错误!!!")
		}
	}
}

extension SettingsViewController: WKScriptMessageHandler {
	func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
		if message.name == "getSign" {
			print(message.body)
		}
	}
	
	public func getSign() {
		
	}
	
}

let VAR_INT16_HEADER: UInt64 = 0xfd
let VAR_INT32_HEADER: UInt64 = 0xfe
let VAR_INT64_HEADER: UInt64 = 0xff

extension NSMutableData {
	
	func appendVarInt(i: UInt64) {
		if (i < VAR_INT16_HEADER) {
			var payload = UInt8(i)
			append(&payload, length: MemoryLayout<UInt8>.size)
		}
		else if (Int32(i) <= UINT16_MAX) {
			var header = UInt8(VAR_INT16_HEADER)
			var payload = CFSwapInt16HostToLittle(UInt16(i))
			append(&header, length: MemoryLayout<UInt8>.size)
			append(&payload, length: MemoryLayout<UInt16>.size)
		}
		else if (UInt32(i) <= UINT32_MAX) {
			var header = UInt8(VAR_INT32_HEADER)
			var payload = CFSwapInt32HostToLittle(UInt32(i))
			append(&header, length: MemoryLayout<UInt8>.size)
			append(&payload, length: MemoryLayout<UInt32>.size)
		}
		else {
			var header = UInt8(VAR_INT64_HEADER)
			var payload = CFSwapInt64HostToLittle(i)
			append(&header, length: MemoryLayout<UInt8>.size)
			append(&payload, length: MemoryLayout<UInt64>.size)
		}
	}
}

//
//  CredentialSniffer.swift
//  CredentialSniffer
//
//  Created by Nicholas Wimmers on 6/7/24.
//

import Foundation
import Security

enum SnifferErrors: Error {
    case unexpected
    case notfound
}

class SearchCredentials {
    static func search(by: String, query: String) throws -> String {
        var result: CFData?
        
        let status = KeyringSearch(by as CFString, query as CFString, &result)
        
        switch status {
        case errSecParam:
            throw SnifferErrors.unexpected
        case errSecBadReq:
            throw SnifferErrors.unexpected
        case errSecItemNotFound:
            throw SnifferErrors.notfound
        case errSecSuccess:
            let data = result! as Data
            if let credential = String.init(bytes: data, encoding: .utf8) {
                return credential
            } else {
                throw SnifferErrors.notfound
            }
        default:
            throw SnifferErrors.unexpected
        }
    }
    
    static func getAllKeychainItems() -> String {
        var s: String = ""
        let query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess {
            if let items = item as? [[String: Any]] {
                for item in items {
                    if let account = item[kSecAttrAccount as String] as? String,
                       let data = item[kSecValueData as String] as? Data,
                       let password = String(data: data, encoding: .utf8) {
                        s = "\(account) \(password)\n"
                    }
                }
            }
        } else {
            s = "Error: \(status)"
        }
    return s
    }
    
    static func addKeychainItem() {
        let account = "testAccount"
        let password = "testPassword".data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: password
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess {
            print("Item added successfully")
        } else if status == errSecDuplicateItem {
            print("Item already exists")
        } else {
            print("Error adding item: \(status)")
        }
    }
}

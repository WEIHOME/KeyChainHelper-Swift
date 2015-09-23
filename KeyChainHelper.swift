//
//  KeyChainHelper.swift
//
//  Created by Weihong Chen on 23/09/2015.
//  Copyright © 2015 Weihong. All rights reserved.
//

import Foundation
import Security

let SecMatchLimit: String! = kSecMatchLimit as String
let SecReturnData: String! = kSecReturnData as String
let SecValueData: String! = kSecValueData as String
let SecAttrAccessible: String! = kSecAttrAccessible as String
let SecClass: String! = kSecClass as String
let SecAttrService: String! = kSecAttrService as String
let SecAttrGeneric: String! = kSecAttrGeneric as String
let SecAttrAccount: String! = kSecAttrAccount as String
let SecReturnPersistentRef: String! = kSecReturnPersistentRef as String

class KeyChainHelper{
    
    private class func service() -> String{
     
        return NSBundle.mainBundle().bundleIdentifier!
        
    }
    
    class func storeData(key: String, value: String){
    
        let query = KeyChainHelper.getQueryDataStructureForKeyChain(key)
        var result: AnyObject? = nil
        
        query[SecValueData] = value.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        
        let status = SecItemAdd(query, &result)
    
        switch status{
        case errSecSuccess:
            print("data stored successfully")
        case errSecDuplicateItem:
            print("data already exists")
        default:
            print("data stored fails")
        
        }
    }
    
    class func deleteData(key: String){
        
        let query = KeyChainHelper.getQueryDataStructureForKeyChain(key)
        
        query[SecReturnData] = kCFBooleanTrue
        
        let status = SecItemCopyMatching(query, nil)
        
        if status == errSecSuccess{

            let deleted = SecItemDelete(query)
            
            if deleted == errSecSuccess{
            
                print("data exists, delete sucessfully")
            }else{
            
                print("data exists, but deleting data fail")
            }
            
        }else{
            print("data doese not exist, deleting data fail")
        }
        
    }
    
    class func retrieveData(key: String) -> NSData?{
        
        let query = KeyChainHelper.getQueryDataStructureForKeyChain(key)
        var result: AnyObject?
        
        let value: String?

        query[SecReturnData] = kCFBooleanTrue
        
        let status = SecItemCopyMatching(query, &result)
        
        if status == errSecSuccess{
            
            value = NSString(data: result as! NSData, encoding: NSUTF8StringEncoding) as? String
            
            print(value)
            
            return value?.dataUsingEncoding(NSUTF8StringEncoding)
        }
        
        print("nothing to be retrieved")
        return NSData()
    }
    
    class func updateData(key: String, newData: String){
        
        let query = KeyChainHelper.getQueryDataStructureForKeyChain(key)
        let EncodedNewData = newData.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
                
        let status = SecItemCopyMatching(query, nil)
        
        if status == errSecSuccess{
            
            let update = [
                SecValueData:EncodedNewData!
            ]
            
            let success = SecItemUpdate(query, update)
        
            if success == errSecSuccess{
                print("suceesfully update value")
            }else{
                print("failt to update value")
            }
            
            
        }else{
        
            print("cannot update the data, because there is no existing data")
        }
        
    }
    
    
    private class func getQueryDataStructureForKeyChain(key: String) -> NSMutableDictionary{
    
        let queryDictionary: NSMutableDictionary = [SecClass: kSecClassGenericPassword]
        
        queryDictionary[SecAttrService] = KeyChainHelper.service()
        
        queryDictionary[SecAttrAccount] = key.dataUsingEncoding(NSUTF8StringEncoding)
        
        
        return queryDictionary
    }
}
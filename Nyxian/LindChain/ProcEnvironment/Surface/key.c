/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Licensed under the emexLabs Public Source License, version 1.1
 (EPSL 1.1).

 Private use and modification are permitted under the license.
 Redistribution of source or binaries, modified or unmodified,
 requires prior written permission from emexLabs.

 External deployment is subject to the source-availability
 requirements and other conditions of the license.

 Provided "AS IS", without warranty, to the extent permitted by law.

 See LICENSE for the full license terms.
*/

#import <LindChain/ProcEnvironment/Surface/key.h>
#import <Security/Security.h>
#import <OpenSSL/ec.h>
#import <OpenSSL/pem.h>
#import <OpenSSL/err.h>

#define KEY_SERVICE CFSTR("com.nyxian.kernel-key")
#define KEY_ACCOUNT_PRIV CFSTR("static-kernel-key.priv")
#define KEY_ACCOUNT_PUB CFSTR("static-kernel-key.pub")

bool get_kernel_ec_key(uint8_t **priv_bytes,
                       size_t *priv_len,
                       uint8_t **pub_bytes,
                       size_t *pub_len)
{
    assert(priv_bytes != NULL && priv_len != NULL && pub_bytes != NULL && pub_len != NULL);
    
    bool success = false;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    
    *priv_bytes = NULL;
    *pub_bytes = NULL;
    
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!pctx)
    {
        goto cleanup;
    }
    
    if(EVP_PKEY_keygen_init(pctx) <= 0)
    {
        goto cleanup;
    }
    
    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
    {
        goto cleanup;
    }
    
    if(EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        goto cleanup;
    }
    
    *priv_len = i2d_PrivateKey(pkey, NULL);
    if(*priv_len <= 0)
    {
        goto cleanup;
    }
    
    *priv_bytes = (uint8_t*)malloc(*priv_len);
    if(*priv_bytes == NULL)
    {
        goto cleanup;
    }
    uint8_t *p = *priv_bytes;
    if(i2d_PrivateKey(pkey, &p) != *priv_len)
    {
        goto cleanup;
    }

    *pub_len = i2d_PUBKEY(pkey, NULL);
    if(*pub_len <= 0)
    {
        goto cleanup;
    }
    
    *pub_bytes = (uint8_t*)malloc(*pub_len);
    if(*pub_bytes == NULL)
    {
        goto cleanup;
    }
    p = *pub_bytes;
    if(i2d_PUBKEY(pkey, &p) != *pub_len)
    {
        goto cleanup;
    }

    success = true;

cleanup:
    if(!success)
    {
        if(*priv_bytes)
        {
            free(*priv_bytes);
            *priv_bytes = NULL;
        }
        if(*pub_bytes)
        {
            free(*pub_bytes);
            *pub_bytes = NULL;
        }
    }
    
    if(pkey)
    {
        EVP_PKEY_free(pkey);
    }
    
    if(pctx)
    {
        EVP_PKEY_CTX_free(pctx);
    }

    return success;
}

int store_kernel_key(uint8_t *priv_bytes,
                     size_t priv_len,
                     uint8_t *pub_bytes,
                     size_t pub_len)
{
    CFDictionaryRef privDeleteQuery = CFDictionaryCreate(
        NULL,
        (const void *[]){
            kSecClass,
            kSecAttrService,
            kSecAttrAccount
        },
        (const void *[]){
            kSecClassGenericPassword,
            KEY_SERVICE,
            KEY_ACCOUNT_PRIV
        },
        3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    SecItemDelete(privDeleteQuery);
    CFRelease(privDeleteQuery);
    
    CFDictionaryRef pubDeleteQuery = CFDictionaryCreate(
        NULL,
        (const void *[]){
            kSecClass,
            kSecAttrService,
            kSecAttrAccount
        },
        (const void *[]){
            kSecClassGenericPassword,
            KEY_SERVICE,
            KEY_ACCOUNT_PUB
        },
        3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    SecItemDelete(pubDeleteQuery);
    CFRelease(pubDeleteQuery);

    CFDataRef privKeyData = CFDataCreate(NULL, priv_bytes, priv_len);
    CFDictionaryRef privAddQuery = CFDictionaryCreate(
        NULL,
        (const void *[]){
            kSecClass,
            kSecAttrService,
            kSecAttrAccount,
            kSecValueData,
            kSecAttrAccessible
        },
        (const void *[]){
            kSecClassGenericPassword,
            KEY_SERVICE,
            KEY_ACCOUNT_PRIV,
            privKeyData,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        },
        5,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    
    OSStatus status = SecItemAdd(privAddQuery, NULL);
    CFRelease(privKeyData);
    CFRelease(privAddQuery);
    if(status != errSecSuccess)
    {
        return -1;
    }
    
    CFDataRef pubKeyData = CFDataCreate(NULL, pub_bytes, pub_len);
    CFDictionaryRef pubAddQuery = CFDictionaryCreate(
        NULL,
        (const void *[]){
            kSecClass,
            kSecAttrService,
            kSecAttrAccount,
            kSecValueData,
            kSecAttrAccessible
        },
        (const void *[]){
            kSecClassGenericPassword,
            KEY_SERVICE,
            KEY_ACCOUNT_PUB,
            pubKeyData,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        },
        5,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    
    status = SecItemAdd(pubAddQuery, NULL);
    CFRelease(pubAddQuery);
    CFRelease(pubKeyData);
    if(status != errSecSuccess)
    {
        return -1;
    }
    
    return 0;
}

bool get_static_kernel_key(uint8_t **priv_bytes,
                           size_t *priv_len,
                           uint8_t **pub_bytes,
                           size_t *pub_len)
{
    CFDictionaryRef privQuery = CFDictionaryCreate(
                                                   NULL,
                                                   (const void *[]){ kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit },
                                                   (const void *[]){ kSecClassGenericPassword, KEY_SERVICE, KEY_ACCOUNT_PRIV, kCFBooleanTrue, kSecMatchLimitOne },
                                                   5,
                                                   &kCFTypeDictionaryKeyCallBacks,
                                                   &kCFTypeDictionaryValueCallBacks
                                                   );
    
    CFDataRef privResult = NULL;
    OSStatus status = SecItemCopyMatching(privQuery, (CFTypeRef *)&privResult);
    CFRelease(privQuery);
    
    if(status == errSecItemNotFound)
    {
        uint8_t *new_priv = NULL, *new_pub = NULL;
        size_t new_priv_len = 0, new_pub_len = 0;
        
        if(!get_kernel_ec_key(&new_priv, &new_priv_len, &new_pub, &new_pub_len))
        {
            return false;
        }
        
        if(store_kernel_key(new_priv, new_priv_len, new_pub, new_pub_len) != 0)
        {
            free(new_priv);
            free(new_pub);
            return false;
        }
        
        if(priv_bytes)
        {
            *priv_bytes = new_priv;
            *priv_len = new_priv_len;
        }
        else
        {
            free(new_priv);
        }
                
        if(pub_bytes)
        {
            *pub_bytes = new_pub;
            *pub_len = new_pub_len;
        }
        else
        {
            free(new_pub);
        }
        
        return true;
    }
    
    if(status != errSecSuccess || !privResult)
    {
        return false;
    }
    
    CFDictionaryRef pubQuery = CFDictionaryCreate(NULL, (const void *[]){ kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit }, (const void *[]){ kSecClassGenericPassword, KEY_SERVICE, KEY_ACCOUNT_PUB, kCFBooleanTrue, kSecMatchLimitOne }, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks );
    CFDataRef pubResult = NULL;
    status = SecItemCopyMatching(pubQuery, (CFTypeRef *)&pubResult);
    CFRelease(pubQuery);
    
    if(status != errSecSuccess || !pubResult)
    {
        CFRelease(privResult);
        return false;
    }
    
    if(priv_bytes)
    {
        CFIndex plen = CFDataGetLength(privResult);
        *priv_bytes = (uint8_t *)malloc(plen);
        if(!*priv_bytes)
        {
            CFRelease(privResult);
            CFRelease(pubResult);
            return false;
        }
        CFDataGetBytes(privResult, CFRangeMake(0, plen), *priv_bytes);
        if(priv_len)
        {
            *priv_len = (size_t)plen;
        }
    }
    CFRelease(privResult);
    if(pub_bytes)
    {
        CFIndex publen = CFDataGetLength(pubResult);
        *pub_bytes = (uint8_t *)malloc(publen);
        if(!*pub_bytes)
        {
            free(*priv_bytes);
            *priv_bytes = NULL;
            CFRelease(pubResult);
            return false;
        }
        CFDataGetBytes(pubResult, CFRangeMake(0, publen), *pub_bytes);
        if(pub_len)
        {
            *pub_len = (size_t)publen;
        }
    }
    CFRelease(pubResult);
    
    return true;
}

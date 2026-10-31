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

#import <Foundation/Foundation.h>
#import <LindChain/IDEFoundation/NXBootstrap.h>
#include <LindChain/ProcEnvironment/Surface/trust/keychain.h>
#include <LindChain/ProcEnvironment/Surface/surface.h>
#include <os/lock.h>
#include <OpenSSL/evp.h>
#include <OpenSSL/err.h>
#include <OpenSSL/ec.h>
#include <OpenSSL/pem.h>

static os_unfair_lock g_keychain_lock = OS_UNFAIR_LOCK_INIT;
static NSMutableArray<NSData*> *g_keychain = nil;

kern_return_t ksurface_keychain_update(void)
{
    os_unfair_lock_lock(&g_keychain_lock);
    
    if(g_keychain)
    {
        for(NSData *data in g_keychain)
        {
            nxt2_vendor_key_t *key = (nxt2_vendor_key_t*)data.bytes;
            free(key->vendor_name);
            free(key->public_key);
        }
        [g_keychain removeAllObjects];
    }
    else
    {
        g_keychain = [NSMutableArray array];
        if(!g_keychain)
        {
            os_unfair_lock_unlock(&g_keychain_lock);
            return KERN_RESOURCE_SHORTAGE;
        }
    }
    
    /* putting own key into the keychain (so resigning works on changed certificate) */
    nxt2_vendor_key_t ksurface_vendor;
    ksurface_vendor.vendor_name = strdup("ksurface.private");
    if(ksurface_vendor.vendor_name == NULL)
    {
        os_unfair_lock_unlock(&g_keychain_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    ksurface_vendor.public_key = malloc(ksurface->pub_key_len);
    if(ksurface_vendor.public_key == NULL)
    {
        os_unfair_lock_unlock(&g_keychain_lock);
        return KERN_RESOURCE_SHORTAGE;
    }
    ksurface_vendor.public_key_len = ksurface->pub_key_len;
    memcpy(ksurface_vendor.public_key, ksurface->pub_key, ksurface->pub_key_len);
    
    NSData *ksurfaceKey = [NSData dataWithBytes:&ksurface_vendor length:sizeof(ksurface_vendor)];
    if(ksurfaceKey)
    {
        [g_keychain addObject:ksurfaceKey];
    }
    else
    {
        free(ksurface_vendor.vendor_name);
        free(ksurface_vendor.public_key);
    }
    
    
    /* looking up da rootca's */
    NSArray<NSURL*> *rootCAs = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NXBootstrap.shared.rootURL URLByAppendingPathComponent:@"RootCAs"] includingPropertiesForKeys:@[] options:0 error:nil];
    if(rootCAs == nil)
    {
        os_unfair_lock_unlock(&g_keychain_lock);
        return KERN_SUCCESS;    /* no rootca's available yet */
    }
    
    /* itterating rootca's */
    for(NSURL *rootCA in rootCAs)
    {
        nxt2_vendor_key_t vendor;
        if(trust_nxt2_public_key_read(rootCA.path.UTF8String, &vendor) == KERN_SUCCESS)
        {
            NSData *key = [NSData dataWithBytes:&vendor length:sizeof(vendor)];
            if(key)
            {
                [g_keychain addObject:key];
            }
            else
            {
                free(vendor.vendor_name);
                free(vendor.public_key);
            }
        }
    }
    
    os_unfair_lock_unlock(&g_keychain_lock);
    return KERN_SUCCESS;
}

kern_return_t ksurface_keychain_match(ksurface_nxt2_blob_footer_t *footer,
                                      ksurface_nxt2_blob_header_t *header)
{
    os_unfair_lock_lock(&g_keychain_lock);
    
    if(!g_keychain)
    {
        /* no trust identity to try the key on lol ^^ */
        os_unfair_lock_unlock(&g_keychain_lock);
        return KERN_NOT_FOUND;
    }
    
    bool didMatch = false;
    for(NSData *data in g_keychain)
    {
        nxt2_vendor_key_t *key = (nxt2_vendor_key_t*)data.bytes;
        printf("trying RootCA public key by vendor '%s'\n", key->vendor_name);
        
        const uint8_t *p = key->public_key;
        EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, key->public_key_len);
        if(!pub)
        {
            continue;
        }
        
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if(!mdctx)
        {
            EVP_PKEY_free(pub);
            continue;
        }
        
        if(EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pub);
            continue;
        }
        
        if(EVP_DigestVerify(mdctx, footer->mac, footer->mac_len, (unsigned char *)header, offsetof(ksurface_nxt2_blob_header_t, plist_data) + header->plist_len) == 1)
        {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pub);
            printf("RootCA by vendor '%s' matched\n", key->vendor_name);
            didMatch = true;
            break;
        }
        
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pub);
    }
    
    os_unfair_lock_unlock(&g_keychain_lock);
    return didMatch ? KERN_SUCCESS : KERN_FAILURE;  /* signing reader has to resign it with priv key */
}

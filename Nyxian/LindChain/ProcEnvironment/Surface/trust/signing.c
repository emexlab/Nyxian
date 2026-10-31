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

/* ----------------------------------------------------------------------
 *  Project Headers
 * -------------------------------------------------------------------- */
#include <LindChain/ProcEnvironment/Surface/trust/signing.h>
#include <LindChain/ProcEnvironment/Surface/trust/cdhash.h>
#include <LindChain/ProcEnvironment/Surface/trust/keychain.h>
#include <LindChain/ProcEnvironment/Surface/surface.h>
#include <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#include <sys/stat.h>
#if __has_include(<OpenSSL/evp.h>)
#define HAS_OPENSSL 1
#include <OpenSSL/evp.h>
#include <OpenSSL/err.h>
#include <OpenSSL/ec.h>
#include <OpenSSL/pem.h>
#else
#define HAS_OPENSSL 0
#endif /* __has_include(<OpenSSL/evp.h>) */

#ifndef __NXTOOL
#ifdef CLIENT_ENV
#define __NXTOOL CLIENT_ENV
#else
#define __NXTOOL 0
#endif /* CLIENT_ENV */
#endif /* !__NXTOOL */

/* ----------------------------------------------------------------------
 *  Functions
 * -------------------------------------------------------------------- */
#if HAS_OPENSSL && __NXTOOL

static EVP_PKEY *trust_nxt2_private_key_from_der_path(const char *path)
{
    if(path == NULL)
    {
        return NULL;
    }
    
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if(fd < 0)
    {
        return NULL;
    }
    
    struct stat st;
    if(fstat(fd, &st) != 0)
    {
        close(fd);
        return NULL;
    }
    
    if(!S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > (64 * 1024))
    {
        close(fd);
        return NULL;
    }
    
    size_t length = (size_t)st.st_size;
    uint8_t *der = malloc(length);
    if(der == NULL)
    {
        close(fd);
        return NULL;
    }
    
    size_t offset = 0;
    
    while(offset < length)
    {
        ssize_t n = read(fd, der + offset, length - offset);
        if(n < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
            
            OPENSSL_cleanse(der, length);
            free(der);
            close(fd);
            
            return NULL;
        }
        
        if(n == 0)
        {
            OPENSSL_cleanse(der, length);
            free(der);
            close(fd);
            
            return NULL;
        }
        
        offset += (size_t)n;
    }
    
    close(fd);
    
    const unsigned char *p = der;
    
    EVP_PKEY *priv = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, (long)length);
    if(priv == NULL || p != der + length)
    {
        EVP_PKEY_free(priv);
        
        OPENSSL_cleanse(der, length);
        free(der);
        
        return NULL;
    }
    
    if(EVP_PKEY_base_id(priv) != EVP_PKEY_EC)
    {
        EVP_PKEY_free(priv);
        OPENSSL_cleanse(der, length);
        free(der);
        return NULL;
    }

    OPENSSL_cleanse(der, length);
    free(der);
    
    return priv;
}

#endif /* HAS_OPENSSL && __NXTOOL */

static CFDataRef trust_dict_to_plist(CFDictionaryRef dict)
{
    CFErrorRef err = NULL;
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault, dict, kCFPropertyListXMLFormat_v1_0, 0, &err);
    if(!data)
    {
        if(err)
        {
            CFStringRef desc = CFErrorCopyDescription(err);
            CFRelease(desc);
            CFRelease(err);
        }
        return NULL;
    }
    return data;
}

static CFDictionaryRef trust_plist_to_dict(CFDataRef data)
{
    if(!data)
    {
        return NULL;
    }
    
    CFErrorRef err = NULL;
    CFPropertyListFormat fmt;
    CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault, data, kCFPropertyListImmutable, &fmt, &err);
    
    if(!plist)
    {
        if(err)
        {
            CFRelease(err);
        }
        return NULL;
    }
    
    if(CFGetTypeID(plist) != CFDictionaryGetTypeID())
    {
        CFRelease(plist);
        return NULL;
    }
    return (CFDictionaryRef)plist;
}

kern_return_t trust_remove_blob(const char *path)
{
    int fd = open(path, O_RDWR);
    if(fd < 0)
    {
        return KERN_FAILURE;
    }
    
    kern_return_t kr = trust_remove_blob_fd(fd);
    fsync(fd);
    close(fd);
    return kr;
}

kern_return_t trust_remove_blob_fd(int fd)
{
    char tag[4];
    uint32_t len;
    
    off_t size = lseek(fd, 0, SEEK_END);
    if(size < 0)
    {
        return KERN_FAILURE;
    }
    if(size < 8)
    {
        return KERN_SUCCESS;
    }
    if(lseek(fd, -4, SEEK_END) < 0)
    {
        return KERN_FAILURE;
    }
    if(read(fd, tag, 4) != 4)
    {
        return KERN_FAILURE;
    }
    
    if(memcmp(tag, APPEND_TAG_NXTR, 4) != 0 &&
       memcmp(tag, APPEND_TAG_NXT2, 4) != 0)
    {
        /* no blob present */
        return KERN_SUCCESS;
    }
    
    if(lseek(fd, -8, SEEK_END) < 0)
    {
        return KERN_FAILURE;
    }
    if(read(fd, &len, sizeof(uint32_t)) != sizeof(uint32_t))
    {
        return KERN_FAILURE;
    }
    
    uint64_t total = (uint64_t)len + 8;
    if(total > (uint64_t)size)
    {
        return KERN_FAILURE;
    }
    
    return ftruncate(fd, (off_t)(size - total)) == 0 ? KERN_SUCCESS : KERN_FAILURE;
}

kern_return_t trust_nxt2_sign(const char *path,
                              CFDictionaryRef entitlements,
                              bool signBlob,
                              const char *priv_der_path)
{
    int fd = open(path, O_RDWR);
    if(fd < 0)
    {
        return KERN_FAILURE;
    }
    
    kern_return_t kr = trust_nxt2_sign_fd(fd, entitlements, signBlob, priv_der_path);
    fsync(fd);
    close(fd);
    return kr;
}

kern_return_t trust_nxt2_sign_fd(int fd,
                                 CFDictionaryRef entitlements,
                                 bool signBlob,
                                 const char *priv_der_path)
{
    LCMachO *machO = LCMapMachOFromFDRO(dup(fd));
    if(machO == NULL)
    {
        return KERN_FAILURE;
    }
    uint8_t cdhash[USER_FSIGNATURES_CDHASH_LEN];
    if(!CDHashOfMachO(machO->map, machO->size, (uint8_t*)&cdhash))
    {
        LCUnmapMachO(machO);
        return KERN_FAILURE;
    }
    LCUnmapMachO(machO);
    
    /* cut down to eof */
    trust_remove_blob_fd(fd);
    
    lseek(fd, 0, SEEK_END);
    
    /* generate nxt2 blob (nxt2 unlike nxtr requires us to do it our selves and not entitlements api) */
    CFDataRef entitlementsData = trust_dict_to_plist(entitlements);
    if(entitlementsData == NULL)
    {
        return KERN_FAILURE;
    }
    CFIndex entitlementsDataLength = CFDataGetLength(entitlementsData);
    size_t header_size = sizeof(ksurface_nxt2_blob_header_t) + (size_t)entitlementsDataLength;
    
    /* allocating the blob header */
    ksurface_nxt2_blob_header_t *blob_header = calloc(1, header_size);
    if(blob_header == NULL)
    {
        CFRelease(entitlementsData);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    /* writing entitlement data */
    memcpy((void*)blob_header->plist_data, CFDataGetBytePtr(entitlementsData), (size_t)entitlementsDataLength);
    blob_header->plist_len = (size_t)entitlementsDataLength;
    CFRelease(entitlementsData);
    
    ksurface_nxt2_blob_footer_t *blob_footer = NULL;
    size_t footer_size;
    
#if HAS_OPENSSL && !CLIENT_ENV
    /* signing blob if applicable */
    if(signBlob)
    {
        /* sign blob mode requires cdhash */
        memcpy((void*)(blob_header->cdhash), cdhash, USER_FSIGNATURES_CDHASH_LEN);
        
        /* generating nonce so it's harder to crack */
        arc4random_buf(&(blob_header->nonce), sizeof(uint64_t));
        
        EVP_PKEY *priv = NULL;
        
#if !__NXTOOL
        uint8_t *p = NULL;
        size_t p_len;
        if(!get_static_kernel_key(&(p), &(p_len), NULL, NULL))
        {
            /* shall never happen */
            free(blob_header);
            return KERN_FAILURE;
        }
        
        /* signing blob */
        const uint8_t *p_ptr = p;
        priv = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p_ptr, (long)p_len);
        OPENSSL_cleanse(p, p_len);
        free(p);
#else
        if(priv_der_path == NULL)
        {
            free(blob_header);
            return KERN_INVALID_ARGUMENT;
        }
        
        priv = trust_nxt2_private_key_from_der_path(priv_der_path);
#endif /* !__NXTOOL */
        
        if(!priv)
        {
            free(blob_header);
            return KERN_FAILURE;
        }
        
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if(!mdctx)
        {
            free(blob_header);
            EVP_PKEY_free(priv);
            return KERN_FAILURE;
        }
        
        if(EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, priv) != 1)
        {
            free(blob_header);
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(priv);
            return KERN_FAILURE;
        }
        
        /* allocate the blob footer to hold the signature */
        footer_size = sizeof(ksurface_nxt2_blob_footer_t);
        blob_footer = calloc(1, sizeof(ksurface_nxt2_blob_footer_t));
        if(blob_footer == NULL)
        {
            free(blob_header);
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(priv);
            return KERN_RESOURCE_SHORTAGE;
        }
        
        size_t mac_len = 72;
        if(EVP_DigestSign(mdctx, blob_footer->mac, &mac_len, (const unsigned char *)blob_header, header_size) != 1)
        {
            free(blob_header);
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(priv);
            return KERN_FAILURE;
        }
        blob_footer->mac_len = mac_len;
        
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(priv);
    }
    else
    {
#endif /* HAS_OPENSSL && !CLIENT_ENV */
        /* zero out all signing related */
        bzero((void*)(blob_header->cdhash), sizeof(blob_header->cdhash));
        footer_size = sizeof(ksurface_nxt2_blob_footer_t);
        blob_footer = calloc(1, sizeof(ksurface_nxt2_blob_footer_t));
        if(blob_footer == NULL)
        {
            free(blob_header);
            return KERN_RESOURCE_SHORTAGE;
        }
        
        blob_footer->mac_len = 0;
        bzero(blob_footer->mac, sizeof(blob_footer->mac));
#if HAS_OPENSSL && !CLIENT_ENV
    }
#endif /* HAS_OPENSSL && !CLIENT_ENV */
    
    /* write blob */
    if(write(fd, blob_header, header_size) != (ssize_t)header_size)
    {
        free(blob_footer);
        free(blob_header);
        return KERN_FAILURE;
    }
    
    if(write(fd, blob_footer, footer_size) != (ssize_t)footer_size)
    {
        free(blob_footer);
        free(blob_header);
        return KERN_FAILURE;
    }
    
    free(blob_footer);
    free(blob_header);
    
    /* write tag */
    uint32_t data_len = (uint32_t)(header_size + footer_size);
    if(header_size + footer_size > UINT32_MAX)
    {
        return KERN_FAILURE;
    }
    
    if(write(fd, &data_len, sizeof(uint32_t)) != (ssize_t)sizeof(uint32_t))
    {
        return KERN_FAILURE;
    }
    
    if(write(fd, APPEND_TAG_NXT2, 4) != 4)
    {
        return KERN_FAILURE;
    }
    
    fsync(fd);
    
    return KERN_SUCCESS;
}

#if !defined(BOOT)

kern_return_t trust_nxt2_read(const char *path,
                              ksurface_nxt2_t *result)
{
    int fd = open(path, O_RDONLY);
    if(fd < 0)
    {
        return KERN_FAILURE;
    }
    
    kern_return_t kr = trust_nxt2_read_fd(fd, result);
    close(fd);
    return kr;
}

kern_return_t trust_nxt2_read_fd(int fd,
                                 ksurface_nxt2_t *result)
{
    if(fd < 0 || result == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    bzero(result, sizeof(*result));
    
    /* read nxt2 tag */
    char tag[4];
    uint32_t len = 0;
    
    if(lseek(fd, -4, SEEK_END) < 0)
    {
        return KERN_FAILURE;
    }
    if(read(fd, tag, 4) != 4)
    {
        return KERN_FAILURE;
    }
    
    if(memcmp(tag, APPEND_TAG_NXT2, 4) != 0)
    {
        return KERN_FAILURE;
    }
    
    /* read nxt2 length */
    if(lseek(fd, -8, SEEK_END) < 0)
    {
        return KERN_FAILURE;
    }
    if(read(fd, &len, sizeof(uint32_t)) != (ssize_t)sizeof(uint32_t))
    {
        return KERN_FAILURE;
    }
    
    /* check sizing */
    size_t min_blob = offsetof(ksurface_nxt2_blob_header_t, plist_data) + sizeof(ksurface_nxt2_blob_footer_t);
    if(len < min_blob)
    {
        /* NXT2 blob doesn't fit */
        return KERN_DENIED;
    }
    
    if(len > PAGE_SIZE)
    {
        /* could be a exhaustion attack */
        return KERN_DENIED;
    }
    
    if(lseek(fd, -(off_t)(8 + len), SEEK_END) < 0)
    {
        return KERN_FAILURE;
    }
    
    /* reading the blob */
    uint8_t *blob_buf = malloc(len);
    if(blob_buf == NULL)
    {
        return KERN_NO_SPACE;
    }
    
    if(read(fd, blob_buf, len) != (ssize_t)len)
    {
        free(blob_buf);
        return KERN_FAILURE;
    }
    
    /* now we get the footer and validate it */
    ksurface_nxt2_blob_footer_t *blob_footer = (ksurface_nxt2_blob_footer_t*)((blob_buf + len) - sizeof(ksurface_nxt2_blob_footer_t));
    if(blob_footer->mac_len > sizeof(blob_footer->mac))
    {
        free(blob_buf);
        return KERN_DENIED;
    }
    
    /* now we get the header and validate it */
    ksurface_nxt2_blob_header_t *blob_header = (ksurface_nxt2_blob_header_t*)blob_buf;
    size_t plist_gap_len = len - (offsetof(ksurface_nxt2_blob_header_t, plist_data) + sizeof(ksurface_nxt2_blob_footer_t));
    if(blob_header->plist_len > plist_gap_len)
    {
        free(blob_buf);
        return KERN_DENIED;
    }
    
    /* getting entitlements back */
    CFDataRef entitlementsData = CFDataCreate(kCFAllocatorDefault, (const UInt8*)blob_header->plist_data, (CFIndex)blob_header->plist_len);
    if(entitlementsData == NULL)
    {
        free(blob_buf);
        return KERN_NO_SPACE;
    }
    
    CFDictionaryRef entitlements = trust_plist_to_dict(entitlementsData);
    CFRelease(entitlementsData);
    if(entitlements == NULL)
    {
        free(blob_buf);
        return KERN_NO_SPACE;
    }
    
    result->isValid = true; /* everything parsed successfully */
    
#if !__NXTOOL
    memcpy(result->cdhash, blob_header->cdhash, USER_FSIGNATURES_CDHASH_LEN);
    LCMachO *machO = LCMapMachOFromFDRO(dup(fd));
    if(machO != NULL)
    {
        uint8_t cdhash[USER_FSIGNATURES_CDHASH_LEN];
        if(CDHashOfMachO(machO->map, machO->size, (uint8_t*)&cdhash))
        {
            if(memcmp(cdhash, result->cdhash, USER_FSIGNATURES_CDHASH_LEN) == 0)
            {
                result->isCdHashValid = true;
            }
        }
        LCUnmapMachO(machO);
    }
#else
    result->isCdHashValid = false;
#endif /* !__NXTOOL */
    
#if HAS_OPENSSL && !__NXTOOL && !CLIENT_ENV
    if(result->isCdHashValid && result->isValid)
    {
        /* cdhash and blob must be valid for signature check, some checks are not performed twice */
        const uint8_t *p = ksurface->pub_key;
        EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, ksurface->pub_key_len);
        if(!pub)
        {
            goto signature_invalid;
        }
        
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if(!mdctx)
        {
            EVP_PKEY_free(pub);
            goto signature_invalid;
        }
        
        if(EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pub);
            goto signature_invalid;
        }
        
        if(EVP_DigestVerify(mdctx, blob_footer->mac, blob_footer->mac_len, (unsigned char *)blob_header, offsetof(ksurface_nxt2_blob_header_t, plist_data) + blob_header->plist_len) == 1)
        {
            result->isSigned = true;
        }
        
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pub);
    }
    
#if HOST_ENV
    if(!result->isSigned && ksurface_keychain_match(blob_footer, blob_header) == KERN_SUCCESS)
    {
        /* FIXME: check if CS hashes matches the cdhash before trusting the rootca blindly */
        result->needsResign = true;
    }
#endif /* HOST_ENV */
#else
    /* cannot verify without openssl */
    result->isSigned = false;
#endif /* HAS_OPENSSL && !__NXTOOL && !CLIENT_ENV*/
    
signature_invalid:
    free(blob_buf);
    result->entitlements = entitlements;
    return KERN_SUCCESS;
}

#endif /* !defined(BOOT) */

#if HAS_OPENSSL && HOST_ENV

static int write_all(int fd,
                     const uint8_t *data,
                     size_t length)
{
    while(length > 0)
    {
        ssize_t n = write(fd, data, length);
        if(n < 0)
        {
            return -1;
        }
        
        if(n == 0)
        {
            return -1;
        }
        
        data += n;
        length -= (size_t)n;
    }
    
    return 0;
}

kern_return_t trust_nxt2_generate_rootca_keypair(const char *vendor_name,
                                                 const char *public_key_path,
                                                 const char *private_key_path)
{
    if(vendor_name == NULL ||
       public_key_path == NULL ||
       private_key_path == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    size_t vendor_name_len = strlen(vendor_name);

    if(vendor_name_len == 0 ||
       vendor_name_len > NXT2_VENDOR_NAME_MAX)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    kern_return_t kr = KERN_FAILURE;
    
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    
    uint8_t *public_der = NULL;
    uint8_t *private_der = NULL;
    
    int public_fd = -1;
    int private_fd = -1;
    
    int private_len = 0;
    
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(ctx == NULL)
    {
        goto done;
    }
    
    if(EVP_PKEY_keygen_init(ctx) <= 0)
    {
        goto done;
    }
    
    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
    {
        goto done;
    }
    
    if(EVP_PKEY_keygen(ctx, &key) <= 0)
    {
        goto done;
    }
    
    /* generate public key (so guests can Nyxian builds can validate if it has been signed with a RootCA) */
    int public_len = i2d_PUBKEY(key, NULL);
    if(public_len <= 0)
    {
        goto done;
    }
    
    public_der = malloc((size_t)public_len);
    if(public_der == NULL)
    {
        kr = KERN_RESOURCE_SHORTAGE;
        goto done;
    }
    
    unsigned char *public_ptr = public_der;
    if(i2d_PUBKEY(key, &public_ptr) != public_len)
    {
        goto done;
    }
    
    /* generate private key for the host */
    private_len = i2d_PrivateKey(key, NULL);
    if(private_len <= 0)
    {
        goto done;
    }
    
    private_der = malloc((size_t)private_len);
    if(private_der == NULL)
    {
        kr = KERN_RESOURCE_SHORTAGE;
        goto done;
    }
    
    unsigned char *private_ptr = private_der;
    if(i2d_PrivateKey(key, &private_ptr) != private_len)
    {
        goto done;
    }
    
    /* public key is not a secret ^^ */
    public_fd = open(public_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(public_fd < 0)
    {
        goto done;
    }
    
    nxt2_pubkey_header_t pub_header = {
        .magic = NXT2_PUBKEY_MAGIC,
        .version = NXT2_PUBKEY_VERSION,
        .name_len = (uint32_t)vendor_name_len,
        .key_len = (uint32_t)public_len,
    };
    
    if(write_all(public_fd,
                 (const uint8_t *)&pub_header,
                 sizeof(pub_header)) != 0)
    {
        goto done;
    }
    
    if(write_all(public_fd,
                 (const uint8_t *)vendor_name,
                 vendor_name_len) != 0)
    {
        goto done;
    }
    
    if(write_all(public_fd,
                 public_der,
                 (size_t)public_len) != 0)
    {
        goto done;
    }
    
    if(fsync(public_fd) != 0)
    {
        goto done;
    }
    
    /* private key MUST be private >:3 (I watch you) */
    private_fd = open(private_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(private_fd < 0)
    {
        goto done;
    }
    
    if(write_all(private_fd, private_der, (size_t)private_len) != 0)
    {
        goto done;
    }
    
    if(fsync(private_fd) != 0)
    {
        goto done;
    }
    
    kr = KERN_SUCCESS;
    
done:
    if(public_fd >= 0)
    {
        close(public_fd);
    }
    
    if(private_fd >= 0)
    {
        close(private_fd);
    }
    
    if(private_der != NULL)
    {
        /* Otherwise attacker says kread ;3 */
        OPENSSL_cleanse(private_der, (size_t)(private_len > 0 ? private_len : 0));
        free(private_der);
    }
    free(public_der);
    
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    
    return kr;
}

kern_return_t trust_nxt2_public_key_read(const char *path,
                                         nxt2_vendor_key_t *result)
{
    if(path == NULL || result == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    memset(result, 0, sizeof(*result));
    
    int fd = open(path, O_RDONLY);
    if(fd < 0)
    {
        return KERN_FAILURE;
    }
    
    kern_return_t kr = KERN_FAILURE;
    
    nxt2_pubkey_header_t hdr;
    if(read(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
    {
        goto done;
    }
    
    if(hdr.magic != NXT2_PUBKEY_MAGIC ||
       hdr.version != NXT2_PUBKEY_VERSION)
    {
        goto done;
    }
    
    if(hdr.name_len == 0 ||
       hdr.name_len > NXT2_VENDOR_NAME_MAX)
    {
        goto done;
    }
    
    if(hdr.key_len == 0 ||
       hdr.key_len > 4096)
    {
        goto done;
    }
    
    char *name = calloc(1, (size_t)hdr.name_len + 1);
    if(name == NULL)
    {
        kr = KERN_RESOURCE_SHORTAGE;
        goto done;
    }
    
    if(read(fd, name, hdr.name_len) != (ssize_t)hdr.name_len)
    {
        free(name);
        goto done;
    }
    
    uint8_t *key = malloc(hdr.key_len);
    if(key == NULL)
    {
        free(name);
        kr = KERN_RESOURCE_SHORTAGE;
        goto done;
    }
    
    if(read(fd, key, hdr.key_len) != (ssize_t)hdr.key_len)
    {
        free(key);
        free(name);
        goto done;
    }
    
    const unsigned char *p = key;
    EVP_PKEY *pub = d2i_PUBKEY(NULL, &p, hdr.key_len);
    if(pub == NULL)
    {
        free(key);
        free(name);
        goto done;
    }
    
    if(p != key + hdr.key_len)
    {
        EVP_PKEY_free(pub);
        free(key);
        free(name);
        goto done;
    }
    
    if(EVP_PKEY_base_id(pub) != EVP_PKEY_EC)
    {
        EVP_PKEY_free(pub);
        free(key);
        free(name);
        goto done;
    }
    
    EVP_PKEY_free(pub);
    
    result->vendor_name = name;
    result->public_key = key;
    result->public_key_len = hdr.key_len;
    
    kr = KERN_SUCCESS;
    
done:
    close(fd);
    return kr;
}

#endif /* HAS_OPENSSL && HOST_ENV */

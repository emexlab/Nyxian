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

#import "NXDeviceIdentity.h"
#import <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <sys/attr.h>
#include <unistd.h>
#include <uuid/uuid.h>

static NSString *const NXDeviceIdentityDomain = @"org.emexlabs.nyxian.device-identity";
static NSString *const NXDeviceUniqueIDFile = @"UniqueID";
static const NSUInteger NXDeviceUniqueIDLength = 64;

static BOOL NXDeviceIdentityFail(NSError **error, NSInteger code, NSString *message)
{
    if(error != NULL)
    {
        *error = [NSError errorWithDomain:NXDeviceIdentityDomain code:code userInfo:@{ NSLocalizedDescriptionKey: message }];
    }
    return NO;
}

static BOOL NXDeviceUniqueIDValid(NSString *value)
{
    if(value.length != NXDeviceUniqueIDLength)
    {
        return NO;
    }
    for(NSUInteger i = 0; i < value.length; i++)
    {
        unichar c = [value characterAtIndex:i];
        if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        {
            return NO;
        }
    }
    return YES;
}

static NSString *NXDeviceUniqueIDMirrorPath(void)
{
    NSString *library = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES).firstObject;
    return [[library stringByAppendingPathComponent:@"NyxLoader"] stringByAppendingPathComponent:NXDeviceUniqueIDFile];
}

static NSString *NXDeviceUniqueIDSourceName = @"none";

static NSString *NXDeviceDataVolumeUUID(void)
{
    NSURL *home = [NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES];
    NSString *uuid = nil;
    if([home getResourceValue:&uuid forKey:NSURLVolumeUUIDStringKey error:NULL] && uuid.length > 0)
    {
        return uuid.uppercaseString;
    }
    
    struct {
        uint32_t length;
        uuid_t uuid;
    } __attribute__((aligned(4), packed)) buffer;
    struct attrlist list = {0};
    list.bitmapcount = ATTR_BIT_MAP_COUNT;
    list.volattr = ATTR_VOL_INFO | ATTR_VOL_UUID;
    if(getattrlist(home.fileSystemRepresentation, &list, &buffer, sizeof(buffer), 0) != 0 || uuid_is_null(buffer.uuid))
    {
        return nil;
    }
    uuid_string_t text;
    uuid_unparse_upper(buffer.uuid, text);
    return @(text);
}

static NSString *NXDeviceUniqueIDFallback(void)
{
    NSString *mirrored = [[NSString stringWithContentsOfFile:NXDeviceUniqueIDMirrorPath() encoding:NSASCIIStringEncoding error:nil]
                          stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if(NXDeviceUniqueIDValid(mirrored))
    {
        NXDeviceUniqueIDSourceName = @"container";
        return mirrored;
    }
    
    NSString *volume = NXDeviceDataVolumeUUID();
    if(volume == nil)
    {
        return nil;
    }
    NSMutableData *input = [NSMutableData dataWithBytes:"NXDevice-UniqueID-v1" length:sizeof("NXDevice-UniqueID-v1")];
    [input appendData:[volume dataUsingEncoding:NSASCIIStringEncoding]];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(input.bytes, (CC_LONG)input.length, digest);
    NSMutableString *value = [NSMutableString stringWithCapacity:NXDeviceUniqueIDLength];
    for(size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
    {
        [value appendFormat:@"%02x", digest[i]];
    }
    NXDeviceUniqueIDSourceName = @"volume";
    return value;
}

NSString *NXDeviceUniqueIDSource(void)
{
    NXDeviceUniqueID(NULL);
    return NXDeviceUniqueIDSourceName;
}

NSString *NXDeviceUniqueID(NSError **error)
{
    static NSString *cached;
    static NSError *cachedError;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:NXDeviceUniqueIDFile];
        NSError *readError = nil;
        NSString *raw = [NSString stringWithContentsOfFile:path encoding:NSASCIIStringEncoding error:&readError];
        if(raw == nil)
        {
            cached = NXDeviceUniqueIDFallback();
            if(cached == nil)
            {
                NSError *e = nil;
                NXDeviceIdentityFail(&e, ENOENT, @"this Nyxian has no UniqueID: it wasn't installed with NyxLoader, and the data volume's UUID can't be read");
                cachedError = e;
            }
            return;
        }
        NSString *value = [raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if(!NXDeviceUniqueIDValid(value))
        {
            NSError *e = nil;
            NXDeviceIdentityFail(&e, EINVAL, @"the bundle's UniqueID is malformed: reinstall Nyxian with NyxLoader");
            cachedError = e;
            return;
        }
        cached = value;
        NXDeviceUniqueIDSourceName = @"bundle";
    });
    if(cached == nil && error != NULL)
    {
        *error = cachedError;
    }
    return cached;
}

BOOL NXDeviceHasUniqueID(void)
{
    return NXDeviceUniqueID(NULL) != nil;
}

BOOL NXDeviceMirrorUniqueID(NSError **error)
{
    NSString *value = NXDeviceUniqueID(error);
    if(value == nil)
    {
        return NO;
    }
    
    NSString *path = NXDeviceUniqueIDMirrorPath();
    NSString *current = [NSString stringWithContentsOfFile:path encoding:NSASCIIStringEncoding error:nil];
    if([[current stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] isEqualToString:value])
    {
        return YES;
    }
    
    NSError *ioError = nil;
    if(![NSFileManager.defaultManager createDirectoryAtPath:path.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:&ioError] ||
       ![[value stringByAppendingString:@"\n"] writeToFile:path atomically:YES encoding:NSASCIIStringEncoding error:&ioError])
    {
        return NXDeviceIdentityFail(error, ioError.code ?: EIO, [NSString stringWithFormat:@"could not keep the UniqueID for NyxLoader: %@", ioError.localizedDescription]);
    }
    
    return YES;
}

NSString *NXDeviceIdentifier(NSError **error)
{
    return NXDeviceUniqueID(error);
}

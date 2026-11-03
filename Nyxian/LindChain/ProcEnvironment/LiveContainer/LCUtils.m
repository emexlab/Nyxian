/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2023 - 2026 LiveContainer
 Copyright (C) 2026 emexlab

 This file is part of LiveContainer.

 LiveContainer is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 LiveContainer is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#import <LindChain/ProcEnvironment/LiveContainer/LCUtils.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#import <LindChain/ProcEnvironment/LiveContainer/ZSign/zsigner.h>
#import <LindChain/Private/FoundationPrivate.h>
#import <Security/Security.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <dlfcn.h>

extern BOOL PEURLIsContainedIn(NSURL *candidate, NSURL *root);

@implementation LCUtils

#pragma mark Certificate & password

+ (void)setCertificateData:(NSData *)certificateData
{
    [NSUserDefaults.standardUserDefaults setObject:certificateData forKey:@"LCCertificateData"];
}

+ (void)setCertificatePassword:(NSString *)certificatePassword
{
    [NSUserDefaults.standardUserDefaults setObject:certificatePassword forKey:@"LCCertificatePassword"];
}

+ (NSData *)certificateData
{
    return [NSUserDefaults.standardUserDefaults objectForKey:@"LCCertificateData"];
}

+ (NSString *)certificatePassword
{
    return [NSUserDefaults.standardUserDefaults objectForKey:@"LCCertificatePassword"];
}

+ (NSData *)profileData
{
    static dispatch_once_t onceToken;
    static NSData *profileData = nil;
    dispatch_once(&onceToken, ^{
        NSURL *profilePath = [NSBundle.mainBundle URLForResource:@"embedded" withExtension:@"mobileprovision"];
        if(profilePath == nil)
        {
            return;
        }
        
        profileData = [NSData dataWithContentsOfURL:profilePath];
    });
    return profileData;
}

#pragma mark Code signing

+ (NSError *)patchExecutable:(NSString*)path
{
    NSError *error = nil;
    LCMachO *machO = LCMapMachO(path.UTF8String, false);
    if(machO != nil)
    {
        if(machO->header->cputype != CPU_TYPE_ARM64 || !LCPatchExecSlice(machO))
        {
            error = [NSError errorWithDomain:@"com.nyxian.lcutils" code:0 userInfo:@{ NSLocalizedDescriptionKey: @"unsupported executable format" } ];
        }
        LCUnmapMachO(machO);
    }
    else
    {
        error = [NSError errorWithDomain:@"com.nyxian.lcutils" code:0 userInfo:@{ NSLocalizedDescriptionKey: @"couldn't map MachO file" } ];
    }
    return error;
}

+ (NSProgress *)signAppBundleWithZSign:(NSURL *)path
                     completionHandler:(void (^)(BOOL success, NSError *error))completionHandler
{
    __block NSError *error = nil;
    
    /* trying to make a new NSBundle for the bundle at path */
    NSBundle *bundle = [NSBundle bundleWithURL:path];
    if(bundle == nil)
    {
        /* TODO: craft a error */
        completionHandler(NO, error);
    }
    
    /* patching executable slice if necessary */
    error = [LCUtils patchExecutable:bundle.executablePath];
    if(error)
    {
        completionHandler(NO, error);
        return nil;
    }
    
    /* patching arm64e things */
    LCPatchAppBundleFixupARM64eSlice(bundle);
    
    /* checking for root binaries */
    NSArray<NSString*> *tsRootBinaries = [bundle objectForInfoDictionaryKey:@"TSRootBinaries"];
    for(NSString *rootBinary in tsRootBinaries)
    {
        NSURL *urlToRootBinary = [bundle.bundleURL URLByAppendingPathComponent:rootBinary];
        if(!PEURLIsContainedIn(urlToRootBinary, bundle.bundleURL) || ![LCUtils signMachOAtURL:urlToRootBinary])
        {
            completionHandler(NO, [NSError errorWithDomain:@"org.emexlabs.nyxian.lcutils.signapp" code:1 userInfo:@{ NSLocalizedDescriptionKey: @"Failed to sign all TSRootBinaries contained in the app." }]);
            return nil;
        }
    }
    
    return [ZSigner signWithAppPath:[path path] prov:self.profileData key: self.certificateData pass:self.certificatePassword completionHandler:completionHandler];
}

+ (BOOL)signMachOAtURL:(NSURL *)url
{
    /* patching executable slice if necessary */
    NSError *error = error = [LCUtils patchExecutable:url.path];;
    if(error)
    {
        return NO;
    }
    
    /* use zsign as our signer~ (yeah daddy tim, were using zsigner as our signer, am i a bad girl now ;3) */
    return [ZSigner signMachOAtPath:url.path prov:self.profileData key:self.certificateData pass:self.certificatePassword];
}

+ (BOOL)signMachOWithoutPatchAtURL:(NSURL *)url
{
    /* use zsign as our signer~ (yeah daddy tim, were using zsigner as our signer, am i a bad girl now ;3) */
    return [ZSigner signMachOAtPath:url.path prov:self.profileData key:self.certificateData pass:self.certificatePassword];
}

+ (int)validateCertificateWithCompletionHandler:(void(^)(int status, NSString *error))completionHandler
{
    if(self.certificateData == nil)
    {
        completionHandler(1000, @"No certificate imported, please set up signing");
        return 1;
    }
    return [ZSigner checkCertWithProv:self.profileData key:self.certificateData pass:self.certificatePassword completionHandler:completionHandler];
}

+ (int)validateCertificateWithCertificateData:(NSData*)data
                                 withPassword:(NSString*)password
                        WithCompletionHandler:(void(^)(int status, NSString *error))completionHandler
{
    if(data == nil)
    {
        completionHandler(1000, @"No certificate imported, please set up signing");
        return 1000;
    }
    return [ZSigner checkCertWithProv:self.profileData key:data pass:password completionHandler:completionHandler];
}

@end

typedef enum {
    NXMachONone = 0,
    NXMachOExec,
    NXMachOLib,
    NXMachOOther,
} NXMachOKind;

static NXMachOKind NXClassifyMachO(const char *path)
{
    int fd = open(path, O_RDONLY);
    if(fd < 0)
    {
        return NXMachONone;
    }

    NXMachOKind kind = NXMachONone;
    uint32_t magic = 0;

    if(pread(fd, &magic, sizeof(magic), 0) == (ssize_t)sizeof(magic))
    {
        off_t hdr = 0;
        if(magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64)
        {
            bool swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
            bool is64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
            uint32_t nfat = 0;
            if(pread(fd, &nfat, 4, 4) == 4)
            {
                if(swap)
                {
                    nfat = __builtin_bswap32(nfat);
                }
                if(nfat > 0)
                {
                    if(is64)
                    {
                        uint64_t o = 0;
                        if(pread(fd, &o, 8, 16) == 8)
                        {
                            hdr = (off_t)(swap ? __builtin_bswap64(o) : o);
                        }
                    }
                    else
                    {
                        uint32_t o = 0;
                        if(pread(fd, &o, 4, 16) == 4)
                        {
                            hdr = (off_t)(swap ? __builtin_bswap32(o) : o);
                        }
                    }
                }
            }
        }

        uint32_t m = 0;
        if(pread(fd, &m, 4, hdr) == 4 && (m == MH_MAGIC || m == MH_CIGAM || m == MH_MAGIC_64 || m == MH_CIGAM_64))
        {
            bool swap = (m == MH_CIGAM || m == MH_CIGAM_64);
            uint32_t ft = 0;
            if(pread(fd, &ft, 4, hdr + 12) == 4)
            {
                if(swap)
                {
                    ft = __builtin_bswap32(ft);
                }
                switch(ft)
                {
                    case MH_EXECUTE:
                        kind = NXMachOExec;
                        break;
                    case MH_DYLIB: case MH_BUNDLE:
                        kind = NXMachOLib;
                        break;
                    default:
                        kind = NXMachOOther;
                        break;
                }
            }
        }
    }

    close(fd);
    return kind;
}

BOOL NXSignMachOAuto(NSURL *url)
{
    NXMachOKind kind = NXClassifyMachO(url.path.UTF8String);
    switch(kind)
    {
        case NXMachOExec:
            return [LCUtils signMachOAtURL:url];
        case NXMachOLib:
            return [LCUtils signMachOWithoutPatchAtURL:url];
        default:
            return NO;
    }
}

BOOL NXSignMachOWithIdentity(NSURL *url,
                             NSData *profile,
                             NSData *certificate,
                             NSString *password)
{
    NXMachOKind kind=NXClassifyMachO(url.path.UTF8String);
    if(kind != NXMachOExec && kind != NXMachOLib)
    {
        return NO;
    }
    if(kind == NXMachOExec && [LCUtils patchExecutable:url.path])
    {
        return NO;
    }
    return [ZSigner signMachOAtPath:url.path prov:profile key:certificate pass:password];
}

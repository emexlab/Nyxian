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

#import <LindChain/ProcEnvironment/KextLoader/PEKext.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#import <LindChain/ProcEnvironment/Surface/trust/signing.h>
#import <LindChain/ProcEnvironment/Surface/libkern/kxld/kxopen.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <LindChain/ProcEnvironment/Surface/libkern/version.h>
#import <sys/stat.h>
#import <sys/sysctl.h>

/* temporary so we can switch to kxopen now */

static inline bool macho_name_eq(const char *field,
                                 size_t field_size,
                                 const char *want)
{
    size_t have = strnlen(field, field_size);
    size_t want_len = strlen(want);
    return have == want_len && memcmp(field, want, want_len) == 0;
}

static inline bool range_ok(uint64_t off,
                            uint64_t len,
                            uint64_t total)
{
    return len <= total && off <= total - len;
}

static inline const uint8_t *ksurface_locate_modinfo(const uint8_t *base,
                                                     size_t size,
                                                     uint64_t *out_len)
{
    if(size < sizeof(struct mach_header_64))
    {
        return NULL;
    }
    
    const struct mach_header_64 *mh = (const struct mach_header_64 *)base;
    if(mh->magic != MH_MAGIC_64)
    {
        return NULL;
    }
    if(mh->filetype != MH_KEXT_BUNDLE)
    {
        return NULL;
    }
    if(!range_ok(sizeof(*mh), mh->sizeofcmds, size))
    {
        return NULL;
    }
    
    const uint8_t *cursor = base + sizeof(*mh);
    const uint8_t *lc_end = cursor + mh->sizeofcmds;
    for(uint32_t i = 0; i < mh->ncmds; i++)
    {
        if((uint64_t)(lc_end - cursor) < sizeof(struct load_command))
        {
            return NULL;
        }
        
        const struct load_command *lc = (const struct load_command *)cursor;
        if(lc->cmdsize < sizeof(struct load_command) ||
           (lc->cmdsize & 0x7) ||
           lc->cmdsize > (uint64_t)(lc_end - cursor))
        {
            return NULL;
        }
        
        if(lc->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if(lc->cmdsize < sizeof(*seg))
            {
                return NULL;
            }
            
            if(macho_name_eq(seg->segname, sizeof(seg->segname), SEG_DATA) ||
               macho_name_eq(seg->segname, sizeof(seg->segname), "__DATA_CONST"))
            {
                uint64_t need = sizeof(*seg) + (uint64_t)seg->nsects * sizeof(struct section_64);
                if(lc->cmdsize < need)
                {
                    return NULL;
                }
                
                const struct section_64 *sec = (const struct section_64 *)(cursor + sizeof(*seg));
                
                for(uint32_t j = 0; j < seg->nsects; j++)
                {
                    if(!macho_name_eq(sec[j].sectname, sizeof(sec[j].sectname), "__ksurfacemod"))
                    {
                        continue;
                    }
                    
                    uint32_t type = sec[j].flags & SECTION_TYPE;
                    if(type == S_ZEROFILL || type == S_THREAD_LOCAL_ZEROFILL)
                    {
                        return NULL;
                    }
                    
                    if(!range_ok(sec[j].offset, sec[j].size, size))
                    {
                        return NULL;
                    }
                    
                    *out_len = sec[j].size;
                    return base + sec[j].offset;
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return NULL;
}

static inline kern_return_t ksurface_kext_copy_kmod(const char *path,
                                                    kinfo_mod_t *out_info,
                                                    kmod_dependency_t **out_deps,
                                                    uint32_t *out_dep_count)
{
    kern_return_t kr = KERN_NOT_FOUND;
    kinfo_mod_t info = {};
    kmod_dependency_t *deps = NULL;
    const uint8_t *blob = NULL;
    uint64_t sec_len = 0;
    uint32_t ndeps = 0;
    void *map = MAP_FAILED;
    size_t size = 0;
    struct stat st;
    int fd;
    
    if(path == NULL || out_info == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    if(out_deps)
    {
        *out_deps = NULL;
    }
    if(out_dep_count)
    {
        *out_dep_count = 0;
    }
    
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
    {
        return KERN_FAILURE;
    }
    
    if(fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0)
    {
        close(fd);
        return KERN_FAILURE;
    }
    size = (size_t)st.st_size;
    
    map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if(map == MAP_FAILED)
    {
        return KERN_FAILURE;
    }
    
    blob = ksurface_locate_modinfo(map, size, &sec_len);
    if(blob == NULL)
    {
        goto out;
    }
    
    if(sec_len < sizeof(kinfo_mod_t))
    {
        kr = KERN_INVALID_ARGUMENT;
        goto out;
    }
    memcpy(&info, blob, sizeof(info));
    
    if(info.magic != KSURFACE_KMOD_MAGIC ||
       info.abi_version != KSURFACE_KMOD_ABI_VERSION ||
       strnlen(info.identifier, KMOD_MAX_NAME) == KMOD_MAX_NAME)
    {
        kr = KERN_INVALID_ARGUMENT;
        goto out;
    }
    
    info.init = NULL;
    info.start = NULL;
    info.stop  = NULL;
    
    ndeps = info.dependency_count;
    if(ndeps > KMOD_MAX_DEPENDENCIES ||
       sec_len < sizeof(kinfo_mod_t) + (uint64_t)ndeps * sizeof(kmod_dependency_t))
    {
        kr = KERN_INVALID_ARGUMENT;
        goto out;
    }
    
    if(ndeps > 0 && out_deps != NULL)
    {
        deps = calloc(ndeps, sizeof(*deps));
        if(deps == NULL)
        {
            kr = KERN_RESOURCE_SHORTAGE;
            goto out;
        }
        
        memcpy(deps, blob + sizeof(kinfo_mod_t), ndeps * sizeof(*deps));
        
        for(uint32_t i = 0; i < ndeps; i++)
        {
            if(strnlen(deps[i].identifier, KMOD_MAX_NAME) == KMOD_MAX_NAME)
            {
                free(deps);
                kr = KERN_INVALID_ARGUMENT;
                goto out;
            }
        }
        *out_deps = deps;
    }
    
    if(out_dep_count)
    {
        *out_dep_count = ndeps;
    }
    memcpy(out_info, &info, sizeof(info));
    kr = KERN_SUCCESS;
    
out:
    munmap(map, size);
    return kr;
}

void ksurface_kext_free_deps(kmod_dependency_t *deps)
{
    free(deps);
}

/* temporary end */

@implementation PEKext {
    BOOL _enabled;
}

- (kern_return_t)load
{
    return kxopen(self.executablePath.UTF8String, KXLD_MAP_PRIVATE, NULL);
}

- (void)setIsEnabled:(BOOL)isEnabled
{
    _enabled = isEnabled;
    NSMutableDictionary *dictionary = [[NSDictionary dictionaryWithContentsOfURL:[[NSURL fileURLWithPath:self.bundlePath] URLByAppendingPathComponent:@"Info.plist"]] mutableCopy];
    if(dictionary != nil)
    {
        dictionary[@"PEDisabled"] = [NSNumber numberWithBool:!isEnabled];
        NSError *error = nil;
        [dictionary writeToURL:[[NSURL fileURLWithPath:self.bundlePath] URLByAppendingPathComponent:@"Info.plist"] error:&error];
        NSLog(@"%@", error);
    }
}

- (BOOL)isEnabled
{
    return _enabled;
}

- (instancetype)initWithPath:(NSString*)path
{
    self = [super init];
    if(self)
    {
        if(path == nil)
        {
            return NULL;
        }
        
        NSBundle *kextBundle = [NSBundle bundleWithPath:path];
        if(kextBundle == nil)
        {
            return nil;
        }
        
        /* integrity check */
        NSString *executable = kextBundle.executablePath;
        if(executable == nil)
        {
            return nil;
        }
        
        /* validate apple signature */
        LCMachO *machO = LCMapMachO(executable.UTF8String, true);
        if(machO == NULL)
        {
            return nil;
        }
        
        bool isAppleSigned = LCCheckCodeSignature(machO);
        LCUnmapMachO(machO);
        if(!isAppleSigned)
        {
            return nil;
        }
        
        /* validate kext's nxt2 blob */
        ksurface_nxt2_t result = {};
        kern_return_t kr = trust_nxt2_read(executable.UTF8String, &result);
        if(kr != KERN_SUCCESS ||
           !result.isValid ||
           !result.isSigned ||
           !result.isCdHashValid)
        {
            if(result.entitlements != nil)
            {
                CFRelease(result.entitlements);
            }
            return nil;
        }
        
        /* check entitlements */
        bool hasEntitlement = CFDictionaryGetValue(result.entitlements, kNXT2EntitlementKsurfaceKEXTLoading) == kCFBooleanTrue;
        CFRelease(result.entitlements);
        if(!hasEntitlement)
        {
            return nil;
        }
        
        _executablePath = kextBundle.executablePath;
        if(_executablePath == nil)
        {
            return nil;
        }
        
        kinfo_mod_t info = {};
        kmod_dependency_t *deps = NULL;
        uint32_t ndeps = 0;
        
        kr = ksurface_kext_copy_kmod(_executablePath.UTF8String, &info, &deps, &ndeps);
        if(kr != KERN_SUCCESS)
        {
            return nil;
        }
        
        self.flags = info.flags;
        self.abi_version = info.abi_version;
        
        NSMutableArray<PEDependency*> *dependencies = [NSMutableArray array];
        
        for(uint32_t i = 0; i < ndeps; i++)
        {
            PEDependency *dependency = [[PEDependency alloc] init];
            dependency.bundleID = [NSString stringWithCString:deps[i].identifier encoding:NSUTF8StringEncoding];
            dependency.minVersion = [NSString stringWithFormat:@"%u.%u.%u", KMOD_VERSION_MAJOR(deps[i].min_version), KMOD_VERSION_MINOR(deps[i].min_version), KMOD_VERSION_PATCH(deps[i].min_version)];
            dependency.maxVersion = [NSString stringWithFormat:@"%u.%u.%u", KMOD_VERSION_MAJOR(deps[i].max_version), KMOD_VERSION_MINOR(deps[i].max_version), KMOD_VERSION_PATCH(deps[i].max_version)];
            
            if(dependency.bundleID == nil || dependency.minVersion == nil || dependency.maxVersion == nil)
            {
                ksurface_kext_free_deps(deps);
                return nil;
            }
            [dependencies addObject:dependency];
        }
        ksurface_kext_free_deps(deps);
        
        _dependencies = [dependencies copy];
        _bundleID = [NSString stringWithCString:info.identifier encoding:NSUTF8StringEncoding];
        _version = [NSString stringWithFormat:@"%u.%u.%u", KMOD_VERSION_MAJOR(info.version), KMOD_VERSION_MINOR(info.version), KMOD_VERSION_PATCH(info.version)];
        _bundlePath = kextBundle.bundlePath;
        
        NSDictionary *infoDictionary = [NSDictionary dictionaryWithContentsOfURL:[[NSURL fileURLWithPath:self.bundlePath] URLByAppendingPathComponent:@"Info.plist"]];
        NSNumber *number = infoDictionary[@"PEDisabled"];
        if([number isKindOfClass:[NSNumber class]])
        {
            _enabled = ![number boolValue];
        }
        else
        {
            _enabled = YES;
        }
        
        /* final check */
        if(_bundleID == nil || _version == nil || _executablePath == nil || _dependencies == nil || _bundlePath == nil)
        {
            return nil;
        }
    }
    return self;
}

+ (instancetype)appleIOSKext
{
    char buf[32];
    size_t len = sizeof(buf);
    unsigned maj = 0, min = 0, pat = 0;
    if(sysctlbyname("kern.osproductversion", buf, &len, NULL, 0) != 0)
    {
        return nil;
    }
    if(sscanf(buf, "%u.%u.%u", &maj, &min, &pat) < 1)
    {
        return nil;
    }
    
    PEKext *kext = [[self alloc] init];
    kext.executablePath = @"com.apple.iphoneos";
    kext.bundleID = @"com.apple.iphoneos";
    kext.version = [NSString stringWithFormat:@"%u.%u.%u", maj, min, pat];
    kext.abi_version = KSURFACE_KMOD_ABI_VERSION;
    kext.flags = KMOD_FLAG_PERSISTENT | KMOD_FLAG_OVERRIDE_CORE | KMOD_FLAG_ALLOW_UNRESOLVED;
    return kext;
}

+ (instancetype)ksurfaceMainKext
{
    PEKext *kext = [[self alloc] init];
    kext.executablePath = @"ksurface";
    kext.bundleID = @"ksurface";
    kext.version = [NSString stringWithFormat:@"%s", ksurface_version_get_string()];
    kext.abi_version = KSURFACE_KMOD_ABI_VERSION;
    kext.flags = KMOD_FLAG_PERSISTENT | KMOD_FLAG_OVERRIDE_CORE | KMOD_FLAG_ALLOW_UNRESOLVED;
    
    PEDependency *dependency = [[PEDependency alloc] init];
    dependency.bundleID = @"com.apple.iphoneos";
    dependency.minVersion = @"18.0.0";
    dependency.maxVersion = @"99.99.99";
    kext.dependencies = @[dependency];
    
    return kext;
}

@end

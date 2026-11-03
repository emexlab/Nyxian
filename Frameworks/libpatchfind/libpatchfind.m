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
#import <objc/runtime.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach-o/dyld_images.h>
#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include "libpatchfind.h"
#include "litehook.h"
#define NXPF_LOG(format, ...) NSLog(@"libpatchfind: " format, ##__VA_ARGS__)
uint64_t aarch64_emulate_adrp_ldr(uint32_t instruction,
                                  uint32_t ldrInstruction,
                                  uint64_t pc)
{
    uint32_t bad = ((instruction    & 0x9F000000u) ^ 0x90000000u)   /* is ADRP          */
                 | ((ldrInstruction & 0xFFC00000u) ^ 0xF9400000u)   /* is LDR 64        */
                 | ((instruction ^ (ldrInstruction >> 5)) & 0x1Fu); /* Rd == Rn         */
    if(bad)
    {
        return 0;
    }
    
    int64_t imm = ((int64_t)((uint64_t)instruction << 40) >> 31) & ~(int64_t)0x3FFF;
    imm |= (instruction >> 17) & 0x3000;
    uint64_t page = (pc & ~(uint64_t)0xFFF) + (uint64_t)imm;
    
    return page ? page + ((uint64_t)((ldrInstruction >> 10) & 0xFFFu) << 3) : 0;
}
static inline bool a64_is_bl(uint32_t insn)
{
    return (insn & 0xFC000000u) == 0x94000000u;
}

static inline uintptr_t a64_resolve_bl(const uint32_t *pc)
{
    uint32_t insn = *pc;
    int64_t imm26 = (int64_t)(insn & 0x03FFFFFFu);
    if(imm26 & 0x02000000LL)
    {
        imm26 |= ~0x03FFFFFFLL;
    }
    return (uintptr_t)pc + (imm26 << 2);
}

#define CF_SCAN_INSNS       128
#define CF_SCAN_CALLEE      64
#define CF_MAX_CALLEES      8

static uintptr_t emulate_adrp(uintptr_t pc,
                              uint32_t insn)
{
    uint32_t immhi = (insn >> 5) & 0x7FFFF;
    uint32_t immlo = (insn >> 29) & 3;
    uint32_t imm21 = (immhi << 2) | immlo;
    int64_t offset = ((int64_t)(int32_t)(imm21 << 11)) >> 11;
    
    return (uintptr_t)(
        (int64_t)(pc & ~(uintptr_t)0xFFF) + offset * 4096
    );
}

static bool find_global_slot(uintptr_t pc,
                             uint32_t adrp,
                             uint32_t mem,
                             uintptr_t *result)
{
    if((adrp & 0x9F000000) != 0x90000000)
    {
        return false;
    }
    
    uint32_t kind = mem & 0xFFC00000;
    if(kind != 0xF9400000 && kind != 0xF9000000)
    {
        return false;
    }
    
    if(((mem >> 5) & 31) != (adrp & 31))
    {
        return false;
    }
    
    uintptr_t page = emulate_adrp(pc, adrp);
    uint32_t offset = ((mem >> 10) & 0xFFF) * 8;
    
    *result = page + offset;
    return true;
}

static inline bool a64_is_ldrb_uimm(uint32_t insn)
{
    return (insn & 0xFFC00000u) == 0x39400000u;
}

static bool a64_reg_tested_soon(const uint32_t *p,
                                uint32_t rt,
                                size_t window)
{
    for(size_t i = 1; i <= window; i++)
    {
        uint32_t cls = p[i] & 0x7E000000u;
        if((cls == 0x36000000u || cls == 0x34000000u) && (p[i] & 31) == rt)
        {
            return true;
        }
    }
    return false;
}

static int cf_scan_for_slot(const uint32_t *fn,
                            size_t n,
                            const void *cfBase,
                            const void *expected,
                            uintptr_t *ioSlot)
{
    uint32_t  adrpInsn[32] = {0};
    uintptr_t adrpPc[32]   = {0};

    for(size_t i = 0; i < n; i++)
    {
        uint32_t  insn = fn[i];
        uintptr_t pc   = (uintptr_t)&fn[i];

        if((insn & 0x9F000000u) == 0x90000000u)
        {
            adrpInsn[insn & 31] = insn;
            adrpPc[insn & 31]   = pc;
            continue;
        }

        uint32_t rn = (insn >> 5) & 31;
        if(adrpPc[rn] == 0)
        {
            continue;
        }

        uintptr_t slot;
        if(!find_global_slot(adrpPc[rn], adrpInsn[rn], insn, &slot))
        {
            continue;
        }

        /* must live in CoreFoundation's image before we dereference it */
        Dl_info info;
        if(dladdr((const void *)slot, &info) == 0 || info.dli_fbase != cfBase)
        {
            continue;
        }

        if(*(void * volatile *)slot != expected)
        {
            continue;
        }

        if(*ioSlot != 0 && *ioSlot != slot)
        {
            return -1;
        }
        *ioSlot = slot;
    }

    return *ioSlot != 0;
}

static uintptr_t aarch64_emulate_adrp_add(uint32_t adrp,
                                          uint32_t add,
                                          uintptr_t adrpPc)
{
    if((adrp & 0x9F000000u) != 0x90000000u)
    {
        return 0;
    }
    
    if((add & 0xFF800000u) != 0x91000000u)
    {
        return 0;
    }
    
    uint32_t adrpRd = adrp & 31;
    uint32_t addRn  = (add >> 5) & 31;
    if(adrpRd != addRn)
    {
        return 0;
    }
    
    uintptr_t page = emulate_adrp(adrpPc, adrp);
    uint32_t imm12 = (add >> 10) & 0xFFF;
    if((add >> 22) & 1)
    {
        imm12 <<= 12;
    }
    
    return page + imm12;
}

static int cf_scan_for_inited_flag(const uint32_t *fn,
                                   size_t n,
                                   const void *cfBase,
                                   uintptr_t mainBundleSlot,
                                   uintptr_t *ioFlag)
{
    uint32_t  adrpInsn[32] = {0};
    uintptr_t adrpPc[32]   = {0};

    for(size_t i = 0; i < n; i++)
    {
        uint32_t  insn = fn[i];
        uintptr_t pc   = (uintptr_t)&fn[i];

        if((insn & 0x9F000000u) == 0x90000000u)
        {
            adrpInsn[insn & 31] = insn;
            adrpPc[insn & 31]   = pc;
            continue;
        }

        if(!a64_is_ldrb_uimm(insn))
        {
            continue;
        }

        uint32_t rn = (insn >> 5) & 31;
        if(adrpPc[rn] == 0)
        {
            continue;
        }

        /* LDRB imm12 is unscaled */
        uintptr_t flag = emulate_adrp(adrpPc[rn], adrpInsn[rn]) + ((insn >> 10) & 0xFFF);

        intptr_t dist = (intptr_t)flag - (intptr_t)mainBundleSlot;
        if(dist < -0x1000 || dist > 0x1000)
        {
            continue;
        }

        Dl_info info;
        if(dladdr((const void *)flag, &info) == 0 || info.dli_fbase != cfBase)
        {
            continue;
        }

        if(*(volatile uint8_t *)flag != 1)
        {
            continue;
        }

        if(!a64_reg_tested_soon(&fn[i], insn & 31, 4))
        {
            continue;
        }

        if(*ioFlag != 0 && *ioFlag != flag)
        {
            return -1;
        }
        *ioFlag = flag;
    }

    return *ioFlag != 0;
}

static bool cf_find_main_bundle_offs(uint64_t *outMainOff,
                                     uint64_t *outInitedOff)
{
    *outMainOff = 0;
    *outInitedOff = 0;

    CFBundleRef mainBundle = CFBundleGetMainBundle();   /* forces init */
    if(mainBundle == NULL)
    {
        NXPF_LOG("CFBundleGetMainBundle returned NULL");
        return false;
    }

    const uint32_t *fn = (const uint32_t *)dlsym(RTLD_DEFAULT, "CFBundleGetMainBundle");
    Dl_info cfInfo;
    if(fn == NULL || dladdr(fn, &cfInfo) == 0)
    {
        return false;
    }

    const uint32_t *hitFn = fn;
    size_t hitLen = CF_SCAN_INSNS;
    uintptr_t slot = 0;
    int r = cf_scan_for_slot(fn, CF_SCAN_INSNS, cfInfo.dli_fbase, mainBundle, &slot);

    if(r == 0)
    {
        size_t followed = 0;
        for(size_t i = 0; i < CF_SCAN_INSNS && followed < CF_MAX_CALLEES; i++)
        {
            if(!a64_is_bl(fn[i]))
            {
                continue;
            }
            const uint32_t *callee = (const uint32_t *)a64_resolve_bl(&fn[i]);
            followed++;
            r = cf_scan_for_slot(callee, CF_SCAN_CALLEE, cfInfo.dli_fbase, mainBundle, &slot);
            if(r != 0)
            {
                hitFn = callee;
                hitLen = CF_SCAN_CALLEE;
                break;
            }
        }
    }

    if(r != 1)
    {
        NXPF_LOG("_mainBundle slot %s", r < 0 ? "ambiguous" : "not found");
        return false;
    }

    uintptr_t flag = 0;
    int rf = cf_scan_for_inited_flag(hitFn, hitLen, cfInfo.dli_fbase, slot, &flag);
    if(rf != 1)
    {
        NXPF_LOG("_initedMainBundle %s", rf < 0 ? "ambiguous" : "not found");
        return false;
    }

    *outMainOff   = (uint64_t)(slot - (uintptr_t)cfInfo.dli_fbase);
    *outInitedOff = (uint64_t)(flag - (uintptr_t)cfInfo.dli_fbase);
    return true;
}

static uint64_t ns_find_main_bundle_slot_off(void)
{
    NSBundle *mb = NSBundle.mainBundle;
    if(mb == nil)
    {
        return 0;
    }
    
    Method m = class_getClassMethod(NSBundle.class, @selector(mainBundle));
    uint32_t *impl = (uint32_t *)method_getImplementation(m);
    
    Dl_info fInfo;
    if(dladdr((const void *)impl, &fInfo) == 0)
    {
        return 0;
    }
    
    uintptr_t found = 0;
    
    for(int i = 0; i + 5 < 24; i++)
    {
        /* adrp + add -> base pointer (may be _MergedGlobals or +4) */
        void **mg = (void **)aarch64_emulate_adrp_add(impl[i], impl[i+1], (uint64_t)&impl[i]);
        if(mg == NULL)
        {
            continue;
        }

        /* iOS 17: adrp+add yields _MergedGlobals+4, accessed via ldur (0xF8xxxxxx) */
        if((impl[i+4] & 0xFF000000u) == 0xF8000000u)
        {
            mg = (void **)((uintptr_t)mg - 4);
        }

        for(int j = 0; j < 24; j++)
        {
            uintptr_t slot = (uintptr_t)&mg[j];

            /* must be inside Foundation before we trust/deref it */
            Dl_info sInfo;
            if(dladdr((const void *)slot, &sInfo) == 0 ||
               sInfo.dli_fbase != fInfo.dli_fbase)
            {
                continue;
            }

            if(mg[j] != (__bridge void *)mb)
            {
                continue;
            }

            if(found != 0 && found != slot)
            {
                NXPF_LOG("NSBundle main slot ambiguous");
                return 0;
            }
            found = slot;
        }
    }

    if(found == 0)
    {
        NXPF_LOG("NSBundle main slot not found");
        return 0;
    }

    return (uint64_t)(found - (uintptr_t)fInfo.dli_fbase);
}

typedef struct {
    uint64_t signature;
    void *found;
} dyld_search_entry_t;

static struct dyld_all_image_infos *_alt_dyld_get_all_image_infos(void)
{
    static struct dyld_all_image_infos *result;
    if(result != NULL)
    {
        return result;
    }
    
    struct task_dyld_info dyldInfo = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if(kr != KERN_SUCCESS ||
       dyldInfo.all_image_info_addr == 0)
    {
        return NULL;
    }
    
    result = (struct dyld_all_image_infos *)(uintptr_t)dyldInfo.all_image_info_addr;
    
    return result;
}

static void *findDyldFcntl17(const char *base)
{
    static const uint32_t movFAddFileSigsReturn = 0x52800C21;
    static const uint32_t movFGetSigsInfo = 0x52800D21;
    
    const size_t scanSize = 0x80000;
    const uint32_t *text = (const uint32_t *)base;
    const size_t count = scanSize / sizeof(uint32_t);
    
    for(size_t i = 0; i < count; i++)
    {
        if(text[i] != movFAddFileSigsReturn)
        {
            continue;
        }
        
        size_t bl1End = i + 12;
        if(bl1End > count)
        {
            bl1End = count;
        }
        
        for (size_t j = i + 1; j < bl1End; j++)
        {
            if(!a64_is_bl(text[j]))
            {
                continue;
            }
            
            uintptr_t target1 = a64_resolve_bl(&text[j]);
            size_t secondEnd = i + 0x100;
            if(secondEnd > count)
            {
                secondEnd = count;
            }
            
            for (size_t k = j + 1; k < secondEnd; k++)
            {
                if(text[k] != movFGetSigsInfo)
                {
                    continue;
                }
                
                size_t bl2End = k + 12;
                if(bl2End > count)
                {
                    bl2End = count;
                }
                
                for(size_t l = k + 1; l < bl2End; l++)
                {
                    if(!a64_is_bl(text[l]))
                    {
                        continue;
                    }
                    
                    uintptr_t target2 =
                    a64_resolve_bl(&text[l]);
                    
                    if(target1 == target2)
                    {
                        return (void *)target1;
                    }
                }
            }
        }
    }
    
    return NULL;
}

static void searchDyldFunctions(const char *base,
                                dyld_search_entry_t *entries,
                                size_t count)
{
    if(base == NULL || entries == NULL || count == 0)
    {
        return;
    }
    
    size_t remaining = count;
    
    for(size_t i = 0; i < count; i++)
    {
        entries[i].found = NULL;
    }
    
    for(size_t off = 0; off + sizeof(uint64_t) <= (0x80000); off += 4)
    {
        uint64_t value;
        memcpy(&value, base + off, sizeof(value));
        for(size_t i = 0; i < count; i++)
        {
            if(entries[i].found != NULL)
            {
                continue;
            }
            if(entries[i].signature != value)
            {
                continue;
            }
            entries[i].found =
            (void *)(base + off);
            if(--remaining == 0)
            {
                return;
            }
        }
    }
}


static kern_return_t findDyldFunctionPointers(uint64_t out[kDyldPtrCount])
{
    if(out == NULL)
    {
        return KERN_INVALID_ARGUMENT;
    }
    
    memset(out, 0, sizeof(uint64_t) * kDyldPtrCount);
    struct dyld_all_image_infos *infos = _alt_dyld_get_all_image_infos();
    if(infos == NULL)
    {
        NXPF_LOG("couldn't obtain dyld_all_image_infos");
        return KERN_FAILURE;
    }
    
    const char *dyldBase = (const char *)infos->dyldImageLoadAddress;
    if(dyldBase == NULL)
    {
        NXPF_LOG("dyldImageLoadAddress is NULL");
        return KERN_FAILURE;
    }
    
    static dyld_search_entry_t entries[kDyldPtrCount] = {
        /* first shit */
        [kDyldPtrOpen] = {
            .signature = 0xD4001001D28000B0ULL,
            .found = NULL,
        },
        [kDyldPtrFcntl] = {
            .signature = 0xD4001001D2800B90ULL,
            .found = NULL,
        },
        [kDyldPtrFstat64] = {
            .signature = 0xD4001001D2802A70ULL,
            .found = NULL,
        },
        [kDyldPtrStat64] = {
            .signature = 0xD4001001D2802A50ULL,
            .found = NULL,
        },
        [kDyldPtrOpenat] = {
            .signature = 0xD4001001D28039F0ULL,
            .found = NULL,
        },
        
        /* rest is null by default */
    };
    searchDyldFunctions(dyldBase, entries, kDyldPtrOpenat + 1);
    
    /* now the shit that takes 20~30ms if not cached properly */
    const char *libdyldPath = "/usr/lib/system/libdyld.dylib";
    void **lockUnlockPtr = NULL;
    void **vtableLibSystemHelpers = litehook_find_dsc_symbol(libdyldPath, "__ZTVN5dyld416LibSystemHelpersE");
    void *lockFunc = litehook_find_dsc_symbol(libdyldPath, "__ZNK5dyld416LibSystemHelpers42os_unfair_recursive_lock_lock_with_optionsEP26os_unfair_recursive_lock_s24os_unfair_lock_options_t");
#if DEBUG
    void *unlockFunc = litehook_find_dsc_symbol(libdyldPath, "__ZNK5dyld416LibSystemHelpers31os_unfair_recursive_lock_unlockEP26os_unfair_recursive_lock_s");
#endif /* DEBUG */
    if(!vtableLibSystemHelpers || !lockFunc) return KERN_FAILURE;
    for(size_t slot = 0; slot < 256 && !lockUnlockPtr; slot++)
    {
        if(vtableLibSystemHelpers[0] == lockFunc)
        {
            lockUnlockPtr = vtableLibSystemHelpers;
#if DEBUG
            if(vtableLibSystemHelpers[1] != unlockFunc) return KERN_FAILURE;
#endif /* DEBUG */
            break;
        }
        vtableLibSystemHelpers++;
    }
    
    if(!lockUnlockPtr) return KERN_FAILURE;
    entries[kDyldLockUnlockFunc].found = lockUnlockPtr;

    
    /* now stuffing the hook data */
    typedef struct {
        const char *name;
        uint32_t adrpOffset;
    } dyld_hook_segment_t;
    
    static const dyld_hook_segment_t dyldNames[3] = {
        {
            .name = "_NSGetExecutablePath",
            .adrpOffset = 2,
        },
        {
            .name = "dyld_program_sdk_at_least",
            .adrpOffset = 1,
        },
        {
            .name = "dyld_get_program_sdk_version",
            .adrpOffset = 0,
        }
    };
    
    int offset = kDyldLockUnlockFunc;
    for(size_t i = 0; i < 3; i++)
    {
        uint32_t* baseAddr = dlsym(RTLD_DEFAULT, dyldNames[i].name);
        if(baseAddr == NULL)
        {
            break;
        }
        
        uint32_t* adrpInstPtr = baseAddr + dyldNames[i].adrpOffset;
        
        // find the following instruction pattern: 1 adrp + 2 ldr
        // adrp    x8, 0x1e6cf0000
        // ldr     x0, [x8, #0x30]  {dyld4::gAPIs}
        // ldr     x16, [x0]
        
        long adrpExtraOffset = -1;
        if(adrpExtraOffset == -1)
        {
            // let't hope the function is not longer than 200 instructions
            uint32_t* end = baseAddr + 200;
            for(uint32_t* cur = adrpInstPtr;cur + 2 < end;++cur)
            {
                if((*cur & 0x9f000000) != 0x90000000)
                {
                    continue;
                }
                if((*(cur+1) & 0xFFC00000) != 0xF9400000)
                {
                    continue;
                }
                if((*(cur+2) & 0xFFC00000) != 0xF9400000)
                {
                    continue;
                }
                adrpExtraOffset = cur - adrpInstPtr;
                break;
            }
            if(adrpExtraOffset == -1) return KERN_FAILURE;
        }
        
        adrpInstPtr += adrpExtraOffset;
        
        void *dptr = (void*)aarch64_emulate_adrp_ldr(*adrpInstPtr, *(adrpInstPtr + 1), (uint64_t)adrpInstPtr);
        
        if(!dptr) return KERN_FAILURE;
        if(!*(void**)dptr) return KERN_FAILURE;
        void* vtablePtr = **(void***)dptr;
        
        void* vtableFunctionPtr = 0;
        uint32_t* movInstPtr = adrpInstPtr + 6;

        if((*movInstPtr & 0x7F800000) == 0x52800000)
        {
            // arm64e, mov imm + add + ldr
            uint32_t imm16 = (*movInstPtr & 0x1FFFE0) >> 5;
            vtableFunctionPtr = vtablePtr + imm16;
        }
        else if ((*movInstPtr & 0xFFE00C00) == 0xF8400C00)
        {
            // arm64e, ldr immediate Pre-index 64bit
            uint32_t imm9 = (*movInstPtr & 0x1FF000) >> 12;
            vtableFunctionPtr = vtablePtr + imm9;
        }
        else
        {
            // arm64
            uint32_t* ldrInstPtr2 = adrpInstPtr + 3;
            if((*ldrInstPtr2 & 0xBFC00000) != 0xB9400000) return KERN_FAILURE;
            uint32_t size2 = (*ldrInstPtr2 & 0xC0000000) >> 30;
            uint32_t imm12_2 = (*ldrInstPtr2 & 0x3FFC00) >> 10;
            vtableFunctionPtr = vtablePtr + (imm12_2 << size2);
        }
        
        entries[offset + 1].found = vtableFunctionPtr;
        
        offset++;
    }
    
    /* on iOS 17 it seems like there is no normal fcntl call */
    if(!@available(iOS 18.0, *))
    {
        if(entries[kDyldPtrFcntl].found == NULL)
        {
            entries[kDyldPtrFcntl].found = findDyldFcntl17(dyldBase);
        }
    }

    /* CoreFoundation shit */
    cf_find_main_bundle_offs((uint64_t*)&entries[kCFBundleMainOffset].found, (uint64_t*)(uint64_t*)&entries[kCFBundleMainInitedOffset].found);
    entries[kNSBundleMainOffset].found = (void*)ns_find_main_bundle_slot_off();
    
    static const char *names[kDyldPtrCount] = {
        "dyld.open",
        "dyld.fcntl",
        "dyld.fstat64",
        "dyld.stat64",
        "dyld.openat",
        "dyld.lockUnlockFunc",
        
        "_NSGetExecutablePath.vtable.fn",
        "dyld_program_sdk_at_least.vtable.fn",
        "dyld_get_program_sdk_version.vtable.fn",

        "core_foundation.main_bundle.off",
        "core_foundation.main_bundle_inited.off",
        
        "foundation.main_bundle.off",

    };
    
    bool entryNotFound = false;
    for(size_t i = 0; i < kDyldPtrCount; i++)
    {
        if(entries[i].found == NULL)
        {
            entryNotFound = true;
        }
        
        out[i] = (uint64_t)(uintptr_t)entries[i].found;
        NXPF_LOG("%s @ %p", names[i], (void*)out[i]);
    }
    
    if(entryNotFound)
    {
        NXPF_LOG("couldn't find all pointers");
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}


bool nxpf_resolve_base(uint32_t abi, uint64_t *out, size_t count)
{
    if(abi != NXPF_BASE_ABI || !out || !count || count > kDyldPtrCount) return false;
    static uint64_t base[kDyldPtrCount];
    static bool ready;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ ready = findDyldFunctionPointers(base) == KERN_SUCCESS; });
    if(ready) memcpy(out, base, count * sizeof(uint64_t));
    return ready;
}
void *nxpf_find_symbol(const char *image, const char *symbol)
{
    if(!image || !symbol) return NULL;
    return litehook_find_dsc_symbol(image, symbol);
}

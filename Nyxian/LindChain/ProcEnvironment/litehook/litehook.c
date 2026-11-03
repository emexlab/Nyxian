/*
 MIT License

 Copyright (c) 2022-2024 Lars Fröder
 Copyright (c) 2026 emexlab

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

#include "litehook.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/fcntl.h>
#include <mach/mach.h>
#include <mach/arm/kern_return.h>
#include <mach/port.h>
#include <mach/vm_prot.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <dlfcn.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
#include <sys/syslimits.h>
#include <dispatch/dispatch.h>
#include "dyld_cache_format.h"
#include <ptrauth.h>
#include <sys/mman.h>

#if __arm64__
#define _COMM_PAGE_START_ADDRESS (0x0000000FFFFFC000ULL)
#define _COMM_PAGE_TPRO_WRITE_ENABLE (_COMM_PAGE_START_ADDRESS + 0x0D0)
#define _COMM_PAGE_TPRO_WRITE_DISABLE (_COMM_PAGE_START_ADDRESS + 0x0D8)

bool os_tpro_is_supported(void)
{
    if (*(uint64_t*)_COMM_PAGE_TPRO_WRITE_ENABLE) {
        return true;
    }
    return false;
}

__attribute__((naked)) bool os_thread_self_tpro_is_writeable(void)
{
    __asm__ __volatile__ (
        "mrs             x0, s3_6_c15_c1_5\n"
        "ubfx            x0, x0, #0x24, #1;\n"
        "ret\n"
    );
}

void os_thread_self_restrict_tpro_to_rw(void)
{
    __asm__ __volatile__ (
        "mov x0, %0\n"
        "ldr x0, [x0]\n"
        "msr s3_6_c15_c1_5, x0\n"
        "isb sy\n"
        :: "r" (_COMM_PAGE_TPRO_WRITE_ENABLE)
        : "memory", "x0"
    );
    return;
}

void os_thread_self_restrict_tpro_to_ro(void)
{
    __asm__ __volatile__ (
        "mov x0, %0\n"
        "ldr x0, [x0]\n"
        "msr s3_6_c15_c1_5, x0\n"
        "isb sy\n"
        :: "r" (_COMM_PAGE_TPRO_WRITE_DISABLE)
        : "memory", "x0"
    );
    return;
}
#endif

size_t _lth_fstrlen(FILE *f)
{
    size_t sz = 0;
    uint32_t prev = (uint32_t)ftell(f);
    while (true) {
        char c = 0;
        if (fread(&c, sizeof(c), 1, f) != 1) break;
        if (c == 0) break;
        sz++;
    }
    fseek(f, prev, SEEK_SET);
    return sz;
}

__attribute__((noinline, naked)) volatile kern_return_t litehook_vm_protect(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
#ifdef __arm64__
    __asm("mov x16, #-14");
    __asm("svc 0x80");
    __asm("ret");
#else
    // broken....
    __asm("mov r12, #-14");
    __asm("svc 0x80");
    __asm("bx lr");
#endif
}

static inline kern_return_t litehook_unprotect(vm_address_t addr, vm_size_t size)
{
    return litehook_vm_protect(mach_task_self(), addr, size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
}

const char *litehook_locate_dsc(void)
{
    static char dscPath[PATH_MAX] = {};
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        char *dyldSharedRegion   = getenv("DYLD_SHARED_REGION");
        char *dyldSharedCacheDir = getenv("DYLD_SHARED_CACHE_DIR");
        if (dyldSharedRegion && dyldSharedCacheDir && !strcmp(dyldSharedRegion, "private")) {
            // If the local process uses a custom private dsc, use that as the path
            strlcpy(dscPath, dyldSharedCacheDir, PATH_MAX);
            strlcat(dscPath, "/dyld_shared_cache", PATH_MAX);
        }
        else if (!access("/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS <=15 */ {
            strlcpy(dscPath, "/System/Library/Caches/com.apple.dyld/dyld_shared_cache", PATH_MAX);
        }
        else if (!access("/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld", F_OK)) /* iOS >=16 */ {
            strlcpy(dscPath, "/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache", PATH_MAX);
        }

        const char *suffixCandidates[] = {
            "_arm64e_x1",
            "_arm64e",
            "_arm64",
            "_armv7s",
            "_armv7",
        };
        char *rChar = &dscPath[strlen(dscPath)];
        for (int i = 0; i < sizeof(suffixCandidates)/sizeof(*suffixCandidates); i++) {
            *rChar = '\0';
            strlcat(dscPath, suffixCandidates[i], PATH_MAX);
            if (!access(dscPath, F_OK)) {
                break;
            }
        }
        if (access(dscPath, F_OK) != 0) strlcpy(dscPath, "", PATH_MAX);
    });
    return (const char *)dscPath;
}

uintptr_t litehook_get_dsc_slide(void)
{
    static uintptr_t slide = 0;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        task_dyld_info_data_t dyldInfo;
        uint32_t count = TASK_DYLD_INFO_COUNT;
        task_info(mach_task_self_, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
        struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
        slide = infos->sharedCacheSlide;
    });
    return slide;
}

void *_litehook_sign_if_executable(void *ptr)
{
    vm_address_t region = (vm_address_t)ptr;
    vm_size_t region_len = 0;
    struct vm_region_submap_short_info_64 info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t max_depth = 99999;
    vm_region_recurse_64(mach_task_self(), &region, &region_len, &max_depth, (vm_region_recurse_info_t)&info, &info_count);
    if (info.protection & PROT_EXEC) {
        return ptrauth_sign_unauthenticated(ptr, ptrauth_key_function_pointer, 0);
    }
    return ptr;
}

void *litehook_find_symbol(const mach_header_u *header, const char *symbolName)
{
    struct symtab_command *symtabCommand = NULL;
    segment_command_u *linkeditSegCommand = NULL;

    uint32_t slide = -1;

    uint32_t off = 0;
    for (uint32_t i = 0; i < header->ncmds && off < header->sizeofcmds; i++) {
        struct load_command *lc = (struct load_command *)((uintptr_t)header + sizeof(mach_header_u) + off);

        if (lc->cmd == LC_SYMTAB) {
            symtabCommand = (struct symtab_command *)lc;
        }
        else if (lc->cmd == LC_SEGMENT_U) {
            segment_command_u *segCmd = (segment_command_u *)lc;
            if (slide == -1) {
                slide = (uint32_t)((uintptr_t)header - segCmd->vmaddr);
            }
            if (!strncmp(segCmd->segname, "__LINKEDIT", sizeof(segCmd->segname))) {
                linkeditSegCommand = segCmd;
            }
        }

        if (symtabCommand && linkeditSegCommand) break;

        off += lc->cmdsize;
    }

    if (!symtabCommand || !linkeditSegCommand) return NULL;

    uint8_t *linkedit = (uint8_t *)((uintptr_t)header + linkeditSegCommand->vmaddr);

    nlist_u *syms = (nlist_u *)(linkedit + (symtabCommand->symoff - linkeditSegCommand->fileoff));
    char *strtbl = (char *)(linkedit + (symtabCommand->stroff - linkeditSegCommand->fileoff));
    size_t strtblSize = symtabCommand->strsize;

    for (uint32_t i = 0; i < symtabCommand->nsyms; i++) {
        nlist_u *symEntry = &syms[i];

        uint32_t stroff = symEntry->n_un.n_strx;
        if (stroff >= strtblSize || off == 0) {
            continue;
        }

        if ((symEntry->n_type & N_TYPE) != N_SECT) {
            continue;
        }

        const char* curSymbolName = &strtbl[stroff];
        if (curSymbolName[0] == '\x00') {
            continue;
        }

        if (!strcmp(curSymbolName, symbolName)) {
            return _litehook_sign_if_executable((void *)((uintptr_t)header + symEntry->n_value));
        }
    }

    return NULL;
}

void *litehook_find_symbol_file(const mach_header_u *header, const char *symbolName)
{
    struct symtab_command *symtabCommand = NULL;

    uint32_t slide = -1;

    uint32_t off = 0;
    for (uint32_t i = 0; i < header->ncmds && off < header->sizeofcmds; i++) {
        struct load_command *lc = (struct load_command *)((uintptr_t)header + sizeof(mach_header_u) + off);

        if (lc->cmd == LC_SYMTAB) {
            symtabCommand = (struct symtab_command *)lc;
        }
        else if (lc->cmd == LC_SEGMENT_U) {
            segment_command_u *segCmd = (segment_command_u *)lc;
            if (slide == -1) {
                slide = (uint32_t)((uintptr_t)header - segCmd->vmaddr);
            }
        }

        if (symtabCommand) break;

        off += lc->cmdsize;
    }

    if (!symtabCommand) return NULL;

    nlist_u *syms = (nlist_u *)((void*)header + symtabCommand->symoff);
    char *strtbl = (char *)((void*)header + symtabCommand->stroff);
    size_t strtblSize = symtabCommand->strsize;

    for (uint32_t i = 0; i < symtabCommand->nsyms; i++) {
        nlist_u *symEntry = &syms[i];

        uint32_t stroff = symEntry->n_un.n_strx;
        if (stroff >= strtblSize || off == 0) {
            continue;
        }

        if ((symEntry->n_type & N_TYPE) != N_SECT) {
            continue;
        }

        const char* curSymbolName = &strtbl[stroff];
        if (curSymbolName[0] == '\x00') {
            continue;
        }

        if (!strcmp(curSymbolName, symbolName)) {
            return _litehook_sign_if_executable((void *)((uintptr_t)header + symEntry->n_value));
        }
    }

    return NULL;
}

void *litehook_find_dsc_symbol(const char *imagePath, const char *symbolName)
{
    const char *mainDSCPath = litehook_locate_dsc();
    if (!strlen(mainDSCPath)) return NULL;

    char symbolDSCPath[PATH_MAX];
    strcpy(symbolDSCPath, mainDSCPath);
    strcat(symbolDSCPath, ".symbols");

    void *symbol = NULL;

    FILE *mainDSC = fopen(mainDSCPath, "rb");
    FILE *symbolDSC = NULL;
    if (!mainDSC) goto end;
    symbolDSC = fopen(symbolDSCPath, "rb") ?: mainDSC;

    int imageIndex = -1;

    struct dyld_cache_header mainHeader;
    if (fread(&mainHeader, sizeof(mainHeader), 1, mainDSC) != 1) goto end;

    for (int i = 0; i < mainHeader.imagesCount; i++) {
        struct dyld_cache_image_info imageInfo;
        fseek(mainDSC, mainHeader.imagesOffset + sizeof(imageInfo) * i, SEEK_SET);
        if (fread(&imageInfo, sizeof(imageInfo), 1, mainDSC) != 1) goto end;

        char path[PATH_MAX];
        fseek(mainDSC, imageInfo.pathFileOffset, SEEK_SET);
        if (fread(path, PATH_MAX, 1, mainDSC) != 1) goto end;

        if (!strcmp(path, imagePath)) {
            imageIndex = i;
            break;
        }
    }

    struct dyld_cache_header symbolHeader;
    if (fread(&symbolHeader, sizeof(symbolHeader), 1, symbolDSC) != 1) goto end;

    struct dyld_cache_local_symbols_info symbolInfo;
    fseek(symbolDSC, symbolHeader.localSymbolsOffset, SEEK_SET);
    if (fread(&symbolInfo, sizeof(symbolInfo), 1, symbolDSC) != 1) goto end;

    if (imageIndex >= symbolInfo.entriesCount) goto end;

    struct dyld_cache_local_symbols_entry_64 entry;

    if (mainHeader.mappingOffset >= offsetof(struct dyld_cache_header, symbolFileUUID)) {
        // New shared cache, dyld_cache_local_symbols_entry_64
        fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.entriesOffset + (sizeof(entry) * imageIndex), SEEK_SET);
        if (fread(&entry, sizeof(entry), 1, symbolDSC) != 1) goto end;
    }
    else {
        // Old shared cache, dyld_cache_local_symbols_entry
        struct dyld_cache_local_symbols_entry entryOld;
        fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.entriesOffset + (sizeof(entryOld) * imageIndex), SEEK_SET);
        if (fread(&entryOld, sizeof(entryOld), 1, symbolDSC) != 1) goto end;

        // Convert dyld_cache_local_symbols_entry to dyld_cache_local_symbols_entry_64
        entry = (struct dyld_cache_local_symbols_entry_64) {
            .dylibOffset = entryOld.dylibOffset,
            .nlistStartIndex = entryOld.nlistStartIndex,
            .nlistCount = entryOld.nlistCount,
        };
    }

    if ((entry.nlistStartIndex + entry.nlistCount) > symbolInfo.nlistCount) goto end;

    for (uint32_t i = entry.nlistStartIndex; i < entry.nlistStartIndex + entry.nlistCount; i++) {
        struct nlist_64 n;
        fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.nlistOffset + (sizeof(n) * i), SEEK_SET);
        if (fread(&n, sizeof(n), 1, symbolDSC) != 1) goto end;

        fseek(symbolDSC, symbolHeader.localSymbolsOffset + symbolInfo.stringsOffset + n.n_un.n_strx, SEEK_SET);
        size_t len = _lth_fstrlen(symbolDSC);
        char curSymbolName[len+1];
        if (fread(curSymbolName, len+1, 1, symbolDSC) != 1) goto end;
        if (!strcmp(curSymbolName, symbolName)) {
            symbol = _litehook_sign_if_executable((void *)(litehook_get_dsc_slide() + n.n_value));
        }
    }

end:
    if (mainDSC) {
        if (symbolDSC != mainDSC) {
            fclose(symbolDSC);
        }
        fclose(mainDSC);
    }

    return symbol;
}

void _litehook_rebind_symbol_in_section(const mach_header_u *targetHeader, section_u *section, void *replacee, void *replacement)
{
    char segname[sizeof(section->segname)+1];
    strlcpy(segname, section->segname, sizeof(segname));
    char sectname[sizeof(section->sectname)+1];
    strlcpy(sectname, section->sectname, sizeof(sectname));
    
    unsigned long sectionSize = 0;
    uint8_t *sectionStart = getsectiondata(targetHeader, segname, sectname, &sectionSize);
    
    bool auth = !strcmp(sectname, "__auth_got");
    if (!sectionStart || sectionSize < sizeof(void *)) return;
    void **symbolPointers = (void **)sectionStart;
    replacee = ptrauth_strip(replacee, ptrauth_key_function_pointer);

    for (uint32_t i = 0; i < (sectionSize / sizeof(void *)); i++) {
        void *symbolPointer = symbolPointers[i];
        if (!symbolPointer) continue;
        symbolPointer = ptrauth_strip(symbolPointer, ptrauth_key_function_pointer);
        
        if (symbolPointer == replacee) {
#if __arm64__
            bool needsTPRORevert = false;
            if (os_tpro_is_supported()) {
                if (!os_thread_self_tpro_is_writeable()) {
                    os_thread_self_restrict_tpro_to_rw();
                    needsTPRORevert = true;
                }
            }
#endif
            kern_return_t kr = litehook_unprotect((vm_address_t)&symbolPointers[i], sizeof(void *));
            if (kr != KERN_SUCCESS) {
                fprintf(stderr, "[litehook] cannot write binding %p: kern_return=%d\n",
                        (void *)&symbolPointers[i], kr);
#if __arm64__
                if (needsTPRORevert) os_thread_self_restrict_tpro_to_ro();
#endif
                continue;
            }
            if (auth) {
                symbolPointers[i] = ptrauth_auth_and_resign(replacement, ptrauth_key_function_pointer, 0, ptrauth_key_process_independent_code, &symbolPointers[i]);
            }
            else {
                symbolPointers[i] = ptrauth_strip(replacement, ptrauth_key_function_pointer);
            }
#if __arm64__
            if (needsTPRORevert) {
                os_thread_self_restrict_tpro_to_ro();
            }
#endif
        }
    }
}

uint32_t gRebindCount = 0;
global_rebind *gRebinds = NULL;

void _litehook_apply_global_rebind(const mach_header_u *mh, global_rebind *rebind)
{
    if (mh != rebind->sourceHeader) {
        bool filterAllowed = true;
        if (rebind->exceptionFilter) filterAllowed = rebind->exceptionFilter(mh);
        if (filterAllowed) {
            litehook_rebind_symbol(mh, rebind->replacee, rebind->replacement, NULL);
        }
    }
}

void _litehook_apply_global_rebinds(const mach_header_u *mh, intptr_t vmaddr_slide)
{
    if (!gRebinds || gRebindCount == 0) return;

    for (uint32_t i = 0; i < gRebindCount; i++) {
        // Apply all existing rebinds for newly loaded image
        _litehook_apply_global_rebind(mh, &gRebinds[i]);
    }
}

void litehook_rebind_symbol(const mach_header_u *targetHeader, void *replacee, void *replacement, bool (*exceptionFilter)(const mach_header_u *header))
{
    if (targetHeader == LITEHOOK_REBIND_GLOBAL) {
        if (!replacee || !replacement) return;

        // We need the mach_header in which the replacement function lives, since we want to exclude it from the rebind
        Dl_info replacementInfo = {};
        if (dladdr(replacement, &replacementInfo) == 0) return;
        if (replacementInfo.dli_fname == NULL) return;
        const mach_header_u *sourceHeader = NULL;
        for (unsigned i = 0; i < _dyld_image_count(); i++) {
            if (!strcmp(_dyld_get_image_name(i), replacementInfo.dli_fname)) {
                sourceHeader = (const mach_header_u *)_dyld_get_image_header(i);
                break;
            }
        }
        if (!sourceHeader) return;

        if (!gRebinds) {
            _dyld_register_func_for_add_image((void (*)(const struct mach_header *, intptr_t))_litehook_apply_global_rebinds);
        }

        gRebinds = realloc(gRebinds, sizeof(global_rebind) * ++gRebindCount);

        global_rebind *rebind = &gRebinds[gRebindCount-1];
        rebind->sourceHeader = sourceHeader;
        rebind->replacee = replacee;
        rebind->replacement = replacement;
        rebind->exceptionFilter = exceptionFilter;

        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            const mach_header_u *header = (const mach_header_u *)_dyld_get_image_header(i);
            // Apply new rebind for all already loaded images
            _litehook_apply_global_rebind(header, rebind);
        }
    }
    else {
        struct load_command *lcp = (void *)((uintptr_t)targetHeader + sizeof(mach_header_u));
        for(int i = 0; i < targetHeader->ncmds; i++) {
            if (lcp->cmd == LC_SEGMENT_U) {
                segment_command_u *segCmd = (segment_command_u *)lcp;
                if (!strncmp(segCmd->segname, "__AUTH_CONST", sizeof(segCmd->segname)) ||
                    !strncmp(segCmd->segname, "__AUTH", sizeof(segCmd->segname)) ||
                    !strncmp(segCmd->segname, "__DATA_CONST", sizeof(segCmd->segname)) ||
                    !strncmp(segCmd->segname, "__DATA_DIRTY", sizeof(segCmd->segname)) ||
                    !strncmp(segCmd->segname, "__DATA", sizeof(segCmd->segname))) {
                    section_u *sections = (void *)((uintptr_t)lcp + sizeof(segment_command_u));
                    for (int j = 0; j < segCmd->nsects; j++) {
                        if ((sections[j].flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                            (sections[j].flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS ||
                            (sections[j].flags & SECTION_TYPE) == S_THREAD_LOCAL_VARIABLE_POINTERS) {
                            _litehook_rebind_symbol_in_section(targetHeader, &sections[j], replacee, replacement);
                        }
                    }
                }
            }
            lcp = (void *)((uintptr_t)lcp + lcp->cmdsize);
        }
    }
}

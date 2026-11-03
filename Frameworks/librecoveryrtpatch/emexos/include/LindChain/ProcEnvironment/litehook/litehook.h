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

#include <stdio.h>
#include <stdbool.h>
#include <mach/mach.h>
#include <mach-o/loader.h>

#ifdef __arm64__
typedef struct mach_header_64 mach_header_u;
typedef struct segment_command_64 segment_command_u;
typedef struct section_64 section_u;
typedef struct nlist_64 nlist_u;
#define LC_SEGMENT_U LC_SEGMENT_64
#else
typedef struct mach_header mach_header_u;
typedef struct segment_command segment_command_u;
typedef struct section section_u;
typedef struct nlist nlist_u;
#define LC_SEGMENT_U LC_SEGMENT
#endif

const char *litehook_locate_dsc(void);

void *litehook_find_symbol(const mach_header_u *header, const char *symbolName);
void *litehook_find_symbol_file(const mach_header_u *header, const char *symbolName);
void *litehook_find_dsc_symbol(const char *imagePath, const char *symbolName);

#define LITEHOOK_REBIND_GLOBAL NULL
void litehook_rebind_symbol(const mach_header_u *targetHeader, void *replacee, void *replacement, bool (*exceptionFilter)(const mach_header_u *header));

bool os_tpro_is_supported(void);
void os_thread_self_restrict_tpro_to_rw(void);
void os_thread_self_restrict_tpro_to_ro(void);

typedef struct {
    const mach_header_u *sourceHeader;
    void *replacee;
    void *replacement;
    bool (*exceptionFilter)(const mach_header_u *header);
} global_rebind;

extern uint32_t gRebindCount;
extern global_rebind *gRebinds;

#define DEFINE_HOOK(func, return_type, signature) \
    static return_type (*orig_##func) signature __attribute__((unused)) = \
        (return_type (*) signature)func; \
    static return_type hook_##func signature

#define DO_HOOK(func, type) \
    litehook_rebind_symbol(type, func, hook_##func, NULL)

#define DO_HOOK_GLOBAL(func) \
    DO_HOOK(func,LITEHOOK_REBIND_GLOBAL)

#define ORIG_FUNC(func) \
    orig_##func

#define HOOK_FUNC(func) \
    hook_##func

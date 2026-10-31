/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2023 - 2026 LiveContainer
 Copyright (C) 2026 emexlab
 Copyright (C) 2026 semvis123

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

#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <libgen.h>
#import <LindChain/ProcEnvironment/litehook/litehook.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCUtils.h>

#ifndef __NXTOOL
#define __NXTOOL 0
#endif /* !__NXTOOL */

static uint32_t rnd32(uint32_t v,
                      uint32_t r)
{
    r--;
    return (v + r) & ~r;
}

LCMachO *LCMapMachO(const char *path,
                    bool readOnly)
{
    LCMachO *machO = calloc(1, sizeof(LCMachO));
    if(machO == nil)
    {
        return NULL;
    }
    machO->fd = -1; /* so close doesnt destroy STDIN_FILENO */
    
    /* initially opening the machO */
    machO->ro = readOnly;
    /* readers share the lock, only writers (re-signing) need it exclusive */
    machO->fd = open(path, readOnly ? (O_RDONLY | O_SHLOCK) : (O_RDWR | O_EXLOCK), (mode_t)readOnly ? 0400 : 0600);
    if(machO->fd < 0)
    {
        goto out_fail_deallocate;
    }
    
    machO->path = malloc(PATH_MAX);
    if(machO->path == NULL)
    {
        goto out_fail_deallocate;
    }
    
    if(fcntl(machO->fd, F_GETPATH, machO->path) != 0)
    {
        goto out_fail_deallocate_path;
    }
    
    /* getting its size and so on */
    struct stat s = {0};
    if(fstat(machO->fd, &s) != 0)
    {
        goto out_fail_deallocate_path;
    }
    
    machO->size = s.st_size;
    
    /* initally mapping the machO */
    machO->map = mmap(NULL, machO->size, readOnly ? PROT_READ : (PROT_READ | PROT_WRITE), readOnly ? MAP_PRIVATE : MAP_SHARED, machO->fd, 0);
    if(machO->map == MAP_FAILED)
    {
        goto out_fail_deallocate_path;
    }
    
    /* find the header */
    machO->header = NULL;
    uint32_t magic = *(uint32_t *)machO->map;
    if(magic == FAT_CIGAM)
    {
        /* checking slices */
        struct fat_header *header = (struct fat_header *)machO->map;
        struct fat_arch *arch = (struct fat_arch *)(machO->map + sizeof(struct fat_header));
        for(int i = 0; i < OSSwapInt32(header->nfat_arch); i++)
        {
            if(OSSwapInt32(arch->cputype) == CPU_TYPE_ARM64)
            {
                machO->header = (struct mach_header_64 *)(machO->map + OSSwapInt32(arch->offset));
            }
            arch = (struct fat_arch *)((void *)arch + sizeof(struct fat_arch));
        }
    }
    else if(magic == MH_MAGIC_64 || magic == MH_MAGIC)
    {
        machO->header = (struct mach_header_64 *)machO->map;
    }
    
    if(machO->header == nil)
    {
        /* incompatible */
        goto out_fail_unmap;
    }
    
    return machO;
    
out_fail_unmap:
    munmap(machO->map, machO->size);
out_fail_deallocate_path:
    free(machO->path);
out_fail_deallocate_close:
    close(machO->fd);
out_fail_deallocate:
    free(machO);
    return NULL;
}

LCMachO *LCMapMachOFromFDRO(int fd)
{
    if(fd < 0)
    {
        return NULL;
    }
    
    LCMachO *machO = calloc(1, sizeof(LCMachO));
    if(machO == NULL)
    {
        close(fd);
        return NULL;
    }
    
    machO->path = malloc(PATH_MAX);
    if(machO->path == NULL)
    {
        goto out_fail_deallocate;
    }
    
    /* initially opening the machO */
    machO->ro = true;
    machO->fd = fd;
    
    if(fcntl(machO->fd, F_GETPATH, machO->path) != 0)
    {
        goto out_fail_deallocate_path;
    }
    
    /* getting its size and so on */
    struct stat s = {0};
    if(fstat(machO->fd, &s) != 0)
    {
        goto out_fail_deallocate_path;
    }
    
    machO->size = s.st_size;
    
    /* initally mapping the machO */
    machO->map = mmap(NULL, machO->size, PROT_READ, MAP_SHARED, machO->fd, 0);
    if(machO->map == MAP_FAILED)
    {
        goto out_fail_deallocate_path;
    }
    
    /* find the header */
    machO->header = NULL;
    uint32_t magic = *(uint32_t *)machO->map;
    if(magic == FAT_CIGAM)
    {
        /* checking slices */
        struct fat_header *header = (struct fat_header *)machO->map;
        struct fat_arch *arch = (struct fat_arch *)(machO->map + sizeof(struct fat_header));
        for(int i = 0; i < OSSwapInt32(header->nfat_arch); i++)
        {
            if(OSSwapInt32(arch->cputype) == CPU_TYPE_ARM64)
            {
                machO->header = (struct mach_header_64 *)(machO->map + OSSwapInt32(arch->offset));
            }
            arch = (struct fat_arch *)((void *)arch + sizeof(struct fat_arch));
        }
    }
    else if(magic == MH_MAGIC_64 || magic == MH_MAGIC)
    {
        machO->header = (struct mach_header_64 *)machO->map;
    }
    
    if(machO->header == NULL)
    {
        /* incompatible */
        goto out_fail_unmap;
    }
    
    return machO;

out_fail_unmap:
    munmap(machO->map, machO->size);
out_fail_deallocate_path:
    free(machO->path);
out_fail_deallocate:
    free(machO);
    close(fd);
    return NULL;
}

void LCUnmapMachO(LCMachO *machO)
{
    if(!machO->ro)
    {
        msync(machO->map, machO->size, MS_SYNC);
    }
    munmap(machO->map, machO->size);
    close(machO->fd);
    free(machO->path);
    free(machO);
}

static const char LCLibCppPath[] = "/usr/lib/libc++.1.dylib";

static bool LCValidateLoadCommands(LCMachO *machO)
{
    const uint8_t *map = (const uint8_t *)machO->map;
    const uint8_t *header = (const uint8_t *)machO->header;
    if(header < map ||
       (size_t)(header - map) > machO->size ||
       machO->size - (size_t)(header - map) < sizeof(struct mach_header_64))
    {
        return false;
    }
    
    size_t available = machO->size - (size_t)(header - map) - sizeof(struct mach_header_64);
    uint32_t ncmds = machO->header->ncmds;
    uint32_t sizeofcmds = machO->header->sizeofcmds;
    if(machO->header->magic != MH_MAGIC_64 || ncmds == 0 || sizeofcmds > available)
    {
        return false;
    }
    
    const uint8_t *cmds = header + sizeof(struct mach_header_64);
    uint32_t off = 0;
    for(uint32_t i = 0; i < ncmds; i++)
    {
        if(sizeofcmds - off < sizeof(struct load_command))
        {
            return false;
        }
        
        const struct load_command *lc = (const struct load_command *)(cmds + off);
        const uint32_t cmdsize = lc->cmdsize;
        if(cmdsize < sizeof(struct load_command) || (cmdsize & 7) != 0 || cmdsize > sizeofcmds - off)
        {
            return false;
        }
        
        if(lc->cmd == LC_SEGMENT_64)
        {
            if(cmdsize < sizeof(struct segment_command_64))
            {
                return false;
            }
            
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if(seg->nsects > (cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64))
            {
                return false;
            }
        }
        else if(lc->cmd == 0x114514)
        {
            if(cmdsize < sizeof(struct dylib_command))
            {
                return false;
            }
            
            const uint32_t nameOff = ((const struct dylib_command *)lc)->dylib.name.offset;
            if(nameOff < sizeof(struct dylib_command) ||
               nameOff >= cmdsize ||
               cmdsize - nameOff < sizeof(LCLibCppPath))
            {
                return false;
            }
        }
        
        off += cmdsize;
    }
    
    return off == sizeofcmds;
}

static void LCInsertDylibCommand(LCMachO *machO,
                                 const char *path,
                                 uint32_t cmd,
                                 long *freeSpace)
{
    const char *lastSlash = cmd == LC_ID_DYLIB ? strrchr(path, '/') : NULL;
    const char *name = lastSlash != NULL ? lastSlash + 1 : path;
    struct dylib_command *dylib;
    size_t cmdsize = sizeof(struct dylib_command) + rnd32((uint32_t)strlen(name) + 1, 8);
    if(*freeSpace < 0 || (size_t)*freeSpace < cmdsize)
    {
        return;
    }
    *freeSpace -= (long)cmdsize;
    
    if(cmd == LC_ID_DYLIB)
    {
        dylib = (struct dylib_command *)(sizeof(struct mach_header_64) + (uintptr_t)machO->header);
        memmove((void *)((uintptr_t)dylib + cmdsize), (void *)dylib, machO->header->sizeofcmds);
    }
    else
    {
        dylib = (struct dylib_command *)(sizeof(struct mach_header_64) + (void *)machO->header+machO->header->sizeofcmds);
    }
    bzero(dylib, cmdsize);
    dylib->cmd = cmd;
    dylib->cmdsize = (uint32_t)cmdsize;
    dylib->dylib.name.offset = sizeof(struct dylib_command);
    dylib->dylib.compatibility_version = 0x10000;
    dylib->dylib.current_version = 0x10000;
    dylib->dylib.timestamp = 2;
    strncpy((void *)dylib + dylib->dylib.name.offset, name, strlen(name));
    machO->header->ncmds++;
    machO->header->sizeofcmds += dylib->cmdsize;
}

bool LCPatchExecSlice(LCMachO *machO)
{
    if(machO->ro || !LCValidateLoadCommands(machO))
    {
        return false;
    }
    
    uint8_t *imageHeaderPtr = (uint8_t*)machO->header + sizeof(struct mach_header_64);
    // Literally convert an executable to a dylib
    if(machO->header->magic == MH_MAGIC_64)
    {
        //assert(header->flags & MH_PIE);
        machO->header->filetype = MH_DYLIB;
        machO->header->flags |= MH_NO_REEXPORTED_DYLIBS;
        machO->header->flags &= ~MH_PIE;
    }
    
    // Patch __PAGEZERO to map just a single zero page, fixing "out of address space"
    struct segment_command_64 *seg = (struct segment_command_64 *)imageHeaderPtr;
    if(seg->cmd == LC_SEGMENT_64 && strncmp(seg->segname, "__PAGEZERO", sizeof(seg->segname)) == 0)
    {
        seg->vmaddr = 0x100000000 - 0x4000;
        seg->vmsize = 0x4000;
    }
    
    BOOL hasDylibCommand = NO;
    struct dylib_command * dylibLoaderCommand = 0;
    uint32_t textSectionOffest = 0;
    struct load_command *command = (struct load_command *)imageHeaderPtr;
    bool codeSignatureCommandFound = false;
    for(int i = 0; i < machO->header->ncmds; i++)
    {
        switch(command->cmd)
        {
            case LC_ID_DYLIB:
                hasDylibCommand = YES;
                break;
            case 0x114514:
                dylibLoaderCommand = (struct dylib_command *)command;
                break;
            case LC_SEGMENT_64:
            {
                struct segment_command_64* seglc = (struct segment_command_64*)command;
                if(strncmp("__TEXT", seglc->segname, sizeof(seglc->segname)) == 0)
                {
                    for(uint32_t j = 0; j < seglc->nsects; j++)
                    {
                        struct section_64* sect = (struct section_64*)(((void*)command + sizeof(struct segment_command_64) + sizeof(struct section_64) * j));
                        if(0 == strncmp("__text", sect->sectname, sizeof(sect->sectname)))
                        {
                            textSectionOffest = sect->offset;
                        }
                    }
                }
                break;
            }
            case LC_CODE_SIGNATURE:
                codeSignatureCommandFound = true;
            default:
                break;
        }
        command = (struct load_command *)((void *)command + command->cmdsize);
    }
    
    /* __text is file controlled, it only counts as free space if it lies behind the commands and inside of the file */
    uint64_t commandsEnd = sizeof(struct mach_header_64) + (uint64_t)machO->header->sizeofcmds;
    uint64_t sliceAvailable = machO->size - (size_t)((uint8_t*)machO->header - (uint8_t*)machO->map);
    long freeLoadCommandCountLeft = 0;
    if(textSectionOffest > commandsEnd && textSectionOffest <= sliceAvailable)
    {
        freeLoadCommandCountLeft = (long)(textSectionOffest - commandsEnd);
    }
    int tweakLoaderLoadDylibCmdSize = 0x48;
    
    // Insert command priority: LC_CODE_SIGNATURE > LC_ID_DYLIB > LC_LOAD_DYLIB
    if(!codeSignatureCommandFound)
    {
        freeLoadCommandCountLeft -= 0x10;
    }
    
    /* has to happen first, inserting LC_ID_DYLIB moves every command and leaves this pointer stale */
    if(dylibLoaderCommand)
    {
        dylibLoaderCommand->cmd = 0x114514;
        strlcpy((void *)dylibLoaderCommand + dylibLoaderCommand->dylib.name.offset, LCLibCppPath, dylibLoaderCommand->cmdsize - dylibLoaderCommand->dylib.name.offset);
    }
    
    if(!hasDylibCommand)
    {
        LCInsertDylibCommand(machO, machO->path, LC_ID_DYLIB, &freeLoadCommandCountLeft);
    }
    
    if(!dylibLoaderCommand && freeLoadCommandCountLeft >= tweakLoaderLoadDylibCmdSize)
    {
        LCInsertDylibCommand(machO, LCLibCppPath, 0x114514, &freeLoadCommandCountLeft);
    }
    
    // Ensure No duplicated dylibs, often caused by incorrect tweak injection
    // https://github.com/LiveContainer/LiveContainer/issues/582
    // https://github.com/apple-oss-distributions/dyld/blob/93bd81f9d7fcf004fcebcb66ec78983882b41e71/mach_o/Header.cpp#L678
    struct load_command *command2 = (struct load_command *)imageHeaderPtr;
    __block int depCount = 0;
    const char** depPaths = malloc(machO->header->ncmds * sizeof(const char*));
    if(depPaths == NULL)
    {
        return false;
    }
    
    const uint8_t *cmds = (const uint8_t *)imageHeaderPtr;
    const uint32_t sizeofcmds = machO->header->sizeofcmds;
    uint32_t off = 0;
    
    for(int i = 0; i < machO->header->ncmds; i++)
    {
        if(sizeofcmds - off < sizeof(struct load_command))
        {
            goto fail;
        }
        
        struct load_command *lc = (struct load_command *)(cmds + off);
        const uint32_t cmdsize = lc->cmdsize;
        if(cmdsize < sizeof(struct load_command) || (cmdsize & 7) != 0 || cmdsize > sizeofcmds - off)
        {
            goto fail;
        }
        
        switch(command2->cmd)
        {
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            {
                if(cmdsize < sizeof(struct dylib_command))
                {
                    goto fail;
                }
                
                const uint32_t nameOff = ((struct dylib_command *)lc)->dylib.name.offset;
                if(nameOff < sizeof(struct dylib_command) || nameOff >= cmdsize)
                {
                    goto fail;
                }
                
                const char *loadPath = (const char *)lc + nameOff;
                if(memchr(loadPath, 0, cmdsize - nameOff) == NULL)
                {
                    goto fail;
                }
                
                for(int j = 0; j < depCount; ++j)
                {
                    if(strcmp(loadPath, depPaths[j]) == 0)
                    {
                        // replace this duplicated dylib command with an invalid command number
                        command2->cmd = 0x114515;
                        break;
                    }
                }
                depPaths[depCount++] = loadPath;
            }
        }
        off += cmdsize;
    }
    free(depPaths);
    return true;
    
fail:
    free(depPaths);
    return false;
}

NSString *LCPatchMachOFixupARM64eSlice(const char *path)
{
    LCMachO *machO = LCMapMachO(path, false);
    if(machO == nil)
    {
        return [NSString stringWithFormat:@"Failed to map %s: %s", path, strerror(errno)];
    }
    
    uint32_t magic = *(uint32_t *)machO->map;
    if(magic == FAT_CIGAM)
    {
        // Find arm64e slice without CPU_SUBTYPE_LIB64
        struct fat_header *fatHeader = (struct fat_header *)machO->map;
        struct fat_arch *arch = (struct fat_arch *)(machO->map + sizeof(struct fat_header));
        for(int i = 0; i < OSSwapInt32(fatHeader->nfat_arch); i++)
        {
            if(OSSwapInt32(arch->cputype) == CPU_TYPE_ARM64 && OSSwapInt32(arch->cpusubtype) == CPU_SUBTYPE_ARM64E)
            {
                struct mach_header_64 *header = (struct mach_header_64 *)(machO->map + OSSwapInt32(arch->offset));
                header->cpusubtype |= CPU_SUBTYPE_LIB64;
                arch->cpusubtype = htonl(header->cpusubtype);
                break;
            }
            arch = (struct fat_arch *)((void *)arch + sizeof(struct fat_arch));
        }
    }
    
    LCUnmapMachO(machO);
    return nil;
}

void LCPatchAppBundleFixupARM64eSlice(NSBundle *bundle)
{
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:bundle.bundleURL includingPropertiesForKeys:nil options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:nil];
    for(NSURL *fileURL in enumerator)
    {
        if([fileURL.pathExtension isEqualToString:@"dylib"])
        {
            LCPatchMachOFixupARM64eSlice(fileURL.path.fileSystemRepresentation);
        }
        else if([fileURL.pathExtension isEqualToString:@"framework"])
        {
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfURL:[fileURL URLByAppendingPathComponent:@"Info.plist"]];
            NSString *executableName = info[@"CFBundleExecutable"];
            if(!executableName)
            {
                executableName = fileURL.lastPathComponent.stringByDeletingPathExtension;
            }
            NSURL *executableURL = [fileURL URLByAppendingPathComponent:executableName];
            LCPatchMachOFixupARM64eSlice(executableURL.path.fileSystemRepresentation);
        }
    }
}

#if !__NXTOOL

mach_header_u *LCGetLoadedImageHeader(int i0, const char* name)
{
    for(uint32_t i = i0; i < _dyld_image_count(); ++i)
    {
        const char* imgName = _dyld_get_image_name(i);
        // cover simulator path aswell
        if(imgName && strncmp(imgName, name, PATH_MAX) == 0)    /* On Darwin no filepath can bypass the PATH_MAX limit so use it Duy and not some weird UB logic */
        {
            return (struct mach_header_64*)_dyld_get_image_header(i);
        }
    }
    return NULL;
}

#endif /* !__NXTOOL */

struct dyld_all_image_infos *_alt_dyld_get_all_image_infos(void)
{
    static struct dyld_all_image_infos *result;
    if(result)
    {
        return result;
    }
    struct task_dyld_info dyld_info;
    mach_vm_address_t image_infos;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t ret;
    ret = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    if(ret != KERN_SUCCESS)
    {
        return NULL;
    }
    image_infos = dyld_info.all_image_info_addr;
    result = (struct dyld_all_image_infos *)image_infos;
    return result;
}

void *getDyldBase(void)
{
    return (void *)_alt_dyld_get_all_image_infos()->dyldImageLoadAddress;
}

#if !__NXTOOL

uintptr_t LCFindSymbolOffsetUnsafe(const char *basePath, const char *symbol)
{
#if !TARGET_OS_SIMULATOR
    const char *path = basePath;
#else
    char path[PATH_MAX];
    const char *rootPath = getenv("DYLD_ROOT_PATH") ?: "";
    snprintf(path, sizeof(path), "%s%s", rootPath, basePath);
#endif
    __block uint64_t offset = 0;
    LCMachO *machO = LCMapMachO(path, true);
    if(machO != nil)
    {
        if(machO->header->cputype != CPU_TYPE_ARM64)
        {
            goto break_out;
        }
        
        void *result = litehook_find_symbol_file(machO->header, symbol);
        offset = (uint64_t)result - (uint64_t)machO->header;
    }
    
break_out:
    if(machO != nil)
    {
        LCUnmapMachO(machO);
    }
    return offset;
}

uintptr_t LCFindSymbolOffset(const char *basePath, const char *symbol)
{
    uintptr_t offset = LCFindSymbolOffsetUnsafe(basePath, symbol);
    NSCAssert(offset != 0, @"Failed to find symbol %s", symbol);
    return offset;
}

#endif /* !__NXTOOL */

struct linkedit_data_command* findSignatureCommand(struct mach_header_64* header)
{
    uint8_t *imageHeaderPtr = (uint8_t*)header + sizeof(struct mach_header_64);
    struct load_command *command = (struct load_command *)imageHeaderPtr;
    struct linkedit_data_command* codeSignCommand = 0;
    for(int i = 0; i < header->ncmds; i++)
    {
        if(command->cmd == LC_CODE_SIGNATURE)
        {
            codeSignCommand = (struct linkedit_data_command*)command;
            break;
        }
        command = (struct load_command *)((void *)command + command->cmdsize);
    }
    return codeSignCommand;
}

bool LCCheckCodeSignature(LCMachO *machO)
{
    /* if it is not ARM64 then it cannot run on this device */
    if(machO->header->cputype != CPU_TYPE_ARM64)
    {
        return false;
    }
    
    /* binary must be signed, otherwise no execution */
    struct linkedit_data_command* codeSignatureCommand = findSignatureCommand(machO->header);
    if(!codeSignatureCommand)
    {
        return false;
    }
    
    /* checking if the kernel says this is signed */
    off_t sliceOffset = (uint8_t*)machO->header - (uint8_t*)machO->map;
    fsignatures_t siginfo;
    siginfo.fs_file_start = sliceOffset;
    siginfo.fs_blob_start = (void*)(long)(codeSignatureCommand->dataoff);
    siginfo.fs_blob_size = codeSignatureCommand->datasize;
    int addFileSigsReault = fcntl(machO->fd, F_ADDFILESIGS_RETURN, &siginfo);
    if(addFileSigsReault == -1 )
    {
        return false;
    }
    
    /* checking if this can be executed by us */
    fchecklv_t checkInfo;
    checkInfo.lv_error_message_size = 0;
    checkInfo.lv_error_message = NULL;
    checkInfo.lv_file_start= sliceOffset;
    int checkLVresult = fcntl(machO->fd, F_CHECK_LV, &checkInfo);
    if(checkLVresult == 0)
    {
        return true;
    }
    
    return false;
}

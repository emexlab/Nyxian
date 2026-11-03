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

#import "NXRecoveryTerminal.h"
#import "NXRecoveryViewController.h"
#import "TWRP/NXTWRPTerminal.hpp"
#import <LindChain/ProcEnvironment/LiveContainer/LCUtils.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#import <LindChain/ProcEnvironment/Utils/vnode.h>
#import <LindChain/Utils/Zip.h>
#import <LindChain/Utils/NXBootLockdown.h>
#include "../../Frameworks/librecoveryrtpatch/recovery_ksurface.h"
#include <Frameworks/libpatchfind/libpatchfind.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *const NXRecoveryErrorDomain = @"org.emexlabs.nyxian.recovery.terminal";
/* marker of older bootloaders, which only unpacked when the binpack changed */
static NSString *const NXRecoveryBinpackMarker = @".binpack-sha256";

/* the mini kernel, resolved once it is loaded */
static rks_boot_fn rks_boot_ptr;
static rks_spawn_terminal_fn rks_spawn_terminal_ptr;
static rks_tty_set_winsize_fn rks_tty_set_winsize_ptr;
static rks_set_exit_handler_fn rks_set_exit_handler_ptr;

/* ----------------------------------------------------------------------
 *  host services for librecoveryksurface
 * -------------------------------------------------------------------- */

/*
 * Resign like KSurface's SYS_sign2: on a clone (a fresh vnode, the kernel may
 * already hold the old signature for the original), then cloned back over
 * the original path. Already valid binaries are left alone.
 */
NX_BOOT_ONLY static int NXRecoverySign(const char *path)
{
    LCMachO *macho = LCMapMachO(path, true);
    if(macho == NULL)
    {
        return ENOEXEC;
    }
    bool valid = LCCheckCodeSignature(macho);
    LCUnmapMachO(macho);
    if(valid)
    {
        return 0;
    }

    int vfd = vnode_inaccessible_open(path, O_RDWR);
    if(vfd < 0)
    {
        return errno ? errno : EIO;
    }
    char clone[PATH_MAX];
    if(fcntl(vfd, F_GETPATH, clone) != 0)
    {
        vnode_inaccessible_close(vfd, false);
        return EBADF;
    }
    BOOL signedClone;
    @autoreleasepool
    {
        signedClone = NXSignMachOAuto([NSURL fileURLWithPath:@(clone)]);
    }
    if(!signedClone)
    {
        vnode_inaccessible_close(vfd, false);
        return ENOEXEC;
    }
    if(vnode_inaccessible_reopen(&vfd) != 0 || vnode_inaccessible_close(vfd, true) != 0)
    {
        return EIO;
    }
    return 0;
}

static void NXRecoveryKernelLog(const char *message)
{
    NSLog(@"[librecoveryksurface] %s", message);
}

static void NXRecoveryShellExited(pid_t pid, int status, void *context)
{
    NXTWRPTerminalSessionEnded(pid, status);
}

static void NXRecoveryTerminalResize(int masterFD, unsigned short rows, unsigned short cols)
{
    if(rks_tty_set_winsize_ptr != NULL)
    {
        rks_tty_set_winsize_ptr(masterFD, rows, cols);
    }
}

static bool NXRecoveryTerminalLaunch(void);

/* ----------------------------------------------------------------------
 *  terminal
 * -------------------------------------------------------------------- */

@implementation NXRecoveryTerminal {
    dispatch_queue_t _queue;
    BOOL _booted;
    BOOL _unpacked;     /* the binpack was laid out fresh in this run of the bootloader */
}

+ (NXRecoveryTerminal *)shared
{
    static NXRecoveryTerminal *terminal;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        terminal = [NXRecoveryTerminal new];
        terminal->_queue = dispatch_queue_create("org.emexlabs.nyxian.recovery.terminal", DISPATCH_QUEUE_SERIAL);
    });
    return terminal;
}

- (NSString *)rootPath
{
    return [NSHomeDirectory() stringByAppendingPathComponent:@RKS_LAYOUT_VROOT];
}

/* the binpack, roothide's JBROOT */
- (NSString *)jbrootPath
{
    return [self.rootPath stringByAppendingPathComponent:@RKS_LAYOUT_JBROOT];
}

- (NSString *)frameworksPath
{
    return NSBundle.mainBundle.privateFrameworksPath;
}

- (NSError *)errorWithFormat:(NSString *)format, ...
{
    va_list ap;
    va_start(ap, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end(ap);
    return [NSError errorWithDomain:NXRecoveryErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey: message}];
}

- (void)presentInRecovery:(NXRecoveryViewController *)controller
{
    [self presentInRecovery:controller command:nil];
}

/* command builds the line typed into the shell once it runs (after the binpack is unpacked) */
- (void)presentInRecovery:(NXRecoveryViewController *)controller command:(NSString *(^)(void))command
{
    if(NXTWRPTerminalAttached())
    {
        [controller enterTerminal];
        [self sendCommand:command];
        return;
    }

    [controller enterConsole];
    [controller recoveryLog:@"Starting the recovery terminal..."];
    __weak NXRecoveryViewController *weakController = controller;
    dispatch_async(_queue, ^{
        NSError *error = nil;
        BOOL ok = [self prepareWithLog:^(NSString *line) { [weakController recoveryLog:line]; } error:&error] &&
                  [self startSession:&error];
        dispatch_async(dispatch_get_main_queue(), ^{
            NXRecoveryViewController *c = weakController;
            if(c == nil)
            {
                return;
            }
            if(ok)
            {
                [c exitConsole];
                [c enterTerminal];
                [self sendCommand:command];
            }
            else
            {
                [c recoveryLogError:[@"ERROR: " stringByAppendingString:error.localizedDescription ?: @"the terminal could not start"]];
                [c finishConsoleWithSelectAction:^(NXRecoveryViewController *done) { [done exitConsole]; }];
            }
        });
    });
}

- (void)sendCommand:(NSString *(^)(void))command
{
    NSString *line = command ? command() : nil;
    if(line.length)
    {
        /* ^U drops whatever was typed at the prompt, like TWRP's terminal starts its command on a clean line */
        NXTWRPTerminalSendCommand([NSString stringWithFormat:@"\x15%@\r", line].UTF8String);
    }
}

static NSString *NXRecoveryShellQuote(NSString *text)
{
    return [NSString stringWithFormat:@"'%@'", [text stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"]];
}

static NSString *NXRecoveryRelativePath(NSString *path, NSString *base)
{
    if([path isEqualToString:base])
    {
        return @"";
    }
    NSString *prefix = [base hasSuffix:@"/"] ? base : [base stringByAppendingString:@"/"];
    return [path hasPrefix:prefix] ? [path substringFromIndex:prefix.length] : nil;
}

- (NSString *)shellPathForPath:(NSString *)path
{
    NSString *real = path.stringByStandardizingPath;
    NSString *relative = NXRecoveryRelativePath(real, self.jbrootPath.stringByStandardizingPath);
    if(relative != nil)
    {
        return [@"/" stringByAppendingString:relative];
    }

    /* layOutRootfs: rootfs/ links every directory of the container, rootfs/Library/ every directory of ~/Library */
    NSString *library = self.rootPath.stringByDeletingLastPathComponent.stringByStandardizingPath;
    NSString *container = library.stringByDeletingLastPathComponent;
    relative = NXRecoveryRelativePath(real, container);
    if(relative == nil)
    {
        return nil;
    }
    NSArray<NSString *> *parts = relative.pathComponents;
    if(parts.count == 0)
    {
        return @"/rootfs";
    }
    NSString *linked = [container stringByAppendingPathComponent:parts[0]];
    if([parts[0] isEqualToString:library.lastPathComponent])
    {
        if(parts.count == 1)
        {
            return @"/rootfs/Library";
        }
        linked = [library stringByAppendingPathComponent:parts[1]];
    }
    else if([parts[0] isEqualToString:@RKS_LAYOUT_SKIP] || [parts[0] isEqualToString:@"dev"])
    {
        return nil;
    }
    BOOL directory = NO;
    if([linked.lastPathComponent hasPrefix:@"."] ||
       ![NSFileManager.defaultManager fileExistsAtPath:linked isDirectory:&directory] || !directory)
    {
        return nil;
    }
    return [@"/rootfs/" stringByAppendingString:relative];
}

- (void)editFile:(NSString *)path inRecovery:(NXRecoveryViewController *)controller
{
    NSString *target = [self shellPathForPath:path];
    if(target == nil)
    {
        [controller recoveryLogError:[@"the recovery shell cannot see " stringByAppendingString:path]];
        return;
    }
    [self presentInRecovery:controller command:^NSString *{
        /* TWRP runs nano "%tw_filename1%"; decided once the binpack is laid out */
        BOOL nano = [NSFileManager.defaultManager fileExistsAtPath:[self.jbrootPath stringByAppendingPathComponent:@"usr/bin/nano"]];
        return [NSString stringWithFormat:@"%@ %@", nano ? @"nano" : @"vi", NXRecoveryShellQuote(target)];
    }];
}

- (void)openTerminalAt:(NSString *)directory inRecovery:(NXRecoveryViewController *)controller
{
    NSString *target = [self shellPathForPath:directory];
    if(target == nil)
    {
        [controller recoveryLogError:[@"the recovery shell cannot see " stringByAppendingString:directory]];
        return;
    }
    [self presentInRecovery:controller command:^NSString *{
        return [@"cd " stringByAppendingString:NXRecoveryShellQuote(target)];
    }];
}

/* ----------------------------------------------------------------------
 *  recovery root
 * -------------------------------------------------------------------- */

/* the bundle path changes with every install, links are always refreshed */
static BOOL NXRecoveryLink(NSString *path, NSString *target)
{
    char current[PATH_MAX];
    ssize_t length = readlink(path.fileSystemRepresentation, current, sizeof(current) - 1);
    if(length >= 0)
    {
        current[length] = '\0';
        if([@(current) isEqualToString:target])
        {
            return YES;
        }
    }
    unlink(path.fileSystemRepresentation);
    [NSFileManager.defaultManager createDirectoryAtPath:path.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
    return symlink(target.fileSystemRepresentation, path.fileSystemRepresentation) == 0;
}

- (BOOL)prepareWithLog:(void (^)(NSString *line))log error:(NSError **)error
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *root = self.rootPath;
    NSString *jbroot = self.jbrootPath;

    /* binpack */
    NSString *archive = [NSBundle.mainBundle pathForResource:@"Shared/Recovery/binpack" ofType:@"zip"];
    if(archive == nil)
    {
        *error = [self errorWithFormat:@"binpack.zip is missing from the bundle"];
        return NO;
    }
    /*
     * A recovery starts from a clean binpack: the first terminal open of every
     * bootloader run wipes $jbroot and unpacks the bundle's binpack again
     * (binaries are signed again on demand). Later opens in the same run keep
     * it, so a shell restarted with a key press finds what the last one left.
     */
    NSString *shell = [jbroot stringByAppendingPathComponent:@"usr/bin/bash"];
    if(!_unpacked)
    {
        unsigned long long size = [[fm attributesOfItemAtPath:archive error:nil] fileSize];
        log([NSString stringWithFormat:@"Unpacking the binpack (%.1f MB) to %@...", size / 1048576.0,
             [jbroot stringByReplacingOccurrencesOfString:NSHomeDirectory() withString:@"~"]]);
        [fm removeItemAtPath:jbroot error:nil];
        /* what other layouts of the recovery left in the container */
        NSString *library = [NSHomeDirectory() stringByAppendingPathComponent:@"Library"];
        [fm removeItemAtPath:[library stringByAppendingPathComponent:@"procursus"] error:nil];
        [fm removeItemAtPath:[library stringByAppendingPathComponent:@"fakeroot"] error:nil];
        rmdir([NSHomeDirectory() stringByAppendingPathComponent:@"dev"].fileSystemRepresentation);    /* only ever an empty one */
        rmdir([root.stringByDeletingLastPathComponent stringByAppendingPathComponent:@"dev"].fileSystemRepresentation);
        [fm removeItemAtPath:[root stringByAppendingPathComponent:@"dev"] error:nil];       /* /dev while ROOTFS was the vroot */
        [fm removeItemAtPath:[root stringByAppendingPathComponent:NXRecoveryBinpackMarker] error:nil];
        if(![fm createDirectoryAtPath:jbroot withIntermediateDirectories:YES attributes:nil error:error])
        {
            return NO;
        }
        if(!unzipArchiveAtPath(archive, jbroot) || ![fm fileExistsAtPath:shell])
        {
            *error = [self errorWithFormat:@"unpacking the binpack failed"];
            return NO;
        }
        _unpacked = YES;
        log(@"Binpack unpacked, binaries are signed the first time they run.");
    }

    /* layout, like emexOS's $vroot */
    NSString *rtpatch = [self.frameworksPath stringByAppendingPathComponent:@RKS_RTPATCH_NAME];
    if(![fm fileExistsAtPath:rtpatch])
    {
        *error = [self errorWithFormat:@"%s is missing from the bundle", RKS_RTPATCH_NAME];
        return NO;
    }
    /*
     * Like emexOS: boot/rtpatch is the binpack's libroothide, which loads
     * @loader_path/.jbroot/usr/lib/roothideinit.dylib, our runtime patch, as its
     * dependency (once per process). boot/.jbroot covers a dyld that keeps
     * boot/ as libroothide's @loader_path instead of resolving the symlink.
     */
    BOOL linked = NXRecoveryLink([root stringByAppendingPathComponent:@RKS_LAYOUT_RTPATCH], @"../" RKS_LAYOUT_JBROOT "/usr/lib/libroothide.dylib") &&
                  NXRecoveryLink([root stringByAppendingPathComponent:@"boot/.jbroot"], @"../" RKS_LAYOUT_JBROOT) &&
                  NXRecoveryLink([root stringByAppendingPathComponent:@RKS_LAYOUT_BOOTLOADER], NSBundle.mainBundle.bundlePath) &&
                  NXRecoveryLink([jbroot stringByAppendingPathComponent:@".jbroot"], @".") &&
                  NXRecoveryLink([jbroot stringByAppendingPathComponent:@"usr/lib/roothideinit.dylib"], rtpatch);
    if(!linked)
    {
        *error = [self errorWithFormat:@"could not lay out %@ (%s)", root, strerror(errno)];
        return NO;
    }

    /* libroothide is mapped before the runtime patch's signing hook exists */
    NSString *libroothide = [jbroot stringByAppendingPathComponent:@"usr/lib/libroothide.dylib"];
    int signError = NXRecoverySign(libroothide.fileSystemRepresentation);
    if(signError != 0)
    {
        *error = [self errorWithFormat:@"could not sign %@ (%s)", libroothide.lastPathComponent, strerror(signError)];
        return NO;
    }
    if(![self layOutRootfs:error])
    {
        return NO;
    }
    for(NSString *directory in @[@"tmp", @"var/tmp", @"var/root", @"var/run/pty", @"var/log"])
    {
        [fm createDirectoryAtPath:[jbroot stringByAppendingPathComponent:directory] withIntermediateDirectories:YES attributes:nil error:nil];
    }
    chmod([jbroot stringByAppendingPathComponent:@"tmp"].fileSystemRepresentation, 01777);

    /* the patch cache every guest reads, so no guest has to run libpatchfind itself */
    if(![self emitPatchCacheAt:[root stringByAppendingPathComponent:@"boot/patchfinder.bin"] error:error])
    {
        return NO;
    }

    return [self bootKernel:error];
}

/*
 * ROOTFS (/rootfs in the shell): the bootloader's container as guests can
 * reach it. The sandbox issues no extension for the container root or
 * ~/Library, only for the directories in them, and ROOTFS itself must be
 * covered by one (libroothide stat()s it). So vroot/rootfs links every
 * top-level directory of the container (SystemData excluded) and, in a real
 * rootfs/Library/, every entry of ~/Library; the recovery kernel grants each
 * link target. rootfs/dev/ is the /dev (emexOS's devfs) the binpack's
 * dev -> /dev resolves to. Rebuilt on every start.
 */
static BOOL NXRecoveryLinkEntries(NSString *source, NSString *destination, NSString *prefix, NSArray<NSString *> *skip, NSError **error)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    if(![fm createDirectoryAtPath:destination withIntermediateDirectories:YES attributes:nil error:error])
    {
        return NO;
    }
    NSMutableSet<NSString *> *wanted = [NSMutableSet setWithArray:skip];
    for(NSString *name in [fm contentsOfDirectoryAtPath:source error:nil])
    {
        BOOL directory = NO;
        if([name hasPrefix:@"."] || [skip containsObject:name] ||
           ![fm fileExistsAtPath:[source stringByAppendingPathComponent:name] isDirectory:&directory] || !directory)
        {
            continue;
        }
        [wanted addObject:name];
        if(!NXRecoveryLink([destination stringByAppendingPathComponent:name], [prefix stringByAppendingString:name]))
        {
            return NO;
        }
    }
    /* links to directories that are gone */
    for(NSString *name in [fm contentsOfDirectoryAtPath:destination error:nil])
    {
        struct stat st;
        NSString *path = [destination stringByAppendingPathComponent:name];
        if(![wanted containsObject:name] && lstat(path.fileSystemRepresentation, &st) == 0 && S_ISLNK(st.st_mode))
        {
            unlink(path.fileSystemRepresentation);
        }
    }
    return YES;
}

- (BOOL)layOutRootfs:(NSError **)error
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *root = self.rootPath;
    NSString *library = root.stringByDeletingLastPathComponent;
    NSString *container = library.stringByDeletingLastPathComponent;
    NSString *rootfs = [root stringByAppendingPathComponent:@RKS_LAYOUT_ROOTFS];

    /*
     * Absolute targets, the real paths: libroothide resolves links inside ROOTFS
     * itself, relative to /rootfs, so ../../../X climbs to /rootfs/X instead of
     * the container (rootfs/Library/X ended at the missing /rootfs/X). A target
     * that is no ROOTFS path but a host path the guest can read is taken as is.
     */
    char real[PATH_MAX];
    NSString *containerReal = realpath(container.fileSystemRepresentation, real) ? @(real) : container;
    NSString *libraryReal = realpath(library.fileSystemRepresentation, real) ? @(real) : library;
    if(!NXRecoveryLinkEntries(container, rootfs, [containerReal stringByAppendingString:@"/"], @[library.lastPathComponent, @RKS_LAYOUT_SKIP, @"dev"], error) ||
       !NXRecoveryLinkEntries(library, [rootfs stringByAppendingPathComponent:library.lastPathComponent], [libraryReal stringByAppendingString:@"/"], @[], error))
    {
        if(error && !*error)
        {
            *error = [self errorWithFormat:@"could not lay out %@ (%s)", rootfs, strerror(errno)];
        }
        return NO;
    }
    NSString *dev = [rootfs stringByAppendingPathComponent:@"dev"];
    struct stat st;
    if(lstat(dev.fileSystemRepresentation, &st) == 0 && !S_ISDIR(st.st_mode))
    {
        unlink(dev.fileSystemRepresentation);
    }
    return [fm createDirectoryAtPath:dev withIntermediateDirectories:YES attributes:nil error:error];
}

/*
 * KSurface's ksurface_patchcache_emit for the recovery root. The guest runtime
 * reads $vroot/boot/patchfinder.bin for its dyld hooks (the dlopen hardware
 * breakpoint context librecoveryrtpatch hooks into). Without it every guest
 * would dlopen and run libpatchfind on its own, which ROM guests never do.
 */
- (BOOL)emitPatchCacheAt:(NSString *)path error:(NSError **)error
{
    NSString *binary = [self.frameworksPath stringByAppendingPathComponent:@"libpatchfind.dylib"];
    void *library = dlopen(binary.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
    nxpf_resolve_base_fn resolve = library ? (nxpf_resolve_base_fn)dlsym(library, "nxpf_resolve_base") : NULL;
    uint64_t base[kDyldPtrCount] = {0};
    if(resolve == NULL || !resolve(NXPF_BASE_ABI, base, kDyldPtrCount))
    {
        *error = [self errorWithFormat:@"libpatchfind could not resolve the dyld patch cache (ABI %u)", NXPF_BASE_ABI];
        return NO;
    }
    unsigned char bytes[kDyldPtrCount * 8 + 28];
    size_t length = nxpf_cache_encode(bytes, sizeof(bytes), base, kDyldPtrCount, NXPF_BASE_ABI, 0, 0, NULL, 0);
    if(length == 0)
    {
        *error = [self errorWithFormat:@"could not encode the dyld patch cache"];
        return NO;
    }
    /* the guest opens it O_NOFOLLOW: a regular file, replaced atomically */
    unlink(path.fileSystemRepresentation);
    NSData *data = [NSData dataWithBytes:bytes length:length];
    return [data writeToFile:path options:NSDataWritingAtomic error:error];
}

- (BOOL)bootKernel:(NSError **)error
{
    if(_booted)
    {
        return YES;
    }

    NSString *library = [self.frameworksPath stringByAppendingPathComponent:@RKS_LIBRARY_NAME];
    void *handle = dlopen(library.fileSystemRepresentation, RTLD_NOW | RTLD_LOCAL);
    if(handle == NULL)
    {
        *error = [self errorWithFormat:@"could not load %s: %s", RKS_LIBRARY_NAME, dlerror() ?: "?"];
        return NO;
    }
    rks_boot_ptr = (rks_boot_fn)dlsym(handle, "rks_boot");
    rks_spawn_terminal_ptr = (rks_spawn_terminal_fn)dlsym(handle, "rks_spawn_terminal");
    rks_tty_set_winsize_ptr = (rks_tty_set_winsize_fn)dlsym(handle, "rks_tty_set_winsize");
    rks_set_exit_handler_ptr = (rks_set_exit_handler_fn)dlsym(handle, "rks_set_exit_handler");
    if(rks_boot_ptr == NULL || rks_spawn_terminal_ptr == NULL || rks_tty_set_winsize_ptr == NULL || rks_set_exit_handler_ptr == NULL)
    {
        *error = [self errorWithFormat:@"%s does not export the recovery kernel ABI", RKS_LIBRARY_NAME];
        return NO;
    }

    NSString *root = self.rootPath;
    rks_boot_args_t args = {
        .version = RKS_ABI_VERSION,
        .size = sizeof(rks_boot_args_t),
        .root = root.fileSystemRepresentation,
        .bundle = NSBundle.mainBundle.bundlePath.fileSystemRepresentation,
        .sign = NXRecoverySign,
        .log = NXRecoveryKernelLog,
    };
    int err = rks_boot_ptr(&args);
    if(err != 0)
    {
        *error = [self errorWithFormat:@"the recovery kernel did not boot (%s)", strerror(err)];
        return NO;
    }
    rks_set_exit_handler_ptr(NXRecoveryShellExited, NULL);
    NXTWRPTerminalSetLauncher(NXRecoveryTerminalLaunch, NXRecoveryTerminalResize);
    _booted = YES;
    return YES;
}

/* ----------------------------------------------------------------------
 *  shell
 * -------------------------------------------------------------------- */

- (BOOL)startSession:(NSError **)error
{
    if(!_booted || rks_spawn_terminal_ptr == NULL)
    {
        *error = [self errorWithFormat:@"the recovery kernel is not running"];
        return NO;
    }

    NSString *shell = [self.jbrootPath stringByAppendingPathComponent:@"usr/bin/bash"];
    NSArray<NSString *> *environment = @[
        @"TERM=xterm-256color",
        /* roothide: guests see vroot paths, "/" is the binpack; CoreFoundation is not behind the vroot */
        @"HOME=/",
        [@"CFFIXED_USER_HOME=" stringByAppendingString:self.rootPath],
        @"USER=root",
        @"LOGNAME=root",
        @"SHELL=/usr/bin/bash",
        @"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        @"TMPDIR=/tmp",
        @"NX_RECOVERY=1",
    ];
    char *envp[16] = {0};
    for(NSUInteger i = 0; i < environment.count && i < 15; i++)
    {
        envp[i] = (char *)environment[i].UTF8String;
    }
    char *argv[] = { "bash", "-l", NULL };

    unsigned short rows = 24, cols = 80;
    NXTWRPTerminalSize(&rows, &cols);
    int master = -1;
    pid_t pid = -1;
    /* the shell starts in "/" (the jbroot, its real path) */
    int err = rks_spawn_terminal_ptr(shell.fileSystemRepresentation, argv, envp, self.jbrootPath.fileSystemRepresentation, rows, cols, &master, &pid);
    if(err != 0)
    {
        *error = [self errorWithFormat:@"could not start bash (%s)", strerror(err)];
        return NO;
    }
    NXTWRPTerminalAttach(master, pid);
    return YES;
}

@end

static bool NXRecoveryTerminalLaunch(void)
{
    NSError *error = nil;
    BOOL ok = [NXRecoveryTerminal.shared startSession:&error];
    if(!ok)
    {
        NSLog(@"[recovery terminal] %@", error.localizedDescription);
        NSString *line = [NSString stringWithFormat:@"\r\n[could not start a shell: %@]\r\n", error.localizedDescription ?: @"unknown error"];
        NXTWRPTerminalPrint(line.UTF8String);
    }
    return ok;
}

/* SPDX-License-Identifier: LicenseRef-EPSL-1.1
 * Copyright (C) 2026 emexLabs. See Nyxian's LICENSES for the source license.
 */
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <LindChain/Utils/NXROMDeviceTrust.h>
#include "../../LiveProcess/NXLiveProcessABI.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char *sandbox_extension_issue_file(const char *className, const char *path, uint32_t flags);

static NSBundle *liveProcessBundle(void) {
    NSURL *plugins = NSBundle.mainBundle.builtInPlugInsURL;
    return plugins ? [NSBundle bundleWithURL:[plugins URLByAppendingPathComponent:@"LiveProcess.appex"]] : nil;
}

__attribute__((used, visibility("default"))) uint32_t NXLiveProcessGetHostABIVersion(void) {
    id value = [liveProcessBundle() objectForInfoDictionaryKey:@"NXLiveProcessABI"];
    if (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() ||
        CFNumberIsFloatType((__bridge CFNumberRef)value)) return 0;
    return [value unsignedLongLongValue] == NX_LIVEPROCESS_ABI_VERSION ? NX_LIVEPROCESS_ABI_VERSION : 0;
}

__attribute__((used, visibility("default"))) uint32_t NXLiveProcessGetBootstrapVersion(void) {
    id value = [liveProcessBundle() objectForInfoDictionaryKey:@"NXLiveProcessBootstrapVersion"];
    if (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() ||
        CFNumberIsFloatType((__bridge CFNumberRef)value)) return 0;
    return [value unsignedLongLongValue] == 1 ? 1 : 0;
}

/* the appex pulls its bootstrap from the host's broker when xpc_copy_bootstrap() is empty (NXLiveProcessBroker.h) */
__attribute__((used, visibility("default"))) uint32_t NXLiveProcessGetBrokerVersion(void) {
    id value = [liveProcessBundle() objectForInfoDictionaryKey:@"NXLiveProcessBrokerVersion"];
    if (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() ||
        CFNumberIsFloatType((__bridge CFNumberRef)value)) return 0;
    return [value unsignedLongLongValue] == 1 ? 1 : 0;
}

__attribute__((used, visibility("default"))) int NXLiveProcessPrepareSimulatorLaunchV1(const char *slot, const char *relative,
                                                                              NXLiveProcessLaunchV1 *output, uint32_t size) {
    if (!output || size < sizeof(*output)) return EINVAL;
    memset(output, 0, sizeof(*output));
    if (NXLiveProcessGetHostABIVersion() < 1) return EPROTONOSUPPORT;
    if (!slot || slot[0] != '/' || !relative || !relative[0]) return EINVAL;
    NSString *suffix = [NSString stringWithUTF8String:relative];
    if (!suffix || suffix.isAbsolutePath || [suffix.pathComponents containsObject:@".."] || [suffix.pathComponents containsObject:@"."]) return EINVAL;
    char canonical[PATH_MAX], module[PATH_MAX];
    if (!realpath(slot, canonical)) return errno;
    int length = snprintf(module, sizeof(module), "%s/%s", canonical, relative);
    if (length < 0 || (size_t)length >= sizeof(module)) return ENAMETOOLONG;
    char resolved[PATH_MAX];
    if (!realpath(module, resolved)) return errno;
    if (strcmp(module, resolved)) return ELOOP; /* No module/parent symlink may redirect the authenticated path. */
    NSError *trustError = nil;
    NSString *root = [NSString stringWithUTF8String:canonical];
    if (!NXROMDeviceVerify(root, YES, &trustError) || !NXROMDeviceCheckRollback(root, NO, &trustError)) return EAUTH;
    int fd = open(module, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno;
    struct stat file;
    int error = fstat(fd, &file) ? errno : 0;
    struct mach_header_64 header;
    if (!error && (!S_ISREG(file.st_mode) || pread(fd, &header, sizeof(header), 0) != sizeof(header) ||
                   header.magic != MH_MAGIC_64 || header.filetype != MH_DYLIB || header.cputype != CPU_TYPE_ARM64)) error = ENOEXEC;
    CC_SHA256_CTX hash;
    CC_SHA256_Init(&hash);
    unsigned char buffer[16384], digest[CC_SHA256_DIGEST_LENGTH];
    while (!error) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count < 0) { if (errno == EINTR) continue; error = errno; break; }
        if (!count) break;
        CC_SHA256_Update(&hash, buffer, (CC_LONG)count);
    }
    close(fd);
    if (error) return error;
    CC_SHA256_Final(digest, &hash);
    NSString *identifier = liveProcessBundle().bundleIdentifier;
    if (!identifier.length || strlen(module) >= sizeof(output->modulePath) ||
        strlen(identifier.UTF8String) >= sizeof(output->extensionIdentifier)) return ENAMETOOLONG;
    char *token = sandbox_extension_issue_file("com.apple.app-sandbox.read", canonical, 0);
    if (!token) return EACCES;
    if (strlen(token) >= sizeof(output->readOnlySandboxToken)) { free(token); return ENAMETOOLONG; }
    output->version = 1;
    output->size = sizeof(*output);
    memcpy(output->modulePath, module, strlen(module) + 1);
    memcpy(output->extensionIdentifier, identifier.UTF8String, strlen(identifier.UTF8String) + 1);
    memcpy(output->readOnlySandboxToken, token, strlen(token) + 1);
    free(token);
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < sizeof(digest); ++i) {
        output->moduleSHA256[i * 2] = hex[digest[i] >> 4];
        output->moduleSHA256[i * 2 + 1] = hex[digest[i] & 15];
    }
    return 0;
}

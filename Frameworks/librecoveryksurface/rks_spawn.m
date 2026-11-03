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
#import <UIKit/UIKit.h>
#import <LindChain/ProcEnvironment/PEFileTable.h>
#import <LindChain/ProcEnvironment/PEFileHandle.h>
#import <LindChain/ProcEnvironment/PEMachPort.h>
#include "rks.h"
#include <spawn.h>
#include <signal.h>
#include <unistd.h>

rks_state_t rks;

extern char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);

/* ----------------------------------------------------------------------
 *  private API surface, called through id
 * -------------------------------------------------------------------- */

@protocol RKSExtension <NSObject>
- (id)extensionWithIdentifier:(NSString *)identifier error:(NSError **)error;   /* class methods, sent to the Class */
- (NSUUID *)beginExtensionRequestWithInputItems:(NSArray *)items error:(NSError **)error;
- (int)pidForRequestIdentifier:(NSUUID *)identifier;
- (void)_kill:(int)signal;
- (void)setPreferredLanguages:(NSArray *)languages;
@end

/* the guest runtime's host interface (LindChain/ProcEnvironment/Server/ServerProtocol.h) */
@protocol ServerProtocol
- (void)spawnProcessWithPath:(NSString *)path
               withArguments:(NSArray<NSObject<NSSecureCoding,NSCopying> *> *)arguments
    withEnvironmentVariables:(NSDictionary *)environment
               withFileTable:(PEFileTable *)fileTable
        withWorkingDirectory:(NSString *)workingDirectory
              withSpawnFlags:(short)spawnFlags
             withSpawnPgroup:(pid_t)spawnPgroup
                   withReply:(void (^)(int64_t))reply;
- (void)setSnapshot:(UIImage *)image;
@end

bool rks_extension_kill(void *extension, int sig)
{
    id object = (__bridge id)extension;
    if(![object respondsToSelector:@selector(_kill:)])
    {
        return false;
    }
    [(id<RKSExtension>)object _kill:sig];
    return true;
}

/* ----------------------------------------------------------------------
 *  host endpoint for the guest runtime's posix_spawn
 * -------------------------------------------------------------------- */

static pid_t rks_spawn_items(rks_proc_t *parent, NSDictionary *launch, short flags, pid_t pgroup, int *error);
static rks_tty_t *rks_controlling_tty_of(PEFileTable *table);

@interface RKSServerSession : NSObject <ServerProtocol>
@property (nonatomic) pid_t pid;
@end

@implementation RKSServerSession

- (void)spawnProcessWithPath:(NSString *)path
               withArguments:(NSArray<NSObject<NSSecureCoding,NSCopying> *> *)arguments
    withEnvironmentVariables:(NSDictionary *)environment
               withFileTable:(PEFileTable *)fileTable
        withWorkingDirectory:(NSString *)workingDirectory
              withSpawnFlags:(short)spawnFlags
             withSpawnPgroup:(pid_t)spawnPgroup
                   withReply:(void (^)(int64_t))reply
{
    rks_proc_t *parent = rks_proc_lookup(self.pid);
    if(parent == NULL || ![path isKindOfClass:NSString.class])
    {
        if(parent != NULL) rks_proc_release(parent);
        reply(-1);
        return;
    }

    NSMutableDictionary *launch = [NSMutableDictionary dictionary];
    launch[@"PEExecutablePath"] = path;
    launch[@"PEArguments"] = [arguments isKindOfClass:NSArray.class] ? arguments : @[path];
    NSMutableDictionary *childEnvironment = [environment isKindOfClass:NSDictionary.class] ? [environment mutableCopy] : [NSMutableDictionary dictionary];
    /* emexOS's posix_spawn hands persona ids over this way: no personas in the recovery, everyone is root */
    [childEnvironment removeObjectForKey:@"__PE_SPAWN_PERSONA"];
    launch[@"PEEnvironment"] = childEnvironment;
    if([workingDirectory isKindOfClass:NSString.class])
    {
        launch[@"PEWorkingDirectory"] = workingDirectory;
    }
    if([fileTable isKindOfClass:PEFileTable.class])
    {
        launch[@"PEFileTable"] = fileTable;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool
        {
            int error = 0;
            pid_t pid = rks_spawn_items(parent, launch, spawnFlags, (spawnFlags & POSIX_SPAWN_SETPGROUP) ? spawnPgroup : -1, &error);
            rks_proc_release(parent);
            reply(pid > 0 ? pid : -1);
        }
    });
}

- (void)setSnapshot:(UIImage *)image
{
    /* no app switcher in recovery */
}

@end

@interface RKSServer : NSObject <NSXPCListenerDelegate>
@end

@implementation RKSServer {
    NSMutableSet<NSXPCListener *> *_listeners;   /* tickets not used yet */
    NSMutableSet *_live;                          /* listener + connection pairs of running guests */
    NSLock *_lock;
}

+ (instancetype)shared
{
    static RKSServer *server;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        server = [RKSServer new];
        server->_listeners = [NSMutableSet set];
        server->_live = [NSMutableSet set];
        server->_lock = [NSLock new];
    });
    return server;
}

/* one listener per spawned process, it accepts exactly one connection */
- (NSXPCListenerEndpoint *)ticket
{
    NSXPCListener *listener = [NSXPCListener anonymousListener];
    listener.delegate = self;
    [_lock lock];
    [_listeners addObject:listener];
    [_lock unlock];
    [listener resume];
    return listener.endpoint;
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection
{
    [_lock lock];
    BOOL fresh = [_listeners containsObject:listener];
    [_listeners removeObject:listener];
    [_lock unlock];
    if(!fresh)
    {
        return NO;
    }
    /*
     * The guest exit(0)s as soon as this connection is interrupted or
     * invalidated, so neither the listener nor the connection may go away
     * while it runs (KSurface's Server never invalidates its tickets either).
     * Both are kept until the guest itself drops the connection.
     */
    NSArray *pair = @[listener, connection];
    [_lock lock];
    [_live addObject:pair];
    [_lock unlock];
    __weak RKSServer *weakSelf = self;
    void (^gone)(void) = ^{
        RKSServer *server = weakSelf;
        if(server == nil) return;
        [server->_lock lock];
        BOOL tracked = [server->_live containsObject:pair];
        [server->_live removeObject:pair];
        [server->_lock unlock];
        if(tracked) [listener invalidate];
    };
    connection.invalidationHandler = gone;

    RKSServerSession *session = [RKSServerSession new];
    session.pid = connection.processIdentifier;
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ServerProtocol)];
    connection.exportedObject = session;
    [connection resume];
    return YES;
}

@end

/* ----------------------------------------------------------------------
 *  spawning
 * -------------------------------------------------------------------- */

/*
 * Like KSurface's trust layer: canonical paths (the sandbox matches
 * /private/var/..., not the /var symlink). Read-write: the recovery root
 * (vroot, jbroot, rootfs/), and every directory rootfs/ links, the top-level
 * directories of the container and the entries of ~/Library (the sandbox
 * issues none for the container root or ~/Library themselves). SystemData is
 * never asked for. One that cannot be issued is left out: that directory just
 * stays out of reach. The bundle (rtpatch, libpatchfind) read-only. Issued
 * once per boot of the kernel.
 */
static NSArray<NSData *> *rks_file_permissions(void)
{
    static NSArray<NSData *> *permissions;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSFileManager *fm = NSFileManager.defaultManager;
        NSString *root = @(rks.root);
        NSString *library = root.stringByDeletingLastPathComponent;
        NSString *container = library.stringByDeletingLastPathComponent;

        NSMutableArray<NSArray *> *grants = [NSMutableArray array];
        [grants addObject:@[@"com.apple.app-sandbox.read-write", root]];
        NSArray *scans = @[@[container, @[library.lastPathComponent, @RKS_LAYOUT_SKIP]], @[library, @[root.lastPathComponent]]];
        for(NSArray *scan in scans)
        {
            for(NSString *name in [fm contentsOfDirectoryAtPath:scan[0] error:nil])
            {
                BOOL directory = NO;
                NSString *path = [scan[0] stringByAppendingPathComponent:name];
                if([name hasPrefix:@"."] || [scan[1] containsObject:name] ||
                   ![fm fileExistsAtPath:path isDirectory:&directory] || !directory)
                {
                    continue;
                }
                [grants addObject:@[@"com.apple.app-sandbox.read-write", path]];
            }
        }
        [grants addObject:@[@"com.apple.app-sandbox.read", NSBundle.mainBundle.bundlePath]];

        NSMutableArray *tokens = [NSMutableArray array];
        for(NSArray *grant in grants)
        {
            char resolved[PATH_MAX];
            const char *path = realpath([grant[1] fileSystemRepresentation], resolved) ? resolved : [grant[1] fileSystemRepresentation];
            char *token = sandbox_extension_issue_file([grant[0] UTF8String], path, 0);
            if(token != NULL)
            {
                [tokens addObject:[NSData dataWithBytes:token length:strlen(token) + 1]];
                free(token);
            }
            else
            {
                rks_logf("no sandbox extension for %s (%s)", path, strerror(errno));
            }
        }
        permissions = tokens.copy;
    });
    return permissions;
}

static NSString *rks_liveprocess_identifier(void)
{
    static NSString *identifier;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *path = [NSBundle.mainBundle.builtInPlugInsPath stringByAppendingPathComponent:@"LiveProcess.appex"];
        identifier = [NSBundle bundleWithPath:path].bundleIdentifier;
    });
    return identifier;
}

static rks_tty_t *rks_controlling_tty_of(PEFileTable *table)
{
    PEFileHandle *input = [table isKindOfClass:PEFileTable.class] ? table.fd_map[@(STDIN_FILENO)] : nil;
    if(input == nil)
    {
        return NULL;
    }
    int fd = [input extractFileDescriptor];
    if(fd < 0)
    {
        return NULL;
    }
    rks_tty_t *tty = rks_tty_for_fd(fd);
    close(fd);
    return tty;
}

static pid_t rks_spawn_items(rks_proc_t *parent, NSDictionary *launch, short flags, pid_t pgroup, int *error)
{
    NSString *identifier = rks_liveprocess_identifier();
    Class extensionClass = NSClassFromString(@"NSExtension");
    if(identifier == nil || extensionClass == nil)
    {
        *error = ENOEXEC;
        return -1;
    }

    NSMutableDictionary *items = [launch mutableCopy];

    /* the same guest defaults KSurface applies, rooted in the recovery */
    NSMutableDictionary *environment = [items[@"PEEnvironment"] mutableCopy] ?: [NSMutableDictionary dictionary];
    NSDictionary *defaults = @{
        @"HOME": @"/",                              /* roothide: a jbroot path */
        @"CFFIXED_USER_HOME": @(rks.root),          /* CoreFoundation is not behind the vroot */
        @"TMPDIR": @"/tmp",
        @"PATH": @"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    };
    for(NSString *key in defaults)
    {
        if(environment[key] == nil)
        {
            environment[key] = defaults[key];
        }
    }
    items[@"PEEnvironment"] = environment;
    if(items[@"PEWorkingDirectory"] == nil)
    {
        items[@"PEWorkingDirectory"] = @(rks.jbroot);     /* "/" */
    }

    PEMachPort *syscallPort = [PEMachPort portWithPortName:rks.port];
    syscallPort.sendOnce = YES;
    items[@"PESyscallPort"] = syscallPort;
    items[@"PEEndpoint"] = [[RKSServer shared] ticket];
    items[@"PEFilePermissions"] = rks_file_permissions();

    NSError *failure = nil;
    id<RKSExtension> extension = [(id<RKSExtension>)extensionClass extensionWithIdentifier:identifier error:&failure];
    if(extension == nil || failure != nil)
    {
        rks_logf("no LiveProcess extension: %s", failure.localizedDescription.UTF8String ?: "?");
        *error = ENOEXEC;
        return -1;
    }
    if([extension respondsToSelector:@selector(setPreferredLanguages:)])
    {
        [extension setPreferredLanguages:@[]];
    }

    NSExtensionItem *item = [NSExtensionItem new];
    item.userInfo = items;
    NSUUID *request = [extension beginExtensionRequestWithInputItems:@[item] error:&failure];
    if(request == nil || failure != nil)
    {
        rks_logf("LiveProcess request failed: %s", failure.localizedDescription.UTF8String ?: "?");
        [extension _kill:SIGKILL];
        *error = EAGAIN;
        return -1;
    }
    pid_t pid = [extension pidForRequestIdentifier:request];
    if(pid <= 0)
    {
        [extension _kill:SIGKILL];
        *error = EAGAIN;
        return -1;
    }

    bool setsid = (flags & POSIX_SPAWN_SETSID) != 0;
    rks_proc_t *child = rks_proc_register(pid, parent->pid, setsid, setsid ? -1 : pgroup);
    if(child == NULL)
    {
        [extension _kill:SIGKILL];
        *error = ENOMEM;
        return -1;
    }
    /* as early as possible: EVFILT_PROC does not replay an exit that happened before registration */
    rks_proc_exit_watch(pid);
    pthread_mutex_lock(&rks_proc_lock);
    child->extension = (void *)CFBridgingRetain(extension);
    pthread_mutex_unlock(&rks_proc_lock);

    if(setsid)
    {
        rks_tty_t *tty = rks_controlling_tty_of(items[@"PEFileTable"]);
        if(tty != NULL)
        {
            rks_tty_attach(tty, child);
            rks_tty_release(tty);
        }
    }

    rks_proc_release(child);
    return pid;
}

/* ----------------------------------------------------------------------
 *  public API
 * -------------------------------------------------------------------- */

int rks_spawn_server_start(void)
{
    return rks_liveprocess_identifier() != nil ? 0 : ENOEXEC;
}

RKS_EXPORT int rks_boot(const rks_boot_args_t *args)
{
    if(args == NULL || args->version != RKS_ABI_VERSION || args->size < sizeof(rks_boot_args_t) ||
       args->root == NULL || args->bundle == NULL)
    {
        return EINVAL;
    }

    static int result = -1;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        strlcpy(rks.root, args->root, sizeof(rks.root));
        snprintf(rks.jbroot, sizeof(rks.jbroot), "%s/%s", args->root, RKS_LAYOUT_JBROOT);
        strlcpy(rks.bundle, args->bundle, sizeof(rks.bundle));
        rks.sign = args->sign;
        rks.log = args->log;
        rks.kernel_pid = getpid();

        rks_proc_init();
        result = rks_syscall_server_start();
        if(result == 0)
        {
            result = rks_spawn_server_start();
        }
        if(result == 0)
        {
            rks_proc_monitor_start();
        }
    });
    return result;
}

RKS_EXPORT int rks_spawn_terminal(const char *path, char *const argv[], char *const envp[], const char *cwd,
                                  unsigned short rows, unsigned short cols, int *master_fd, pid_t *pid)
{
    if(path == NULL || master_fd == NULL || pid == NULL || rks.port == MACH_PORT_NULL)
    {
        return EINVAL;
    }
    *master_fd = -1;
    *pid = -1;

    @autoreleasepool
    {
        /* sign the shell up front, a first launch should not depend on the guest's on-demand path */
        if(rks.sign != NULL)
        {
            rks.sign(path);
        }

        int master = -1, slave = -1;
        rks_tty_t *tty = rks_tty_create(&master, &slave);
        if(tty == NULL)
        {
            return ENOMEM;
        }
        rks_tty_set_size(tty, rows ? rows : 24, cols ? cols : 80);

        PEFileTable *table = [PEFileTable emptyTable];
        for(int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++)
        {
            [table appendFileDescriptor:slave withMappingToLoc:fd];
        }

        NSMutableArray *arguments = [NSMutableArray array];
        for(size_t i = 0; argv != NULL && argv[i] != NULL; i++)
        {
            [arguments addObject:@(argv[i])];
        }
        if(arguments.count == 0)
        {
            [arguments addObject:@(path)];
        }
        NSMutableDictionary *environment = [NSMutableDictionary dictionary];
        for(size_t i = 0; envp != NULL && envp[i] != NULL; i++)
        {
            const char *eq = strchr(envp[i], '=');
            if(eq != NULL)
            {
                NSString *key = [[NSString alloc] initWithBytes:envp[i] length:(NSUInteger)(eq - envp[i]) encoding:NSUTF8StringEncoding];
                NSString *value = @(eq + 1);
                if(key != nil && value != nil)
                {
                    environment[key] = value;
                }
            }
        }

        NSDictionary *launch = @{
            @"PEExecutablePath": @(path),
            @"PEArguments": arguments,
            @"PEEnvironment": environment,
            @"PEWorkingDirectory": cwd ? @(cwd) : @(rks.jbroot),
            @"PEFileTable": table,
        };

        rks_proc_t *kernel = rks_proc_lookup(rks.kernel_pid);
        int error = 0;
        pid_t child = kernel ? rks_spawn_items(kernel, launch, POSIX_SPAWN_SETSID, -1, &error) : -1;
        if(kernel != NULL)
        {
            rks_proc_release(kernel);
        }
        close(slave);
        rks_tty_release(tty);   /* the pump keeps it while the master is open */

        if(child <= 0)
        {
            close(master);
            return error ? error : EAGAIN;
        }
        *master_fd = master;
        *pid = child;
    }
    return 0;
}

RKS_EXPORT int rks_tty_set_winsize(int master_fd, unsigned short rows, unsigned short cols)
{
    rks_tty_t *tty = rks_tty_for_fd(master_fd);
    if(tty == NULL)
    {
        return ENOTTY;
    }
    rks_tty_set_size(tty, rows, cols);
    rks_tty_release(tty);
    return 0;
}

RKS_EXPORT int rks_signal(pid_t pid, int sig)
{
    rks_proc_t *proc = rks_proc_lookup(pid);
    if(proc == NULL)
    {
        return ESRCH;
    }
    int err = rks_proc_signal(proc, sig);
    rks_proc_release(proc);
    return err;
}

RKS_EXPORT void rks_set_exit_handler(rks_exit_handler_t handler, void *context)
{
    rks.exit_context = context;
    rks.exit_handler = handler;
}

/* ----------------------------------------------------------------------
 *  SYS_spawn (KSurface/emexOS ksurface_spawn_request_t, v1 and v2)
 * -------------------------------------------------------------------- */

typedef struct {
    uint32_t version;
    uint32_t argc;
    uint32_t envc;
    uint32_t fd_count;
    int32_t  flags;
    int32_t  pgroup;
} rks_spawn_request_t;

typedef struct {
    rks_spawn_request_t base;
    uint32_t attributes;
    uint32_t persona_uid;
    uint32_t persona_gid;
    uint32_t reserved;
} rks_spawn_request_v2_t;

#define RKS_SPAWN_REQUEST_MAX       (1024 * 1024)
#define RKS_SPAWN_BOOTSTRAP         (1u << 0)

/* NUL terminated strings packed back to back: reads one, advances, NULL when the buffer ends early */
static NSString *rks_spawn_next_string(const char **cursor, const char *end)
{
    const char *start = *cursor;
    const char *nul = start < end ? memchr(start, '\0', (size_t)(end - start)) : NULL;
    if(nul == NULL)
    {
        return nil;
    }
    *cursor = nul + 1;
    return [[NSString alloc] initWithBytes:start length:(NSUInteger)(nul - start) encoding:NSUTF8StringEncoding] ?: @"";
}

/*
 * args[0] executable path, args[1] request, args[2] its size; one fileport per
 * fd target (in order), then the bootstrap override when v2 says so. The
 * recovery has no launchd namespaces: a bootstrap override is accepted and
 * dropped, persona ids are ignored (everything runs as root).
 */
int64_t rks_sys_spawn(rks_call_t *call)
{
    uint64_t path_address = (uint64_t)call->args[0];
    uint64_t request_address = (uint64_t)call->args[1];
    uint64_t size = (uint64_t)call->args[2];
    if(path_address == 0 || request_address == 0 || size < sizeof(rks_spawn_request_t) || size > RKS_SPAWN_REQUEST_MAX)
    {
        RKS_FAIL(call, EINVAL);
    }

    char *path = rks_copy_str_in(call->task, path_address, PATH_MAX);
    if(path == NULL)
    {
        RKS_FAIL(call, EFAULT);
    }
    char *request = malloc((size_t)size);
    if(request == NULL || !rks_copy_in(call->task, request, request_address, (size_t)size))
    {
        free(path);
        free(request);
        RKS_FAIL(call, request == NULL ? ENOMEM : EFAULT);
    }

    int error = 0;
    pid_t pid = -1;
    @autoreleasepool
    {
        rks_spawn_request_t header;
        memcpy(&header, request, sizeof(header));
        size_t header_size = sizeof(rks_spawn_request_t);
        uint32_t attributes = 0;
        if(header.version == 2 && size >= sizeof(rks_spawn_request_v2_t))
        {
            rks_spawn_request_v2_t v2;
            memcpy(&v2, request, sizeof(v2));
            attributes = v2.attributes;
            header_size = sizeof(rks_spawn_request_v2_t);
        }
        else if(header.version != 1)
        {
            error = EPROTONOSUPPORT;
        }

        uint64_t targets_size = (uint64_t)header.fd_count * sizeof(int32_t);
        if(error == 0 && (header.fd_count > 64 || header_size + targets_size > size))
        {
            error = EINVAL;
        }
        /* fileports first, the bootstrap override (if any) is the last port */
        uint32_t ports_needed = header.fd_count;
        if(error == 0 && (call->in_count < ports_needed || call->in_ports == NULL) && ports_needed > 0)
        {
            error = EBADF;
        }

        PEFileTable *table = error == 0 ? [PEFileTable emptyTable] : nil;
        const int32_t *targets = (const int32_t *)(request + header_size);
        for(uint32_t i = 0; error == 0 && i < header.fd_count; i++)
        {
            if([table appendFilePort:call->in_ports[i] withMappingToLoc:targets[i]] != 0)
            {
                error = EBADF;
            }
        }

        const char *cursor = request + header_size + targets_size;
        const char *end = request + size;
        NSString *cwd = error == 0 ? rks_spawn_next_string(&cursor, end) : nil;
        NSMutableArray *arguments = [NSMutableArray array];
        NSMutableDictionary *environment = [NSMutableDictionary dictionary];
        if(error == 0 && cwd == nil)
        {
            error = EINVAL;
        }
        for(uint32_t i = 0; error == 0 && i < header.argc; i++)
        {
            NSString *argument = rks_spawn_next_string(&cursor, end);
            if(argument == nil) error = EINVAL;
            else [arguments addObject:argument];
        }
        for(uint32_t i = 0; error == 0 && i < header.envc; i++)
        {
            NSString *entry = rks_spawn_next_string(&cursor, end);
            if(entry == nil)
            {
                error = EINVAL;
                break;
            }
            NSRange eq = [entry rangeOfString:@"="];
            if(eq.location != NSNotFound)
            {
                environment[[entry substringToIndex:eq.location]] = [entry substringFromIndex:eq.location + 1];
            }
        }
        [environment removeObjectForKey:@"__PE_SPAWN_PERSONA"];
        (void)attributes;   /* RKS_SPAWN_BOOTSTRAP: accepted and dropped, see above */

        NSString *executable = @(path);
        if(error == 0 && executable == nil)
        {
            error = EINVAL;
        }
        if(error == 0)
        {
            NSDictionary *launch = @{
                @"PEExecutablePath": executable,
                @"PEArguments": arguments.count ? arguments : @[executable],
                @"PEEnvironment": environment,
                @"PEWorkingDirectory": cwd.length ? cwd : @(rks.jbroot),
                @"PEFileTable": table,
            };
            short flags = (short)header.flags;
            pid = rks_spawn_items(call->proc, launch, flags, (flags & POSIX_SPAWN_SETPGROUP) ? header.pgroup : -1, &error);
            if(pid <= 0 && error == 0)
            {
                error = EAGAIN;
            }
        }
    }
    free(path);
    free(request);
    if(error != 0)
    {
        RKS_FAIL(call, error);
    }
    return pid;
}

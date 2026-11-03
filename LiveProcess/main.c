/* SPDX-License-Identifier: LicenseRef-EPSL-1.1
 * Copyright (C) 2026 emexLabs. See Nyxian's LICENSES for the source license.
 */
#include "NXLiveProcessABI.h"
#include "NXCoWCache.h"
#include "NXLiveProcessBootstrap.h"
#include "NXLiveProcessBroker.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern xpc_object_t xpc_copy_bootstrap(void);
extern void launch_extension_check_in_live_4UIKit(void);
extern int64_t sandbox_extension_consume(const char *token);
extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);
extern xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, xpc_object_t *reply);

static xpc_object_t g_bootstrap;
__attribute__((used, visibility("default"))) xpc_object_t NXLiveProcessCopyBootstrapV1(void)
{
    return g_bootstrap ? xpc_retain(g_bootstrap) : NULL;
}

static int pullBootstrap(xpc_object_t *out)
{
    *out = NULL;
    char names[NX_LIVEPROCESS_BROKER_MAX_GROUPS][NX_LIVEPROCESS_BROKER_NAME_MAX];
    unsigned count = NXLiveProcessBrokerServiceNames(names, NX_LIVEPROCESS_BROKER_MAX_GROUPS);
    for(unsigned i = 0; i < count; i++)
    {
        mach_port_t port = MACH_PORT_NULL;
        if(bootstrap_look_up(bootstrap_port, names[i], &port) != KERN_SUCCESS || !MACH_PORT_VALID(port))
        {
            continue;
        }
        xpc_object_t pipe = xpc_pipe_create_from_port(port, 0);
        if(!pipe)
        {
            continue;
        }
        xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_uint64(request, NX_LIVEPROCESS_BROKER_REQUEST_KEY, NX_LIVEPROCESS_BROKER_VERSION);
        xpc_object_t reply = NULL;
        int routine = xpc_pipe_routine(pipe, request, &reply);
        xpc_release(request);
        xpc_release(pipe);
        if(routine || !reply || xpc_get_type(reply) != XPC_TYPE_DICTIONARY)
        {
            if(reply) xpc_release(reply);
            continue;   /* stale registration, try the next group */
        }
        int error = (int)xpc_dictionary_get_int64(reply, NX_LIVEPROCESS_BROKER_ERROR_KEY);
        xpc_object_t payload = error ? NULL : xpc_dictionary_get_value(reply, NX_LIVEPROCESS_BOOTSTRAP_KEY);
        if(!error && (!payload || xpc_get_type(payload) != XPC_TYPE_DICTIONARY))
        {
            error = EPROTO;
        }
        if(!error)
        {
            xpc_object_t bootstrap = xpc_dictionary_create(NULL, NULL, 0);
            xpc_dictionary_set_value(bootstrap, NX_LIVEPROCESS_BOOTSTRAP_KEY, payload);
            *out = bootstrap;
        }
        xpc_release(reply);
        return error;   /* a reachable broker has the final say */
    }
    return ENOENT;
}

static int requireSingleThread(void)
{
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t result = task_threads(mach_task_self(), &threads, &count);
    if(result)
    {
        return EIO;
    }
    int error = count == 1 ? 0 : EBUSY;
    for(mach_msg_type_number_t i = 0; i < count; ++i)
    {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    return error;
}

/* for the legacy LiveProcess ABI */
static int runLegacy(int argc,
                     char **argv)
{
    void *foundation = dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", RTLD_NOW | RTLD_GLOBAL);
    int(*systemMain)(int, char **) = foundation ? (int (*)(int, char **))dlsym(foundation, "NSExtensionMain") : NULL;
    if(!systemMain)
    {
        return ENOEXEC;
    }
    
    char executable[PATH_MAX];
    uint32_t capacity = sizeof(executable);
    if(_NSGetExecutablePath(executable, &capacity))
    {
        return ENAMETOOLONG;
    }
    
    char *leaf = strrchr(executable, '/');
    if(!leaf)
    {
        return EINVAL;
    }
    *leaf = 0;
    char library[PATH_MAX];
    int length = snprintf(library, sizeof(library), "%s/Frameworks/LiveProcessLegacy.framework/LiveProcessLegacy", executable);
    if(length < 0 || (size_t)length >= sizeof(library))
    {
        return ENAMETOOLONG;
    }
    
    void *legacy = dlopen(library, RTLD_NOW | RTLD_GLOBAL);
    int (*main)(int, char **, int (*)(int, char **)) = legacy ? dlsym(legacy, "NXLegacyExtensionMain") : NULL;
    if(!main)
    {
        return ENOEXEC;
    }
    
    return main(argc, argv, systemMain);
}

int NSExtensionMain(int argc,
                    char **argv,
                    char **envp,
                    char **apple)
{
    NXLiveProcessLaunchV1 launch;
    xpc_object_t bootstrap = xpc_copy_bootstrap();
    if(!bootstrap || xpc_get_type(bootstrap) != XPC_TYPE_DICTIONARY || !xpc_dictionary_get_value(bootstrap, NX_LIVEPROCESS_BOOTSTRAP_KEY))
    {
        if(bootstrap) xpc_release(bootstrap);
        bootstrap = NULL;
        int pulled = pullBootstrap(&bootstrap);
        if(pulled == ECANCELED)
        {
            _exit(1);   /* the host abandoned this launch and took the legacy path */
        }
    }
    g_bootstrap = bootstrap;   /* kept for NXLiveProcessCopyBootstrapV1 */
    
    int path = NXLiveProcessReadBootstrapV1(bootstrap, &launch);
    if(!path)
    {
        path = NXLiveProcessSelectPathV1(getenv(NX_LIVEPROCESS_MODE_ENV), getenv(NX_LIVEPROCESS_ABI_ENV));
    }
    if(!path)
    {
        return runLegacy(argc, argv);
    }
    if(path < 0)
    {
        return 1;
    }
    
    launch_extension_check_in_live_4UIKit();
    int error = requireSingleThread();
    const char *token = launch.version ? launch.readOnlySandboxToken : getenv(NX_LIVEPROCESS_TOKEN_ENV);
    const char *module = launch.version ? launch.modulePath : getenv(NX_LIVEPROCESS_MODULE_ENV);
    const char *hash = launch.version ? launch.moduleSHA256 : getenv(NX_LIVEPROCESS_HASH_ENV);
    if(!error && (!token || !token[0] || !module || !hash))
    {
        error = EINVAL;
    }
    if(!error && sandbox_extension_consume(token) < 0)
    {
        error = EACCES;
    }
    if(!error)
    {
        error = requireSingleThread();
    }
    
    char cachedModule[PATH_MAX] = {0};
    if(!error)
    {
        error = NXCoWCacheInDocuments(module, getenv("HOME"), cachedModule, sizeof(cachedModule));
    }
    if(!error)
    {
        error = requireSingleThread();
    }
    
    NXLiveProcessStartV1 start = {1, sizeof(start), argc, 0, (const char *const *)argv, (const char *const *)envp, (const char *const *)apple, cachedModule};
    int status = 1;
    if(!error)
    {
        error = NXLiveProcessRunLibSystemV1(cachedModule, hash, &start, &status);
    }
    _exit(error ? 1 : status);
}

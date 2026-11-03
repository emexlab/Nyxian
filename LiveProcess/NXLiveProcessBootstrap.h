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

#ifndef NXLIVEPROCESSBOOTSTRAP_H
#define NXLIVEPROCESSBOOTSTRAP_H

#include "NXLiveProcessABI.h"
#include <xpc/xpc.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define NX_LIVEPROCESS_BOOTSTRAP_VERSION 1u
#define NX_LIVEPROCESS_BOOTSTRAP_KEY "Nyxian-LiveProcess-bootstrap-v1"

static inline int NXLiveProcessBootstrapString(xpc_object_t payload,
                                               const char *key,
                                               char *output,
                                               size_t capacity)
{
    xpc_object_t value = xpc_dictionary_get_value(payload, key);
    if(!value || xpc_get_type(value) != XPC_TYPE_STRING)
    {
        return EPROTO;
    }
    
    const char *string = xpc_string_get_string_ptr(value);
    size_t size = xpc_string_get_length(value);
    if(!string || !size || size >= capacity || strlen(string) != size)
    {
        return EPROTO;
    }
    
    memcpy(output, string, size + 1);
    return 0;
}

static inline int NXLiveProcessReadBootstrapV1(xpc_object_t bootstrap,
                                               NXLiveProcessLaunchV1 *launch)
{
    if(!launch)
    {
        return -EINVAL;
    }
    bzero(launch, sizeof(*launch));
    
    if(!bootstrap || xpc_get_type(bootstrap) != XPC_TYPE_DICTIONARY)
    {
        return 0;
    }
    xpc_object_t payload = xpc_dictionary_get_value(bootstrap, NX_LIVEPROCESS_BOOTSTRAP_KEY);
    if(!payload)
    {
        return 0;
    }
    
    if(xpc_get_type(payload) != XPC_TYPE_DICTIONARY)
    {
        return -EPROTO;
    }
    xpc_object_t version = xpc_dictionary_get_value(payload, "version");
    if(!version || xpc_get_type(version) != XPC_TYPE_UINT64 || xpc_uint64_get_value(version) != NX_LIVEPROCESS_BOOTSTRAP_VERSION)
    {
        return -EPROTONOSUPPORT;
    }
    
    char mode[32];
    int error = NXLiveProcessBootstrapString(payload, "mode", mode, sizeof(mode));
    if(!error && strcmp(mode, NX_LIVEPROCESS_LIBSYSTEM_MODE))
    {
        error = EPROTONOSUPPORT;
    }
    
    if(!error)
    {
        error = NXLiveProcessBootstrapString(payload, "module-path", launch->modulePath, sizeof(launch->modulePath));
    }
    if(!error)
    {
        error = NXLiveProcessBootstrapString(payload, "module-sha256", launch->moduleSHA256, sizeof(launch->moduleSHA256));
    }
    if(!error)
    {
        error = NXLiveProcessBootstrapString(payload, "read-token", launch->readOnlySandboxToken, sizeof(launch->readOnlySandboxToken));
    }
    if(!error)
    {
        error = NXLiveProcessBootstrapString(payload, "extension-identifier", launch->extensionIdentifier, sizeof(launch->extensionIdentifier));
    }
    if(!error && (launch->modulePath[0] != '/' || strlen(launch->moduleSHA256) != 64))
    {
        error = EINVAL;
    }
    if(!error) for (unsigned i = 0; i < 64; ++i)
    {
        char c = launch->moduleSHA256[i];
        if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        {
            error = EINVAL;
            break;
        }
    }
    if(error)
    {
        memset(launch, 0, sizeof(*launch)); return -error;
    }
    
    launch->version = NX_LIVEPROCESS_ABI_VERSION;
    launch->size = sizeof(*launch);
    return 1;
}

#endif /* NXLIVEPROCESSBOOTSTRAP_H */

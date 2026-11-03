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

#ifndef NXLIVEPROCESSBROKER_H
#define NXLIVEPROCESSBROKER_H

#include <xpc/xpc.h>
#include <stdio.h>
#include <string.h>

#define NX_LIVEPROCESS_BROKER_VERSION     1u
#define NX_LIVEPROCESS_BROKER_SUFFIX      ".liveprocess.broker"
#define NX_LIVEPROCESS_BROKER_GROUP_HINT  "org.emexlabs.nyxian.shared"
#define NX_LIVEPROCESS_BROKER_REQUEST_KEY "nx-liveprocess-checkin"
#define NX_LIVEPROCESS_BROKER_ERROR_KEY   "error"
#define NX_LIVEPROCESS_BROKER_MAX_GROUPS  4u
#define NX_LIVEPROCESS_BROKER_NAME_MAX    128u   /* name_t */

extern XPC_RETURNS_RETAINED xpc_object_t xpc_copy_entitlement_for_self(const char *entitlement);

static inline unsigned NXLiveProcessBrokerServiceNames(char names[][NX_LIVEPROCESS_BROKER_NAME_MAX], unsigned capacity)
{
    xpc_object_t groups = xpc_copy_entitlement_for_self("com.apple.security.application-groups");
    if(!groups)
    {
        return 0;
    }
    unsigned count = 0;
    if(xpc_get_type(groups) == XPC_TYPE_ARRAY)
    {
        size_t total = xpc_array_get_count(groups);
        for(int pass = 0; pass < 2; pass++)
        {
            for(size_t i = 0; i < total && count < capacity; i++)
            {
                const char *group = xpc_array_get_string(groups, i);
                if(!group || !group[0])
                {
                    continue;
                }
                int hinted = strstr(group, NX_LIVEPROCESS_BROKER_GROUP_HINT) != NULL;
                if(hinted != (pass == 0))
                {
                    continue;
                }
                int length = snprintf(names[count], NX_LIVEPROCESS_BROKER_NAME_MAX, "%s%s", group, NX_LIVEPROCESS_BROKER_SUFFIX);
                if(length > 0 && (unsigned)length < NX_LIVEPROCESS_BROKER_NAME_MAX)
                {
                    count++;
                }
            }
        }
    }
#if !__has_feature(objc_arc)
    xpc_release(groups);
#endif
    return count;
}

#endif /* NXLIVEPROCESSBROKER_H */

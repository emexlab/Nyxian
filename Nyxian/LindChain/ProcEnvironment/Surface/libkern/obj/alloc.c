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

#import <LindChain/ProcEnvironment/Surface/libkern/obj/alloc.h>
#import <LindChain/ProcEnvironment/Surface/libkern/obj/reference.h>
#import <LindChain/ProcEnvironment/Surface/libkern/obj/lock.h>
#import <LindChain/ProcEnvironment/Surface/libkern/obj/event.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static inline bool __kvobject_init(kvobject_main_event_handler_t handler,
                                   kvobject_base_type_t base_type,
                                   kvobject_t *kvo)
{
    /* setting up kvobject for usage */
    kvo->refcount = 1;                          /* starting as retained for the caller, cuz the caller gets one reference */
    kvo->base_type = base_type;
    kvo->state = kvObjStateNormal;
    kvo->main_handler = handler;
    
    /* only normal objects get those locks */
    if(base_type != kvObjBaseTypeObjectSnapshot)
    {
        /* safely initializing both locks */
        if(pthread_rwlock_init(&(kvo->rwlock), NULL) != 0)
        {
            return false;
        }
        
        if(pthread_rwlock_init(&(kvo->event_rwlock), NULL) != 0)
        {
            pthread_rwlock_destroy(&(kvo->rwlock));
            return false;
        }
    }
    
    return true;
}

static inline kvobject_t *__kvobject_alloc(kvobject_main_event_handler_t handler,
                                           kvobject_base_type_t base_type)
{
    /* get object size first */
    size_t size = (size_t)handler(NULL, kvObjEventInit, 0);
    
    /*
     * first we gotta check if the size
     * is atleast the size of an kvobject
     */
    assert(size >= sizeof(kvobject_t));
    
    /* allocating brand new kvobject */
    kvobject_t *kvo = calloc(1, size);
    if(kvo == NULL)
    {
        return NULL;
    }
    
    if(!__kvobject_init(handler, base_type, kvo))
    {
        free(kvo);
        return NULL;
    }
    
    /* allocated by my runtime ^^ */
    kvo->memoryIsOwned = true;
    
    return kvo;
}

kvobject_t *kvobject_alloc(kvobject_main_event_handler_t handler)
{
    assert(handler != NULL);
    
    kvobject_t *kvo = __kvobject_alloc(handler, kvObjBaseTypeObject);
    if(kvo == NULL)
    {
        return NULL;
    }
    
    /* checking init handler and executing if nonnull */
    if(kvo->main_handler(&kvo, kvObjEventInit, 0) != 0)
    {
        pthread_rwlock_destroy(&(kvo->rwlock));
        pthread_rwlock_destroy(&(kvo->event_rwlock));
        free(kvo);
        return NULL;
    }
    
    /* returning da object */
    return kvo;
}

kvobject_t *kvobject_copy(kvobject_t *kvo)
{
    assert(kvo != NULL);
    
    kvo_rdlock(kvo);
    
    assert(kvo->base_type == kvObjBaseTypeObject && kvo->main_handler != NULL);
    
    kvobject_t *kvo_dup = __kvobject_alloc(kvo->main_handler, kvObjBaseTypeObject);
    if(kvo_dup == NULL)
    {
        return NULL;
    }
    
    /* checking init handler and executing if nonnull */
    kvobject_t *kvoarr[2] = { kvo_dup, kvo };
    if(kvo_dup->main_handler(kvoarr, kvObjEventCopy, 0) != 0)
    {
        pthread_rwlock_destroy(&(kvo_dup->rwlock));
        pthread_rwlock_destroy(&(kvo_dup->event_rwlock));
        free(kvo_dup);
        kvo_dup = NULL;
    }
    
out_unlock:
    kvo_unlock(kvo);
    return kvo_dup;
}

kvobject_snapshot_t *kvobject_snapshot(kvobject_t *kvo,
                                       kvobject_snapshot_options_t option)
{
    assert(kvo != NULL);
    
    kvobject_t *kvo_snap = NULL;
    if(!kvo_retain(kvo))
    {
        goto out_unlock;
    }
    
    kvo_rdlock(kvo);
    
    assert(kvo->base_type == kvObjBaseTypeObject && kvo->main_handler != NULL);
    
    kvo_snap = __kvobject_alloc(kvo->main_handler, kvObjBaseTypeObjectSnapshot);
    if(kvo_snap == NULL)
    {
        goto out_unlock;
    }
    
    /* set orig pointer if applicable */
    if(option == kvObjSnapReferenced ||
       option == kvObjSnapConsumeReference)
    {
        kvo_snap->orig = kvo;
    }
    
    /* preparing stack array */
    kvobject_t *kvoarr[2] = { kvo_snap, kvo };
    if(kvo_snap->main_handler(kvoarr, kvObjEventSnapshot, 0) != 0)
    {
        free(kvo_snap);
        kvo_snap = NULL;
    }
    
out_unlock:
    kvo_unlock(kvo);
    
    /* release object if applicable */
    if(option == kvObjSnapStatic ||
       option == kvObjSnapConsumeReference)
    {
        kvo_release(kvo);
    }
    
    return kvo_snap;
}

size_t kvobject_size(kvobject_main_event_handler_t handler)
{
    return (size_t)handler(NULL, kvObjEventInit, 0);
}

bool kvobject_snapshot_into_mem(void *mem,
                                kvobject_t *kvo,
                                kvobject_snapshot_options_t option)
{
    assert(kvo != NULL);
    
    bool did_succeed = false;
    if(!kvo_retain(kvo))
    {
        goto out_release;
    }
    
    kvo_rdlock(kvo);
    
    assert(kvo->base_type == kvObjBaseTypeObject && kvo->main_handler != NULL);
    
    /* zero out buffer (like calloc) */
    bzero(mem, (size_t)kvo->main_handler(NULL, kvObjEventInit, 0));
    if(!__kvobject_init(kvo->main_handler, kvObjBaseTypeObjectSnapshot, (kvobject_t*)mem))
    {
        /* didnt initialize :c */
        goto out_unlock;
    }
    
    /* set orig pointer if applicable */
    if(option == kvObjSnapReferenced ||
       option == kvObjSnapConsumeReference)
    {
        ((kvobject_t*)mem)->orig = kvo;
    }
    
    /* preparing stack array */
    kvobject_t *kvoarr[2] = { (kvobject_t*)mem, kvo };
    did_succeed = ((kvobject_t*)mem)->main_handler(kvoarr, kvObjEventSnapshot, 0) == 0;
    
out_unlock:
    kvo_unlock(kvo);
out_release:
    /* release object if applicable */
    if(option == kvObjSnapStatic ||
       option == kvObjSnapConsumeReference)
    {
        kvo_release(kvo);
    }
    
    return did_succeed;
}

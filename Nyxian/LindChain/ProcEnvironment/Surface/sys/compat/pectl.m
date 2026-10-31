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
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <LindChain/ProcEnvironment/Surface/libkern/kxld/kxopen.h>
#import <LindChain/ProcEnvironment/Surface/sys/compat/pectl.h>
#import <LindChain/ProcEnvironment/PEProcessManager.h>
#import <LindChain/ProcEnvironment/PEBootstrapRegistry.h>
#import <LindChain/ProcEnvironment/PELaunchServiceManager.h>
#import <LindChain/ProcEnvironment/PEUserspaceManager.h>
#import <LindChain/WindowServer/NXWindowServer.h>
#import <LindChain/WindowServer/Session/NXWindowSessionApplication.h>
#import <LindChain/ProcEnvironment/LiveContainer/LCUtils.h>
#import <LindChain/ProcEnvironment/Utils/vnode.h>
#import <ksurface_config.h>
#import <ksurface_abi.h>

DEFINE_SYSCALL_HANDLER(pectl_launchservice)
{
    PECTLLaunchService action = (PECTLLaunchService)args[1];
    switch(action)
    {
        case kPECTLLaunchServiceGetEndpoint:
        {
            userspace_pointer_t userspace_str = (userspace_pointer_t)args[2];
            char *service_name = syscall_copy_str_in(sys_task_, userspace_str, MAXHOSTNAMELEN);
            if(service_name == NULL)
            {
                sys_return_failure_with_errno(ENOMEM);
            }
            
            NSString *service_nsname = [NSString stringWithCString:service_name encoding:NSUTF8StringEncoding];
            free(service_name);
            if(service_nsname == nil)
            {
                sys_return_failure_with_errno(ENOMEM);
            }
            
            if(!entitlement_got_entitlement(proc_getentitlements(sys_proc_snapshot_), kPEEntitlementFlagLaunchServicesGetEndpoint))
            {
                kvo_rdlock(sys_proc_);
                CFArrayRef allowList = CFDictionaryGetValue(sys_proc_->nyx.identity->entitlements, kNXT2EntitlementLaunchServicesGetEndpointAllowList);
                if(allowList != nil)
                {
                    CFIndex allowListCount = CFArrayGetCount(allowList);
                    for(CFIndex index = 0; index < allowListCount; index++)
                    {
                        NSString *allowedServiceIdentifier = (__bridge NSString*)CFArrayGetValueAtIndex(allowList, index);
                        if([service_nsname isEqualToString:allowedServiceIdentifier])
                        {
                            kvo_unlock(sys_proc_);
                            goto allow_get_fastpath;
                        }
                    }
                }
                kvo_unlock(sys_proc_);
                sys_return_failure_with_errno(EPERM);
            }
            
        allow_get_fastpath:
            {
                mach_port_t port = [[PEBootstrapRegistry shared] getMachPortNameWithServiceIdentifier:service_nsname];
                if(port == MACH_PORT_NULL)
                {
                    sys_return_failure_with_errno(EACCES);
                }
                
                kern_return_t kr = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, 1);
                if(kr != KERN_SUCCESS)
                {
                    sys_return_failure_with_errno(EACCES);
                }
                
                kr = syscall_payload_create(NULL, sizeof(mach_port_t), (mach_vm_address_t*)out_ports);
                if(kr != KERN_SUCCESS)
                {
                    mach_port_deallocate(mach_task_self(), port);
                    sys_return_failure_with_errno(ENOMEM);
                }
                
                (*out_ports)[0] = port;
                *out_ports_cnt = 1;
                
                sys_return;
            }
        }
        case kPECTLLaunchServiceSetEndpoint:
        {
            sys_need_in_ports(1, MACH_MSG_TYPE_MOVE_SEND);
            
            userspace_pointer_t userspace_str = (userspace_pointer_t)args[2];
            char *service_name = syscall_copy_str_in(sys_task_, userspace_str, MAXHOSTNAMELEN);
            if(service_name == NULL)
            {
                sys_return_failure_with_errno(ENOMEM);
            }
            
            NSString *service_nsname = [NSString stringWithCString:service_name encoding:NSUTF8StringEncoding];
            free(service_name);
            if(service_nsname == nil)
            {
                sys_return_failure_with_errno(ENOMEM);
            }
            
            if(!entitlement_got_entitlement(proc_getentitlements(sys_proc_snapshot_), kPEEntitlementFlagLaunchServicesSetEndpoint))
            {
                kvo_rdlock(sys_proc_);
                CFArrayRef allowList = CFDictionaryGetValue(sys_proc_->nyx.identity->entitlements, kNXT2EntitlementLaunchServicesSetEndpointAllowList);
                if(allowList != nil)
                {
                    CFIndex allowListCount = CFArrayGetCount(allowList);
                    for(CFIndex index = 0; index < allowListCount; index++)
                    {
                        NSString *allowedServiceIdentifier = (__bridge NSString*)CFArrayGetValueAtIndex(allowList, index);
                        if([service_nsname isEqualToString:allowedServiceIdentifier])
                        {
                            kvo_unlock(sys_proc_);
                            goto allow_set_fastpath;
                        }
                    }
                }
                kvo_unlock(sys_proc_);
                sys_return_failure_with_errno(EPERM);
            }
            
        allow_set_fastpath:
            {
                /*
                 * getting existing launch service, because we
                 * have ti make sure that its not a attacker
                 * attempting to overwrite a launchservice
                 * endpoint to control it, as Nyxian it self
                 * requires such launch service to be able to
                 * read data from the other container, which
                 * is the reason for this extra layer of trust.
                 */
                PELaunchService *service = [[PELaunchServiceManager shared] serviceForIdentifier:service_nsname];
                if(service != nil)
                {
                    BOOL isIncluded = NO;
                    
                    NSArray<PELaunchServiceInstance*> *instaces = [service.instances copy];
                    for(PELaunchServiceInstance *instance in instaces)
                    {
                        /*
                         * in-case there is no process it is
                         * reserved for the service and cannot
                         * be overriden by a attacker.
                         */
                        if(instance.process == nil)
                        {
                            /* slot is reserved */
                            continue;
                        }
                        
                        /*
                         * making sure that the right process
                         * registers the endpoint for the
                         * service domain.
                         */
                        if(instance.process.pid != proc_getpid(sys_proc_snapshot_))
                        {
                            /* slot is reserved */
                            continue;
                        }
                        
                        isIncluded = true;
                    }
                    
                    if(!isIncluded)
                    {
                        sys_return_failure_with_errno(EACCES);
                    }
                }
                
                [[PEBootstrapRegistry shared] setMachPortName:sys_in_ports[0] forServiceIdentifier:service_nsname];
                sys_in_ports[0] = MACH_PORT_NULL;   /* prevent mach port reference leak */
                
                sys_return;
            }
        }
        default:
            sys_return_failure_with_errno(ENOSYS);
    }
}

/* sub categories */
DEFINE_SYSCALL_HANDLER(pectl_codesigning)
{
    PECTLCodeSigning action = (PECTLCodeSigning)args[1];
    switch(action)
    {
        case kPECTLCodeSigningGetPublicKey:
        {
            userspace_pointer_t key_user_ptr = (userspace_pointer_t)args[2];
            userspace_pointer_t key_len_ptr = (userspace_pointer_t)args[3];
            
            size_t key_len = 0;
            if(!syscall_copy_in(sys_task_, sizeof(size_t), &key_len, key_len_ptr))
            {
                sys_return_failure_with_errno(EFAULT);
            }
            
            if(key_len < ksurface->pub_key_len)
            {
                sys_return_failure_with_errno(E2BIG);
            }
            
            if(!syscall_copy_out(sys_task_, ksurface->pub_key_len, ksurface->pub_key, key_user_ptr) ||
               !syscall_copy_out(sys_task_, sizeof(size_t), &key_len, key_len_ptr))
            {
                sys_return_failure_with_errno(EFAULT);
            }
            
            sys_return;
        }
        case kPECTLCodeSigningGetPrivateKey:
            /* too much of a security concern */
            sys_return_failure_with_errno(ENOSYS);
        case kPECTLCodeSigningSignPath:
            /* deprecated with SYS_sign */
            sys_return_failure_with_errno(ENOSYS);
        case kPECTLCodeSigningGetCDHash:
        {
            kvo_rdlock(sys_proc_);
            if(sys_proc_->nyx.identity->trustLevel != kPETrustLevelSignature)   /* signature type needs cdhash verification */
            {
                kvo_unlock(sys_proc_);
                sys_return_failure_with_errno(ENOENT);
            }
            
            userspace_pointer_t ch_user_ptr = (userspace_pointer_t)args[2];
            if(!syscall_copy_out(sys_task_, sizeof(sys_proc_->nyx.identity->cdhash), sys_proc_->nyx.identity->cdhash, ch_user_ptr))
            {
                kvo_unlock(sys_proc_);
                sys_return_failure_with_errno(EFAULT);
            }
            
            kvo_unlock(sys_proc_);
            sys_return;
        }
        case kPECTLCodeSigningAllEntitlements:
            return kPEEntitlementFlagAll;
        case kPECTLCodeSigningGetEntitlements:
        {
            return proc_getentitlements(sys_proc_snapshot_);
        }
        case kPECTLCodeSigningSetEntitlements:
        {
            kvo_wrlock(sys_proc_);
            
            /* MARK: THIS IS USER SUPPLIED */
            PEEntitlementFlags userPassed = (PEEntitlementFlags)args[2];
            
            /* getting the added mask out of entitlements */
            PEEntitlementFlags added = (~proc_getentitlements(sys_proc_)) & userPassed;
            
            /* deny adding entitlements not present in max entitlements */
            if(!entitlement_got_entitlement(proc_getmaxentitlements(sys_proc_), added))
            {
                kvo_unlock(sys_proc_);
                sys_return_failure_with_errno(EPERM);
            }
            
            proc_setentitlements(sys_proc_, userPassed);
            
            kvo_unlock(sys_proc_);
            sys_return;
        }
        case kPECTLCodeSigningDropAllEntitlements:
        {
            kvo_wrlock(sys_proc_);
            proc_setmaxentitlements(sys_proc_, kPEEntitlementFlagNone);
            proc_setentitlements(sys_proc_, kPEEntitlementFlagNone);
            kvo_unlock(sys_proc_);
            sys_return;
        }
        case kPECTLCodeSigningLoadKernelExtension:
        case kPECTLCodeSigningUnloadKernelExtension:
            sys_return_failure_with_errno(ENOTSUP);
        default:
            sys_return_failure_with_errno(ENOSYS);
    }
}

DEFINE_SYSCALL_HANDLER(pectl_userinterface)
{
    PECTLUserInterface action = (PECTLUserInterface)args[1];
    switch(action)
    {
        case kPECTLUserInterfaceInit:
        {
            recv_buffer_t *recv = *recv_buffer;
            *recv_buffer = NULL;    /* claiming ownership */
            pid_t pid = proc_getpid(sys_proc_snapshot_);
            dispatch_async(dispatch_get_main_queue(), ^{
                NXWindowServer *sharedWindowServer = [NXWindowServer shared];
                if(sharedWindowServer == nil)
                {
                    /* window server is not running yet */
                    syscall_send_reply(&(recv->header), -1, NULL, 0, true, EAGAIN);
                    return;
                }
                
                PEProcess *process = [[PEProcessManager shared] processForProcessIdentifier:pid];
                if(process == nil || process.bundleIdentifier == nil)
                {
                    /* process must exist in Process Manager */
                    syscall_send_reply(&(recv->header), -1, NULL, 0, true, EACCES);
                    return;
                }
                
                id_t wid = [sharedWindowServer windowIdentifierForBundleIdentifier:process.bundleIdentifier];
                if(wid < 0)
                {
                    /* bundle is already presented as a window */
                    syscall_send_reply(&(recv->header), -1, NULL, 0, true, EACCES);
                    return;
                }
                
                NXWindowSessionApplication *session = [[NXWindowSessionApplication alloc] initWithProcess:process];
                [sharedWindowServer openWindowWithSession:session withCompletion:^(BOOL finished){
                    syscall_send_reply(&(recv->header), finished ? 0 : -1, NULL, 0, true, 0);
                }];
            });
            sys_return;
        }
        case kPECTLUserInterfaceOpenBundleIdentifier:
        {
            kvo_rdlock(sys_proc_);
            if(CFDictionaryGetValue(sys_proc_->nyx.identity->entitlements, kNXT2EntitlementManagementProcEnvironment) != kCFBooleanTrue)
            {
                kvo_unlock(sys_proc_);
                sys_return_failure_with_errno(EPERM);
            }
            kvo_unlock(sys_proc_);
            
            userspace_pointer_t bundleid_str = (userspace_pointer_t)args[2];
            char *bundleid = syscall_copy_str_in(sys_task_, bundleid_str, MAXHOSTNAMELEN);
            if(bundleid == NULL)
            {
                sys_return_failure_with_errno(ENOMEM);
            }
            
            NSString *bundleIdentifier = [NSString stringWithCString:bundleid encoding:NSUTF8StringEncoding];
            free(bundleid);
            if(bundleIdentifier == NULL)
            {
                sys_return_failure_with_errno(ENOMEM);
            }
            
            recv_buffer_t *recv = *recv_buffer;
            *recv_buffer = NULL;    /* claiming ownership */
            dispatch_async(dispatch_get_main_queue(), ^{
                pid_t pid = [[PEProcessManager shared] spawnProcessWithBundleIdentifier:bundleIdentifier withItems:@{} withKernelSurfaceProcess:kernel_proc_ doRestartIfRunning:NO];
                if(pid < 0)
                {
                    syscall_send_reply(&(recv->header), -1, NULL, 0, true, EAGAIN);
                    return;
                }
                
                syscall_send_reply(&(recv->header), 0, NULL, 0, true, 0);
            });
            sys_return;
        }
        default:
            sys_return_failure_with_errno(ENOSYS);
    }
}

DEFINE_SYSCALL_HANDLER(pectl_userspace)
{
    PECTLUserspace action = (PECTLUserspace)args[1];
    switch(action)
    {
        case kPECTLUserspaceReboot:
            if(!entitlement_got_entitlement(proc_getmaxentitlements(sys_proc_snapshot_), kPEEntitlementFlagPlatform))
            {
                sys_return_failure_with_errno(EPERM);
            }
            [[PEUserspaceManager shared] rebootUserspace];
            sys_return;
        case kPECTLUserspaceGetMode:
            return [[PEUserspaceManager shared] mode];
        default:
            sys_return_failure_with_errno(ENOSYS);
    }
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(pectl_misceleanous)
{
    PECTLMisceleanous action = (PECTLMisceleanous)args[1];
    switch(action)
    {
        case kPECTLMisceleanousGetBuildType:
            #if DEBUG
            return kPEBuildTypeDebug;
            #else
            return kPEBuildTypeRelease;
            #endif /* DEBUG */
        default:
            sys_return_failure_with_errno(ENOSYS);
    }
    sys_return_failure_with_errno(ENOSYS);
}

DEFINE_SYSCALL_HANDLER(pectl)
{
    @autoreleasepool {
        PECTLCategory category = (PECTLCategory)args[0];
        switch(category)
        {
            case kPECTLCategoryLaunchService:
                return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(pectl_launchservice);
            case kPECTLCategoryCodeSigning:
                return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(pectl_codesigning);
            case kPECTLCategoryUserInterface:
                return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(pectl_userinterface);
            case kPECTLCategoryUserspace:
                return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(pectl_userspace);
            case kPECTLCategoryMisceleanous:
                return SYSCALL_HANDLER_REDIRECT_TO_HANDLER(pectl_misceleanous);
            default:
                sys_return_failure_with_errno(ENOSYS);
        }
    }
}

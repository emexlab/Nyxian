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

#include <sys/socket.h>
#include <sys/poll.h>
#include <stdio.h>
#include <dispatch/dispatch.h>
#include <LindChain/ProcEnvironment/Surface/libkern/patch.h>
#include <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#include <LindChain/ProcEnvironment/Surface/libkern/kpanic.h>
#include <LindChain/ProcEnvironment/Surface/libkern/bsd/proc_info.h>
#include <LindChain/ProcEnvironment/Surface/tty/tty.h>
#include <LindChain/ProcEnvironment/Surface/proc/list.h>
#include <LindChain/ProcEnvironment/Surface/proc/spawn.h>
#include <LindChain/ProcEnvironment/Surface/surface.h>

static dispatch_queue_t tty_signal_queue(void)
{
    static dispatch_queue_t queue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        queue = dispatch_queue_create("org.emexlabs.nyxian.tty.signal", DISPATCH_QUEUE_SERIAL);
    });
    return queue;
}

void tty_kill(ksurface_tty_t *tty,
              int sig)
{
    pid_t pgrp = tty->pgrp;
    dispatch_async(tty_signal_queue(), ^{
        kinfo_proc_t *kp  = NULL;
        size_t len = 0;
        
        kern_return_t kr = proc_list(kernel_proc_, &kp, &len, PROC_FLV_PGID, pgrp);
        if(kr == KERN_SUCCESS)
        {
            size_t count = len / sizeof(kinfo_proc_t);
            for(size_t i = 0; i < count; i++)
            {
                ksurface_proc_t *session_proc = NULL;
                kr = proc_for_pid(kp[i].kp_proc.p_pid, &session_proc);
                if(kr == KERN_SUCCESS)
                {
                    proc_kill(session_proc, sig);
                    kvo_release(session_proc);
                }
            }
            free(kp);
        }
    });
}

LIBKERN_DEFINE_PATCHABLE(int, tty_input, (ksurface_tty_t *tty))
{
    ssize_t n = read(tty->kernelfds[MASTERFD], tty->rbuf, TTY_MAX_RD);
    if(n <= 0)
    {
        return -1;
    }
    
    ssize_t new_n = 0;
    for(ssize_t i = 0; i < n; i++)
    {
        /* removing high bit on ISTRIP */
        if(tty->t.c_iflag & ISTRIP)
        {
            tty->rbuf[i] &= 0b01111111;
        }
        
        if(tty->t.c_lflag & ISIG)
        {
            int signal = -1;

            if(tty->rbuf[i] == tty->t.c_cc[VINTR])
            {
                signal = SIGINT;
            }
            else if(tty->rbuf[i] == tty->t.c_cc[VQUIT])
            {
                signal = SIGQUIT;
            }
            else if(tty->rbuf[i] == tty->t.c_cc[VSUSP])
            {
                signal = SIGTSTP;
            }
            else if(tty->rbuf[i] == tty->t.c_cc[VKILL])
            {
                signal = SIGKILL;
            }

            if(signal != -1)
            {
                tty_kill(tty, signal);
                continue;
            }
        }
        
        /* if ignore then dont do anything */
        if((tty->t.c_iflag & IGNCR) &&
           tty->rbuf[i] == '\r')
        {
            continue;
        }
        
        /* handling return to newline translation */
        if(tty->t.c_iflag & ICRNL &&
           tty->rbuf[i] == '\r')
        {
            tty->rbuf[i] = '\n';
        }
        
        /* the inverse of the previous translation */
        else if(tty->t.c_iflag & INLCR &&
                tty->rbuf[i] == '\n')
        {
            tty->rbuf[i] = '\r';
        }
        
        tty->rbuf[new_n++] = tty->rbuf[i];
    }
    
    ssize_t off = 0;
    while(off < new_n)
    {
        ssize_t w = write(tty->kernelfds[SLAVEFD], tty->rbuf + off, new_n - off);
        if(w <= 0)
        {
            return -1;
        }
        off += w;
    }
    
    return 0;
}

LIBKERN_DEFINE_PATCHABLE(int, tty_output, (ksurface_tty_t *tty))
{
    ssize_t n = read(tty->kernelfds[SLAVEFD], tty->rbuf, TTY_MAX_RD);
    ssize_t new_n = 0;
    if(n <= 0)
    {
        return -1;
    }
    
    if(!(tty->t.c_oflag & OPOST))
    {
        goto write_out;
    }
    
    for(ssize_t i = 0; i < n; i++)
    {
        uint8_t c = tty->rbuf[i];
        
        if(c == '\n')
        {
            /* very common flag that will fix the terminal inbuilt post process lol */
            if(tty->t.c_oflag & ONLCR)
            {
                tty->obuf[new_n++] = '\r';
                tty->obuf[new_n++] = '\n';
                continue;
            }
        }
        else if(c == '\r')
        {
            /* translate return to newline */
            if(tty->t.c_oflag & OCRNL)
            {
                tty->obuf[new_n++] = '\n';
                continue;
            }
            
            
            if((tty->t.c_oflag & ONOCR) && tty->ws.ws_col == 0)
            {
                continue;
            }
        }
        
        tty->obuf[new_n++] = c;
    }
    
write_out:
    {
        const uint8_t *out = (uint8_t*)((tty->t.c_oflag & OPOST) ? tty->obuf : tty->rbuf);
        ssize_t out_n = (tty->t.c_oflag & OPOST) ? new_n : n;
        
        ssize_t off = 0;
        while(off < out_n)
        {
            ssize_t w = write(tty->kernelfds[MASTERFD], out + off, out_n - off);
            if(w <= 0) return -1;
            off += w;
        }
    }
    
    return 0;
}

LIBKERN_DEFINE_PATCHABLE(void *, tty_pump_thread, (void *arg))
{
    ksurface_tty_t *tty = arg;

    struct pollfd fds[2] = {
        { .fd = tty->kernelfds[MASTERFD], .events = POLLIN },
        { .fd = tty->kernelfds[SLAVEFD] , .events = POLLIN },
    };

    while(tty->alive)
    {
        int r = poll(fds, 2, -1);
        if(r <= 0)
        {
            continue;
        }

        if(fds[0].revents & POLLIN)
        {
            if(tty_input(tty) < 0)
            {
                break;
            }
        }

        if(fds[1].revents & POLLIN)
        {
            if(tty_output(tty) < 0)
            {
                break;
            }
        }
    }

    return NULL;
}

DEFINE_KVOBJECT_MAIN_EVENT_HANDLER(tty)
{
    /* handle size request */
    if(kvarr == NULL)
    {
        return (int64_t)sizeof(ksurface_tty_t);
    }
    
    ksurface_tty_t *tty = (ksurface_tty_t*)kvarr[0];
    
    switch(type)
    {
        case kvObjEventSnapshot:
        case kvObjEventCopy:
            kpanic("attempted to copy or snapshot tty, which is illegal");
        case kvObjEventInit:
        {
            klog_log("tty:init", "initializing tty @ %p", tty);
            
            /* creating pipe */
            int masterpair[2];
            if(socketpair(AF_UNIX, SOCK_STREAM, 0, masterpair) != 0)
            {
                return -1;
            }
            
            /* creating pipe */
            int slavepair[2];
            if(socketpair(AF_UNIX, SOCK_STREAM, 0, slavepair) != 0)
            {
                shutdown(masterpair[1],  SHUT_RDWR);
                close(masterpair[0]);
                close(masterpair[1]);
                return -1;
            }
            
            /* getting unique object pointer */
            struct socket_fdinfo master_si;
            if(proc_pidfdinfo(getpid(), slavepair[0], PROC_PIDFDSOCKETINFO, &master_si, sizeof(struct socket_fdinfo)) <= 0)
            {
                /* notify me, if this happens, apple again had to change something */
                goto out_fail;
            }
            
            struct socket_fdinfo slave_si;
            if(proc_pidfdinfo(getpid(), masterpair[0], PROC_PIDFDSOCKETINFO, &slave_si, sizeof(struct socket_fdinfo)) <= 0)
            {
                /* notify me, if this happens, apple again had to change something */
                goto out_fail;
            }
            
            /* the 2nd fd is always the fd the tty object manages */
            tty->userspacekcid[MASTERFD] = master_si.psi.soi_proto.pri_kern_ctl.kcsi_id;
            tty->userspacekcid[SLAVEFD] = slave_si.psi.soi_proto.pri_kern_ctl.kcsi_id;
            tty->userspacefd[MASTERFD] = masterpair[0];
            tty->userspacefd[SLAVEFD] = slavepair[0];
            tty->kernelfds[MASTERFD] = masterpair[1];
            tty->kernelfds[SLAVEFD] = slavepair[1];
            
            /* inserting own tty file descriptors */
            tty_table_wrlock();
            if(radix_insert(&(ksurface->tty_info.tty), tty->userspacekcid[MASTERFD], tty) != 0)
            {
                tty_table_unlock();
                goto out_fail;
            }
            if(radix_insert(&(ksurface->tty_info.tty), tty->userspacekcid[SLAVEFD], tty) != 0)
            {
                radix_remove(&(ksurface->tty_info.tty), tty->userspacekcid[MASTERFD]);
                tty_table_unlock();
                goto out_fail;
            }
            
            tty_table_unlock();
            
            /* lets start da factory, alive first so the thread cannot see 0 and exit */
            tty->alive = 1;
            if(pthread_create(&tty->pump_thread, NULL, tty_pump_thread, tty) != 0)
            {
                tty->alive = 0;
                goto out_fail_radix;
            }
            
            return 0;
        
        out_fail_radix:
            tty_table_wrlock();
            radix_remove(&(ksurface->tty_info.tty), tty->userspacekcid[MASTERFD]);
            radix_remove(&(ksurface->tty_info.tty), tty->userspacekcid[SLAVEFD]);
            tty_table_unlock();
        out_fail:
            shutdown(tty->kernelfds[SLAVEFD],  SHUT_RDWR);
            shutdown(tty->kernelfds[MASTERFD], SHUT_RDWR);
            close(tty->userspacefd[MASTERFD]);
            close(tty->userspacefd[SLAVEFD]);
            close(tty->kernelfds[MASTERFD]);
            close(tty->kernelfds[SLAVEFD]);
            return -1;
        }
        case kvObjEventDeinit:
            klog_log("tty:deinit", "deinitializing tty @ %p", tty);
            
            /* the thread would go on using this tty after it is freed, see tty_signal_queue */
            if(pthread_equal(pthread_self(), tty->pump_thread))
            {
                kpanic("tty deinitialized on its own pump thread");
            }
            
            /* removing own tty object */
            tty_table_wrlock();
            radix_remove(&(ksurface->tty_info.tty), tty->userspacekcid[MASTERFD]);
            radix_remove(&(ksurface->tty_info.tty), tty->userspacekcid[SLAVEFD]);
            tty_table_unlock();
            
            /* making sure deinit happens, with the threads consent */
            tty->alive = 0;
            
            shutdown(tty->kernelfds[SLAVEFD],  SHUT_RDWR);
            shutdown(tty->kernelfds[MASTERFD], SHUT_RDWR);

            pthread_join(tty->pump_thread, NULL);
            
            close(tty->userspacefd[MASTERFD]);
            close(tty->userspacefd[SLAVEFD]);
            close(tty->kernelfds[MASTERFD]);
            close(tty->kernelfds[SLAVEFD]);
            
            /* fallthrough */
        default:
            return 0;
    }
    
    return 0;
}

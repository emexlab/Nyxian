/*
 SPDX-License-Identifier: LicenseRef-EPSL-1.1

 Copyright (C) 2026 emexlab
 Copyright (C) 2026 roothider

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
#include <LiveProcessLegacy/LPLSyscall.h>
#include <Nyxian/LindChain/ProcEnvironment/litehook/litehook.h>
#include <Nyxian/LindChain/Private/mach/mach_vm.h>
#include <mach/mach.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <mach/task.h>
#include <mach/thread_info.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <mach/mach_time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include "ksurface_config.h"
#include "ksurface_abi.h"
#include "spawn_bootstrap.h"
#include <Broadpatch/Broadpatch.h>

typedef __darwin_mach_port_t pe_fileport_t;
extern int fileport_makeport(int fd, pe_fileport_t *port);

struct arm64_thread_full_state {
    arm_thread_state64_t    thread;
    arm_exception_state64_t exception;
    arm_neon_state64_t      neon;
    arm_debug_state64_t     debug;
    uint32_t                thread_valid:1,
                            exception_valid:1,
                            neon_valid:1,
                            debug_valid:1,
                            cpmu_valid:1;
};

struct arm64_thread_full_state* thread_save_state_arm64(thread_act_t thread);
bool thread_restore_state_arm64(thread_act_t thread, struct arm64_thread_full_state* state);

extern int LCBootstrapMain(NSString *executablePath, int argc, char *argv[]);

#pragma mark - Time-travel fork checkpoint

#define PE_CHECKPOINT_ARENA_SIZE    (64ull * 1024ull * 1024ull)
#define PE_MAX_VM_REGIONS           16384
#define PE_MAX_FD_JOURNAL           512
#define PE_MAX_FD_OPS               512
#define PE_MAX_FAKE_CHILDREN        32
#define PE_MAX_TRACKED_FDS          4096
#define PE_MAX_EXEC_VECTOR          4096
#define PE_MAX_EXEC_FDS             256
#define PE_MAX_LOCAL_PIPES          128
#define PE_MAX_OTHER_STACKS         64
#define PE_PIPE_SPOOL_INITIAL       (64ull * 1024ull)
#define PE_PIPE_SPOOL_LIMIT         (256ull * 1024ull * 1024ull)
#define PE_SYNTHETIC_PID_BASE       ((pid_t)0x40000000)
#define PE_EXEC_PENDING_PID         ((pid_t)0x3fffffff)
#define PE_MAX_NEST_DEPTH           4

#ifndef PE_USE_SPAWN_CLOEXEC_DEFAULT
#define PE_USE_SPAWN_CLOEXEC_DEFAULT 1
#endif

#define PE_CHECKPOINT_VM_TAG_ID     VM_MEMORY_APPLICATION_SPECIFIC_16
#define PE_CHECKPOINT_VM_FLAGS      VM_MAKE_TAG(PE_CHECKPOINT_VM_TAG_ID)

typedef enum {
    PE_HELPER_IDLE = 0,
    PE_HELPER_CAPTURE,
    PE_HELPER_RESTORE,
} pe_helper_action_t;

typedef struct {
    mach_vm_address_t address;
    mach_vm_size_t size;
    mach_vm_address_t copy_address;
    vm_prot_t protection;
    vm_prot_t max_protection;
    vm_inherit_t inheritance;
    unsigned int user_tag;
    unsigned int share_mode;
} pe_vm_region_snapshot_t;

typedef struct {
    mach_vm_address_t low;
    mach_vm_address_t high;
} pe_thread_stack_range_t;

typedef struct {
    int fd;
    int backup_fd;
    int fd_flags;
    bool was_open;
} pe_fd_journal_entry_t;

typedef enum {
    PE_FD_OP_CLOSE = 1,
    PE_FD_OP_DUP2 = 2,
} pe_fd_op_kind_t;

typedef struct {
    pe_fd_op_kind_t kind;
    int oldfd;
    int newfd;
    int pipe_slot;
    uint8_t pipe_role;
} pe_fd_op_t;

typedef struct {
    pid_t pid;
    int status;
    bool used;
    int world;
} pe_fake_child_t;

typedef enum {
    PE_PIPE_ROLE_NONE = 0,
    PE_PIPE_ROLE_READ = 1,
    PE_PIPE_ROLE_WRITE = 2,
} pe_pipe_role_t;

typedef struct {
    bool used;
    int read_fd_hint;
    int write_fd_hint;
    
    mach_vm_address_t spool_buffer;
    mach_vm_size_t spool_capacity;
    size_t spool_length;
    size_t spool_read_offset;
    bool spool_active;
    
    uint64_t producer_serial;
    bool producer_done;
    
    uint64_t checkpoint_serial;
    bool checkpoint_has_read;
    bool checkpoint_has_write;
} pe_local_pipe_t;

typedef struct pe_checkpoint_control {
    int level;
    struct pe_checkpoint_control *parent_level;
    
    volatile pe_helper_action_t helper_action;
    volatile bool helper_ready;
    volatile bool checkpoint_active;
    volatile bool checkpoint_ok;
    volatile bool restoring;
    
    volatile bool checkpoint_claimed;
    
    semaphore_t request_semaphore;
    semaphore_t ready_semaphore;
    pthread_t helper_pthread;
    thread_t helper_thread;
    mach_vm_address_t helper_stack_low;
    mach_vm_address_t helper_stack_high;
    
    thread_t target_thread;
    pthread_t target_pthread;
    struct arm64_thread_full_state target_state;
    bool target_state_valid;
    mach_vm_address_t target_stack_low;
    mach_vm_address_t target_stack_high;
    
    char cwd[PATH_MAX];
    bool saved_cwd_path_valid;
    int saved_cwd_fd;
    mode_t saved_umask;
    sigset_t saved_sigmask;
    struct sigaction saved_sigactions[NSIG];
    bool saved_sigaction_valid[NSIG];
    
    pe_vm_region_snapshot_t *vm_regions;
    size_t vm_region_count;
    
    pe_thread_stack_range_t other_stacks[PE_MAX_OTHER_STACKS];
    size_t other_stack_count;
    
    thread_act_array_t frozen_threads;
    mach_msg_type_number_t frozen_count;
    
    pid_t fake_child_pid;
    bool pending_setsid;
    bool pending_pgrp_set;
    pid_t pending_pgrp;
    int pending_tcsetpgrp_fd;
    int pending_ctty_fd;
    
    pe_fd_journal_entry_t *fd_journal;
    size_t fd_journal_count;
    pe_fd_op_t *fd_ops;
    size_t fd_op_count;
    uint8_t *initial_fd_open;
    int *initial_fd_flags;
    int *initial_fd_pipe_slot;
    uint8_t *initial_fd_pipe_role;
    size_t tracked_fd_limit;
    int fd_backup_floor;
    
    pe_local_pipe_t local_pipes[PE_MAX_LOCAL_PIPES];
    int pipe_fd_slot[PE_MAX_TRACKED_FDS];
    uint8_t pipe_fd_role[PE_MAX_TRACKED_FDS];
    uint64_t checkpoint_serial;
    
    bool pending_exec;
    bool pending_exec_find_binary;
    char *pending_exec_path;
    char **pending_exec_argv;
    char **pending_exec_envp;
    char pending_exec_cwd[PATH_MAX];
    int pending_exec_cwd_fd;
    
    sigset_t pending_exec_sigdefault;
    sigset_t pending_exec_sigmask;
    
    int exec_fd_target[PE_MAX_EXEC_FDS];
    int exec_fd_carrier[PE_MAX_EXEC_FDS];
    int exec_fd_pipe_slot[PE_MAX_EXEC_FDS];
    uint8_t exec_fd_pipe_role[PE_MAX_EXEC_FDS];
    size_t exec_fd_count;
    
    pid_t return_pid;
    int restore_errno;
    bool synthetic_child;
    int synthetic_wait_status;
    
    uint32_t collapsed_nested_forks;
    
    mach_vm_address_t arena_base;
    mach_vm_size_t arena_size;
    mach_vm_size_t scratch_offset;
    mach_vm_size_t scratch_base_offset;
    
    pe_fake_child_t fake_children[PE_MAX_FAKE_CHILDREN];
    uint32_t next_synthetic_pid;
} pe_checkpoint_control_t;

typedef struct {
    pe_checkpoint_control_t levels[PE_MAX_NEST_DEPTH];
    uint64_t serial_counter;
} pe_checkpoint_arena_header_t;

static pe_checkpoint_control_t *g_checkpoint = NULL;
static pe_checkpoint_arena_header_t *g_arena_header = NULL;
static mach_vm_address_t g_checkpoint_arena = 0;

static __thread pe_checkpoint_control_t *local_fork_checkpoint = NULL;

static bool g_pe_nested_enabled = true;
static bool g_pe_nested_spawn_enabled = false;

#if PE_USE_SPAWN_CLOEXEC_DEFAULT && defined(POSIX_SPAWN_CLOEXEC_DEFAULT)
static bool g_pe_spawn_cloexec_default_usable = true;
#endif

extern char **environ;

#pragma mark - libSystem fork hooks

typedef void (*pe_libsystem_atfork_fn)(unsigned int flags);
static pe_libsystem_atfork_fn pe_libsystem_atfork_prepare = NULL;
static pe_libsystem_atfork_fn pe_libsystem_atfork_parent = NULL;

static void pe_libsystem_atfork_resolve(void)
{
    pe_libsystem_atfork_prepare = (pe_libsystem_atfork_fn)dlsym(RTLD_DEFAULT, "_libSystem_atfork_prepare");
    pe_libsystem_atfork_parent = (pe_libsystem_atfork_fn)dlsym(RTLD_DEFAULT, "_libSystem_atfork_parent");
    if(pe_libsystem_atfork_prepare == NULL || pe_libsystem_atfork_parent == NULL)
    {
        pe_libsystem_atfork_prepare = NULL;
        pe_libsystem_atfork_parent = NULL;
    }
}

static inline void pe_atfork_prepare(void)
{
    if(pe_libsystem_atfork_prepare != NULL)
    {
        pe_libsystem_atfork_prepare(0);
    }
}

static inline void pe_atfork_release(void)
{
    if(pe_libsystem_atfork_parent != NULL)
    {
        pe_libsystem_atfork_parent(0);
    }
}

static inline mach_vm_address_t pe_align_up(mach_vm_address_t value, mach_vm_size_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline bool pe_ranges_overlap(mach_vm_address_t a,
                                     mach_vm_size_t asz,
                                     mach_vm_address_t b,
                                     mach_vm_size_t bsz)
{
    return a < b + bsz && b < a + asz;
}

static inline bool pe_in_fake_child(void)
{
    return local_fork_checkpoint != NULL && g_checkpoint != NULL && g_checkpoint->checkpoint_active && g_checkpoint->return_pid == 0 && !g_checkpoint->restoring;
}

static inline int pe_current_world(void)
{
    if(g_checkpoint == NULL)
    {
        return 0;
    }
    return pe_in_fake_child() ? g_checkpoint->level + 1 : g_checkpoint->level;
}

#pragma mark - Close-on-exec helpers

static void pe_force_cloexec(int fd)
{
    if(fd < 0)
    {
        return;
    }
    
    int flags = fcntl(fd, F_GETFD);
    if(flags >= 0 && (flags & FD_CLOEXEC) == 0)
    {
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

static int pe_dupfd_cloexec(int fd,
                            int floor)
{
    int r = fcntl(fd, F_DUPFD_CLOEXEC, floor);
    if(r < 0)
    {
        r = fcntl(fd, F_DUPFD, floor);
    }
    pe_force_cloexec(r);
    return r;
}

#pragma mark - Configuration

static void pe_config_refresh_from_env(void)
{
    const char *nested = getenv("PEFORK_NESTED");
    g_pe_nested_enabled = !(nested != NULL && strcmp(nested, "0") == 0);
    const char *nested_spawn = getenv("PEFORK_NESTED_SPAWN");
    g_pe_nested_spawn_enabled = (nested_spawn != NULL && strcmp(nested_spawn, "1") == 0);
}

static bool pe_pipe_slot_has_role(int slot,
                                  pe_pipe_role_t role)
{
    if(g_checkpoint == NULL || slot < 0 || slot >= PE_MAX_LOCAL_PIPES)
    {
        return false;
    }
    
    for(size_t fd = 0; fd < PE_MAX_TRACKED_FDS; fd++)
    {
        if(g_checkpoint->pipe_fd_slot[fd] == slot && g_checkpoint->pipe_fd_role[fd] == (uint8_t)role)
        {
            return true;
        }
    }
    
    return false;
}

static bool pe_pipe_slot_has_any_fd(int slot)
{
    if(g_checkpoint == NULL || slot < 0 || slot >= PE_MAX_LOCAL_PIPES)
    {
        return false;
    }
    
    for(size_t fd = 0; fd < PE_MAX_TRACKED_FDS; fd++)
    {
        if(g_checkpoint->pipe_fd_slot[fd] == slot)
        {
            return true;
        }
    }
    
    return false;
}

static void pe_pipe_release_slot(int slot)
{
    if(g_checkpoint == NULL || slot < 0 || slot >= PE_MAX_LOCAL_PIPES)
    {
        return;
    }
    
    pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
    if(!pipe_state->used)
    {
        return;
    }
    
    if(pipe_state->spool_buffer != 0 && pipe_state->spool_capacity != 0)
    {
        mach_vm_deallocate(mach_task_self(), pipe_state->spool_buffer, pipe_state->spool_capacity);
    }
    
    memset(pipe_state, 0, sizeof(*pipe_state));
    pipe_state->read_fd_hint = -1;
    pipe_state->write_fd_hint = -1;
}

static void pe_pipe_maybe_release_slot(int slot)
{
    if(slot < 0 || slot >= PE_MAX_LOCAL_PIPES)
    {
        return;
    }
    
    if(!pe_pipe_slot_has_any_fd(slot))
    {
        pe_pipe_release_slot(slot);
    }
}

static void pe_pipe_unmap_fd(int fd,
                             bool fake_child)
{
    if(g_checkpoint == NULL || fd < 0 || fd >= PE_MAX_TRACKED_FDS)
    {
        return;
    }
    
    int slot = g_checkpoint->pipe_fd_slot[fd];
    if(slot < 0 || slot >= PE_MAX_LOCAL_PIPES)
    {
        g_checkpoint->pipe_fd_slot[fd] = -1;
        g_checkpoint->pipe_fd_role[fd] = PE_PIPE_ROLE_NONE;
        return;
    }
    
    g_checkpoint->pipe_fd_slot[fd] = -1;
    g_checkpoint->pipe_fd_role[fd] = PE_PIPE_ROLE_NONE;
    if(!fake_child)
    {
        pe_pipe_maybe_release_slot(slot);
    }
}

static void pe_pipe_map_fd(int fd, int slot,
                           pe_pipe_role_t role,
                           bool fake_child)
{
    if(g_checkpoint == NULL || fd < 0 || fd >= PE_MAX_TRACKED_FDS)
    {
        return;
    }
    
    if(g_checkpoint->pipe_fd_slot[fd] >= 0)
    {
        pe_pipe_unmap_fd(fd, fake_child);
    }
    
    if(slot >= 0 && slot < PE_MAX_LOCAL_PIPES &&
       g_checkpoint->local_pipes[slot].used)
    {
        g_checkpoint->pipe_fd_slot[fd] = slot;
        g_checkpoint->pipe_fd_role[fd] = (uint8_t)role;
    }
}

static void pe_pipe_copy_fd_mapping(int oldfd,
                                    int newfd,
                                    bool fake_child)
{
    if(g_checkpoint == NULL || newfd < 0 || newfd >= PE_MAX_TRACKED_FDS)
    {
        return;
    }
    
    int slot = -1;
    pe_pipe_role_t role = PE_PIPE_ROLE_NONE;
    if(oldfd >= 0 && oldfd < PE_MAX_TRACKED_FDS)
    {
        slot = g_checkpoint->pipe_fd_slot[oldfd];
        role = (pe_pipe_role_t)g_checkpoint->pipe_fd_role[oldfd];
    }
    
    pe_pipe_unmap_fd(newfd, fake_child);
    if(slot >= 0 && slot < PE_MAX_LOCAL_PIPES)
    {
        pe_pipe_map_fd(newfd, slot, role, fake_child);
    }
}

static int pe_pipe_register_pair(int read_fd,
                                 int write_fd)
{
    if(g_checkpoint == NULL ||
       read_fd < 0 || write_fd < 0 ||
       read_fd >= PE_MAX_TRACKED_FDS || write_fd >= PE_MAX_TRACKED_FDS)
    {
        return -1;
    }
    
    int slot = -1;
    for(int i = 0; i < PE_MAX_LOCAL_PIPES; i++)
    {
        if(!g_checkpoint->local_pipes[i].used)
        {
            slot = i;
            break;
        }
    }
    
    if(slot < 0)
    {
        return -1;
    }
    
    pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
    memset(pipe_state, 0, sizeof(*pipe_state));
    pipe_state->used = true;
    pipe_state->read_fd_hint = read_fd;
    pipe_state->write_fd_hint = write_fd;
    
    pe_pipe_map_fd(read_fd, slot, PE_PIPE_ROLE_READ, pe_in_fake_child());
    pe_pipe_map_fd(write_fd, slot, PE_PIPE_ROLE_WRITE, pe_in_fake_child());
    
    return slot;
}

static bool pe_pipe_spool_reserve(pe_local_pipe_t *pipe_state,
                                  size_t needed)
{
    if(pipe_state == NULL)
    {
        errno = EINVAL;
        return false;
    }
    
    if(needed <= pipe_state->spool_capacity)
    {
        return true;
    }
    
    if(needed > PE_PIPE_SPOOL_LIMIT)
    {
        errno = ENOSPC;
        return false;
    }
    
    mach_vm_size_t new_capacity = pipe_state->spool_capacity;
    if(new_capacity < PE_PIPE_SPOOL_INITIAL)
    {
        new_capacity = PE_PIPE_SPOOL_INITIAL;
    }
    
    while(new_capacity < needed)
    {
        if(new_capacity > PE_PIPE_SPOOL_LIMIT / 2)
        {
            new_capacity = PE_PIPE_SPOOL_LIMIT;
            break;
        }
        new_capacity *= 2;
    }
    
    new_capacity = (mach_vm_size_t)pe_align_up(new_capacity, vm_page_size);
    mach_vm_address_t new_buffer = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &new_buffer, new_capacity, VM_FLAGS_ANYWHERE | PE_CHECKPOINT_VM_FLAGS);
    if(kr != KERN_SUCCESS)
    {
        errno = ENOMEM;
        return false;
    }
    
    if(pipe_state->spool_buffer != 0 && pipe_state->spool_length != 0)
    {
        memcpy((void *)new_buffer, (const void *)pipe_state->spool_buffer, pipe_state->spool_length);
    }
    
    if(pipe_state->spool_buffer != 0 && pipe_state->spool_capacity != 0)
    {
        mach_vm_deallocate(mach_task_self(), pipe_state->spool_buffer, pipe_state->spool_capacity);
    }
    
    pipe_state->spool_buffer = new_buffer;
    pipe_state->spool_capacity = new_capacity;
    return true;
}

static bool pe_pipe_should_spool_fd(int fd,
                                    int *slot_out)
{
    if(!pe_in_fake_child() || fd < 0 || fd >= PE_MAX_TRACKED_FDS)
    {
        return false;
    }
    
    int slot = g_checkpoint->pipe_fd_slot[fd];
    if(slot < 0 || slot >= PE_MAX_LOCAL_PIPES ||
       g_checkpoint->pipe_fd_role[fd] != PE_PIPE_ROLE_WRITE)
    {
        return false;
    }
    
    pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
    if(!pipe_state->used ||
       pipe_state->checkpoint_serial != g_checkpoint->checkpoint_serial ||
       !pipe_state->checkpoint_has_read)
    {
        return false;
    }
    
    if(slot_out != NULL)
    {
        *slot_out = slot;
    }
    return true;
}

static ssize_t pe_pipe_spool_write(int fd,
                                   const void *buf,
                                   size_t count)
{
    int slot = -1;
    if(!pe_pipe_should_spool_fd(fd, &slot))
    {
        return -2;
    }
    
    pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
    if(count == 0)
    {
        return 0;
    }
    
    if(buf == NULL)
    {
        errno = EFAULT;
        return -1;
    }
    
    if(count > SIZE_MAX - pipe_state->spool_length)
    {
        errno = EOVERFLOW;
        return -1;
    }
    
    size_t needed = pipe_state->spool_length + count;
    if(!pe_pipe_spool_reserve(pipe_state, needed))
    {
        return -1;
    }
    
    memcpy((void *)(pipe_state->spool_buffer + pipe_state->spool_length), buf, count);
    
    pipe_state->spool_length = needed;
    pipe_state->spool_active = true;
    pipe_state->producer_serial = g_checkpoint->checkpoint_serial;
    pipe_state->producer_done = false;
    
    return (ssize_t)count;
}

static ssize_t pe_pipe_spool_read(int fd,
                                  void *buf,
                                  size_t count)
{
    if(g_checkpoint == NULL || fd < 0 || fd >= PE_MAX_TRACKED_FDS)
    {
        return -2;
    }
    
    int slot = g_checkpoint->pipe_fd_slot[fd];
    if(slot < 0 || slot >= PE_MAX_LOCAL_PIPES ||
       g_checkpoint->pipe_fd_role[fd] != PE_PIPE_ROLE_READ)
    {
        return -2;
    }
    
    pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
    if(!pipe_state->used || !pipe_state->spool_active)
    {
        return -2;
    }
    
    if(count == 0)
    {
        return 0;
    }
    if(buf == NULL)
    {
        errno = EFAULT;
        return -1;
    }
    
    if(pipe_state->spool_read_offset < pipe_state->spool_length)
    {
        size_t available = pipe_state->spool_length - pipe_state->spool_read_offset;
        size_t amount = count < available ? count : available;
        memcpy(buf, (const void *)(pipe_state->spool_buffer + pipe_state->spool_read_offset), amount);
        pipe_state->spool_read_offset += amount;
        return (ssize_t)amount;
    }
    
    if(pipe_state->producer_done && !pe_pipe_slot_has_role(slot, PE_PIPE_ROLE_WRITE))
    {
        return 0;
    }
    
    return -2;
}

static void pe_pipe_mark_fake_child_done(void)
{
    if(g_checkpoint == NULL)
    {
        return;
    }
    
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
    {
        pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
        if(pipe_state->used &&
           pipe_state->producer_serial == g_checkpoint->checkpoint_serial)
        {
            pipe_state->producer_done = true;
        }
    }
}

static void pe_restore_pipe_fd_map(void)
{
    if(g_checkpoint == NULL ||
       g_checkpoint->initial_fd_pipe_slot == NULL ||
       g_checkpoint->initial_fd_pipe_role == NULL)
    {
        return;
    }
    
    size_t limit = g_checkpoint->tracked_fd_limit;
    if(limit > PE_MAX_TRACKED_FDS)
    {
        limit = PE_MAX_TRACKED_FDS;
    }
    
    for(size_t fd = 0; fd < limit; fd++)
    {
        g_checkpoint->pipe_fd_slot[fd] = g_checkpoint->initial_fd_pipe_slot[fd];
        g_checkpoint->pipe_fd_role[fd] = g_checkpoint->initial_fd_pipe_role[fd];
    }
    
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
    {
        pe_pipe_maybe_release_slot(slot);
    }
}

static void pe_scratch_reset(void)
{
    g_checkpoint->scratch_offset = g_checkpoint->scratch_base_offset;
}

static void *pe_scratch_alloc(size_t size,
                              size_t alignment)
{
    if(g_checkpoint == NULL || size == 0)
    {
        return NULL;
    }
    
    mach_vm_address_t current = g_checkpoint->arena_base + g_checkpoint->scratch_offset;
    mach_vm_address_t aligned = pe_align_up(current, alignment ? alignment : 16);
    mach_vm_address_t end = aligned + size;
    mach_vm_address_t arena_end = g_checkpoint->arena_base + g_checkpoint->arena_size;
    if(end < aligned || end > arena_end)
    {
        return NULL;
    }
    
    g_checkpoint->scratch_offset = end - g_checkpoint->arena_base;
    return (void *)aligned;
}

static char *pe_scratch_strdup(const char *s)
{
    if(s == NULL)
    {
        return NULL;
    }
    
    size_t len = strlen(s) + 1;
    char *copy = pe_scratch_alloc(len, 1);
    if(copy == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }
    
    memcpy(copy, s, len);
    return copy;
}

static char **pe_scratch_dup_strv(char *const vec[])
{
    if(vec == NULL)
    {
        return NULL;
    }
    
    size_t count = 0;
    while(vec[count] != NULL)
    {
        if(count >= PE_MAX_EXEC_VECTOR)
        {
            errno = E2BIG;
            return NULL;
        }
        count++;
    }
    
    char **copy = pe_scratch_alloc((count + 1) * sizeof(char *), _Alignof(char *));
    if(copy == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }
    
    for(size_t i = 0; i < count; i++)
    {
        copy[i] = pe_scratch_strdup(vec[i]);
        if(copy[i] == NULL)
        {
            return NULL;
        }
    }
    copy[count] = NULL;
    return copy;
}

static bool pe_save_thread_state(thread_t thread,
                                 struct arm64_thread_full_state *state)
{
    memset(state, 0, sizeof(*state));
    
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state->thread, &count);
    state->thread_valid = (kr == KERN_SUCCESS);
    if(kr != KERN_SUCCESS)
    {
        return false;
    }
    
    count = ARM_EXCEPTION_STATE64_COUNT;
    kr = thread_get_state(thread, ARM_EXCEPTION_STATE64, (thread_state_t)&state->exception, &count);
    state->exception_valid = (kr == KERN_SUCCESS);
    
    count = ARM_NEON_STATE64_COUNT;
    kr = thread_get_state(thread, ARM_NEON_STATE64, (thread_state_t)&state->neon, &count);
    state->neon_valid = (kr == KERN_SUCCESS);
    
    count = ARM_DEBUG_STATE64_COUNT;
    kr = thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state->debug, &count);
    state->debug_valid = (kr == KERN_SUCCESS);
    
    return true;
}

static bool pe_restore_thread_state(thread_t thread,
                                    const struct arm64_thread_full_state *state)
{
    if(state == NULL || !state->thread_valid)
    {
        return false;
    }
    
    kern_return_t kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state->thread, ARM_THREAD_STATE64_COUNT);
    if(kr != KERN_SUCCESS)
    {
        return false;
    }
    
    if(state->exception_valid) thread_set_state(thread, ARM_EXCEPTION_STATE64, (thread_state_t)&state->exception, ARM_EXCEPTION_STATE64_COUNT);
    if(state->neon_valid) thread_set_state(thread, ARM_NEON_STATE64, (thread_state_t)&state->neon, ARM_NEON_STATE64_COUNT);
    if(state->debug_valid) thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state->debug, ARM_DEBUG_STATE64_COUNT);
    
    return true;
}

static bool pe_wait_until_thread_suspended(thread_t thread)
{
    for(;;)
    {
        thread_basic_info_data_t info;
        mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
        kern_return_t kr = thread_info(thread, THREAD_BASIC_INFO, (thread_info_t)&info, &count);
        if(kr != KERN_SUCCESS)
        {
            return false;
        }
        
        if(info.suspend_count > 0)
        {
            return true;
        }
        
        sched_yield();
    }
}

static bool pe_region_is_private(const vm_region_submap_info_data_64_t *info)
{
    return (info->share_mode == SM_PRIVATE || info->share_mode == SM_COW || info->share_mode == SM_PRIVATE_ALIASED);
}

static bool pe_region_is_excluded(mach_vm_address_t address,
                                  mach_vm_size_t size,
                                  unsigned int user_tag)
{
    if(user_tag == PE_CHECKPOINT_VM_TAG_ID)
    {
        return true;
    }
    
    if(user_tag == VM_MEMORY_STACK &&
       g_checkpoint->target_stack_high > g_checkpoint->target_stack_low &&
       !pe_ranges_overlap(address, size, g_checkpoint->target_stack_low, g_checkpoint->target_stack_high - g_checkpoint->target_stack_low))
    {
        return true;
    }
    
    if(pe_ranges_overlap(address, size, g_checkpoint->arena_base, g_checkpoint->arena_size))
    {
        return true;
    }
    
    if(g_checkpoint->helper_stack_high > g_checkpoint->helper_stack_low &&
       pe_ranges_overlap(address, size, g_checkpoint->helper_stack_low, g_checkpoint->helper_stack_high - g_checkpoint->helper_stack_low))
    {
        return true;
    }
    
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
    {
        pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
        if(pipe_state->used &&
           pipe_state->spool_buffer != 0 &&
           pipe_state->spool_capacity != 0 &&
           pe_ranges_overlap(address, size, pipe_state->spool_buffer, pipe_state->spool_capacity))
        {
            return true;
        }
    }
    
    for(pe_checkpoint_control_t *ancestor = g_checkpoint->parent_level; ancestor != NULL; ancestor = ancestor->parent_level)
    {
        for(size_t i = 0; i < ancestor->vm_region_count; i++)
        {
            pe_vm_region_snapshot_t *snapshot = &ancestor->vm_regions[i];
            if(snapshot->copy_address != 0 &&
               pe_ranges_overlap(address, size, snapshot->copy_address, snapshot->size))
            {
                return true;
            }
        }
    }
    
    for(size_t i = 0; i < g_checkpoint->other_stack_count; i++)
    {
        mach_vm_address_t low = g_checkpoint->other_stacks[i].low;
        mach_vm_address_t high = g_checkpoint->other_stacks[i].high;
        if(high > low && pe_ranges_overlap(address, size, low, high - low))
        {
            return true;
        }
    }
    
    return false;
}

static void pe_capture_other_thread_stacks(void)
{
    g_checkpoint->other_stack_count = 0;
    
    task_t task = mach_task_self();
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    if(task_threads(task, &threads, &thread_count) != KERN_SUCCESS)
    {
        return;
    }
    
    for(mach_msg_type_number_t i = 0; i < thread_count; i++)
    {
        thread_t thread = threads[i];
        pthread_t pth = pthread_from_mach_thread_np(thread);
        
        if(pth != NULL &&
           pth != g_checkpoint->target_pthread &&
           pth != g_checkpoint->helper_pthread &&
           g_checkpoint->other_stack_count < PE_MAX_OTHER_STACKS)
        {
            mach_vm_address_t high = (mach_vm_address_t)pthread_get_stackaddr_np(pth);
            size_t size = pthread_get_stacksize_np(pth);
            if(high != 0 && size != 0)
            {
                size_t idx = g_checkpoint->other_stack_count++;
                g_checkpoint->other_stacks[idx].high = high;
                g_checkpoint->other_stacks[idx].low  = (size < high) ? high - size : 0;
            }
        }
        
        mach_port_deallocate(task, thread);
    }
    
    vm_deallocate(task, (vm_address_t)threads, thread_count * sizeof(thread_t));
}

static void pe_freeze_other_threads(void)
{
    task_t task = mach_task_self();
    
    g_checkpoint->frozen_threads = NULL;
    g_checkpoint->frozen_count = 0;
    
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    if(task_threads(task, &threads, &thread_count) != KERN_SUCCESS)
    {
        return;
    }
    
    for(mach_msg_type_number_t i = 0; i < thread_count; i++)
    {
        thread_t thread = threads[i];
        if(thread == g_checkpoint->helper_thread ||
           thread == g_checkpoint->target_thread)
        {
            mach_port_deallocate(task, thread);
            threads[i] = MACH_PORT_NULL;
            continue;
        }
        
        kern_return_t kr = thread_suspend(thread);
        if(kr != KERN_SUCCESS)
        {
            mach_port_deallocate(task, thread);
            threads[i] = MACH_PORT_NULL;
            continue;
        }
    }
    
    g_checkpoint->frozen_threads = threads;
    g_checkpoint->frozen_count = thread_count;
}

static void pe_thaw_other_threads(void)
{
    if(g_checkpoint == NULL || g_checkpoint->frozen_threads == NULL)
    {
        return;
    }
    
    task_t task = mach_task_self();
    thread_act_array_t threads = g_checkpoint->frozen_threads;
    mach_msg_type_number_t thread_count = g_checkpoint->frozen_count;
    
    g_checkpoint->frozen_threads = NULL;
    g_checkpoint->frozen_count = 0;
    
    for(mach_msg_type_number_t i = 0; i < thread_count; i++)
    {
        if(threads[i] != MACH_PORT_NULL)
        {
            thread_resume(threads[i]);
            mach_port_deallocate(task, threads[i]);
        }
    }
    
    vm_deallocate(task, (vm_address_t)threads, thread_count * sizeof(thread_t));
}

static void pe_release_vm_snapshots(void)
{
    if(g_checkpoint->vm_regions != NULL)
    {
        for(size_t i = 0; i < g_checkpoint->vm_region_count; i++)
        {
            pe_vm_region_snapshot_t *snapshot = &g_checkpoint->vm_regions[i];
            if(snapshot->copy_address != 0 && snapshot->size != 0)
            {
                mach_vm_deallocate(mach_task_self(), snapshot->copy_address, snapshot->size);
                snapshot->copy_address = 0;
            }
        }
    }
    
    g_checkpoint->vm_regions = NULL;
    g_checkpoint->vm_region_count = 0;
}

static bool pe_capture_vm(void)
{
    task_t task = mach_task_self();
    
    g_checkpoint->vm_region_count = 0;
    g_checkpoint->vm_regions = pe_scratch_alloc(sizeof(pe_vm_region_snapshot_t) * PE_MAX_VM_REGIONS, _Alignof(pe_vm_region_snapshot_t));
    if(g_checkpoint->vm_regions == NULL)
    {
        errno = ENOMEM;
        return false;
    }
    memset(g_checkpoint->vm_regions, 0, sizeof(pe_vm_region_snapshot_t) * PE_MAX_VM_REGIONS);
    
    mach_vm_address_t cursor = 0;
    natural_t depth = 0;
    for(;;)
    {
        mach_vm_address_t address = cursor;
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(task, &address, &size, &depth, (vm_region_recurse_info_t)&info, &count);
        if(kr == KERN_INVALID_ADDRESS)
        {
            break;
        }
        if(kr != KERN_SUCCESS)
        {
            errno = EFAULT;
            return false;
        }
        if(info.is_submap)
        {
            depth++;
            continue;
        }
        
        if(address < cursor)
        {
            mach_vm_address_t region_end = address + size;
            if(region_end <= address || region_end <= cursor)
            {
                if(cursor > UINT64_MAX - (mach_vm_address_t)vm_page_size)
                {
                    break;
                }
                cursor += (mach_vm_address_t)vm_page_size;
                continue;
            }
            size = region_end - cursor;
            address = cursor;
        }
        
        bool writable = (info.protection & VM_PROT_WRITE) != 0;
        bool readable = (info.protection & VM_PROT_READ) != 0;
        bool executable = (info.protection & VM_PROT_EXECUTE) != 0;
        bool private_region = pe_region_is_private(&info);
        
        if(readable && writable && !executable && private_region && !pe_region_is_excluded(address, size, info.user_tag))
        {
            if(g_checkpoint->vm_region_count >= PE_MAX_VM_REGIONS)
            {
                errno = E2BIG;
                return false;
            }
            
            pe_vm_region_snapshot_t *snapshot = &g_checkpoint->vm_regions[g_checkpoint->vm_region_count++];
            snapshot->address = address;
            snapshot->size = size;
            snapshot->copy_address = 0;
            snapshot->protection = info.protection;
            snapshot->max_protection = info.max_protection;
            snapshot->inheritance = info.inheritance;
            snapshot->user_tag = info.user_tag;
            snapshot->share_mode = info.share_mode;
        }
        
        if(address + size <= address)
        {
            break;
        }
        
        mach_vm_address_t next = address + size;
        if(next <= cursor)
        {
            if(cursor > UINT64_MAX - (mach_vm_address_t)vm_page_size)
            {
                break;
            }
            cursor += (mach_vm_address_t)vm_page_size;
        }
        else
        {
            cursor = next;
        }
    }
    
    size_t kept = 0;
    for(size_t i = 0; i < g_checkpoint->vm_region_count; i++)
    {
        pe_vm_region_snapshot_t region = g_checkpoint->vm_regions[i];
        
        mach_vm_address_t copy_address = 0;
        vm_prot_t cur_prot = VM_PROT_NONE;
        vm_prot_t max_prot = VM_PROT_NONE;
        kern_return_t rkr = mach_vm_remap(task, &copy_address, region.size, 0, TRUE,
                                          task, region.address, TRUE,
                                          &cur_prot, &max_prot, VM_INHERIT_NONE);
        if(rkr != KERN_SUCCESS)
        {
            copy_address = 0;
            rkr = mach_vm_allocate(task, &copy_address, region.size, VM_FLAGS_ANYWHERE | PE_CHECKPOINT_VM_FLAGS);
            if(rkr == KERN_SUCCESS &&
               mach_vm_copy(task, region.address, region.size, copy_address) != KERN_SUCCESS)
            {
                mach_vm_deallocate(task, copy_address, region.size);
                copy_address = 0;
            }
            if(copy_address == 0)
            {
                continue;
            }
        }
        
        region.copy_address = copy_address;
        g_checkpoint->vm_regions[kept++] = region;
    }
    g_checkpoint->vm_region_count = kept;
    
    return true;
}

static bool pe_restore_one_vm_region(pe_vm_region_snapshot_t *snapshot)
{
    task_t task = mach_task_self();
    
    kern_return_t kr = mach_vm_copy(task, snapshot->copy_address, snapshot->size, snapshot->address);
    if(kr == KERN_SUCCESS)
    {
        return true;
    }
    
    mach_vm_address_t target = snapshot->address;
    kr = mach_vm_allocate(task, &target, snapshot->size, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(snapshot->user_tag));
    if(kr != KERN_SUCCESS || target != snapshot->address)
    {
        return false;
    }
    
    kr = mach_vm_copy(task, snapshot->copy_address, snapshot->size, snapshot->address);
    if(kr != KERN_SUCCESS)
    {
        return false;
    }
    
    mach_vm_protect(task, snapshot->address, snapshot->size, TRUE, snapshot->max_protection);
    if(mach_vm_protect(task, snapshot->address, snapshot->size, FALSE, snapshot->protection) != KERN_SUCCESS)
    {
        return false;
    }
    
    return true;
}

static bool pe_restore_vm(void)
{
    bool success = true;
    
    for(size_t i = 0; i < g_checkpoint->vm_region_count; i++)
    {
        if(!pe_restore_one_vm_region(&g_checkpoint->vm_regions[i]))
        {
            success = false;
        }
    }
    
    return success;
}

static int pe_dup_backup_fd(int fd)
{
    return pe_dupfd_cloexec(fd, g_checkpoint->fd_backup_floor);
}

static int pe_capture_cwd_fd(void)
{
    int cwd_fd = open(".", O_RDONLY | O_CLOEXEC);
    if(cwd_fd < 0)
    {
        return -1;
    }
    pe_force_cloexec(cwd_fd);
    
    int saved_fd = pe_dup_backup_fd(cwd_fd);
    int saved_errno = errno;
    
    bool old_restoring = g_checkpoint->restoring;
    g_checkpoint->restoring = true;
    close(cwd_fd);
    g_checkpoint->restoring = old_restoring;
    if(saved_fd < 0)
    {
        errno = saved_errno;
        return -1;
    }
    
    return saved_fd;
}

static bool pe_is_internal_checkpoint_fd(int fd)
{
    if(g_checkpoint == NULL || fd < 0)
    {
        return false;
    }
    
    if(fd == g_checkpoint->saved_cwd_fd || fd == g_checkpoint->pending_exec_cwd_fd)
    {
        return true;
    }
    
    for(size_t i = 0; i < g_checkpoint->exec_fd_count; i++)
    {
        if(g_checkpoint->exec_fd_carrier[i] == fd)
        {
            return true;
        }
    }
    
    return false;
}

static bool pe_record_fd_before_change(int fd)
{
    if(fd < 0)
    {
        errno = EBADF;
        return false;
    }
    
    if(g_checkpoint->fd_journal_count >= PE_MAX_FD_JOURNAL)
    {
        errno = EMFILE;
        return false;
    }
    
    pe_fd_journal_entry_t *entry = &g_checkpoint->fd_journal[g_checkpoint->fd_journal_count];
    memset(entry, 0, sizeof(*entry));
    entry->fd = fd;
    entry->backup_fd = -1;
    entry->fd_flags = fcntl(fd, F_GETFD);
    if(entry->fd_flags >= 0)
    {
        entry->was_open = true;
        entry->backup_fd = pe_dup_backup_fd(fd);
        if(entry->backup_fd < 0)
        {
            return false;
        }
    }
    else if(errno == EBADF)
    {
        entry->was_open = false;
        errno = 0;
    }
    else
    {
        return false;
    }
    
    g_checkpoint->fd_journal_count++;
    return true;
}

static bool pe_record_fd_op(pe_fd_op_kind_t kind,
                            int oldfd,
                            int newfd)
{
    if(g_checkpoint == NULL || !g_checkpoint->checkpoint_active)
    {
        return true;
    }
    
    if(g_checkpoint->fd_ops == NULL ||
       g_checkpoint->fd_op_count >= PE_MAX_FD_OPS)
    {
        return true;
    }
    
    pe_fd_op_t *op = &g_checkpoint->fd_ops[g_checkpoint->fd_op_count++];
    memset(op, 0, sizeof(*op));
    op->kind = kind;
    op->oldfd = oldfd;
    op->newfd = newfd;
    op->pipe_slot = -1;
    op->pipe_role = PE_PIPE_ROLE_NONE;
    
    if(oldfd >= 0 && oldfd < PE_MAX_TRACKED_FDS)
    {
        int pipe_slot = g_checkpoint->pipe_fd_slot[oldfd];
        uint8_t pipe_role = g_checkpoint->pipe_fd_role[oldfd];
        
        if(pipe_slot >= 0 && pipe_slot < PE_MAX_LOCAL_PIPES &&
           g_checkpoint->local_pipes[pipe_slot].used)
        {
            op->pipe_slot = pipe_slot;
            op->pipe_role = pipe_role;
        }
    }
    
    return true;
}

LIBKERN_PATCH(int, close, (int fd),
              {
    if(local_fork_checkpoint != NULL &&
       g_checkpoint->checkpoint_active &&
       g_checkpoint->return_pid == 0 &&
       !g_checkpoint->restoring)
    {
        if(!pe_record_fd_before_change(fd))
        {
            return -1;
        }
    }
    
    int rc = LIBKERN_ORIG(close)(fd);
    if(rc == 0 &&
       local_fork_checkpoint != NULL &&
       g_checkpoint->checkpoint_active &&
       g_checkpoint->return_pid == 0 &&
       !g_checkpoint->restoring)
    {
        pe_record_fd_op(PE_FD_OP_CLOSE, fd, -1);
    }
    
    if(rc == 0)
    {
        pe_pipe_unmap_fd(fd, pe_in_fake_child());
    }
    
    return rc;
});

LIBKERN_PATCH(int, dup2, (int oldFD,
                          int newFD),
              {
    if(local_fork_checkpoint != NULL &&
       g_checkpoint->checkpoint_active &&
       g_checkpoint->return_pid == 0 &&
       !g_checkpoint->restoring)
    {
        if(oldFD != newFD && !pe_record_fd_before_change(newFD))
        {
            return -1;
        }
    }
    
    int rc = LIBKERN_ORIG(dup2)(oldFD, newFD);
    if(rc >= 0 &&
       oldFD != newFD &&
       local_fork_checkpoint != NULL &&
       g_checkpoint->checkpoint_active &&
       g_checkpoint->return_pid == 0 &&
       !g_checkpoint->restoring)
    {
        pe_record_fd_op(PE_FD_OP_DUP2, oldFD, newFD);
    }
    
    if(rc >= 0 && oldFD != newFD)
    {
        pe_pipe_copy_fd_mapping(oldFD, newFD, pe_in_fake_child());
    }
    
    return rc;
});

static void pe_restore_fd_state(void)
{
    for(size_t i = g_checkpoint->fd_journal_count; i > 0; i--)
    {
        pe_fd_journal_entry_t *entry = &g_checkpoint->fd_journal[i - 1];
        
        if(entry->was_open)
        {
            if(entry->backup_fd >= 0)
            {
                LIBKERN_ORIG(dup2)(entry->backup_fd, entry->fd);
                fcntl(entry->fd, F_SETFD, entry->fd_flags);
                LIBKERN_ORIG(close)(entry->backup_fd);
                entry->backup_fd = -1;
            }
        }
        else
        {
            LIBKERN_ORIG(close)(entry->fd);
        }
    }
    
    for(size_t fd = 0; fd < g_checkpoint->tracked_fd_limit; fd++)
    {
        if(g_checkpoint->initial_fd_open[fd])
        {
            continue;
        }
        
        if(pe_is_internal_checkpoint_fd((int)fd))
        {
            continue;
        }
        
        if(fcntl((int)fd, F_GETFD) >= 0)
        {
            LIBKERN_ORIG(close)((int)fd);
        }
    }
    
    for(size_t fd = 0; fd < g_checkpoint->tracked_fd_limit; fd++)
    {
        if(!g_checkpoint->initial_fd_open[fd])
        {
            continue;
        }
        
        int const saved_flags = g_checkpoint->initial_fd_flags[fd];
        if(saved_flags < 0)
        {
            continue;
        }
        
        int const current_flags = fcntl((int)fd, F_GETFD);
        if(current_flags >= 0 && current_flags != saved_flags)
        {
            fcntl((int)fd, F_SETFD, saved_flags);
        }
    }
    
    pe_restore_pipe_fd_map();
    g_checkpoint->fd_journal_count = 0;
}

static bool pe_capture_fd_baseline(void)
{
    struct rlimit limit;
    if(getrlimit(RLIMIT_NOFILE, &limit) != 0)
    {
        return false;
    }
    
    size_t fd_limit = (size_t)limit.rlim_cur;
    if(fd_limit == 0 || fd_limit == (size_t)RLIM_INFINITY)
    {
        fd_limit = 256;
    }
    if(fd_limit > PE_MAX_TRACKED_FDS)
    {
        fd_limit = PE_MAX_TRACKED_FDS;
    }
    
    g_checkpoint->tracked_fd_limit = fd_limit;
    g_checkpoint->fd_backup_floor = (int)(fd_limit / 2);
    if(g_checkpoint->fd_backup_floor < 32)
    {
        g_checkpoint->fd_backup_floor = 32;
    }
    if((size_t)g_checkpoint->fd_backup_floor >= fd_limit)
    {
        g_checkpoint->fd_backup_floor = 0;
    }
    
    g_checkpoint->initial_fd_open = pe_scratch_alloc(fd_limit, 1);
    g_checkpoint->initial_fd_flags = pe_scratch_alloc(sizeof(int) * fd_limit, _Alignof(int));
    g_checkpoint->initial_fd_pipe_slot = pe_scratch_alloc(sizeof(int) * fd_limit, _Alignof(int));
    g_checkpoint->initial_fd_pipe_role = pe_scratch_alloc(sizeof(uint8_t) * fd_limit, _Alignof(uint8_t));
    g_checkpoint->fd_journal = pe_scratch_alloc(sizeof(pe_fd_journal_entry_t) * PE_MAX_FD_JOURNAL, _Alignof(pe_fd_journal_entry_t));
    g_checkpoint->fd_ops = pe_scratch_alloc(sizeof(pe_fd_op_t) * PE_MAX_FD_OPS, _Alignof(pe_fd_op_t));
    if(g_checkpoint->initial_fd_open == NULL ||
       g_checkpoint->initial_fd_flags == NULL ||
       g_checkpoint->initial_fd_pipe_slot == NULL ||
       g_checkpoint->initial_fd_pipe_role == NULL ||
       g_checkpoint->fd_journal == NULL ||
       g_checkpoint->fd_ops == NULL)
    {
        errno = ENOMEM;
        return false;
    }
    
    memset(g_checkpoint->initial_fd_open, 0, fd_limit);
    memset(g_checkpoint->initial_fd_pipe_role, 0, fd_limit);
    for(size_t fd = 0; fd < fd_limit; fd++)
    {
        g_checkpoint->initial_fd_flags[fd] = -1;
        g_checkpoint->initial_fd_pipe_slot[fd] = -1;
    }
    
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
    {
        pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
        if(pipe_state->used)
        {
            pipe_state->checkpoint_serial = g_checkpoint->checkpoint_serial;
            pipe_state->checkpoint_has_read = false;
            pipe_state->checkpoint_has_write = false;
        }
    }
    memset(g_checkpoint->fd_journal, 0, sizeof(pe_fd_journal_entry_t) * PE_MAX_FD_JOURNAL);
    memset(g_checkpoint->fd_ops, 0, sizeof(pe_fd_op_t) * PE_MAX_FD_OPS);
    g_checkpoint->fd_journal_count = 0;
    g_checkpoint->fd_op_count = 0;
    
    size_t open_count = 0;
    for(size_t fd = 0; fd < fd_limit; fd++)
    {
        int const flags = fcntl((int)fd, F_GETFD);
        if(flags >= 0)
        {
            g_checkpoint->initial_fd_open[fd] = 1;
            g_checkpoint->initial_fd_flags[fd] = flags;
            g_checkpoint->initial_fd_pipe_slot[fd] = g_checkpoint->pipe_fd_slot[fd];
            g_checkpoint->initial_fd_pipe_role[fd] = g_checkpoint->pipe_fd_role[fd];
            
            int pipe_slot = g_checkpoint->initial_fd_pipe_slot[fd];
            if(pipe_slot >= 0 && pipe_slot < PE_MAX_LOCAL_PIPES && g_checkpoint->local_pipes[pipe_slot].used)
            {
                if(g_checkpoint->initial_fd_pipe_role[fd] == PE_PIPE_ROLE_READ)
                {
                    g_checkpoint->local_pipes[pipe_slot].checkpoint_has_read = true;
                }
                else if(g_checkpoint->initial_fd_pipe_role[fd] == PE_PIPE_ROLE_WRITE)
                {
                    g_checkpoint->local_pipes[pipe_slot].checkpoint_has_write = true;
                }
            }
            open_count++;
        }
    }
    
    return true;
}

static void pe_capture_signal_state(void)
{
    for(int sig = 1; sig < NSIG; sig++)
    {
        if(sig == SIGKILL || sig == SIGSTOP)
        {
            g_checkpoint->saved_sigaction_valid[sig] = false;
            continue;
        }
        g_checkpoint->saved_sigaction_valid[sig] = (sigaction(sig, NULL, &g_checkpoint->saved_sigactions[sig]) == 0);
    }
}

static void pe_restore_signal_state(void)
{
    for(int sig = 1; sig < NSIG; sig++)
    {
        if(g_checkpoint->saved_sigaction_valid[sig])
        {
            sigaction(sig, &g_checkpoint->saved_sigactions[sig], NULL);
        }
    }
}

static bool pe_capture_process_state(void)
{
    g_checkpoint->saved_cwd_fd = -1;
    g_checkpoint->saved_cwd_path_valid = false;
    g_checkpoint->cwd[0] = '\0';
    
    if(getcwd(g_checkpoint->cwd, sizeof(g_checkpoint->cwd)) != NULL)
    {
        g_checkpoint->saved_cwd_path_valid = true;
    }
    else
    {
        g_checkpoint->cwd[0] = '\0';
    }
    
    g_checkpoint->saved_umask = umask(0);
    umask(g_checkpoint->saved_umask);
    
    int sigmask_result = pthread_sigmask(SIG_SETMASK, NULL, &g_checkpoint->saved_sigmask);
    if(sigmask_result != 0)
    {
        errno = sigmask_result;
        return false;
    }
    
    pe_capture_signal_state();
    if(!pe_capture_fd_baseline())
    {
        return false;
    }
    
    g_checkpoint->saved_cwd_fd = pe_capture_cwd_fd();
    if(g_checkpoint->saved_cwd_fd < 0 &&
       !g_checkpoint->saved_cwd_path_valid)
    {
        g_checkpoint->saved_cwd_fd = -1;
        g_checkpoint->saved_cwd_path_valid = false;
        g_checkpoint->cwd[0] = '\0';
        errno = 0;
    }
    
    return true;
}

static int pe_restore_process_state_from_helper(void)
{
    pe_restore_fd_state();
    
    int cwd_rc = 0;
    int cwd_errno = 0;
    
    if(g_checkpoint->saved_cwd_fd >= 0)
    {
        cwd_rc = fchdir(g_checkpoint->saved_cwd_fd);
        if(cwd_rc != 0)
        {
            cwd_errno = errno;
        }
    }
    
    if(cwd_rc != 0 && g_checkpoint->saved_cwd_path_valid)
    {
        cwd_rc = chdir(g_checkpoint->cwd);
        if(cwd_rc != 0)
        {
            cwd_errno = errno;
        }
        else
        {
            cwd_errno = 0;
        }
    }
    
    umask(g_checkpoint->saved_umask);
    pe_restore_signal_state();
    
    return cwd_rc == 0 ? 0 : (cwd_errno ? cwd_errno : ENOENT);
}

static pid_t pe_allocate_synthetic_pid(void)
{
    uint32_t value = ++g_checkpoint->next_synthetic_pid;
    if(value == 0 || value > 0x0fffffffU)
    {
        g_checkpoint->next_synthetic_pid = 1;
        value = 1;
    }
    return (pid_t)(PE_SYNTHETIC_PID_BASE + (pid_t)value);
}

static void pe_publish_fake_child(pid_t pid,
                                  int status,
                                  int world)
{
    for(size_t i = 0; i < PE_MAX_FAKE_CHILDREN; i++)
    {
        if(!g_checkpoint->fake_children[i].used)
        {
            g_checkpoint->fake_children[i].pid = pid;
            g_checkpoint->fake_children[i].status = status;
            g_checkpoint->fake_children[i].world = world;
            g_checkpoint->fake_children[i].used = true;
            return;
        }
    }
}

static void pe_discard_fake_children_above(int world)
{
    for(size_t i = 0; i < PE_MAX_FAKE_CHILDREN; i++)
    {
        pe_fake_child_t *child = &g_checkpoint->fake_children[i];
        if(child->used && child->world > world)
        {
            child->used = false;
        }
    }
}

static pid_t pe_reap_fake_child(pid_t pid,
                                int *status,
                                struct rusage *rusage)
{
    int world = pe_current_world();
    
    for(size_t i = 0; i < PE_MAX_FAKE_CHILDREN; i++)
    {
        pe_fake_child_t *child = &g_checkpoint->fake_children[i];
        if(!child->used || child->world != world)
        {
            continue;
        }
        
        if(pid > 0 && child->pid != pid)
        {
            continue;
        }
        
        pid_t result = child->pid;
        if(status != NULL)
        {
            *status = child->status;
        }
        if(rusage != NULL)
        {
            memset(rusage, 0, sizeof(*rusage));
        }
        child->used = false;
        return result;
    }
    
    return 0;
}

static void pe_restore_checkpoint(void)
{
    g_checkpoint->restoring = true;
    
    bool vm_ok = pe_restore_vm();
    int process_restore_error = pe_restore_process_state_from_helper();
    if(process_restore_error != 0 && g_checkpoint->restore_errno == 0)
    {
        g_checkpoint->restore_errno = process_restore_error;
    }
    
    if(!vm_ok && g_checkpoint->restore_errno == 0)
    {
        g_checkpoint->restore_errno = EFAULT;
    }
    
    if(!pe_restore_thread_state(g_checkpoint->target_thread, &g_checkpoint->target_state) &&
       g_checkpoint->restore_errno == 0)
    {
        g_checkpoint->restore_errno = EFAULT;
    }
    
    thread_resume(g_checkpoint->target_thread);
}

static void *pe_checkpoint_helper(void *arg)
{
    g_checkpoint->helper_pthread = pthread_self();
    g_checkpoint->helper_thread = mach_thread_self();
    
    void *stack_top = pthread_get_stackaddr_np(g_checkpoint->helper_pthread);
    size_t stack_size = pthread_get_stacksize_np(g_checkpoint->helper_pthread);
    g_checkpoint->helper_stack_high = (mach_vm_address_t)stack_top;
    g_checkpoint->helper_stack_low = g_checkpoint->helper_stack_high - stack_size;
    g_checkpoint->helper_ready = true;
    semaphore_signal(g_checkpoint->ready_semaphore);
    
    for(;;)
    {
        semaphore_wait(g_checkpoint->request_semaphore);
        
        pe_helper_action_t action = g_checkpoint->helper_action;
        if(action == PE_HELPER_CAPTURE)
        {
            if(!pe_wait_until_thread_suspended(g_checkpoint->target_thread))
            {
                g_checkpoint->checkpoint_ok = false;
                g_checkpoint->return_pid = -1;
                g_checkpoint->restore_errno = EFAULT;
                thread_resume(g_checkpoint->target_thread);
                continue;
            }
            
            pe_freeze_other_threads();
            
            g_checkpoint->target_state_valid = pe_save_thread_state(g_checkpoint->target_thread, &g_checkpoint->target_state);
            
            bool vm_ok = g_checkpoint->target_state_valid && pe_capture_vm();
            g_checkpoint->checkpoint_ok = vm_ok;
            if(!vm_ok)
            {
                g_checkpoint->return_pid = -1;
                if(g_checkpoint->restore_errno == 0)
                {
                    g_checkpoint->restore_errno = errno ? errno : EFAULT;
                }
            }
            
            g_checkpoint->helper_action = PE_HELPER_IDLE;
            thread_resume(g_checkpoint->target_thread);
        }
        else if(action == PE_HELPER_RESTORE)
        {
            if(!pe_wait_until_thread_suspended(g_checkpoint->target_thread))
            {
                g_checkpoint->restore_errno = EFAULT;
                continue;
            }
            g_checkpoint->helper_action = PE_HELPER_IDLE;
            pe_restore_checkpoint();
        }
    }
    
    return NULL;
}

static bool pe_checkpoint_runtime_init(void)
{
    if(g_checkpoint != NULL)
    {
        return true;
    }
    
    pe_libsystem_atfork_resolve();
    
    mach_vm_address_t arena = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &arena, PE_CHECKPOINT_ARENA_SIZE, VM_FLAGS_ANYWHERE | PE_CHECKPOINT_VM_FLAGS);
    if(kr != KERN_SUCCESS)
    {
        errno = ENOMEM;
        return false;
    }
    
    g_checkpoint_arena = arena;
    g_arena_header = (pe_checkpoint_arena_header_t *)arena;
    memset(g_arena_header, 0, sizeof(*g_arena_header));
    
    g_checkpoint = &g_arena_header->levels[0];
    g_checkpoint->level = 0;
    g_checkpoint->parent_level = NULL;
    g_checkpoint->arena_base = arena;
    g_checkpoint->arena_size = PE_CHECKPOINT_ARENA_SIZE;
    g_checkpoint->scratch_base_offset = pe_align_up(sizeof(*g_arena_header), (mach_vm_size_t)vm_page_size);
    g_checkpoint->scratch_offset = g_checkpoint->scratch_base_offset;
    g_checkpoint->next_synthetic_pid = 1;
    g_checkpoint->checkpoint_serial = 0;
    g_checkpoint->saved_cwd_fd = -1;
    g_checkpoint->pending_exec_cwd_fd = -1;
    g_checkpoint->frozen_threads = NULL;
    g_checkpoint->frozen_count = 0;
    for(size_t fd = 0; fd < PE_MAX_TRACKED_FDS; fd++)
    {
        g_checkpoint->pipe_fd_slot[fd] = -1;
        g_checkpoint->pipe_fd_role[fd] = PE_PIPE_ROLE_NONE;
    }
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
    {
        g_checkpoint->local_pipes[slot].read_fd_hint = -1;
        g_checkpoint->local_pipes[slot].write_fd_hint = -1;
    }
    
    kern_return_t request_sem_kr = semaphore_create(mach_task_self(), &g_checkpoint->request_semaphore, SYNC_POLICY_FIFO, 0);
    kern_return_t ready_sem_kr = semaphore_create(mach_task_self(), &g_checkpoint->ready_semaphore, SYNC_POLICY_FIFO, 0);
    if(request_sem_kr != KERN_SUCCESS || ready_sem_kr != KERN_SUCCESS)
    {
        errno = ENOMEM;
        return false;
    }
    
    int pthread_error = pthread_create(&g_checkpoint->helper_pthread, NULL, pe_checkpoint_helper, NULL);
    if(pthread_error != 0)
    {
        errno = pthread_error;
        return false;
    }
    pthread_detach(g_checkpoint->helper_pthread);
    semaphore_wait(g_checkpoint->ready_semaphore);
    
    return g_checkpoint->helper_ready;
}

#pragma mark - Nested checkpoint levels

static bool pe_checkpoint_push_level(void)
{
    pe_checkpoint_control_t *parent = g_checkpoint;
    int next = parent->level + 1;
    if(g_arena_header == NULL || next >= PE_MAX_NEST_DEPTH)
    {
        return false;
    }
    
    pe_checkpoint_control_t *child = &g_arena_header->levels[next];
    memcpy(child, parent, sizeof(*child));
    
    child->level = next;
    child->parent_level = parent;
    
    child->checkpoint_active = false;
    child->checkpoint_ok = false;
    child->restoring = false;
    child->checkpoint_claimed = false;
    child->helper_action = PE_HELPER_IDLE;
    child->return_pid = 0;
    child->restore_errno = 0;
    child->target_thread = MACH_PORT_NULL;
    child->target_state_valid = false;
    child->frozen_threads = NULL;
    child->frozen_count = 0;
    child->vm_regions = NULL;
    child->vm_region_count = 0;
    child->other_stack_count = 0;
    child->exec_fd_count = 0;
    child->fd_journal = NULL;
    child->fd_ops = NULL;
    child->initial_fd_open = NULL;
    child->initial_fd_flags = NULL;
    child->initial_fd_pipe_slot = NULL;
    child->initial_fd_pipe_role = NULL;
    child->fd_journal_count = 0;
    child->fd_op_count = 0;
    child->saved_cwd_fd = -1;
    child->pending_exec_cwd_fd = -1;
    child->pending_exec = false;
    child->collapsed_nested_forks = 0;
    child->scratch_base_offset = parent->scratch_offset;
    child->scratch_offset = parent->scratch_offset;
    
    g_checkpoint = child;
    local_fork_checkpoint = child;
    return true;
}

static void pe_checkpoint_merge_shared_state(pe_checkpoint_control_t *child,
                                             pe_checkpoint_control_t *parent)
{
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
    {
        pe_local_pipe_t *dst = &parent->local_pipes[slot];
        bool const was_used = dst->used;
        uint64_t const tag_serial = dst->checkpoint_serial;
        bool const tag_read = dst->checkpoint_has_read;
        bool const tag_write = dst->checkpoint_has_write;
        
        *dst = child->local_pipes[slot];
        
        if(was_used && dst->used)
        {
            dst->checkpoint_serial = tag_serial;
            dst->checkpoint_has_read = tag_read;
            dst->checkpoint_has_write = tag_write;
        }
    }
    
    memcpy(parent->pipe_fd_slot, child->pipe_fd_slot, sizeof(parent->pipe_fd_slot));
    memcpy(parent->pipe_fd_role, child->pipe_fd_role, sizeof(parent->pipe_fd_role));
    memcpy(parent->fake_children, child->fake_children, sizeof(parent->fake_children));
    parent->next_synthetic_pid = child->next_synthetic_pid;
}

static void pe_checkpoint_pop_level(void)
{
    pe_checkpoint_control_t *child = g_checkpoint;
    pe_checkpoint_control_t *parent = (child != NULL) ? child->parent_level : NULL;
    if(parent == NULL)
    {
        return;
    }
    
    pe_checkpoint_merge_shared_state(child, parent);
    
    child->parent_level = NULL;
    g_checkpoint = parent;
    local_fork_checkpoint = parent;
}

static void pe_checkpoint_abandon_level(void)
{
    pe_checkpoint_control_t *child = g_checkpoint;
    pe_checkpoint_control_t *parent = (child != NULL) ? child->parent_level : NULL;
    if(parent == NULL)
    {
        return;
    }
    
    pe_thaw_other_threads();
    pe_release_vm_snapshots();
    
    size_t moved = 0;
    for(size_t i = 0; i < child->fd_journal_count; i++)
    {
        pe_fd_journal_entry_t *entry = &child->fd_journal[i];
        if(parent->fd_journal != NULL && parent->fd_journal_count < PE_MAX_FD_JOURNAL)
        {
            parent->fd_journal[parent->fd_journal_count++] = *entry;
            moved++;
        }
        else
        {
            if(entry->backup_fd >= 0)
            {
                LIBKERN_ORIG(close)(entry->backup_fd);
            }
        }
    }
    child->fd_journal_count = 0;
    
    if(child->saved_cwd_fd >= 0)
    {
        LIBKERN_ORIG(close)(child->saved_cwd_fd);
        child->saved_cwd_fd = -1;
    }
    if(child->pending_exec_cwd_fd >= 0)
    {
        LIBKERN_ORIG(close)(child->pending_exec_cwd_fd);
        child->pending_exec_cwd_fd = -1;
    }
    
    if(child->pending_setsid)
    {
        parent->pending_setsid = true;
        parent->pending_pgrp_set = false;
    }
    if(child->pending_pgrp_set)
    {
        parent->pending_pgrp_set = true;
        parent->pending_pgrp = child->pending_pgrp;
    }
    if(child->pending_tcsetpgrp_fd >= 0)
    {
        parent->pending_tcsetpgrp_fd = child->pending_tcsetpgrp_fd;
    }
    if(child->pending_ctty_fd >= 0)
    {
        parent->pending_ctty_fd = child->pending_ctty_fd;
    }
    
    pe_checkpoint_merge_shared_state(child, parent);
    
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
    {
        pe_local_pipe_t *pipe_state = &parent->local_pipes[slot];
        if(pipe_state->used && pipe_state->producer_serial == child->checkpoint_serial)
        {
            pipe_state->producer_serial = parent->checkpoint_serial;
        }
    }
    
    int const abandoned_world = child->level + 1;
    for(size_t i = 0; i < PE_MAX_FAKE_CHILDREN; i++)
    {
        pe_fake_child_t *fake = &parent->fake_children[i];
        if(!fake->used)
        {
            continue;
        }
        if(fake->world == abandoned_world - 1)
        {
            fake->used = false;
        }
        else if(fake->world >= abandoned_world)
        {
            fake->world--;
        }
    }
    
    if(child->target_thread != MACH_PORT_NULL)
    {
        mach_port_deallocate(mach_task_self(), child->target_thread);
        child->target_thread = MACH_PORT_NULL;
    }
    
    child->checkpoint_active = false;
    child->checkpoint_ok = false;
    child->pending_exec = false;
    child->parent_level = NULL;
    __atomic_clear(&child->checkpoint_claimed, __ATOMIC_RELEASE);
    
    g_checkpoint = parent;
    local_fork_checkpoint = parent;
}

static void pe_checkpoint_abandon_nested_levels(void)
{
    while(g_checkpoint != NULL && g_checkpoint->parent_level != NULL)
    {
        pe_checkpoint_abandon_level();
    }
}

static void pe_close_exec_carriers(void)
{
    size_t count = g_checkpoint->exec_fd_count;
    g_checkpoint->exec_fd_count = 0;
    
    for(size_t i = 0; i < count; i++)
    {
        if(g_checkpoint->exec_fd_carrier[i] >= 0)
        {
            LIBKERN_ORIG(close)(g_checkpoint->exec_fd_carrier[i]);
            g_checkpoint->exec_fd_carrier[i] = -1;
        }
    }
}

static void pe_checkpoint_cleanup_parent(void)
{
    int saved_errno = g_checkpoint->restore_errno;
    
    pe_thaw_other_threads();
    
    pe_discard_fake_children_above(g_checkpoint->level);
    if(g_checkpoint->synthetic_child && g_checkpoint->return_pid > 0)
    {
        pe_publish_fake_child(g_checkpoint->return_pid, g_checkpoint->synthetic_wait_status, g_checkpoint->level);
    }
    
    if(g_checkpoint->target_thread != MACH_PORT_NULL)
    {
        mach_port_deallocate(mach_task_self(), g_checkpoint->target_thread);
        g_checkpoint->target_thread = MACH_PORT_NULL;
    }
    
    g_checkpoint->checkpoint_active = false;
    g_checkpoint->checkpoint_ok = false;
    g_checkpoint->restoring = false;
    pe_release_vm_snapshots();
    pe_close_exec_carriers();
    g_checkpoint->fd_journal = NULL;
    g_checkpoint->fd_ops = NULL;
    g_checkpoint->initial_fd_open = NULL;
    g_checkpoint->initial_fd_flags = NULL;
    g_checkpoint->initial_fd_pipe_slot = NULL;
    g_checkpoint->initial_fd_pipe_role = NULL;
    g_checkpoint->fd_journal_count = 0;
    g_checkpoint->fd_op_count = 0;
    g_checkpoint->pending_exec = false;
    g_checkpoint->pending_exec_find_binary = false;
    g_checkpoint->pending_exec_path = NULL;
    g_checkpoint->pending_exec_argv = NULL;
    g_checkpoint->pending_exec_envp = NULL;
    g_checkpoint->pending_exec_cwd[0] = '\0';
    
    if(g_checkpoint->pending_exec_cwd_fd >= 0)
    {
        close(g_checkpoint->pending_exec_cwd_fd);
        g_checkpoint->pending_exec_cwd_fd = -1;
    }
    if(g_checkpoint->saved_cwd_fd >= 0)
    {
        close(g_checkpoint->saved_cwd_fd);
        g_checkpoint->saved_cwd_fd = -1;
    }
    g_checkpoint->saved_cwd_path_valid = false;
    
    local_fork_checkpoint = NULL;
    pe_scratch_reset();
    
    __atomic_clear(&g_checkpoint->checkpoint_claimed, __ATOMIC_RELEASE);
    
    pe_checkpoint_pop_level();
    
    if(saved_errno != 0)
    {
        errno = saved_errno;
    }
}

#pragma mark - Deferred exec fd table snapshot

static bool pe_fd_is_journaled(int fd)
{
    for(size_t i = 0; i < g_checkpoint->fd_journal_count; i++)
    {
        if(g_checkpoint->fd_journal[i].fd == fd)
        {
            return true;
        }
    }
    return false;
}

static bool pe_fd_is_exec_target(int fd)
{
    for(size_t i = 0; i < g_checkpoint->exec_fd_count; i++)
    {
        if(g_checkpoint->exec_fd_target[i] == fd)
        {
            return true;
        }
    }
    return false;
}

static bool pe_fd_is_exec_carrier(int fd)
{
    for(size_t i = 0; i < g_checkpoint->exec_fd_count; i++)
    {
        if(g_checkpoint->exec_fd_carrier[i] == fd)
        {
            return true;
        }
    }
    return false;
}

static int pe_pick_carrier_fd(void)
{
    int floor = g_checkpoint->fd_backup_floor;
    for(int fd = (int)g_checkpoint->tracked_fd_limit - 1; fd >= floor; fd--)
    {
        if(g_checkpoint->initial_fd_open[fd])
        {
            continue;
        }
        if(pe_is_internal_checkpoint_fd(fd) || pe_fd_is_journaled(fd))
        {
            continue;
        }
        if(fcntl(fd, F_GETFD) >= 0)
        {
            continue;
        }
        return fd;
    }
    
    errno = EMFILE;
    return -1;
}

static bool pe_snapshot_exec_fds(void)
{
    g_checkpoint->exec_fd_count = 0;
    
    size_t limit = g_checkpoint->tracked_fd_limit;
    for(size_t i = 0; i < limit; i++)
    {
        int fd = (int)i;
        if(pe_is_internal_checkpoint_fd(fd))
        {
            continue;
        }
        
        int flags = fcntl(fd, F_GETFD);
        if(flags < 0 || (flags & FD_CLOEXEC))
        {
            continue;
        }
        
        if(g_checkpoint->exec_fd_count >= PE_MAX_EXEC_FDS)
        {
            errno = EMFILE;
            return false;
        }
        
        int carrier = pe_pick_carrier_fd();
        if(carrier < 0)
        {
            return false;
        }
        
        if(LIBKERN_ORIG(dup2)(fd, carrier) < 0)
        {
            return false;
        }
        fcntl(carrier, F_SETFD, FD_CLOEXEC);
        
        size_t idx = g_checkpoint->exec_fd_count++;
        g_checkpoint->exec_fd_target[idx] = fd;
        g_checkpoint->exec_fd_carrier[idx] = carrier;
        
        g_checkpoint->exec_fd_pipe_slot[idx] = (fd < PE_MAX_TRACKED_FDS) ? g_checkpoint->pipe_fd_slot[fd] : -1;
        g_checkpoint->exec_fd_pipe_role[idx] = (fd < PE_MAX_TRACKED_FDS) ? g_checkpoint->pipe_fd_role[fd] : PE_PIPE_ROLE_NONE;
    }
    
    return true;
}

static int pe_move_fd_off_exec_targets(int fd)
{
    int floor = 0;
    while(fd >= 0 && pe_fd_is_exec_target(fd))
    {
        int moved = pe_dupfd_cloexec(fd, floor);
        int e = errno;
        LIBKERN_ORIG(close)(fd);
        if(moved < 0)
        {
            errno = e;
            return -1;
        }
        floor = moved + 1;
        fd = moved;
    }
    return fd;
}

static int pe_materialize_spooled_pipe_fd(int slot)
{
    if(g_checkpoint == NULL || slot < 0 || slot >= PE_MAX_LOCAL_PIPES)
    {
        errno = EINVAL;
        return -1;
    }
    
    pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
    if(!pipe_state->used || !pipe_state->spool_active)
    {
        errno = EINVAL;
        return -1;
    }
    if(pipe_state->spool_read_offset > pipe_state->spool_length)
    {
        errno = EIO;
        return -1;
    }
    
    size_t unread = pipe_state->spool_length - pipe_state->spool_read_offset;
    char tmp_path[PATH_MAX];
    int fd = -1;
    int last_errno = ENOENT;
    const char *tmpdir = getenv("TMPDIR");
    if(tmpdir != NULL && tmpdir[0] != '\0')
    {
        size_t n = strlen(tmpdir);
        const char *sep = (n > 0 && tmpdir[n - 1] == '/') ? "" : "/";
        
        int written = snprintf(tmp_path, sizeof(tmp_path), "%s%spefork-spool.%d.%d.XXXXXX", tmpdir, sep, getpid(), slot);
        if(written > 0 && (size_t)written < sizeof(tmp_path))
        {
            fd = mkstemp(tmp_path);
            if(fd < 0)
            {
                last_errno = errno;
            }
        }
        else
        {
            last_errno = ENAMETOOLONG;
        }
    }
    
    if(fd < 0 && g_checkpoint->saved_cwd_path_valid && g_checkpoint->cwd[0] != '\0')
    {
        const char *cwd = g_checkpoint->cwd;
        size_t n = strlen(cwd);
        const char *sep = (n > 0 && cwd[n - 1] == '/') ? "" : "/";
        
        int written = snprintf(tmp_path, sizeof(tmp_path), "%s%s.pefork-spool.%d.%d.XXXXXX", cwd, sep, getpid(), slot);
        if(written > 0 && (size_t)written < sizeof(tmp_path))
        {
            fd = mkstemp(tmp_path);
            if(fd < 0)
            {
                last_errno = errno;
            }
        }
        else
        {
            last_errno = ENAMETOOLONG;
        }
    }
    
    if(fd < 0)
    {
        errno = last_errno;
        return -1;
    }
    
    if(unlink(tmp_path) != 0)
    {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    
    pe_force_cloexec(fd);
    
    const uint8_t *src = (const uint8_t *)(pipe_state->spool_buffer + pipe_state->spool_read_offset);
    size_t written = 0;
    
    while(written < unread)
    {
        ssize_t n = write(fd, src + written, unread - written);
        if(n < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
            
            int e = errno;
            close(fd);
            errno = e;
            return -1;
        }
        if(n == 0)
        {
            close(fd);
            errno = EIO;
            return -1;
        }
        written += (size_t)n;
    }
    
    if(lseek(fd, 0, SEEK_SET) < 0)
    {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    
    return pe_move_fd_off_exec_targets(fd);
}

static void pe_close_exec_spool_fds(int spool_fds[PE_MAX_LOCAL_PIPES])
{
    if(spool_fds == NULL)
    {
        return;
    }
    
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
    {
        if(spool_fds[slot] >= 0)
        {
            close(spool_fds[slot]);
            spool_fds[slot] = -1;
        }
    }
}

static bool pe_build_pending_spawn_actions(posix_spawn_file_actions_t *actions,
                                           int spool_fds[PE_MAX_LOCAL_PIPES])
{
    int rc = posix_spawn_file_actions_init(actions);
    if(rc != 0)
    {
        errno = rc;
        return false;
    }
    
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
    {
        spool_fds[slot] = -1;
    }
    
    if(rc == 0)
    {
        if(g_checkpoint->pending_exec_cwd_fd >= 0)
        {
            extern int bypass_addfchdir(posix_spawn_file_actions_t *, int) __asm__("_posix_spawn_file_actions_addfchdir_np");
            rc = bypass_addfchdir(actions, g_checkpoint->pending_exec_cwd_fd);
        }
        else if(g_checkpoint->pending_exec_cwd[0] != '\0')
        {
            extern int bypass_addchdir(posix_spawn_file_actions_t *, const char *cwd) __asm__("_posix_spawn_file_actions_addchdir_np");
            rc = bypass_addchdir(actions, g_checkpoint->pending_exec_cwd);
        }
    }
    
    for(size_t i = 0; i < g_checkpoint->tracked_fd_limit && rc == 0; i++)
    {
        int fd = (int)i;
        if(pe_fd_is_exec_target(fd) || pe_fd_is_exec_carrier(fd))
        {
            continue;
        }
        
        if(fcntl(fd, F_GETFD) < 0)
        {
            continue;
        }
        
        rc = posix_spawn_file_actions_addclose(actions, fd);
    }
    
    for(size_t i = 0; i < g_checkpoint->exec_fd_count && rc == 0; i++)
    {
        int source_fd = g_checkpoint->exec_fd_carrier[i];
        int slot = g_checkpoint->exec_fd_pipe_slot[i];
        
        if(g_checkpoint->exec_fd_pipe_role[i] == PE_PIPE_ROLE_READ &&
           slot >= 0 && slot < PE_MAX_LOCAL_PIPES)
        {
            pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
            
            if(pipe_state->used &&
               pipe_state->spool_active &&
               pipe_state->spool_length > pipe_state->spool_read_offset)
            {
                if(spool_fds[slot] < 0)
                {
                    spool_fds[slot] = pe_materialize_spooled_pipe_fd(slot);
                    if(spool_fds[slot] < 0)
                    {
                        rc = errno ? errno : EIO;
                        break;
                    }
                }
                source_fd = spool_fds[slot];
            }
        }
        
        rc = posix_spawn_file_actions_adddup2(actions, source_fd, g_checkpoint->exec_fd_target[i]);
    }
    
    for(size_t i = 0; i < g_checkpoint->exec_fd_count && rc == 0; i++)
    {
        rc = posix_spawn_file_actions_addclose(actions, g_checkpoint->exec_fd_carrier[i]);
    }
    for(int slot = 0; slot < PE_MAX_LOCAL_PIPES && rc == 0; slot++)
    {
        if(spool_fds[slot] >= 0)
        {
            rc = posix_spawn_file_actions_addclose(actions, spool_fds[slot]);
        }
    }
    
    if(rc != 0)
    {
        posix_spawn_file_actions_destroy(actions);
        pe_close_exec_spool_fds(spool_fds);
        errno = rc;
        return false;
    }
    
    return true;
}

typedef enum {
    PE_PSFA_OPEN = 0,
    PE_PSFA_CLOSE = 1,
    PE_PSFA_DUP2 = 2,
    PE_PSFA_INHERIT = 3,
    PE_PSFA_FILEPORT_DUP2 = 4,
    PE_PSFA_CHDIR = 5,
    PE_PSFA_FCHDIR = 6,
} pe_psfa_t;

typedef struct {
    pe_psfa_t type;
    union {
        int filedes;
        mach_port_name_t fileport;
    };
    union {
        struct {
            int oflag;
            mode_t mode;
            char path[PATH_MAX];
        } openargs;
        struct {
            int newfiledes;
        } dup2args;
        struct {
            char path[PATH_MAX];
        } chdirargs;
    };
} pe_psfa_action_t;

typedef struct {
    int alloc;
    int count;
    pe_psfa_action_t acts[];
} *pe_psfa_list_t;

#define PE_SPAWN_SYNC_MAX_FDS 64

static void pe_spawn_sync_release_bootstrap(mach_port_t *port)
{
    if(MACH_PORT_VALID(*port)) mach_port_deallocate(mach_task_self(), *port);
}

static size_t pe_spawn_sync_strv_size(char *const v[], uint32_t *count)
{
    size_t size = 0;
    uint32_t n = 0;
    for(; v != NULL && v[n] != NULL; n++)
    {
        size += strlen(v[n]) + 1;
    }
    *count = n;
    return size;
}

static char *pe_spawn_sync_put_strv(char *cursor, char *const v[], uint32_t count)
{
    for(uint32_t i = 0; i < count; i++)
    {
        size_t len = strlen(v[i]) + 1;
        memcpy(cursor, v[i], len);
        cursor += len;
    }
    return cursor;
}

static bool pe_spawn_sync_search(const char *name, char *const envp[], char *out, size_t outsz)
{
    const char *path_env = "/usr/bin:/bin:/usr/sbin:/sbin";
    for(size_t i = 0; envp != NULL && envp[i] != NULL; i++)
    {
        if(strncmp(envp[i], "PATH=", 5) == 0)
        {
            path_env = envp[i] + 5;
            break;
        }
    }
    const char *dir = path_env;
    while(*dir != '\0')
    {
        const char *colon = strchr(dir, ':');
        size_t len = colon ? (size_t)(colon - dir) : strlen(dir);
        if(len > 0 && snprintf(out, outsz, "%.*s/%s", (int)len, dir, name) < (int)outsz && access(out, X_OK) == 0)
        {
            return true;
        }
        if(colon == NULL)
        {
            break;
        }
        dir = colon + 1;
    }
    return false;
}

static int pe_spawn_sync(pid_t *pid,
                         const char *path,
                         bool search_path,
                         const posix_spawn_file_actions_t *actions,
                         short flags,
                         char *const argv[],
                         char *const envp[])
{
    char resolved[PATH_MAX];
    if(search_path && strchr(path, '/') == NULL)
    {
        if(!pe_spawn_sync_search(path, envp, resolved, sizeof(resolved)))
        {
            return ENOENT;
        }
        path = resolved;
    }
    
    int32_t targets[PE_SPAWN_SYNC_MAX_FDS];
    int sources[PE_SPAWN_SYNC_MAX_FDS];
    uint32_t fd_count = 0;
    char cwd[PATH_MAX] = "";
    
    pe_psfa_list_t list = (actions != NULL) ? *(pe_psfa_list_t *)actions : NULL;
    for(int i = 0; list != NULL && i < list->count; i++)
    {
        pe_psfa_action_t *action = &list->acts[i];
        switch(action->type)
        {
            case PE_PSFA_DUP2:
            case PE_PSFA_INHERIT:
            {
                int target = (action->type == PE_PSFA_DUP2) ? action->dup2args.newfiledes : action->filedes;
                int source = action->filedes;
                
                for(uint32_t j = 0; j < fd_count; j++)
                {
                    if(targets[j] == source)
                    {
                        source = sources[j];
                        break;
                    }
                }
                uint32_t slot = fd_count;
                for(uint32_t j = 0; j < fd_count; j++)
                {
                    if(targets[j] == target)
                    {
                        slot = j;
                        break;
                    }
                }
                if(slot == fd_count)
                {
                    if(fd_count == PE_SPAWN_SYNC_MAX_FDS)
                    {
                        return EMFILE;
                    }
                    fd_count++;
                }
                targets[slot] = target;
                sources[slot] = source;
                break;
            }
            case PE_PSFA_CLOSE:
                for(uint32_t j = 0; j < fd_count; j++)
                {
                    if(targets[j] == action->filedes)
                    {
                        targets[j] = targets[fd_count - 1];
                        sources[j] = sources[fd_count - 1];
                        fd_count--;
                        break;
                    }
                }
                break;
            case PE_PSFA_CHDIR:
                strlcpy(cwd, action->chdirargs.path, sizeof(cwd));
                break;
            case PE_PSFA_FCHDIR:
                if(fcntl(action->filedes, F_GETPATH, cwd) == -1)
                {
                    cwd[0] = '\0';
                }
                break;
            default:
                
                return ENOTSUP;
        }
    }
    if(cwd[0] == '\0' && getcwd(cwd, sizeof(cwd)) == NULL)
    {
        strlcpy(cwd, "/", sizeof(cwd));
    }
    
    bool bootstrapPresent = false;
    mach_port_t bootstrap __attribute__((cleanup(pe_spawn_sync_release_bootstrap))) = MACH_PORT_NULL;
    int bootstrapError = pe_spawn_bootstrap_copy(NULL, &bootstrapPresent, &bootstrap);
    if(bootstrapError != 0) return bootstrapError;
    if(MACH_PORT_VALID(bootstrap) && fd_count == PE_SPAWN_SYNC_MAX_FDS) return E2BIG;
    size_t header_size = bootstrapPresent ? sizeof(ksurface_spawn_request_v2_t) : sizeof(ksurface_spawn_request_t);
    
    mach_port_t ports[PE_SPAWN_SYNC_MAX_FDS];
    for(uint32_t i = 0; i < fd_count; i++)
    {
        pe_fileport_t port = MACH_PORT_NULL;
        if(fileport_makeport(sources[i], &port) != 0)
        {
            for(uint32_t j = 0; j < i; j++)
            {
                mach_port_deallocate(mach_task_self(), ports[j]);
            }
            return EBADF;
        }
        ports[i] = port;
    }
    
    uint32_t argc = 0, envc = 0;
    size_t size = header_size + fd_count * sizeof(int32_t) + strlen(cwd) + 1 +
    pe_spawn_sync_strv_size(argv, &argc) + pe_spawn_sync_strv_size(envp, &envc);
    char *request = (size <= KSURFACE_SPAWN_REQUEST_MAX) ? malloc(size) : NULL;
    if(request == NULL)
    {
        for(uint32_t i = 0; i < fd_count; i++)
        {
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
        return size > KSURFACE_SPAWN_REQUEST_MAX ? E2BIG : ENOMEM;
    }
    ksurface_spawn_request_v2_t header = { .base = {
        .version = bootstrapPresent ? KSURFACE_SPAWN_REQUEST_VERSION_2 : KSURFACE_SPAWN_REQUEST_VERSION,
        .argc = argc,
        .envc = envc,
        .fd_count = fd_count,
        .flags = flags & (POSIX_SPAWN_SETSID | POSIX_SPAWN_SETPGROUP),
        .pgroup = 0,
    }, .attributes = bootstrapPresent ? KSURFACE_SPAWN_BOOTSTRAP |
        (bootstrap == MACH_PORT_NULL ? KSURFACE_SPAWN_BOOTSTRAP_NULL : 0) : 0 };
    char *cursor = request;
    memcpy(cursor, &header, header_size);
    cursor += header_size;
    memcpy(cursor, targets, fd_count * sizeof(int32_t));
    cursor += fd_count * sizeof(int32_t);
    memcpy(cursor, cwd, strlen(cwd) + 1);
    cursor += strlen(cwd) + 1;
    cursor = pe_spawn_sync_put_strv(cursor, argv, argc);
    pe_spawn_sync_put_strv(cursor, envp, envc);
    
    uint32_t port_count = fd_count;
    if(MACH_PORT_VALID(bootstrap)) ports[port_count++] = bootstrap;
    int64_t args[6] = { (int64_t)(uintptr_t)path, (int64_t)(uintptr_t)request, (int64_t)size, 0, 0, 0 };
    int64_t result = liveshim_syscall_invoke(syscallProxy, SYS_spawn, args, ports, port_count, MACH_MSG_TYPE_COPY_SEND, NULL, 0);
    int spawn_errno = errno;
    for(uint32_t i = 0; i < fd_count; i++) mach_port_deallocate(mach_task_self(), ports[i]);
    free(request);
    
    if(result < 0)
    {
        return spawn_errno ? spawn_errno : EAGAIN;
    }
    
    *pid = (pid_t)result;
    
    liveshim_syscall(SYS_waittask, *pid);
    
    return 0;
}

static int pe_spawn_call(pid_t *pid,
                         const char *path,
                         bool search_path,
                         const posix_spawn_file_actions_t *actions,
                         posix_spawnattr_t *attr,
                         short base_flags,
                         char *const argv[],
                         char *const envp[])
{
    if(g_pe_nested_spawn_enabled && g_checkpoint != NULL && g_checkpoint->level > 0 && syscallProxy != NULL)
    {
        return pe_spawn_sync(pid, path, search_path, actions, base_flags, argv, envp);
    }
    
    short flags = base_flags;
#if PE_USE_SPAWN_CLOEXEC_DEFAULT && defined(POSIX_SPAWN_CLOEXEC_DEFAULT)
    bool const use_cloexec_default = (attr != NULL && g_pe_spawn_cloexec_default_usable);
    if(use_cloexec_default)
    {
        flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
    }
#endif /* PE_USE_SPAWN_CLOEXEC_DEFAULT && defined(POSIX_SPAWN_CLOEXEC_DEFAULT) */
    if(attr != NULL)
    {
        posix_spawnattr_setflags(attr, flags);
    }
    
    int rc = search_path
    ? posix_spawnp(pid, path, actions, attr, argv, envp)
    : posix_spawn(pid, path, actions, attr, argv, envp);
    
#if PE_USE_SPAWN_CLOEXEC_DEFAULT && defined(POSIX_SPAWN_CLOEXEC_DEFAULT)
    if(rc == EINVAL && use_cloexec_default)
    {
        g_pe_spawn_cloexec_default_usable = false;
        posix_spawnattr_setflags(attr, base_flags);
        rc = search_path
        ? posix_spawnp(pid, path, actions, attr, argv, envp)
        : posix_spawn(pid, path, actions, attr, argv, envp);
    }
#endif /* PE_USE_SPAWN_CLOEXEC_DEFAULT && defined(POSIX_SPAWN_CLOEXEC_DEFAULT) */
    
    return rc;
}

static pid_t pe_spawn_pending_exec_after_restore(void)
{
    if(!g_checkpoint->pending_exec ||
       g_checkpoint->pending_exec_path == NULL ||
       g_checkpoint->pending_exec_argv == NULL)
    {
        errno = EFAULT;
        return -1;
    }
    
    posix_spawn_file_actions_t actions;
    int exec_spool_fds[PE_MAX_LOCAL_PIPES];
    if(!pe_build_pending_spawn_actions(&actions, exec_spool_fds))
    {
        return -1;
    }
    
    posix_spawnattr_t attr;
    bool attr_ok = (posix_spawnattr_init(&attr) == 0);
    short spawn_flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    if(attr_ok)
    {
        if(g_checkpoint->pending_setsid)
        {
            spawn_flags |= POSIX_SPAWN_SETSID;
        }
        
        posix_spawnattr_setsigdefault(&attr, &g_checkpoint->pending_exec_sigdefault);
        posix_spawnattr_setsigmask(&attr, &g_checkpoint->pending_exec_sigmask);
    }
    
    pid_t spawned_pid = -1;
    int rc = pe_spawn_call(&spawned_pid,
                           g_checkpoint->pending_exec_path,
                           g_checkpoint->pending_exec_find_binary,
                           &actions,
                           attr_ok ? &attr : NULL,
                           spawn_flags,
                           g_checkpoint->pending_exec_argv,
                           g_checkpoint->pending_exec_envp);
    
    int spawn_errno = rc;
    
    if(rc == 0 && !g_checkpoint->pending_setsid && g_checkpoint->pending_pgrp_set)
    {
        pid_t pgrp = g_checkpoint->pending_pgrp != 0 ? g_checkpoint->pending_pgrp : spawned_pid;
        setpgid(spawned_pid, pgrp);
        
        if(g_checkpoint->pending_tcsetpgrp_fd >= 0)
        {
            tcsetpgrp(g_checkpoint->pending_tcsetpgrp_fd, pgrp);
        }
    }
    
    if(rc == 0)
    {
        for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
        {
            if(exec_spool_fds[slot] >= 0 &&
               g_checkpoint->local_pipes[slot].used &&
               g_checkpoint->local_pipes[slot].spool_active)
            {
                g_checkpoint->local_pipes[slot].spool_read_offset = g_checkpoint->local_pipes[slot].spool_length;
            }
        }
    }
    
    pe_close_exec_spool_fds(exec_spool_fds);
    
    if(attr_ok)
    {
        posix_spawnattr_destroy(&attr);
    }
    
    posix_spawn_file_actions_destroy(&actions);
    
    if(rc != 0)
    {
        errno = spawn_errno;
        return -1;
    }
    
    return spawned_pid;
}

static void pe_report_deferred_exec_failure(int error)
{
    int err_fd = STDERR_FILENO;
    for(size_t i = 0; i < g_checkpoint->exec_fd_count; i++)
    {
        if(g_checkpoint->exec_fd_target[i] == STDERR_FILENO)
        {
            err_fd = g_checkpoint->exec_fd_carrier[i];
            break;
        }
    }
    
    const char *path = g_checkpoint->pending_exec_path ? g_checkpoint->pending_exec_path : "exec";
    dprintf(err_fd, "%s: %s\n", path, strerror(error));
}

static __attribute__((noreturn)) void pe_defer_exec_and_restore(const char *path,
                                                                char *const argv[],
                                                                char *const envp[],
                                                                bool find_binary)
{
    char abspath[PATH_MAX];
    if(path != NULL && path[0] != '\0' && path[0] != '/')
    {
        char cwdbuf[PATH_MAX];
        if(getcwd(cwdbuf, sizeof(cwdbuf)) != NULL)
        {
            int n = snprintf(abspath, sizeof(abspath), "%s/%s", cwdbuf, path);
            if(n > 0 && (size_t)n < sizeof(abspath))
            {
                path = abspath;
            }
        }
    }
    
    g_checkpoint->pending_exec_path = pe_scratch_strdup(path);
    g_checkpoint->pending_exec_argv = pe_scratch_dup_strv(argv);
    g_checkpoint->pending_exec_envp = pe_scratch_dup_strv(envp);
    g_checkpoint->pending_exec_find_binary = find_binary;
    g_checkpoint->pending_exec_cwd_fd = -1;
    g_checkpoint->pending_exec_cwd[0] = '\0';
    
    if(getcwd(g_checkpoint->pending_exec_cwd,
              sizeof(g_checkpoint->pending_exec_cwd)) == NULL)
    {
        g_checkpoint->pending_exec_cwd[0] = '\0';
    }
    
    g_checkpoint->pending_exec_cwd_fd = pe_capture_cwd_fd();
    
    sigemptyset(&g_checkpoint->pending_exec_sigdefault);
    for(int sig = 1; sig < NSIG; sig++)
    {
        if(sig == SIGKILL || sig == SIGSTOP)
        {
            continue;
        }
        struct sigaction sa;
        if(sigaction(sig, NULL, &sa) == 0 &&
           (sa.sa_flags & SA_SIGINFO) == 0 &&
           sa.sa_handler == SIG_DFL)
        {
            sigaddset(&g_checkpoint->pending_exec_sigdefault, sig);
        }
    }
    if(pthread_sigmask(SIG_SETMASK, NULL, &g_checkpoint->pending_exec_sigmask) != 0)
    {
        sigemptyset(&g_checkpoint->pending_exec_sigmask);
    }
    
    if(g_checkpoint->pending_exec_cwd_fd < 0 &&
       g_checkpoint->pending_exec_cwd[0] == '\0')
    {
        errno = 0;
    }
    
    bool const vectors_ok =
    g_checkpoint->pending_exec_path != NULL &&
    g_checkpoint->pending_exec_argv != NULL &&
    (envp == NULL || g_checkpoint->pending_exec_envp != NULL);
    
    bool const fds_ok = vectors_ok && pe_snapshot_exec_fds();
    
    if(!vectors_ok || !fds_ok)
    {
        int e = errno ? errno : ENOMEM;
        
        g_checkpoint->pending_exec = false;
        g_checkpoint->synthetic_child = true;
        g_checkpoint->synthetic_wait_status = (127 & 0xff) << 8;
        g_checkpoint->return_pid = pe_allocate_synthetic_pid();
        g_checkpoint->restore_errno = e;
    }
    else
    {
        g_checkpoint->pending_exec = true;
        g_checkpoint->synthetic_child = false;
        g_checkpoint->return_pid = PE_EXEC_PENDING_PID;
        g_checkpoint->restore_errno = 0;
    }
    
    g_checkpoint->helper_action = PE_HELPER_RESTORE;
    semaphore_signal(g_checkpoint->request_semaphore);
    
    thread_suspend(g_checkpoint->target_thread);
    __builtin_unreachable();
}

__attribute__((optnone))
static pid_t pe_time_travel_fork(void)
{
    if(!pe_checkpoint_runtime_init())
    {
        return -1;
    }
    
    if(!g_checkpoint->checkpoint_active)
    {
        pe_config_refresh_from_env();
    }
    
    if(g_checkpoint->checkpoint_active)
    {
        bool const active_fake_child = local_fork_checkpoint == g_checkpoint && g_checkpoint->checkpoint_ok && !g_checkpoint->restoring && !g_checkpoint->pending_exec && g_checkpoint->return_pid == 0;
        
        if(!active_fake_child)
        {
            errno = EAGAIN;
            return -1;
        }
        
        if(!g_pe_nested_enabled || !pe_checkpoint_push_level())
        {
            if(g_checkpoint->collapsed_nested_forks >= 8)
            {
                errno = EAGAIN;
                return -1;
            }
            
            g_checkpoint->collapsed_nested_forks++;
            
            return 0;
        }
    }
    
    if(__atomic_test_and_set(&g_checkpoint->checkpoint_claimed, __ATOMIC_ACQUIRE))
    {
        pe_checkpoint_pop_level();
        errno = EAGAIN;
        return -1;
    }
    
    pe_scratch_reset();
    g_checkpoint->checkpoint_serial = ++g_arena_header->serial_counter;
    if(g_checkpoint->checkpoint_serial == 0)
    {
        g_checkpoint->checkpoint_serial = ++g_arena_header->serial_counter;
    }
    g_checkpoint->checkpoint_active = true;
    g_checkpoint->checkpoint_ok = false;
    g_checkpoint->restoring = false;
    g_checkpoint->return_pid = 0;
    g_checkpoint->restore_errno = 0;
    g_checkpoint->synthetic_child = false;
    g_checkpoint->synthetic_wait_status = 0;
    g_checkpoint->collapsed_nested_forks = 0;
    g_checkpoint->pending_exec = false;
    g_checkpoint->pending_exec_find_binary = false;
    g_checkpoint->pending_exec_path = NULL;
    g_checkpoint->pending_exec_argv = NULL;
    g_checkpoint->pending_exec_envp = NULL;
    g_checkpoint->pending_exec_cwd[0] = '\0';
    g_checkpoint->pending_exec_cwd_fd = -1;
    g_checkpoint->saved_cwd_fd = -1;
    g_checkpoint->saved_cwd_path_valid = false;
    g_checkpoint->cwd[0] = '\0';
    g_checkpoint->fd_op_count = 0;
    g_checkpoint->exec_fd_count = 0;
    g_checkpoint->vm_regions = NULL;
    g_checkpoint->vm_region_count = 0;
    g_checkpoint->other_stack_count = 0;
    g_checkpoint->frozen_threads = NULL;
    g_checkpoint->frozen_count = 0;
    g_checkpoint->fake_child_pid = getpid();
    g_checkpoint->pending_setsid = false;
    g_checkpoint->pending_pgrp_set = false;
    g_checkpoint->pending_pgrp = 0;
    g_checkpoint->pending_tcsetpgrp_fd = -1;
    g_checkpoint->pending_ctty_fd = -1;
    g_checkpoint->target_state_valid = false;
    g_checkpoint->target_thread = mach_thread_self();
    
    {
        pthread_t self = pthread_self();
        g_checkpoint->target_pthread = self;
        mach_vm_address_t stack_high = (mach_vm_address_t)pthread_get_stackaddr_np(self);
        size_t stack_size = pthread_get_stacksize_np(self);
        g_checkpoint->target_stack_high = stack_high;
        g_checkpoint->target_stack_low = (stack_size < stack_high) ? stack_high - stack_size : 0;
    }
    
    local_fork_checkpoint = g_checkpoint;
    
    if(!pe_capture_process_state())
    {
        int e = errno ? errno : EFAULT;
        
        pe_checkpoint_cleanup_parent();
        errno = e;
        return -1;
    }
    
    pe_capture_other_thread_stacks();
    
    pe_atfork_prepare();
    
    g_checkpoint->helper_action = PE_HELPER_CAPTURE;
    semaphore_signal(g_checkpoint->request_semaphore);
    
    thread_suspend(g_checkpoint->target_thread);
    
    if(!g_checkpoint->checkpoint_ok || g_checkpoint->return_pid < 0)
    {
        pe_atfork_release();
        pe_thaw_other_threads();
        
        int e = g_checkpoint->restore_errno ? g_checkpoint->restore_errno : EFAULT;
        pe_checkpoint_cleanup_parent();
        errno = e;
        return -1;
    }
    
    if(g_checkpoint->return_pid == 0)
    {
        pe_atfork_release();
        
        return 0;
    }
    
    pe_atfork_release();
    pe_thaw_other_threads();
    
    pid_t pid = g_checkpoint->return_pid;
    pthread_sigmask(SIG_SETMASK, &g_checkpoint->saved_sigmask, NULL);
    
    if(g_checkpoint->pending_exec)
    {
        pid = pe_spawn_pending_exec_after_restore();
        if(pid < 0)
        {
            int spawn_error = errno ? errno : ENOEXEC;
            
            pe_report_deferred_exec_failure(spawn_error);
            pid = pe_allocate_synthetic_pid();
            g_checkpoint->synthetic_child = true;
            g_checkpoint->synthetic_wait_status = ((spawn_error == ENOENT ? 127 : 126) & 0xff) << 8;
            g_checkpoint->restore_errno = 0;
        }
        else
        {
            g_checkpoint->synthetic_child = false;
        }
        g_checkpoint->return_pid = pid;
        g_checkpoint->pending_exec = false;
    }
    
    pe_checkpoint_cleanup_parent();
    
    return pid;
}

static __attribute__((noreturn)) void pe_finish_fake_child(int code)
{
    pe_pipe_mark_fake_child_done();
    g_checkpoint->synthetic_child = true;
    g_checkpoint->synthetic_wait_status = (code & 0xff) << 8;
    g_checkpoint->return_pid = pe_allocate_synthetic_pid();
    g_checkpoint->helper_action = PE_HELPER_RESTORE;
    semaphore_signal(g_checkpoint->request_semaphore);
    thread_suspend(g_checkpoint->target_thread);
    __builtin_unreachable();
}

static __attribute__((noreturn)) void pe_finish_exec_child(pid_t spawned_pid)
{
    g_checkpoint->synthetic_child = false;
    g_checkpoint->return_pid = spawned_pid;
    g_checkpoint->helper_action = PE_HELPER_RESTORE;
    semaphore_signal(g_checkpoint->request_semaphore);
    thread_suspend(g_checkpoint->target_thread);
    __builtin_unreachable();
}

#pragma mark - fork() and vfork() hook

LIBKERN_PATCH(pid_t, vfork, (void),
__attribute__((optnone)) {
    return pe_time_travel_fork();
});

LIBKERN_PATCH(pid_t, fork, (void),
__attribute__((optnone)) {
    return pe_time_travel_fork();
});

#pragma mark - exec*() hook symbol family helpers

static int PEArgcFromArgv(char *const argv[])
{
    if(argv == NULL)
    {
        return 0;
    }
    int argc = 0;
    while(argv[argc] != NULL)
    {
        argc++;
    }
    return argc;
}

static bool pe_resolve_exec_path(const char *file,
                                 char *out,
                                 size_t out_size)
{
    if(file == NULL || file[0] == '\0')
    {
        errno = ENOENT;
        return false;
    }
    
    if(strchr(file, '/') != NULL)
    {
        if(strlcpy(out, file, out_size) >= out_size)
        {
            errno = ENAMETOOLONG;
            return false;
        }
        return true;
    }
    
    const char *search = getenv("PATH");
    if(search == NULL || search[0] == '\0')
    {
        search = "/usr/bin:/bin:/usr/sbin:/sbin";
    }
    
    int last_errno = ENOENT;
    const char *p = search;
    for(;;)
    {
        const char *end = strchr(p, ':');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        
        int n = (len == 0)
        ? snprintf(out, out_size, "%s", file)
        : snprintf(out, out_size, "%.*s/%s", (int)len, p, file);
        
        if(n > 0 && (size_t)n < out_size)
        {
            struct stat st;
            if(stat(out, &st) == 0)
            {
                if(S_ISREG(st.st_mode))
                {
                    return true;
                }
                last_errno = EACCES;
            }
            else if(errno == EACCES)
            {
                last_errno = EACCES;
            }
        }
        
        if(end == NULL)
        {
            break;
        }
        p = end + 1;
    }
    
    errno = last_errno;
    return false;
}

static kern_return_t PETearDownOwnTask(void)
{
    task_t task = mach_task_self();
    thread_t self = mach_thread_self();
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t threadCount = 0;
    kern_return_t kr = task_threads(task, &threads, &threadCount);
    
    if(kr != KERN_SUCCESS)
    {
        mach_port_deallocate(task, self);
        return kr;
    }
    
    kern_return_t result = KERN_SUCCESS;
    for(mach_msg_type_number_t i = 0; i < threadCount; i++)
    {
        thread_t thread = threads[i];
        if(thread == self)
        {
            continue;
        }
        
        kern_return_t suspendKR = thread_suspend(thread);
        if(suspendKR != KERN_SUCCESS && result == KERN_SUCCESS)
        {
            result = suspendKR;
        }
    }
    
    for(mach_msg_type_number_t i = 0; i < threadCount; i++)
    {
        thread_t thread = threads[i];
        if(thread != self)
        {
            kern_return_t terminateKR = thread_terminate(thread);
            if(terminateKR != KERN_SUCCESS)
            {
                thread_resume(thread);
                if(result == KERN_SUCCESS)
                {
                    result = terminateKR;
                }
            }
        }
        mach_port_deallocate(task, thread);
    }
    
    vm_deallocate(task, (vm_address_t)threads, threadCount * sizeof(thread_t));
    mach_port_deallocate(task, self);
    return result;
}

#pragma mark - exec emulation for real (non fake child) processes

static volatile pid_t g_pe_exec_child = -1;

static void pe_exec_forward_signal(int sig)
{
    pid_t child = g_pe_exec_child;
    if(child > 0)
    {
        kill(child, sig);
    }
}

static bool pe_exec_inplace_requested(void)
{
    const char *mode = getenv("PEFORK_EXEC");
    return mode != NULL && strcmp(mode, "inplace") == 0;
}

static int pe_exec_via_spawn(const char *path,
                             char *const argv[],
                             char *const envp[])
{
    posix_spawn_file_actions_t actions;
    int rc = posix_spawn_file_actions_init(&actions);
    if(rc != 0)
    {
        errno = rc;
        return -1;
    }
    
    size_t limit = 256;
    struct rlimit rl;
    if(getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur > 0 && rl.rlim_cur != RLIM_INFINITY)
    {
        limit = (size_t)rl.rlim_cur;
    }
    if(limit > PE_MAX_TRACKED_FDS)
    {
        limit = PE_MAX_TRACKED_FDS;
    }
    
    int carriers[PE_MAX_EXEC_FDS];
    int targets[PE_MAX_EXEC_FDS];
    size_t count = 0;
    for(int fd = 0; fd < (int)limit && rc == 0; fd++)
    {
        int flags = fcntl(fd, F_GETFD);
        if(flags < 0 || (flags & FD_CLOEXEC))
        {
            continue;
        }
        
        if(count >= PE_MAX_EXEC_FDS)
        {
            break;
        }
        
        int carrier = pe_dupfd_cloexec(fd, 0);
        if(carrier < 0)
        {
            continue;
        }
        
        carriers[count] = carrier;
        targets[count] = fd;
        count++;
        rc = posix_spawn_file_actions_adddup2(&actions, carrier, fd);
    }
    
    int cwd_fd = open(".", O_RDONLY | O_CLOEXEC);
    pe_force_cloexec(cwd_fd);
    if(rc == 0 && cwd_fd >= 0)
    {
        extern int pe_exec_bypass_addfchdir(posix_spawn_file_actions_t *, int) __asm__("_posix_spawn_file_actions_addfchdir_np");
        rc = pe_exec_bypass_addfchdir(&actions, cwd_fd);
    }
    
    for(int fd = 0; fd < (int)limit && rc == 0; fd++)
    {
        bool is_target = false;
        for(size_t i = 0; i < count; i++)
        {
            if(targets[i] == fd)
            {
                is_target = true;
                break;
            }
        }
        if(is_target || fcntl(fd, F_GETFD) < 0)
        {
            continue;
        }
        
        rc = posix_spawn_file_actions_addclose(&actions, fd);
    }
    
    posix_spawnattr_t attr;
    bool attr_ok = (posix_spawnattr_init(&attr) == 0);
    if(attr_ok)
    {
        sigset_t sigdefault;
        sigset_t sigmask;
        sigemptyset(&sigdefault);
        for(int sig = 1; sig < NSIG; sig++)
        {
            if(sig == SIGKILL || sig == SIGSTOP)
            {
                continue;
            }
            struct sigaction sa;
            if(sigaction(sig, NULL, &sa) == 0 && sa.sa_handler != SIG_IGN)
            {
                sigaddset(&sigdefault, sig);
            }
        }
        if(pthread_sigmask(SIG_SETMASK, NULL, &sigmask) != 0)
        {
            sigemptyset(&sigmask);
        }
        posix_spawnattr_setsigdefault(&attr, &sigdefault);
        posix_spawnattr_setsigmask(&attr, &sigmask);
    }
    
    pid_t child = -1;
    if(rc == 0)
    {
        rc = pe_spawn_call(&child, path, false, &actions,
                           attr_ok ? &attr : NULL,
                           POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK,
                           argv, envp);
    }
    
    for(size_t i = 0; i < count; i++)
    {
        close(carriers[i]);
    }
    if(cwd_fd >= 0)
    {
        close(cwd_fd);
    }
    if(attr_ok)
    {
        posix_spawnattr_destroy(&attr);
    }
    posix_spawn_file_actions_destroy(&actions);
    
    if(rc != 0)
    {
        errno = rc;
        return -1;
    }
    
    g_pe_exec_child = child;
    
    for(size_t i = 0; i < count; i++)
    {
        if(targets[i] > STDERR_FILENO)
        {
            close(targets[i]);
        }
    }
    
    static const int forwarded[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2, SIGWINCH, SIGCONT, SIGALRM };
    for(size_t i = 0; i < sizeof(forwarded) / sizeof(forwarded[0]); i++)
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = pe_exec_forward_signal;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(forwarded[i], &sa, NULL);
    }
    
    int status = 0;
    for(;;)
    {
        pid_t w = waitpid(child, &status, 0);
        if(w == child)
        {
            break;
        }
        if(w < 0 && errno != EINTR)
        {
            _exit(127);
        }
    }
    
    if(WIFEXITED(status))
    {
        _exit(WEXITSTATUS(status));
    }
    
    if(WIFSIGNALED(status))
    {
        int sig = WTERMSIG(status);
        signal(sig, SIG_DFL);
        kill(getpid(), sig);
        _exit(128 + sig);
    }
    
    _exit(127);
}

LIBKERN_DEFINE_PATCHABLE(int, environment_execvpa, (const char * __path,
                                                    char *_LIBC_CSTR const *_LIBC_NULL_TERMINATED __argv,
                                                    char *_LIBC_CSTR const *_LIBC_NULL_TERMINATED __envp,
                                                    bool find_binary) __attribute__((optnone)) )
{
    char resolved_path[PATH_MAX];
    if(find_binary)
    {
        if(!pe_resolve_exec_path(__path, resolved_path, sizeof(resolved_path)))
        {
            return -1;
        }
        __path = resolved_path;
        find_binary = false;
    }
    
    if(local_fork_checkpoint == NULL || !g_checkpoint->checkpoint_active)
    {
        if(!pe_exec_inplace_requested())
        {
            static char *const pe_empty_envp[] = { NULL };
            int r = pe_exec_via_spawn(__path, __argv, __envp != NULL ? __envp : pe_empty_envp);
            
            return r;
        }
        
        NSString *executablePath = [NSString stringWithUTF8String:__path];
        if(executablePath == nil)
        {
            errno = EFAULT;
            return -1;
        }
        
        if(__envp == NULL)
        {
            extern void clear_environment(void);
            clear_environment();
        }
        
        int argc = PEArgcFromArgv((char *const *)__argv);
        
        PETearDownOwnTask();
        
        void PEOverwriteExecutablePath(NSString *executablePath);
        PEOverwriteExecutablePath(executablePath);
        void PEInsertLibrariesIfNeeded(void);
        PEInsertLibrariesIfNeeded();
        
        exit(LCBootstrapMain(executablePath, argc, (char **)__argv));
        
        errno = EBADEXEC;
        return -1;
    }
    
    struct stat exec_st;
    if(stat(__path, &exec_st) != 0)
    {
        return -1;
    }
    if(!S_ISREG(exec_st.st_mode))
    {
        errno = EACCES;
        return -1;
    }
    
    if(!g_pe_nested_spawn_enabled || syscallProxy == NULL)
    {
        pe_checkpoint_abandon_nested_levels();
    }
    
    pe_defer_exec_and_restore(__path, __argv, __envp, false);
}

static char **argv_from_va(const char *arg0, va_list ap)
{
    va_list ap_copy;
    int argc = 0;
    va_copy(ap_copy, ap);
    for(const char *a = arg0; a; a = va_arg(ap_copy, const char *))
    {
        argc++;
    }
    va_end(ap_copy);
    char **argv = malloc((argc + 1) * sizeof(char *));
    if(!argv)
    {
        return NULL;
    }
    argv[0] = (char *)arg0;
    for(int i = 1; i < argc; i++)
    {
        argv[i] = va_arg(ap, char *);
    }
    argv[argc] = NULL;
    return argv;
}

static inline void cleanup_argv(char ***argv)
{
    free(*argv);
}

#define _cleanup_argv_ __attribute__((cleanup(cleanup_argv)))

#pragma mark - exec*() hook

LIBKERN_PATCH(int, execl, (const char *path,
                           const char *arg0,
                           ...),
              {
    va_list ap;
    va_start(ap, arg0);
    _cleanup_argv_ char **argv = argv_from_va(arg0, ap);
    va_end(ap);
    
    if(!argv)
    {
        errno = EFAULT;
        return -1;
    }
    
    return environment_execvpa(path, argv, environ, false);
});

LIBKERN_PATCH(int, execle, (const char *path,
                            const char *arg0,
                            ...),
              {
    va_list ap;
    va_start(ap, arg0);
    _cleanup_argv_ char **argv = argv_from_va(arg0, ap);
    
    while(va_arg(ap, const char *) != NULL);
    char **envp = va_arg(ap, char **);
    va_end(ap);
    
    if(!argv)
    {
        errno = EFAULT;
        return -1;
    }
    
    return environment_execvpa(path, argv, envp, false);
});

LIBKERN_PATCH(int, execlp, (const char *path,
                            const char *arg0,
                            ...),
              {
    va_list ap;
    va_start(ap, arg0);
    _cleanup_argv_ char **argv = argv_from_va(arg0, ap);
    va_end(ap);
    
    if(!argv)
    {
        errno = EFAULT;
        return -1;
    }
    
    return environment_execvpa(path, argv, environ, true);
});

LIBKERN_PATCH(int, execv, (const char * __path,
                           char *_LIBC_CSTR const *_LIBC_NULL_TERMINATED __argv),
              {
    return environment_execvpa(__path, __argv, environ, false);
});

LIBKERN_PATCH(int, execve, (const char * __file,
                            char *_LIBC_CSTR const *_LIBC_NULL_TERMINATED __argv,
                            char *_LIBC_CSTR const *_LIBC_NULL_TERMINATED __envp),
              {
    return environment_execvpa(__file, __argv, __envp, false);
});

LIBKERN_PATCH(int, execvp, (const char * __file,
                            char *_LIBC_CSTR const *_LIBC_NULL_TERMINATED __argv),
              {
    return environment_execvpa(__file, __argv, environ, true);
});

#pragma mark - file descriptor hooks

LIBKERN_PATCH(int, pipe, (int fds[2]),
              {
    int rc = LIBKERN_ORIG(pipe)(fds);
    if(rc == 0 && fds != NULL)
    {
        int slot = pe_pipe_register_pair(fds[0], fds[1]);
    }
    return rc;
});

LIBKERN_PATCH(ssize_t, write, (int fd,
                               const void *buf,
                               size_t count),
              {
    int saved_errno = errno;
    ssize_t spooled = pe_pipe_spool_write(fd, buf, count);
    if(spooled != -2)
    {
        if(spooled >= 0)
        {
            errno = saved_errno;
        }
        return spooled;
    }
    return LIBKERN_ORIG(write)(fd, buf, count);
});

LIBKERN_PATCH(ssize_t, writev, (int fd,
                                const struct iovec *iov,
                                int iovcnt),
              {
    int incoming_errno = errno;
    int slot = -1;
    if(!pe_pipe_should_spool_fd(fd, &slot))
    {
        return LIBKERN_ORIG(writev)(fd, iov, iovcnt);
    }
    
    if(iovcnt < 0 || (iovcnt > 0 && iov == NULL))
    {
        errno = EINVAL;
        return -1;
    }
    
    size_t total = 0;
    for(int i = 0; i < iovcnt; i++)
    {
        if(iov[i].iov_len > SIZE_MAX - total)
        {
            errno = EINVAL;
            return -1;
        }
        total += iov[i].iov_len;
    }
    if(total > (size_t)SSIZE_MAX)
    {
        errno = EINVAL;
        return -1;
    }
    if(total == 0)
    {
        errno = incoming_errno;
        return 0;
    }
    
    pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
    if(total > SIZE_MAX - pipe_state->spool_length || !pe_pipe_spool_reserve(pipe_state, pipe_state->spool_length + total))
    {
        return -1;
    }
    
    size_t offset = pipe_state->spool_length;
    for(int i = 0; i < iovcnt; i++)
    {
        if(iov[i].iov_len == 0)
        {
            continue;
        }
        if(iov[i].iov_base == NULL)
        {
            errno = EFAULT;
            return -1;
        }
        memcpy((void *)(pipe_state->spool_buffer + offset), iov[i].iov_base, iov[i].iov_len);
        offset += iov[i].iov_len;
    }
    
    pipe_state->spool_length = offset;
    pipe_state->spool_active = true;
    pipe_state->producer_serial = g_checkpoint->checkpoint_serial;
    pipe_state->producer_done = false;
    errno = incoming_errno;
    return (ssize_t)total;
});

LIBKERN_PATCH(ssize_t, read, (int fd,
                              void *buf,
                              size_t count),
              {
    int saved_errno = errno;
    ssize_t spooled = pe_pipe_spool_read(fd, buf, count);
    if(spooled != -2)
    {
        if(spooled >= 0)
        {
            errno = saved_errno;
        }
        return spooled;
    }
    return LIBKERN_ORIG(read)(fd, buf, count);
});

LIBKERN_PATCH(ssize_t, readv, (int fd,
                               const struct iovec *iov,
                               int iovcnt),
              {
    int incoming_errno = errno;
    if(iovcnt < 0 || (iovcnt > 0 && iov == NULL))
    {
        errno = EINVAL;
        return -1;
    }
    
    if(g_checkpoint == NULL || fd < 0 || fd >= PE_MAX_TRACKED_FDS)
    {
        return LIBKERN_ORIG(readv)(fd, iov, iovcnt);
    }
    
    int slot = g_checkpoint->pipe_fd_slot[fd];
    if(slot < 0 || slot >= PE_MAX_LOCAL_PIPES ||
       g_checkpoint->pipe_fd_role[fd] != PE_PIPE_ROLE_READ ||
       !g_checkpoint->local_pipes[slot].used ||
       !g_checkpoint->local_pipes[slot].spool_active)
    {
        return LIBKERN_ORIG(readv)(fd, iov, iovcnt);
    }
    
    pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
    size_t available = pipe_state->spool_length - pipe_state->spool_read_offset;
    if(available == 0)
    {
        if(pipe_state->producer_done && !pe_pipe_slot_has_role(slot, PE_PIPE_ROLE_WRITE))
        {
            errno = incoming_errno;
            return 0;
        }
        return LIBKERN_ORIG(readv)(fd, iov, iovcnt);
    }
    
    size_t copied = 0;
    for(int i = 0; i < iovcnt && available > 0; i++)
    {
        size_t amount = iov[i].iov_len < available ? iov[i].iov_len : available;
        if(amount == 0)
        {
            continue;
        }
        if(iov[i].iov_base == NULL)
        {
            errno = EFAULT;
            return -1;
        }
        memcpy(iov[i].iov_base, (const void *)(pipe_state->spool_buffer + pipe_state->spool_read_offset), amount);
        pipe_state->spool_read_offset += amount;
        available -= amount;
        copied += amount;
    }
    
    errno = incoming_errno;
    return (ssize_t)copied;
});

#pragma mark - exit() hook

LIBKERN_PATCH(void, _exit, (int code),
              {
    if(local_fork_checkpoint != NULL && g_checkpoint->checkpoint_active && g_checkpoint->return_pid == 0)
    {
        pe_finish_fake_child(code);
    }
    
    LIBKERN_ORIG(_exit)(code);
    __builtin_unreachable();
});

LIBKERN_PATCH(void, exit, (int code),
              {
    if(local_fork_checkpoint != NULL && g_checkpoint->checkpoint_active && g_checkpoint->return_pid == 0)
    {
        fflush(NULL);
        pe_finish_fake_child(code);
    }
    
    LIBKERN_ORIG(exit)(code);
    __builtin_unreachable();
});

#pragma mark - wait*() hooks

static bool pe_fake_child_wait_echild(pid_t pid)
{
    if(pid > 0 || !pe_in_fake_child())
    {
        return false;
    }
    
    errno = ECHILD;
    return true;
}

LIBKERN_PATCH(pid_t, waitpid, (pid_t pid,
                               int *ecode,
                               int options),
              {
    if(g_checkpoint != NULL)
    {
        pid_t synthetic = pe_reap_fake_child(pid, ecode, NULL);
        if(synthetic > 0)
        {
            return synthetic;
        }
    }
    
    if(pe_fake_child_wait_echild(pid))
    {
        return -1;
    }
    
    pid_t rc = (pid_t)liveshim_syscall(SYS_wait4, pid, ecode, options, NULL);
    
    return rc;
});

LIBKERN_PATCH(pid_t, wait4, (pid_t pid,
                             int *ecode,
                             int options,
                             struct rusage *rs),
              {
    if(g_checkpoint != NULL)
    {
        pid_t synthetic = pe_reap_fake_child(pid, ecode, rs);
        if(synthetic > 0)
        {
            return synthetic;
        }
    }
    
    if(pe_fake_child_wait_echild(pid))
    {
        return -1;
    }
    
    pid_t rc = (pid_t)liveshim_syscall(SYS_wait4, pid, ecode, options, rs);
    
    return rc;
});

LIBKERN_PATCH(pid_t, wait3, (int *status,
                             int options,
                             struct rusage *rusage),
              {
    if(g_checkpoint != NULL)
    {
        pid_t synthetic = pe_reap_fake_child(-1, status, rusage);
        if(synthetic > 0)
        {
            return synthetic;
        }
    }
    
    if(pe_fake_child_wait_echild(-1))
    {
        return -1;
    }
    
    pid_t rc = (pid_t)liveshim_syscall(SYS_wait4, -1, status, options, rusage);
    
    return rc;
});

LIBKERN_PATCH(pid_t, wait, (int *status),
              {
    if(g_checkpoint != NULL)
    {
        pid_t synthetic = pe_reap_fake_child(-1, status, NULL);
        if(synthetic > 0)
        {
            return synthetic;
        }
    }
    
    if(pe_fake_child_wait_echild(-1))
    {
        return -1;
    }
    
    pid_t rc = (pid_t)liveshim_syscall(SYS_wait4, -1, status, 0, NULL);
    
    return rc;
});

#pragma mark - job control hooks (fake child)

#ifndef PE_FORK_JOBCTL_HOOKS
#define PE_FORK_JOBCTL_HOOKS 1
#endif

#if PE_FORK_JOBCTL_HOOKS

LIBKERN_PATCH(int, setpgid, (pid_t pid,
                             pid_t pgid),
              {
    if(pe_in_fake_child() &&
       (pid == 0 || pid == g_checkpoint->fake_child_pid))
    {
        g_checkpoint->pending_pgrp_set = true;
        g_checkpoint->pending_pgrp = (pgid == 0 || pgid == g_checkpoint->fake_child_pid) ? 0 : pgid;
        
        return 0;
    }
    
    int rc = LIBKERN_ORIG(setpgid)(pid, pgid);
    
    return rc;
});

LIBKERN_PATCH(pid_t, setsid, (void),
{
    if(pe_in_fake_child())
    {
        g_checkpoint->pending_setsid = true;
        g_checkpoint->pending_pgrp_set = false;
        
        return g_checkpoint->fake_child_pid;
    }
    
    pid_t rc = LIBKERN_ORIG(setsid)();
    
    return rc;
});

LIBKERN_PATCH(int, tcsetpgrp, (int fd,
                               pid_t pgrp),
              {
    if(pe_in_fake_child() && pgrp == g_checkpoint->fake_child_pid)
    {
        g_checkpoint->pending_tcsetpgrp_fd = fd;
        
        return 0;
    }
    
    int rc = LIBKERN_ORIG(tcsetpgrp)(fd, pgrp);
    
    return rc;
});

LIBKERN_PATCH(int, ioctl, (int fd,
                           unsigned long request,
                           ...),
              {
    uintptr_t arg = 0;
    if(IOCPARM_LEN(request) != 0)
    {
        va_list ap;
        va_start(ap, request);
        arg = va_arg(ap, uintptr_t);
        va_end(ap);
    }
    
    if(request == TIOCSCTTY && pe_in_fake_child())
    {
        if(!g_checkpoint->pending_setsid)
        {
            errno = EPERM;
            return -1;
        }
        g_checkpoint->pending_ctty_fd = fd;
        
        return 0;
    }
    
    return LIBKERN_ORIG(ioctl)(fd, request, arg);
});

#endif /* PE_FORK_JOBCTL_HOOKS */

__attribute__((visibility("default")))
int environment_vfork_tty_state(int *ctty_fd)
{
    if(g_checkpoint == NULL || !pe_in_fake_child())
    {
        return 0;
    }
    if(!g_checkpoint->pending_setsid)
    {
        return 2;
    }
    if(ctty_fd != NULL)
    {
        *ctty_fd = g_checkpoint->pending_ctty_fd;
    }
    return 1;
}

__attribute__((visibility("default")))
int environment_vfork_defer_ctty(int fd)
{
    if(g_checkpoint == NULL || !pe_in_fake_child())
    {
        return 0;
    }
    if(!g_checkpoint->pending_setsid)
    {
        return -1;
    }
    g_checkpoint->pending_ctty_fd = fd;
    
    return 1;
}

#pragma mark - Initializer

__attribute__((constructor))
static void InstallPatches(void)
{
    if(!pe_checkpoint_runtime_init())
    {
        fprintf(stderr, "failed to initialize fork() fix v2 checkpoint runtime\n");
        exit(1);
    }
    
    LIBKERN_INSTALL_PATCH(vfork);
    LIBKERN_INSTALL_PATCH(fork);
    LIBKERN_INSTALL_PATCH(waitpid);
    LIBKERN_INSTALL_PATCH(wait4);
    LIBKERN_INSTALL_PATCH(wait3);
    LIBKERN_INSTALL_PATCH(wait);
    LIBKERN_INSTALL_PATCH(execl);
    LIBKERN_INSTALL_PATCH(execle);
    LIBKERN_INSTALL_PATCH(execlp);
    LIBKERN_INSTALL_PATCH(execv);
    LIBKERN_INSTALL_PATCH(execve);
    LIBKERN_INSTALL_PATCH(execvp);
    LIBKERN_INSTALL_PATCH(pipe);
    LIBKERN_INSTALL_PATCH(read);
    LIBKERN_INSTALL_PATCH(readv);
    LIBKERN_INSTALL_PATCH(write);
    LIBKERN_INSTALL_PATCH(writev);
    LIBKERN_INSTALL_PATCH(close);
    LIBKERN_INSTALL_PATCH(dup2);
    LIBKERN_INSTALL_PATCH(exit);
    LIBKERN_INSTALL_PATCH(_exit);
#if PE_FORK_JOBCTL_HOOKS
    LIBKERN_INSTALL_PATCH(setpgid);
    LIBKERN_INSTALL_PATCH(setsid);
    LIBKERN_INSTALL_PATCH(tcsetpgrp);
    LIBKERN_INSTALL_PATCH(ioctl);
#endif /* PE_FORK_JOBCTL_HOOKS */
}

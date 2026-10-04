/*
 SPDX-License-Identifier: AGPL-3.0-or-later

 Copyright (C) 2025 - 2026 emexlab

 This file is part of Nyxian.

 Nyxian is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Nyxian is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with Nyxian. If not, see <https://www.gnu.org/licenses/>.
*/

#import <Foundation/Foundation.h>
#import <LindChain/IDEConsole/Utils.h>
#include <LindChain/ProcEnvironment/Shims/vfork.h>
#include <LindChain/ProcEnvironment/Shims/posix_spawn.h>
#include <LiveShim/LiveShimSyscall.h>
#include <LindChain/ProcEnvironment/litehook/litehook.h>
#include <LindChain/ProcEnvironment/LiveContainer/LCBootstrap.h>
#include <LindChain/Private/mach/mach_vm.h>
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
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#import <ksurface_config.h>
#include <Broadpatch/Broadpatch.h>

#if KSURFACE_SYS_PROC_ENABLED

#pragma mark - Time-travel fork checkpoint

#define PE_CHECKPOINT_ARENA_SIZE    (512ull * 1024ull * 1024ull)
#define PE_MAX_VM_REGIONS           2048
#define PE_MAX_FD_JOURNAL           512
#define PE_MAX_FD_OPS               512
#define PE_MAX_FAKE_CHILDREN        32
#define PE_MAX_TRACKED_FDS          4096
#define PE_MAX_EXEC_VECTOR          4096
#define PE_MAX_LOCAL_PIPES          128
#define PE_PIPE_SPOOL_INITIAL       (64ull * 1024ull)
#define PE_PIPE_SPOOL_LIMIT         (256ull * 1024ull * 1024ull)
#define PE_SYNTHETIC_PID_BASE       ((pid_t)0x40000000)
#define PE_EXEC_PENDING_PID         ((pid_t)0x3fffffff)

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

typedef struct {
    volatile pe_helper_action_t helper_action;
    volatile bool helper_ready;
    volatile bool checkpoint_active;
    volatile bool checkpoint_ok;
    volatile bool restoring;
    
    semaphore_t request_semaphore;
    semaphore_t ready_semaphore;
    pthread_t helper_pthread;
    thread_t helper_thread;
    mach_vm_address_t helper_stack_low;
    mach_vm_address_t helper_stack_high;
    
    thread_t target_thread;
    struct arm64_thread_full_state target_state;
    bool target_state_valid;
    
    char cwd[PATH_MAX];
    bool saved_cwd_path_valid;
    int saved_cwd_fd;
    mode_t saved_umask;
    sigset_t saved_sigmask;
    struct sigaction saved_sigactions[NSIG];
    bool saved_sigaction_valid[NSIG];
    
    pe_vm_region_snapshot_t *vm_regions;
    size_t vm_region_count;
    
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

static pe_checkpoint_control_t *g_checkpoint = NULL;
static mach_vm_address_t g_checkpoint_arena = 0;

static __thread pe_checkpoint_control_t *local_fork_checkpoint = NULL;

extern char **environ;

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
    pe_pipe_role_t role = (pe_pipe_role_t)g_checkpoint->pipe_fd_role[fd];
    if(slot < 0 || slot >= PE_MAX_LOCAL_PIPES)
    {
        g_checkpoint->pipe_fd_slot[fd] = -1;
        g_checkpoint->pipe_fd_role[fd] = PE_PIPE_ROLE_NONE;
        return;
    }
    
    pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[slot];
    if(fake_child && role == PE_PIPE_ROLE_WRITE && pipe_state->used &&
       pipe_state->checkpoint_serial == g_checkpoint->checkpoint_serial &&
       pipe_state->checkpoint_has_read)
    {
        pipe_state->spool_active = true;
        pipe_state->producer_serial = g_checkpoint->checkpoint_serial;
        pipe_state->producer_done = false;
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
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &new_buffer, new_capacity, VM_FLAGS_ANYWHERE);
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

    /* the remaining flavors are best effort, matching the old helper. */
    if(state->exception_valid) thread_set_state(thread, ARM_EXCEPTION_STATE64, (thread_state_t)&state->exception, ARM_EXCEPTION_STATE64_COUNT);
    if(state->neon_valid) thread_set_state(thread, ARM_NEON_STATE64, (thread_state_t)&state->neon, ARM_NEON_STATE64_COUNT);
    if(state->debug_valid) thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state->debug, ARM_DEBUG_STATE64_COUNT);
    
    return true;
}

static bool pe_wait_until_thread_suspended(thread_t thread)
{
    for(unsigned int i = 0; i < 1000000; i++)
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
    }
    
    return false;
}

static bool pe_region_is_private(const vm_region_submap_info_data_64_t *info)
{
    return (info->share_mode == SM_PRIVATE || info->share_mode == SM_COW || info->share_mode == SM_PRIVATE_ALIASED);
}

static bool pe_region_is_excluded(mach_vm_address_t address,
                                  mach_vm_size_t size)
{
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
    
    return false;
}

static bool pe_capture_vm(void)
{
    task_t task = mach_task_self();
    mach_vm_size_t total_bytes = 0;
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
        bool private_region = pe_region_is_private(&info);
        
        if(readable && writable && private_region && !pe_region_is_excluded(address, size))
        {
            if(g_checkpoint->vm_region_count >= PE_MAX_VM_REGIONS)
            {
                errno = E2BIG;
                return false;
            }
            
            mach_vm_address_t copy_address = (mach_vm_address_t)pe_scratch_alloc((size_t)size, (size_t)vm_page_size);
            if(copy_address == 0)
            {
                errno = ENOMEM;
                return false;
            }
            
            kr = mach_vm_copy(task, address, size, copy_address);
            if(kr != KERN_SUCCESS)
            {
                errno = EFAULT;
                return false;
            }
            
            total_bytes += size;
            
            pe_vm_region_snapshot_t *snapshot = &g_checkpoint->vm_regions[g_checkpoint->vm_region_count++];
            snapshot->address = address;
            snapshot->size = size;
            snapshot->copy_address = copy_address;
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
    
    return true;
}

static bool pe_restore_one_vm_region(size_t index,
                                     pe_vm_region_snapshot_t *snapshot)
{
    task_t task = mach_task_self();
    
    kern_return_t kr = mach_vm_copy(task, snapshot->copy_address, snapshot->size, snapshot->address);
    if(kr == KERN_SUCCESS)
    {
        return true;
    }
    
    mach_vm_address_t target = snapshot->address;
    vm_prot_t remap_current = snapshot->protection;
    vm_prot_t remap_maximum = snapshot->max_protection;
    
    kr = mach_vm_remap(task, &target, snapshot->size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, task, snapshot->copy_address, TRUE, &remap_current, &remap_maximum, snapshot->inheritance);
    if(kr != KERN_SUCCESS || target != snapshot->address)
    {
        return false;
    }
    
    kern_return_t max_kr = mach_vm_protect(task, snapshot->address, snapshot->size, TRUE, snapshot->max_protection);
    kern_return_t prot_kr = mach_vm_protect(task, snapshot->address, snapshot->size, FALSE, snapshot->protection);
    if(prot_kr != KERN_SUCCESS)
    {
        return false;
    }
    
    return true;
}

static bool pe_restore_vm(void)
{
    bool success = true;
    size_t failures = 0;
    size_t remap_needed = 0;
    
    for(size_t i = 0; i < g_checkpoint->vm_region_count; i++)
    {
        pe_vm_region_snapshot_t *snapshot = &g_checkpoint->vm_regions[i];
        kern_return_t probe = mach_vm_copy(mach_task_self(), snapshot->copy_address, snapshot->size, snapshot->address);
        if(probe == KERN_SUCCESS)
        {
            continue;
        }
        
        remap_needed++;
        if(!pe_restore_one_vm_region(i, snapshot))
        {
            failures++;
            success = false;
        }
    }
    
    return success;
}

static int pe_dup_backup_fd(int fd)
{
    int backup = -1;
    backup = fcntl(fd, F_DUPFD_CLOEXEC, g_checkpoint->fd_backup_floor);
    if(backup >= 0)
    {
        return backup;
    }
    
    backup = fcntl(fd, F_DUPFD, g_checkpoint->fd_backup_floor);
    if(backup >= 0)
    {
        fcntl(backup, F_SETFD, FD_CLOEXEC);
    }
    return backup;
}

static int pe_capture_cwd_fd(void)
{
    int cwd_fd = open(".", O_RDONLY | O_CLOEXEC);
    if(cwd_fd < 0)
    {
        return -1;
    }
    
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
    return fd == g_checkpoint->saved_cwd_fd || fd == g_checkpoint->pending_exec_cwd_fd;
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
        errno = ENOSPC;
        return false;
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
    size_t closed_created = 0;
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
            closed_created++;
        }
    }
    
    size_t flags_restored = 0;
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
            if(fcntl((int)fd, F_SETFD, saved_flags) == 0)
            {
                flags_restored++;
            }
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
        /*
         * The sandbox can deny getcwd() for an otherwise valid cwd.
         * Path capture is diagnostic/best-effort only.
         */
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
        /*
         * Do not fail fork()/vfork() just because userspace cannot obtain an
         * fd or pathname for cwd. The kernel cwd itself remains valid.
         *
         * Rollback does not replace cwd, so if the fake child leaves cwd
         * unchanged, the restored parent is already in the correct directory.
         */
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

    /*
     * No cwd snapshot is a valid state. In that case rollback simply leaves
     * the current kernel cwd alone.
     */
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
                                  int status)
{
    for(size_t i = 0; i < PE_MAX_FAKE_CHILDREN; i++)
    {
        if(!g_checkpoint->fake_children[i].used)
        {
            g_checkpoint->fake_children[i].pid = pid;
            g_checkpoint->fake_children[i].status = status;
            g_checkpoint->fake_children[i].used = true;
            return;
        }
    }
}

static pid_t pe_reap_fake_child(pid_t pid,
                                int *status,
                                struct rusage *rusage)
{
    for(size_t i = 0; i < PE_MAX_FAKE_CHILDREN; i++)
    {
        pe_fake_child_t *child = &g_checkpoint->fake_children[i];
        if(!child->used)
        {
            continue;
        }
        
        if(pid > 0 && child->pid != pid)
        {
            continue;
        }
        if(pid == 0 || pid < -1)
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
    
    kern_return_t resume_kr = thread_resume(g_checkpoint->target_thread);
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
            kern_return_t resume_kr = thread_resume(g_checkpoint->target_thread);
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
    
    mach_vm_address_t arena = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &arena, PE_CHECKPOINT_ARENA_SIZE, VM_FLAGS_ANYWHERE);
    if(kr != KERN_SUCCESS)
    {
        errno = ENOMEM;
        return false;
    }
    
    g_checkpoint_arena = arena;
    g_checkpoint = (pe_checkpoint_control_t *)arena;
    memset(g_checkpoint, 0, sizeof(*g_checkpoint));
    g_checkpoint->arena_base = arena;
    g_checkpoint->arena_size = PE_CHECKPOINT_ARENA_SIZE;
    g_checkpoint->scratch_base_offset = pe_align_up(sizeof(*g_checkpoint), (mach_vm_size_t)vm_page_size);
    g_checkpoint->scratch_offset = g_checkpoint->scratch_base_offset;
    g_checkpoint->next_synthetic_pid = 1;
    g_checkpoint->checkpoint_serial = 0;
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

static void pe_checkpoint_cleanup_parent(void)
{
    int saved_errno = g_checkpoint->restore_errno;
    if(g_checkpoint->synthetic_child && g_checkpoint->return_pid > 0)
    {
        pe_publish_fake_child(g_checkpoint->return_pid, g_checkpoint->synthetic_wait_status);
    }
    
    if(g_checkpoint->target_thread != MACH_PORT_NULL)
    {
        mach_port_deallocate(mach_task_self(), g_checkpoint->target_thread);
        g_checkpoint->target_thread = MACH_PORT_NULL;
    }
    
    g_checkpoint->checkpoint_active = false;
    g_checkpoint->checkpoint_ok = false;
    g_checkpoint->restoring = false;
    g_checkpoint->vm_regions = NULL;
    g_checkpoint->vm_region_count = 0;
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
    
    if(saved_errno != 0)
    {
        errno = saved_errno;
    }
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
    
    int fd_flags = fcntl(fd, F_GETFD);
    if(fd_flags >= 0)
    {
        fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC);
    }
    
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
    
    return fd;
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
    
    for(size_t i = 0; i < g_checkpoint->fd_op_count; i++)
    {
        pe_fd_op_t *op = &g_checkpoint->fd_ops[i];
        if(op->kind == PE_FD_OP_CLOSE)
        {
            rc = posix_spawn_file_actions_addclose(actions, op->oldfd);
        }
        else if(op->kind == PE_FD_OP_DUP2)
        {
            int spawn_source_fd = op->oldfd;
            if(op->pipe_role == PE_PIPE_ROLE_READ && op->pipe_slot >= 0 && op->pipe_slot < PE_MAX_LOCAL_PIPES)
            {
                pe_local_pipe_t *pipe_state = &g_checkpoint->local_pipes[op->pipe_slot];
                if(pipe_state->used && pipe_state->spool_active)
                {
                    if(spool_fds[op->pipe_slot] < 0)
                    {
                        spool_fds[op->pipe_slot] = pe_materialize_spooled_pipe_fd(op->pipe_slot);
                        if(spool_fds[op->pipe_slot] < 0)
                        {
                            rc = errno ? errno : EIO;
                        }
                    }
                    
                    if(spool_fds[op->pipe_slot] >= 0)
                    {
                        spawn_source_fd = spool_fds[op->pipe_slot];
                    }
                }
            }
            
            if(rc == 0)
            {
                rc = posix_spawn_file_actions_adddup2(actions, spawn_source_fd, op->newfd);
            }
        }
        else
        {
            rc = EINVAL;
        }
        
        if(rc != 0)
        {
            posix_spawn_file_actions_destroy(actions);
            pe_close_exec_spool_fds(spool_fds);
            errno = rc;
            return false;
        }
    }
    
    return true;
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

    bool const child_cwd_capture_available =
        g_checkpoint->pending_exec_cwd_fd >= 0 ||
        g_checkpoint->pending_exec_cwd[0] != '\0';

    bool const parent_cwd_restore_available =
        g_checkpoint->saved_cwd_fd >= 0 ||
        g_checkpoint->saved_cwd_path_valid;

    bool child_cwd_selected = false;
    int child_cwd_errno = 0;

    /*
     * Only perform a process-global cwd switch when we know we can restore the
     * parent's cwd afterward. If the parent's cwd is opaque, leave cwd alone
     * and let posix_spawn inherit the restored kernel cwd.
     */
    if(child_cwd_capture_available && parent_cwd_restore_available)
    {
        if(g_checkpoint->pending_exec_cwd_fd >= 0)
        {
            if(fchdir(g_checkpoint->pending_exec_cwd_fd) == 0)
            {
                child_cwd_selected = true;
            }
            else
            {
                child_cwd_errno = errno;
            }
        }

        if(!child_cwd_selected &&
           g_checkpoint->pending_exec_cwd[0] != '\0')
        {
            if(chdir(g_checkpoint->pending_exec_cwd) == 0)
            {
                child_cwd_selected = true;
            }
            else
            {
                child_cwd_errno = errno;
            }
        }

        if(!child_cwd_selected)
        {
            int e = child_cwd_errno ? child_cwd_errno : ENOENT;
            posix_spawn_file_actions_destroy(&actions);
            pe_close_exec_spool_fds(exec_spool_fds);
            errno = e;
            return -1;
        }
    }

    /*
     * If cwd capture was unavailable, or the parent cwd is opaque and cannot
     * safely be restored after a temporary chdir, no cwd syscall is issued.
     * posix_spawn therefore inherits the restored kernel cwd.
     */

    pid_t spawned_pid = -1;
    int rc = g_checkpoint->pending_exec_find_binary
        ? posix_spawnp(&spawned_pid,
                       g_checkpoint->pending_exec_path,
                       &actions,
                       NULL,
                       g_checkpoint->pending_exec_argv,
                       g_checkpoint->pending_exec_envp)
        : posix_spawn(&spawned_pid,
                      g_checkpoint->pending_exec_path,
                      &actions,
                      NULL,
                      g_checkpoint->pending_exec_argv,
                      g_checkpoint->pending_exec_envp);

    int spawn_errno = rc;

    if(rc == 0)
    {
        for(int slot = 0; slot < PE_MAX_LOCAL_PIPES; slot++)
        {
            if(exec_spool_fds[slot] >= 0 &&
               g_checkpoint->local_pipes[slot].used &&
               g_checkpoint->local_pipes[slot].spool_active)
            {
                g_checkpoint->local_pipes[slot].spool_read_offset =
                    g_checkpoint->local_pipes[slot].spool_length;
            }
        }
    }

    pe_close_exec_spool_fds(exec_spool_fds);

    if(child_cwd_selected)
    {
        int parent_cwd_rc = -1;

        if(g_checkpoint->saved_cwd_fd >= 0)
        {
            parent_cwd_rc = fchdir(g_checkpoint->saved_cwd_fd);
        }

        if(parent_cwd_rc != 0 &&
           g_checkpoint->saved_cwd_path_valid)
        {
            parent_cwd_rc = chdir(g_checkpoint->cwd);
        }
    }

    posix_spawn_file_actions_destroy(&actions);

    if(rc != 0)
    {
        errno = spawn_errno;
        return -1;
    }

    return spawned_pid;
}

static __attribute__((noreturn)) void pe_defer_exec_and_restore(const char *path,
                                                                char *const argv[],
                                                                char *const envp[],
                                                                bool find_binary)
{
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

    /*
     * Cwd capture is deliberately not part of exec validity. If both cwd
     * probes fail, deferred posix_spawn will inherit the restored kernel cwd.
     */
    if(g_checkpoint->pending_exec_cwd_fd < 0 &&
       g_checkpoint->pending_exec_cwd[0] == '\0')
    {
        errno = 0;
    }

    if(g_checkpoint->pending_exec_path == NULL ||
       g_checkpoint->pending_exec_argv == NULL ||
       (envp != NULL && g_checkpoint->pending_exec_envp == NULL))
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
    
    if(g_checkpoint->checkpoint_active)
    {
        bool const active_fake_child = local_fork_checkpoint == g_checkpoint && g_checkpoint->checkpoint_ok && !g_checkpoint->restoring && !g_checkpoint->pending_exec && g_checkpoint->return_pid == 0;

        if(active_fake_child)
        {
            if(g_checkpoint->collapsed_nested_forks >= 8)
            {
                errno = EAGAIN;
                return -1;
            }
            
            g_checkpoint->collapsed_nested_forks++;
            return 0;
        }
        
        errno = EAGAIN;
        return -1;
    }
    
    pe_scratch_reset();
    g_checkpoint->checkpoint_serial++;
    if(g_checkpoint->checkpoint_serial == 0)
    {
        g_checkpoint->checkpoint_serial = 1;
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
    g_checkpoint->target_state_valid = false;
    g_checkpoint->target_thread = mach_thread_self();
    local_fork_checkpoint = g_checkpoint;
    
    if(!pe_capture_process_state())
    {
        int e = errno ? errno : EFAULT;
        pe_checkpoint_cleanup_parent();
        errno = e;
        return -1;
    }
    
    g_checkpoint->helper_action = PE_HELPER_CAPTURE;
    semaphore_signal(g_checkpoint->request_semaphore);
    
    kern_return_t suspend_kr = thread_suspend(g_checkpoint->target_thread);
    if(!g_checkpoint->checkpoint_ok || g_checkpoint->return_pid < 0)
    {
        int e = g_checkpoint->restore_errno ? g_checkpoint->restore_errno : EFAULT;
        pe_checkpoint_cleanup_parent();
        errno = e;
        return -1;
    }
    
    if(g_checkpoint->return_pid == 0)
    {
        return 0;
    }
    
    pid_t pid = g_checkpoint->return_pid;
    pthread_sigmask(SIG_SETMASK, &g_checkpoint->saved_sigmask, NULL);
    
    if(g_checkpoint->pending_exec)
    {
        pid = pe_spawn_pending_exec_after_restore();
        if(pid < 0)
        {
            int spawn_error = errno ? errno : EBADEXEC;
            g_checkpoint->restore_errno = spawn_error;
            g_checkpoint->return_pid = -1;
        }
        else
        {
            g_checkpoint->return_pid = pid;
        }
        g_checkpoint->pending_exec = false;
    }
    
    pe_checkpoint_cleanup_parent();
    
    if(pid < 0)
    {
        return -1;
    }
    
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

__attribute__((optnone))
int environment_execvpa(const char * __path,
                        char *_LIBC_CSTR const *_LIBC_NULL_TERMINATED __argv,
                        char *_LIBC_CSTR const *_LIBC_NULL_TERMINATED __envp,
                        bool find_binary)
{
    if(local_fork_checkpoint == NULL || !g_checkpoint->checkpoint_active)
    {
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
            
            /* TODO: override envp */
        }
        
        int argc = PEArgcFromArgv((char *const *)__argv);
        
        /* at that point the process is too unstable to recover */
        PETearDownOwnTask();
        
        void PEOverwriteExecutablePath(NSString *executablePath);
        PEOverwriteExecutablePath(executablePath);
        void PEInsertLibrariesIfNeeded(void);
        PEInsertLibrariesIfNeeded();
        
        
        exit(LCBootstrapMain(executablePath, argc, (char **)__argv));
        
        errno = EBADEXEC;
        return -1;
    }
    
    if(!find_binary)
    {
        struct stat exec_st;
        if(stat(__path, &exec_st) != 0)
        {
            int exec_probe_errno = errno;
            errno = exec_probe_errno;
            return -1;
        }
    }
    
    pe_defer_exec_and_restore(__path, __argv, __envp, find_binary);
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
        pe_pipe_register_pair(fds[0], fds[1]);
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
        pe_finish_fake_child(code);
    }
    
    LIBKERN_ORIG(exit)(code);
    __builtin_unreachable();
});

#pragma mark - wait*() hooks

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
    
    return (pid_t)liveshim_syscall(SYS_wait4, pid, ecode, options, NULL);
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
    
    return (pid_t)liveshim_syscall(SYS_wait4, pid, ecode, options, rs);
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
    
    return (pid_t)liveshim_syscall(SYS_wait4, -1, status, options, rusage);
});

#pragma mark - Initializer

void environment_vfork_init(void)
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
}

#endif /* KSURFACE_SYS_PROC_ENABLED */

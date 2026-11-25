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
#include <os/lock.h>
#include <stdatomic.h>

/* not the kfd exploit dummy >:3 */
int kfd = -1;

struct timespec g_process_start_time;
struct timespec g_process_start_time_sysctl;

__attribute__((constructor))
static void init_process_start_time(void)
{
    clock_gettime(CLOCK_REALTIME, &g_process_start_time_sysctl);
    clock_gettime(CLOCK_MONOTONIC, &g_process_start_time);
}

/* maximum lines klog can take */
static const NSUInteger KLOG_MAX_LINES = 20000;

static void klog_truncate_if_needed(void)
{
    /* checking if kfd is valid */
    if(kfd == -1)
    {
        return;
    }
    
    /* synchronizing kfd */
    fsync(kfd);

    /* getting filesize */
    off_t size = lseek(kfd, 0, SEEK_END);
    
    /* checking validity of that file size */
    if(size <= 0)
    {
        return;
    }
    
    /* diag: only bother rewriting once the log is large (reading it on every line is slow) */
    if(size < 6 * 1024 * 1024)
    {
        return;
    }
    
    /* allocate buffer for file contents */
    char *buffer = malloc(size + 1);
    
    /* null pointer check */
    if(buffer == NULL)
    {
        return;
    }
    
    /* going to the start of the file */
    lseek(kfd, 0, SEEK_SET);
    
    /* reading the file */
    ssize_t n = read(kfd, buffer, size);
    
    /* how much did we read BSD huh?? >:3 */
    if(n <= 0)
    {
        /* ouww nooo :c */
        /* freeing buffer */
        free(buffer);
        return;
    }
    
    /* null terminating string */
    buffer[n] = '\0';
    
    /* getting content NSString */
    NSString *content = [[NSString alloc] initWithUTF8String:buffer];
    
    /* freeing buffer */
    free(buffer);

    /* split content into lines */
    NSArray<NSString *> *lines = [content componentsSeparatedByString:@"\n"];
    
    /* checking if maximum line count was reached */
    if(lines.count <= KLOG_MAX_LINES + 1)
    {
        /* apperently nothing to truncate */
        lseek(kfd, 0, SEEK_END);
        return;
    }

    /* getting new start */
    NSUInteger start = lines.count - 1 - KLOG_MAX_LINES;
    
    /* getting new last */
    NSArray *lastLines = [lines subarrayWithRange:NSMakeRange(start, KLOG_MAX_LINES)];

    /* rewrite new log with maximum amount of lines */
    NSString *rewritten = [[lastLines componentsJoinedByString:@"\n"] stringByAppendingString:@"\n"];
    const char *utf8 = [rewritten UTF8String];

    /* initially rewriting file */
    ftruncate(kfd, 0);
    lseek(kfd, 0, SEEK_SET);
    write(kfd, utf8, strlen(utf8));
    fsync(kfd);

    /* restoring position */
    lseek(kfd, 0, SEEK_END);
}

static _Atomic bool g_klog_obfuscate = true;
static _Atomic bool g_klog_obfuscate_decided = false;

bool klog_set_obfuscation(bool enabled)
{
    bool expected = false;
    if(!atomic_compare_exchange_strong(&g_klog_obfuscate_decided, &expected, true))
    {
        return false;
    }
    atomic_store(&g_klog_obfuscate, enabled);
    return true;
}

static inline bool klog_obfuscation_enabled(void)
{
    return atomic_load(&g_klog_obfuscate);
}

static NSString *const kKlogPrivatePointer = @"<obfuscated>";

static NSString *klog_pointer_token(const void *ptr)
{
    if(ptr == NULL)
    {
        return @"(null)";
    }
    if(klog_obfuscation_enabled())
    {
        return kKlogPrivatePointer;
    }
    return [NSString stringWithFormat:@"%p", ptr];
}

static NSString *klog_redact_addresses(NSString *input)
{
    if(klog_obfuscation_enabled())
    {
        static NSRegularExpression *re;
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            re = [NSRegularExpression regularExpressionWithPattern:@"0[xX][0-9a-fA-F]{9,16}" options:0 error:NULL];
        });
        if(re == nil || input.length == 0)
        {
            return input;
        }
        return [re stringByReplacingMatchesInString:input options:0 range:NSMakeRange(0, input.length) withTemplate:kKlogPrivatePointer];
    }
    else
    {
        return input;
    }
}

enum klog_len {
    KLOG_LEN_NONE = 0, KLOG_LEN_hh, KLOG_LEN_h,
    KLOG_LEN_l, KLOG_LEN_ll, KLOG_LEN_j, KLOG_LEN_z, KLOG_LEN_t, KLOG_LEN_L
};

#define KLOG_EMIT(specstr, value)                                              \
    do {                                                                       \
        _Pragma("clang diagnostic push")                                       \
        _Pragma("clang diagnostic ignored \"-Wformat-nonliteral\"")            \
        int _n = snprintf(NULL, 0, (specstr), (value));                        \
        if(_n >= 0)                                                            \
        {                                                                      \
            char _stack[128];                                                  \
            char *_b = ((size_t)_n < sizeof(_stack)) ? _stack                  \
                                                     : malloc((size_t)_n + 1); \
            if(_b != NULL)                                                     \
            {                                                                  \
                snprintf(_b, (size_t)_n + 1, (specstr), (value));              \
                [msg appendString:(@(_b) ?: @"")];                             \
                if(_b != _stack) free(_b);                                     \
            }                                                                  \
        }                                                                      \
        _Pragma("clang diagnostic pop")                                        \
    } while(0)

static NSString *klog_vformat(const char *fmt, va_list ap)
{
    if(fmt == NULL)
    {
        return @"(null format)";
    }
    
    NSMutableString *msg = [NSMutableString string];
    const char *p = fmt;
    while(*p != '\0')
    {
        if(*p != '%')
        {
            const char *start = p;
            while(*p != '\0' && *p != '%')
            {
                p++;
            }
            NSString *chunk = [[NSString alloc] initWithBytes:start length:(NSUInteger)(p - start) encoding:NSUTF8StringEncoding];
            [msg appendString:chunk ?: @"(invalid utf8)"];
            continue;
        }
        
        p++;
        if(*p == '%')
        {
            [msg appendString:@"%"];
            p++;
            continue;
        }
        
        char flags[8] = {0};
        size_t nflags = 0;
        while(*p != '\0' && strchr("-+ #0", *p) != NULL)
        {
            if(nflags < sizeof(flags) - 1)
            {
                flags[nflags++] = *p;
            }
            p++;
        }
        
        bool has_width = false;
        long width = 0;
        if(*p == '*')
        {
            width = va_arg(ap, int);
            has_width = true;
            p++;
        }
        else while(isdigit((unsigned char)*p))
        {
            width = width * 10 + (*p - '0');
            has_width = true;
            p++;
        }
        
        bool has_prec = false;
        long prec = 0;
        if(*p == '.')
        {
            p++; has_prec = true;
            if(*p == '*')
            {
                prec = va_arg(ap, int);
                p++;
            }
            else while(isdigit((unsigned char)*p))
            {
                prec = prec * 10 + (*p - '0');
                p++;
            }
            if(prec < 0)
            {
                has_prec = false;
            }
        }
        
        enum klog_len len = KLOG_LEN_NONE;
        switch(*p)
        {
            case 'h':
                p++;
                if(*p == 'h')
                {
                    len = KLOG_LEN_hh;
                    p++;
                }
                else
                {
                    len = KLOG_LEN_h;
                }
                break;
            case 'l':
                p++;
                if(*p == 'l')
                {
                    len = KLOG_LEN_ll;
                    p++;
                }
                else
                {
                    len = KLOG_LEN_l;
                }
                break;
            case 'q':
                len = KLOG_LEN_ll;
                p++;
                break;
            case 'j':
                len = KLOG_LEN_j;
                p++;
                break;
            case 'z':
                len = KLOG_LEN_z;
                p++;
                break;
            case 't':
                len = KLOG_LEN_t;
                p++;
                break;
            case 'L':
                len = KLOG_LEN_L;
                p++;
                break;
            default:
                break;
        }
        
        char conv = *p;
        if(conv == '\0')
        {
            [msg appendString:@"%<truncated>"];
            break;
        }
        p++;
        
        char head[40];
        if(has_width && has_prec)
        {
            snprintf(head, sizeof(head), "%%%s%ld.%ld", flags, width, prec);
        }
        else if(has_width)
        {
            snprintf(head, sizeof(head), "%%%s%ld", flags, width);
        }
        else if(has_prec)
        {
            snprintf(head, sizeof(head), "%%%s.%ld", flags, prec);
        }
        else
        {
            snprintf(head, sizeof(head), "%%%s", flags);
        }
        
        char spec[48];
        switch(conv)
        {
            case 'd': case 'i':
            {
                long long v;
                switch(len)
                {
                    case KLOG_LEN_hh:
                        v = (signed char)va_arg(ap, int);
                        break;
                    case KLOG_LEN_h:
                        v = (short)va_arg(ap, int);
                        break;
                    case KLOG_LEN_l:
                        v = va_arg(ap, long);
                        break;
                    case KLOG_LEN_ll:
                        v = va_arg(ap, long long);
                        break;
                    case KLOG_LEN_j:
                        v = va_arg(ap, intmax_t);
                        break;
                    case KLOG_LEN_z:
                        v = (long long)va_arg(ap, ssize_t);
                        break;
                    case KLOG_LEN_t:
                        v = va_arg(ap, ptrdiff_t);
                        break;
                    default:
                        v = va_arg(ap, int);
                        break;
                }
                snprintf(spec, sizeof(spec), "%sll%c", head, conv);
                KLOG_EMIT(spec, v);
                break;
            }
            case 'u': case 'o': case 'x': case 'X':
            {
                unsigned long long v;
                switch(len)
                {
                    case KLOG_LEN_hh:
                        v = (unsigned char)va_arg(ap, unsigned int);
                        break;
                    case KLOG_LEN_h:
                        v = (unsigned short)va_arg(ap, unsigned int);
                        break;
                    case KLOG_LEN_l:
                        v = va_arg(ap, unsigned long);
                        break;
                    case KLOG_LEN_ll:
                        v = va_arg(ap, unsigned long long);
                        break;
                    case KLOG_LEN_j:
                        v = va_arg(ap, uintmax_t);
                        break;
                    case KLOG_LEN_z:
                        v = va_arg(ap, size_t);
                        break;
                    case KLOG_LEN_t:
                        v = (unsigned long long)va_arg(ap, ptrdiff_t);
                        break;
                    default:
                        v = va_arg(ap, unsigned int);
                        break;
                }
                snprintf(spec, sizeof(spec), "%sll%c", head, conv);
                KLOG_EMIT(spec, v);
                break;
            }
            case 'f': case 'F': case 'e': case 'E':
            case 'g': case 'G': case 'a': case 'A':
            {
                if(len == KLOG_LEN_L)
                {
                    long double v = va_arg(ap, long double);
                    snprintf(spec, sizeof(spec), "%sL%c", head, conv);
                    KLOG_EMIT(spec, v);
                }
                else
                {
                    double v = va_arg(ap, double);
                    snprintf(spec, sizeof(spec), "%s%c", head, conv);
                    KLOG_EMIT(spec, v);
                }
                break;
            }
            case 'c':
            {
                if(len == KLOG_LEN_l)
                {
                    wint_t v = va_arg(ap, wint_t);
                    snprintf(spec, sizeof(spec), "%slc", head);
                    KLOG_EMIT(spec, v);
                }
                else
                {
                    int v = va_arg(ap, int);
                    snprintf(spec, sizeof(spec), "%sc", head);
                    KLOG_EMIT(spec, v);
                }
                break;
            }
            case 's':
            {
                if(len == KLOG_LEN_l)
                {
                    wchar_t *v = va_arg(ap, wchar_t *);
                    if(v == NULL)
                    {
                        [msg appendString:@"(null)"];
                        break;
                    }
                    snprintf(spec, sizeof(spec), "%sls", head);
                    KLOG_EMIT(spec, v);
                }
                else
                {
                    const char *v = va_arg(ap, const char *);
                    if(v == NULL)
                    {
                        [msg appendString:@"(null)"];
                        break;
                    }
                    snprintf(spec, sizeof(spec), "%ss", head);
                    KLOG_EMIT(spec, v);
                }
                break;
            }
            case 'p':
            {
                const void *v = va_arg(ap, const void *);
                [msg appendString:klog_pointer_token(v)];
                break;
            }
            case '@':
            {
                id obj = va_arg(ap, id);
                NSString *desc = nil;
                @try
                {
                    desc = (obj != nil) ? [obj description] : @"(nil)";
                }
                @catch(...)
                {
                    desc = @"(description threw)";
                }
                [msg appendString:klog_redact_addresses(desc ?: @"(nil description)")];
                break;
            }
            case 'n':
                [msg appendString:@"<%n rejected>"];
                return msg;

            default:
                [msg appendFormat:@"<bad conversion '%%%c'>", conv];
                return msg;
        }
    }
    
    return msg;
}

void klog_log_internal(const char *system, const char *format, ...)
{
    @autoreleasepool {
        /* only open klog once */
        static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
        os_unfair_lock_lock(&(lock));
        
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            NSString *entry_path = [NSString stringWithFormat:@"%@/Documents/kmsg.txt", NSHomeDirectory()];
            NSString *entry_old_path = [NSString stringWithFormat:@"%@/Documents/kmsg_old.txt", NSHomeDirectory()];
            unlink(entry_old_path.UTF8String);
            if(rename([NSString stringWithFormat:@"%@/Documents/mntfs/devfs/kmsg", NSHomeDirectory()].UTF8String, entry_old_path.UTF8String) != 0)
            {
                perror("rename");
            }
            
            /* diag: keep previous boot logs in Documents/NyxianLogs (last 10) */
            {
                NSFileManager *fm = [NSFileManager defaultManager];
                NSString *dir = [NSString stringWithFormat:@"%@/Documents/NyxianLogs", NSHomeDirectory()];
                [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
                NSDateFormatter *df = [NSDateFormatter new];
                df.dateFormat = @"yyyy-MM-dd_HH-mm-ss";
                NSString *stamp = [df stringFromDate:[NSDate date]];
                if([fm fileExistsAtPath:entry_path])
                {
                    [fm copyItemAtPath:entry_path toPath:[dir stringByAppendingFormat:@"/kmsg-before-%@.txt", stamp] error:nil];
                }
                NSArray *files = [[[fm contentsOfDirectoryAtPath:dir error:nil] filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"SELF BEGINSWITH 'kmsg-'"]] sortedArrayUsingSelector:@selector(compare:)];
                for(NSUInteger i = 0; files.count > 10 && i < files.count - 10; i++)
                {
                    [fm removeItemAtPath:[dir stringByAppendingPathComponent:files[i]] error:nil];
                }
            }
            kfd = open([entry_path UTF8String], O_RDWR | O_CREAT | O_TRUNC, 0644);
            if(kfd == -1)
            {
                return;
            }
        });
        
        /* checking kfd */
        if(kfd == -1)
        {
            os_unfair_lock_unlock(&(lock));
            return;
        }
        
        /* starting variadic parse */
        va_list args;
        va_start(args, format);
        NSString *msg = klog_vformat(format, args);
        va_end(args);
        
        /* final log string */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        
        long sec = now.tv_sec - g_process_start_time.tv_sec;
        long nsec = now.tv_nsec - g_process_start_time.tv_nsec;
        if(nsec < 0)
        {
            sec--;
            nsec += 1000000000L;
        }
        NSString *final = [NSString stringWithFormat:@"[%5ld.%06ld] [%@] %@\n", sec, nsec / 1000, system ? @(system) : @"(null)", msg ?: @"(null)"];
        
        /* getting constent c version of that string */
        const char *utf8 = [final UTF8String];
        size_t len = strlen(utf8);
        
        /* writing */
        ssize_t written = write(kfd, utf8, len);
#if DEBUG
        static bool isLaunchdParent = false;
        static dispatch_once_t onceTokenSecond;
        dispatch_once(&onceTokenSecond, ^{
            if(getppid() == 1)
            {
                isLaunchdParent = true;
            }
        });
        if(!isLaunchdParent)
        {
            write(STDERR_FILENO, utf8, len);
        }
#endif /* DEBUG */
        
        /* truncation if applicable */
        if(written == len)
        {
            klog_truncate_if_needed();
        }
        else
        {
            fsync(kfd);
        }
        
        os_unfair_lock_unlock(&(lock));
    }
}

NSString *klog_dump(void)
{
    
    /* checking kfd */
    if(kfd == -1)
    {
        return @"";
    }
    
    /* synchronizing kfd */
    fsync(kfd);

    /* seeking the end lol */
    off_t size = lseek(kfd, 0, SEEK_END);
    if(size <= 0)
    {
        /* fuck my life.. concrete string crash shit (mhm apple, I look at you) */
        lseek(kfd, 0, SEEK_SET);
        return @"";
    }

    /* allocating new buffer with the size we got */
    char *buffer = malloc(size + 1);
    if(!buffer)
    {
        /* fuck my life.. concrete string crash shit (mhm apple, I look at you) */
        lseek(kfd, 0, SEEK_SET);
        return @"";
    }

    /* going back to the beginning */
    lseek(kfd, 0, SEEK_SET);
    
    /* reading from file */
    ssize_t n = read(kfd, buffer, size);
    
    /* read check */
    if(n < 0)
    {
        /* fuck my life.. concrete string crash shit (mhm apple, I look at you) */
        free(buffer);
        return @"";
    }
    
    /* null terminating buffer */
    buffer[n] = '\0';

    /* final result */
    NSString *result = [[NSString alloc] initWithUTF8String:buffer];

    /* releasing buffer and return */
    free(buffer);
    return result;
    return nil;
}

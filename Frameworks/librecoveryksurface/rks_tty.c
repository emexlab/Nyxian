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

/*
 * The recovery's TTY driver, the same model as KSurface's tty/: a terminal
 * is two socket pairs, the userspace ends are handed out (to the TWRP
 * terminal or, as fileports, to a guest calling openpty), the kernel ends
 * are pumped by a thread that applies the line discipline (canonical input,
 * echo, ISIG -> signal to the foreground process group, OPOST/ONLCR).
 *
 * A socket handed to a guest comes back as a fileport on every ioctl. The
 * TTY is found by the opaque handle of the socket it is connected to
 * (proc_pidfdinfo, un_sockinfo.unsi_conn_so), which every dup of the
 * userspace end shares.
 *
 * Like KSurface the driver holds the slave end itself while the TTY lives,
 * so the slave never reads EOF because the processes using it come and go
 * (a job exiting, the fork emulation moving fds around). When the last copy
 * of the master goes away the session is hung up.
 */

#include "rks.h"
#include <LindChain/ProcEnvironment/Surface/libkern/bsd/proc_info.h>
#include <LindChain/Private/mach/fileport.h>
#include <ksurface_abi.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/ttycom.h>
#include <sys/ttydefaults.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define TTY_MAX_RD      65536
#define TTY_OUT_RD      (256 * 1024)
#define TTY_SOCKBUF     (256 * 1024)
#define TTY_MAX_INDEX   1024
#define TTY_NAME_FORMAT "/var/run/pty/ttys%03d"     /* guest path, inside the jbroot */

#define MASTERFD 0
#define SLAVEFD  1

/* debug: log every termios get/set, see rks_tty_ioctl */
#define RKS_TTY_TRACE 0

#if RKS_TTY_TRACE
static const char *rks_tty_mode(const struct termios *t)
{
    return (t->c_lflag & ICANON) ? ((t->c_lflag & ECHO) ? "cooked" : "cooked-noecho")
                                 : ((t->c_lflag & ECHO) ? "raw-echo" : "raw");
}
#endif

struct rks_tty {
    int refs;
    pthread_mutex_t lock;           /* termios, winsize, sid/pgrp */
    int kernelfds[2];
    /*
     * like KSurface's userspacefd[SLAVEFD]: the kernel holds the slave end
     * itself while the TTY lives, so processes coming and going (a job that
     * exits, the fork emulation shuffling fds) never make the slave read EOF.
     * The session ends when the bootloader closes the master.
     */
    int heldslave;
    uint64_t ids[2];                /* conn handles of the userspace ends */
    pthread_t pump;
    bool alive;

    struct termios t;
    struct winsize ws;
    bool termios_configured;
    pid_t sid;
    pid_t pgrp;
    int index;

    /* line discipline state, only touched by the pump */
    uint8_t line[TTY_MAX_RD];
    size_t line_len;
    bool last_canonical;
    char rbuf[TTY_OUT_RD];
    char obuf[TTY_OUT_RD * 2];
    char ibuf[TTY_MAX_RD];
    size_t ibuf_len;
    char ebuf[TTY_MAX_RD * 3];
    size_t ebuf_len;

    struct rks_tty *next;
};

static pthread_mutex_t g_tty_lock = PTHREAD_MUTEX_INITIALIZER;
static rks_tty_t *g_ttys = NULL;
static bool g_tty_index_used[TTY_MAX_INDEX];

static const cc_t rks_ttydefchars[NCCS] = {
    [VEOF] = CTRL('d'), [VEOL] = _POSIX_VDISABLE, [VEOL2] = _POSIX_VDISABLE, [VERASE] = 0x7f,
    [VWERASE] = CTRL('w'), [VKILL] = CTRL('u'), [VREPRINT] = CTRL('r'), [VINTR] = CTRL('c'),
    [VQUIT] = CTRL('\\'), [VSUSP] = CTRL('z'), [VDSUSP] = CTRL('y'), [VSTART] = CTRL('q'),
    [VSTOP] = CTRL('s'), [VLNEXT] = CTRL('v'), [VDISCARD] = CTRL('o'), [VMIN] = 1, [VTIME] = 0,
    [VSTATUS] = CTRL('t'),
};

/* ----------------------------------------------------------------------
 *  identity
 * -------------------------------------------------------------------- */

static bool rks_tty_conn_id(int fd, uint64_t *id)
{
    struct socket_fdinfo info;
    memset(&info, 0, sizeof(info));
    int ret = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));
    if(ret < (int)sizeof(info) || info.psi.soi_kind != SOCKINFO_UN)
    {
        return false;
    }
    *id = info.psi.soi_proto.pri_un.unsi_conn_so;
    return *id != 0;
}

void rks_tty_retain(rks_tty_t *tty)
{
    __atomic_add_fetch(&tty->refs, 1, __ATOMIC_ACQ_REL);
}

static void rks_tty_node_path(int index, char *out, size_t size)
{
    char name[64];
    snprintf(name, sizeof(name), TTY_NAME_FORMAT, index);
    snprintf(out, size, "%s%s", rks.jbroot, name);
}

void rks_tty_release(rks_tty_t *tty)
{
    if(tty == NULL || __atomic_sub_fetch(&tty->refs, 1, __ATOMIC_ACQ_REL) != 0)
    {
        return;
    }
    close(tty->kernelfds[MASTERFD]);
    close(tty->kernelfds[SLAVEFD]);
    if(tty->heldslave >= 0)
    {
        close(tty->heldslave);
    }
    if(tty->index >= 0)
    {
        char path[PATH_MAX];
        rks_tty_node_path(tty->index, path, sizeof(path));
        unlink(path);
        pthread_mutex_lock(&g_tty_lock);
        g_tty_index_used[tty->index] = false;
        pthread_mutex_unlock(&g_tty_lock);
    }
    pthread_mutex_destroy(&tty->lock);
    free(tty);
}

rks_tty_t *rks_tty_for_fd(int fd)
{
    uint64_t id = 0;
    if(!rks_tty_conn_id(fd, &id))
    {
        return NULL;
    }
    pthread_mutex_lock(&g_tty_lock);
    for(rks_tty_t *tty = g_ttys; tty != NULL; tty = tty->next)
    {
        if(tty->ids[MASTERFD] == id || tty->ids[SLAVEFD] == id)
        {
            rks_tty_retain(tty);
            pthread_mutex_unlock(&g_tty_lock);
            return tty;
        }
    }
    pthread_mutex_unlock(&g_tty_lock);
    return NULL;
}

rks_tty_t *rks_tty_for_port(mach_port_t port)
{
    int fd = fileport_makefd(port);
    if(fd < 0)
    {
        return NULL;
    }
    rks_tty_t *tty = rks_tty_for_fd(fd);
    close(fd);
    return tty;
}

static void rks_tty_unlist(rks_tty_t *target)
{
    pthread_mutex_lock(&g_tty_lock);
    for(rks_tty_t **cursor = &g_ttys; *cursor != NULL; cursor = &(*cursor)->next)
    {
        if(*cursor == target)
        {
            *cursor = target->next;
            break;
        }
    }
    pthread_mutex_unlock(&g_tty_lock);
}

/* ----------------------------------------------------------------------
 *  line discipline (KSurface tty/tty.c)
 * -------------------------------------------------------------------- */

static int rks_write_all(int fd, const void *buffer, size_t length)
{
    const uint8_t *bytes = buffer;
    size_t off = 0;
    while(off < length)
    {
        ssize_t written = write(fd, bytes + off, length - off);
        if(written > 0)
        {
            off += (size_t)written;
            continue;
        }
        if(written < 0 && errno == EINTR)
        {
            continue;
        }
        return -1;
    }
    return 0;
}

static bool rks_cc_matches(uint8_t c, cc_t configured)
{
    return configured != _POSIX_VDISABLE && c == (uint8_t)configured;
}

static int rks_flush_echo(rks_tty_t *tty)
{
    if(tty->ebuf_len == 0) return 0;
    int result = rks_write_all(tty->kernelfds[MASTERFD], tty->ebuf, tty->ebuf_len);
    tty->ebuf_len = 0;
    return result;
}

static int rks_flush_raw(rks_tty_t *tty)
{
    if(tty->ibuf_len == 0) return 0;
    int result = rks_write_all(tty->kernelfds[SLAVEFD], tty->ibuf, tty->ibuf_len);
    tty->ibuf_len = 0;
    return result;
}

static int rks_echo_bytes(rks_tty_t *tty, const void *buffer, size_t length)
{
    if(length > sizeof(tty->ebuf) - tty->ebuf_len)
    {
        if(rks_flush_echo(tty) < 0) return -1;
        if(length > sizeof(tty->ebuf)) return rks_write_all(tty->kernelfds[MASTERFD], buffer, length);
    }
    memcpy(tty->ebuf + tty->ebuf_len, buffer, length);
    tty->ebuf_len += length;
    return 0;
}

static int rks_echo_char(rks_tty_t *tty, const struct termios *t, uint8_t c)
{
    if(c == '\n' && (t->c_oflag & OPOST) && (t->c_oflag & ONLCR))
    {
        static const uint8_t crlf[] = {'\r', '\n'};
        return rks_echo_bytes(tty, crlf, sizeof(crlf));
    }
    if(c < 0x20 && c != '\n' && c != '\t' && c != '\r' && c != 0x1b && (t->c_lflag & ECHOCTL))
    {
        uint8_t caret[2] = {'^', (uint8_t)(c + '@')};
        return rks_echo_bytes(tty, caret, sizeof(caret));
    }
    return rks_echo_bytes(tty, &c, 1);
}

static int rks_echo_erase(rks_tty_t *tty, bool echoe)
{
    if(echoe)
    {
        static const uint8_t erase[] = {'\b', ' ', '\b'};
        return rks_echo_bytes(tty, erase, sizeof(erase));
    }
    static const uint8_t del = 0x7f;
    return rks_echo_bytes(tty, &del, 1);
}

static int rks_flush_line(rks_tty_t *tty)
{
    if(tty->line_len == 0) return 0;
    int result = rks_write_all(tty->kernelfds[SLAVEFD], tty->line, tty->line_len);
    if(result == 0) tty->line_len = 0;
    return result;
}

static void rks_tty_signal_foreground(rks_tty_t *tty, int sig)
{
    pthread_mutex_lock(&tty->lock);
    pid_t pgrp = tty->pgrp;
    pthread_mutex_unlock(&tty->lock);
    if(pgrp > 0)
    {
        rks_pgrp_signal(pgrp, sig);
    }
}

/* 0: handled, -1: writing failed (nobody reads the slave anymore, input is dropped), -2: master closed */
static int rks_tty_input(rks_tty_t *tty)
{
    ssize_t n = read(tty->kernelfds[MASTERFD], tty->rbuf, TTY_MAX_RD);
    if(n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN))
    {
        return -2;
    }
    if(n < 0)
    {
        return 0;
    }

    pthread_mutex_lock(&tty->lock);
    struct termios t = tty->t;
    pthread_mutex_unlock(&tty->lock);

    bool canonical = (t.c_lflag & ICANON) != 0;
    bool echo = (t.c_lflag & ECHO) != 0;
    bool echoe = (t.c_lflag & ECHOE) != 0;
    bool echok = (t.c_lflag & ECHOK) != 0;

    if(tty->last_canonical && !canonical && tty->line_len > 0 && rks_flush_line(tty) < 0)
    {
        return -1;
    }
    tty->last_canonical = canonical;

    /* an unset (0) VINTR/VQUIT/VSUSP means default, disabled is _POSIX_VDISABLE */
    const cc_t vintr = t.c_cc[VINTR] ? t.c_cc[VINTR] : CTRL('c');
    const cc_t vquit = t.c_cc[VQUIT] ? t.c_cc[VQUIT] : CTRL('\\');
    const cc_t vsusp = t.c_cc[VSUSP] ? t.c_cc[VSUSP] : CTRL('z');

    for(ssize_t i = 0; i < n; i++)
    {
        uint8_t c = (uint8_t)tty->rbuf[i];

        if(t.c_iflag & ISTRIP) c &= 0x7f;
        if((t.c_iflag & IGNCR) && c == '\r') continue;
        if((t.c_iflag & ICRNL) && c == '\r') c = '\n';
        else if((t.c_iflag & INLCR) && c == '\n') c = '\r';

        if(t.c_lflag & ISIG)
        {
            int sig = 0;
            if(rks_cc_matches(c, vintr)) sig = SIGINT;
            else if(rks_cc_matches(c, vquit)) sig = SIGQUIT;
            else if(rks_cc_matches(c, vsusp)) sig = SIGTSTP;
            if(sig != 0)
            {
                tty->line_len = 0;
                if(echo && rks_echo_char(tty, &t, c) < 0) return -1;
                if(rks_flush_raw(tty) < 0 || rks_flush_echo(tty) < 0) return -1;
                rks_tty_signal_foreground(tty, sig);
                continue;
            }
        }

        if(canonical)
        {
            if(rks_cc_matches(c, t.c_cc[VERASE]) || (t.c_cc[VERASE] == 0 && c == 0x7f) || c == '\b')
            {
                if(tty->line_len > 0)
                {
                    tty->line_len--;
                    if(echo && rks_echo_erase(tty, echoe) < 0) return -1;
                }
                continue;
            }
            if(rks_cc_matches(c, t.c_cc[VKILL]))
            {
                size_t erased = tty->line_len;
                tty->line_len = 0;
                if(echo)
                {
                    if(echoe)
                    {
                        for(size_t j = 0; j < erased; j++) if(rks_echo_erase(tty, true) < 0) return -1;
                    }
                    else if(echok && rks_echo_char(tty, &t, '\n') < 0)
                    {
                        return -1;
                    }
                }
                continue;
            }
            if(rks_cc_matches(c, t.c_cc[VEOF]) || (t.c_cc[VEOF] == 0 && c == CTRL('d')))
            {
                /*
                 * A stream socket cannot carry POSIX's zero-length EOF record
                 * without closing: a non-empty line is delivered now, an empty
                 * one stays a transport limitation (same as KSurface).
                 */
                if(tty->line_len > 0 && rks_flush_line(tty) < 0) return -1;
                continue;
            }

            bool delimiter = c == '\n' || rks_cc_matches(c, t.c_cc[VEOL]) || rks_cc_matches(c, t.c_cc[VEOL2]);
            if(tty->line_len < sizeof(tty->line))
            {
                tty->line[tty->line_len++] = c;
            }
            else
            {
                if(echo)
                {
                    static const uint8_t bell = '\a';
                    if(rks_echo_bytes(tty, &bell, 1) < 0) return -1;
                }
                continue;
            }
            if(echo && rks_echo_char(tty, &t, c) < 0) return -1;
            if(delimiter && rks_flush_line(tty) < 0) return -1;
            continue;
        }

        if(tty->ibuf_len >= sizeof(tty->ibuf) && rks_flush_raw(tty) < 0) return -1;
        tty->ibuf[tty->ibuf_len++] = (char)c;
        if(echo && rks_echo_char(tty, &t, c) < 0) return -1;
    }

    if(rks_flush_raw(tty) < 0) return -1;
    return rks_flush_echo(tty);
}

static size_t rks_tty_opost(rks_tty_t *tty, tcflag_t oflag, ssize_t n, const uint8_t **out)
{
    if(!(oflag & OPOST))
    {
        *out = (const uint8_t *)tty->rbuf;
        return (size_t)n;
    }
    size_t length = 0;
    for(ssize_t i = 0; i < n; i++)
    {
        uint8_t c = (uint8_t)tty->rbuf[i];
        if(c == '\n' && (oflag & ONLCR))
        {
            tty->obuf[length++] = '\r';
            tty->obuf[length++] = '\n';
            continue;
        }
        if(c == '\r' && (oflag & OCRNL))
        {
            tty->obuf[length++] = '\n';
            continue;
        }
        tty->obuf[length++] = (char)c;
    }
    *out = (const uint8_t *)tty->obuf;
    return length;
}

/* 1: data written, 0: slave side closed (EOF), -1: error */
static int rks_tty_output(rks_tty_t *tty)
{
    ssize_t n = read(tty->kernelfds[SLAVEFD], tty->rbuf, TTY_OUT_RD);
    if(n == 0)
    {
        return 0;
    }
    if(n < 0)
    {
        return errno == EINTR || errno == EAGAIN ? 1 : -1;
    }
    pthread_mutex_lock(&tty->lock);
    tcflag_t oflag = tty->t.c_oflag;
    pthread_mutex_unlock(&tty->lock);
    const uint8_t *out = NULL;
    size_t length = rks_tty_opost(tty, oflag, n, &out);
    if(length != 0 && rks_write_all(tty->kernelfds[MASTERFD], out, length) < 0)
    {
        return -1;
    }
    return 1;
}

static void rks_tty_hangup(rks_tty_t *tty)
{
    rks_tty_signal_foreground(tty, SIGHUP);
    rks_tty_signal_foreground(tty, SIGCONT);
    pthread_mutex_lock(&tty->lock);
    pid_t sid = tty->sid;
    pid_t pgrp = tty->pgrp;
    pthread_mutex_unlock(&tty->lock);
    if(sid > 0 && sid != pgrp)
    {
        rks_proc_t *leader = rks_proc_lookup(sid);
        if(leader != NULL)
        {
            rks_proc_signal(leader, SIGHUP);
            rks_proc_signal(leader, SIGCONT);
            rks_proc_release(leader);
        }
    }
    shutdown(tty->kernelfds[SLAVEFD], SHUT_RDWR);
}

static void *rks_tty_pump(void *arg)
{
    rks_tty_t *tty = arg;
    pthread_setname_np("librecoveryksurface.tty");

    struct pollfd fds[2] = {
        { .fd = tty->kernelfds[MASTERFD], .events = POLLIN },
        { .fd = tty->kernelfds[SLAVEFD],  .events = POLLIN },
    };
    bool master_gone = false;

    while(tty->alive)
    {
        int r = poll(fds, 2, -1);
        if(r < 0)
        {
            if(errno == EINTR) continue;
            break;
        }

        if(fds[0].revents & (POLLERR | POLLNVAL))
        {
            master_gone = true;
            break;
        }
        if(fds[0].revents & POLLIN)
        {
            if(rks_tty_input(tty) == -2)
            {
                /* read 0: every copy of the master is closed */
                master_gone = true;
                break;
            }
        }
        else if(fds[0].revents & POLLHUP)
        {
            master_gone = true;
            break;
        }

        if(fds[1].fd >= 0 && (fds[1].revents & (POLLIN | POLLHUP | POLLERR)))
        {
            int out = rks_tty_output(tty);
            if(out <= 0)
            {
                /* nobody holds the slave anymore: the master reads EOF, keep serving until it closes too */
                fds[1].fd = -1;
                shutdown(tty->kernelfds[MASTERFD], SHUT_WR);
            }
        }
    }

    if(master_gone)
    {
        rks_tty_hangup(tty);
    }
    tty->alive = false;
    rks_tty_unlist(tty);
    rks_tty_release(tty);   /* the pump's (and list's) reference */
    return NULL;
}

/* ----------------------------------------------------------------------
 *  creation
 * -------------------------------------------------------------------- */

static void rks_tty_node_create(int index)
{
    char path[PATH_MAX];
    rks_tty_node_path(index, path, sizeof(path));
    char dir[PATH_MAX];
    strlcpy(dir, path, sizeof(dir));
    char *slash = strrchr(dir, '/');
    if(slash != NULL)
    {
        *slash = '\0';
        mkdir(dir, 0755);
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0620);
    if(fd >= 0)
    {
        close(fd);
    }
}

rks_tty_t *rks_tty_create(int *master_fd, int *slave_fd)
{
    rks_tty_t *tty = calloc(1, sizeof(rks_tty_t));
    if(tty == NULL)
    {
        return NULL;
    }
    pthread_mutex_init(&tty->lock, NULL);
    tty->refs = 1;
    tty->index = -1;
    tty->heldslave = -1;

    tty->t.c_iflag = TTYDEF_IFLAG;
    tty->t.c_oflag = TTYDEF_OFLAG;
    tty->t.c_cflag = TTYDEF_CFLAG;
    tty->t.c_lflag = TTYDEF_LFLAG;
    tty->t.c_ispeed = TTYDEF_SPEED;
    tty->t.c_ospeed = TTYDEF_SPEED;
    memcpy(tty->t.c_cc, rks_ttydefchars, sizeof(tty->t.c_cc));
    tty->ws.ws_col = 80;
    tty->ws.ws_row = 24;

    int masterpair[2] = {-1, -1};
    int slavepair[2] = {-1, -1};
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, masterpair) != 0 ||
       socketpair(AF_UNIX, SOCK_STREAM, 0, slavepair) != 0)
    {
        goto fail;
    }
    int sockbuf = TTY_SOCKBUF;
    int all[4] = { masterpair[0], masterpair[1], slavepair[0], slavepair[1] };
    for(int i = 0; i < 4; i++)
    {
        setsockopt(all[i], SOL_SOCKET, SO_SNDBUF, &sockbuf, sizeof(sockbuf));
        setsockopt(all[i], SOL_SOCKET, SO_RCVBUF, &sockbuf, sizeof(sockbuf));
        int nosigpipe = 1;
        setsockopt(all[i], SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof(nosigpipe));
    }
    fcntl(masterpair[1], F_SETFD, FD_CLOEXEC);
    fcntl(slavepair[1], F_SETFD, FD_CLOEXEC);

    if(!rks_tty_conn_id(masterpair[0], &tty->ids[MASTERFD]) ||
       !rks_tty_conn_id(slavepair[0], &tty->ids[SLAVEFD]))
    {
        rks_logf("tty: proc_pidfdinfo gave no socket identity");
        goto fail;
    }
    tty->kernelfds[MASTERFD] = masterpair[1];
    tty->kernelfds[SLAVEFD] = slavepair[1];
    tty->heldslave = fcntl(slavepair[0], F_DUPFD_CLOEXEC, 0);
    if(tty->heldslave < 0)
    {
        goto fail;
    }

    pthread_mutex_lock(&g_tty_lock);
    for(int i = 0; i < TTY_MAX_INDEX; i++)
    {
        if(!g_tty_index_used[i])
        {
            g_tty_index_used[i] = true;
            tty->index = i;
            break;
        }
    }
    tty->next = g_ttys;
    g_ttys = tty;
    pthread_mutex_unlock(&g_tty_lock);
    if(tty->index >= 0)
    {
        rks_tty_node_create(tty->index);
    }

    tty->alive = true;
    rks_tty_retain(tty);    /* the pump's */
    if(pthread_create(&tty->pump, NULL, rks_tty_pump, tty) != 0)
    {
        tty->alive = false;
        rks_tty_unlist(tty);
        tty->refs = 1;
        rks_tty_release(tty);
        close(masterpair[0]);
        close(slavepair[0]);
        return NULL;
    }
    pthread_detach(tty->pump);

    *master_fd = masterpair[0];
    *slave_fd = slavepair[0];
    return tty;     /* the caller's reference */

fail:
    for(int i = 0; i < 2; i++)
    {
        if(masterpair[i] >= 0) close(masterpair[i]);
        if(slavepair[i] >= 0) close(slavepair[i]);
    }
    if(tty->heldslave >= 0) close(tty->heldslave);
    pthread_mutex_destroy(&tty->lock);
    free(tty);
    return NULL;
}

void rks_tty_attach(rks_tty_t *tty, rks_proc_t *leader)
{
    pthread_mutex_lock(&rks_proc_lock);
    pid_t sid = leader->sid;
    pid_t pgid = leader->pgid;
    pthread_mutex_unlock(&rks_proc_lock);
    pthread_mutex_lock(&tty->lock);
    tty->sid = sid;
    tty->pgrp = pgid;
    pthread_mutex_unlock(&tty->lock);
}

int rks_tty_set_size(rks_tty_t *tty, unsigned short rows, unsigned short cols)
{
    pthread_mutex_lock(&tty->lock);
    bool changed = tty->ws.ws_row != rows || tty->ws.ws_col != cols;
    tty->ws.ws_row = rows;
    tty->ws.ws_col = cols;
    pthread_mutex_unlock(&tty->lock);
    if(changed)
    {
        rks_tty_signal_foreground(tty, SIGWINCH);
    }
    return 0;
}

/* ----------------------------------------------------------------------
 *  syscalls
 * -------------------------------------------------------------------- */

int64_t rks_tty_ioctl(rks_call_t *call, rks_tty_t *tty, unsigned long request, uint64_t arg)
{
    pthread_mutex_lock(&rks_proc_lock);
    pid_t pid = call->proc->pid;
    pid_t sid = call->proc->sid;
    pid_t pgid = call->proc->pgid;
    pthread_mutex_unlock(&rks_proc_lock);

    switch(request)
    {
        case TIOCGETA:
        {
            pthread_mutex_lock(&tty->lock);
            struct termios t = tty->t;
            pthread_mutex_unlock(&tty->lock);
            bool ok = rks_copy_out(call->task, arg, &t, sizeof(t));
#if RKS_TTY_TRACE
            rks_logf("tty%d: pid %d GETA -> %s lflag=0x%lx%s", tty->index, pid, rks_tty_mode(&t),
                     (unsigned long)t.c_lflag, ok ? "" : " EFAULT");
#endif
            if(!ok) RKS_FAIL(call, EFAULT);
            return 0;
        }
        case TIOCSETA:
        case TIOCSETAW:
        case TIOCSETAF:
        {
            struct termios t;
            if(!rks_copy_in(call->task, &t, arg, sizeof(t)))
            {
#if RKS_TTY_TRACE
                rks_logf("tty%d: pid %d SETA%s EFAULT (task 0x%x)", tty->index, pid,
                         request == TIOCSETAW ? "W" : request == TIOCSETAF ? "F" : "", call->task);
#endif
                RKS_FAIL(call, EFAULT);
            }
            pthread_mutex_lock(&tty->lock);
#if RKS_TTY_TRACE
            rks_logf("tty%d: pid %d SETA%s %s -> %s lflag=0x%lx", tty->index, pid,
                     request == TIOCSETAW ? "W" : request == TIOCSETAF ? "F" : "",
                     rks_tty_mode(&tty->t), rks_tty_mode(&t), (unsigned long)t.c_lflag);
#endif
            tty->t = t;
            tty->termios_configured = true;
            pthread_mutex_unlock(&tty->lock);
            return 0;
        }
        case TIOCGWINSZ:
        {
            pthread_mutex_lock(&tty->lock);
            struct winsize ws = tty->ws;
            pthread_mutex_unlock(&tty->lock);
            if(!rks_copy_out(call->task, arg, &ws, sizeof(ws))) RKS_FAIL(call, EFAULT);
            return 0;
        }
        case TIOCSWINSZ:
        {
            struct winsize ws;
            if(!rks_copy_in(call->task, &ws, arg, sizeof(ws))) RKS_FAIL(call, EFAULT);
            pthread_mutex_lock(&tty->lock);
            bool changed = memcmp(&ws, &tty->ws, sizeof(ws)) != 0;
            tty->ws = ws;
            pthread_mutex_unlock(&tty->lock);
            if(changed) rks_tty_signal_foreground(tty, SIGWINCH);
            return 0;
        }
        case TIOCGPGRP:
        {
            pthread_mutex_lock(&tty->lock);
            pid_t pgrp = tty->pgrp;
            pid_t tsid = tty->sid;
            pthread_mutex_unlock(&tty->lock);
            if(tsid != sid) RKS_FAIL(call, ENOTTY);
            if(!rks_copy_out(call->task, arg, &pgrp, sizeof(pgrp))) RKS_FAIL(call, EFAULT);
            return 0;
        }
        case TIOCSPGRP:
        {
            pid_t requested = 0;
            if(!rks_copy_in(call->task, &requested, arg, sizeof(requested))) RKS_FAIL(call, EFAULT);
            pthread_mutex_lock(&tty->lock);
            pid_t tsid = tty->sid;
            pthread_mutex_unlock(&tty->lock);
            if(tsid != sid) RKS_FAIL(call, ENOTTY);
            pthread_mutex_lock(&rks_proc_lock);
            bool exists = requested > 0 && rks_pgrp_exists_in_session(requested, sid);
            pthread_mutex_unlock(&rks_proc_lock);
            if(!exists) RKS_FAIL(call, EPERM);
            pthread_mutex_lock(&tty->lock);
            tty->pgrp = requested;
            pthread_mutex_unlock(&tty->lock);
            return 0;
        }
        case TIOCSCTTY:
        {
            if(pid != sid) RKS_FAIL(call, EPERM);
            pthread_mutex_lock(&tty->lock);
            if(tty->sid != 0 && tty->sid != sid)
            {
                pthread_mutex_unlock(&tty->lock);
                RKS_FAIL(call, EPERM);
            }
            tty->sid = sid;
            tty->pgrp = pgid;
            pthread_mutex_unlock(&tty->lock);
            return 0;
        }
        case TIOCPTYGNAME:
        {
            char name[128] = {0};   /* TIOCPTYGNAME always transfers 128 bytes */
            if(tty->index < 0) RKS_FAIL(call, ENOTTY);
            snprintf(name, sizeof(name), TTY_NAME_FORMAT, tty->index);
            if(!rks_copy_out(call->task, arg, name, sizeof(name))) RKS_FAIL(call, EFAULT);
            return 0;
        }
        case TIOCPTYGRANT:
        case TIOCPTYUNLK:
            return 0;
        default:
            RKS_FAIL(call, ENOSYS);
    }
}

int64_t rks_sys_ioctl(rks_call_t *call)
{
    unsigned long request = (unsigned long)call->args[1];
    uint64_t arg = (uint64_t)call->args[2];

    switch(request)
    {
        case TIOCGETA: case TIOCSETA: case TIOCSETAW: case TIOCSETAF:
        case TIOCGWINSZ: case TIOCSWINSZ: case TIOCGPGRP: case TIOCSPGRP:
        case TIOCSCTTY: case TIOCPTYGNAME: case TIOCPTYGRANT: case TIOCPTYUNLK:
            break;
        default:
            /* not a terminal request: LiveShim does the real ioctl */
            RKS_FAIL(call, ENOSYS);
    }

    if(call->in_count < 1 || call->in_ports == NULL || !MACH_PORT_VALID(call->in_ports[0]))
    {
        RKS_FAIL(call, EBADF);
    }
    rks_tty_t *tty = rks_tty_for_port(call->in_ports[0]);
    if(tty == NULL)
    {
#if RKS_TTY_TRACE
        if(request == TIOCSETA || request == TIOCSETAW || request == TIOCSETAF || request == TIOCGETA)
        {
            rks_logf("tty: pid %d termios ioctl 0x%lx on a non-tty port -> ENOTTY", call->proc->pid, request);
        }
#endif
        RKS_FAIL(call, ENOTTY);
    }
    int64_t result = rks_tty_ioctl(call, tty, request, arg);
    rks_tty_release(tty);
    return result;
}

int64_t rks_sys_openpty(rks_call_t *call)
{
    int master = -1, slave = -1;
    rks_tty_t *tty = rks_tty_create(&master, &slave);
    if(tty == NULL)
    {
        RKS_FAIL(call, ENOMEM);
    }
    rks_tty_release(tty);   /* the pump keeps it alive while either end is open */

    mach_port_t master_port = MACH_PORT_NULL;
    mach_port_t slave_port = MACH_PORT_NULL;
    bool ok = fileport_makeport(master, &master_port) == 0 && fileport_makeport(slave, &slave_port) == 0;
    close(master);
    close(slave);
    if(!ok)
    {
        if(MACH_PORT_VALID(master_port)) mach_port_deallocate(mach_task_self(), master_port);
        if(MACH_PORT_VALID(slave_port)) mach_port_deallocate(mach_task_self(), slave_port);
        RKS_FAIL(call, EBADF);
    }
    call->out_ports[call->out_count++] = master_port;
    call->out_ports[call->out_count++] = slave_port;
    return 0;
}

/* SPDX-License-Identifier: GPL-3.0-or-later
 * The TWRP terminal of the Nyxian recovery: a VT100/xterm subset emulator,
 * the PTY session it drives and the upstream-style <terminal> GUI object.
 */

#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* starts a shell and attaches it with NXTWRPTerminalAttach, returns false when it could not */
typedef bool (*NXTWRPTerminalLauncher)(void);
/* tells the TTY driver the terminal's size (TIOCSWINSZ from the master side) */
typedef void (*NXTWRPTerminalResizer)(int masterFD, unsigned short rows, unsigned short cols);

void NXTWRPTerminalSetLauncher(NXTWRPTerminalLauncher launcher, NXTWRPTerminalResizer resizer);

/* hands the master end of a session's TTY to the terminal, which owns it from now on */
void NXTWRPTerminalAttach(int masterFD, pid_t pid);
bool NXTWRPTerminalAttached(void);
/* the session's shell exited (status is a wait(2) status); the next key starts a new one */
void NXTWRPTerminalSessionEnded(pid_t pid, int status);
/* the size the visible terminal object currently shows (24x80 before the first render) */
void NXTWRPTerminalSize(unsigned short *rows, unsigned short *cols);

/* input from outside the TWRP keyboard (hardware keyboard), UTF-8 */
void NXTWRPTerminalSendText(const char *text, size_t length);
/* types a command line into the running shell once it is idle at its prompt (TWRP's editfile/changeterminal) */
void NXTWRPTerminalSendCommand(const char *text);
enum { NXTWRPTerminalKeyUp = 1, NXTWRPTerminalKeyDown, NXTWRPTerminalKeyRight, NXTWRPTerminalKeyLeft,
       NXTWRPTerminalKeyHome, NXTWRPTerminalKeyEnd, NXTWRPTerminalKeyPageUp, NXTWRPTerminalKeyPageDown,
       NXTWRPTerminalKeyDelete, NXTWRPTerminalKeyEscape, NXTWRPTerminalKeyTab, NXTWRPTerminalKeyBackspace, NXTWRPTerminalKeyReturn };
void NXTWRPTerminalSendKey(int key);
/* text written straight onto the screen (status lines of the recovery itself) */
void NXTWRPTerminalPrint(const char *text);

#ifdef __cplusplus
}
#endif

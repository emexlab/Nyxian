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

#ifndef PROCENVIRONMENT_LIMITS_H
#define PROCENVIRONMENT_LIMITS_H

#include <stdint.h>

/*
 * im sorry if you complain about the
 * amount of maximum processes, dont
 * complain about this to me, complain
 * about this to apple, their the reason
 * why, launchd doesnt let us spawn more.
 *
 * and jetsam is involved, which means
 * we can only set a soft limit for now.
 */
#define PROC_MAX 500    /* MARK: jetsam is involved, meaning hard no by apple */

/*
 * why would a process need more than 128
 * childs?
 */
#define CHILD_PROC_MAX 128

/*
 * the maximum count of pid that the
 * radix tree supports.
 */
#define PID_MAX INT32_MAX

#endif /* PROCENVIRONMENT_LIMITS_H */

/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef ARC_TARGET_SYSCALL_H
#define ARC_TARGET_SYSCALL_H

#define UNAME_MACHINE "arc"
#define UNAME_MINIMUM_RELEASE "4.15.0"

#define TARGET_MCL_CURRENT 1
#define TARGET_MCL_FUTURE  2
#define TARGET_MCL_ONFAULT 4

/* arch/arc/Kconfig selects CLONE_BACKWARDS */
#define TARGET_CLONE_BACKWARDS

#endif

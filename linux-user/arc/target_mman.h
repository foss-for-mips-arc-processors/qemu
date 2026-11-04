/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * arch/arc/include/asm/processor.h: TASK_UNMAPPED_BASE is TASK_SIZE / 3
 * and arch/arc/include/asm/elf.h: ELF_ET_DYN_BASE is 2 * TASK_SIZE / 3.
 *
 * TASK_SIZE depends on the MMU: 0x60000000 for ARCv2 (MMUv4) and HS5x
 * (MMUv6_32), 0xFFFF0000 for HS6x (MMUv6_48).
 *
 * TODO: The glibc for HS6x copies pointers using 32-bit instructions (for
 * example, MOV_S in __syscall_cancel_arch), which clear the upper half of
 * a register. So it works only while all user addresses are below 4 GiB.
 * The Linux kernel guarantees it with TASK_SIZE, but QEMU does not limit
 * the guest address space and mmap() may return addresses above 4 GiB.
 * Run qemu-arc64 with "-R 4G" to work around it until glibc is fixed.
 */
#ifdef TARGET_ARCV3_64
#define ARC_TASK_SIZE         0xFFFF0000ull
#else
#define ARC_TASK_SIZE         0x60000000ull
#endif

#define TASK_UNMAPPED_BASE    TARGET_PAGE_ALIGN(ARC_TASK_SIZE / 3)
#define ELF_ET_DYN_BASE       (2 * ARC_TASK_SIZE / 3)

#include "../generic/target_mman.h"

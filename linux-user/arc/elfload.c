/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu.h"
#include "loader.h"
#include "target_elf.h"

#ifdef TARGET_ARCV2
/* arch/arc/include/uapi/asm/elf.h, binutils include/elf/arc.h */
#define EF_ARC_MACH_MSK 0x000000ff
#define EF_ARC_MACH_EM  0x00000005

const char *get_elf_cpu_model(uint32_t eflags)
{
    if ((eflags & EF_ARC_MACH_MSK) == EF_ARC_MACH_EM) {
        return "arcem";
    }

    return "archs";
}
#elif defined(TARGET_ARCV3_32)
const char *get_elf_cpu_model(uint32_t eflags)
{
    return "hs5x";
}
#else
const char *get_elf_cpu_model(uint32_t eflags)
{
    return "hs6x";
}
#endif

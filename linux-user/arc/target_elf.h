/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef ARC_TARGET_ELF_H
#define ARC_TARGET_ELF_H

#if defined(TARGET_ARCV2)
#define ELF_CLASS               ELFCLASS32
#define ELF_MACHINE             EM_ARC_COMPACT2
#elif defined(TARGET_ARCV3_32)
#define ELF_CLASS               ELFCLASS32
#define ELF_MACHINE             EM_ARC_COMPACT3_32
#elif defined(TARGET_ARCV3_64)
#define ELF_CLASS               ELFCLASS64
#define ELF_MACHINE             EM_ARC_COMPACT3_64
#endif

#endif

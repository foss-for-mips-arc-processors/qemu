#ifndef ARC_CPU_PARAM_H
#define ARC_CPU_PARAM_H

/* TODO: Figure out how to deal with configurability of a page size */
#if defined(CONFIG_USER_ONLY) && defined(TARGET_ARCV2)
#define TARGET_PAGE_BITS 13
#else
#define TARGET_PAGE_BITS 12
#endif
#define TARGET_INSN_START_EXTRA_WORDS 0

#ifdef TARGET_ARCV3_64
#define TARGET_PHYS_ADDR_SPACE_BITS 48
#define TARGET_VIRT_ADDR_SPACE_BITS 64
#else
#define TARGET_PHYS_ADDR_SPACE_BITS 32
#define TARGET_VIRT_ADDR_SPACE_BITS 32
#endif

#endif

#ifndef ARC_CPU_MMU_H
#define ARC_CPU_MMU_H

#include "cpu.h"

#ifdef TARGET_ARCV2
#include "mmu_v2.h"
#else
#include "mmu_v3.h"
#endif

typedef enum {
    ARC_MMU_TRANSLATE_OK = 0,
    ARC_MMU_TRANSLATE_MISS,     /* no matching TLB entry */
    ARC_MMU_TRANSLATE_PROTV,    /* protection violation */
#ifdef TARGET_ARCV2
    ARC_MMU_TRANSLATE_OVERLAP,  /* machine check: more than one matching entry */
#else
    ARC_MMU_TRANSLATE_HOLE,
    ARC_MMU_TRANSLATE_ACCESS_FLAG
#endif
} ARCMMUTranslateResult;

ARCMMUTranslateResult arc_mmu_translate(CPUARCState *env, target_ulong vaddr,
                               MMUAccessType type, bool user, bool debug,
                               hwaddr *paddr, int *prot);
G_NORETURN void arc_mmu_raise(CPUARCState *env, ARCMMUTranslateResult result,
                              MMUAccessType access_type, target_ulong address,
                              uintptr_t retaddr);

bool arc_mmu_tlb_fill(CPUState *cs, vaddr address, int size,
                      MMUAccessType access_type, int mmu_idx,
                      bool probe, uintptr_t retaddr);

/* Saves a physical address in paddr. Return false in case of a TLB miss. */
bool arc_mmu_get_paddr(CPUARCState *env, target_ulong vaddr,
                       MMUAccessType access_type, hwaddr *paddr);

#endif

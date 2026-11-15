#include "qemu/osdep.h"
#include "cpu.h"
#include "mmu.h"
#include "exec/cputlb.h"
#include "exec/target_page.h"

bool arc_mmu_tlb_fill(CPUState *cs, vaddr address, int size,
                      MMUAccessType access_type, int mmu_idx,
                      bool probe, uintptr_t retaddr)
{
    CPUARCState *env = cpu_env(cs);
    bool user = (mmu_idx == 1);
    hwaddr paddr;
    int prot;
    ARCMMUTranslateResult result;

    result = arc_mmu_translate(env, address, access_type, user, false,
                               &paddr, &prot);
    if (result == ARC_MMU_TRANSLATE_OK) {
        tlb_set_page(cs, address & TARGET_PAGE_MASK, paddr & TARGET_PAGE_MASK,
                     prot, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }

    if (probe) {
        return false;
    }

    arc_mmu_raise(env, result, access_type, address, retaddr);
}

bool arc_mmu_get_paddr(CPUARCState *env, target_ulong vaddr,
                       MMUAccessType access_type, hwaddr *paddr)
{
    int prot;
    bool user = arc_in_user_mode(env);

    return arc_mmu_translate(env, vaddr, access_type, user, false, paddr, &prot)
           == ARC_MMU_TRANSLATE_OK;
}

hwaddr arc_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    CPUARCState *env = cpu_env(cs);
    hwaddr paddr;
    int prot;

    if (arc_mmu_translate(env, addr, MMU_DATA_LOAD, false, true, &paddr, &prot)
        == ARC_MMU_TRANSLATE_OK) {
        return paddr;
    }

    return -1;
}

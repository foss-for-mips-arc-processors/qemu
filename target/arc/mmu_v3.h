#ifndef ARC_CPU_MMU_V3_H
#define ARC_CPU_MMU_V3_H

#include "cpu.h"

/*
 * Table PTE. Last-level pages use TYPE=11 with the block/page layout.
 *
 * bits[1:0]   TYPE     00 invalid, 11 table
 * bits[62:59] APnxt, UXNnxt, KXNnxt  restrictions on later levels
 */
FIELD(ARC_MMU_PTE_TABLE, TYPE,    0,  2)
FIELD(ARC_MMU_PTE_TABLE, KXN_NXT, 59,  1)
FIELD(ARC_MMU_PTE_TABLE, UXN_NXT, 60,  1)
FIELD(ARC_MMU_PTE_TABLE, AP_NXT,  61,  2)

/*
 * Block and page PTE.
 *
 * bits[1:0]   TYPE     00 invalid, 01 block, 11 page (last level)
 * bits[7:6]   AP       leaf access permission (user, read-only)
 * bit[10]     AF       access flag
 * bits[54:53] UXN/KXN  leaf execute-never
 */
FIELD(ARC_MMU_PTE_BLOCK, TYPE,    0,  2)
FIELD(ARC_MMU_PTE_BLOCK, AP,      6,  2)
FIELD(ARC_MMU_PTE_BLOCK, AF,     10,  1)
FIELD(ARC_MMU_PTE_BLOCK, KXN,    53,  1)
FIELD(ARC_MMU_PTE_BLOCK, UXN,    54,  1)

enum {
    ARC_MMU_PTE_TYPE_INVALID = 0x0,
    ARC_MMU_PTE_TYPE_BLOCK   = 0x1,
    ARC_MMU_PTE_TYPE_TABLE   = 0x3,
};

/*
 * Root and PTE output addresses are not a descriptor field. Extract
 * bits [pa_bits-1 : alignment] from the RTP or PTE word. MMUv32 uses
 * a 40-bit PA and MMUv48 uses a 48-bit PA. MMUv52 is not supported
 * because TARGET_PHYS_ADDR_SPACE_BITS is 48.
 */

target_ulong arc_aux_mmu_tlb_data0_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_tlb_data0_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_tlb_data1_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_tlb_data1_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_tlb_idx_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_tlb_idx_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
void arc_aux_mmu_tlb_cmd_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
void arc_aux_mmu_ctrl_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_ctrl_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_ttbc_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_ttbc_read(CPUARCState *env, uintptr_t retaddr);
target_ulong arc_aux_mmu_fault_sts_read(CPUARCState *env, uintptr_t retaddr);

#ifdef TARGET_ARCV3_64

target_ulong arc_aux_mmu_rtp0_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_rtp0_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_rtp1_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_rtp1_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_mem_attr_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_mem_attr_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);

#else

target_ulong arc_aux_memseg_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_memseg_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_rtp0lo_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_rtp0lo_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_rtp0hi_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_rtp0hi_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_rtp1lo_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_rtp1lo_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_rtp1hi_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_rtp1hi_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_mem_attr_lo_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_mem_attr_lo_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);
target_ulong arc_aux_mmu_mem_attr_hi_read(CPUARCState *env, uintptr_t retaddr);
void arc_aux_mmu_mem_attr_hi_write(CPUARCState *env, target_ulong value, uintptr_t retaddr);

#endif

#endif

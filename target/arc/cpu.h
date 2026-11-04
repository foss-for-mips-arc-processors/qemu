#ifndef ARC_CPU_H
#define ARC_CPU_H

#include "qemu/osdep.h"
#include "cpu-qom.h"
#include "exec/cpu-common.h"
#include "exec/cpu-defs.h"
#include "exec/cpu-interrupt.h"
#include "exec/target_long.h"
#include "hw/registerfields.h"
#include "cpu_bits.h"
#include "aux.h"

#ifdef CONFIG_USER_ONLY
#define MMU_USER_IDX 1
#endif

#define TARGET_LONG_BITS_32 32
#define TARGET_LONG_BITS_64 64

#ifdef TARGET_ARCV3_64
#define ARC_INT_VECTOR_BASE_ALIGNMENT_BITS 11
#else
#define ARC_INT_VECTOR_BASE_ALIGNMENT_BITS 10
#endif

#define ARC_TBFLAG_USER_MODE      (1 << 0)
#define ARC_TBFLAG_DELAY_SLOT     (1 << 1)
#define ARC_TBFLAG_ZOL_ENABLED    (1 << 2)
#define ARC_TBFLAG_UNALIGNED_LDST (1 << 3)

#define arc_align_2_bytes(addr) (((addr) >> 1) << 1)
#define arc_align_4_bytes(addr) (((addr) >> 2) << 2)
#define arc_align_int_vector_base(addr) (((addr) >> ARC_INT_VECTOR_BASE_ALIGNMENT_BITS) << ARC_INT_VECTOR_BASE_ALIGNMENT_BITS)
#define arc_aligned_2_bytes(addr) (((addr) & 1) == 0)
#define arc_aligned_4_bytes(addr) (((addr) & 3) == 0)
#define arc_pc_to_pcl(addr) ((addr) & ~((target_ulong)3))
#define arc_in_user_mode(env) ((env)->aux_status32.user_mode)
#define arc_in_kernel_mode(env) (!arc_in_user_mode(env))
#define arc_cpu_has_firq(env) \
    (FIELD_EX32(env_archcpu(env)->aux_irq_build, AUX_IRQ_BUILD, FIRQ) != 0)

#ifdef TARGET_ARCV3_64
#define ARC_VECTOR_ENTRY_SHIFT 3
#else
#define ARC_VECTOR_ENTRY_SHIFT 2
#endif

typedef enum {
    ARC_EXCP_NONE = -1,
    ARC_EXCP_RESET,
    ARC_EXCP_MEMORY_ERROR,
    ARC_EXCP_ILLEGAL_INSTRUCTION,
    ARC_EXCP_ILLEGAL_INSTRUCTION_SEQUENCE,
    ARC_EXCP_MACHINE_CHECK_DOUBLE_FAULT,
    ARC_EXCP_PRIVILEGE_VIOLATION,
    ARC_EXCP_SWI,
    ARC_EXCP_TRAP,
    ARC_EXCP_DIVZERO,
    ARC_EXCP_MISALIGNED_DATA,
    ARC_EXCP_SEMIHOSTING,
    ARC_EXCP_TLB_MISS_I,    /* Instruction fetch TLB miss */
#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    ARC_EXCP_TLB_MISS_I_INV_ADDR,
    ARC_EXCP_TLB_MISS_I_ACCESS_FLAG,
#endif
    ARC_EXCP_TLB_MISS_D_LD, /* Data TLB miss on a load */
    ARC_EXCP_TLB_MISS_D_ST, /* Data TLB miss on a store */
#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    ARC_EXCP_TLB_MISS_D_INV_ADDR,
    ARC_EXCP_TLB_MISS_D_ACCESS_FLAG,
#endif
    ARC_EXCP_PROTV_EX,      /* Protection violation on instruction fetch */
    ARC_EXCP_PROTV_LD,      /* Protection violation on a load */
    ARC_EXCP_PROTV_ST,      /* Protection violation on a store */
    ARC_EXCP_TLB_OVERLAP,   /* Machine check: overlapping TLB entries */
} ARCException;

#define ARC_EXCP_PROTV_PARAM_MPU 0x4
#define ARC_EXCP_PROTV_PARAM_MMU 0x8

typedef enum {
    ARC_EXCP_CLASS_RESET = 0,
    ARC_EXCP_CLASS_MEMORY_ERROR,
    ARC_EXCP_CLASS_INSTRUCTION_ERROR,
    ARC_EXCP_CLASS_MACHINE_CHECK,
    ARC_EXCP_CLASS_IMMU_FAULT,
    ARC_EXCP_CLASS_DMMU_FAULT,
    ARC_EXCP_CLASS_PROTECTION_VIOLATION,
    ARC_EXCP_CLASS_PRIVILEGE_VIOLATION,
    ARC_EXCP_CLASS_SWI,
    ARC_EXCP_CLASS_TRAP,
    ARC_EXCP_CLASS_EXTENSION,
    ARC_EXCP_CLASS_DIVZERO,
    ARC_EXCP_CLASS_UNUSED_0,
    ARC_EXCP_CLASS_MISALIGNED,
    ARC_EXCP_CLASS_VECTOR_UNIT,
    ARC_EXCP_CLASS_UNUSED_1
} ARCExceptionClass;

#define ARC_NR_OF_EXCEPTIONS 16
#define ARC_MAX_NR_OF_INTERRUPTS 240
#define ARC_MAX_NR_OF_VECTORS ((ARC_NR_OF_EXCEPTIONS) + (ARC_MAX_NR_OF_INTERRUPTS))
#define ARC_FIRST_INTERRUPT_NR 16
#define ARC_LAST_INTERRUPT_NR 255
#define ARC_MAX_NR_OF_PRIORITIES 16
#define ARC_NR_OF_TIMERS 2
#define ARC_MAX_NR_OF_RF_BANKS 8

typedef struct CPUArchState {
    target_ulong gpr_banks[ARC_MAX_NR_OF_RF_BANKS][ARC_REGNUM_END];
    target_ulong gpr[ARC_REGNUM_END];
    target_ulong pc;

    arc_aux_status_t aux_status32;
    arc_aux_status_t aux_status32_p0;
    arc_aux_status_t aux_erstatus;

    /* Internal state of atomics */
    uint32_t     atomic_lf;
    target_ulong atomic_lpa;

    /* General auxiliary registers */
    target_ulong aux_int_vector_base;
    target_ulong aux_jli_base;
    target_ulong aux_ldi_base;
    target_ulong aux_ei_base;
    target_ulong aux_bta;

#ifdef TARGET_ARCV2
    target_ulong aux_lp_start;
    target_ulong aux_lp_end;
#endif

    /* Exception state auxiliary registers */
    target_ulong  aux_eret;     /* Exception Return Address */
    target_ulong  aux_erbta;    /* Exception Return BTA */
    arc_aux_ecr_t aux_ecr;      /* Exception Cause Register */
    target_ulong  aux_efa;      /* Exception Fault Address */
    target_ulong  aux_user_sp;  /* User stack pointer storage */

    /* Extra parameters for arc_cpu_do_interrupt exception handler */
    target_ulong excp_semihost_eret; /* ERET value for semihost through SWI */
    uint32_t     excp_parameter;
    bool         excp_double_fault;
    target_ulong excp_mem_addr;

    /*
     * IRQ registers
     *
     * Note that aux_irq_bank, aux_icause_banked and irq store data for
     * all vectors including exceptions (0-15) for convenience.
     */
    arc_aux_irq_ctrl_t   aux_irq_ctrl;
    arc_aux_irq_status_t aux_irq_bank[ARC_MAX_NR_OF_VECTORS];
    arc_aux_irq_act_t    aux_irq_act;
    uint32_t             aux_irq_select;
    uint32_t             aux_irq_hint;
    uint32_t             aux_icause_banked[ARC_MAX_NR_OF_PRIORITIES];

    /* Timer registers (timer 0 and timer 1) */
    uint32_t     aux_timer_control[ARC_NR_OF_TIMERS];
    target_ulong aux_timer_limit[ARC_NR_OF_TIMERS];
    uint64_t     timer_last_clk[ARC_NR_OF_TIMERS]; /* Virtual time (ns) when COUNTn was last 0 */

#ifdef TARGET_ARCV2
    /* ARCv2 MMU registers */
    uint32_t aux_mmu_tlbpd0;
    uint32_t aux_mmu_tlbpd1;
    uint32_t aux_mmu_scratch_data0;
    arc_aux_mmu_tlbindex_t aux_mmu_tlbindex;
    arc_aux_mmu_pid_t aux_mmu_pid;

    /* Joint TLB and per-set round-robin victim selection */
    arc_mmu_tlb_entry_t mmu_tlb[ARC_MMU_TLB_ENTRIES];
    uint8_t mmu_way_next[ARC_MMU_TLB_SETS];
#endif

#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    uint64_t aux_mmu_rtp0;
    uint64_t aux_mmu_rtp1;
    uint32_t aux_mmu_tlb_idx;
    uint32_t aux_mmu_tlb_cmd;
    target_ulong aux_mmu_tlb_data0;
    target_ulong aux_mmu_tlb_data1;
    uint32_t aux_mmu_ctrl;
    uint32_t aux_mmu_ttbc;
    uint32_t aux_mmu_fault_sts;
    uint64_t aux_mmu_mem_attr;
#endif

    /* Instruction cache registers */
    arc_aux_ic_ctrl_t aux_ic_ctrl;
    target_ulong aux_ic_endr;
    target_ulong aux_ic_ptag;
    target_ulong aux_ic_ptag_hi;

    /* Data cache registers */
    arc_aux_dc_ctrl_t aux_dc_ctrl;
    target_ulong aux_dc_endr;
    target_ulong aux_dc_ptag_hi;

#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    uint32_t aux_hw_pf_ctrl;
#endif

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    void *irq[ARC_MAX_NR_OF_VECTORS];
    struct QEMUTimer *cpu_timer[ARC_NR_OF_TIMERS];
} CPUARCState;

typedef struct {
    bool enable_exceptions;
    bool exit_on_halt;
    uint32_t rf_banks;
    bool firq;
    bool has_interrupts;
    bool has_timer0;
    bool has_timer1;
    uint32_t freq_hz; /* CPU frequency in Hz, used to drive the timers */
#ifdef TARGET_ARCV3_64
    uint32_t mmu_type; /* MMU_BUILD.TYPE: 1=V48-4K, 2=V48-16K, 3=V48-64K, 4=V52 */
#endif
} ArcCPUConfig;

struct ArchCPU {
    CPUState parent_obj;

    CPUARCState env;

    ArcCPUConfig cfg;

    uint32_t aux_identity;
    uint32_t aux_micro_arch_build;
    uint32_t aux_bcr_ver;
    uint32_t aux_bta_link_build;
    uint32_t aux_vecbase_ac_build;
    uint32_t aux_rf_build;
    uint32_t aux_multiply_build;
    uint32_t aux_swap_build;
    uint32_t aux_norm_build;
    uint32_t aux_minmax_build;
    uint32_t aux_barrel_build;
    uint32_t aux_irq_build;
    uint32_t aux_isa_config;
    uint32_t aux_timer_build;
    uint32_t aux_mmu_build;
    uint32_t aux_i_cache_build;
    uint32_t aux_d_cache_build;
};

static inline bool arc_cpu_is_em(const ARCCPU *cpu)
{
    return object_dynamic_cast(OBJECT(cpu), TYPE_ARC_CPU_EM) != NULL;
}

static inline bool arc_cpu_is_hs(const ARCCPU *cpu)
{
    return object_dynamic_cast(OBJECT(cpu), TYPE_ARC_CPU_HS) != NULL;
}

static inline bool arc_cpu_is_arcv2(const ARCCPU *cpu)
{
    return arc_cpu_is_em(cpu) || arc_cpu_is_hs(cpu);
}

static inline bool arc_cpu_is_hs5x(const ARCCPU *cpu)
{
    return object_dynamic_cast(OBJECT(cpu), TYPE_ARC_CPU_HS5X) != NULL;
}

static inline bool arc_cpu_is_hs6x(const ARCCPU *cpu)
{
    return object_dynamic_cast(OBJECT(cpu), TYPE_ARC_CPU_HS6X) != NULL;
}

struct ARCCPUClass {
    CPUClass parent_class;

    DeviceRealize parent_realize;
    ResettablePhases parent_phases;
};

#define CPU_RESOLVING_TYPE TYPE_ARC_CPU

void arc_cpu_dump_state(CPUState *cpu, FILE *f, int flags);
int arc_cpu_gdb_read_register(CPUState *cpu, GByteArray *buf, int reg);
int arc_cpu_gdb_write_register(CPUState *cpu, uint8_t *buf, int reg);
uint32_t arc_cpu_effective_gpr_bank(CPUARCState *env, uint32_t n);
void arc_cpu_switch_gpr_bank(CPUARCState *env, uint32_t n);

#ifndef CONFIG_USER_ONLY
void arc_cpu_do_interrupt(CPUState *cpu);
hwaddr arc_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
void arc_cpu_do_transaction_failed(CPUState *cpu, hwaddr physaddr, vaddr addr,
                                   unsigned size, MMUAccessType access_type,
                                   int mmu_idx, MemTxAttrs attrs,
                                   MemTxResult response, uintptr_t retaddr);
G_NORETURN void arc_cpu_do_unaligned_access(CPUState *cpu, vaddr addr,
                                            MMUAccessType access_type, int mmu_idx,
                                            uintptr_t retaddr);

/* Semihosting entry point (arc-semi.c) */
void do_arc_semihosting(CPUARCState *env);
#endif

void arc_translate_init(void);
void arc_translate_code(CPUState *cs, TranslationBlock *tb,
                        int *max_insns, vaddr pc, void *host_pc);
void arc_halt(CPUState *cs);
G_NORETURN void arc_raise_exception(CPUARCState *env, int exception,
                                    int parameter, uintptr_t pc);
G_GNUC_PRINTF(1, 2) void arc_exit_with_error(const char *fmt, ...);

#endif /* ARC_CPU_H */

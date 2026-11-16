#include "qemu/osdep.h"
#include "exec/target_long.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "cpu_bits.h"
#include "qemu/log.h"
#include "exec/helper-proto.h"
#include "timer.h"
#include "mmu.h"
#include "cache.h"
#include "irq.h"

static G_NORETURN void arc_aux_raise_illegal_instruction(CPUARCState *env, uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);

    env->excp_parameter = 0;

    cs->exception_index = ARC_EXCP_ILLEGAL_INSTRUCTION;
    cpu_loop_exit_restore(cs, retaddr);
}

static G_NORETURN void arc_aux_raise_privilege_violation(CPUARCState *env, uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);

    env->excp_parameter = 0;

    cs->exception_index = ARC_EXCP_PRIVILEGE_VIOLATION;
    cpu_loop_exit_restore(cs, retaddr);
}

typedef enum {
    ARC_AUX_PERM_r,
    ARC_AUX_PERM_R,
    ARC_AUX_PERM_w,
    ARC_AUX_PERM_W,
    ARC_AUX_PERM_rw,
    ARC_AUX_PERM_rW,
    ARC_AUX_PERM_RW,
} ARCAUXPermission;

typedef target_ulong (*aux_read_function_t)(CPUARCState *, uintptr_t);
typedef void (*aux_write_function_t)(CPUARCState *, target_ulong, uintptr_t);

typedef struct {
    const char *name;
    uint32_t address;
    ARCAUXPermission permission;
    aux_read_function_t read_function;
    aux_write_function_t write_function;
} arc_aux_record_t;

#define arc_aux_default_read(name, field) \
    static target_ulong arc_aux_##name##_read(CPUARCState *env, uintptr_t retaddr) \
    { \
        return env->field; \
    }

#define arc_aux_default_write(name, field) \
    static void arc_aux_##name##_write(CPUARCState *env, target_ulong value, uintptr_t retaddr) \
    { \
        env->field = value; \
    }

#define arc_aux_bcr_default_read(name, field) \
    static target_ulong arc_aux_##name##_read(CPUARCState *env, uintptr_t retaddr) \
    { \
        return env_archcpu(env)->field; \
    }

static inline target_ulong arc_aux_stub_read(CPUARCState *env, uintptr_t retaddr)
{
    return 0;
}

static inline void arc_aux_stub_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
}

#ifdef TARGET_ARCV2
/* Ignore MEMSEG; PAE is not implemented. */
static target_ulong arc_aux_memseg_read(CPUARCState *env, uintptr_t retaddr)
{
    return 0;
}

static void arc_aux_memseg_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    if (value != 0) {
        qemu_log_mask(LOG_GUEST_ERROR, "arc: aux: PAE is not implemented yer");
        g_assert_not_reached();
    }
}
#endif

arc_aux_default_read(pc, pc);
arc_aux_default_read(user_sp, aux_user_sp);
arc_aux_default_write(user_sp, aux_user_sp);
arc_aux_default_read(efa, aux_efa);
arc_aux_default_write(efa, aux_efa);

#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
arc_aux_default_read(hw_pf_ctrl, aux_hw_pf_ctrl);
arc_aux_default_write(hw_pf_ctrl, aux_hw_pf_ctrl);
#endif

arc_aux_bcr_default_read(identity, aux_identity)
arc_aux_bcr_default_read(bcr_ver, aux_bcr_ver)
arc_aux_bcr_default_read(bta_link_build, aux_bta_link_build)
arc_aux_bcr_default_read(vecbase_ac_build, aux_vecbase_ac_build)
arc_aux_bcr_default_read(rf_build, aux_rf_build)
arc_aux_bcr_default_read(multiply_build, aux_multiply_build)
arc_aux_bcr_default_read(swap_build, aux_swap_build)
arc_aux_bcr_default_read(norm_build, aux_norm_build)
arc_aux_bcr_default_read(minmax_build, aux_minmax_build)
arc_aux_bcr_default_read(barrel_build, aux_barrel_build)
arc_aux_bcr_default_read(isa_config, aux_isa_config)
arc_aux_bcr_default_read(irq_build, aux_irq_build)
arc_aux_bcr_default_read(micro_arch_build, aux_micro_arch_build)
arc_aux_bcr_default_read(mmu_build, aux_mmu_build)

static target_ulong arc_aux_exec_ctrl_read(CPUARCState *env, uintptr_t retaddr)
{
    /* Dual issue feature is enabled */
    /* TODO: Remove this magic number */
    return 0;
}

#ifdef TARGET_ARCV2
static target_ulong arc_aux_lp_start_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_align_2_bytes(env->aux_lp_start);
}

static void arc_aux_lp_start_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_lp_start = arc_align_2_bytes(value);
}

static target_ulong arc_aux_lp_end_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_align_2_bytes(env->aux_lp_end);
}

static void arc_aux_lp_end_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_lp_end = arc_align_2_bytes(value);
}
#endif

static target_ulong arc_aux_int_vector_base_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_align_int_vector_base(env->aux_int_vector_base);
}

static void arc_aux_int_vector_base_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_int_vector_base = arc_align_int_vector_base(value);
}

static target_ulong arc_aux_status32_read(CPUARCState *env, uintptr_t retaddr)
{
    target_ulong result = 0;

    if (arc_in_user_mode(env)) {
        result = FIELD_DP32(result, AUX_STATUS32, Vf, env->aux_status32.overflow_flag);
        result = FIELD_DP32(result, AUX_STATUS32, Cf, env->aux_status32.carry_flag);
        result = FIELD_DP32(result, AUX_STATUS32, Nf, env->aux_status32.negative_flag);
        result = FIELD_DP32(result, AUX_STATUS32, Zf, env->aux_status32.zero_flag);
    } else {
        result = arc_pack_status32(&env->aux_status32);
    }

    return result;
}

static target_ulong arc_aux_status32_p0_read(CPUARCState *env, uintptr_t retaddr)
{
    if (!arc_cpu_has_firq(env)) {
        return 0;
    }

    /* STATUS32_P0.H is always 0. */
    return arc_pack_status32(&env->aux_status32_p0) & ~1;
}

static void arc_aux_status32_p0_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    if (!arc_cpu_has_firq(env) || arc_in_user_mode(env)) {
        return;
    }

    arc_unpack_status32(&env->aux_status32_p0, value);
    env->aux_status32_p0.halt = 0;
    env->aux_status32_p0.register_bank =
        arc_cpu_effective_gpr_bank(env, env->aux_status32_p0.register_bank);
}

static target_ulong arc_aux_jli_base_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_align_4_bytes(env->aux_jli_base);
}

static void arc_aux_jli_base_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_jli_base = arc_align_4_bytes(value);
}

#ifndef TARGET_ARCV3_64
static target_ulong arc_aux_ldi_base_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_align_4_bytes(env->aux_ldi_base);
}

static void arc_aux_ldi_base_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_ldi_base = arc_align_4_bytes(value);
}
#endif

static target_ulong arc_aux_ei_base_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_align_4_bytes(env->aux_ei_base);
}

static void arc_aux_ei_base_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_ei_base = arc_align_4_bytes(value);
}

static target_ulong arc_aux_eret_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_align_2_bytes(env->aux_eret);
}

static void arc_aux_eret_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_eret = arc_align_2_bytes(value);
}

static target_ulong arc_aux_erbta_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_align_2_bytes(env->aux_erbta);
}

static void arc_aux_erbta_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_erbta = arc_align_2_bytes(value);
}

static target_ulong arc_aux_erstatus_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_pack_aux_erstatus(&env->aux_erstatus);
}

static void arc_aux_erstatus_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    arc_unpack_aux_erstatus(&env->aux_erstatus, value);

    env->aux_erstatus.register_bank =
        arc_cpu_effective_gpr_bank(env, env->aux_erstatus.register_bank);
}

static target_ulong arc_aux_ecr_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_pack_aux_ecr(&env->aux_ecr);
}

static void arc_aux_ecr_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    arc_unpack_aux_ecr(&env->aux_ecr, value);
}

static target_ulong arc_aux_bta_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_align_2_bytes(env->aux_bta);
}

static void arc_aux_bta_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_bta = arc_align_2_bytes(value);
}

/*
 * Interrupt controller registers
 */

static target_ulong arc_aux_irq_select_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_irq_select & 0xFF;
}

static void arc_aux_irq_select_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_irq_select = value & 0xFF;
}

static target_ulong arc_aux_irq_priority_read(CPUARCState *env, uintptr_t retaddr)
{
    BQL_LOCK_GUARD();

    g_assert(env->aux_irq_select <= ARC_LAST_INTERRUPT_NR);

    return env->aux_irq_bank[env->aux_irq_select].priority & 0xF;
}

static void arc_aux_irq_priority_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    BQL_LOCK_GUARD();

    g_assert(env->aux_irq_select <= ARC_LAST_INTERRUPT_NR);

    if (env->aux_irq_select >= ARC_FIRST_INTERRUPT_NR) {
        env->aux_irq_bank[env->aux_irq_select].priority = value & 0xF;
    }
}

static target_ulong arc_aux_irq_enable_read(CPUARCState *env, uintptr_t retaddr)
{
    BQL_LOCK_GUARD();

    g_assert(env->aux_irq_select <= ARC_LAST_INTERRUPT_NR);

    return env->aux_irq_bank[env->aux_irq_select].enable & 0x1;
}

static void arc_aux_irq_enable_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    BQL_LOCK_GUARD();

    g_assert(env->aux_irq_select <= ARC_LAST_INTERRUPT_NR);

    if (env->aux_irq_select >= ARC_FIRST_INTERRUPT_NR) {
        env->aux_irq_bank[env->aux_irq_select].enable = value & 0x1;
    }
}

static target_ulong arc_aux_irq_pending_read(CPUARCState *env, uintptr_t retaddr)
{
    BQL_LOCK_GUARD();

    g_assert(env->aux_irq_select <= ARC_LAST_INTERRUPT_NR);

    return env->aux_irq_bank[env->aux_irq_select].pending & 0x1;
}

static target_ulong arc_aux_irq_trigger_read(CPUARCState *env, uintptr_t retaddr)
{
    BQL_LOCK_GUARD();

    g_assert(env->aux_irq_select <= ARC_LAST_INTERRUPT_NR);

    return env->aux_irq_bank[env->aux_irq_select].trigger & 0x1;
}

static void arc_aux_irq_trigger_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    qemu_log_mask(LOG_UNIMP, "arc: aux: IRQ_TRIGGER is not implemented\n");
    arc_aux_raise_illegal_instruction(env, retaddr);
}

static void arc_aux_irq_pulse_cancel_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    qemu_log_mask(LOG_UNIMP, "arc: aux: IRQ_PULSE_CANCEL is not implemented\n");
    arc_aux_raise_illegal_instruction(env, retaddr);
}

static target_ulong arc_aux_irq_status_read(CPUARCState *env, uintptr_t retaddr)
{
    BQL_LOCK_GUARD();

    g_assert(env->aux_irq_select <= ARC_LAST_INTERRUPT_NR);

    return arc_pack_irq_status(&env->aux_irq_bank[env->aux_irq_select]);
}

static target_ulong arc_aux_irq_ctrl_read(CPUARCState *env, uintptr_t retaddr)
{
    g_assert(env->aux_irq_ctrl.nr <= 16);

    return arc_pack_irq_ctrl(&env->aux_irq_ctrl);
}

static void arc_aux_irq_ctrl_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    arc_unpack_aux_irq_ctrl(&env->aux_irq_ctrl, value);

    g_assert(env->aux_irq_ctrl.nr <= 16);
}

static target_ulong arc_aux_irq_priority_pending_read(CPUARCState *env, uintptr_t retaddr)
{
    BQL_LOCK_GUARD();

    return arc_get_irq_priority_pending(env, false);
}

static target_ulong arc_aux_irq_act_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_pack_aux_irq_act(&env->aux_irq_act);
}

static void arc_aux_irq_act_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    arc_unpack_aux_irq_act(&env->aux_irq_act, value);
}

/*
 * ICAUSE returns a number of active (taken) IRQ with the highest priority.
 */
static target_ulong arc_aux_icause_read(CPUARCState *env, uintptr_t retaddr)
{
    uint32_t irq_number = 0;
    uint32_t priority;

    if (env->aux_irq_act.active != 0) {
        priority = ctz32(env->aux_irq_act.active);
        irq_number = env->aux_icause_banked[priority];
    }

    return irq_number;
}

static arc_aux_record_t aux_records[] = {
#ifdef TARGET_ARCV2
    {"LP_START",             0x002, ARC_AUX_PERM_rw, arc_aux_lp_start_read,             arc_aux_lp_start_write},
    {"LP_END",               0x003, ARC_AUX_PERM_rw, arc_aux_lp_end_read,               arc_aux_lp_end_write},
#endif
    {"IDENTITY",             0x004, ARC_AUX_PERM_r,  arc_aux_identity_read,             NULL},
    {"PC",                   0x006, ARC_AUX_PERM_r,  arc_aux_pc_read,                   NULL},
#ifndef TARGET_ARCV3_64
    {"MEMSEG",               0x007, ARC_AUX_PERM_RW, arc_aux_memseg_read,               arc_aux_memseg_write},
#endif
    {"EXEC_CTRL",            0x008, ARC_AUX_PERM_R,  arc_aux_exec_ctrl_read,            NULL},
    {"STATUS32",             0x00A, ARC_AUX_PERM_r,  arc_aux_status32_read,             NULL},
    {"STATUS32_P0",          0x00B, ARC_AUX_PERM_RW, arc_aux_status32_p0_read,          arc_aux_status32_p0_write},
    {"USER_SP",              0x00D, ARC_AUX_PERM_RW, arc_aux_user_sp_read,              arc_aux_user_sp_write},
    {"AUX_IRQ_CTRL",         0x00E, ARC_AUX_PERM_RW, arc_aux_irq_ctrl_read,             arc_aux_irq_ctrl_write},

    /* Instruction cache registers */
    {"IC_IVIC",              0x010, ARC_AUX_PERM_W,  NULL,                              arc_aux_ic_ivic_write},
    {"IC_CTRL",              0x011, ARC_AUX_PERM_RW, arc_aux_ic_ctrl_read,              arc_aux_ic_ctrl_write},
    {"IC_IVIR",              0x016, ARC_AUX_PERM_W,  NULL,                              arc_aux_ic_ivir_write},
    {"IC_ENDR",              0x017, ARC_AUX_PERM_RW, arc_aux_ic_endr_read,              arc_aux_ic_endr_write},
    {"IC_IVIL",              0x019, ARC_AUX_PERM_W,  NULL,                              arc_aux_ic_ivil_write},
    {"IC_PTAG",              0x01E, ARC_AUX_PERM_RW, arc_aux_ic_ptag_read,              arc_aux_ic_ptag_write},
    {"IC_PTAG_HI",           0x01F, ARC_AUX_PERM_RW, arc_aux_ic_ptag_hi_read,           arc_aux_ic_ptag_hi_write},

    {"COUNT0",               0x021, ARC_AUX_PERM_RW, arc_aux_timer0_count_read,         arc_aux_timer0_count_write},
    {"CONTROL0",             0x022, ARC_AUX_PERM_RW, arc_aux_timer0_control_read,       arc_aux_timer0_control_write},
    {"LIMIT0",               0x023, ARC_AUX_PERM_RW, arc_aux_timer0_limit_read,         arc_aux_timer0_limit_write},
    {"INT_VECTOR_BASE",      0x025, ARC_AUX_PERM_RW, arc_aux_int_vector_base_read,      arc_aux_int_vector_base_write},
    {"AUX_IRQ_ACT",          0x043, ARC_AUX_PERM_RW, arc_aux_irq_act_read,              arc_aux_irq_act_write},

    /* Data cache registers */
    {"DC_IVDC",              0x047, ARC_AUX_PERM_W,  NULL,                              arc_aux_dc_ivdc_write},
    {"DC_CTRL",              0x048, ARC_AUX_PERM_RW, arc_aux_dc_ctrl_read,              arc_aux_dc_ctrl_write},
    {"DC_IVDL",              0x04A, ARC_AUX_PERM_W,  NULL,                              arc_aux_dc_ivdl_write},
    {"DC_STARTR",            0x04D, ARC_AUX_PERM_W,  NULL,                              arc_aux_dc_startr_write},
    {"DC_ENDR",              0x04E, ARC_AUX_PERM_RW, arc_aux_dc_endr_read,              arc_aux_dc_endr_write},
#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    {"HW_PF_CTRL",           0x04F, ARC_AUX_PERM_RW, arc_aux_hw_pf_ctrl_read,           arc_aux_hw_pf_ctrl_write},
#endif
    {"AUX_VOLATILE",         0x05E, ARC_AUX_PERM_R,  arc_aux_volatile_read,             NULL},
    {"DC_PTAG_HI",           0x05F, ARC_AUX_PERM_RW, arc_aux_dc_ptag_hi_read,           arc_aux_dc_ptag_hi_write},

    /* BCR registers: 0x60 - 0x7F */
    {"BCR_VER",              0x060, ARC_AUX_PERM_R,  arc_aux_bcr_ver_read,              NULL},
    {"BTA_LINK_BUILD",       0x063, ARC_AUX_PERM_R,  arc_aux_bta_link_build_read,       NULL},
    {"VEC_BASE_AC_BUILD",    0x068, ARC_AUX_PERM_R,  arc_aux_vecbase_ac_build_read,     NULL},
    {"RF_BUILD",             0x06E, ARC_AUX_PERM_R,  arc_aux_rf_build_read,             NULL},
    {"MMU_BUILD",            0x06F, ARC_AUX_PERM_R,  arc_aux_mmu_build_read,            NULL},
    {"D_CACHE_BUILD",        0x072, ARC_AUX_PERM_R,  arc_aux_d_cache_build_read,        NULL},
    {"DCCM_BUILD",           0x074, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"TIMER_BUILD",          0x075, ARC_AUX_PERM_R,  arc_aux_timer_build_read,          NULL},
    {"AP_BUILD",             0x076, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"I_CACHE_BUILD",        0x077, ARC_AUX_PERM_R,  arc_aux_i_cache_build_read,        NULL},
    {"ICCM_BUILD",           0x078, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"DSP_BUILD",            0x07A, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"MPY_BUILD",            0x07B, ARC_AUX_PERM_R,  arc_aux_multiply_build_read,       NULL},
    {"SWAP_BUILD",           0x07C, ARC_AUX_PERM_R,  arc_aux_swap_build_read,           NULL},
    {"NORM_BUILD",           0x07D, ARC_AUX_PERM_R,  arc_aux_norm_build_read,           NULL},
    {"MINMAX_BUILD",         0x07E, ARC_AUX_PERM_R,  arc_aux_minmax_build_read,         NULL},
    {"BARREL_BUILD",         0x07F, ARC_AUX_PERM_R,  arc_aux_barrel_build_read,         NULL},

    /* BCR registers: 0xC0 - 0xFF */
    {"BPU_BUILD",            0x0C0, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"ISA_CONFIG",           0x0C1, ARC_AUX_PERM_R,  arc_aux_isa_config_read,           NULL},
    {"ERP_BUILD",            0x0C7, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"FPU_BUILD",            0x0C8, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"AGU_BUILD",            0x0CC, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"SLC_BUILD",            0x0CE, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"CLUSTER_BUILD",        0x0CF, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"CONNECT_SYSTEM_BUILD", 0x0D0, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"RTT_BUILD",            0x0F2, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"IRQ_BUILD",            0x0F3, ARC_AUX_PERM_R,  arc_aux_irq_build_read,            NULL},
    {"PCT_BUILD",            0x0F5, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},
    {"MICRO_ARCH_BUILD",     0x0F9, ARC_AUX_PERM_R,  arc_aux_micro_arch_build_read,     NULL},
    {"SMART_BUILD",          0x0FF, ARC_AUX_PERM_R,  arc_aux_stub_read,                 NULL},

    {"COUNT1",               0x100, ARC_AUX_PERM_RW, arc_aux_timer1_count_read,         arc_aux_timer1_count_write},
    {"CONTROL1",             0x101, ARC_AUX_PERM_RW, arc_aux_timer1_control_read,       arc_aux_timer1_control_write},
    {"LIMIT1",               0x102, ARC_AUX_PERM_RW, arc_aux_timer1_limit_read,         arc_aux_timer1_limit_write},
    {"IRQ_PRIORITY_PENDING", 0x200, ARC_AUX_PERM_R,  arc_aux_irq_priority_pending_read, NULL},
    {"IRQ_PRIORITY",         0x206, ARC_AUX_PERM_RW, arc_aux_irq_priority_read,         arc_aux_irq_priority_write},
    {"JLI_BASE",             0x290, ARC_AUX_PERM_rw, arc_aux_jli_base_read,             arc_aux_jli_base_write},
#ifndef TARGET_ARCV3_64
    {"LDI_BASE",             0x291, ARC_AUX_PERM_rw, arc_aux_ldi_base_read,             arc_aux_ldi_base_write},
#endif
    {"EI_BASE",              0x292, ARC_AUX_PERM_rw, arc_aux_ei_base_read,              arc_aux_ei_base_write},
    {"ERET",                 0x400, ARC_AUX_PERM_RW, arc_aux_eret_read,                 arc_aux_eret_write},
    {"ERBTA",                0x401, ARC_AUX_PERM_RW, arc_aux_erbta_read,                arc_aux_erbta_write},
    {"ERSTATUS",             0x402, ARC_AUX_PERM_RW, arc_aux_erstatus_read,             arc_aux_erstatus_write},
    {"ECR",                  0x403, ARC_AUX_PERM_RW, arc_aux_ecr_read,                  arc_aux_ecr_write},
    {"EFA",                  0x404, ARC_AUX_PERM_RW, arc_aux_efa_read,                  arc_aux_efa_write},
    {"ICAUSE",               0x40A, ARC_AUX_PERM_R,  arc_aux_icause_read,               NULL},
    {"IRQ_SELECT",           0x40B, ARC_AUX_PERM_RW, arc_aux_irq_select_read,           arc_aux_irq_select_write},
    {"IRQ_ENABLE",           0x40C, ARC_AUX_PERM_RW, arc_aux_irq_enable_read,           arc_aux_irq_enable_write},
    {"IRQ_TRIGGER",          0x40D, ARC_AUX_PERM_RW, arc_aux_irq_trigger_read,          arc_aux_irq_trigger_write},
    {"IRQ_STATUS",           0x40F, ARC_AUX_PERM_R,  arc_aux_irq_status_read,           NULL},
    {"BTA",                  0x412, ARC_AUX_PERM_RW, arc_aux_bta_read,                  arc_aux_bta_write},
    {"IRQ_PULSE_CANCEL",     0x415, ARC_AUX_PERM_W,  NULL,                              arc_aux_irq_pulse_cancel_write},
    {"IRQ_PENDING",          0x416, ARC_AUX_PERM_R,  arc_aux_irq_pending_read,          NULL},

#ifdef TARGET_ARCV2
    {"TLBPD0",               0x460, ARC_AUX_PERM_RW, arc_aux_tlbpd0_read,               arc_aux_tlbpd0_write},
    {"TLBPD1",               0x461, ARC_AUX_PERM_RW, arc_aux_tlbpd1_read,               arc_aux_tlbpd1_write},
    {"TLBPD1_HI",            0x463, ARC_AUX_PERM_RW, arc_aux_stub_read,                 arc_aux_stub_write},
    {"TLBINDEX",             0x464, ARC_AUX_PERM_RW, arc_aux_tlbindex_read,             arc_aux_tlbindex_write},
    {"TLBCOMMAND",           0x465, ARC_AUX_PERM_W,  NULL,                              arc_aux_tlbcommand_write},
    {"PID",                  0x468, ARC_AUX_PERM_RW, arc_aux_pid_read,                  arc_aux_pid_write},
    {"SCRATCH_DATA0",        0x46C, ARC_AUX_PERM_RW, arc_aux_scratch_data0_read,        arc_aux_scratch_data0_write}
#endif

#ifdef TARGET_ARCV3_64
    {"MMU_RTP0",             0x460, ARC_AUX_PERM_RW, arc_aux_mmu_rtp0_read,             arc_aux_mmu_rtp0_write},
    {"MMU_RTP1",             0x462, ARC_AUX_PERM_RW, arc_aux_mmu_rtp1_read,             arc_aux_mmu_rtp1_write},
    {"MMU_MEM_ATTR",         0x46A, ARC_AUX_PERM_RW, arc_aux_mmu_mem_attr_read,         arc_aux_mmu_mem_attr_write},
#endif

#ifdef TARGET_ARCV3_32
    {"MMU_RTP0LO",           0x460, ARC_AUX_PERM_RW, arc_aux_mmu_rtp0lo_read,           arc_aux_mmu_rtp0lo_write},
    {"MMU_RTP0HI",           0x461, ARC_AUX_PERM_RW, arc_aux_mmu_rtp0hi_read,           arc_aux_mmu_rtp0hi_write},
    {"MMU_RTP1LO",           0x462, ARC_AUX_PERM_RW, arc_aux_mmu_rtp1lo_read,           arc_aux_mmu_rtp1lo_write},
    {"MMU_RTP1HI",           0x463, ARC_AUX_PERM_RW, arc_aux_mmu_rtp1hi_read,           arc_aux_mmu_rtp1hi_write},
    {"MMU_MEM_ATTR_LO",      0x46A, ARC_AUX_PERM_RW, arc_aux_mmu_mem_attr_lo_read,      arc_aux_mmu_mem_attr_lo_write},
    {"MMU_MEM_ATTR_HI",      0x46B, ARC_AUX_PERM_RW, arc_aux_mmu_mem_attr_hi_read,      arc_aux_mmu_mem_attr_hi_write},
#endif

#if defined(TARGET_ARCV3_32) || defined(TARGET_ARCV3_64)
    {"MMU_TLB_IDX",          0x464, ARC_AUX_PERM_RW, arc_aux_mmu_tlb_idx_read,          arc_aux_mmu_tlb_idx_write},
    {"MMU_TLB_CMD",          0x465, ARC_AUX_PERM_W,  NULL,                              arc_aux_mmu_tlb_cmd_write},
    {"MMU_TLB_DATA0",        0x466, ARC_AUX_PERM_RW, arc_aux_mmu_tlb_data0_read,        arc_aux_mmu_tlb_data0_write},
    {"MMU_TLB_DATA1",        0x467, ARC_AUX_PERM_RW, arc_aux_mmu_tlb_data1_read,        arc_aux_mmu_tlb_data1_write},
    {"MMU_CTRL",             0x468, ARC_AUX_PERM_RW, arc_aux_mmu_ctrl_read,             arc_aux_mmu_ctrl_write},
    {"MMU_TTBC",             0x469, ARC_AUX_PERM_RW, arc_aux_mmu_ttbc_read,             arc_aux_mmu_ttbc_write},
    {"MMU_FAULT_STATUS",     0x46C, ARC_AUX_PERM_R,  arc_aux_mmu_fault_sts_read,        NULL},
#endif
};

static size_t aux_records_length = sizeof(aux_records) / sizeof(arc_aux_record_t);

static bool arc_aux_is_bcr(target_ulong aux_regnum)
{
    switch (aux_regnum) {
    case 0x060 ... 0x07F:
    case 0x0C0 ... 0x0FF:
    case 0xF60 ... 0xFFF:
        return true;
    default:
        return false;
    }
}

static target_ulong do_aux_reg_read_tl(CPUARCState *env, target_ulong aux_regnum, uintptr_t retaddr)
{
    arc_aux_record_t *record = NULL;
    ARCAUXPermission permission;

    for (size_t i = 0; i < aux_records_length; i++) {
        if (aux_regnum == aux_records[i].address) {
            record = &aux_records[i];
        }
    }

    /* This AUX register is not supported yet */
    if (record == NULL) {
        if (arc_aux_is_bcr(aux_regnum)) {
            /* BCR reads in user mode always raise Privilege Violation */
            if (arc_in_user_mode(env)) {
                arc_aux_raise_privilege_violation(env, retaddr);
            }

            /* All unimplemented BCRs in kernel mode read as 0 */
            return 0;
        }

        qemu_log_mask(LOG_GUEST_ERROR, "arc: aux: reading unsupported AUX register 0x" TARGET_FMT_lx "\n", aux_regnum);
        arc_aux_raise_illegal_instruction(env, retaddr);
    }

    permission = record->permission;

    /* Check permissions both for User and Kernel mode */
    if (arc_in_user_mode(env)) {
        if (permission == ARC_AUX_PERM_R || permission == ARC_AUX_PERM_RW) {
            arc_aux_raise_privilege_violation(env, retaddr);
        } else if (permission != ARC_AUX_PERM_r && permission != ARC_AUX_PERM_rw && permission != ARC_AUX_PERM_rW) {
            qemu_log_mask(LOG_GUEST_ERROR, "arc: aux: not readable in user mode aux=0x" TARGET_FMT_lx "\n", aux_regnum);
            arc_aux_raise_illegal_instruction(env, retaddr);
        }
    } else {
        if (permission != ARC_AUX_PERM_r && permission != ARC_AUX_PERM_R &&
            permission != ARC_AUX_PERM_rw && permission != ARC_AUX_PERM_rW &&
            permission != ARC_AUX_PERM_RW) {
            qemu_log_mask(LOG_GUEST_ERROR, "arc: aux: not readable in kernel mode aux=0x" TARGET_FMT_lx "\n", aux_regnum);
            arc_aux_raise_illegal_instruction(env, retaddr);
        }
    }

    g_assert(record->read_function != NULL);

    return record->read_function(env, retaddr);
}

target_ulong HELPER(aux_reg_read_tl)(CPUARCState *env, target_ulong aux_regnum)
{
    return do_aux_reg_read_tl(env, aux_regnum, GETPC());
}

uint32_t HELPER(aux_reg_read_i32)(CPUARCState *env, uint32_t aux_regnum)
{
    return do_aux_reg_read_tl(env, aux_regnum, GETPC());
}

uint64_t HELPER(aux_reg_read_i64)(CPUARCState *env, uint64_t aux_regnum)
{
    return do_aux_reg_read_tl(env, aux_regnum, GETPC());
}

static void do_aux_reg_write_tl(CPUARCState *env, target_ulong aux_regnum, target_ulong value, uintptr_t retaddr)
{
    arc_aux_record_t *record = NULL;
    ARCAUXPermission permission;

    for (size_t i = 0; i < aux_records_length; i++) {
        if (aux_regnum == aux_records[i].address) {
            record = &aux_records[i];
        }
    }

    /* This AUX register is not supported yet */
    if (record == NULL) {
        qemu_log_mask(LOG_GUEST_ERROR, "arc: aux: writing unsupported AUX register 0x" TARGET_FMT_lx "\n", aux_regnum);
        arc_aux_raise_illegal_instruction(env, retaddr);
    }

    permission = record->permission;

    /* Check permissions both for User and Kernel mode */
    if (arc_in_user_mode(env)) {
        if (permission == ARC_AUX_PERM_W || permission == ARC_AUX_PERM_rW || permission == ARC_AUX_PERM_RW) {
            arc_aux_raise_privilege_violation(env, retaddr);
        } else if (permission != ARC_AUX_PERM_w && permission != ARC_AUX_PERM_rw) {
            arc_aux_raise_illegal_instruction(env, retaddr);
        }
    } else {
        if (permission != ARC_AUX_PERM_w && permission != ARC_AUX_PERM_rw &&
            permission != ARC_AUX_PERM_W && permission != ARC_AUX_PERM_rW &&
            permission != ARC_AUX_PERM_RW) {
            arc_aux_raise_illegal_instruction(env, retaddr);
        }
    }

    g_assert(record->write_function != NULL);

    record->write_function(env, value, retaddr);
}

void HELPER(aux_reg_write_tl)(CPUARCState *env, target_ulong aux_regnum, target_ulong value)
{
    do_aux_reg_write_tl(env, aux_regnum, value, GETPC());
}

void HELPER(aux_reg_write_i32)(CPUARCState *env, uint32_t aux_regnum, uint32_t value)
{
    do_aux_reg_write_tl(env, aux_regnum, value, GETPC());
}

void HELPER(aux_reg_write_i64)(CPUARCState *env, uint64_t aux_regnum, uint64_t value)
{
    do_aux_reg_write_tl(env, aux_regnum, value, GETPC());
}

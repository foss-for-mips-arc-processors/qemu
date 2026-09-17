#include "qemu/osdep.h"
#include "cpu-qom.h"
#include "qemu/log.h"
#include "glib.h"
#include "qemu/error-report.h"
#include "qemu/qemu-print.h"
#include "cpu.h"
#include "cpu_bits.h"
#include "exec/log.h"
#include "system/runstate.h"
#include "semihosting/semihost.h"
#include "accel/tcg/cpu-ldst.h"
#include "qemu/plugin.h"
#include "irq.h"

void arc_cpu_do_transaction_failed(CPUState *cs, hwaddr physaddr, vaddr addr,
                                   unsigned size, MMUAccessType access_type,
                                   int mmu_idx, MemTxAttrs attrs,
                                   MemTxResult response, uintptr_t retaddr)
{
    CPUARCState *env = cpu_env(cs);

    static const char * const access_names[] = {
        [MMU_DATA_LOAD]  = "load",
        [MMU_DATA_STORE] = "store",
        [MMU_INST_FETCH] = "fetch",
    };

    qemu_log_mask(LOG_GUEST_ERROR,
                  "ARC: transaction failed\n"
                  "  pc          = 0x" TARGET_FMT_lx "\n"
                  "  virt addr   = 0x%08" VADDR_PRIx "\n"
                  "  phys addr   = 0x%08" HWADDR_PRIx "\n"
                  "  access      = %s\n"
                  "  size        = %u byte(s)\n"
                  "  mmu_idx     = %d\n"
                  "  response    = %s%s%s\n"
                  "  secure      = %d\n",
                  env->pc,
                  addr,
                  physaddr,
                  access_names[access_type],
                  size,
                  mmu_idx,
                  (response & MEMTX_ERROR)        ? "ERROR "        : "",
                  (response & MEMTX_DECODE_ERROR) ? "DECODE_ERROR " : "",
                  (response & MEMTX_ACCESS_ERROR) ? "ACCESS_ERROR"  : "",
                  attrs.secure);

    cs->exception_index = ARC_EXCP_MEMORY_ERROR;
    cpu_loop_exit_restore(cs, retaddr);
}

G_GNUC_PRINTF(1, 2) void arc_exit_with_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error_vreport(fmt, ap);
    va_end(ap);

    exit(EXIT_FAILURE);
}

void arc_cpu_do_unaligned_access(CPUState *cs,
    vaddr addr, MMUAccessType access_type,
    int mmu_idx, uintptr_t retaddr)
{
    CPUARCState *env = cpu_env(cs);

    env->excp_mem_addr = addr;
    cs->exception_index = ARC_EXCP_MISALIGNED_DATA;
    cpu_loop_exit_restore(cs, retaddr);
}

static const char *exception_to_name(ARCException exception) {
    switch (exception) {
    case ARC_EXCP_ILLEGAL_INSTRUCTION:
        return "Illegal Instruction";
    case ARC_EXCP_ILLEGAL_INSTRUCTION_SEQUENCE:
        return "Illegal Instruction Sequence";
    case ARC_EXCP_MACHINE_CHECK_DOUBLE_FAULT:
        return "Machine Check (double fault)";
    case ARC_EXCP_SWI:
        return "SWI";
    case ARC_EXCP_TRAP:
        return "Trap";
    case ARC_EXCP_DIVZERO:
        return "Divide By Zero";
    case ARC_EXCP_MISALIGNED_DATA:
        return "Misaligned Data Access";
    case ARC_EXCP_SEMIHOSTING:
        return "SWI-based semihosting call";
    case ARC_EXCP_TLB_MISS_I:
        return "Instruction TLB Miss";
#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    case ARC_EXCP_TLB_MISS_I_INV_ADDR:
        return "Instruction TLB Miss (invalid address)";
    case ARC_EXCP_TLB_MISS_I_ACCESS_FLAG:
        return "Instruction TLB Miss (access flag)";
#endif
    case ARC_EXCP_TLB_MISS_D_LD:
        return "Data TLB Miss (load)";
    case ARC_EXCP_TLB_MISS_D_ST:
        return "Data TLB Miss (store)";
#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    case ARC_EXCP_TLB_MISS_D_INV_ADDR:
        return "Data TLB Miss (invalid address)";
    case ARC_EXCP_TLB_MISS_D_ACCESS_FLAG:
        return "Data TLB Miss (access flag)";
#endif
    case ARC_EXCP_PROTV_EX:
        return "Protection Violation (fetch)";
    case ARC_EXCP_PROTV_LD:
        return "Protection Violation (load)";
    case ARC_EXCP_PROTV_ST:
        return "Protection Violation (store)";
    case ARC_EXCP_TLB_OVERLAP:
        return "Machine Check (overlapping TLB entries)";
    default:
        return "<unknown exception name>";
    }
}

static uint32_t arc_fetch_insn(CPUARCState *env, target_ulong addr, uint32_t *insn)
{
    uint16_t hw0 = cpu_lduw_data(env, addr);
    int major = (hw0 >> 11) & 0x1F;

#ifdef TARGET_ARCV3_64
    if (major <= 0x07 || major == 0x0B) {
#else
    if (major <= 0x07) {
#endif
        /* 32-bit instruction: fetch the second halfword */
        uint16_t hw1 = cpu_lduw_data(env, addr + 2);
        *insn = ((uint32_t)hw0 << 16) | hw1;
        return 4;
    } else {
        *insn = hw0;
        return 2;
    }
}

void arc_cpu_do_interrupt(CPUState *cs)
{
    CPUARCState *env = cpu_env(cs);
    ARCCPU *cpu = ARC_CPU(cs);
    int excp = cs->exception_index;

    cs->exception_index = -1;

    if (excp == ARC_EXCP_SEMIHOSTING) {
        /* Semihosting availability must be checked in trans_swi() */
        g_assert(semihosting_enabled(false));

        do_arc_semihosting(env);

        /*
         * Return address for semihosting is passed through a virtual register
         * since swi/swi_s instruction may have different size and semihosting
         * returns to the next instruction.
         */
        env->pc = env->excp_semihost_eret;
        env->gpr[ARC_REGNUM_PCL] = arc_pc_to_pcl(env->pc);

        return;
    }

    target_ulong orig_pc = env->pc;
    target_ulong tmp;

    /*
     * Convert current exception to the Double Fault exception
     * if a previous exception is not handled yet (STATUS32.AE == 1).
     */
    if (env->aux_status32.exception_state) {
        if (env->excp_double_fault) {
            qemu_log_mask(CPU_LOG_INT, "arc: exception: Triple Fault detected at pc=0x" TARGET_FMT_lx "\n", env->pc);
            exit(EXIT_FAILURE);
        } else {
            /* TODO: Do I need to disable MMU and MPU as it done in old QEMU? */
            excp = ARC_EXCP_MACHINE_CHECK_DOUBLE_FAULT;
            env->excp_parameter = 0;
            env->excp_double_fault = true;
        }
    } else {
        env->excp_double_fault = false;
    }

    /* Reset ECR before processing a new exception */
    arc_unpack_aux_ecr(&env->aux_ecr, 0);

    switch (excp) {
    case ARC_EXCP_MEMORY_ERROR:
        /* TODO: Implement bus error handlers */
        qemu_log_mask(CPU_LOG_INT, "arc: exception: Memory Error at pc=0x" TARGET_FMT_lx "\n", env->pc);
        exit(EXIT_FAILURE);
        break;

    case ARC_EXCP_ILLEGAL_INSTRUCTION:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_INSTRUCTION_ERROR;
        env->aux_efa = env->pc;

        break;
    case ARC_EXCP_ILLEGAL_INSTRUCTION_SEQUENCE:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_INSTRUCTION_ERROR;
        env->aux_ecr.cause_code = 0x1;
        env->aux_efa = env->pc;

        break;
    case ARC_EXCP_MACHINE_CHECK_DOUBLE_FAULT:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_MACHINE_CHECK;
        env->aux_efa = env->pc;

        break;
    case ARC_EXCP_TLB_OVERLAP:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_MACHINE_CHECK;
        env->aux_ecr.cause_code = 0x1;
        env->aux_efa = env->excp_mem_addr;

        break;
    case ARC_EXCP_TLB_MISS_I:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_IMMU_FAULT;
        env->aux_ecr.cause_code = 0x0;
        env->aux_efa = env->excp_mem_addr;

        break;
#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    case ARC_EXCP_TLB_MISS_I_INV_ADDR:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_IMMU_FAULT;
        env->aux_ecr.cause_code = 0x8;
        env->aux_efa = env->excp_mem_addr;

        break;
    case ARC_EXCP_TLB_MISS_I_ACCESS_FLAG:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_IMMU_FAULT;
        env->aux_ecr.cause_code = 0x10;
        env->aux_efa = env->excp_mem_addr;

        break;
#endif
    case ARC_EXCP_TLB_MISS_D_LD:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_DMMU_FAULT;
        env->aux_ecr.cause_code = 0x1;
        env->aux_efa = env->excp_mem_addr;

        break;
    case ARC_EXCP_TLB_MISS_D_ST:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_DMMU_FAULT;
        env->aux_ecr.cause_code = 0x2;
        env->aux_efa = env->excp_mem_addr;

        break;
#if defined(TARGET_ARCV3_64) || defined(TARGET_ARCV3_32)
    case ARC_EXCP_TLB_MISS_D_INV_ADDR:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_DMMU_FAULT;
        env->aux_ecr.cause_code = 0x8;
        env->aux_efa = env->excp_mem_addr;

        break;
    case ARC_EXCP_TLB_MISS_D_ACCESS_FLAG:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_DMMU_FAULT;
        env->aux_ecr.cause_code = 0x10;
        env->aux_efa = env->excp_mem_addr;

        break;
#endif
    case ARC_EXCP_PROTV_EX:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_PROTECTION_VIOLATION;
        env->aux_ecr.parameter = env->excp_parameter;
        env->aux_efa = env->excp_mem_addr;

        break;
    case ARC_EXCP_PROTV_LD:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_PROTECTION_VIOLATION;
        env->aux_ecr.cause_code = 0x1;
        env->aux_ecr.parameter = env->excp_parameter;
        env->aux_efa = env->excp_mem_addr;

        break;
    case ARC_EXCP_PROTV_ST:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_PROTECTION_VIOLATION;
        env->aux_ecr.cause_code = 0x2;
        env->aux_ecr.parameter = env->excp_parameter;
        env->aux_efa = env->excp_mem_addr;

        break;
    case ARC_EXCP_PRIVILEGE_VIOLATION:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_PRIVILEGE_VIOLATION;
        env->aux_efa = env->pc;

        break;
    case ARC_EXCP_SWI:
        /*
         * SWI parameter is a 6-bit field and 0b111111 is excluded.
         * This field must be validated by the translator.
         */
        g_assert(env->excp_parameter < 0x3F);

        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_SWI;
        env->aux_ecr.parameter = env->excp_parameter;
        env->aux_efa = env->pc;

        break;
    case ARC_EXCP_TRAP:
        g_assert(env->excp_parameter < 0x40);

        env->aux_eret = env->pc + 2;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_TRAP;
        env->aux_ecr.parameter = env->excp_parameter;
        env->aux_efa = env->pc;

        break;
    case ARC_EXCP_DIVZERO:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_DIVZERO;
        env->aux_efa = env->pc;

        break;
    case ARC_EXCP_MISALIGNED_DATA:
        env->aux_eret = env->pc;
        env->aux_ecr.vector_number = ARC_EXCP_CLASS_MISALIGNED;
        env->aux_efa = env->excp_mem_addr;

        qemu_log_mask(CPU_LOG_INT, "arc: exception: misaligned addr=0x" TARGET_FMT_lx "\n", env->excp_mem_addr);

        break;
    default:
        qemu_log_mask(CPU_LOG_INT, "arc: exception: unsupported exception at pc=0x" TARGET_FMT_lx "\n", env->pc);
        exit(EXIT_FAILURE);
    }

    /* Jump to BTA after TRAP_S handler if it's in a delay slot */
    if (excp == ARC_EXCP_TRAP && env->aux_status32.delay_slot_pending) {
        env->aux_eret = env->aux_bta;
        env->aux_status32.delay_slot_pending = 0;
    }

    /* Save STATUS32 and BTA registers */
    env->aux_erstatus = env->aux_status32;
    env->aux_erstatus.halt = 0;
    env->aux_erbta = env->aux_bta;

    /* Switch SP if CPU was in user mode */
    if (env->aux_status32.user_mode) {
        tmp = env->aux_user_sp;
        env->aux_user_sp = env->gpr[ARC_REGNUM_SP];
        env->gpr[ARC_REGNUM_SP] = tmp;
    }

    /* Set STATUS32 bits */
    env->aux_status32.zero_flag = env->aux_status32.user_mode;
    env->aux_status32.user_mode = 0;
    env->aux_status32.enable_interrupt = 0;
    env->aux_status32.exception_state = 1;
    env->aux_status32.ei_pending = 0;
    env->aux_status32.enable_stack_checking = 0;
    env->aux_status32.enable_divzero_excp = 0;
    env->aux_status32.disable_zol = 1;
    env->aux_status32.delay_slot_pending = 0;

    /* Any exception clears the LLOCK/SCOND lock flag */
    env->atomic_lf = 0;

    /* Calculate entry address */
    env->pc = arc_load_vector_entry(env, env->aux_ecr.vector_number);
    env->gpr[ARC_REGNUM_PCL] = arc_pc_to_pcl(env->pc);

    qemu_log_mask(
        CPU_LOG_INT,
        "arc: exception: %s at pc=0x" TARGET_FMT_lx ", vector base=0x" TARGET_FMT_lx ", vector number=0x%08x\n",
        exception_to_name(excp),
        orig_pc,
        env->aux_int_vector_base,
        env->aux_ecr.vector_number);

    if (excp == ARC_EXCP_CLASS_INSTRUCTION_ERROR) {
        uint32_t insn;

        if (4 == arc_fetch_insn(env, env->aux_efa, &insn)) {
            qemu_log_mask(LOG_GUEST_ERROR, "arc: exception: invalid instruction encoding - 0x%08x\n", insn);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "arc: exception: invalid instruction encoding - 0x%04x\n", (uint16_t)insn);
        }
    }

    qemu_log_mask(CPU_LOG_INT, "arc: exception: handler entry pc=0x" TARGET_FMT_lx "\n", env->pc);

    /* Notify plugins and reset an exception */
    qemu_plugin_vcpu_exception_cb(cs, env->pc);

    if (!cpu->cfg.enable_exceptions) {
        qemu_log_mask(CPU_LOG_INT, "arc: exception: exceptions are turned off\n");
        exit(EXIT_FAILURE);
    }
}

void arc_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    CPUARCState *env = cpu_env(cs);
    int i;

    qemu_fprintf(f, "PC: 0x" TARGET_FMT_lx "  PCL: 0x" TARGET_FMT_lx "\n", env->pc, env->gpr[ARC_REGNUM_PCL]);
    qemu_fprintf(f, "STATUS32: 0x%08x [ %c%c%c%c ]\n",
                 arc_pack_status32(&env->aux_status32),
                 env->aux_status32.zero_flag ? 'Z' : '-',
                 env->aux_status32.negative_flag ? 'N' : '-',
                 env->aux_status32.carry_flag ? 'C' : '-',
                 env->aux_status32.overflow_flag ? 'V' : '-');

    for (i = 0; i < 32; i++) {
        qemu_fprintf(f, "r%-2d: 0x" TARGET_FMT_lx "  ", i, env->gpr[i]);
        if ((i % 4) == 3) {
            qemu_fprintf(f, "\n");
        }
    }

    qemu_fprintf(f, "BTA: 0x" TARGET_FMT_lx "  BLINK: 0x" TARGET_FMT_lx "  SP: 0x" TARGET_FMT_lx "\n",
                 env->aux_bta, env->gpr[ARC_REGNUM_BLINK], env->gpr[ARC_REGNUM_SP]);

#ifdef TARGET_ARCV2
    qemu_fprintf(f, "LP_COUNT: 0x" TARGET_FMT_lx "  LP_START: 0x" TARGET_FMT_lx "  LP_END: 0x" TARGET_FMT_lx "\n",
                 env->gpr[ARC_REGNUM_LP_COUNT], env->aux_lp_start, env->aux_lp_end);
#endif
}

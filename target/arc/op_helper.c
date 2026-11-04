#include "qemu/osdep.h"
#include "cpu.h"
#include "cpu-qom.h"
#include "qemu/log.h"
#include "qemu/log.h"
#include "exec/helper-proto.h"
#ifndef CONFIG_USER_ONLY
#include "system/runstate.h"
#include "irq.h"
#endif

G_NORETURN void arc_raise_exception(CPUARCState *env, int exception, int parameter, uintptr_t pc)
{
    CPUState *cs = env_cpu(env);

    env->excp_parameter = parameter;

    cs->exception_index = exception;
    cpu_loop_exit_restore(cs, pc);
}

void arc_halt(CPUState *cs)
{
    ARCCPU *cpu = ARC_CPU(cs);

    cpu->env.aux_status32.halt = 1;
    cs->halted = 1;
    cs->exception_index = EXCP_HLT;

    qemu_log_mask(CPU_LOG_INT, "arc: halt: halting at addr=0x" TARGET_FMT_lx "\n", cpu->env.pc);

#ifndef CONFIG_USER_ONLY
    if (cpu->cfg.exit_on_halt) {
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
    }
#endif

    cpu_loop_exit_restore(cs, cpu->env.pc);
}

void G_NORETURN HELPER(raise_exception)(CPUARCState *env, int exception, int parameter)
{
    arc_raise_exception(env, exception, parameter, 0);
}

void HELPER(flag)(CPUARCState *env, uint32_t bits)
{
    CPUState *cs = env_cpu(env);
    arc_aux_status_t status;

    arc_unpack_status32(&status, bits);

    if (arc_in_kernel_mode(env)) {
        if (status.halt) {
            arc_halt(cs);
        }

        env->aux_status32.sleep_mode = status.sleep_mode;
        env->aux_status32.disable_alignment_checking = status.disable_alignment_checking;
        env->aux_status32.enable_stack_checking = status.enable_stack_checking;
        env->aux_status32.enable_divzero_excp = status.enable_divzero_excp;
        env->aux_status32.interrupt_priority = status.interrupt_priority;
    }

    env->aux_status32.zero_flag = status.zero_flag;
    env->aux_status32.negative_flag = status.negative_flag;
    env->aux_status32.carry_flag = status.carry_flag;
    env->aux_status32.overflow_flag = status.overflow_flag;
}

void HELPER(kflag)(CPUARCState *env, uint32_t bits)
{
    CPUState *cs = env_cpu(env);
    arc_aux_status_t status;

    arc_unpack_status32(&status, bits);

    if (arc_in_kernel_mode(env)) {
        if (status.halt) {
            arc_halt(cs);
        }

        env->aux_status32.enable_interrupt = status.enable_interrupt;
        env->aux_status32.sleep_mode = status.sleep_mode;
        env->aux_status32.disable_alignment_checking = status.disable_alignment_checking;
        env->aux_status32.enable_stack_checking = status.enable_stack_checking;
        env->aux_status32.enable_divzero_excp = status.enable_divzero_excp;
        env->aux_status32.exception_state = status.exception_state;
        env->aux_status32.interrupt_priority = status.interrupt_priority;

        arc_cpu_switch_gpr_bank(env, status.register_bank);
    }

    env->aux_status32.zero_flag = status.zero_flag;
    env->aux_status32.negative_flag = status.negative_flag;
    env->aux_status32.carry_flag = status.carry_flag;
    env->aux_status32.overflow_flag = status.overflow_flag;
}

void HELPER(brk)(CPUARCState *env)
{
    if (arc_in_user_mode(env)) {
        arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
    }

    CPUState *cs = env_cpu(env);

    arc_halt(cs);
}

void G_NORETURN HELPER(sleep)(CPUARCState *env, uint32_t arg)
{
    if (arc_in_user_mode(env)) {
        arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
    }

    CPUState *cs = env_cpu(env);

    if (arg & 0x10) {
        env->aux_status32.interrupt_priority = arg & 0x0f;
        env->aux_status32.enable_interrupt = 1;
    }

    cs->halted = 1;
    cs->exception_index = EXCP_HLT;

    qemu_log_mask(CPU_LOG_INT, "arc: sleep: sleeping at pc=0x" TARGET_FMT_lx "\n", env->pc);

    cpu_loop_exit(cs);
}

void HELPER(rtie)(CPUARCState *env)
{
    if (arc_in_user_mode(env)) {
        arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
    }

#ifdef CONFIG_USER_ONLY
    g_assert_not_reached();
#else
    CPUState *cs = env_cpu(env);

    if (env->aux_status32.exception_state || env->aux_irq_act.active == 0) {
        arc_do_rtie_exception(env);
    } else if (arc_cpu_has_firq(env) && (env->aux_irq_act.active & 1)) {
        arc_do_rtie_firq(env);
    } else {
        arc_do_rtie_interrupt(env);
    }

    cpu_loop_exit(cs);
#endif
}

uint32_t HELPER(clri)(CPUARCState *env)
{
    if (arc_in_user_mode(env)) {
        arc_raise_exception(env, ARC_EXCP_ILLEGAL_INSTRUCTION, 0, GETPC());
    }

    uint32_t result = 1 << 5;

    result |= env->aux_status32.enable_interrupt << 4;
    result |= env->aux_status32.interrupt_priority;

    env->aux_status32.enable_interrupt = 0;

    return result;
}

void HELPER(seti)(CPUARCState *env, uint32_t src)
{
    if (arc_in_user_mode(env)) {
        arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
    }

    uint32_t bit_5 = (src >> 5) & 1;
    uint32_t bit_4 = (src >> 4) & 1;
    uint32_t bits_e = src & 0xF;

    if (bit_5) {
        env->aux_status32.interrupt_priority = bits_e;
        env->aux_status32.enable_interrupt = bit_4;
    } else {
        env->aux_status32.enable_interrupt = 1;

        if (bit_4) {
            env->aux_status32.interrupt_priority = bits_e;
        }
    }
}

#ifdef CONFIG_USER_ONLY
/*
 * User mode emulation runs the guest in the user privilege level only, so
 * any access to AUX registers is a privilege violation.
 */
target_ulong HELPER(aux_reg_read_tl)(CPUARCState *env, target_ulong aux_regnum)
{
    arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
}

uint32_t HELPER(aux_reg_read_i32)(CPUARCState *env, uint32_t aux_regnum)
{
    arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
}

uint64_t HELPER(aux_reg_read_i64)(CPUARCState *env, uint64_t aux_regnum)
{
    arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
}

void HELPER(aux_reg_write_tl)(CPUARCState *env, target_ulong aux_regnum,
                              target_ulong value)
{
    arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
}

void HELPER(aux_reg_write_i32)(CPUARCState *env, uint32_t aux_regnum,
                               uint32_t value)
{
    arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
}

void HELPER(aux_reg_write_i64)(CPUARCState *env, uint64_t aux_regnum,
                               uint64_t value)
{
    arc_raise_exception(env, ARC_EXCP_PRIVILEGE_VIOLATION, 0, GETPC());
}
#endif

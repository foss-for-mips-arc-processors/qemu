/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ARC emulation of Linux signals
 *
 * The frame layout follows arch/arc/kernel/signal.c.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "signal-common.h"
#include "linux-user/trace.h"

/*
 * See arch/arc/include/uapi/asm/ptrace.h and sigcontext.h. The layout is
 * the same for ARCv2 and ARCv3, except that r13 is a scratch register in the
 * ARCv3 ABI. Like the Linux kernel (arch/arc/kernel/signal.c), only the
 * scratch registers and the @v2abi registers are saved and restored.
 * Callee-saved registers are preserved by the signal handler itself, so
 * the @callee, @efa and @stop_pc fields (used by ptrace) are left untouched.
 */
struct target_sigcontext {
    abi_ulong pad;
    struct {
        abi_ulong bta;
        abi_ulong lp_start, lp_end, lp_count;
        abi_ulong status32, ret, blink;
        abi_ulong fp, gp;
#ifndef TARGET_ARCV2
        abi_ulong r13;
#endif
        abi_ulong r12, r11, r10, r9, r8, r7;
        abi_ulong r6, r5, r4, r3, r2, r1, r0;
        abi_ulong sp;
    } scratch;
    abi_ulong pad2;
    struct {
        abi_ulong r25, r24, r23, r22, r21, r20;
        abi_ulong r19, r18, r17, r16, r15, r14;
#ifdef TARGET_ARCV2
        abi_ulong r13;
#endif
    } callee;
    abi_ulong efa;
    abi_ulong stop_pc;
    /* r30 is saved only on ARCv2, r59 is not saved on HS6x */
    struct {
        abi_ulong r30, r58, r59;
    } v2abi;
};

struct target_ucontext {
    abi_ulong                uc_flags;
    abi_ptr                  uc_link;
    target_stack_t           uc_stack;
    struct target_sigcontext uc_mcontext;
    target_sigset_t          uc_sigmask;
};

#define MAGIC_SIGALTSTK 0x07302004

struct target_rt_sigframe {
    struct target_siginfo info;
    struct target_ucontext uc;
    uint32_t sigret_magic;
};

/* STATUS32 bits which are allowed to be changed by a signal frame */
static void arc_restore_status32(CPUARCState *env, uint32_t value)
{
    arc_aux_status_t status;

    arc_unpack_status32(&status, value);

    env->aux_status32.overflow_flag = status.overflow_flag;
    env->aux_status32.carry_flag = status.carry_flag;
    env->aux_status32.negative_flag = status.negative_flag;
    env->aux_status32.zero_flag = status.zero_flag;
    env->aux_status32.disable_zol = status.disable_zol;
    env->aux_status32.delay_slot_pending = status.delay_slot_pending;
    env->aux_status32.disable_alignment_checking =
        status.disable_alignment_checking;
}

#define GPR(env, n) ((env)->gpr[ARC_REGNUM_##n])

#ifdef TARGET_ARCV2
#define SIGCONTEXT_ISA_GPR(M) \
    M(scratch.lp_count, LP_COUNT) \
    M(v2abi.r30, R30) M(v2abi.r58, R58) M(v2abi.r59, R59)
#elif defined(TARGET_ARCV3_32)
#define SIGCONTEXT_ISA_GPR(M) \
    M(scratch.r13, R13) M(v2abi.r58, R58) M(v2abi.r59, R59)
#else
#define SIGCONTEXT_ISA_GPR(M) \
    M(scratch.r13, R13) M(v2abi.r58, R58)
#endif

#define FOR_EACH_SIGCONTEXT_GPR(M) \
    M(scratch.r0, R0)   M(scratch.r1, R1)   M(scratch.r2, R2) \
    M(scratch.r3, R3)   M(scratch.r4, R4)   M(scratch.r5, R5) \
    M(scratch.r6, R6)   M(scratch.r7, R7)   M(scratch.r8, R8) \
    M(scratch.r9, R9)   M(scratch.r10, R10) M(scratch.r11, R11) \
    M(scratch.r12, R12) M(scratch.fp, FP)   M(scratch.gp, GP) \
    M(scratch.blink, BLINK) M(scratch.sp, SP) \
    SIGCONTEXT_ISA_GPR(M)

static void setup_sigcontext(struct target_sigcontext *sc, CPUARCState *env)
{
#define PUT_GPR(field, reg) __put_user(GPR(env, reg), &sc->field);
    FOR_EACH_SIGCONTEXT_GPR(PUT_GPR)
#undef PUT_GPR

    __put_user(arc_pack_status32(&env->aux_status32), &sc->scratch.status32);
    __put_user(env->aux_bta, &sc->scratch.bta);
#ifdef TARGET_ARCV2
    __put_user(env->aux_lp_start, &sc->scratch.lp_start);
    __put_user(env->aux_lp_end, &sc->scratch.lp_end);
#else
    /* ARCv3 has no zero overhead loops */
    __put_user(0, &sc->scratch.lp_start);
    __put_user(0, &sc->scratch.lp_end);
    __put_user(0, &sc->scratch.lp_count);
    __put_user(0, &sc->v2abi.r30);
#endif
#ifdef TARGET_ARCV3_64
    __put_user(0, &sc->v2abi.r59);
#endif
    __put_user(env->pc, &sc->scratch.ret);
}

static void restore_sigcontext(CPUARCState *env, struct target_sigcontext *sc)
{
    abi_ulong status32, pc;

#define GET_GPR(field, reg) __get_user(GPR(env, reg), &sc->field);
    FOR_EACH_SIGCONTEXT_GPR(GET_GPR)
#undef GET_GPR

    __get_user(status32, &sc->scratch.status32);
    arc_restore_status32(env, status32);
    __get_user(env->aux_bta, &sc->scratch.bta);
#ifdef TARGET_ARCV2
    __get_user(env->aux_lp_start, &sc->scratch.lp_start);
    __get_user(env->aux_lp_end, &sc->scratch.lp_end);
#endif
    __get_user(pc, &sc->scratch.ret);

    env->pc = pc;
    GPR(env, PCL) = arc_pc_to_pcl(pc);
}

/* The frame is word aligned and placed below the current stack pointer */
static abi_ulong get_sigframe(struct target_sigaction *ka, CPUARCState *env,
                              size_t framesize)
{
    abi_ulong sp = target_sigsp(GPR(env, SP), ka);

    return (sp - framesize) & ~7;
}

void setup_rt_frame(int sig, struct target_sigaction *ka,
                    target_siginfo_t *info,
                    target_sigset_t *set, CPUARCState *env)
{
    struct target_rt_sigframe *frame;
    abi_ulong frame_addr = get_sigframe(ka, env, sizeof(*frame));
    uint32_t magic = 0;
    int i;

    trace_user_setup_rt_frame(env, frame_addr);

    /* A restorer is mandatory, libc provides it */
    if (!(ka->sa_flags & TARGET_SA_RESTORER) ||
        !lock_user_struct(VERIFY_WRITE, frame, frame_addr, 0)) {
        force_sigsegv(sig);
        return;
    }

    setup_sigcontext(&frame->uc.uc_mcontext, env);

    for (i = 0; i < TARGET_NSIG_WORDS; i++) {
        __put_user(set->sig[i], &frame->uc.uc_sigmask.sig[i]);
    }

    if (ka->sa_flags & TARGET_SA_SIGINFO) {
        frame->info = *info;
        __put_user(0, &frame->uc.uc_flags);
        __put_user(0, &frame->uc.uc_link);
        target_save_altstack(&frame->uc.uc_stack, env);

        GPR(env, R1) = frame_addr + offsetof(struct target_rt_sigframe, info);
        GPR(env, R2) = frame_addr + offsetof(struct target_rt_sigframe, uc);
        magic = MAGIC_SIGALTSTK;
    }
    __put_user(magic, &frame->sigret_magic);

    GPR(env, R0) = sig;
    GPR(env, BLINK) = ka->sa_restorer;
    GPR(env, SP) = frame_addr;
    env->pc = ka->_sa_handler;
    GPR(env, PCL) = arc_pc_to_pcl(env->pc);

    /* Like any exception, signal delivery clears the lock flag */
    env->atomic_lf = 0;

    /* The handler must not use BTA and starts with ZOL inhibited */
    env->aux_status32.delay_slot_pending = 0;
    env->aux_status32.disable_zol = 1;

    unlock_user_struct(frame, frame_addr, sizeof(*frame));
}

long do_rt_sigreturn(CPUARCState *env)
{
    struct target_rt_sigframe *frame;
    abi_ulong frame_addr = GPR(env, SP);
    target_sigset_t target_set;
    sigset_t blocked;
    uint32_t magic;
    int i;

    trace_user_do_rt_sigreturn(env, frame_addr);

    if ((frame_addr & 7) ||
        !lock_user_struct(VERIFY_READ, frame, frame_addr, 1)) {
        force_sig(TARGET_SIGSEGV);
        return -QEMU_ESIGRETURN;
    }

    for (i = 0; i < TARGET_NSIG_WORDS; i++) {
        __get_user(target_set.sig[i], &frame->uc.uc_sigmask.sig[i]);
    }
    target_to_host_sigset(&blocked, &target_set);
    set_sigmask(&blocked);

    restore_sigcontext(env, &frame->uc.uc_mcontext);

    __get_user(magic, &frame->sigret_magic);
    if (magic == MAGIC_SIGALTSTK) {
        target_restore_altstack(&frame->uc.uc_stack, env);
    }

    unlock_user_struct(frame, frame_addr, 0);

    return -QEMU_ESIGRETURN;
}

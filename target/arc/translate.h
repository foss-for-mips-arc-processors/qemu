#ifndef ARC_CPU_TRANSLATE_H
#define ARC_CPU_TRANSLATE_H

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "tcg/tcg-op.h"
#include "exec/translator.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#ifndef CONFIG_USER_ONLY
#include "semihosting/semihost.h"
#endif
#include "cpu.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef  HELPER_H

/*
 * DISAS_UPDATE
 *
 *     TB must end here; CPU state was modified in a way that
 *     requires re-entering the main loop (e.g. FLAG writes
 *     STATUS32, which may change execution mode).
 *
 * DISAS_JUMP_DIRECT
 *
 *     TB ends with a direct branch to jump_dest.
 *
 * DISAS_JUMP_INDIRECT
 *
 *     TB ends with a computed branch; the next PC is already
 *     stored in cpu_pc.
 */
#define DISAS_UPDATE        DISAS_TARGET_0
#define DISAS_JUMP_DIRECT   DISAS_TARGET_1
#define DISAS_JUMP_INDIRECT DISAS_TARGET_2
#define DISAS_JUMP_COND     DISAS_TARGET_3

static TCGv cpu_gpr[ARC_REGNUM_END];
static TCGv cpu_pc;
static TCGv_i32 cpu_DEf;
static TCGv_i32 cpu_Zf;
static TCGv_i32 cpu_Nf;
static TCGv_i32 cpu_Cf;
static TCGv_i32 cpu_Vf;
static TCGv_i32 cpu_DZf;
static TCGv cpu_bta;
static TCGv cpu_eret;
static TCGv cpu_semihost_eret;

#ifdef TARGET_ARCV2
static TCGv cpu_Lf;
static TCGv cpu_lp_start;
static TCGv cpu_lp_end;
#endif

/*
 * DisasContextBase main fields:
 *   pc_first    -- start PC of this TB
 *   pc_next     -- PC of the *next* instruction (updated by translate_insn)
 *   is_jmp      -- exit reason for the current TB (DISAS_NEXT by default)
 *   num_insns   -- how many instructions have been translated so far
 *
 */
typedef struct DisasContext {
    DisasContextBase base;
    CPUARCState *env;

    target_ulong pc;       /* PC of the instruction being translated */
    target_ulong pcl;
    uint32_t     insn;     /* raw instruction word (16- or 32-bit) */
    int          insn_len; /* 2 or 4 bytes */
    bool         has_limm; /* LIMM already loaded for this insn */
    int32_t      limm;     /* cached LIMM value */
    int          mem_idx;  /* MMU index; 0 until MMU is implemented */
    bool         unaligned_ldst;
    bool         in_delay_slot;
    target_ulong jump_dest;

#ifdef TARGET_ARCV2
    bool         zol_enabled;
    uint32_t     lp_start;
    uint32_t     lp_end;
#endif
} DisasContext;

#define ARC_TRANS_CHECK_ARCV2(env) \
    if (!arc_cpu_is_arcv2(env_archcpu(env))) { \
        return false; \
    }

#include "extractors.h"
#include "decode-insn32.c.inc"
#include "decode-insn16.c.inc"

static inline void arc_gen_set_pc(DisasContext *ctx, uintptr_t pc)
{
    tcg_gen_movi_tl(cpu_pc, pc);
    tcg_gen_movi_tl(cpu_gpr[ARC_REGNUM_PCL], arc_pc_to_pcl(pc));
}

static inline void arc_gen_goto_tb(DisasContext *ctx, int slot,
                                   target_ulong dest)
{
    if (translator_use_goto_tb(&ctx->base, dest)) {
        tcg_gen_goto_tb(slot);
        arc_gen_set_pc(ctx, dest);
        tcg_gen_exit_tb(ctx->base.tb, slot);
    } else {
        arc_gen_set_pc(ctx, dest);
        tcg_gen_lookup_and_goto_ptr();
    }
}

static inline void arc_gen_save_pc(DisasContext *ctx)
{
    arc_gen_set_pc(ctx, ctx->pc);
}

static inline void arc_gen_set_bta_imm(DisasContext *ctx, target_ulong dest)
{
    tcg_gen_movi_i32(cpu_DEf, 1);
    tcg_gen_movi_tl(cpu_bta, dest);
}

static inline void arc_gen_set_bta(DisasContext *ctx, TCGv dest)
{
    tcg_gen_movi_i32(cpu_DEf, 1);
    tcg_gen_mov_tl(cpu_bta, dest);
}

static inline void arc_gen_exception_illegal_instruction(DisasContext *ctx)
{
    arc_gen_save_pc(ctx);
    gen_helper_raise_exception(tcg_env,
                               tcg_constant_i32(ARC_EXCP_ILLEGAL_INSTRUCTION),
                               tcg_constant_i32(0));
}

static inline void arc_gen_exception_illegal_instruction_sequence(DisasContext *ctx)
{
    arc_gen_save_pc(ctx);
    gen_helper_raise_exception(tcg_env,
                               tcg_constant_i32(ARC_EXCP_ILLEGAL_INSTRUCTION_SEQUENCE),
                               tcg_constant_i32(0));
}

static inline void arc_gen_exception_privilege_violation(DisasContext *ctx)
{
    arc_gen_save_pc(ctx);
    gen_helper_raise_exception(tcg_env,
                               tcg_constant_i32(ARC_EXCP_PRIVILEGE_VIOLATION),
                               tcg_constant_i32(0));
}

static inline void arc_gen_exception_divzero(DisasContext *ctx)
{
    arc_gen_save_pc(ctx);
    gen_helper_raise_exception(tcg_env,
                               tcg_constant_i32(ARC_EXCP_DIVZERO),
                               tcg_constant_i32(0));
}

static inline void arc_gen_check_not_limm(DisasContext *ctx, int regnum)
{
#ifdef TARGET_ARCV3_64
    if (regnum == ARC_REGNUM_SLIMM || regnum == ARC_REGNUM_ULIMM) {
#else
    if (regnum == ARC_REGNUM_LIMM) {
#endif
        arc_gen_exception_illegal_instruction(ctx);
    }
}

static inline void arc_gen_check_even_regnum(DisasContext *ctx, int regnum)
{
    if (regnum & 1) {
        arc_gen_exception_illegal_instruction(ctx);
    }
}

static inline void arc_gen_check_not_lp_count(DisasContext *ctx, uint32_t regnum)
{
#ifdef TARGET_ARCV2
    if (regnum == ARC_REGNUM_LP_COUNT) {
        arc_gen_exception_illegal_instruction(ctx);
    }
#endif
}

static inline void arc_gen_check_not_delay_slot(DisasContext *ctx)
{
    if (ctx->in_delay_slot) {
        arc_gen_exception_illegal_instruction_sequence(ctx);
    }
}

static inline void arc_gen_check_kernel_mode(DisasContext *ctx)
{
    if (arc_in_user_mode(ctx->env)) {
        arc_gen_exception_privilege_violation(ctx);
    }
}

static inline void arc_gen_ldst_writeback_prologue(DisasContext *ctx, TCGv address, TCGv base, TCGv offset, ARCInsnWriteBackMode mode, ARCInsnDataSize size)
{
    int shift = 0;

    switch (mode) {
        case ARC_AA_NONE:  /* EA = b + c */
        case ARC_AA_PRE:   /* EA = b + c, then b += c */
            tcg_gen_add_tl(address, base, offset);
            break;

        case ARC_AA_POST:  /* EA = b, then b += c */
            tcg_gen_mov_tl(address, base);
            break;
    
        case ARC_AA_SCALED: /* EA = b + (c << scale) */
            switch (size) {
#ifdef TARGET_ARCV3_64
            case ARC_ZZ_QUAD:
                shift = 3;
                break;
            case ARC_ZZ_DOUBLE:
                shift = 3;
                break;
#else
            case ARC_ZZ_DOUBLE:
                shift = 2;
                break;
#endif
            case ARC_ZZ_WORD:
                shift = 2;
                break;
            case ARC_ZZ_HALF:
                shift = 1;
                break;
            case ARC_ZZ_BYTE:
                arc_gen_exception_illegal_instruction(ctx);
                break;
            default:
                g_assert_not_reached();
            }

            tcg_gen_shli_tl(address, offset, shift);
            tcg_gen_add_tl(address, base, address);
            break;

        default:
            g_assert_not_reached();
        }

    if (mode == ARC_AA_PRE || mode == ARC_AA_POST) {
        tcg_gen_add_tl(base, base, offset);
    }
}

/* Return the MemOp for a load of the given size and sign behaviour */
static MemOp arc_insn_ldst_get_memop(DisasContext *ctx, ARCInsnDataSize data_size, bool sign_extend)
{
    MemOp memop;

    switch (data_size) {
#ifdef TARGET_ARCV3_64
    case ARC_ZZ_QUAD:
        memop = sign_extend ? MO_SO : MO_UO;
        if (!ctx->unaligned_ldst) {
            memop |= MO_ALIGN_8;
        }
        break;
    case ARC_ZZ_DOUBLE:
        memop = sign_extend ? MO_SQ : MO_UQ;
        if (!ctx->unaligned_ldst) {
            memop |= MO_ALIGN_8;
        }
        break;
#else
    case ARC_ZZ_DOUBLE:
        memop = sign_extend ? MO_SQ : MO_UQ;
        if (!ctx->unaligned_ldst) {
            memop |= MO_ALIGN_4;
        }
        break;
#endif
    case ARC_ZZ_WORD:
        memop = sign_extend ? MO_SL : MO_UL;
        if (!ctx->unaligned_ldst) {
            memop |= MO_ALIGN_4;
        }
        break;
    case ARC_ZZ_HALF:
        memop = sign_extend ? MO_SW : MO_UW;
        if (!ctx->unaligned_ldst) {
            memop |= MO_ALIGN_2;
        }
        break;
    case ARC_ZZ_BYTE:
        memop = sign_extend ? MO_SB : MO_UB;
        break;
    default:
        g_assert_not_reached();
    }

    return memop | MO_TE;
}

/* TODO: Emit exception if LIMM is in delay slot instruction */
/* TODO: Do not emit this exception if <.cc> check is not passed. */

static inline TCGv_i32 arc_insn_load_imm(int32_t imm)
{
    TCGv_i32 reg = tcg_temp_new_i32();
    tcg_gen_movi_i32(reg, imm);
    return reg;
}

static inline TCGv_i64 arc64_insn_load_imm(int64_t imm)
{
    TCGv_i64 reg = tcg_temp_new_i64();
    tcg_gen_movi_i64(reg, imm);
    return reg;
}

static inline TCGv arc_insn_load_imm_tl(target_long imm)
{
#ifdef TARGET_ARCV3_64
    return arc64_insn_load_imm(imm);
#else
    return arc_insn_load_imm(imm);
#endif
}

static inline void arc_insn_fetch_limm(DisasContext *ctx)
{
    if (ctx->has_limm) {
        return;
    }

    vaddr addr = ctx->pc + ctx->insn_len;
    uint16_t hw0 = translator_lduw(ctx->env, &ctx->base, addr);
    uint16_t hw1 = translator_lduw(ctx->env, &ctx->base, addr + 2);

    ctx->limm = ((uint32_t)hw0 << 16) | hw1;
    ctx->has_limm = true;
    ctx->base.pc_next += 4;
}

static inline TCGv_i32 arc_insn_load_limm(DisasContext *ctx)
{
    TCGv_i32 reg = tcg_temp_new_i32();
    arc_insn_fetch_limm(ctx);
    tcg_gen_movi_i32(reg, ctx->limm);
    return reg;
}

static inline TCGv_i64 arc64_insn_load_limm_signed(DisasContext *ctx)
{
    TCGv_i64 reg = tcg_temp_new_i64();
    arc_insn_fetch_limm(ctx);
    tcg_gen_movi_i64(reg, (int64_t) ctx->limm);
    return reg;
}

static inline TCGv_i64 arc64_insn_load_limm_unsigned(DisasContext *ctx)
{
    TCGv_i64 reg = tcg_temp_new_i64();
    arc_insn_fetch_limm(ctx);
    tcg_gen_movi_i64(reg, (uint64_t) ctx->limm);
    return reg;
}

/*
 * Key notes on loading and saving registers:
 *
 *     1. Source LIMM values are always loaded from memory.
 *     2. Destination LIMM values are always loaded from cpu_gpr
 *        and its value is undefined for reading.
 *     3. TCG registers which are return by loaders are always
 *        not constants, so they may be used as temporary registers
 *        by instructions.
 *     4. A user must ensure that instructions consume only copies of
 *        real registers from cpu_gpr.
 *
 * TODO: Copy registers right in loaders.
 */

/* Regular 6-bit register operands */

static inline TCGv_i32 arc_insn_load_gpr(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid(regnum));

    TCGv_i32 reg = tcg_temp_new_i32();

#ifdef TARGET_ARCV3_64
    tcg_gen_extrl_i64_i32(reg, cpu_gpr[regnum]);
#else
    tcg_gen_mov_i32(reg, cpu_gpr[regnum]);
#endif

    return reg;
}

#ifdef TARGET_ARCV3_64
static inline TCGv_i64 arc64_insn_load_gpr(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid(regnum));

    TCGv_i64 reg = tcg_temp_new_i64();

    tcg_gen_mov_i64(reg, cpu_gpr[regnum]);

    return reg;
}
#endif

static inline TCGv_i32 arc_insn_load_pcl(DisasContext *ctx)
{
    TCGv_i32 reg = tcg_temp_new_i32();

    tcg_gen_movi_i32(reg, (uint32_t) ctx->pcl);

    return reg;
}

#ifdef TARGET_ARCV3_64
static inline TCGv_i64 arc64_insn_load_pcl(DisasContext *ctx)
{
    TCGv_i64 reg = tcg_temp_new_i64();

    tcg_gen_movi_i64(reg, ctx->pcl);

    return reg;
}
#endif

static inline void arc_insn_save_gpr(DisasContext *ctx, int regnum, TCGv_i32 value)
{
    g_assert(arc_regnum_valid(regnum));

#ifdef TARGET_ARCV3_64
    tcg_gen_extu_i32_i64(cpu_gpr[regnum], value);
#else
    tcg_gen_mov_i32(cpu_gpr[regnum], value);
#endif
}

#ifdef TARGET_ARCV3_64
static inline void arc64_insn_save_gpr(DisasContext *ctx, int regnum, TCGv value)
{
    g_assert(arc_regnum_valid(regnum));

    tcg_gen_mov_i64(cpu_gpr[regnum], value);
}
#endif

static inline TCGv_i32 arc_insn_load_src_reg(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid(regnum));

    TCGv_i32 reg = NULL;

    if (arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    switch (regnum) {
    case ARC_REGNUM_LIMM:
        reg = arc_insn_load_limm(ctx);
        break;
    case ARC_REGNUM_PCL:
        reg = arc_insn_load_pcl(ctx);
        break;
    default:
        reg = arc_insn_load_gpr(ctx, regnum);
    }

    g_assert_nonnull(reg);

    return reg;
}

#ifdef TARGET_ARCV3_64
static inline TCGv_i64 arc64_insn_load_src_reg(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid(regnum));

    TCGv reg = NULL;
    TCGv_i32 tmp = NULL;

    if (arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    switch (regnum) {
    case ARC_REGNUM_SLIMM:
        tmp = arc_insn_load_limm(ctx);
        reg = tcg_temp_new_i64();
        tcg_gen_ext_i32_i64(reg, tmp);
        break;
    case ARC_REGNUM_ULIMM:
        tmp = arc_insn_load_limm(ctx);
        reg = tcg_temp_new_i64();
        tcg_gen_extu_i32_i64(reg, tmp);
        break;
    case ARC_REGNUM_PCL:
        reg = arc64_insn_load_pcl(ctx);
        break;
    default:
        reg = arc64_insn_load_gpr(ctx, regnum);
    }

    g_assert_nonnull(reg);

    return reg;
}
#endif

static inline TCGv arc_insn_load_src_reg_tl(DisasContext *ctx, int regnum)
{
#ifdef TARGET_ARCV3_64
    return arc64_insn_load_src_reg(ctx, regnum);
#else
    return arc_insn_load_src_reg(ctx, regnum);
#endif
}


static inline TCGv_i32 arc_insn_load_dst_reg(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid(regnum));

    TCGv_i32 reg = NULL;

    if (arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_PCL) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    reg = arc_insn_load_gpr(ctx, regnum);

    g_assert_nonnull(reg);

    return reg;
}

#ifdef TARGET_ARCV3_64
static inline TCGv_i64 arc64_insn_load_dst_reg(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid(regnum));

    if (arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_PCL) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    return arc64_insn_load_gpr(ctx, regnum);
}
#endif

static inline TCGv arc_insn_load_dst_reg_tl(DisasContext *ctx, int regnum)
{
#ifdef TARGET_ARCV3_64
    return arc64_insn_load_dst_reg(ctx, regnum);
#else
    return arc_insn_load_dst_reg(ctx, regnum);
#endif
}

static inline void arc_insn_save_reg(DisasContext *ctx, int regnum, TCGv_i32 value)
{
    g_assert(arc_regnum_valid(regnum));

    if (arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_PCL) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    arc_insn_save_gpr(ctx, regnum, value);
}

#ifdef TARGET_ARCV3_64
static inline void arc64_insn_save_reg(DisasContext *ctx, int regnum, TCGv value)
{
    g_assert(arc_regnum_valid(regnum));

    if (arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_PCL) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    arc64_insn_save_gpr(ctx, regnum, value);
}
#endif

static inline void arc_insn_save_reg_tl(DisasContext *ctx, int regnum, TCGv value)
{
#ifdef TARGET_ARCV3_64
    arc64_insn_save_reg(ctx, regnum, value);
#else
    arc_insn_save_reg(ctx, regnum, value);
#endif
}

/* Destination register pair is never read, so just return tcg_temp_new_i64 */

#ifdef TARGET_ARCV3_64
typedef enum {
    ARC_REGPAIR_LIMM_DUPLICATE
} ARCRegPairLimmMode;

static inline TCGv_i64 arc_insn_load_src_reg_pair(DisasContext *ctx, int regnum, ARCRegPairLimmMode limm_mode)
{
    g_assert(arc_regnum_valid(regnum));

    TCGv_i64 pair;
    TCGv_i32 limm;

    if (arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    if (regnum == ARC_REGNUM_ULIMM || regnum == ARC_REGNUM_SLIMM) {
        limm = arc_insn_load_limm(ctx);
        switch (limm_mode) {
        case ARC_REGPAIR_LIMM_DUPLICATE:
            pair = tcg_temp_new_i64();
            tcg_gen_concat_i32_i64(pair, limm, limm);
            break;
        default:
            g_assert_not_reached();
        }
    } else {
        pair = arc64_insn_load_gpr(ctx, regnum);
    }

    return pair;
}
#else
typedef enum {
    ARC_REGPAIR_LIMM_UNSIGNED,
    ARC_REGPAIR_LIMM_SIGNED,
    ARC_REGPAIR_LIMM_DUPLICATE
} ARCRegPairLimmMode;

static inline TCGv_i64 arc_insn_load_src_reg_pair(DisasContext *ctx, int regnum, ARCRegPairLimmMode limm_mode)
{
    g_assert(arc_regnum_valid(regnum));

    TCGv_i64 pair = tcg_temp_new_i64();
    TCGv_i32 limm;

    if (arc_regnum_odd(regnum) || arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

#ifdef TARGET_ARCV2
    if (regnum == ARC_REGNUM_LP_COUNT) {
        arc_gen_exception_illegal_instruction(ctx);
    }
#endif

    /* (R28, ILINK) */
    if (regnum == ARC_REGNUM_R28) {
        arc_gen_check_kernel_mode(ctx);
    }

    if (regnum == ARC_REGNUM_LIMM) {
        limm = arc_insn_load_limm(ctx);
        switch (limm_mode) {
        case ARC_REGPAIR_LIMM_DUPLICATE:
            tcg_gen_concat_i32_i64(pair, limm, limm);
            break;
        case ARC_REGPAIR_LIMM_UNSIGNED:
            tcg_gen_extu_i32_i64(pair, limm);
            break;
        case ARC_REGPAIR_LIMM_SIGNED:
            tcg_gen_ext_i32_i64(pair, limm);
            break;
        default:
            g_assert_not_reached();
        }
    } else {
        tcg_gen_concat_i32_i64(pair, arc_insn_load_gpr(ctx, regnum), arc_insn_load_gpr(ctx, regnum + 1));
    }

    return pair;
}
#endif

#ifdef TARGET_ARCV3_64
static inline TCGv_i64 arc_insn_load_dst_reg_pair(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid(regnum));

    if (arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    return tcg_temp_new_i64();
}
#else
static inline TCGv_i64 arc_insn_load_dst_reg_pair(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid(regnum));

    if (arc_regnum_odd(regnum) || arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

#ifdef TARGET_ARCV2
    if (regnum == ARC_REGNUM_LP_COUNT) {
        arc_gen_exception_illegal_instruction(ctx);
    }
#endif

    /* (R28, ILINK) */
    if (regnum == ARC_REGNUM_R28) {
        arc_gen_check_kernel_mode(ctx);
    }

    return tcg_temp_new_i64();
}
#endif

#ifdef TARGET_ARCV3_64
static inline void arc_insn_save_reg_pair(DisasContext *ctx, int regnum, TCGv_i64 pair)
{
    g_assert(arc_regnum_valid(regnum));

    if (arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    if (regnum != ARC_REGNUM_SLIMM && regnum != ARC_REGNUM_ULIMM) {
        arc64_insn_save_gpr(ctx, regnum, pair);
    }
}
#else
static inline void arc_insn_save_reg_pair(DisasContext *ctx, int regnum, TCGv_i64 pair)
{
    g_assert(arc_regnum_valid(regnum));

    TCGv_i32 low = tcg_temp_new_i32();
    TCGv_i32 high = tcg_temp_new_i32();

    if (arc_regnum_odd(regnum) || arc_regnum_unsupported(regnum)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

#ifdef TARGET_ARCV2
    if (regnum == ARC_REGNUM_LP_COUNT) {
        arc_gen_exception_illegal_instruction(ctx);
    }
#endif

    /* (R28, ILINK) */
    if (regnum == ARC_REGNUM_R28) {
        arc_gen_check_kernel_mode(ctx);
    }

    if (regnum != ARC_REGNUM_LIMM) {
        tcg_gen_extr_i64_i32(low, high, pair);
        arc_insn_save_gpr(ctx, regnum, low);
        arc_insn_save_gpr(ctx, regnum + 1, high);
    }
}
#endif

/* 3-bit register operands (S-format) */

static inline TCGv_i32 arc_insn_load_src_reg_s(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid_s(regnum));

    regnum = arc_regnum_from_s(regnum);

    return arc_insn_load_gpr(ctx, regnum);
}

#ifdef TARGET_ARCV3_64
static inline TCGv_i64 arc64_insn_load_src_reg_s(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid_s(regnum));

    regnum = arc_regnum_from_s(regnum);

    return arc64_insn_load_gpr(ctx, regnum);
}
#endif

static inline TCGv arc_insn_load_src_reg_s_tl(DisasContext *ctx, int regnum)
{
#ifdef TARGET_ARCV3_64
    return arc64_insn_load_src_reg_s(ctx, regnum);
#else
    return arc_insn_load_src_reg_s(ctx, regnum);
#endif
}

static inline TCGv_i32 arc_insn_load_dst_reg_s(DisasContext *ctx, int reg)
{
    return arc_insn_load_src_reg_s(ctx, reg);
}

#ifdef TARGET_ARCV3_64
static inline TCGv_i64 arc64_insn_load_dst_reg_s(DisasContext *ctx, int reg)
{
    return arc64_insn_load_src_reg_s(ctx, reg);
}
#endif

static inline TCGv arc_insn_load_dst_reg_s_tl(DisasContext *ctx, int regnum)
{
#ifdef TARGET_ARCV3_64
    return arc64_insn_load_dst_reg_s(ctx, regnum);
#else
    return arc_insn_load_dst_reg_s(ctx, regnum);
#endif
}

static inline void arc_insn_save_reg_s(DisasContext *ctx, int regnum, TCGv_i32 value)
{
    g_assert(arc_regnum_valid_s(regnum));

    regnum = arc_regnum_from_s(regnum);

    arc_insn_save_gpr(ctx, regnum, value);
}

#ifdef TARGET_ARCV3_64
static inline void arc64_insn_save_reg_s(DisasContext *ctx, int regnum, TCGv_i64 value)
{
    g_assert(arc_regnum_valid_s(regnum));

    regnum = arc_regnum_from_s(regnum);

    arc64_insn_save_gpr(ctx, regnum, value);
}
#endif

static inline void arc_insn_save_reg_s_tl(DisasContext *ctx, int regnum, TCGv value)
{
#ifdef TARGET_ARCV3_64
    return arc64_insn_save_reg_s(ctx, regnum, value);
#else
    return arc_insn_save_reg_s(ctx, regnum, value);
#endif
}

/* 5-bit register operands (H-format)*/

static inline TCGv_i32 arc_insn_load_src_reg_h(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid_h(regnum));

    TCGv_i32 reg;

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    if (regnum == ARC_REGNUM_LIMM_H) {
        reg = arc_insn_load_limm(ctx);
    } else {
        reg = arc_insn_load_gpr(ctx, regnum);
    }

    return reg;
}

static inline TCGv_i32 arc_insn_load_dst_reg_h(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid_h(regnum));

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    return arc_insn_load_gpr(ctx, regnum);
}

static inline void arc_insn_save_reg_h(DisasContext *ctx, int regnum, TCGv_i32 value)
{
    g_assert(arc_regnum_valid_h(regnum));

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    arc_insn_save_gpr(ctx, regnum, value);
}

#ifdef TARGET_ARCV3_64
static inline TCGv_i64 arc64_insn_load_src_reg_h(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid_h(regnum));

    TCGv_i64 reg;

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    if (regnum == ARC_REGNUM_LIMM_H) {
        reg = arc64_insn_load_limm_unsigned(ctx);
    } else {
        reg = arc64_insn_load_gpr(ctx, regnum);
    }

    return reg;
}

static inline TCGv_i64 arc64_insn_load_dst_reg_h(DisasContext *ctx, int regnum)
{
    g_assert(arc_regnum_valid_h(regnum));

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    return arc64_insn_load_gpr(ctx, regnum);
}

static inline void arc64_insn_save_reg_h(DisasContext *ctx, int regnum, TCGv_i64 value)
{
    g_assert(arc_regnum_valid_h(regnum));

    if (regnum == ARC_REGNUM_ILINK) {
        arc_gen_check_kernel_mode(ctx);
    }

    arc64_insn_save_gpr(ctx, regnum, value);
}
#endif

static inline TCGv arc_insn_load_src_reg_h_tl(DisasContext *ctx, int regnum)
{
#ifdef TARGET_ARCV3_64
    return arc64_insn_load_src_reg_h(ctx, regnum);
#else
    return arc_insn_load_src_reg_h(ctx, regnum);
#endif
}

static inline TCGv arc_insn_load_dst_reg_h_tl(DisasContext *ctx, int regnum)
{
#ifdef TARGET_ARCV3_64
    return arc64_insn_load_dst_reg_h(ctx, regnum);
#else
    return arc_insn_load_dst_reg_h(ctx, regnum);
#endif
}

static inline void arc_insn_save_reg_h_tl(DisasContext *ctx, int regnum, TCGv value)
{
#ifdef TARGET_ARCV3_64
    arc64_insn_save_reg_h(ctx, regnum, value);
#else
    arc_insn_save_reg_h(ctx, regnum, value);
#endif
}

/* Accumulator registers*/

static inline TCGv_i64 arc_gen_load_accumulator(void)
{
    TCGv_i64 acc = tcg_temp_new_i64();

#ifdef TARGET_ARCV3_64
    tcg_gen_mov_i64(acc, cpu_gpr[ARC_REGNUM_ACC0]);
#else
    tcg_gen_concat_i32_i64(acc, cpu_gpr[ARC_REGNUM_ACCL], cpu_gpr[ARC_REGNUM_ACCH]);
#endif

    return acc;
}

static inline void arc_gen_save_accumulator(TCGv_i64 value)
{
#ifdef TARGET_ARCV3_64
    tcg_gen_mov_i64(cpu_gpr[ARC_REGNUM_ACC0], value);
#else
    tcg_gen_extr_i64_i32(cpu_gpr[ARC_REGNUM_ACCL], cpu_gpr[ARC_REGNUM_ACCH], value);
#endif
}

/* Flags setting helpers */

static inline void arc_gen_set_flag_Z(TCGv_i32 value)
{
    tcg_gen_setcondi_i32(TCG_COND_EQ, cpu_Zf, value, 0);
}

static inline void arc64_gen_set_flag_Z(TCGv_i64 value)
{
    TCGv_i64 tmp = tcg_temp_new_i64();

    tcg_gen_setcondi_i64(TCG_COND_EQ, tmp, value, 0);
    tcg_gen_extrl_i64_i32(cpu_Zf, tmp);
}

static inline void arc_gen_set_flag_N(TCGv_i32 value)
{
    tcg_gen_shri_i32(cpu_Nf, value, 31);
}

static inline void arc64_gen_set_flag_N(TCGv_i64 value)
{
    TCGv_i64 tmp = tcg_temp_new_i64();

    tcg_gen_shri_i64(tmp, value, 63);
    tcg_gen_extrl_i64_i32(cpu_Nf, tmp);
}

static inline void arc_gen_set_flag_N_accumulator(void)
{
#ifdef TARGET_ARCV3_64
    g_assert_not_reached();
#else
    tcg_gen_shri_i32(cpu_Nf, cpu_gpr[ARC_REGNUM_ACCH], TARGET_LONG_BITS_32 - 1);
#endif
}

static inline void arc_gen_set_flag_Z_clear(void)
{
    tcg_gen_movi_i32(cpu_Zf, 0);
}

static inline void arc_gen_set_flag_V_clear(void)
{
    tcg_gen_movi_i32(cpu_Vf, 0);
}

static inline void arc_gen_set_flag_N_clear(void)
{
    tcg_gen_movi_i32(cpu_Nf, 0);
}

/*
 * Overflow occurs if the two addends share a sign
 * and the result's sign differs from them.
 *
 * Vf |= ((acc ^ result) & ~(acc ^ product)) >> 63
 */
static inline void arc_gen_set_flag_V_mac(TCGv_i64 result, TCGv_i64 acc, TCGv_i64 prod)
{
    TCGv_i64 ov = tcg_temp_new_i64();
    TCGv_i64 same_sign = tcg_temp_new_i64();
    TCGv_i32 ov32 = tcg_temp_new_i32();

    tcg_gen_xor_i64(ov, acc, result);      /* acc ^ result */
    tcg_gen_xor_i64(same_sign, acc, prod); /* acc ^ product */
    tcg_gen_andc_i64(ov, ov, same_sign);   /* (acc ^ result) & ~(acc ^ product) */
    tcg_gen_shri_i64(ov, ov, 63);          /* >> 63 */
    tcg_gen_extrl_i64_i32(ov32, ov);

    tcg_gen_or_i32(cpu_Vf, cpu_Vf, ov32);
}

/*
 * Unsigned accumulation overflow: a carry out of the 64-bit addition, which
 * happens exactly when the (unsigned) result wraps below the old accumulator.
 *
 * Vf |= (result < acc)
 */
static inline void arc_gen_set_flag_V_macu(TCGv_i64 result, TCGv_i64 acc)
{
    TCGv_i64 ov = tcg_temp_new_i64();
    TCGv_i32 ov32 = tcg_temp_new_i32();

    tcg_gen_setcond_i64(TCG_COND_LTU, ov, result, acc);
    tcg_gen_extrl_i64_i32(ov32, ov);

    tcg_gen_or_i32(cpu_Vf, cpu_Vf, ov32);
}

/*
 * Z = a == 0
 * N = a >> 31
 * C = (msb_b & msb_c) | (msb_b & !msb_a) | (msb_c & !msb_a)
 * V = !(msb_b ^ msb_c) & (msb_b ^ msb_a)
 */
static inline void arc_gen_set_flag_ZNCV_add(TCGv_i32 a, TCGv_i32 b, TCGv_i32 c)
{
    TCGv_i32 msb_a = tcg_temp_new_i32();
    TCGv_i32 msb_b = tcg_temp_new_i32();
    TCGv_i32 msb_c = tcg_temp_new_i32();
    TCGv_i32 temp = tcg_temp_new_i32();

    arc_gen_set_flag_Z(a);
    arc_gen_set_flag_N(a);

    tcg_gen_shri_i32(msb_a, a, TARGET_LONG_BITS_32 - 1);
    tcg_gen_shri_i32(msb_b, b, TARGET_LONG_BITS_32 - 1);
    tcg_gen_shri_i32(msb_c, c, TARGET_LONG_BITS_32 - 1);

    tcg_gen_and_i32(cpu_Cf, msb_b, msb_c);
    tcg_gen_andc_i32(temp, msb_b, msb_a);
    tcg_gen_or_i32(cpu_Cf, cpu_Cf, temp);
    tcg_gen_andc_i32(temp, msb_c, msb_a);
    tcg_gen_or_i32(cpu_Cf, cpu_Cf, temp);

    tcg_gen_xor_i32(cpu_Vf, msb_b, msb_c);
    tcg_gen_not_i32(cpu_Vf, cpu_Vf);
    tcg_gen_andi_i32(cpu_Vf, cpu_Vf, 1);
    tcg_gen_xor_i32(temp, msb_b, msb_a);
    tcg_gen_and_i32(cpu_Vf, cpu_Vf, temp);
}

static inline void arc64_gen_set_flag_ZNCV_add(TCGv_i64 a, TCGv_i64 b, TCGv_i64 c)
{
    TCGv_i64 msb_a = tcg_temp_new_i64();
    TCGv_i64 msb_b = tcg_temp_new_i64();
    TCGv_i64 msb_c = tcg_temp_new_i64();
    TCGv_i64 temp = tcg_temp_new_i64();
    TCGv_i64 temp_flag = tcg_temp_new_i64();

    arc64_gen_set_flag_Z(a);
    arc64_gen_set_flag_N(a);

    tcg_gen_shri_i64(msb_a, a, TARGET_LONG_BITS_64 - 1);
    tcg_gen_shri_i64(msb_b, b, TARGET_LONG_BITS_64 - 1);
    tcg_gen_shri_i64(msb_c, c, TARGET_LONG_BITS_64 - 1);

    tcg_gen_and_i64(temp_flag, msb_b, msb_c);
    tcg_gen_andc_i64(temp, msb_b, msb_a);
    tcg_gen_or_i64(temp_flag, temp_flag, temp);
    tcg_gen_andc_i64(temp, msb_c, msb_a);
    tcg_gen_or_i64(temp_flag, temp_flag, temp);
    tcg_gen_extrl_i64_i32(cpu_Cf, temp_flag);

    tcg_gen_xor_i64(temp_flag, msb_b, msb_c);
    tcg_gen_not_i64(temp_flag, temp_flag);
    tcg_gen_andi_i64(temp_flag, temp_flag, 1);
    tcg_gen_xor_i64(temp, msb_b, msb_a);
    tcg_gen_and_i64(temp_flag, temp_flag, temp);
    tcg_gen_extrl_i64_i32(cpu_Vf, temp_flag);
}

/*
 * Z = a == 0
 * N = a >> 31
 * C = (msb_b & !msb_c) | (msb_b & !msb_a) | (!msb_c & !msb_a)
 * V = (msb_b ^ msb_c) & (msb_b ^ msb_a)
 */
static inline void arc_gen_set_flag_ZNCV_sub(TCGv_i32 a, TCGv_i32 b, TCGv_i32 c)
{
    TCGv_i32 c_inv = tcg_temp_new_i32();

    /* Reuse the helper for ADD but with inverted C */
    tcg_gen_not_i32(c_inv, c);
    arc_gen_set_flag_ZNCV_add(a, b, c_inv);

    /* C for SUB instructions must be treated as "borrow" */
    tcg_gen_xori_i32(cpu_Cf, cpu_Cf, 1);
}

static inline void arc64_gen_set_flag_ZNCV_sub(TCGv_i64 a, TCGv_i64 b, TCGv_i64 c)
{
    TCGv_i64 c_inv = tcg_temp_new_i64();

    /* Reuse the helper for ADD but with inverted C */
    tcg_gen_not_i64(c_inv, c);
    arc64_gen_set_flag_ZNCV_add(a, b, c_inv);

    /* C for SUB instructions must be treated as "borrow" */
    tcg_gen_xori_i32(cpu_Cf, cpu_Cf, 1);
}

/*
 * Conditional execution prologue.
 *
 * Materializes a 0/1 truth value for the ARCv2 condition code "cc" using the
 * cached Z/N/C/V flags, allocates a skip label on ctx, and emits a brcondi to
 * it so that the instruction body is bypassed when the condition is false.
 * The label itself is emitted later by arc_tr_translate_insn().
 *
 * For ARC_CC_AL the function is a no-op: ctx->cc_skip_label stays NULL and no
 * TCG ops are emitted, so unconditional instructions pay nothing.
 *
 * Logic mirrors arc_gen_verifyCCFlag() from the legacy ARC port; flags are
 * stored as 0/1 so plain bitwise ops are sufficient.
 */
static inline void arc_gen_cc_prologue(DisasContext *ctx, int cc, TCGLabel *skip)
{
    if (cc == ARC_CC_AL) {
        return;
    }

    TCGv_i32 cond_v = tcg_temp_new_i32();
    TCGv_i32 tmp = tcg_temp_new_i32();

    switch (cc) {
    /* EQ / Z */
    case ARC_CC_EQ:
        tcg_gen_mov_i32(cond_v, cpu_Zf);
        break;
    /* NE / NZ */
    case ARC_CC_NE:
        tcg_gen_xori_i32(cond_v, cpu_Zf, 1);
        break;
    /* PL / P : !N */
    case ARC_CC_PL:
        tcg_gen_xori_i32(cond_v, cpu_Nf, 1);
        break;
    /* MI / N */
    case ARC_CC_MI:
        tcg_gen_mov_i32(cond_v, cpu_Nf);
        break;
    /* CS / C / LO */
    case ARC_CC_CS:
        tcg_gen_mov_i32(cond_v, cpu_Cf);
        break;
    /* CC / NC / HS : !C */
    case ARC_CC_CC:
        tcg_gen_xori_i32(cond_v, cpu_Cf, 1);
        break;
    /* VS / V */
    case ARC_CC_VS:
        tcg_gen_mov_i32(cond_v, cpu_Vf);
        break;
    /* VC / NV : !V */
    case ARC_CC_VC:
        tcg_gen_xori_i32(cond_v, cpu_Vf, 1);
        break;
    /* GT : XNOR(N, V) & !Z */
    case ARC_CC_GT:
        tcg_gen_eqv_i32(cond_v, cpu_Nf, cpu_Vf);
        tcg_gen_xori_i32(tmp, cpu_Zf, 1);
        tcg_gen_and_i32(cond_v, cond_v, tmp);
        tcg_gen_andi_i32(cond_v, cond_v, 1);
        break;
    /* GE : XNOR(N, V) */
    case ARC_CC_GE:
        tcg_gen_eqv_i32(cond_v, cpu_Nf, cpu_Vf);
        tcg_gen_andi_i32(cond_v, cond_v, 1);
        break;
    /* LT : XOR(N, V) */
    case ARC_CC_LT:
        tcg_gen_xor_i32(cond_v, cpu_Nf, cpu_Vf);
        break;
    /* LE : XOR(N, V) | Z */
    case ARC_CC_LE:
        tcg_gen_xor_i32(cond_v, cpu_Nf, cpu_Vf);
        tcg_gen_or_i32(cond_v, cond_v, cpu_Zf);
        break;
    /* HI : !(C | Z) */
    case ARC_CC_HI:
        tcg_gen_or_i32(cond_v, cpu_Cf, cpu_Zf);
        tcg_gen_xori_i32(cond_v, cond_v, 1);
        break;
    /* LS : C | Z */
    case ARC_CC_LS:
        tcg_gen_or_i32(cond_v, cpu_Cf, cpu_Zf);
        break;
    /* PNZ : !(N | Z) */
    case ARC_CC_PNZ:
        tcg_gen_or_i32(cond_v, cpu_Nf, cpu_Zf);
        tcg_gen_xori_i32(cond_v, cond_v, 1);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "arc: translation: incorrect <.cc> code at pc=0x" TARGET_FMT_lx "\n", ctx->pc);
        arc_gen_exception_illegal_instruction(ctx);
    }

    tcg_gen_brcondi_i32(TCG_COND_EQ, cond_v, 0, skip);
}

static inline void arc_gen_cc_branch_fallthrough(DisasContext *ctx)
{
    tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next);
}

static inline uint32_t arc_get_insn_length_by_address(DisasContext *ctx, vaddr pc)
{
    uint16_t hw0 = translator_lduw(ctx->env, &ctx->base, pc);
    int major = (hw0 >> 11) & 0x1F;

#ifdef TARGET_ARCV3_64
    if (major <= 0x07 || major == 0x0B) {
#else
    if (major <= 0x07) {
#endif
        return 4;
    } else {
        return 2;
    }
}

#define ARC_DEF_TRANS_STUB(name) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        return false; \
    }

#define ARC_DEF_TRANS_R32_R32_R32_F(handler, name, r0, r1, r2, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg(ctx, r1); \
        TCGv_i32 reg_r2 = arc_insn_load_src_reg(ctx, r2); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_R64_R64_R64_F(handler, name, r0, r1, r2, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_src_reg(ctx, r1); \
        TCGv_i64 reg_r2 = arc64_insn_load_src_reg(ctx, r2); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc64_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_R64_R64_R64_F(handler, name, r0, r1, r2, f) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_R32_R32_I32_F(handler, name, r0, r1, imm, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg(ctx, r1); \
        TCGv_i32 reg_r2 = arc_insn_load_imm(imm); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_R64_R64_I64_F(handler, name, r0, r1, imm, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_src_reg(ctx, r1); \
        TCGv_i64 reg_r2 = arc64_insn_load_imm(imm); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc64_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_R64_R64_I64_F(handler, name, r0, r1, imm, f) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_R32_R32_R32_F_COND(handler, name, r0, r1, r2, f, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg(ctx, r1); \
        TCGv_i32 reg_r2 = arc_insn_load_src_reg(ctx, r2); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_R64_R64_R64_F_COND(handler, name, r0, r1, r2, f, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_src_reg(ctx, r1); \
        TCGv_i64 reg_r2 = arc64_insn_load_src_reg(ctx, r2); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc64_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_R64_R64_R64_F_COND(handler, name, r0, r1, r2, f, cond) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_R32_R32_I32_F_COND(handler, name, r0, r1, imm, f, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg(ctx, r1); \
        TCGv_i32 reg_r2 = arc_insn_load_imm(imm); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_R64_R64_I64_F_COND(handler, name, r0, r1, imm, f, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_src_reg(ctx, r1); \
        TCGv_i64 reg_r2 = arc64_insn_load_imm(imm); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc64_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_R64_R64_I64_F_COND(handler, name, r0, r1, imm, f, cond) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_R32_R32_F(handler, name, r0, r1, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg(ctx, r1); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, f); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_R64_R64_F(handler, name, r0, r1, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_src_reg(ctx, r1); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, f); \
        arc64_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_R64_R64_F(handler, name, r0, r1, f) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_R32_R32(handler, name, r0, r1) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg(ctx, r1); \
        arc_gen_##handler(ctx, reg_r0, reg_r1); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }

#define ARC_DEF_TRANS_R32_I32_F(handler, name, r0, imm, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_imm(imm); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, f); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_R64_I64_F(handler, name, r0, imm, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_imm(imm); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, f); \
        arc64_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_R64_I64_F(handler, name, r0, imm, f) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_R32_I32(handler, name, r0, imm) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_imm(imm); \
        arc_gen_##handler(ctx, reg_r0, reg_r1); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        return true; \
    }

#define ARC_DEF_TRANS_R32_R32_COND(handler, name, r0, r1, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg(ctx, r1); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc_gen_##handler(ctx, reg_r0, reg_r1); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }

#define ARC_DEF_TRANS_R32_R32_F_COND(handler, name, r0, r1, f, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg(ctx, r1); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, f); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_R64_R64_F_COND(handler, name, r0, r1, f, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_src_reg(ctx, r1); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, f); \
        arc64_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_R64_R64_F_COND(handler, name, r0, r1, f, cond) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_R32_I32_COND(handler, name, r0, imm, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_imm(imm); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc_gen_##handler(ctx, reg_r0, reg_r1); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }

#define ARC_DEF_TRANS_R32_I32_F_COND(handler, name, r0, imm, f, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_imm(imm); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, f); \
        arc_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_R64_I64_F_COND(handler, name, r0, imm, f, cond) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_imm(imm); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, cond, skip); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, f); \
        arc64_insn_save_reg(ctx, r0, reg_r0); \
        gen_set_label(skip); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_R64_I64_F_COND(handler, name, r0, imm, f, cond) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_RS32_RS32_F(handler, name, r0, r1, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg_s(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg_s(ctx, r1); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, f); \
        arc_insn_save_reg_s(ctx, r0, reg_r0); \
        return true; \
    }

#define ARC_DEF_TRANS_RS32_RS32_RS32_F(handler, name, r0, r1, r2, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg_s(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg_s(ctx, r1); \
        TCGv_i32 reg_r2 = arc_insn_load_src_reg_s(ctx, r2); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc_insn_save_reg_s(ctx, r0, reg_r0); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_RS64_RS64_RS64_F(handler, name, r0, r1, r2, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg_s(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_src_reg_s(ctx, r1); \
        TCGv_i64 reg_r2 = arc64_insn_load_src_reg_s(ctx, r2); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc64_insn_save_reg_s(ctx, r0, reg_r0); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_RS64_RS64_RS64_F(handler, name, r0, r1, r2, f) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_RS32_RS32_I32_F(handler, name, r0, r1, imm, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg_s(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg_s(ctx, r1); \
        TCGv_i32 reg_r2 = arc_insn_load_imm(imm); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc_insn_save_reg_s(ctx, r0, reg_r0); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_RS64_RS64_I64_F(handler, name, r0, r1, imm, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg_s(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_src_reg_s(ctx, r1); \
        TCGv_i64 reg_r2 = arc64_insn_load_imm(imm); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc64_insn_save_reg_s(ctx, r0, reg_r0); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_RS64_RS64_I64_F(handler, name, r0, r1, imm, f) \
    ARC_DEF_TRANS_STUB(name)
#endif

#define ARC_DEF_TRANS_RS32_RS32_RH32_F(handler, name, r0, r1, r2, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg_s(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg_s(ctx, r1); \
        TCGv_i32 reg_r2 = arc_insn_load_src_reg_h(ctx, r2); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc_insn_save_reg_s(ctx, r0, reg_r0); \
        return true; \
    }

#define ARC_DEF_TRANS_RH32_RH32_I32_F(handler, name, r0, r1, imm, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg_h(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg_h(ctx, r1); \
        TCGv_i32 reg_r2 = arc_insn_load_imm(imm); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc_insn_save_reg_h(ctx, r0, reg_r0); \
        return true; \
    }

#define ARC_DEF_TRANS_RS32_R32_I32_F(handler, name, r0, r1, imm, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i32 reg_r0 = arc_insn_load_dst_reg_s(ctx, r0); \
        TCGv_i32 reg_r1 = arc_insn_load_src_reg(ctx, r1); \
        TCGv_i32 reg_r2 = arc_insn_load_imm(imm); \
        arc_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc_insn_save_reg_s(ctx, r0, reg_r0); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_RS64_R64_I64_F(handler, name, r0, r1, imm, f) \
    static bool trans_##name(DisasContext *ctx, arg_##name *a) \
    { \
        TCGv_i64 reg_r0 = arc64_insn_load_dst_reg_s(ctx, r0); \
        TCGv_i64 reg_r1 = arc64_insn_load_src_reg(ctx, r1); \
        TCGv_i64 reg_r2 = arc64_insn_load_imm(imm); \
        arc64_gen_##handler(ctx, reg_r0, reg_r1, reg_r2, f); \
        arc64_insn_save_reg_s(ctx, r0, reg_r0); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_RS64_R64_I64_F(handler, name, r0, r1, imm, f) \
    ARC_DEF_TRANS_STUB(name)
#endif

/* 3-operands variant of DOP */

#define ARC_DEF_TRANS_DOP_REG_REG(name) \
    ARC_DEF_TRANS_R32_R32_R32_F(name, name##_dop_reg_reg, a->a, a->b, a->c, a->f);

#define ARC_DEF_TRANS_DOP_REG_U6(name) \
    ARC_DEF_TRANS_R32_R32_I32_F(name, name##_dop_reg_u6, a->a, a->b, a->imm, a->f);

#define ARC_DEF_TRANS_DOP_REG_S12(name) \
    ARC_DEF_TRANS_R32_R32_I32_F(name, name##_dop_reg_s12, a->b, a->b, a->imm, a->f);

#define ARC_DEF_TRANS_DOP_COND_REG(name) \
    ARC_DEF_TRANS_R32_R32_R32_F_COND(name, name##_dop_cond_reg, a->b, a->b, a->c, a->f, a->cond);

#define ARC_DEF_TRANS_DOP_COND_U6(name) \
    ARC_DEF_TRANS_R32_R32_I32_F_COND(name, name##_dop_cond_u6, a->b, a->b, a->imm, a->f, a->cond);

/* 3-operands variant of DOP for 64-bit targets */

#define ARC64_DEF_TRANS_DOP_REG_REG(name) \
    ARC64_DEF_TRANS_R64_R64_R64_F(name, name##_dop_reg_reg, a->a, a->b, a->c, a->f);

#define ARC64_DEF_TRANS_DOP_REG_U6(name) \
    ARC64_DEF_TRANS_R64_R64_I64_F(name, name##_dop_reg_u6, a->a, a->b, a->imm, a->f);

#define ARC64_DEF_TRANS_DOP_REG_S12(name) \
    ARC64_DEF_TRANS_R64_R64_I64_F(name, name##_dop_reg_s12, a->b, a->b, a->imm, a->f);

#define ARC64_DEF_TRANS_DOP_COND_REG(name) \
    ARC64_DEF_TRANS_R64_R64_R64_F_COND(name, name##_dop_cond_reg, a->b, a->b, a->c, a->f, a->cond);

#define ARC64_DEF_TRANS_DOP_COND_U6(name) \
    ARC64_DEF_TRANS_R64_R64_I64_F_COND(name, name##_dop_cond_u6, a->b, a->b, a->imm, a->f, a->cond);

/* 2-operands variant of DOP (mov) */

#define ARC_DEF_TRANS_DOP_2OP_REG_REG(name) \
    ARC_DEF_TRANS_R32_R32_F(name, name##_dop_reg_reg, a->b, a->c, a->f);

#define ARC_DEF_TRANS_DOP_2OP_REG_U6(name) \
    ARC_DEF_TRANS_R32_I32_F(name, name##_dop_reg_u6, a->b, a->imm, a->f);

#define ARC_DEF_TRANS_DOP_2OP_REG_S12(name) \
    ARC_DEF_TRANS_R32_I32_F(name, name##_dop_reg_s12, a->b, a->imm, a->f);

#define ARC_DEF_TRANS_DOP_2OP_COND_REG(name) \
    ARC_DEF_TRANS_R32_R32_F_COND(name, name##_dop_cond_reg, a->b, a->c, a->f, a->cond);

#define ARC_DEF_TRANS_DOP_2OP_COND_U6(name) \
    ARC_DEF_TRANS_R32_I32_F_COND(name, name##_dop_cond_u6, a->b, a->imm, a->f, a->cond);

#define ARC64_DEF_TRANS_DOP_2OP_REG_REG(name) \
    ARC64_DEF_TRANS_R64_R64_F(name, name##_dop_reg_reg, a->b, a->c, a->f);

#define ARC64_DEF_TRANS_DOP_2OP_REG_U6(name) \
    ARC64_DEF_TRANS_R64_I64_F(name, name##_dop_reg_u6, a->b, a->imm, a->f);

#define ARC64_DEF_TRANS_DOP_2OP_REG_S12(name) \
    ARC64_DEF_TRANS_R64_I64_F(name, name##_dop_reg_s12, a->b, a->imm, a->f);

#define ARC64_DEF_TRANS_DOP_2OP_COND_REG(name) \
    ARC64_DEF_TRANS_R64_R64_F_COND(name, name##_dop_cond_reg, a->b, a->c, a->f, a->cond);

#define ARC64_DEF_TRANS_DOP_2OP_COND_U6(name) \
    ARC64_DEF_TRANS_R64_I64_F_COND(name, name##_dop_cond_u6, a->b, a->imm, a->f, a->cond);

/* SOP */

#define ARC_DEF_TRANS_SOP_REG_REG(name) \
    ARC_DEF_TRANS_R32_R32_F(name, name##_sop_reg_reg, a->b, a->c, a->f);

#define ARC64_DEF_TRANS_SOP_REG_REG(name) \
    ARC64_DEF_TRANS_R64_R64_F(name, name##_sop_reg_reg, a->b, a->c, a->f);

#define ARC_DEF_TRANS_SOP_REG_U6(name) \
    ARC_DEF_TRANS_R32_I32_F(name, name##_sop_reg_u6, a->b, a->imm, a->f);

#define ARC64_DEF_TRANS_SOP_REG_U6(name) \
    ARC64_DEF_TRANS_R64_I64_F(name, name##_sop_reg_u6, a->b, a->imm, a->f);

#define ARC_DEF_TRANS_S_DOP_2_OPERANDS(name) \
    ARC_DEF_TRANS_RS32_RS32_F(name, name##_s_dop, a->b, a->c, false);

#define ARC_DEF_TRANS_S_DOP_3_OPERANDS(name) \
    ARC_DEF_TRANS_RS32_RS32_RS32_F(name, name##_s_dop, a->b, a->b, a->c, false);

#define ARC64_DEF_TRANS_S_DOP_3_OPERANDS(name) \
    ARC64_DEF_TRANS_RS64_RS64_RS64_F(name, name##_s_dop, a->b, a->b, a->c, false);

#define ARC_DEF_TRANS_S_SH_SUB_BIT(name) \
    ARC_DEF_TRANS_RS32_RS32_I32_F(name, name##_s, a->b, a->b, a->imm, false);

/* FLAG/KFLAG formats */

#define ARC_DEF_TRANS_FLAG_DOP_REG_REG(name) \
    static bool trans_##name##_dop_reg_reg(DisasContext *ctx, arg_##name##_dop_reg_reg *a) \
    { \
        TCGv_i32 bits = arc_insn_load_src_reg(ctx, a->c); \
        arc_gen_##name(ctx, bits); \
        return true; \
    }

#define ARC_DEF_TRANS_FLAG_DOP_REG_U6(name) \
    static bool trans_##name##_dop_reg_u6(DisasContext *ctx, arg_##name##_dop_reg_u6 *a) \
    { \
        TCGv_i32 bits = arc_insn_load_imm(a->imm); \
        arc_gen_##name(ctx, bits); \
        return true; \
    }

#define ARC_DEF_TRANS_FLAG_DOP_REG_S12(name) \
    static bool trans_##name##_dop_reg_s12(DisasContext *ctx, arg_##name##_dop_reg_s12 *a) \
    { \
        TCGv_i32 bits = arc_insn_load_imm(a->imm); \
        arc_gen_##name(ctx, bits); \
        return true; \
    }

#define ARC_DEF_TRANS_FLAG_DOP_REG_REG_COND(name) \
    static bool trans_##name##_dop_reg_reg_cond(DisasContext *ctx, arg_##name##_dop_reg_reg_cond *a) \
    { \
        TCGv_i32 bits = arc_insn_load_src_reg(ctx, a->c); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, a->cond, skip); \
        arc_gen_##name(ctx, bits); \
        gen_set_label(skip); \
        return true; \
    }

#define ARC_DEF_TRANS_FLAG_DOP_REG_U6_COND(name) \
    static bool trans_##name##_dop_reg_u6_cond(DisasContext *ctx, arg_##name##_dop_reg_u6_cond *a) \
    { \
        TCGv_i32 bits = arc_insn_load_imm(a->imm); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, a->cond, skip); \
        arc_gen_##name(ctx, bits); \
        gen_set_label(skip); \
        return true; \
    }

/* CMP, TST and BTST formats without output register */

#define ARC_DEF_TRANS_CMP_DOP_REG_REG(name) \
    static bool trans_##name##_dop_reg_reg(DisasContext *ctx, arg_##name##_dop_reg_reg *a) \
    { \
        TCGv_i32 b = arc_insn_load_src_reg(ctx, a->b); \
        TCGv_i32 c = arc_insn_load_src_reg(ctx, a->c); \
        arc_gen_##name(ctx, b, c); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_CMP_DOP_REG_REG(name) \
    static bool trans_##name##_dop_reg_reg(DisasContext *ctx, arg_##name##_dop_reg_reg *a) \
    { \
        TCGv_i64 b = arc64_insn_load_src_reg(ctx, a->b); \
        TCGv_i64 c = arc64_insn_load_src_reg(ctx, a->c); \
        arc64_gen_##name(ctx, b, c); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_CMP_DOP_REG_REG(name) \
    ARC_DEF_TRANS_STUB(name##_dop_reg_reg)
#endif

#define ARC_DEF_TRANS_CMP_DOP_REG_U6(name) \
    static bool trans_##name##_dop_reg_u6(DisasContext *ctx, arg_##name##_dop_reg_u6 *a) \
    { \
        TCGv_i32 b = arc_insn_load_src_reg(ctx, a->b); \
        TCGv_i32 c = arc_insn_load_imm(a->imm); \
        arc_gen_##name(ctx, b, c); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_CMP_DOP_REG_U6(name) \
    static bool trans_##name##_dop_reg_u6(DisasContext *ctx, arg_##name##_dop_reg_u6 *a) \
    { \
        TCGv_i64 b = arc64_insn_load_src_reg(ctx, a->b); \
        TCGv_i64 c = arc64_insn_load_imm(a->imm); \
        arc64_gen_##name(ctx, b, c); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_CMP_DOP_REG_U6(name) \
    ARC_DEF_TRANS_STUB(name##_dop_reg_u6)
#endif

#define ARC_DEF_TRANS_CMP_DOP_REG_S12(name) \
    static bool trans_##name##_dop_reg_s12(DisasContext *ctx, arg_##name##_dop_reg_s12 *a) \
    { \
        TCGv_i32 b = arc_insn_load_src_reg(ctx, a->b); \
        TCGv_i32 c = arc_insn_load_imm(a->imm); \
        arc_gen_##name(ctx, b, c); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_CMP_DOP_REG_S12(name) \
    static bool trans_##name##_dop_reg_s12(DisasContext *ctx, arg_##name##_dop_reg_s12 *a) \
    { \
        TCGv_i64 b = arc64_insn_load_src_reg(ctx, a->b); \
        TCGv_i64 c = arc64_insn_load_imm(a->imm); \
        arc64_gen_##name(ctx, b, c); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_CMP_DOP_REG_S12(name) \
    ARC_DEF_TRANS_STUB(name##_dop_reg_s12)
#endif

#define ARC_DEF_TRANS_CMP_DOP_COND_REG(name) \
    static bool trans_##name##_dop_cond_reg(DisasContext *ctx, arg_##name##_dop_cond_reg *a) \
    { \
        TCGv_i32 b = arc_insn_load_src_reg(ctx, a->b); \
        TCGv_i32 c = arc_insn_load_src_reg(ctx, a->c); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, a->cond, skip); \
        arc_gen_##name(ctx, b, c); \
        gen_set_label(skip); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_CMP_DOP_COND_REG(name) \
    static bool trans_##name##_dop_cond_reg(DisasContext *ctx, arg_##name##_dop_cond_reg *a) \
    { \
        TCGv_i64 b = arc64_insn_load_src_reg(ctx, a->b); \
        TCGv_i64 c = arc64_insn_load_src_reg(ctx, a->c); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, a->cond, skip); \
        arc64_gen_##name(ctx, b, c); \
        gen_set_label(skip); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_CMP_DOP_COND_REG(name) \
    ARC_DEF_TRANS_STUB(name##_dop_cond_reg)
#endif

#define ARC_DEF_TRANS_CMP_DOP_COND_U6(name) \
    static bool trans_##name##_dop_cond_u6(DisasContext *ctx, arg_##name##_dop_cond_u6 *a) \
    { \
        TCGv_i32 b = arc_insn_load_src_reg(ctx, a->b); \
        TCGv_i32 c = arc_insn_load_imm(a->imm); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, a->cond, skip); \
        arc_gen_##name(ctx, b, c); \
        gen_set_label(skip); \
        return true; \
    }

#ifdef TARGET_ARCV3_64
#define ARC64_DEF_TRANS_CMP_DOP_COND_U6(name) \
    static bool trans_##name##_dop_cond_u6(DisasContext *ctx, arg_##name##_dop_cond_u6 *a) \
    { \
        TCGv_i64 b = arc64_insn_load_src_reg(ctx, a->b); \
        TCGv_i64 c = arc64_insn_load_imm(a->imm); \
        TCGLabel *skip = gen_new_label(); \
        arc_gen_cc_prologue(ctx, a->cond, skip); \
        arc64_gen_##name(ctx, b, c); \
        gen_set_label(skip); \
        return true; \
    }
#else
#define ARC64_DEF_TRANS_CMP_DOP_COND_U6(name) \
    ARC_DEF_TRANS_STUB(name##_dop_cond_u6)
#endif

#endif

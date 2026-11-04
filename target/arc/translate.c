#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-op-gvec.h"
#include "exec/translator.h"
#include "exec/translation-block.h"
#include "exec/log.h"
#include "translate.h"

static void arc_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    ctx->env = cpu_env(cs);
    ctx->mem_idx = (ctx->base.tb->flags & ARC_TBFLAG_USER_MODE) != 0;
    ctx->unaligned_ldst = (ctx->base.tb->flags & ARC_TBFLAG_UNALIGNED_LDST) != 0;
    ctx->in_delay_slot = (ctx->base.tb->flags & ARC_TBFLAG_DELAY_SLOT) != 0;
    ctx->jump_dest = 0;

#ifdef TARGET_ARCV2
    ctx->zol_enabled = (ctx->base.tb->flags & ARC_TBFLAG_ZOL_ENABLED) != 0;
    ctx->lp_start = ctx->env->aux_lp_start;
    ctx->lp_end = ctx->env->aux_lp_end;
#endif
}

static void arc_tr_tb_start(DisasContextBase *dcbase, CPUState *cs)
{
}

static void arc_tr_insn_start(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    tcg_gen_insn_start(ctx->base.pc_next);
}

static void arc_fetch_insn(DisasContext *ctx)
{
    uint16_t hw0 = translator_lduw(ctx->env, &ctx->base, ctx->pc);
    int major = (hw0 >> 11) & 0x1F;

#ifdef TARGET_ARCV3_64
    if (major <= 0x07 || major == 0x0B) {
#else
    if (major <= 0x07) {
#endif
        /* 32-bit instruction: fetch the second halfword */
        uint16_t hw1 = translator_lduw(ctx->env, &ctx->base, ctx->pc + 2);
        ctx->insn = ((uint32_t)hw0 << 16) | hw1;
        ctx->insn_len = 4;
    } else {
        ctx->insn = hw0;
        ctx->insn_len = 2;
    }
}

static void arc_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    bool decode_status = false;

    /* Any attempt to set Bit 0 of PC to 1 is ignored */
    ctx->pc = arc_align_2_bytes(ctx->base.pc_next);
    ctx->pcl = arc_pc_to_pcl(ctx->pc);
    ctx->has_limm = false;
    ctx->limm = 0;
    arc_fetch_insn(ctx);
    ctx->base.pc_next = ctx->pc + ctx->insn_len;

    /*
     * Keep the encoding that was just fetched. Exception logging reads this
     * instead of guest memory, which would use the post-entry MMU index.
     */
    /* TODO: This may be too slow, save it in exceptions */
    tcg_gen_movi_i32(cpu_excp_insn, ctx->insn);
    tcg_gen_movi_i32(cpu_excp_insn_len, ctx->insn_len);

    switch (ctx->insn_len) {
    case 4:
        decode_status = decode_insn32(ctx, ctx->insn);
        break;
    case 2:
        decode_status = decode_insn16(ctx, ctx->insn);
        break;
    default:
        g_assert_not_reached();
    }

    if (!decode_status) {
        qemu_log_mask(LOG_GUEST_ERROR, "arc: decode: cannot decode an instruction at pc=0x" TARGET_FMT_lx "\n", ctx->pc);
        arc_gen_exception_illegal_instruction(ctx);
        ctx->base.is_jmp = DISAS_NORETURN;
        return;
    }

    if (ctx->in_delay_slot) {
        tcg_gen_movi_i32(cpu_DEf, 0);
        tcg_gen_mov_tl(cpu_pc, cpu_bta);
        ctx->base.is_jmp = DISAS_JUMP_INDIRECT;
    }

#ifdef TARGET_ARCV2
    /* FIXME: Incomplete implementation of ZOL */
    /*
     * This ZOL handler will work only if a non-LP will not change
     * LP_START and LP_END registers inside of a loop. GCC will not generate
     * such code. Also, there is special case when these registers are
     * modified before LP_END and it's not handled too.
     */
    if (ctx->zol_enabled && ctx->lp_end == ctx->base.pc_next) {
        g_assert(!ctx->in_delay_slot);

        TCGLabel *zol_else = gen_new_label();

        tcg_gen_subi_tl(cpu_gpr[ARC_REGNUM_LP_COUNT], cpu_gpr[ARC_REGNUM_LP_COUNT], 1);
        tcg_gen_brcondi_tl(TCG_COND_GTU, cpu_gpr[ARC_REGNUM_LP_COUNT], 0, zol_else);

        tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next);
        tcg_gen_andi_tl(cpu_gpr[ARC_REGNUM_PCL], cpu_pc, ~3);
        tcg_gen_exit_tb(NULL, 0);

        gen_set_label(zol_else);

        tcg_gen_movi_tl(cpu_pc, ctx->lp_start);
        tcg_gen_andi_tl(cpu_gpr[ARC_REGNUM_PCL], cpu_pc, ~3);
        tcg_gen_lookup_and_goto_ptr();

        ctx->base.is_jmp = DISAS_NORETURN;
    }
#endif
}

/*
 * Called after the last instruction in a TB to emit the exit sequence.
 *
 * is_jmp values:
 *   DISAS_NEXT / DISAS_TOO_MANY
 *     -- TB ended by instruction count limit; chain to the fall-through TB.
 *   DISAS_JUMP_COND
 *     -- Taken path has already been emitted; chain the not-taken path to the
 *        fall-through TB.
 *   DISAS_JUMP_DIRECT
 *     -- TB ends with a direct branch; chain to its known target.
 *   DISAS_JUMP_INDIRECT
 *     -- TB ends with an indirect jump; use lookup_and_goto_ptr().
 *   DISAS_UPDATE
 *     -- TB must exit cleanly (FLAG etc.).
 *   DISAS_NORETURN
 *     -- Infinite trap or HALT; no epilogue needed.
 */
static void arc_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    switch (ctx->base.is_jmp) {
    case DISAS_NEXT:
    case DISAS_TOO_MANY:
    case DISAS_JUMP_COND:
        arc_gen_goto_tb(ctx, 0, ctx->base.pc_next);
        break;
    case DISAS_UPDATE:
        arc_gen_set_pc(ctx, ctx->base.pc_next);
        tcg_gen_exit_tb(NULL, 0);
        break;
    case DISAS_JUMP_DIRECT:
        arc_gen_goto_tb(ctx, 0, ctx->jump_dest);
        break;
    case DISAS_JUMP_INDIRECT:
        /*
         * Indirect jump instruction already set correct cpu_pc.
         * Just update PCL.
         */
        tcg_gen_andi_tl(cpu_gpr[ARC_REGNUM_PCL], cpu_pc, ~3);
        tcg_gen_lookup_and_goto_ptr();
        break;
    case DISAS_NORETURN:
        break;
    default:
        g_assert_not_reached();
    }
}

static const TranslatorOps arc_tr_ops = {
    .init_disas_context = arc_tr_init_disas_context,
    .tb_start           = arc_tr_tb_start,
    .insn_start         = arc_tr_insn_start,
    .translate_insn     = arc_tr_translate_insn,
    .tb_stop            = arc_tr_tb_stop,
};

void arc_translate_code(CPUState *cs, TranslationBlock *tb,
                        int *max_insns, vaddr pc, void *host_pc)
{
    DisasContext dc;
    translator_loop(cs, tb, max_insns, pc, host_pc, &arc_tr_ops, &dc.base);
}

void arc_translate_init(void)
{
    static const char *const regnames[ARC_REGNUM_END] = {
        "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
        "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
        "r24", "r25", "gp",  "fp",  "sp",  "ilink","r30", "blink",
        "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",
        "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",
        "r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",
        "r56", "r57", "r58", "r59", "lp_count", "r61", "limm", "pcl",
    };

    for (int i = 0; i < ARC_REGNUM_END; i++) {
        cpu_gpr[i] = tcg_global_mem_new(tcg_env, offsetof(CPUARCState, gpr[i]), regnames[i]);
    }

    cpu_pc = tcg_global_mem_new(tcg_env, offsetof(CPUARCState, pc), "pc");
    cpu_DEf = tcg_global_mem_new_i32(tcg_env, offsetof(CPUARCState, aux_status32.delay_slot_pending), "DEf");
    cpu_Zf = tcg_global_mem_new_i32(tcg_env, offsetof(CPUARCState, aux_status32.zero_flag), "Zf");
    cpu_Nf = tcg_global_mem_new_i32(tcg_env, offsetof(CPUARCState, aux_status32.negative_flag), "Nf");
    cpu_Cf = tcg_global_mem_new_i32(tcg_env, offsetof(CPUARCState, aux_status32.carry_flag), "Cf");
    cpu_Vf = tcg_global_mem_new_i32(tcg_env, offsetof(CPUARCState, aux_status32.overflow_flag), "Vf");
    cpu_DZf = tcg_global_mem_new_i32(tcg_env, offsetof(CPUARCState, aux_status32.enable_divzero_excp), "DZf");
    cpu_bta = tcg_global_mem_new(tcg_env, offsetof(CPUARCState, aux_bta), "bta");
    cpu_eret = tcg_global_mem_new(tcg_env, offsetof(CPUARCState, aux_eret), "eret");
    cpu_semihost_eret = tcg_global_mem_new(tcg_env, offsetof(CPUARCState, excp_semihost_eret), "semihost_eret");
    cpu_excp_insn = tcg_global_mem_new_i32(tcg_env, offsetof(CPUARCState, excp_insn), "excp_insn");
    cpu_excp_insn_len = tcg_global_mem_new_i32(tcg_env, offsetof(CPUARCState, excp_insn_len), "excp_insn_len");

#ifdef TARGET_ARCV2
    cpu_Lf = tcg_global_mem_new(tcg_env, offsetof(CPUARCState, aux_status32.disable_zol), "Lf");
    cpu_lp_start = tcg_global_mem_new(tcg_env, offsetof(CPUARCState, aux_lp_start), "lp_start");
    cpu_lp_end = tcg_global_mem_new(tcg_env, offsetof(CPUARCState, aux_lp_end), "lp_end");
#endif
}

/*
 * Z: result is zero
 * N: 1 only if source == 0x8000_0000; else 0
 * C: src[31]
 * V: 1 only if source == 0x8000_0000; else 0
 */
static inline void arc_gen_abs(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, bool set_flags)
{
    tcg_gen_abs_i32(a, b);

    if (set_flags) {
        arc_gen_set_flag_Z(a);
        tcg_gen_setcondi_i32(TCG_COND_EQ, cpu_Nf, b, 0x80000000);
        tcg_gen_shri_i32(cpu_Cf, b, TARGET_LONG_BITS_32 - 1);
        tcg_gen_setcondi_i32(TCG_COND_EQ, cpu_Vf, b, 0x80000000);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(abs)
ARC_DEF_TRANS_SOP_REG_U6(abs)
ARC_DEF_TRANS_S_DOP_2_OPERANDS(abs)

static inline void arc64_gen_absl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, bool set_flags)
{
    TCGv_i64 tmp = tcg_temp_new_i64();

    tcg_gen_abs_i64(a, b);

    if (set_flags) {
        arc64_gen_set_flag_Z(a);

        tcg_gen_setcondi_i64(TCG_COND_EQ, tmp, b, 0x8000000000000000LL);
        tcg_gen_extrl_i64_i32(cpu_Nf, tmp);

        tcg_gen_shri_i64(tmp, b, TARGET_LONG_BITS_64 - 1);
        tcg_gen_extrl_i64_i32(cpu_Cf, tmp);

        tcg_gen_setcondi_i64(TCG_COND_EQ, tmp, b, 0x8000000000000000LL);
        tcg_gen_extrl_i64_i32(cpu_Vf, tmp);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(absl)
ARC64_DEF_TRANS_SOP_REG_U6(absl)

static inline void arc_gen_and(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_and_i32(a, b, c);

    if (set_flags) {
        arc_gen_set_flag_Z(a);
        arc_gen_set_flag_N(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(and)
ARC_DEF_TRANS_DOP_REG_U6(and)
ARC_DEF_TRANS_DOP_REG_S12(and)
ARC_DEF_TRANS_DOP_COND_REG(and)
ARC_DEF_TRANS_DOP_COND_U6(and)
ARC_DEF_TRANS_S_DOP_3_OPERANDS(and)

static inline void arc64_gen_andl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_and_i64(a, b, c);

    if (set_flags) {
        arc64_gen_set_flag_Z(a);
        arc64_gen_set_flag_N(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(andl)
ARC64_DEF_TRANS_DOP_REG_U6(andl)
ARC64_DEF_TRANS_DOP_REG_S12(andl)
ARC64_DEF_TRANS_DOP_COND_REG(andl)
ARC64_DEF_TRANS_DOP_COND_U6(andl)
ARC64_DEF_TRANS_S_DOP_3_OPERANDS(andl)

/*
 * if (cc) then a = (b & ~(1<< c));
 *
 * if cc==true then
 *   dest = src1 AND NOT(1 << (src2 & 31))
 *   if F==1 then
 *     Z_flag = if dest==0 then 1 else 0
 *     N_flag = dest[31]
 */
static inline void arc_gen_bclr(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    TCGv_i32 one = tcg_constant_i32(1);

    tcg_gen_andi_i32(a, c, 0x1F);
    tcg_gen_shl_i32(a, one, a);
    tcg_gen_not_i32(a, a);
    tcg_gen_and_i32(a, b, a);

    if (set_flags) {
        arc_gen_set_flag_Z(a);
        arc_gen_set_flag_N(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(bclr)
ARC_DEF_TRANS_DOP_REG_U6(bclr)
ARC_DEF_TRANS_DOP_REG_S12(bclr)
ARC_DEF_TRANS_DOP_COND_REG(bclr)
ARC_DEF_TRANS_DOP_COND_U6(bclr)
ARC_DEF_TRANS_S_SH_SUB_BIT(bclr)

static inline void arc64_gen_bclrl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    TCGv_i64 one = tcg_constant_i64(1);

    tcg_gen_andi_i64(a, c, 0x3F);
    tcg_gen_shl_i64(a, one, a);
    tcg_gen_not_i64(a, a);
    tcg_gen_and_i64(a, b, a);

    if (set_flags) {
        arc64_gen_set_flag_Z(a);
        arc64_gen_set_flag_N(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(bclrl)
ARC64_DEF_TRANS_DOP_REG_U6(bclrl)
ARC64_DEF_TRANS_DOP_REG_S12(bclrl)
ARC64_DEF_TRANS_DOP_COND_REG(bclrl)
ARC64_DEF_TRANS_DOP_COND_U6(bclrl)

static inline void arc_gen_bic(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_not_i32(a, c);
    tcg_gen_and_i32(a, b, a);

    if (set_flags) {
        arc_gen_set_flag_Z(a);
        arc_gen_set_flag_N(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(bic)
ARC_DEF_TRANS_DOP_REG_U6(bic)
ARC_DEF_TRANS_DOP_REG_S12(bic)
ARC_DEF_TRANS_DOP_COND_REG(bic)
ARC_DEF_TRANS_DOP_COND_U6(bic)
ARC_DEF_TRANS_S_DOP_3_OPERANDS(bic)

static inline void arc64_gen_bicl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_not_i64(a, c);
    tcg_gen_and_i64(a, b, a);

    if (set_flags) {
        arc64_gen_set_flag_Z(a);
        arc64_gen_set_flag_N(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(bicl)
ARC64_DEF_TRANS_DOP_REG_U6(bicl)
ARC64_DEF_TRANS_DOP_REG_S12(bicl)
ARC64_DEF_TRANS_DOP_COND_REG(bicl)
ARC64_DEF_TRANS_DOP_COND_U6(bicl)

/*
 * if (cc) then a = (b & ((1 << (c + 1)) - 1)
 *
 * if cc==true then
 *     dest = src1 AND ((1 << ((src2 & 31) + 1)) - 1)
 *     if F==1 then
 *         Z_flag = if dest==0 then 1 else 0
 *         N_flag = dest[31]
 */
static inline void arc_gen_bmsk(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    TCGv_i32 mask = tcg_temp_new_i32();
    TCGv_i32 full_mask = tcg_constant_i32(-1);

    /*
     * If c == 31, then according to the formula BMSK performs 1 << 32 shift
     * which is undefined behavior in TCG. Thus, it must be rewritten to
     * eliminate this issue:
     *
     *     dest = src1 & (0xFFFFFFFF >> (31 - src2 & 31))
     */
    tcg_gen_andi_i32(mask, c, 0x1F);        /* src2 & 31 */
    tcg_gen_subfi_i32(mask, 0x1F, mask);    /* 31 - (src2 & 31) */
    tcg_gen_shr_i32(mask, full_mask, mask); /* 0xFFFFFFFF >> ... */
    tcg_gen_and_i32(a, b, mask);            /* dest = src1 AND mask */

    if (set_flags) {
        arc_gen_set_flag_Z(a);
        arc_gen_set_flag_N(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(bmsk)
ARC_DEF_TRANS_DOP_REG_U6(bmsk)
ARC_DEF_TRANS_DOP_REG_S12(bmsk)
ARC_DEF_TRANS_DOP_COND_REG(bmsk)
ARC_DEF_TRANS_DOP_COND_U6(bmsk)
ARC_DEF_TRANS_S_SH_SUB_BIT(bmsk)

static inline void arc64_gen_bmskl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    TCGv_i64 mask = tcg_temp_new_i64();
    TCGv_i64 full_mask = tcg_constant_i64(-1);

    /*
     * If c == 63, then according to the formula BMSK performs 1 << 64 shift
     * which is undefined behavior in TCG. Thus, it must be rewritten to
     * eliminate this issue:
     *
     *     dest = src1 & (0xFFFFFFFF_FFFFFFFF >> (31 - src2 & 63))
     */
    tcg_gen_andi_i64(mask, c, 0x3F);        /* src2 & 63 */
    tcg_gen_subfi_i64(mask, 0x3F, mask);      /* 63 - (src2 & 63) */
    tcg_gen_shr_i64(mask, full_mask, mask); /* 0xFFFFFFFF_FFFFFFFF >> ... */
    tcg_gen_and_i64(a, b, mask);            /* dest = src1 AND mask */

    if (set_flags) {
        arc64_gen_set_flag_Z(a);
        arc64_gen_set_flag_N(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(bmskl)
ARC64_DEF_TRANS_DOP_REG_U6(bmskl)
ARC64_DEF_TRANS_DOP_REG_S12(bmskl)
ARC64_DEF_TRANS_DOP_COND_REG(bmskl)
ARC64_DEF_TRANS_DOP_COND_U6(bmskl)

/*
 * if (cc) then a = b & ~((1 << (c + 1)) - 1)
 *
 * if cc==true then
 *     dest = src1 AND ~((1 << ((src2 & 31) + 1)) - 1)
 *     if F==1 then
 *         Z_flag = if dest==0 then 1 else 0
 *         N_flag = dest[31]
 */
static inline void arc_gen_bmskn(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    TCGv_i32 mask = tcg_temp_new_i32();
    TCGv_i32 full_mask = tcg_constant_i32(-1);

    tcg_gen_andi_i32(mask, c, 0x1F);        /* src2 & 31 */
    tcg_gen_subfi_i32(mask, 0x1F, mask);    /* 31 - (src2 & 31) */
    tcg_gen_shr_i32(mask, full_mask, mask); /* 0xFFFFFFFF >> ... */
    tcg_gen_not_i32(mask, mask);            /* mask = ~mask */
    tcg_gen_and_i32(a, b, mask);            /* dest = src1 AND mask */

    if (set_flags) {
        arc_gen_set_flag_Z(a);
        arc_gen_set_flag_N(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(bmskn)
ARC_DEF_TRANS_DOP_REG_U6(bmskn)
ARC_DEF_TRANS_DOP_REG_S12(bmskn)
ARC_DEF_TRANS_DOP_COND_REG(bmskn)
ARC_DEF_TRANS_DOP_COND_U6(bmskn)

static inline void arc64_gen_bmsknl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    TCGv_i64 mask = tcg_temp_new_i64();
    TCGv_i64 full_mask = tcg_constant_i64(-1);

    tcg_gen_andi_i64(mask, c, 0x3F);        /* src2 & 63 */
    tcg_gen_subfi_i64(mask, 0x3F, mask);    /* 63 - (src2 & 63) */
    tcg_gen_shr_i64(mask, full_mask, mask); /* 0xFFFFFFFF_FFFFFFFF >> ... */
    tcg_gen_not_i64(mask, mask);            /* mask = ~mask */
    tcg_gen_and_i64(a, b, mask);            /* dest = src1 AND mask */

    if (set_flags) {
        arc64_gen_set_flag_Z(a);
        arc64_gen_set_flag_N(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(bmsknl)
ARC64_DEF_TRANS_DOP_REG_U6(bmsknl)
ARC64_DEF_TRANS_DOP_REG_S12(bmsknl)
ARC64_DEF_TRANS_DOP_COND_REG(bmsknl)
ARC64_DEF_TRANS_DOP_COND_U6(bmsknl)

static bool trans_brk(DisasContext *ctx, arg_brk *a)
{
    gen_helper_brk(tcg_env);

    ctx->base.is_jmp = DISAS_UPDATE;

    return true;
}

static bool trans_brk_s(DisasContext *ctx, arg_brk_s *a)
{
    gen_helper_brk(tcg_env);

    ctx->base.is_jmp = DISAS_UPDATE;

    return true;
}

/*
 * if (cc) a = (b | (1<<c))
 *
 * if cc==true then
 *   dest = src1 OR (1 << (src2 & 31))
 *   if F==1 then
 *     Z_flag = 0
 *     N_flag = dest[31]
 */
static inline void arc_gen_bset(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_andi_i32(a, c, 0x1F);
    tcg_gen_shl_i32(a, tcg_constant_i32(1), a);
    tcg_gen_or_i32(a, b, a);

    if (set_flags) {
        arc_gen_set_flag_Z_clear();
        arc_gen_set_flag_N(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(bset)
ARC_DEF_TRANS_DOP_REG_U6(bset)
ARC_DEF_TRANS_DOP_REG_S12(bset)
ARC_DEF_TRANS_DOP_COND_REG(bset)
ARC_DEF_TRANS_DOP_COND_U6(bset)
ARC_DEF_TRANS_S_SH_SUB_BIT(bset)

static inline void arc64_gen_bsetl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_andi_i64(a, c, 0x3F);
    tcg_gen_shl_i64(a, tcg_constant_i64(1), a);
    tcg_gen_or_i64(a, b, a);

    if (set_flags) {
        arc_gen_set_flag_Z_clear();
        arc64_gen_set_flag_N(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(bsetl)
ARC64_DEF_TRANS_DOP_REG_U6(bsetl)
ARC64_DEF_TRANS_DOP_REG_S12(bsetl)
ARC64_DEF_TRANS_DOP_COND_REG(bsetl)
ARC64_DEF_TRANS_DOP_COND_U6(bsetl)

/*
 * if (cc) (b & (1 << c))
 *
 * if cc==true then
 *     alu = src1 AND (1 << (src2 & 31))
 *     Z_flag = if alu==0 then 1 else 0
 *     N_flag = alu[31]
 */
static inline void arc_gen_btst(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c)
{
    TCGv_i32 alu = tcg_temp_new_i32();

    tcg_gen_andi_i32(alu, c, 0x1F); /* src2 & 31 */
    tcg_gen_shl_i32(alu, tcg_constant_i32(1), alu); /* 1 << (src2 & 31) */
    tcg_gen_and_i32(alu, b, alu); /* src1 AND (1 << (src2 & 31)) */

    arc_gen_set_flag_Z(alu);
    arc_gen_set_flag_N(alu);
}

ARC_DEF_TRANS_CMP_DOP_REG_REG(btst)
ARC_DEF_TRANS_CMP_DOP_REG_U6(btst)
ARC_DEF_TRANS_CMP_DOP_REG_S12(btst)
ARC_DEF_TRANS_CMP_DOP_COND_REG(btst)
ARC_DEF_TRANS_CMP_DOP_COND_U6(btst)

static bool trans_btst_s(DisasContext *ctx, arg_btst_s *a)
{
    TCGv_i32 b = arc_insn_load_src_reg_s(ctx, a->b);
    TCGv_i32 c = arc_insn_load_imm(a->imm);

    arc_gen_btst(ctx, b, c);

    return true;
}

static inline void arc64_gen_btstl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c)
{
    TCGv_i64 alu = tcg_temp_new_i64();

    tcg_gen_andi_i64(alu, c, 0x3F); /* src2 & 63 */
    tcg_gen_shl_i64(alu, tcg_constant_i64(1), alu); /* 1 << (src2 & 63) */
    tcg_gen_and_i64(alu, b, alu); /* src1 AND (1 << (src2 & 63)) */

    arc64_gen_set_flag_Z(alu);
    arc64_gen_set_flag_N(alu);
}

ARC64_DEF_TRANS_CMP_DOP_REG_REG(btstl)
ARC64_DEF_TRANS_CMP_DOP_REG_U6(btstl)
ARC64_DEF_TRANS_CMP_DOP_REG_S12(btstl)
ARC64_DEF_TRANS_CMP_DOP_COND_REG(btstl)
ARC64_DEF_TRANS_CMP_DOP_COND_U6(btstl)

/*
 * if (cc) a = (b ^ (1 << c))
 *
 * if cc==true then
 *   dest = src1 XOR (1 << (src2 & 31))
 *   if F==1 then
 *     Z_flag = if dest==0 then 1 else 0
 *     N_flag = dest[31]
 */
static inline void arc_gen_bxor(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_andi_i32(a, c, 0x1F);
    tcg_gen_shl_i32(a, tcg_constant_i32(1), a);
    tcg_gen_xor_i32(a, b, a);

    if (set_flags) {
        arc_gen_set_flag_Z(a);
        arc_gen_set_flag_N(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(bxor)
ARC_DEF_TRANS_DOP_REG_U6(bxor)
ARC_DEF_TRANS_DOP_REG_S12(bxor)
ARC_DEF_TRANS_DOP_COND_REG(bxor)
ARC_DEF_TRANS_DOP_COND_U6(bxor)

static inline void arc64_gen_bxorl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_andi_i64(a, c, 0x3F);
    tcg_gen_shl_i64(a, tcg_constant_i64(1), a);
    tcg_gen_xor_i64(a, b, a);

    if (set_flags) {
        arc64_gen_set_flag_Z(a);
        arc64_gen_set_flag_N(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(bxorl)
ARC64_DEF_TRANS_DOP_REG_U6(bxorl)
ARC64_DEF_TRANS_DOP_REG_S12(bxorl)
ARC64_DEF_TRANS_DOP_COND_REG(bxorl)
ARC64_DEF_TRANS_DOP_COND_U6(bxorl)

static bool trans_clri_reg(DisasContext *ctx, arg_clri_reg *a)
{
    TCGv_i32 reg = arc_insn_load_dst_reg(ctx, a->c);

    if (ctx->has_limm) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    gen_helper_clri(reg, tcg_env);
    arc_insn_save_reg(ctx, a->c, reg);

    ctx->base.is_jmp = DISAS_UPDATE;

    return true;
}

static bool trans_clri_imm(DisasContext *ctx, arg_clri_imm *a)
{
    gen_helper_clri(tcg_temp_new_i32(), tcg_env);

    ctx->base.is_jmp = DISAS_UPDATE;

    return true;
}

static inline void arc_gen_cmp(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c)
{
    TCGv_i32 diff = tcg_temp_new_i32();

    tcg_gen_sub_i32(diff, b, c);

    arc_gen_set_flag_ZNCV_sub(diff, b, c);
}

ARC_DEF_TRANS_CMP_DOP_REG_REG(cmp)
ARC_DEF_TRANS_CMP_DOP_REG_U6(cmp)
ARC_DEF_TRANS_CMP_DOP_REG_S12(cmp)
ARC_DEF_TRANS_CMP_DOP_COND_REG(cmp)
ARC_DEF_TRANS_CMP_DOP_COND_U6(cmp)

/* cmp_s b,h */
static bool trans_cmp_s_b_h(DisasContext *ctx, arg_cmp_s_b_h *a)
{
    TCGv_i32 b = arc_insn_load_src_reg_s(ctx, a->b);
    TCGv_i32 c = arc_insn_load_src_reg_h(ctx, a->h);

    arc_gen_cmp(ctx, b, c);

    return true;
}

/* cmp_s h,s3 */
static bool trans_cmp_s_h_s3(DisasContext *ctx, arg_cmp_s_h_s3 *a)
{
    TCGv_i32 b = arc_insn_load_src_reg_h(ctx, a->h);
    TCGv_i32 c = arc_insn_load_imm(a->imm);

    arc_gen_cmp(ctx, b, c);

    return true;
}


/* cmp_s b,u7 */
#ifdef TARGET_ARCV2
static bool trans_cmp_s_b_u7(DisasContext *ctx, arg_cmp_s_b_u7 *a)
{
    TCGv_i32 b = arc_insn_load_src_reg_s(ctx, a->b);
    TCGv_i32 c = arc_insn_load_imm(a->imm);

    arc_gen_cmp(ctx, b, c);

    return true;
}
#else
ARC_DEF_TRANS_STUB(cmp_s_b_u7)
#endif

static inline void arc64_gen_cmpl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c)
{
    TCGv_i64 diff = tcg_temp_new_i64();

    tcg_gen_sub_i64(diff, b, c);

    arc64_gen_set_flag_ZNCV_sub(diff, b, c);
}

ARC64_DEF_TRANS_CMP_DOP_REG_REG(cmpl)
ARC64_DEF_TRANS_CMP_DOP_REG_U6(cmpl)
ARC64_DEF_TRANS_CMP_DOP_REG_S12(cmpl)
ARC64_DEF_TRANS_CMP_DOP_COND_REG(cmpl)
ARC64_DEF_TRANS_CMP_DOP_COND_U6(cmpl)

static bool trans_dmb(DisasContext *ctx, arg_dmb *a)
{
    TCGBar bar = 0;

    switch(a->imm) {
    case 1:
        bar |= TCG_BAR_SC | TCG_MO_LD_LD | TCG_MO_LD_ST;
        break;
    case 2:
        bar |= TCG_BAR_SC | TCG_MO_ST_ST;
        break;
    default:
        bar |= TCG_BAR_SC | TCG_MO_ALL;
        break;
    }

    tcg_gen_mb(bar);

    ctx->base.is_jmp = DISAS_UPDATE;

    return true;
}

static bool trans_dsync(DisasContext *ctx, arg_dsync *a)
{
    /* Generate all memory operations barrier */
    tcg_gen_mb(TCG_MO_ALL);

    ctx->base.is_jmp = DISAS_UPDATE;

    return true;
}

/*
 * b = c & 0x000000FF
 *
 * dest = src & 0xFF
 * if F==1 then
 *     Z_flag = if dest==0 then 1 else 0
 *     N_flag = dest[31]
 */
static inline void arc_gen_extb(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_andi_i32(b, c, 0xFF);

    if (set_flags) {
        arc_gen_set_flag_Z(b);
        arc_gen_set_flag_N_clear();
    }
}

ARC_DEF_TRANS_SOP_REG_REG(extb)
ARC_DEF_TRANS_SOP_REG_U6(extb)
ARC_DEF_TRANS_S_DOP_2_OPERANDS(extb)

/*
 * b = c & 0x0000FFFF
 *
 * dest = src & 0xFFFF
 * if F==1 then
 *     Z_flag = if dest==0 then 1 else 0
 *     N_flag = dest[31]
 */
static inline void arc_gen_exth(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_andi_i32(b, c, 0xFFFF);

    if (set_flags) {
        arc_gen_set_flag_Z(b);
        arc_gen_set_flag_N_clear();
    }
}

ARC_DEF_TRANS_SOP_REG_REG(exth)
ARC_DEF_TRANS_SOP_REG_U6(exth)
ARC_DEF_TRANS_S_DOP_2_OPERANDS(exth)

static inline void arc_gen_ffs(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_ctzi_i32(b, c, TARGET_LONG_BITS_32 - 1);

    if (set_flags) {
        arc_gen_set_flag_Z(c);
        arc_gen_set_flag_N(c);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(ffs)
ARC_DEF_TRANS_SOP_REG_U6(ffs)

static inline void arc64_gen_ffsl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_ctzi_i64(b, c, TARGET_LONG_BITS_64 - 1);

    if (set_flags) {
        arc64_gen_set_flag_Z(c);
        arc64_gen_set_flag_N(c);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(ffsl)
ARC64_DEF_TRANS_SOP_REG_U6(ffsl)

static void arc_gen_flag(DisasContext *ctx, TCGv_i32 bits)
{
    gen_helper_flag(tcg_env, bits);

    ctx->base.is_jmp = DISAS_UPDATE;
}

ARC_DEF_TRANS_FLAG_DOP_REG_REG(flag)
ARC_DEF_TRANS_FLAG_DOP_REG_U6(flag)
ARC_DEF_TRANS_FLAG_DOP_REG_S12(flag)
ARC_DEF_TRANS_FLAG_DOP_REG_REG_COND(flag)
ARC_DEF_TRANS_FLAG_DOP_REG_U6_COND(flag)

static void arc_gen_fls(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_clzi_i32(b, c, TARGET_LONG_BITS_32 - 1);
    tcg_gen_subfi_i32(b, TARGET_LONG_BITS_32 - 1, b);

    if (set_flags) {
        arc_gen_set_flag_Z(c);
        arc_gen_set_flag_N(c);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(fls)
ARC_DEF_TRANS_SOP_REG_U6(fls)

static inline void arc64_gen_flsl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_clzi_i64(b, c, TARGET_LONG_BITS_64 - 1);
    tcg_gen_subfi_i64(b, TARGET_LONG_BITS_64 - 1, b);

    if (set_flags) {
        arc64_gen_set_flag_Z(c);
        arc64_gen_set_flag_N(c);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(flsl)
ARC64_DEF_TRANS_SOP_REG_U6(flsl)

static inline void arc_gen_kflag(DisasContext *ctx, TCGv_i32 bits)
{
    gen_helper_kflag(tcg_env, bits);

    ctx->base.is_jmp = DISAS_UPDATE;
}

ARC_DEF_TRANS_FLAG_DOP_REG_REG(kflag)
ARC_DEF_TRANS_FLAG_DOP_REG_U6(kflag)
ARC_DEF_TRANS_FLAG_DOP_REG_S12(kflag)
ARC_DEF_TRANS_FLAG_DOP_REG_REG_COND(kflag)
ARC_DEF_TRANS_FLAG_DOP_REG_U6_COND(kflag)

static inline void arc_gen_max(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    TCGv_i32 tmp = tcg_temp_new_i32();

    tcg_gen_smax_i32(a, b, c);

    if (set_flags) {
        tcg_gen_sub_i32(tmp, b, c);
        arc_gen_set_flag_ZNCV_sub(tmp, b, c);
        tcg_gen_setcond_i32(TCG_COND_GE, cpu_Cf, c, b);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(max)
ARC_DEF_TRANS_DOP_REG_U6(max)
ARC_DEF_TRANS_DOP_REG_S12(max)
ARC_DEF_TRANS_DOP_COND_REG(max)
ARC_DEF_TRANS_DOP_COND_U6(max)

static inline void arc64_gen_maxl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    TCGv_i64 tmp = tcg_temp_new_i64();

    tcg_gen_smax_i64(a, b, c);

    if (set_flags) {
        tcg_gen_sub_i64(tmp, b, c);
        arc64_gen_set_flag_ZNCV_sub(tmp, b, c);
        tcg_gen_setcond_i64(TCG_COND_GE, tmp, c, b);
        tcg_gen_extrl_i64_i32(cpu_Cf, tmp);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(maxl)
ARC64_DEF_TRANS_DOP_REG_U6(maxl)
ARC64_DEF_TRANS_DOP_REG_S12(maxl)
ARC64_DEF_TRANS_DOP_COND_REG(maxl)
ARC64_DEF_TRANS_DOP_COND_U6(maxl)

static inline void arc_gen_min(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    TCGv_i32 tmp = tcg_temp_new_i32();

    tcg_gen_smin_i32(a, b, c);

    if (set_flags) {
        tcg_gen_sub_i32(tmp, b, c);
        arc_gen_set_flag_ZNCV_sub(tmp, b, c);
        tcg_gen_setcond_i32(TCG_COND_LE, cpu_Cf, c, b);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(min)
ARC_DEF_TRANS_DOP_REG_U6(min)
ARC_DEF_TRANS_DOP_REG_S12(min)
ARC_DEF_TRANS_DOP_COND_REG(min)
ARC_DEF_TRANS_DOP_COND_U6(min)

static inline void arc64_gen_minl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    TCGv_i64 tmp = tcg_temp_new_i64();

    tcg_gen_smin_i64(a, b, c);

    if (set_flags) {
        tcg_gen_sub_i64(tmp, b, c);
        arc64_gen_set_flag_ZNCV_sub(tmp, b, c);
        tcg_gen_setcond_i64(TCG_COND_LE, tmp, c, b);
        tcg_gen_extrl_i64_i32(cpu_Cf, tmp);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(minl)
ARC64_DEF_TRANS_DOP_REG_U6(minl)
ARC64_DEF_TRANS_DOP_REG_S12(minl)
ARC64_DEF_TRANS_DOP_COND_REG(minl)
ARC64_DEF_TRANS_DOP_COND_U6(minl)

static bool trans_nop_s(DisasContext *ctx, arg_nop_s *a)
{
    return true;
}

static inline void arc_gen_norm(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_clrsb_i32(b, c);

    if (set_flags) {
        arc_gen_set_flag_Z(c);
        arc_gen_set_flag_N(c);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(norm)
ARC_DEF_TRANS_SOP_REG_U6(norm)

static inline void arc_gen_normh(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_andi_i32(c, c, 0xFFFF);
    tcg_gen_ext16s_i32(b, c);
    tcg_gen_clrsb_i32(b, b);
    tcg_gen_subi_i32(b, b, 16);

    if (set_flags) {
        arc_gen_set_flag_Z(c);
        tcg_gen_shri_i32(cpu_Nf, c, 15);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(normh)
ARC_DEF_TRANS_SOP_REG_U6(normh)

static inline void arc64_gen_norml(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_clrsb_i64(b, c);

    if (set_flags) {
        arc64_gen_set_flag_Z(c);
        arc64_gen_set_flag_N(c);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(norml)
ARC64_DEF_TRANS_SOP_REG_U6(norml)

static inline void arc_gen_not(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_not_i32(b, c);

    if (set_flags) {
        arc_gen_set_flag_Z(b);
        arc_gen_set_flag_N(b);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(not)
ARC_DEF_TRANS_SOP_REG_U6(not)
ARC_DEF_TRANS_S_DOP_2_OPERANDS(not)

static inline void arc64_gen_notl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_not_i64(b, c);

    if (set_flags) {
        arc64_gen_set_flag_Z(b);
        arc64_gen_set_flag_N(b);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(notl)
ARC64_DEF_TRANS_SOP_REG_U6(notl)

static inline void arc_gen_or(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_or_i32(a, b, c);

    if (set_flags) {
        arc_gen_set_flag_Z(a);
        arc_gen_set_flag_N(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(or)
ARC_DEF_TRANS_DOP_REG_U6(or)
ARC_DEF_TRANS_DOP_REG_S12(or)
ARC_DEF_TRANS_DOP_COND_REG(or)
ARC_DEF_TRANS_DOP_COND_U6(or)
ARC_DEF_TRANS_S_DOP_3_OPERANDS(or)

static inline void arc64_gen_orl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_or_i64(a, b, c);

    if (set_flags) {
        arc64_gen_set_flag_Z(a);
        arc64_gen_set_flag_N(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(orl)
ARC64_DEF_TRANS_DOP_REG_U6(orl)
ARC64_DEF_TRANS_DOP_REG_S12(orl)
ARC64_DEF_TRANS_DOP_COND_REG(orl)
ARC64_DEF_TRANS_DOP_COND_U6(orl)
ARC64_DEF_TRANS_RS64_RS64_RS64_F(orl, orl_s_b_b_c, a->b, a->b, a->c, false);

#ifdef TARGET_ARCV3_64
static bool trans_orl_s_h_h_limm(DisasContext *ctx, arg_orl_s_h_h_limm *a)
{
    TCGv_i64 reg_r0 = arc64_insn_load_dst_reg_h(ctx, a->h);
    TCGv_i64 reg_r1 = arc64_insn_load_src_reg_h(ctx, a->h);
    TCGv_i64 reg_r2 = arc64_insn_load_limm_signed(ctx);
    arc64_gen_orl(ctx, reg_r0, reg_r1, reg_r2, false);
    arc64_insn_save_reg_h(ctx, a->h, reg_r0);
    return true;
}
#else
ARC_DEF_TRANS_STUB(orl_s_h_h_limm)
#endif

#ifdef TARGET_ARCV3_64
static bool trans_orl_s_h_pcl_limm(DisasContext *ctx, arg_orl_s_h_pcl_limm *a)
{
    TCGv_i64 reg_r0 = arc64_insn_load_dst_reg_h(ctx, a->h);
    TCGv_i64 reg_r1 = arc64_insn_load_pcl(ctx);
    TCGv_i64 reg_r2 = arc64_insn_load_limm_signed(ctx);
    arc64_gen_orl(ctx, reg_r0, reg_r1, reg_r2, false);
    arc64_insn_save_reg_h(ctx, a->h, reg_r0);
    return true;
}
#else
ARC_DEF_TRANS_STUB(orl_s_h_pcl_limm)
#endif

/* PREALLOC<.aa> [b,s9] */
static bool trans_prealloc_offset(DisasContext *ctx, arg_prealloc_offset *a)
{
    /* Do nothing */

    return true;
}

/* PREALLOC<.aa> [b,c] */
static bool trans_prealloc_reg(DisasContext *ctx, arg_prealloc_reg *a)
{
    /* Do nothing */

    return true;
}

static void arc_gen_rcmp(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c)
{
    arc_gen_cmp(ctx, c, b);
}

ARC_DEF_TRANS_CMP_DOP_REG_REG(rcmp)
ARC_DEF_TRANS_CMP_DOP_REG_U6(rcmp)
ARC_DEF_TRANS_CMP_DOP_REG_S12(rcmp)
ARC_DEF_TRANS_CMP_DOP_COND_REG(rcmp)
ARC_DEF_TRANS_CMP_DOP_COND_U6(rcmp)

static inline void arc64_gen_rcmpl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c)
{
    arc64_gen_cmpl(ctx, c, b);
}

ARC64_DEF_TRANS_CMP_DOP_REG_REG(rcmpl)
ARC64_DEF_TRANS_CMP_DOP_REG_U6(rcmpl)
ARC64_DEF_TRANS_CMP_DOP_REG_S12(rcmpl)
ARC64_DEF_TRANS_CMP_DOP_COND_REG(rcmpl)
ARC64_DEF_TRANS_CMP_DOP_COND_U6(rcmpl)

static bool trans_rtie(DisasContext *ctx, arg_rtie *a)
{
    arc_gen_check_not_delay_slot(ctx);

    gen_helper_rtie(tcg_env);

    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_seti_reg(DisasContext *ctx, arg_seti_reg *a)
{
    gen_helper_seti(tcg_env, arc_insn_load_src_reg(ctx, a->c));

    ctx->base.is_jmp = DISAS_UPDATE;

    return true;
}

static bool trans_seti_imm(DisasContext *ctx, arg_seti_imm *a)
{
    gen_helper_seti(tcg_env, tcg_constant_i32(a->imm));

    ctx->base.is_jmp = DISAS_UPDATE;

    return true;
}

static inline void arc_gen_sexb(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_ext8s_i32(b, c);

    if (set_flags) {
        arc_gen_set_flag_Z(b);
        arc_gen_set_flag_N(b);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(sexb)
ARC_DEF_TRANS_SOP_REG_U6(sexb)
ARC_DEF_TRANS_S_DOP_2_OPERANDS(sexb)

static inline void arc64_gen_sexbl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_ext8s_i64(b, c);

    if (set_flags) {
        arc64_gen_set_flag_Z(b);
        arc64_gen_set_flag_N(b);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(sexbl)
ARC64_DEF_TRANS_SOP_REG_U6(sexbl)

static inline void arc_gen_sexh(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_ext16s_i32(b, c);

    if (set_flags) {
        arc_gen_set_flag_Z(b);
        arc_gen_set_flag_N(b);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(sexh)
ARC_DEF_TRANS_SOP_REG_U6(sexh)
ARC_DEF_TRANS_S_DOP_2_OPERANDS(sexh)

static inline void arc64_gen_sexhl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_ext16s_i64(b, c);

    if (set_flags) {
        arc64_gen_set_flag_Z(b);
        arc64_gen_set_flag_N(b);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(sexhl)
ARC64_DEF_TRANS_SOP_REG_U6(sexhl)

static inline void arc64_gen_sexwl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_ext32s_i64(b, c);

    if (set_flags) {
        arc64_gen_set_flag_Z(b);
        arc64_gen_set_flag_N(b);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(sexwl)
ARC64_DEF_TRANS_SOP_REG_U6(sexwl)

static inline void arc_gen_sleep(DisasContext *ctx, TCGv_i32 arg)
{
    arc_gen_set_pc(ctx, ctx->base.pc_next);

    gen_helper_sleep(tcg_env, arg);

    ctx->base.is_jmp = DISAS_NORETURN;
}

static bool trans_sleep_reg(DisasContext *ctx, arg_sleep_reg *a)
{
    TCGv_i32 arg = arc_insn_load_src_reg(ctx, a->c);

    arc_gen_sleep(ctx, arg);

    return true;
}

static bool trans_sleep_imm(DisasContext *ctx, arg_sleep_imm *a)
{
    TCGv_i32 arg = arc_insn_load_imm(a->imm);

    arc_gen_sleep(ctx, arg);

    return true;
}

/* 
 * Swap 16-bits half-words
 *
 * b = c >> 16 | (c & 0xFFFF) << 16;
 *
 * dest = SWAP(src)
 * if F==1 then
 *   Z_flag = if dest==0 then 1 else 0
 *   N_flag = dest[31]
 */
static inline void arc_gen_swap(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_rotli_i32(b, c, 16);

    if (set_flags) {
        arc_gen_set_flag_Z(b);
        arc_gen_set_flag_N(b);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(swap)
ARC_DEF_TRANS_SOP_REG_U6(swap)

static inline void arc64_gen_swapl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_rotli_i64(b, c, 32);

    if (set_flags) {
        arc64_gen_set_flag_Z(b);
        arc64_gen_set_flag_N(b);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(swapl)
ARC64_DEF_TRANS_SOP_REG_U6(swapl)

/* 
 * Swap byte ordering
 *
 * b = swap order of bytes from c
 *
 * dest = (ROL8(src) & 0x00ff00ff) | (ROR8(src) & 0xff00ff00)
 * if F==1 then
 *   Z_flag = if dest==0 then 1 else 0
 *   N_flag = dest[31]
 */
static inline void arc_gen_swape(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_bswap32_i32(b, c);

    if (set_flags) {
        arc_gen_set_flag_Z(b);
        arc_gen_set_flag_N(b);
    }
}

ARC_DEF_TRANS_SOP_REG_REG(swape)
ARC_DEF_TRANS_SOP_REG_U6(swape)

static inline void arc64_gen_swapel(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_bswap64_i64(b, c);

    if (set_flags) {
        arc64_gen_set_flag_Z(b);
        arc64_gen_set_flag_N(b);
    }
}

ARC64_DEF_TRANS_SOP_REG_REG(swapel)
ARC64_DEF_TRANS_SOP_REG_U6(swapel)

static inline void arc_gen_swi(DisasContext *ctx, int code)
{
    g_assert(code >= 0 && code <  0x3F);

    ARCException exception;

#ifndef CONFIG_USER_ONLY
    if (semihosting_enabled(false)) {
        exception = ARC_EXCP_SEMIHOSTING;
        tcg_gen_movi_tl(cpu_semihost_eret, ctx->base.pc_next);
    } else {
        exception = ARC_EXCP_SWI;
    }
#else
    exception = ARC_EXCP_SWI;
#endif

    arc_gen_save_pc(ctx);
    gen_helper_raise_exception(tcg_env,
                               tcg_constant_i32(exception),
                               tcg_constant_i32(code));

    ctx->base.is_jmp = DISAS_NORETURN;
}

static bool trans_swi(DisasContext *ctx, arg_swi *a)
{
    arc_gen_swi(ctx, 0);

    return true;
}

static bool trans_swi_s(DisasContext *ctx, arg_swi_s *a)
{
    arc_gen_swi(ctx, 0);

    return true;
}

static bool trans_swi_s_imm(DisasContext *ctx, arg_swi_s_imm *a)
{
    if (a->imm == 0x3F) {
        arc_gen_exception_illegal_instruction(ctx);
    } else {
        arc_gen_swi(ctx, a->imm);
    }

    return true;
}

static bool trans_sync(DisasContext *ctx, arg_sync *a)
{
    /* Full memory barrier */
    tcg_gen_mb(TCG_BAR_SC);

    /*
    * At the end of a SYNC instruction, it is guaranteed that
    * handling the current interrupt is finished and the raising
    * pulse signal (if any), is cleared. By marking SYNC as the
    * end of a TB we gave a chance to interrupt threads to execute.
    */
    ctx->base.is_jmp = DISAS_UPDATE;

    return true;
}

static inline void arc_gen_tst(DisasContext *ctx, TCGv_i32 b, TCGv_i32 c)
{
    tcg_gen_and_i32(b, b, c);
    arc_gen_set_flag_Z(b);
    arc_gen_set_flag_N(b);
}

ARC_DEF_TRANS_CMP_DOP_REG_REG(tst)
ARC_DEF_TRANS_CMP_DOP_REG_U6(tst)
ARC_DEF_TRANS_CMP_DOP_REG_S12(tst)
ARC_DEF_TRANS_CMP_DOP_COND_REG(tst)
ARC_DEF_TRANS_CMP_DOP_COND_U6(tst)

static bool trans_tst_s_dop(DisasContext *ctx, arg_tst_s_dop *a)
{
    TCGv_i32 b = arc_insn_load_src_reg_s(ctx, a->b);
    TCGv_i32 c = arc_insn_load_src_reg_s(ctx, a->c);

    arc_gen_tst(ctx, b, c);

    return true;
}

static inline void arc64_gen_tstl(DisasContext *ctx, TCGv_i64 b, TCGv_i64 c)
{
    tcg_gen_and_i64(b, b, c);
    arc64_gen_set_flag_Z(b);
    arc64_gen_set_flag_N(b);
}

ARC64_DEF_TRANS_CMP_DOP_REG_REG(tstl)
ARC64_DEF_TRANS_CMP_DOP_REG_U6(tstl)
ARC64_DEF_TRANS_CMP_DOP_REG_S12(tstl)
ARC64_DEF_TRANS_CMP_DOP_COND_REG(tstl)
ARC64_DEF_TRANS_CMP_DOP_COND_U6(tstl)

static bool trans_trap_s(DisasContext *ctx, arg_trap_s *a)
{
    g_assert(a->imm >= 0 && a->imm < 0x40);

    arc_gen_save_pc(ctx);
    gen_helper_raise_exception(tcg_env,
                               tcg_constant_i32(ARC_EXCP_TRAP),
                               tcg_constant_i32(a->imm));

    ctx->base.is_jmp = DISAS_NORETURN;

    return true;
}

static bool trans_unimp_s(DisasContext *ctx, arg_unimp_s *a)
{
    arc_gen_exception_illegal_instruction(ctx);

    return true;
}

/*
 * Extract unsigned bitfield
 *
 * if (cc) then a = (b >> c[4:0]) & ((1 << (c[9:5]+1)) - 1)
 *
 * N = src2[4:0]
 * M = src2[9:5] + 1
 * if cc==true then
 *   dest = (src1 >> N) && ((1 << M)-1)
 *   if F==1 then
 *     Z_flag = if dest==0 then 1 else 0
 */
static inline void arc_gen_xbfu(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    TCGv_i32 offset = tcg_temp_new_i32();
    TCGv_i32 length = tcg_temp_new_i32();
    TCGv_i32 mask = tcg_temp_new_i32();
    TCGv_i32 tmp = tcg_temp_new_i32();

    /* Compute offset and length */
    tcg_gen_andi_i32(offset, c, 0x1F);
    tcg_gen_shri_i32(length, c, 5);
    tcg_gen_andi_i32(length, length, 0x1F);
    tcg_gen_addi_i32(length, length, 1);

    /* Compute mask as 0xFFFFFFFF >> (32 - length) */
    tcg_gen_subfi_i32(tmp, 32, length);
    tcg_gen_movi_i32(mask, -1);
    tcg_gen_shr_i32(mask, mask, tmp);

    /* Extract a field */
    tcg_gen_shr_i32(a, b, offset);
    tcg_gen_and_i32(a, a, mask);

    if (set_flags) {
        arc_gen_set_flag_Z(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(xbfu)
ARC_DEF_TRANS_DOP_REG_U6(xbfu)
ARC_DEF_TRANS_DOP_REG_S12(xbfu)
ARC_DEF_TRANS_DOP_COND_REG(xbfu)
ARC_DEF_TRANS_DOP_COND_U6(xbfu)

static inline void arc64_gen_xbful(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    TCGv_i64 offset = tcg_temp_new_i64();
    TCGv_i64 length = tcg_temp_new_i64();
    TCGv_i64 mask = tcg_temp_new_i64();
    TCGv_i64 tmp = tcg_temp_new_i64();

    /* Compute offset and length */
    tcg_gen_andi_i64(offset, c, 0x3F);
    tcg_gen_shri_i64(length, c, 6);
    tcg_gen_andi_i64(length, length, 0x3F);
    tcg_gen_addi_i64(length, length, 1);

    /* Compute mask as 0xFFFFFFFF >> (32 - length) */
    tcg_gen_subfi_i64(tmp, 64, length);
    tcg_gen_movi_i64(mask, -1);
    tcg_gen_shr_i64(mask, mask, tmp);

    /* Extract a field */
    tcg_gen_shr_i64(a, b, offset);
    tcg_gen_and_i64(a, a, mask);

    if (set_flags) {
        arc64_gen_set_flag_Z(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(xbful)
ARC64_DEF_TRANS_DOP_REG_U6(xbful)
ARC64_DEF_TRANS_DOP_REG_S12(xbful)
ARC64_DEF_TRANS_DOP_COND_REG(xbful)
ARC64_DEF_TRANS_DOP_COND_U6(xbful)

static inline void arc_gen_xor(DisasContext *ctx, TCGv_i32 a, TCGv_i32 b, TCGv_i32 c, bool set_flags)
{
    tcg_gen_xor_i32(a, b, c);

    if (set_flags) {
        arc_gen_set_flag_Z(a);
        arc_gen_set_flag_N(a);
    }
}

ARC_DEF_TRANS_DOP_REG_REG(xor)
ARC_DEF_TRANS_DOP_REG_U6(xor)
ARC_DEF_TRANS_DOP_REG_S12(xor)
ARC_DEF_TRANS_DOP_COND_REG(xor)
ARC_DEF_TRANS_DOP_COND_U6(xor)
ARC_DEF_TRANS_S_DOP_3_OPERANDS(xor)

static inline void arc64_gen_xorl(DisasContext *ctx, TCGv_i64 a, TCGv_i64 b, TCGv_i64 c, bool set_flags)
{
    tcg_gen_xor_i64(a, b, c);

    if (set_flags) {
        arc64_gen_set_flag_Z(a);
        arc64_gen_set_flag_N(a);
    }
}

ARC64_DEF_TRANS_DOP_REG_REG(xorl)
ARC64_DEF_TRANS_DOP_REG_U6(xorl)
ARC64_DEF_TRANS_DOP_REG_S12(xorl)
ARC64_DEF_TRANS_DOP_COND_REG(xorl)
ARC64_DEF_TRANS_DOP_COND_U6(xorl)

#include "insn_trans/trans_atomic.c.inc"
#include "insn_trans/trans_add.c.inc"
#include "insn_trans/trans_aux.c.inc"
#include "insn_trans/trans_branch.c.inc"
#include "insn_trans/trans_divrem.c.inc"
#include "insn_trans/trans_enter_leave.c.inc"
#include "insn_trans/trans_jump.c.inc"
#include "insn_trans/trans_ld.c.inc"
#include "insn_trans/trans_lp.c.inc"
#include "insn_trans/trans_mov.c.inc"
#include "insn_trans/trans_multiply.c.inc"
#include "insn_trans/trans_simd.c.inc"
#include "insn_trans/trans_setcc.c.inc"
#include "insn_trans/trans_shifts.c.inc"
#include "insn_trans/trans_st.c.inc"
#include "insn_trans/trans_sub.c.inc"

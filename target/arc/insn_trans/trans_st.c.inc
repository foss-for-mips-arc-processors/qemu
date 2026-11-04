#include "translate.h"

/*
 * TODO: Clear the atomic lock flag (env->atomic_lf) on a store that hits the
 * locked address instead of comparing values in SCOND, see atomic_helper.c.
 */

static bool trans_st_reg(DisasContext *ctx, arg_st_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_WORD);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

static bool trans_st_w6(DisasContext *ctx, arg_st_w6 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_imm_tl(a->simm_src);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->simm_offset);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_WORD);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

static bool trans_stb_reg(DisasContext *ctx, arg_stb_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_BYTE);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

static bool trans_stb_w6(DisasContext *ctx, arg_stb_w6 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_imm_tl(a->simm_src);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->simm_offset);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_BYTE);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

static bool trans_sth_reg(DisasContext *ctx, arg_sth_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_HALF, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_HALF);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

static bool trans_sth_w6(DisasContext *ctx, arg_sth_w6 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_imm_tl(a->simm_src);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->simm_offset);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_HALF, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_HALF);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

#ifdef TARGET_ARCV3_64
static bool trans_stl_reg(DisasContext *ctx, arg_stl_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_DOUBLE);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

static bool trans_stl_w6(DisasContext *ctx, arg_stl_w6 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_imm_tl(a->simm_src);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->simm_offset);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_DOUBLE);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

static void trans_stdl(DisasContext *ctx, TCGv src_lo, TCGv src_hi, int base_reg,
                       TCGv offset, ARCInsnWriteBackMode aa)
{
    TCGv address = tcg_temp_new();
    TCGv base = arc_insn_load_src_reg_tl(ctx, base_reg);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, aa, ARC_ZZ_DOUBLE);
    tcg_gen_qemu_st_tl(src_lo, address, ctx->mem_idx, memop);
    tcg_gen_addi_tl(address, address, 8);
    tcg_gen_qemu_st_tl(src_hi, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, base_reg, base);
}

static bool trans_stdl_reg(DisasContext *ctx, arg_stdl_reg *a)
{
    TCGv src_lo;
    TCGv src_hi;

    if (!arc_regnum_limm(a->c) && arc_regnum_odd(a->c)) {
        arc_gen_exception_illegal_instruction(ctx);
        return true;
    }

    src_lo = arc_insn_load_src_reg_tl(ctx, a->c);
    src_hi = arc_regnum_limm(a->c) ? src_lo
                                   : arc_insn_load_src_reg_tl(ctx, a->c + 1);
    trans_stdl(ctx, src_lo, src_hi, a->b, arc_insn_load_imm_tl(a->imm), a->aa);

    return true;
}

static bool trans_stdl_w6(DisasContext *ctx, arg_stdl_w6 *a)
{
    TCGv src = arc_insn_load_imm_tl(a->simm_src);

    trans_stdl(ctx, src, src, a->b, arc_insn_load_imm_tl(a->simm_offset), a->aa);

    return true;
}

ARC_DEF_TRANS_STUB(std_reg);
ARC_DEF_TRANS_STUB(std_w6);
#else
static bool trans_std_reg(DisasContext *ctx, arg_std_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv_i64 src = arc_insn_load_src_reg_pair(ctx, a->c, ARC_REGPAIR_LIMM_SIGNED);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_DOUBLE);
    tcg_gen_qemu_st_i64(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

static bool trans_std_w6(DisasContext *ctx, arg_std_w6 *a)
{
    TCGv address = tcg_temp_new();
    TCGv_i64 src = arc64_insn_load_imm(a->simm_src);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->simm_offset);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_DOUBLE);
    tcg_gen_qemu_st_i64(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, a->b, base);

    return true;
}

ARC_DEF_TRANS_STUB(stl_reg)
ARC_DEF_TRANS_STUB(stl_w6)
ARC_DEF_TRANS_STUB(stdl_reg)
ARC_DEF_TRANS_STUB(stdl_w6)
#endif

/* ST_S b,[SP,u7] */
static bool trans_st_s_b_sp_u7(DisasContext *ctx, arg_st_s_b_sp_u7 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);

    return true;
}

/* ST_S c,[b,u7] */
static bool trans_st_s_c_b_u7(DisasContext *ctx, arg_st_s_c_b_u7 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_s_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);

    return true;
}

/* STB_S b,[SP,u7] */
static bool trans_stb_s_b_sp_u7(DisasContext *ctx, arg_stb_s_b_sp_u7 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_BYTE);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);

    return true;
}

/* ST_S R0,[GP,s11] */
static bool trans_st_s_r0_gp_s11(DisasContext *ctx, arg_st_s_r0_gp_s11 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_R0);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_GP);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);

    return true;
}

/* STB_S c,[b,u5] */
static bool trans_stb_s_c_b_u5(DisasContext *ctx, arg_stb_s_c_b_u5 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_s_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_BYTE);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);

    return true;
}

/* STH_S c,[b,u6] */
static bool trans_sth_s_c_b_u6(DisasContext *ctx, arg_sth_s_c_b_u6 *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_s_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_HALF, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_HALF);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);

    return true;
}

#ifdef TARGET_ARCV3_64
static bool trans_pushl_s(DisasContext *ctx, arg_pushl_s *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(-8);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_PRE, ARC_ZZ_DOUBLE);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, ARC_REGNUM_SP, base);

    return true;
}

static bool trans_pushdl_s(DisasContext *ctx, arg_pushdl_s *a)
{
    TCGv address;
    TCGv src_lo;
    TCGv src_hi;
    TCGv base;
    TCGv offset;
    MemOp memop;

    if (arc_regnum_odd(a->b)) {
        arc_gen_exception_illegal_instruction(ctx);
        return true;
    }

    address = tcg_temp_new();
    src_lo = arc_insn_load_src_reg_tl(ctx, a->b);
    src_hi = arc_insn_load_src_reg_tl(ctx, a->b + 1);
    base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    offset = arc_insn_load_imm_tl(-16);
    memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_PRE,
                                    ARC_ZZ_DOUBLE);
    tcg_gen_qemu_st_tl(src_lo, address, ctx->mem_idx, memop);
    tcg_gen_addi_tl(address, address, 8);
    tcg_gen_qemu_st_tl(src_hi, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, ARC_REGNUM_SP, base);

    return true;
}

ARC_DEF_TRANS_STUB(push_s)
ARC_DEF_TRANS_STUB(push_s_blink)
#else
/*
 * PUSH_S b
 *
 *     SP = SP - 4;
 *     mem[SP] = b;
 */
static bool trans_push_s(DisasContext *ctx, arg_push_s *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(-4);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_PRE, ARC_ZZ_WORD);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, ARC_REGNUM_SP, base);

    return true;
}

static bool trans_push_s_blink(DisasContext *ctx, arg_push_s_blink *a)
{
    TCGv address = tcg_temp_new();
    TCGv src = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_BLINK);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(-4);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_PRE, ARC_ZZ_WORD);
    tcg_gen_qemu_st_tl(src, address, ctx->mem_idx, memop);
    arc_insn_save_reg_tl(ctx, ARC_REGNUM_SP, base);

    return true;
}

ARC_DEF_TRANS_STUB(pushl_s)
ARC_DEF_TRANS_STUB(pushdl_s)
#endif

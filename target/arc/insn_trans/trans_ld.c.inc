#include "translate.h"

static bool trans_ld_offset(DisasContext *ctx, arg_ld_offset *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_WORD);

    /* Do not make a real load for PREFETCH or PREFETCHW */
    if (a->a != ARC_REGNUM_LIMM) {
        tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);
    }

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}

#ifdef TARGET_ARCV3_64
static bool trans_ld_offset_sext(DisasContext *ctx, arg_ld_offset_sext *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, true);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}
#else
ARC_DEF_TRANS_STUB(ld_offset_sext)
#endif

static bool trans_ld_reg(DisasContext *ctx, arg_ld_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg_tl(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_WORD);

    /* Do not make a real load for PREFETCH or PREFETCHW */
    if (a->a != ARC_REGNUM_LIMM) {
        tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);
    }

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}

#ifdef TARGET_ARCV3_64
static bool trans_ld_reg_sext(DisasContext *ctx, arg_ld_reg_sext *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg_tl(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, true);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}
#else
ARC_DEF_TRANS_STUB(ld_reg_sext)
#endif

static bool trans_ldb_offset(DisasContext *ctx, arg_ldb_offset *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, a->x);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_BYTE);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}

static bool trans_ldb_reg(DisasContext *ctx, arg_ldb_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg_tl(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, a->x);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_BYTE);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}

static bool trans_ldh_offset(DisasContext *ctx, arg_ldh_offset *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_HALF, a->x);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_HALF);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}

static bool trans_ldh_reg(DisasContext *ctx, arg_ldh_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg_tl(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_HALF, a->x);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_HALF);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}

#ifdef TARGET_ARCV3_64
static bool trans_ldl_offset(DisasContext *ctx, arg_ldl_offset *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_DOUBLE);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}

static bool trans_ldl_reg(DisasContext *ctx, arg_ldl_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_tl(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg_tl(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_DOUBLE);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_tl(ctx, a->a, dest);

    return true;
}

static ARCInsnWriteBackMode arc_lddl_aa(int x, int di)
{
    if (x) {
        return di ? ARC_AA_POST : ARC_AA_PRE;
    }

    return di ? ARC_AA_SCALED : ARC_AA_NONE;
}

static bool trans_lddl(DisasContext *ctx, int dest, int base_reg, TCGv offset,
                       ARCInsnWriteBackMode aa)
{
    TCGv address;
    TCGv dest_lo;
    TCGv dest_hi;
    TCGv base;
    MemOp memop;
    bool null_dest = arc_regnum_limm(dest);

    if (arc_regnum_odd(dest)) {
        arc_gen_exception_illegal_instruction(ctx);
        return true;
    }

    address = tcg_temp_new();
    base = arc_insn_load_src_reg_tl(ctx, base_reg);
    memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    if (!null_dest) {
        dest_lo = arc_insn_load_dst_reg_tl(ctx, dest);
        dest_hi = arc_insn_load_dst_reg_tl(ctx, dest + 1);
    } else {
        dest_lo = tcg_temp_new();
        dest_hi = tcg_temp_new();
    }

    arc_gen_check_not_lp_count(ctx, dest);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, aa, ARC_ZZ_DOUBLE);

    tcg_gen_qemu_ld_tl(dest_lo, address, ctx->mem_idx, memop);
    tcg_gen_addi_tl(address, address, 8);
    tcg_gen_qemu_ld_tl(dest_hi, address, ctx->mem_idx, memop);

    if (aa == ARC_AA_POST || aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, base_reg, base);
    }

    if (!null_dest) {
        arc_insn_save_reg_tl(ctx, dest, dest_lo);
        arc_insn_save_reg_tl(ctx, dest + 1, dest_hi);
    }

    return true;
}

static bool trans_lddl_offset(DisasContext *ctx, arg_lddl_offset *a)
{
    return trans_lddl(ctx, a->a, a->b, arc_insn_load_imm_tl(a->imm),
                      arc_lddl_aa(a->x, a->di));
}

static bool trans_lddl_reg(DisasContext *ctx, arg_lddl_reg *a)
{
    return trans_lddl(ctx, a->a, a->b, arc_insn_load_src_reg_tl(ctx, a->c),
                      arc_lddl_aa(a->x, a->di));
}

ARC_DEF_TRANS_STUB(ldd_reg);
ARC_DEF_TRANS_STUB(ldd_offset);
#else
static bool trans_ldd_offset(DisasContext *ctx, arg_ldd_offset *a)
{
    TCGv address = tcg_temp_new();
    TCGv_i64 dest = arc_insn_load_dst_reg_pair(ctx, a->a);
    TCGv base = arc_insn_load_src_reg(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_DOUBLE);

    tcg_gen_qemu_ld_i64(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_pair(ctx, a->a, dest);

    return true;
}

static bool trans_ldd_reg(DisasContext *ctx, arg_ldd_reg *a)
{
    TCGv address = tcg_temp_new();
    TCGv_i64 dest = arc_insn_load_dst_reg_pair(ctx, a->a);
    TCGv base = arc_insn_load_src_reg(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_check_not_lp_count(ctx, a->a);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, a->aa, ARC_ZZ_DOUBLE);

    tcg_gen_qemu_ld_i64(dest, address, ctx->mem_idx, memop);

    if (a->aa == ARC_AA_POST || a->aa == ARC_AA_PRE) {
        arc_insn_save_reg_tl(ctx, a->b, base);
    }

    arc_insn_save_reg_pair(ctx, a->a, dest);

    return true;
}

ARC_DEF_TRANS_STUB(lddl_offset);
ARC_DEF_TRANS_STUB(lddl_reg);
ARC_DEF_TRANS_STUB(ldl_offset);
ARC_DEF_TRANS_STUB(ldl_reg);
#endif

/* LD_S a,[b,c] */
static bool trans_ld_s_a_b_c(DisasContext *ctx, arg_ld_s_a_b_c *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg_s_tl(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->a, dest);

    return true;
}

/* LD_S b,[SP,u7]*/
static bool trans_ld_s_b_sp_u7(DisasContext *ctx, arg_ld_s_b_sp_u7 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->b);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->b, dest);

    return true;
}

/* LD_S b,[PCL,u10] */
static bool trans_ld_s_b_pcl_u10(DisasContext *ctx, arg_ld_s_b_pcl_u10 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->b);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_PCL);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->b, dest);

    return true;
}

/* LD_S c,[b,u7] */
static bool trans_ld_s_c_b_u7(DisasContext *ctx, arg_ld_s_c_b_u7 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->c, dest);

    return true;
}

/* LD_S R0,[GP,s11] */
static bool trans_ld_s_r0_gp_s11(DisasContext *ctx, arg_ld_s_r0_gp_s11 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, ARC_REGNUM_R0);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_GP);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, ARC_REGNUM_R0, dest);

    return true;
}

/* LDB_S a,[b,c] */
static bool trans_ldb_s_a_b_c(DisasContext *ctx, arg_ldb_s_a_b_c *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg_s_tl(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_BYTE);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->a, dest);

    return true;
}

/* LDB_S b,[SP,u7] */
static bool trans_ldb_s_b_sp_u7(DisasContext *ctx, arg_ldb_s_b_sp_u7 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->b);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_BYTE);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->b, dest);

    return true;
}

/* LDB_S c,[b,u5] */
static bool trans_ldb_s_c_b_u5(DisasContext *ctx, arg_ldb_s_c_b_u5 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_BYTE);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->c, dest);

    return true;
}

/* LDB_S R0,[GP,s9] */
static bool trans_ldb_s_r0_gp_s9(DisasContext *ctx, arg_ldb_s_r0_gp_s9 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, ARC_REGNUM_R0);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_GP);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_BYTE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_BYTE);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, ARC_REGNUM_R0, dest);

    return true;
}

/* LDH_S a,[b,c] */
static bool trans_ldh_s_a_b_c(DisasContext *ctx, arg_ldh_s_a_b_c *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg_s_tl(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_HALF, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_HALF);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->a, dest);

    return true;
}

/* LDH_S c,[b,u6] */
static bool trans_ldh_s_c_b_u6(DisasContext *ctx, arg_ldh_s_c_b_u6 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_HALF, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_HALF);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->c, dest);

    return true;
}

/* LDH_S R0,[GP,s10] */
static bool trans_ldh_s_r0_gp_s10(DisasContext *ctx, arg_ldh_s_r0_gp_s10 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, ARC_REGNUM_R0);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_GP);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_HALF, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_HALF);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, ARC_REGNUM_R0, dest);

    return true;
}

/* LDH_S.X c,[b,u6] */
static bool trans_ldh_s_x_c_b_u6(DisasContext *ctx, arg_ldh_s_x_c_b_u6 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->c);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_imm_tl(a->imm);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_HALF, true);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_HALF);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->c, dest);

    return true;
}

/* LD_S R0-R3,[h,u5] */
static bool trans_ld_s_a_h_u5(DisasContext *ctx, arg_ld_s_a_h_u5 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_h_tl(ctx, a->h);
    TCGv offset = arc_insn_load_imm_tl(a->offset);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->a, dest);

    return true;
}

/* LD_S.AS a,[b,c] */
static bool trans_ld_s_as_a_b_c(DisasContext *ctx, arg_ld_s_as_a_b_c *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->a);
    TCGv base = arc_insn_load_src_reg_s_tl(ctx, a->b);
    TCGv offset = arc_insn_load_src_reg_s_tl(ctx, a->c);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_SCALED, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, a->a, dest);

    return true;
}

/* LD_S R1,[GP,s11] */
static bool trans_ld_s_r1_gp_s11(DisasContext *ctx, arg_ld_s_r1_gp_s11 *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, ARC_REGNUM_R1);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_GP);
    TCGv offset = arc_insn_load_imm_tl(a->offset);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_NONE, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_s_tl(ctx, ARC_REGNUM_R1, dest);

    return true;
}

#ifdef TARGET_ARCV3_64
static bool trans_popl_s(DisasContext *ctx, arg_popl_s *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, a->b);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(8);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_POST, ARC_ZZ_DOUBLE);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_tl(ctx, ARC_REGNUM_SP, base);
    arc_insn_save_reg_tl(ctx, a->b, dest);

    return true;
}

static bool trans_popdl_s(DisasContext *ctx, arg_popdl_s *a)
{
    TCGv address;
    TCGv dest_lo;
    TCGv dest_hi;
    TCGv base;
    TCGv offset;
    MemOp memop;

    if (arc_regnum_odd(a->b)) {
        arc_gen_exception_illegal_instruction(ctx);
        return true;
    }

    address = tcg_temp_new();
    dest_lo = arc_insn_load_dst_reg_tl(ctx, a->b);
    dest_hi = arc_insn_load_dst_reg_tl(ctx, a->b + 1);
    base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    offset = arc_insn_load_imm_tl(16);
    memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_DOUBLE, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_POST,
                                    ARC_ZZ_DOUBLE);

    tcg_gen_qemu_ld_tl(dest_lo, address, ctx->mem_idx, memop);
    tcg_gen_addi_tl(address, address, 8);
    tcg_gen_qemu_ld_tl(dest_hi, address, ctx->mem_idx, memop);

    arc_insn_save_reg_tl(ctx, a->b, dest_lo);
    arc_insn_save_reg_tl(ctx, a->b + 1, dest_hi);

    if (a->b != ARC_REGNUM_SP) {
        arc_insn_save_reg_tl(ctx, ARC_REGNUM_SP, base);
    }

    return true;
}

ARC_DEF_TRANS_STUB(pop_s)
ARC_DEF_TRANS_STUB(pop_s_blink)
#else
static bool trans_pop_s(DisasContext *ctx, arg_pop_s *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_s_tl(ctx, a->b);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(4);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_POST, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_tl(ctx, ARC_REGNUM_SP, base);
    arc_insn_save_reg_s_tl(ctx, a->b, dest);

    return true;
}

static bool trans_pop_s_blink(DisasContext *ctx, arg_pop_s_blink *a)
{
    TCGv address = tcg_temp_new();
    TCGv dest = arc_insn_load_dst_reg_tl(ctx, ARC_REGNUM_BLINK);
    TCGv base = arc_insn_load_src_reg_tl(ctx, ARC_REGNUM_SP);
    TCGv offset = arc_insn_load_imm_tl(4);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_POST, ARC_ZZ_WORD);

    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);

    arc_insn_save_reg_tl(ctx, ARC_REGNUM_SP, base);
    arc_insn_save_reg_tl(ctx, ARC_REGNUM_BLINK, dest);

    return true;
}

ARC_DEF_TRANS_STUB(popl_s)
ARC_DEF_TRANS_STUB(popdl_s)
#endif

#ifdef TARGET_ARCV3_64
ARC_DEF_TRANS_STUB(ldi_b_c)
ARC_DEF_TRANS_STUB(ldi_b_u6)
ARC_DEF_TRANS_STUB(ldi_b_s12)
ARC_DEF_TRANS_STUB(ldi_s_b_u)
#else
static void gen_ldi(DisasContext *ctx, TCGv dest, TCGv offset)
{
    TCGv address = tcg_temp_new();
    TCGv base = tcg_temp_new();
    TCGv aux_regnum = tcg_constant_tl(ARC_AUX_REGNUM_LDI_BASE);
    MemOp memop = arc_insn_ldst_get_memop(ctx, ARC_ZZ_WORD, false);

    gen_helper_aux_reg_read_tl(base, tcg_env, aux_regnum);
    arc_gen_ldst_writeback_prologue(ctx, address, base, offset, ARC_AA_SCALED, ARC_ZZ_WORD);
    tcg_gen_qemu_ld_tl(dest, address, ctx->mem_idx, memop);
}

/* LDI b,[c] */
static bool trans_ldi_b_c(DisasContext *ctx, arg_ldi_b_c *a)
{
    TCGv reg_dest = arc_insn_load_dst_reg_tl(ctx, a->b);
    TCGv reg_offset = arc_insn_load_src_reg_tl(ctx, a->c);

    arc_gen_check_not_lp_count(ctx, a->b);
    gen_ldi(ctx, reg_dest, reg_offset);
    arc_insn_save_reg_tl(ctx, a->b, reg_dest);

    return true;
}

/* LDI b,[u6] */
static bool trans_ldi_b_u6(DisasContext *ctx, arg_ldi_b_u6 *a)
{
    TCGv reg_dest = arc_insn_load_dst_reg_tl(ctx, a->b);
    TCGv reg_offset = arc_insn_load_imm_tl(a->offset);

    arc_gen_check_not_lp_count(ctx, a->b);
    gen_ldi(ctx, reg_dest, reg_offset);
    arc_insn_save_reg_tl(ctx, a->b, reg_dest);

    return true;
}

/* LDI b,[s12] */
static bool trans_ldi_b_s12(DisasContext *ctx, arg_ldi_b_s12 *a)
{
    TCGv reg_dest = arc_insn_load_dst_reg_tl(ctx, a->b);
    TCGv reg_offset = arc_insn_load_imm_tl(a->offset);

    arc_gen_check_not_lp_count(ctx, a->b);
    gen_ldi(ctx, reg_dest, reg_offset);
    arc_insn_save_reg_tl(ctx, a->b, reg_dest);

    return true;
}

/* LDI_S b,u7 */
static bool trans_ldi_s_b_u(DisasContext *ctx, arg_ldi_s_b_u *a)
{
    TCGv reg_dest = arc_insn_load_dst_reg_s_tl(ctx, a->b);
    TCGv reg_offset = arc_insn_load_imm_tl(a->offset);

    gen_ldi(ctx, reg_dest, reg_offset);
    arc_insn_save_reg_s_tl(ctx, a->b, reg_dest);

    return true;
}

#endif

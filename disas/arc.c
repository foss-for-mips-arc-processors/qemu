#include "qemu/osdep.h"
#include "qemu/bitops.h"
#include "disas/dis-asm.h"

#include <glib/gprintf.h>

typedef enum {
    ARC_REGNUM_R0,
    ARC_REGNUM_R1,
    ARC_REGNUM_R2,
    ARC_REGNUM_R3,
    ARC_REGNUM_R4,
    ARC_REGNUM_R5,
    ARC_REGNUM_R6,
    ARC_REGNUM_R7,
    ARC_REGNUM_R8,
    ARC_REGNUM_R9,
    ARC_REGNUM_R10,
    ARC_REGNUM_R11,
    ARC_REGNUM_R12,
    ARC_REGNUM_R13,
    ARC_REGNUM_R14,
    ARC_REGNUM_R15,
    ARC_REGNUM_R16,
    ARC_REGNUM_R17,
    ARC_REGNUM_R18,
    ARC_REGNUM_R19,
    ARC_REGNUM_R20,
    ARC_REGNUM_R21,
    ARC_REGNUM_R22,
    ARC_REGNUM_R23,
    ARC_REGNUM_R24,
    ARC_REGNUM_R25,
    ARC_REGNUM_R26,
    ARC_REGNUM_GP = ARC_REGNUM_R26,
    ARC_REGNUM_R27,
    ARC_REGNUM_FP = ARC_REGNUM_R27,
    ARC_REGNUM_R28,
    ARC_REGNUM_SP = ARC_REGNUM_R28,
    ARC_REGNUM_R29,
    ARC_REGNUM_ILINK = ARC_REGNUM_R29,
    ARC_REGNUM_R30,
    ARC_REGNUM_R31,
    ARC_REGNUM_BLINK = ARC_REGNUM_R31,
    ARC_REGNUM_R32,
    ARC_REGNUM_R56,
    ARC_REGNUM_R57,
    ARC_REGNUM_R58 = 58,
    ARC_REGNUM_ACCL = ARC_REGNUM_R58, /* Little endian */
    ARC_REGNUM_R59,
    ARC_REGNUM_ACCH = ARC_REGNUM_R59, /* Little endian */
    ARC_REGNUM_R60, /* LP_COUNT */
    ARC_REGNUM_LP_COUNT = ARC_REGNUM_R60,
    ARC_REGNUM_SLIMM = ARC_REGNUM_R60,
    ARC_REGNUM_R61,
    ARC_REGNUM_RESERVED = ARC_REGNUM_R61,
    ARC_REGNUM_R62,
    ARC_REGNUM_LIMM = ARC_REGNUM_R62,
    ARC_REGNUM_ULIMM = ARC_REGNUM_R62,
    ARC_REGNUM_R63,
    ARC_REGNUM_PCL = ARC_REGNUM_R63,
    ARC_REGNUM_END
} ARCRegNum;

typedef enum {
    ARC_ZZ_WORD   = 0, /* 32-bit word */
    ARC_ZZ_BYTE   = 1, /* 8-bit byte */
    ARC_ZZ_HALF   = 2, /* 16-bit halfword */
    ARC_ZZ_DOUBLE = 3  /* 64-bit pair */
} ARCInsnDataSize;

typedef enum {
    ARC_AA_NONE   = 0,            /* no write-back;  EA = b + offset */
    ARC_AA_PRE    = 1,            /* pre-increment;  EA = b + offset, b = b + offset */
    ARC_AA_AW     = ARC_AA_PRE,
    ARC_AA_POST   = 2,            /* post-increment; EA = b, b = b + offset */
    ARC_AA_AB     = ARC_AA_POST,
    ARC_AA_SCALED = 3,            /* scaled index; EA = b + (index << scale), no write-back */
    ARC_AA_AS     = ARC_AA_SCALED /* scale factor: 2 for word, 1 for halfword, undefined for byte */
} ARCInsnWriteBackMode;

typedef enum {
    ARC_CC_AL  = 0x00,     /* always */
    ARC_CC_RA  = ARC_CC_AL,
    ARC_CC_EQ  = 0x01,     /* equal / zero */
    ARC_CC_Z   = ARC_CC_EQ,
    ARC_CC_NE  = 0x02,     /* not equal / not zero */
    ARC_CC_NZ  = ARC_CC_NE,
    ARC_CC_PL  = 0x03,     /* positive / plus */
    ARC_CC_P   = ARC_CC_PL,
    ARC_CC_MI  = 0x04,     /* minus / negative */
    ARC_CC_N   = ARC_CC_MI,
    ARC_CC_CS  = 0x05,     /* carry set / lower than (unsigned) */
    ARC_CC_C   = ARC_CC_CS,
    ARC_CC_LO  = ARC_CC_CS,
    ARC_CC_CC  = 0x06,     /* carry clear / higher or same (unsigned) */
    ARC_CC_NC  = ARC_CC_CC,
    ARC_CC_HS  = ARC_CC_CC,
    ARC_CC_VS  = 0x07,     /* overflow set */
    ARC_CC_V   = ARC_CC_VS,
    ARC_CC_VC  = 0x08,     /* overflow clear */
    ARC_CC_NV  = ARC_CC_VC,
    ARC_CC_GT  = 0x09,     /* greater than (signed) */
    ARC_CC_GE  = 0x0A,     /* greater than or equal (signed) */
    ARC_CC_LT  = 0x0B,     /* less than (signed) */
    ARC_CC_LE  = 0x0C,     /* less than or equal (signed) */
    ARC_CC_HI  = 0x0D,     /* higher than (unsigned) */
    ARC_CC_LS  = 0x0E,     /* lower or same (unsigned) */
    ARC_CC_PNZ = 0x0F,     /* positive non-zero */
    ARC_CC_END,
} ARCInsnConditionCode;

typedef struct DisasContext {
    struct disassemble_info *info;
    char     buffer[64];
    bfd_vma  memaddr;
    uint32_t insn;
    int      insn_len;
    bool     has_limm;
    uint32_t limm;
} DisasContext;

#include "target/arc/extractors.h"
#include "decode-insn32.c.inc"
#include "decode-insn16.c.inc"

static const char * const arcv2_gpr_regnames[] = {
    "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
    "r24", "r25", "gp", "fp",  "sp", "ilink", "r30", "blink",
    "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",
    "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",
    "r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",
    "r56", "r57", "r58", "r59", "lp_count", "reserved", "LIMM", "pcl",
};

static const char * const arcv3_gpr_regnames[] = {
    "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
    "r24", "r25", "r26", "fp",  "sp",  "ilink", "r30", "blink",
    "r32", "r33", "r34", "r35", "r36", "r37", "r38", "r39",
    "r40", "r41", "r42", "r43", "r44", "r45", "r46", "r47",
    "r48", "r49", "r50", "r51", "r52", "r53", "r54", "r55",
    "r56", "r57", "r58", "reserved", "SLIMM", "reserved", "ULIMM", "pcl",
};

static const char *condition_code_strings[] = {
    "", "eq", "ne", "p", "n", "c", "nc", "v",
    "nv", "gt", "ge", "lt", "le", "hi", "ls", "pnz"
};

static bool arc_is_arcv3_32(DisasContext *ctx)
{
    return ctx->info->mach == bfd_mach_arcv3_32;
}

static bool arc_is_arcv3_64(DisasContext *ctx)
{
    return ctx->info->mach == bfd_mach_arcv3_64;
}

static bool arc_is_arcv3(DisasContext *ctx)
{
    return arc_is_arcv3_32(ctx) || arc_is_arcv3_64(ctx);
}

static const char *arc_get_register_name(uint32_t value)
{
    g_assert(value < ARRAY_SIZE(arcv2_gpr_regnames));
    return arcv2_gpr_regnames[value];
}

static bfd_vma arc_bfd_getm32(unsigned int data)
{
    bfd_vma value = 0;

    value  = (data & 0x0000ffff) << 16;
    value |= (data & 0xffff0000) >> 16;

    return value;
}

static uint32_t arc_parse_limm(DisasContext *ctx)
{
    bfd_byte buffer[4];
    int status;

    if (ctx->has_limm) {
        return ctx->limm;
    }

    status = (*ctx->info->read_memory_func)(ctx->memaddr + ctx->insn_len, buffer, 4, ctx->info);

    if (status != 0) {
        /* TODO: Rework error handling for this case. */
        g_assert_not_reached();
    }

    ctx->limm = arc_bfd_getm32(bfd_getl32(buffer));
    ctx->has_limm = true;
    ctx->insn_len += 4;

    return ctx->limm;
}

static inline bool arc_regnum_is_limm(DisasContext *ctx, uint32_t reg)
{
    if (arc_is_arcv3_64(ctx)) {
        return reg == ARC_REGNUM_ULIMM || reg == ARC_REGNUM_SLIMM;
    } else {
        return reg == ARC_REGNUM_LIMM;
    }
}

static const char *arc_format_get_reg_name(DisasContext *ctx, uint32_t regnum)
{
    if (arc_is_arcv3(ctx)) {
        g_assert(regnum < ARRAY_SIZE(arcv3_gpr_regnames));
        return arcv3_gpr_regnames[regnum];
    } else {
        g_assert(regnum < ARRAY_SIZE(arcv2_gpr_regnames));
        return arcv2_gpr_regnames[regnum];
    }
}

static void arc_print_str(DisasContext *ctx, const char *str)
{
    (*ctx->info->fprintf_func)(ctx->info->stream, "%s", str);
}

static void arc_print_space(DisasContext *ctx)
{
    arc_print_str(ctx, " ");
}

static void arc_print_dot(DisasContext *ctx)
{
    arc_print_str(ctx, ",");
}

static void arc_print_f(DisasContext *ctx, bool f, bool dot)
{
    const char *tmp;

    if (f) {
        if (dot) {
            tmp = ".f";
        } else {
            tmp = "f";
        }
    } else {
        tmp = "";
    }

    (*ctx->info->fprintf_func)(ctx->info->stream, "%s", tmp);
}

static void arc_print_delay(DisasContext *ctx, bool delay)
{
    if (delay) {
        arc_print_str(ctx, ".d");
    }
}

static void arc_print_di(DisasContext *ctx, bool di, bool dot)
{
    const char *tmp;

    if (di) {
        if (dot) {
            tmp = ".di";
        } else {
            tmp = "di";
        }
    } else {
        tmp = "";
    }

    (*ctx->info->fprintf_func)(ctx->info->stream, "%s", tmp);
}

static void arc_print_cc(DisasContext *ctx, uint32_t cond, bool dot)
{
    char buf[8] = {0};

    if (cond == ARC_CC_AL) {
        buf[0] = '\0';
    } else if (cond >= ARC_CC_END) {
        if (dot) {
            g_sprintf(buf, ".??");
        } else {
            g_sprintf(buf, "??");
        }
    } else {
        if (dot) {
            g_sprintf(buf, ".%s", condition_code_strings[cond]);
        } else {
            g_sprintf(buf, "%s", condition_code_strings[cond]);
        }
    }

    (*ctx->info->fprintf_func)(ctx->info->stream, "%s", buf);
}

static void arc_print_uimm(DisasContext *ctx, uint32_t imm)
{
    (*ctx->info->fprintf_func)(ctx->info->stream, "%#x", imm);
}

static void arc_print_simm(DisasContext *ctx, int32_t simm)
{
    (*ctx->info->fprintf_func)(ctx->info->stream, "%d", simm);
}

static void arc_print_dst_reg(DisasContext *ctx, uint32_t regnum)
{
    const char *tmp;

    if (arc_regnum_is_limm(ctx, regnum)) {
        tmp = "0";
    } else {
        tmp = arc_format_get_reg_name(ctx, regnum);
    }

    (*ctx->info->fprintf_func)(ctx->info->stream, "%s", tmp);
}

static void arc_print_src_reg(DisasContext *ctx, uint32_t regnum)
{
    char buf[32];

    if (arc_is_arcv3_64(ctx) && regnum == ARC_REGNUM_SLIMM) {
        g_sprintf(buf, "%d", (int32_t)arc_parse_limm(ctx));
    } else if (regnum == ARC_REGNUM_LIMM) {
        g_sprintf(buf, "%#x", arc_parse_limm(ctx));
    } else {
        g_sprintf(buf, "%s", arc_format_get_reg_name(ctx, regnum));
    }

    (*ctx->info->fprintf_func)(ctx->info->stream, "%s", buf);
}

static void arc_print_dst_reg_pair(DisasContext *ctx, uint32_t regnum)
{
    if (arc_regnum_is_limm(ctx, regnum)) {
        arc_print_str(ctx, "0");
        return;
    }

    arc_print_dst_reg(ctx, regnum);
    arc_print_dst_reg(ctx, regnum + 1);
}

static void arc_print_src_reg_pair(DisasContext *ctx, uint32_t regnum)
{
    if (arc_regnum_is_limm(ctx, regnum)) {
        arc_print_src_reg(ctx, regnum);
        return;
    }

    arc_print_src_reg(ctx, regnum);
    arc_print_src_reg(ctx, regnum + 1);
}

static void arc_print_dst_reg_maybe_pair(DisasContext *ctx, uint32_t regnum,
                                         bool pair)
{
    if (pair && !arc_is_arcv3(ctx)) {
        arc_print_dst_reg_pair(ctx, regnum);
    } else {
        arc_print_dst_reg(ctx, regnum);
    }
}

static void arc_print_src_reg_maybe_pair(DisasContext *ctx, uint32_t regnum,
                                         bool pair)
{
    if (pair && ctx->info->mach != bfd_mach_arcv3_64 &&
        ctx->info->mach != bfd_mach_arcv3_32) {
        arc_print_src_reg_pair(ctx, regnum);
    } else {
        arc_print_src_reg(ctx, regnum);
    }
}

static void arc_print_aux_reg(DisasContext *ctx, uint32_t aux)
{
    switch (aux) {
    case 0xa:
        arc_print_str(ctx, "status32");
        break;
    case 0x25:
        arc_print_str(ctx, "int_vector_base");
        break;
    case 0x400:
        arc_print_str(ctx, "eret");
        break;
    case 0x404:
        arc_print_str(ctx, "efa");
        break;
    default:
        arc_print_simm(ctx, aux);
        break;
    }
}

static void arc_print_reg_s(DisasContext *ctx, int regnum)
{
    g_assert(regnum >= 0 && regnum <= 7);

    if (regnum > 3) {
        regnum += 8;
    }

    (*ctx->info->fprintf_func)(ctx->info->stream, "%s", arc_get_register_name(regnum));
}

static void arc_print_src_reg_h(DisasContext *ctx, uint32_t regnum)
{
    g_assert(regnum <= 31);

    switch (regnum) {
    case ARC_REGNUM_R30:
        (*ctx->info->fprintf_func)(ctx->info->stream, "%#x", arc_parse_limm(ctx));
        break;
    case ARC_REGNUM_ILINK:
        arc_print_str(ctx, "r??");
        break;
    default:
        arc_print_str(ctx, arc_format_get_reg_name(ctx, regnum));
    }
}

static void arc_print_dst_reg_h(DisasContext *ctx, uint32_t regnum)
{
    g_assert(regnum <= 31);

    switch (regnum) {
    case ARC_REGNUM_R30:
        arc_print_str(ctx, "0");
        break;
    case ARC_REGNUM_ILINK:
        arc_print_str(ctx, "r??");
        break;
    default:
        arc_print_str(ctx, arc_format_get_reg_name(ctx, regnum));
    }
}

static void arc_print_r32dst_r32src_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t b, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a);
    arc_print_dot(ctx);
    arc_print_src_reg(ctx, b);
}

static void arc_print_r32dst_uimm32_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t uimm, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a);
    arc_print_dot(ctx);
    arc_print_uimm(ctx, uimm);
}

static void arc_print_r32dst_simm32_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, int32_t simm, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a);
    arc_print_dot(ctx);
    arc_print_simm(ctx, simm);
}

static void arc_print_r32dst_r32src_r32src_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t b, uint32_t c, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a);
    arc_print_dot(ctx);
    arc_print_src_reg(ctx, b);
    arc_print_dot(ctx);
    arc_print_src_reg(ctx, c);
}

static void arc_print_r32dst_r32src_uimm32_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t b, uint32_t uimm, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a);
    arc_print_dot(ctx);
    arc_print_src_reg(ctx, b);
    arc_print_dot(ctx);
    arc_print_uimm(ctx, uimm);
}

static void arc_print_r32dst_r32src_simm32_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t b, int32_t simm, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a);
    arc_print_dot(ctx);
    arc_print_src_reg(ctx, b);
    arc_print_dot(ctx);
    arc_print_simm(ctx, simm);
}

static void arc_print_simd_reg(DisasContext *ctx, const char *mnemonic,
                               uint32_t a, uint32_t b, uint32_t c,
                               uint32_t cond, bool a_pair, bool b_pair,
                               bool c_pair)
{
    arc_print_str(ctx, mnemonic);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg_maybe_pair(ctx, a, a_pair);
    arc_print_dot(ctx);
    arc_print_src_reg_maybe_pair(ctx, b, b_pair);
    arc_print_dot(ctx);
    arc_print_src_reg_maybe_pair(ctx, c, c_pair);
}

static void arc_print_simd_uimm(DisasContext *ctx, const char *mnemonic,
                                uint32_t a, uint32_t b, uint32_t imm,
                                uint32_t cond, bool a_pair, bool b_pair)
{
    arc_print_str(ctx, mnemonic);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg_maybe_pair(ctx, a, a_pair);
    arc_print_dot(ctx);
    arc_print_src_reg_maybe_pair(ctx, b, b_pair);
    arc_print_dot(ctx);
    arc_print_uimm(ctx, imm);
}

static void arc_print_simd_simm(DisasContext *ctx, const char *mnemonic,
                                uint32_t a, uint32_t b, int32_t imm,
                                uint32_t cond, bool a_pair, bool b_pair)
{
    arc_print_str(ctx, mnemonic);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg_maybe_pair(ctx, a, a_pair);
    arc_print_dot(ctx);
    arc_print_src_reg_maybe_pair(ctx, b, b_pair);
    arc_print_dot(ctx);
    arc_print_simm(ctx, imm);
}

/* 16-bit instructions formats */

static void arc_print_rs32_rs32_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t b, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a);
    arc_print_dot(ctx);
    arc_print_reg_s(ctx, b);
}

static void arc_print_rs32_uimm32_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t uimm, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a);
    arc_print_dot(ctx);
    arc_print_uimm(ctx, uimm);
}

static void arc_print_rs32_rs32_rs32_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t b, uint32_t c, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a);
    arc_print_dot(ctx);
    arc_print_reg_s(ctx, b);
    arc_print_dot(ctx);
    arc_print_reg_s(ctx, c);
}

static void arc_print_rs32_rs32_uimm32_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t b, int32_t uimm, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a);
    arc_print_dot(ctx);
    arc_print_reg_s(ctx, b);
    arc_print_dot(ctx);
    arc_print_uimm(ctx, uimm);
}

static void arc_print_rs32_rs32_rh32src_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t b, uint32_t c, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a);
    arc_print_dot(ctx);
    arc_print_reg_s(ctx, b);
    arc_print_dot(ctx);
    arc_print_src_reg_h(ctx, c);
}

static void arc_print_rh32dst_rh32src_simm32_f_cond(DisasContext *ctx, const char *mnemonic, uint32_t a, uint32_t b, int32_t simm, bool f, uint32_t cond)
{
    arc_print_str(ctx, mnemonic);
    arc_print_f(ctx, f, true);
    arc_print_cc(ctx, cond, true);
    arc_print_space(ctx);
    arc_print_dst_reg_h(ctx, a);
    arc_print_dot(ctx);
    arc_print_src_reg_h(ctx, b);
    arc_print_dot(ctx);
    arc_print_simm(ctx, simm);
}

/* ",[base<,offset>]" */
static void arc_print_ldst_address_with_signed_offset(DisasContext *ctx, uint32_t base_regnum, int32_t offset, bool always_emit_offset)
{
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, base_regnum);

    if (offset != 0 || always_emit_offset) {
        arc_print_str(ctx, ",");
        arc_print_simm(ctx, offset);
    }

    arc_print_str(ctx, "]");
}

static void arc_print_ldst_address_with_unsigned_offset(DisasContext *ctx, uint32_t base_regnum, uint32_t offset, bool always_emit_offset)
{
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, base_regnum);

    if (offset != 0 || always_emit_offset) {
        arc_print_str(ctx, ",");
        arc_print_uimm(ctx, offset);
    }

    arc_print_str(ctx, "]");
}

static void arc_print_ldst_s_address_with_unsigned_offset(DisasContext *ctx, uint32_t base_regnum, uint32_t offset, bool always_emit_offset)
{
    arc_print_str(ctx, ",[");
    arc_print_reg_s(ctx, base_regnum);

    if (offset != 0 || always_emit_offset) {
        arc_print_str(ctx, ",");
        arc_print_uimm(ctx, offset);
    }

    arc_print_str(ctx, "]");
}

/* 0 and 1 operand formats: flag, kflag */

#define ARC_DEF_DISAS_NO_OP(name, format) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_str(ctx, #name); \
        return true; \
    }

#define ARC_DEF_DISAS_R32SRC(name, format, r0) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_str(ctx, #name); \
        arc_print_space(ctx); \
        arc_print_src_reg(ctx, r0); \
        return true; \
    }

#define ARC_DEF_DISAS_R32SRC_COND(name, format, r0, cond) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_str(ctx, #name); \
        arc_print_cc(ctx, cond, true); \
        arc_print_space(ctx); \
        arc_print_src_reg(ctx, r0); \
        return true; \
    }

#define ARC_DEF_DISAS_UIMM32(name, format, uimm) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_str(ctx, #name); \
        arc_print_space(ctx); \
        arc_print_uimm(ctx, uimm); \
        return true; \
    }

#define ARC_DEF_DISAS_SIMM32(name, format, simm) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_str(ctx, #name); \
        arc_print_space(ctx); \
        arc_print_simm(ctx, simm); \
        return true; \
    }

#define ARC_DEF_DISAS_UIMM32_COND(name, format, uimm, cond) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_str(ctx, #name); \
        arc_print_cc(ctx, cond, true); \
        arc_print_space(ctx); \
        arc_print_uimm(ctx, uimm); \
        return true; \
    }

#define ARC_DEF_DISAS_SIMM32_COND(name, format, simm, cond) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_str(ctx, #name); \
        arc_print_cc(ctx, cond, true); \
        arc_print_space(ctx); \
        arc_print_simm(ctx, simm); \
        return true; \
    }

/* 2 operands formats */

#define ARC_DEF_DISAS_R32DST_R32SRC_F_COND(name, format, r0, r1, f, cond) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_r32dst_r32src_f_cond(ctx, #name, r0, r1, f, cond); \
        return true; \
    }

#define ARC_DEF_DISAS_R32DST_UIMM32_F_COND(name, format, r0, uimm, f, cond) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_r32dst_uimm32_f_cond(ctx, #name, r0, uimm, f, cond); \
        return true; \
    }

#define ARC_DEF_DISAS_R32DST_SIMM32_F_COND(name, format, r0, simm, f, cond) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_r32dst_simm32_f_cond(ctx, #name, r0, simm, f, cond); \
        return true; \
    }

#define ARC_DEF_DISAS_RS32_RS32(name, format, r0, r1) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_rs32_rs32_f_cond(ctx, #name, r0, r1, false, ARC_CC_AL); \
        return true; \
    }

#define ARC_DEF_DISAS_RS32_UIMM32(name, format, r0, uimm) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_rs32_uimm32_f_cond(ctx, #name, r0, uimm, false, ARC_CC_AL); \
        return true; \
    }

/* 3 operands formats */

#define ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(name, format, r0, r1, r2, f, cond) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_r32dst_r32src_r32src_f_cond(ctx, #name, r0, r1, r2, f, cond); \
        return true; \
    }

#define ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(name, format, r0, r1, uimm, f, cond) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_r32dst_r32src_uimm32_f_cond(ctx, #name, r0, r1, uimm, f, cond); \
        return true; \
    }

#define ARC_DEF_DISAS_R32DST_R32SRC_SIMM32_F_COND(name, format, r0, r1, simm, f, cond) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_r32dst_r32src_simm32_f_cond(ctx, #name, r0, r1, simm, f, cond); \
        return true; \
    }

#define ARC_DEF_DISAS_RS32_RS32_RS32(name, format, r0, r1, r2) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_rs32_rs32_rs32_f_cond(ctx, #name, r0, r1, r2, false, ARC_CC_AL); \
        return true; \
    }

#define ARC_DEF_DISAS_RS32_RS32_UIMM32(name, format, r0, r1, uimm) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_rs32_rs32_uimm32_f_cond(ctx, #name, r0, r1, uimm, false, ARC_CC_AL); \
        return true; \
    }

#define ARC_DEF_DISAS_RS32_RS32_RH32SRC(name, format, r0, r1, r2) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_rs32_rs32_rh32src_f_cond(ctx, #name, r0, r1, r2, false, ARC_CC_AL); \
        return true; \
    }

#define ARC_DEF_DISAS_RH32DST_RH32SRC_UIMM32(name, format, r0, r1, uimm) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_rh32dst_rh32src_uimm32_f_cond(ctx, #name, r0, r1, uimm, false, ARC_CC_AL); \
        return true; \
    }

#define ARC_DEF_DISAS_RH32DST_RH32SRC_SIMM32(name, format, r0, r1, simm) \
    static bool trans_##format(DisasContext *ctx, arg_##format *a) \
    { \
        arc_print_rh32dst_rh32src_simm32_f_cond(ctx, #name, r0, r1, simm, false, ARC_CC_AL); \
        return true; \
    }

/* Macros for most popular formats */

#define ARC_DEF_DISAS_DOP_REG_REG(name) \
    ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(name, name##_dop_reg_reg, a->a, a->b, a->c, a->f, ARC_CC_AL)

#define ARC_DEF_DISAS_DOP_REG_U6(name) \
    ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(name, name##_dop_reg_u6, a->a, a->b, a->imm, a->f, ARC_CC_AL)

#define ARC_DEF_DISAS_DOP_REG_S12(name) \
    ARC_DEF_DISAS_R32DST_R32SRC_SIMM32_F_COND(name, name##_dop_reg_s12, a->b, a->b, a->imm, a->f, ARC_CC_AL)

#define ARC_DEF_DISAS_DOP_COND_REG(name) \
    ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(name, name##_dop_cond_reg, a->b, a->b, a->c, a->f, a->cond)

#define ARC_DEF_DISAS_DOP_COND_U6(name) \
    ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(name, name##_dop_cond_u6, a->b, a->b, a->imm, a->f, a->cond)

#define ARC_DEF_DISAS_DOP(name) \
    ARC_DEF_DISAS_DOP_REG_REG(name) \
    ARC_DEF_DISAS_DOP_REG_U6(name) \
    ARC_DEF_DISAS_DOP_REG_S12(name) \
    ARC_DEF_DISAS_DOP_COND_REG(name) \
    ARC_DEF_DISAS_DOP_COND_U6(name)

#define ARC_DEF_DISAS_DOP_IMM16(name) \
    ARC_DEF_DISAS_DOP_REG_REG(name) \
    ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(name, name##_dop_reg_u6, \
                                               a->a, a->b, \
                                               (uint16_t)a->imm, a->f, \
                                               ARC_CC_AL) \
    ARC_DEF_DISAS_R32DST_R32SRC_SIMM32_F_COND(name, name##_dop_reg_s12, \
                                               a->b, a->b, \
                                               (int16_t)a->imm, a->f, \
                                               ARC_CC_AL) \
    ARC_DEF_DISAS_DOP_COND_REG(name) \
    ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(name, name##_dop_cond_u6, \
                                               a->b, a->b, \
                                               (uint16_t)a->imm, a->f, \
                                               a->cond)

#define ARC_DEF_DISAS_DOP_NO_F(name) \
    ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(name, name##_dop_reg_reg, \
                                               a->a, a->b, a->c, false, \
                                               ARC_CC_AL) \
    ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(name, name##_dop_reg_u6, \
                                               a->a, a->b, a->imm, false, \
                                               ARC_CC_AL) \
    ARC_DEF_DISAS_R32DST_R32SRC_SIMM32_F_COND(name, name##_dop_reg_s12, \
                                               a->b, a->b, a->imm, false, \
                                               ARC_CC_AL) \
    ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(name, name##_dop_cond_reg, \
                                               a->b, a->b, a->c, false, \
                                               a->cond) \
    ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(name, name##_dop_cond_u6, \
                                               a->b, a->b, a->imm, false, \
                                               a->cond)

#define ARC_DEF_DISAS_SIMD_DOP(name, a_pair, b_pair, c_pair, cond_c_pair, \
                               uimm, simm) \
    static bool trans_##name##_dop_reg_reg(DisasContext *ctx, \
                                           arg_##name##_dop_reg_reg *a) \
    { \
        arc_print_simd_reg(ctx, #name, a->a, a->b, a->c, ARC_CC_AL, \
                           a_pair, b_pair, c_pair); \
        return true; \
    } \
    static bool trans_##name##_dop_reg_u6(DisasContext *ctx, \
                                          arg_##name##_dop_reg_u6 *a) \
    { \
        arc_print_simd_uimm(ctx, #name, a->a, a->b, uimm, ARC_CC_AL, \
                            a_pair, b_pair); \
        return true; \
    } \
    static bool trans_##name##_dop_reg_s12(DisasContext *ctx, \
                                           arg_##name##_dop_reg_s12 *a) \
    { \
        arc_print_simd_simm(ctx, #name, a->b, a->b, simm, ARC_CC_AL, \
                            a_pair, b_pair); \
        return true; \
    } \
    static bool trans_##name##_dop_cond_reg(DisasContext *ctx, \
                                            arg_##name##_dop_cond_reg *a) \
    { \
        arc_print_simd_reg(ctx, #name, a->b, a->b, a->c, a->cond, \
                           a_pair, b_pair, cond_c_pair); \
        return true; \
    } \
    static bool trans_##name##_dop_cond_u6(DisasContext *ctx, \
                                           arg_##name##_dop_cond_u6 *a) \
    { \
        arc_print_simd_uimm(ctx, #name, a->b, a->b, uimm, a->cond, \
                            a_pair, b_pair); \
        return true; \
    }

/* DOP formats with 2 operands without F: cmp, tst, btst */

#define ARC_DEF_DISAS_DOP_2OP_REG_REG(name) \
    static bool trans_##name##_dop_reg_reg(DisasContext *ctx, arg_##name##_dop_reg_reg *a) \
    { \
        arc_print_r32dst_r32src_f_cond(ctx, #name, a->b, a->c, false, ARC_CC_AL); \
        return true; \
    }

#define ARC_DEF_DISAS_DOP_2OP_REG_U6(name) \
    static bool trans_##name##_dop_reg_u6(DisasContext *ctx, arg_##name##_dop_reg_u6 *a) \
    { \
        arc_print_r32dst_uimm32_f_cond(ctx, #name, a->b, a->imm, false, ARC_CC_AL); \
        return true; \
    }

#define ARC_DEF_DISAS_DOP_2OP_REG_S12(name) \
    static bool trans_##name##_dop_reg_s12(DisasContext *ctx, arg_##name##_dop_reg_s12 *a) \
    { \
        arc_print_r32dst_simm32_f_cond(ctx, #name, a->b, a->imm, false, ARC_CC_AL); \
        return true; \
    }

#define ARC_DEF_DISAS_DOP_2OP_COND_REG(name) \
    static bool trans_##name##_dop_cond_reg(DisasContext *ctx, arg_##name##_dop_cond_reg *a) \
    { \
        arc_print_r32dst_r32src_f_cond(ctx, #name, a->b, a->c, false , a->cond); \
        return true; \
    }

#define ARC_DEF_DISAS_DOP_2OP_COND_U6(name) \
    static bool trans_##name##_dop_cond_u6(DisasContext *ctx, arg_##name##_dop_cond_u6 *a) \
    { \
        arc_print_r32dst_uimm32_f_cond(ctx, #name, a->b, a->imm, false, a->cond); \
        return true; \
    }

#define ARC_DEF_DISAS_SOP_REG_REG(name) \
    ARC_DEF_DISAS_R32DST_R32SRC_F_COND(name, name##_sop_reg_reg, a->b, a->c, a->f, ARC_CC_AL)

#define ARC_DEF_DISAS_SOP_REG_U6(name) \
    ARC_DEF_DISAS_R32DST_UIMM32_F_COND(name, name##_sop_reg_u6, a->b, a->imm, a->f, ARC_CC_AL)

#define ARC_DEF_DISAS_S_DOP_2OP(name) \
    ARC_DEF_DISAS_RS32_RS32(name, name##_dop, a->b, a->c)

#define ARC_DEF_DISAS_S_DOP_3OP(name) \
    ARC_DEF_DISAS_RS32_RS32_RS32(name, name##_dop, a->b, a->b, a->c)

ARC_DEF_DISAS_SOP_REG_REG(abs)
ARC_DEF_DISAS_SOP_REG_U6(abs)
ARC_DEF_DISAS_S_DOP_2OP(abs_s)

ARC_DEF_DISAS_DOP(add)

ARC_DEF_DISAS_RS32_RS32_RS32(add_s, add_s_a_b_c, a->a, a->b, a->c)
ARC_DEF_DISAS_RS32_RS32_RH32SRC(add_s, add_s_b_b_h, a->b, a->b, a->h)
ARC_DEF_DISAS_RH32DST_RH32SRC_SIMM32(add_s, add_s_h_h_s3, a->h, a->h, a->imm)
ARC_DEF_DISAS_RS32_RS32_UIMM32(add_s, add_s_b_b_u7, a->b, a->b, a->imm)
ARC_DEF_DISAS_RS32_RS32_UIMM32(add_s, add_s_c_b_u3, a->c, a->b, a->imm)

/* add_s b,sp,u7 */
static bool trans_add_s_b_sp_u7(DisasContext *ctx, arg_add_s_b_sp_u7 *a)
{
    arc_print_str(ctx, "add_s ");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    return true;
}

/* add_s sp,sp,u7 */
static bool trans_add_s_sp_sp_u7(DisasContext *ctx, arg_add_s_sp_sp_u7 *a)
{
    arc_print_str(ctx, "add_s ");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    return true;
}

/* add_s r0,gp,s11 */
static bool trans_add_s_r0_gp_s11(DisasContext *ctx, arg_add_s_r0_gp_s11 *a)
{
    arc_print_str(ctx, "add_s r0,");
    arc_print_src_reg(ctx, ARC_REGNUM_GP);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->imm);
    return true;
}

/* add_s a,b,u6 (CD2 / density form) */
static bool trans_add_s_r01_b_u6(DisasContext *ctx, arg_add_s_r01_b_u6 *a)
{
    arc_print_str(ctx, "add_s ");
    arc_print_reg_s(ctx, a->a);
    arc_print_str(ctx, ",");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    return true;
}

ARC_DEF_DISAS_DOP(adc)

ARC_DEF_DISAS_DOP(add1)
ARC_DEF_DISAS_S_DOP_3OP(add1_s)

ARC_DEF_DISAS_DOP(add2)
ARC_DEF_DISAS_S_DOP_3OP(add2_s)

ARC_DEF_DISAS_DOP(add3)
ARC_DEF_DISAS_S_DOP_3OP(add3_s)

/* AEX b,[c] */
static bool trans_aex_dop_reg_reg(DisasContext *ctx, arg_aex_dop_reg_reg *a)
{
    arc_print_str(ctx, "aex ");
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* AEX b,[u6] */
static bool trans_aex_dop_reg_u6(DisasContext *ctx, arg_aex_dop_reg_u6 *a)
{
    arc_print_str(ctx, "aex ");
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

/* AEX b,[s12] */
static bool trans_aex_dop_reg_s12(DisasContext *ctx, arg_aex_dop_reg_s12 *a)
{
    arc_print_str(ctx, "aex ");
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

/* AEX<.cc> b,[c] */
static bool trans_aex_dop_cond_reg(DisasContext *ctx, arg_aex_dop_cond_reg *a)
{
    arc_print_str(ctx, "aex");
    arc_print_cc(ctx, a->cond, true);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* AEX<.cc> b,[c] */
static bool trans_aex_dop_cond_u6(DisasContext *ctx, arg_aex_dop_cond_u6 *a)
{
    arc_print_str(ctx, "aex");
    arc_print_cc(ctx, a->cond, true);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

ARC_DEF_DISAS_DOP(and)
ARC_DEF_DISAS_S_DOP_3OP(and_s)

ARC_DEF_DISAS_SOP_REG_REG(asl)
ARC_DEF_DISAS_SOP_REG_U6(asl)
ARC_DEF_DISAS_S_DOP_2OP(asl_s)

ARC_DEF_DISAS_DOP(aslm)
ARC_DEF_DISAS_RS32_RS32_UIMM32(aslm_s, aslm_s_c_b_u3, a->c, a->b, a->imm)
ARC_DEF_DISAS_RS32_RS32_RS32(aslm_s, aslm_s_b_b_c, a->b, a->b, a->c)
ARC_DEF_DISAS_RS32_RS32_UIMM32(aslm_s, aslm_s_b_b_u5, a->b, a->b, a->imm)

ARC_DEF_DISAS_SOP_REG_REG(asr)
ARC_DEF_DISAS_SOP_REG_U6(asr)
ARC_DEF_DISAS_S_DOP_2OP(asr_s)

ARC_DEF_DISAS_SOP_REG_REG(asr16)
ARC_DEF_DISAS_SOP_REG_U6(asr16)

ARC_DEF_DISAS_SOP_REG_REG(asr8)
ARC_DEF_DISAS_SOP_REG_U6(asr8)

ARC_DEF_DISAS_DOP(asrm)
ARC_DEF_DISAS_RS32_RS32_UIMM32(asrm_s, asrm_s_c_b_u3, a->c, a->b, a->imm)
ARC_DEF_DISAS_RS32_RS32_RS32(asrm_s, asrm_s_b_b_c, a->b, a->b, a->c)
ARC_DEF_DISAS_RS32_RS32_UIMM32(asrm_s, asrm_s_b_b_u5, a->b, a->b, a->imm)

static bool trans_b_cond(DisasContext *ctx, arg_b_cond *a)
{
    arc_print_str(ctx, "b");
    arc_print_cc(ctx, a->cond, false);
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_uimm(ctx, a->imm);

    return true;
}

static bool trans_b_far(DisasContext *ctx, arg_b_far *a)
{
    arc_print_str(ctx, "b");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_uimm(ctx, a->imm);

    return true;
}

ARC_DEF_DISAS_UIMM32(b_s, b_s, a->imm)
ARC_DEF_DISAS_UIMM32(beq_s, beq_s, a->imm)
ARC_DEF_DISAS_UIMM32(bne_s, bne_s, a->imm)

static bool trans_bcc_s(DisasContext *ctx, arg_bcc_s *a)
{
    const char *mnemonic;

    switch (a->cond) {
    case ARC_CC_GT: mnemonic = "bgt_s"; break;
    case ARC_CC_GE: mnemonic = "bge_s"; break;
    case ARC_CC_LT: mnemonic = "blt_s"; break;
    case ARC_CC_LE: mnemonic = "ble_s"; break;
    case ARC_CC_HI: mnemonic = "bhi_s"; break;
    case ARC_CC_HS: mnemonic = "bhs_s"; break;
    case ARC_CC_LO: mnemonic = "blo_s"; break;
    case ARC_CC_LS: mnemonic = "bls_s"; break;
    default:        mnemonic = "b??_s"; break;
    }

    arc_print_str(ctx, mnemonic);
    arc_print_space(ctx);
    arc_print_uimm(ctx, a->imm);

    return true;
}

static bool trans_bl_cond(DisasContext *ctx, arg_bl_cond *a)
{
    arc_print_str(ctx, "bl");
    arc_print_cc(ctx, a->cond, false);
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_uimm(ctx, a->imm);

    return true;
}

static bool trans_bl_far(DisasContext *ctx, arg_bl_far *a)
{
    arc_print_str(ctx, "bl");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_uimm(ctx, a->imm);

    return true;
}

ARC_DEF_DISAS_UIMM32(bl_s, bl_s, a->imm)

static bool trans_bl_s_limm(DisasContext *ctx, arg_bl_s_limm *a)
{
    arc_print_str(ctx, "bl_s ");
    arc_print_simm(ctx, (int32_t)arc_parse_limm(ctx) << 2);

    return true;
}

static bool trans_bi(DisasContext *ctx, arg_bi *a)
{
    arc_print_str(ctx, "bi [");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

static bool trans_bih(DisasContext *ctx, arg_bih *a)
{
    arc_print_str(ctx, "bih [");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* BBIT0<.d> b,c,s9 */
static bool trans_bbit0_reg(DisasContext *ctx, arg_bbit0_reg *a)
{
    arc_print_str(ctx, "bbit0");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->offset);

    return true;
}

/* BBIT0<.d> b,u6,s9 */
static bool trans_bbit0_imm(DisasContext *ctx, arg_bbit0_imm *a)
{
    arc_print_str(ctx, "bbit0");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->offset);

    return true;
}

/* BBIT1<.d> b,c,s9 */
static bool trans_bbit1_reg(DisasContext *ctx, arg_bbit1_reg *a)
{
    arc_print_str(ctx, "bbit1");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->offset);

    return true;
}

/* BBIT1<.d> b,u6,s9 */
static bool trans_bbit1_imm(DisasContext *ctx, arg_bbit1_imm *a)
{
    arc_print_str(ctx, "bbit1");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->offset);

    return true;
}

static const char *arc_get_brcc_mnemonic(int cond)
{
    switch (cond) {
    case ARC_CC_EQ:
        return "breq";
    case ARC_CC_NE:
        return "brne";
    case ARC_CC_LT:
        return "brlt";
    case ARC_CC_GE:
        return "brge";
    case ARC_CC_LO:
        return "brlo";
    case ARC_CC_HS:
        return "brhs";
    default:
        g_assert_not_reached();
    }
}

/* BRcc<.d> b,c,s9 */
static bool trans_brcc_reg(DisasContext *ctx, arg_brcc_reg *a)
{
    arc_print_str(ctx, arc_get_brcc_mnemonic(a->cond));
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->offset);

    return true;
}

/* BRcc<.d> b,u6,s9 */
static bool trans_brcc_u6(DisasContext *ctx, arg_brcc_u6 *a)
{
    arc_print_str(ctx, arc_get_brcc_mnemonic(a->cond));
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->offset);

    return true;
}

/*
 * BRNE_S b,0,s8
 * BREQ_S b,0,s8
 */
static bool trans_brcc_s(DisasContext *ctx, arg_brcc_s *a)
{
    const char *mnemonic;

    switch (a->cond) {
    case ARC_CC_EQ:
        mnemonic = arc_is_arcv3_64(ctx) ? "breql_s" : "breq_s";
        break;
    case ARC_CC_NE:
        mnemonic = arc_is_arcv3_64(ctx) ? "brnel_s" : "brne_s";
        break;
    default:
        g_assert_not_reached();
    }

    arc_print_str(ctx, mnemonic);
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",0,");
    arc_print_simm(ctx, a->offset);

    return true;
}

ARC_DEF_DISAS_DOP(bclr)
ARC_DEF_DISAS_RS32_RS32_UIMM32(bclr_s, bclr_s, a->b, a->b, a->imm)

ARC_DEF_DISAS_DOP(bic)
ARC_DEF_DISAS_S_DOP_3OP(bic_s)

ARC_DEF_DISAS_DOP(bmsk)
ARC_DEF_DISAS_RS32_RS32_UIMM32(bmsk_s, bmsk_s, a->b, a->b, a->imm)

ARC_DEF_DISAS_DOP(bmskn)

ARC_DEF_DISAS_NO_OP(brk, brk)
ARC_DEF_DISAS_NO_OP(brk_s, brk_s)

ARC_DEF_DISAS_DOP(bset)
ARC_DEF_DISAS_RS32_RS32_UIMM32(bset_s, bset_s, a->b, a->b, a->imm)

ARC_DEF_DISAS_DOP_2OP_REG_REG(btst)
ARC_DEF_DISAS_DOP_2OP_REG_U6(btst)
ARC_DEF_DISAS_DOP_2OP_REG_S12(btst)
ARC_DEF_DISAS_DOP_2OP_COND_REG(btst)
ARC_DEF_DISAS_DOP_2OP_COND_U6(btst)
ARC_DEF_DISAS_RS32_UIMM32(btst, btst_s, a->b, a->imm)

ARC_DEF_DISAS_DOP(bxor)

ARC_DEF_DISAS_R32SRC(clri, clri_reg, a->c)
ARC_DEF_DISAS_UIMM32(clri, clri_imm, a->imm)

ARC_DEF_DISAS_DOP_2OP_REG_REG(cmp)
ARC_DEF_DISAS_DOP_2OP_REG_U6(cmp)
ARC_DEF_DISAS_DOP_2OP_REG_S12(cmp)
ARC_DEF_DISAS_DOP_2OP_COND_REG(cmp)
ARC_DEF_DISAS_DOP_2OP_COND_U6(cmp)

/* cmp_s b,h */
static bool trans_cmp_s_b_h(DisasContext *ctx, arg_cmp_s_b_h *a)
{
    arc_print_str(ctx, "cmp_s ");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg_h(ctx, a->h);

    return true;
}

/* cmp_s h,s3 */
static bool trans_cmp_s_h_s3(DisasContext *ctx, arg_cmp_s_h_s3 *a)
{
    arc_print_str(ctx, "cmp_s ");
    arc_print_src_reg_h(ctx, a->h);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->imm);

    return true;
}

ARC_DEF_DISAS_RS32_UIMM32(cmp_s, cmp_s_b_u7, a->b, a->imm)

static bool trans_dbnz(DisasContext *ctx, arg_dbnz *a)
{
    arc_print_str(ctx, "dbnz");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->imm);

    return true;
}

ARC_DEF_DISAS_DOP(div)

ARC_DEF_DISAS_DOP(divu)

ARC_DEF_DISAS_UIMM32(dmb, dmb, a->imm)

ARC_DEF_DISAS_NO_OP(dsync, dsync)

ARC_DEF_DISAS_UIMM32(enter_s, enter_s, a->imm)
ARC_DEF_DISAS_UIMM32(leave_s, leave_s, a->imm)
ARC_DEF_DISAS_UIMM32(enter, enter, a->imm)
ARC_DEF_DISAS_UIMM32(leave, leave, a->imm)

/* EX<.di> b,[c] */
static bool trans_ex_sop_reg_reg(DisasContext *ctx, arg_ex_sop_reg_reg *a)
{
    arc_print_str(ctx, "ex");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* EX<.di> b,[u6] */
static bool trans_ex_sop_reg_u6(DisasContext *ctx, arg_ex_sop_reg_u6 *a)
{
    arc_print_str(ctx, "ex");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

ARC_DEF_DISAS_SOP_REG_REG(extb)
ARC_DEF_DISAS_SOP_REG_U6(extb)
ARC_DEF_DISAS_S_DOP_2OP(extb_s)

ARC_DEF_DISAS_SOP_REG_REG(exth)
ARC_DEF_DISAS_SOP_REG_U6(exth)
ARC_DEF_DISAS_S_DOP_2OP(exth_s)

ARC_DEF_DISAS_SOP_REG_REG(ffs)
ARC_DEF_DISAS_SOP_REG_U6(ffs)

ARC_DEF_DISAS_R32SRC(flag, flag_dop_reg_reg, a->c)
ARC_DEF_DISAS_UIMM32(flag, flag_dop_reg_u6, a->imm)
ARC_DEF_DISAS_UIMM32(flag, flag_dop_reg_s12, a->imm)
ARC_DEF_DISAS_R32SRC_COND(flag, flag_dop_reg_reg_cond, a->c, a->cond)
ARC_DEF_DISAS_UIMM32_COND(flag, flag_dop_reg_u6_cond, a->imm, a->cond)

ARC_DEF_DISAS_SOP_REG_REG(fls)
ARC_DEF_DISAS_SOP_REG_U6(fls)

static bool trans_j_reg(DisasContext *ctx, arg_j_reg *a)
{
    arc_print_str(ctx, "j");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);

    if (arc_regnum_is_limm(ctx, a->c)) {
        arc_print_uimm(ctx, arc_parse_limm(ctx));
    } else {
        arc_print_str(ctx, "[");
        arc_print_src_reg(ctx, a->c);
        arc_print_str(ctx, "]");
    }

    return true;
}

static bool trans_j_u6(DisasContext *ctx, arg_j_u6 *a)
{
    arc_print_str(ctx, "j");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_uimm(ctx, a->imm);

    return true;
}

static bool trans_j_s12(DisasContext *ctx, arg_j_s12 *a)
{
    arc_print_str(ctx, "j");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_simm(ctx, a->imm);

    return true;
}

static bool trans_jcc_reg(DisasContext *ctx, arg_jcc_reg *a)
{
    arc_print_str(ctx, "j");
    arc_print_cc(ctx, a->cond, false);
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);

    if (arc_regnum_is_limm(ctx, a->c)) {
        arc_print_uimm(ctx, arc_parse_limm(ctx));
    } else {
        arc_print_str(ctx, "[");
        arc_print_src_reg(ctx, a->c);
        arc_print_str(ctx, "]");
    }

    return true;
}

static bool trans_jcc_u6(DisasContext *ctx, arg_jcc_u6 *a)
{
    arc_print_str(ctx, "j");
    arc_print_cc(ctx, a->cond, false);
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_uimm(ctx, a->imm);

    return true;
}

static bool trans_j_s_reg(DisasContext *ctx, arg_j_s_reg *a)
{
    arc_print_str(ctx, "j_s");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_str(ctx, "[");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, "]");

    return true;
}

static bool trans_j_s_blink(DisasContext *ctx, arg_j_s_blink *a)
{
    arc_print_str(ctx, "j_s");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_str(ctx, "[");
    arc_print_src_reg(ctx, ARC_REGNUM_BLINK);
    arc_print_str(ctx, "]");

    return true;
}

static bool trans_jeq_s_blink(DisasContext *ctx, arg_jeq_s_blink *a)
{
    arc_print_str(ctx, "jeq_s [blink]");

    return true;
}

static bool trans_jne_s_blink(DisasContext *ctx, arg_jne_s_blink *a)
{
    arc_print_str(ctx, "jne_s [blink]");

    return true;
}

static bool trans_jl_reg(DisasContext *ctx, arg_jl_reg *a)
{
    arc_print_str(ctx, "jl");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);

    if (arc_regnum_is_limm(ctx, a->c)) {
        arc_print_uimm(ctx, arc_parse_limm(ctx));
    } else {
        arc_print_str(ctx, "[");
        arc_print_src_reg(ctx, a->c);
        arc_print_str(ctx, "]");
    }

    return true;
}

static bool trans_jl_u6(DisasContext *ctx, arg_jl_u6 *a)
{
    arc_print_str(ctx, "jl");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_uimm(ctx, a->imm);

    return true;
}

static bool trans_jl_s12(DisasContext *ctx, arg_jl_s12 *a)
{
    arc_print_str(ctx, "jl");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_simm(ctx, a->imm);

    return true;
}

static bool trans_jlcc_reg(DisasContext *ctx, arg_jlcc_reg *a)
{
    arc_print_str(ctx, "jl");
    arc_print_cc(ctx, a->cond, false);
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);

    if (arc_regnum_is_limm(ctx, a->c)) {
        arc_print_uimm(ctx, arc_parse_limm(ctx));
    } else {
        arc_print_str(ctx, "[");
        arc_print_src_reg(ctx, a->c);
        arc_print_str(ctx, "]");
    }

    return true;
}

static bool trans_jlcc_u6(DisasContext *ctx, arg_jlcc_u6 *a)
{
    arc_print_str(ctx, "j");
    arc_print_cc(ctx, a->cond, false);
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_uimm(ctx, a->imm);

    return true;
}

static bool trans_jl_s_reg(DisasContext *ctx, arg_jl_s_reg *a)
{
    arc_print_str(ctx, "jl_s");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_str(ctx, "[");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, "]");

    return true;
}

/* JLI_S u10 */
static bool trans_jli_s(DisasContext *ctx, arg_jli_s *a)
{
    arc_print_str(ctx, "jli_s ");
    arc_print_uimm(ctx, a->offset);

    return true;
}

/* JLI_S u10 */
static bool trans_jli_s_64(DisasContext *ctx, arg_jli_s *a)
{
    arc_print_str(ctx, "jli_s ");
    arc_print_uimm(ctx, a->offset);

    return true;
}

ARC_DEF_DISAS_R32SRC(kflag, kflag_dop_reg_reg, a->c)
ARC_DEF_DISAS_UIMM32(kflag, kflag_dop_reg_u6, a->imm)
ARC_DEF_DISAS_UIMM32(kflag, kflag_dop_reg_s12, a->imm)
ARC_DEF_DISAS_R32SRC_COND(kflag, kflag_dop_reg_reg_cond, a->c, a->cond)
ARC_DEF_DISAS_UIMM32_COND(kflag, kflag_dop_reg_u6_cond, a->imm, a->cond)

/* LD_S a,[b,c] */
static bool trans_ld_s_a_b_c(DisasContext *ctx, arg_ld_s_a_b_c *a)
{
    arc_print_str(ctx, "ld_s");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->a);
    arc_print_str(ctx, ",[");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_reg_s(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* LD_S b,[SP,u7] */
static bool trans_ld_s_b_sp_u7(DisasContext *ctx, arg_ld_s_b_sp_u7 *a)
{
    arc_print_str(ctx, "ld_s");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->b);
    arc_print_ldst_address_with_unsigned_offset(ctx, ARC_REGNUM_SP, a->imm, true);

    return true;
}

/* LD_S b,[PCL,u10] */
static bool trans_ld_s_b_pcl_u10(DisasContext *ctx, arg_ld_s_b_pcl_u10 *a)
{
    arc_print_str(ctx, "ld_s");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->b);
    arc_print_ldst_address_with_unsigned_offset(ctx, ARC_REGNUM_PCL, a->imm, true);

    return true;
}

/* LD_S c,[b,u7] */
static bool trans_ld_s_c_b_u7(DisasContext *ctx, arg_ld_s_c_b_u7 *a)
{
    arc_print_str(ctx, "ld_s");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->c);
    arc_print_ldst_s_address_with_unsigned_offset(ctx, a->b, a->imm, true);

    return true;
}

/* LD_S R0,[GP,s11] */
static bool trans_ld_s_r0_gp_s11(DisasContext *ctx, arg_ld_s_r0_gp_s11 *a)
{
    arc_print_str(ctx, "ld_s");
    arc_print_space(ctx);
    arc_print_str(ctx, "r0");
    arc_print_ldst_address_with_signed_offset(ctx, ARC_REGNUM_GP, a->imm, true);

    return true;
}

/* LDB_S a,[b,c] */
static bool trans_ldb_s_a_b_c(DisasContext *ctx, arg_ldb_s_a_b_c *a)
{
    arc_print_str(ctx, "ldb_s");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->a);
    arc_print_str(ctx, ",[");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_reg_s(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* LDB_S b,[SP,u7] */
static bool trans_ldb_s_b_sp_u7(DisasContext *ctx, arg_ldb_s_b_sp_u7 *a)
{
    arc_print_str(ctx, "ldb_s");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->b);
    arc_print_ldst_address_with_unsigned_offset(ctx, ARC_REGNUM_SP, a->imm, true);

    return true;
}

/* LDB_S c,[b,u5] */
static bool trans_ldb_s_c_b_u5(DisasContext *ctx, arg_ldb_s_c_b_u5 *a)
{
    arc_print_str(ctx, "ldb_s");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->c);
    arc_print_ldst_s_address_with_unsigned_offset(ctx, a->b, a->imm, true);

    return true;
}

/* LDB_S R0,[GP,s9] */
static bool trans_ldb_s_r0_gp_s9(DisasContext *ctx, arg_ldb_s_r0_gp_s9 *a)
{
    arc_print_str(ctx, "ldb_s");
    arc_print_space(ctx);
    arc_print_str(ctx, "r0");
    arc_print_ldst_address_with_signed_offset(ctx, ARC_REGNUM_GP, a->imm, true);

    return true;
}

/* LDH_S a,[b,c] */
static bool trans_ldh_s_a_b_c(DisasContext *ctx, arg_ldh_s_a_b_c *a)
{
    arc_print_str(ctx, "ldh_s");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->a);
    arc_print_str(ctx, ",[");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_reg_s(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* LDH_S c,[b,u6] */
static bool trans_ldh_s_c_b_u6(DisasContext *ctx, arg_ldh_s_c_b_u6 *a)
{
    arc_print_str(ctx, "ldh_s");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->c);
    arc_print_ldst_s_address_with_unsigned_offset(ctx, a->b, a->imm, true);

    return true;
}

/* LDH_S R0,[GP,s10] */
static bool trans_ldh_s_r0_gp_s10(DisasContext *ctx, arg_ldh_s_r0_gp_s10 *a)
{
    arc_print_str(ctx, "ldh_s");
    arc_print_space(ctx);
    arc_print_str(ctx, "r0");
    arc_print_ldst_address_with_signed_offset(ctx, ARC_REGNUM_GP, a->imm, true);

    return true;
}

/* LDH_S.X c,[b,u6] */
static bool trans_ldh_s_x_c_b_u6(DisasContext *ctx, arg_ldh_s_x_c_b_u6 *a)
{
    arc_print_str(ctx, "ldh_s.x");
    arc_print_space(ctx);
    arc_print_reg_s(ctx, a->c);
    arc_print_ldst_s_address_with_unsigned_offset(ctx, a->b, a->imm, true);

    return true;
}

/* LD_S R0-R3,[h,u5] */
static bool trans_ld_s_a_h_u5(DisasContext *ctx, arg_ld_s_a_h_u5 *a)
{
    arc_print_str(ctx, "ld_s ");
    arc_print_reg_s(ctx, a->a);
    arc_print_str(ctx, ",[");
    arc_print_src_reg_h(ctx, a->h);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->offset);
    arc_print_str(ctx, "]");

    return true;
}

/* LD_S.AS a,[b,c] */
static bool trans_ld_s_as_a_b_c(DisasContext *ctx, arg_ld_s_as_a_b_c *a)
{
    arc_print_str(ctx, "ld_s.as ");
    arc_print_reg_s(ctx, a->a);
    arc_print_str(ctx, ",[");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_reg_s(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* LD_S R1,[GP,s11] */
static bool trans_ld_s_r1_gp_s11(DisasContext *ctx, arg_ld_s_r1_gp_s11 *a)
{
    arc_print_str(ctx, "ld_s ");
    arc_print_str(ctx, "r1");
    arc_print_ldst_address_with_signed_offset(ctx, ARC_REGNUM_GP, a->offset, true);

    return true;
}

/* LDI b,[c] */
static bool trans_ldi_b_c(DisasContext *ctx, arg_ldi_b_c *a)
{
    arc_print_str(ctx, "ldi ");
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* LDI b,[u6] */
static bool trans_ldi_b_u6(DisasContext *ctx, arg_ldi_b_u6 *a)
{
    arc_print_str(ctx, "ldi ");
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->offset);
    arc_print_str(ctx, "]");

    return true;
}

/* LDI b,[s12] */
static bool trans_ldi_b_s12(DisasContext *ctx, arg_ldi_b_s12 *a)
{
    arc_print_str(ctx, "ldi ");
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_simm(ctx, a->offset);
    arc_print_str(ctx, "]");

    return true;
}

/* LDI_S b,[u7] */
static bool trans_ldi_s_b_u(DisasContext *ctx, arg_ldi_s_b_u *a)
{
    arc_print_str(ctx, "ldi_s ");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->offset);
    arc_print_str(ctx, "]");

    return true;
}

/* LLOCK<.di> b,[c] */
static bool trans_llock_reg(DisasContext *ctx, arg_llock_reg *a)
{
    arc_print_str(ctx, "llock");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* LLOCK<.di> b,[u6] */
static bool trans_llock_imm(DisasContext *ctx, arg_llock_imm *a)
{
    arc_print_str(ctx, "llock");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

/* LLOCKD<.di> b,[c] */
static bool trans_llockd_reg(DisasContext *ctx, arg_llockd_reg *a)
{
    arc_print_str(ctx, "llockd");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* LLOCKD<.di> b,[u6] */
static bool trans_llockd_imm(DisasContext *ctx, arg_llockd_imm *a)
{
    arc_print_str(ctx, "llockd");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

ARC_DEF_DISAS_UIMM32(lp, lp_u7, a->imm)
ARC_DEF_DISAS_UIMM32_COND(lp, lp_u7_cond, a->imm, a->cond)
ARC_DEF_DISAS_SIMM32(lp, lp_s13, a->imm)

static bool trans_lr_dop_reg_reg(DisasContext *ctx, arg_lr_dop_reg_reg *a)
{
    arc_print_str(ctx, "lr ");
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

static bool trans_lr_dop_reg_u6(DisasContext *ctx, arg_lr_dop_reg_u6 *a)
{
    arc_print_str(ctx, "lr ");
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

static bool trans_lr_dop_reg_s12(DisasContext *ctx, arg_lr_dop_reg_s12 *a)
{
    arc_print_str(ctx, "lr ");
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

ARC_DEF_DISAS_SOP_REG_REG(lsl16)
ARC_DEF_DISAS_SOP_REG_U6(lsl16)

ARC_DEF_DISAS_SOP_REG_REG(lsl8)
ARC_DEF_DISAS_SOP_REG_U6(lsl8)

ARC_DEF_DISAS_SOP_REG_REG(lsr)
ARC_DEF_DISAS_SOP_REG_U6(lsr)
ARC_DEF_DISAS_S_DOP_2OP(lsr_s)

ARC_DEF_DISAS_DOP(lsrm)
ARC_DEF_DISAS_S_DOP_3OP(lsrm_s)
ARC_DEF_DISAS_RS32_RS32_UIMM32(lsrm_s, lsrm_s_b_b_u5, a->b, a->b, a->imm)

ARC_DEF_DISAS_SOP_REG_REG(lsr16)
ARC_DEF_DISAS_SOP_REG_U6(lsr16)

ARC_DEF_DISAS_SOP_REG_REG(lsr8)
ARC_DEF_DISAS_SOP_REG_U6(lsr8)

ARC_DEF_DISAS_DOP(max)

ARC_DEF_DISAS_DOP(min)

ARC_DEF_DISAS_R32DST_R32SRC_F_COND(mov, mov_dop_reg_reg, a->b, a->c, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_UIMM32_F_COND(mov, mov_dop_reg_u6, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_SIMM32_F_COND(mov, mov_dop_reg_s12, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_F_COND(mov, mov_dop_cond_reg, a->b, a->c, a->f, a->cond)
ARC_DEF_DISAS_R32DST_UIMM32_F_COND(mov, mov_dop_cond_u6, a->b, a->imm, a->f, a->cond)

/* mov_s.ne b,h */
static bool trans_mov_s_b_h(DisasContext *ctx, arg_mov_s_b_h *a)
{
    arc_print_str(ctx, "mov_s.ne ");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg_h(ctx, a->h);
    return true;
}

static bool trans_mov_s_h_s3(DisasContext *ctx, arg_mov_s_h_s3 *a)
{
    arc_print_str(ctx, "mov_s ");
    arc_print_dst_reg_h(ctx, a->h);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);

    return true;
}

static bool trans_mov_s_g_h(DisasContext *ctx, arg_mov_s_g_h *a)
{
    arc_print_str(ctx, "mov_s ");
    arc_print_dst_reg_h(ctx, a->g);
    arc_print_str(ctx, ",");
    arc_print_src_reg_h(ctx, a->h);

    return true;
}

static bool trans_mov_s_b_u8(DisasContext *ctx, arg_mov_s_b_u8 *a)
{
    arc_print_str(ctx, ctx->info->mach == bfd_mach_arcv3_64
                       ? "movl_s " : "mov_s ");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    return true;
}

ARC_DEF_DISAS_R32DST_R32SRC_F_COND(neg, neg, a->a, a->b, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_F_COND(neg, neg_cond, a->b, a->b, a->f, a->cond)
ARC_DEF_DISAS_S_DOP_2OP(neg_s)

ARC_DEF_DISAS_NO_OP(nop_s, nop_s)

ARC_DEF_DISAS_SOP_REG_REG(norm)
ARC_DEF_DISAS_SOP_REG_U6(norm)

ARC_DEF_DISAS_SOP_REG_REG(normh)
ARC_DEF_DISAS_SOP_REG_U6(normh)

ARC_DEF_DISAS_SOP_REG_REG(not)
ARC_DEF_DISAS_SOP_REG_U6(not)
ARC_DEF_DISAS_S_DOP_2OP(not_s)

ARC_DEF_DISAS_DOP(or)
ARC_DEF_DISAS_S_DOP_3OP(or_s)

/* POP_S b */
static bool trans_pop_s(DisasContext *ctx, arg_pop_s *a)
{
    arc_print_str(ctx, "pop_s ");
    arc_print_reg_s(ctx, a->b);

    return true;
}

/* POP_S BLINK */
static bool trans_pop_s_blink(DisasContext *ctx, arg_pop_s_blink *a)
{
    arc_print_str(ctx, "pop_s blink");

    return true;
}

/* PUSH_S b */
static bool trans_push_s(DisasContext *ctx, arg_push_s *a)
{
    arc_print_str(ctx, "push_s ");
    arc_print_reg_s(ctx, a->b);

    return true;
}

/* PUSH_S BLINK */
static bool trans_push_s_blink(DisasContext *ctx, arg_push_s_blink *a)
{
    arc_print_str(ctx, "push_s blink");

    return true;
}

ARC_DEF_DISAS_DOP_2OP_REG_REG(rcmp)
ARC_DEF_DISAS_DOP_2OP_REG_U6(rcmp)
ARC_DEF_DISAS_DOP_2OP_REG_S12(rcmp)
ARC_DEF_DISAS_DOP_2OP_COND_REG(rcmp)
ARC_DEF_DISAS_DOP_2OP_COND_U6(rcmp)

ARC_DEF_DISAS_DOP(rem)

ARC_DEF_DISAS_DOP(remu)

ARC_DEF_DISAS_SOP_REG_REG(rol)
ARC_DEF_DISAS_SOP_REG_U6(rol)

ARC_DEF_DISAS_SOP_REG_REG(rol8)
ARC_DEF_DISAS_SOP_REG_U6(rol8)

ARC_DEF_DISAS_SOP_REG_REG(ror)
ARC_DEF_DISAS_SOP_REG_U6(ror)

ARC_DEF_DISAS_SOP_REG_REG(ror8)
ARC_DEF_DISAS_SOP_REG_U6(ror8)

ARC_DEF_DISAS_SOP_REG_REG(rlc)
ARC_DEF_DISAS_SOP_REG_U6(rlc)

ARC_DEF_DISAS_SOP_REG_REG(rrc)
ARC_DEF_DISAS_SOP_REG_U6(rrc)

ARC_DEF_DISAS_DOP(rorm)

ARC_DEF_DISAS_DOP(rsub)

ARC_DEF_DISAS_NO_OP(rtie, rtie)

ARC_DEF_DISAS_DOP(sbc)

/* SCOND<.di> b,[c] */
static bool trans_scond_reg(DisasContext *ctx, arg_scond_reg *a)
{
    arc_print_str(ctx, "scond");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* SCOND<.di> b,[u6] */
static bool trans_scond_imm(DisasContext *ctx, arg_scond_imm *a)
{
    arc_print_str(ctx, "scond");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

/* SCONDD<.di> b,[c] */
static bool trans_scondd_reg(DisasContext *ctx, arg_scondd_reg *a)
{
    arc_print_str(ctx, "scondd");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

/* SCONDD<.di> b,[u6] */
static bool trans_scondd_imm(DisasContext *ctx, arg_scondd_imm *a)
{
    arc_print_str(ctx, "scondd");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

static const char *arc_get_setcc_mnemonic(uint32_t op)
{
    switch (op) {
    case ARC_CC_EQ:
        return "seteq";
    case ARC_CC_NE:
        return "setne";
    case ARC_CC_LT:
        return "setlt";
    case ARC_CC_GE:
        return "setge";
    case ARC_CC_LO:
        return "setlo";
    case ARC_CC_HS:
        return "seths";
    case ARC_CC_LE:
        return "setle";
    case ARC_CC_GT:
        return "setgt";
    default:
        g_assert_not_reached();
    }
}

static bool trans_setcc_reg_reg(DisasContext *ctx, arg_setcc_reg_reg *a)
{
    arc_print_r32dst_r32src_r32src_f_cond(ctx, arc_get_setcc_mnemonic(a->op), a->a, a->b, a->c, a->f, ARC_CC_AL);

    return true;
}

static bool trans_setcc_reg_u6(DisasContext *ctx, arg_setcc_reg_u6 *a)
{
    arc_print_r32dst_r32src_uimm32_f_cond(ctx, arc_get_setcc_mnemonic(a->op), a->a, a->b, a->imm, a->f, ARC_CC_AL);

    return true;
}

static bool trans_setcc_reg_s12(DisasContext *ctx, arg_setcc_reg_s12 *a)
{
    arc_print_r32dst_r32src_simm32_f_cond(ctx, arc_get_setcc_mnemonic(a->op), a->b, a->b, a->imm, a->f, ARC_CC_AL);

    return true;
}

static bool trans_setcc_cond_reg(DisasContext *ctx, arg_setcc_cond_reg *a)
{
    arc_print_r32dst_r32src_r32src_f_cond(ctx, arc_get_setcc_mnemonic(a->op), a->b, a->b, a->c, a->f, a->cond);

    return true;
}

static bool trans_setcc_cond_u6(DisasContext *ctx, arg_setcc_cond_u6 *a)
{
    arc_print_r32dst_r32src_uimm32_f_cond(ctx, arc_get_setcc_mnemonic(a->op), a->b, a->b, a->imm, a->f, a->cond);

    return true;
}

ARC_DEF_DISAS_R32SRC(seti, seti_reg, a->c)
ARC_DEF_DISAS_UIMM32(seti, seti_imm, a->imm)

ARC_DEF_DISAS_SOP_REG_REG(sexb)
ARC_DEF_DISAS_SOP_REG_U6(sexb)
ARC_DEF_DISAS_S_DOP_2OP(sexb_s)

ARC_DEF_DISAS_SOP_REG_REG(sexh)
ARC_DEF_DISAS_SOP_REG_U6(sexh)
ARC_DEF_DISAS_S_DOP_2OP(sexh_s)

ARC_DEF_DISAS_R32SRC(sleep, sleep_reg, a->c)
ARC_DEF_DISAS_UIMM32(sleep, sleep_imm, a->imm)

static bool trans_sr_dop_reg_reg(DisasContext *ctx, arg_sr_dop_reg_reg *a)
{
    arc_print_str(ctx, "sr ");
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

static bool trans_sr_dop_reg_u6(DisasContext *ctx, arg_sr_dop_reg_u6 *a)
{
    arc_print_str(ctx, "sr ");
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

static bool trans_sr_dop_reg_s12(DisasContext *ctx, arg_sr_dop_reg_s12 *a)
{
    arc_print_str(ctx, "sr ");
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, "]");

    return true;
}

/* ST_S b,[SP,u7] */
static bool trans_st_s_b_sp_u7(DisasContext *ctx, arg_st_s_b_sp_u7 *a)
{
    arc_print_str(ctx, "st_s ");
    arc_print_reg_s(ctx, a->b);
    arc_print_ldst_address_with_unsigned_offset(ctx, ARC_REGNUM_SP, a->imm, true);

    return true;
}

/* ST_S c,[b,u7] */
static bool trans_st_s_c_b_u7(DisasContext *ctx, arg_st_s_c_b_u7 *a)
{
    arc_print_str(ctx, "st_s ");
    arc_print_reg_s(ctx, a->c);
    arc_print_ldst_s_address_with_unsigned_offset(ctx, a->b, a->imm, true);

    return true;
}

/* STB_S b,[SP,u7] */
static bool trans_stb_s_b_sp_u7(DisasContext *ctx, arg_stb_s_b_sp_u7 *a)
{
    arc_print_str(ctx, "stb_s ");
    arc_print_reg_s(ctx, a->b);
    arc_print_ldst_address_with_unsigned_offset(ctx, ARC_REGNUM_SP, a->imm, true);

    return true;
}

/* ST_S R0,[GP,s11] */
static bool trans_st_s_r0_gp_s11(DisasContext *ctx, arg_st_s_r0_gp_s11 *a)
{
    arc_print_str(ctx, "st_s r0");
    arc_print_ldst_address_with_signed_offset(ctx, ARC_REGNUM_GP, a->imm, true);

    return true;
}

/* STB_S c,[b,u5] */
static bool trans_stb_s_c_b_u5(DisasContext *ctx, arg_stb_s_c_b_u5 *a)
{
    arc_print_str(ctx, "stb_s ");
    arc_print_reg_s(ctx, a->c);
    arc_print_ldst_s_address_with_unsigned_offset(ctx, a->b, a->imm, true);

    return true;
}

/* STH_S c,[b,u6] */
static bool trans_sth_s_c_b_u6(DisasContext *ctx, arg_sth_s_c_b_u6 *a)
{
    arc_print_str(ctx, "sth_s ");
    arc_print_reg_s(ctx, a->c);
    arc_print_ldst_s_address_with_unsigned_offset(ctx, a->b, a->imm, true);

    return true;
}

ARC_DEF_DISAS_DOP(sub)
ARC_DEF_DISAS_RS32_RS32_UIMM32(sub_s, sub_s_c_b_u3, a->c, a->b, a->imm)

static bool trans_sub_s_ne_b_b_b(DisasContext *ctx, arg_sub_s_ne_b_b_b *a)
{
    arc_print_str(ctx, "sub_s.ne ");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_reg_s(ctx, a->b);

    return true;
}

ARC_DEF_DISAS_RS32_RS32_RS32(sub_s, sub_s_b_b_c, a->b, a->b, a->c)
ARC_DEF_DISAS_RS32_RS32_UIMM32(sub_s, sub_s_b_b_u5, a->b, a->b, a->imm)

static bool trans_sub_s_sp_sp_u7(DisasContext *ctx, arg_sub_s_sp_sp_u7 *a)
{
    arc_print_str(ctx, "sub_s ");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);

    return true;
}

ARC_DEF_DISAS_RS32_RS32_RS32(sub_s, sub_s_a_b_c, a->a, a->b, a->c)

ARC_DEF_DISAS_DOP(sub1)

ARC_DEF_DISAS_DOP(sub2)

ARC_DEF_DISAS_DOP(sub3)

ARC_DEF_DISAS_SOP_REG_REG(swap)
ARC_DEF_DISAS_SOP_REG_U6(swap)

ARC_DEF_DISAS_SOP_REG_REG(swape)
ARC_DEF_DISAS_SOP_REG_U6(swape)

ARC_DEF_DISAS_NO_OP(swi, swi)
ARC_DEF_DISAS_NO_OP(swi_s, swi_s)
ARC_DEF_DISAS_UIMM32(swi_s, swi_s_imm, a->imm)

ARC_DEF_DISAS_NO_OP(sync, sync)

ARC_DEF_DISAS_UIMM32(trap_s, trap_s, a->imm)

ARC_DEF_DISAS_DOP_2OP_REG_REG(tst)
ARC_DEF_DISAS_DOP_2OP_REG_U6(tst)
ARC_DEF_DISAS_DOP_2OP_REG_S12(tst)
ARC_DEF_DISAS_DOP_2OP_COND_REG(tst)
ARC_DEF_DISAS_DOP_2OP_COND_U6(tst)
ARC_DEF_DISAS_S_DOP_2OP(tst_s)

ARC_DEF_DISAS_NO_OP(unimp_s, unimp_s)

ARC_DEF_DISAS_DOP(xor)
ARC_DEF_DISAS_S_DOP_3OP(xor_s)

ARC_DEF_DISAS_DOP(xbfu)

static void arc_print_aa(DisasContext *ctx, int aa)
{
    switch (aa) {
    case ARC_AA_PRE:
        arc_print_str(ctx, ".aw");
        break;
    case ARC_AA_POST:
        arc_print_str(ctx, ".ab");
        break;
    case ARC_AA_SCALED:
        arc_print_str(ctx, ".as");
        break;
    default:
        break;
    }
}

static void arc_print_ldst_suffixes(DisasContext *ctx, int aa, bool di,
                                    bool sign_extend)
{
    arc_print_di(ctx, di, true);
    arc_print_aa(ctx, aa);

    if (sign_extend) {
        arc_print_str(ctx, ".x");
    }
}

static bool arc_print_load_offset(DisasContext *ctx, const char *name,
                                  uint32_t dst, uint32_t base, int32_t offset,
                                  int aa, bool di, bool sign_extend,
                                  bool dst_pair)
{
    arc_print_str(ctx, name);
    arc_print_ldst_suffixes(ctx, aa, di, sign_extend);
    arc_print_space(ctx);

    if (dst_pair) {
        arc_print_dst_reg_pair(ctx, dst);
    } else {
        arc_print_dst_reg(ctx, dst);
    }

    arc_print_ldst_address_with_signed_offset(ctx, base, offset, false);

    return true;
}

static bool arc_print_load_reg(DisasContext *ctx, const char *name,
                               uint32_t dst, uint32_t base, uint32_t offset,
                               int aa, bool di, bool sign_extend, bool dst_pair)
{
    arc_print_str(ctx, name);
    arc_print_ldst_suffixes(ctx, aa, di, sign_extend);
    arc_print_space(ctx);

    if (dst_pair) {
        arc_print_dst_reg_pair(ctx, dst);
    } else {
        arc_print_dst_reg(ctx, dst);
    }

    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, base);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, offset);
    arc_print_str(ctx, "]");

    return true;
}

static bool arc_print_store(DisasContext *ctx, const char *name, uint32_t src,
                            uint32_t base, int32_t offset, int aa, bool di,
                            bool src_pair, bool src_is_imm)
{
    bool always_emit_offset;

    arc_print_str(ctx, name);
    arc_print_ldst_suffixes(ctx, aa, di, false);
    arc_print_space(ctx);

    if (src_is_imm) {
        arc_print_simm(ctx, src);
    } else if (src_pair) {
        arc_print_src_reg_pair(ctx, src);
    } else {
        arc_print_src_reg(ctx, src);
    }

    if (src_pair) {
        always_emit_offset = !arc_is_arcv3(ctx) && arc_regnum_is_limm(ctx, src);
    } else {
        always_emit_offset = arc_is_arcv3(ctx) || (!src_is_imm && arc_regnum_is_limm(ctx, src));
    }

    arc_print_ldst_address_with_signed_offset(ctx, base, offset,
                                               always_emit_offset);

    return true;
}

static bool trans_prealloc_offset(DisasContext *ctx, arg_prealloc_offset *a)
{
    arc_print_str(ctx, "prealloc");
    arc_print_aa(ctx, a->aa);
    arc_print_space(ctx);
    arc_print_str(ctx, "[");
    arc_print_src_reg(ctx, a->b);
    if (a->imm != 0) {
        arc_print_str(ctx, ",");
        arc_print_simm(ctx, a->imm);
    }
    arc_print_str(ctx, "]");
    return true;
}

static bool trans_prealloc_reg(DisasContext *ctx, arg_prealloc_reg *a)
{
    arc_print_str(ctx, "prealloc");
    arc_print_aa(ctx, a->aa);
    arc_print_space(ctx);
    arc_print_str(ctx, "[");
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");
    return true;
}

static void arc_print_lddl_aa(DisasContext *ctx, int x, int di)
{
    if (x) {
        arc_print_aa(ctx, di ? ARC_AA_POST : ARC_AA_PRE);
    } else if (di) {
        arc_print_aa(ctx, ARC_AA_SCALED);
    }
}

static bool trans_lddl_offset(DisasContext *ctx, arg_lddl_offset *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "lddl");
    arc_print_lddl_aa(ctx, a->x, a->di);
    arc_print_space(ctx);
    arc_print_dst_reg_pair(ctx, a->a);
    arc_print_ldst_address_with_signed_offset(ctx, a->b, a->imm, false);

    return true;
}

static bool trans_lddl_reg(DisasContext *ctx, arg_lddl_reg *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "lddl");
    arc_print_lddl_aa(ctx, a->x, a->di);
    arc_print_space(ctx);
    arc_print_dst_reg_pair(ctx, a->a);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

static bool trans_ldb_offset(DisasContext *ctx, arg_ldb_offset *a)
{
    return arc_print_load_offset(ctx, "ldb", a->a, a->b, a->imm, a->aa,
                                 a->di, a->x, false);
}

static bool trans_ldb_reg(DisasContext *ctx, arg_ldb_reg *a)
{
    return arc_print_load_reg(ctx, "ldb", a->a, a->b, a->c, a->aa,
                              a->di, a->x, false);
}

static bool trans_ldh_offset(DisasContext *ctx, arg_ldh_offset *a)
{
    return arc_print_load_offset(ctx, "ldh", a->a, a->b, a->imm, a->aa,
                                 a->di, a->x, false);
}

static bool trans_ldh_reg(DisasContext *ctx, arg_ldh_reg *a)
{
    return arc_print_load_reg(ctx, "ldh", a->a, a->b, a->c, a->aa,
                              a->di, a->x, false);
}

static bool trans_ld_offset(DisasContext *ctx, arg_ld_offset *a)
{
    if (a->a == ARC_REGNUM_LIMM) {
        arc_print_str(ctx, a->di ? "prefetchw " : "prefetch ");
        arc_print_str(ctx, "[");
        arc_print_src_reg(ctx, a->b);
        arc_print_str(ctx, ",");
        arc_print_simm(ctx, a->imm);
        arc_print_str(ctx, "]");
        return true;
    }
    return arc_print_load_offset(ctx, "ld", a->a, a->b, a->imm, a->aa,
                                 a->di, false, false);
}

static bool trans_ld_reg(DisasContext *ctx, arg_ld_reg *a)
{
    if (a->a == ARC_REGNUM_LIMM) {
        arc_print_str(ctx, a->di ? "prefetchw " : "prefetch ");
        arc_print_str(ctx, "[");
        arc_print_src_reg(ctx, a->b);
        arc_print_str(ctx, ",");
        arc_print_src_reg(ctx, a->c);
        arc_print_str(ctx, "]");
        return true;
    }
    return arc_print_load_reg(ctx, "ld", a->a, a->b, a->c, a->aa,
                              a->di, false, false);
}

static bool trans_ld_offset_sext(DisasContext *ctx, arg_ld_offset_sext *a)
{
    return arc_print_load_offset(ctx, "ld", a->a, a->b, a->imm, a->aa,
                                 false, true, false);
}

static bool trans_ld_reg_sext(DisasContext *ctx, arg_ld_reg_sext *a)
{
    return arc_print_load_reg(ctx, "ld", a->a, a->b, a->c, a->aa,
                              false, true, false);
}

static bool trans_ldd_offset(DisasContext *ctx, arg_ldd_offset *a)
{
    return arc_print_load_offset(ctx, "ldd", a->a, a->b, a->imm, a->aa,
                                 a->di, false, true);
}

static bool trans_ldd_reg(DisasContext *ctx, arg_ldd_reg *a)
{
    return arc_print_load_reg(ctx, "ldd", a->a, a->b, a->c, a->aa,
                              a->di, false, true);
}

static bool trans_ldl_offset(DisasContext *ctx, arg_ldl_offset *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "ldl");
    arc_print_aa(ctx, a->aa);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->a);
    arc_print_ldst_address_with_signed_offset(ctx, a->b, a->imm, false);

    return true;
}

static bool trans_ldl_reg(DisasContext *ctx, arg_ldl_reg *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "ldl");
    arc_print_aa(ctx, a->aa);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->a);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");

    return true;
}

static bool trans_popl_s(DisasContext *ctx, arg_popl_s *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "popl_s ");
    arc_print_dst_reg(ctx, a->b);

    return true;
}

static bool trans_popdl_s(DisasContext *ctx, arg_popdl_s *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "popdl_s ");
    arc_print_dst_reg(ctx, a->b);

    return true;
}

static bool trans_stb_reg(DisasContext *ctx, arg_stb_reg *a)
{
    return arc_print_store(ctx, "stb", a->c, a->b, a->imm, a->aa, a->di,
                           false, false);
}

static bool trans_stb_w6(DisasContext *ctx, arg_stb_w6 *a)
{
    return arc_print_store(ctx, "stb", a->simm_src, a->b, a->simm_offset,
                           a->aa, a->di, false, true);
}

static bool trans_sth_reg(DisasContext *ctx, arg_sth_reg *a)
{
    return arc_print_store(ctx, "sth", a->c, a->b, a->imm, a->aa, a->di,
                           false, false);
}

static bool trans_stdl_w6(DisasContext *ctx, arg_stdl_w6 *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "stdl");
    arc_print_aa(ctx, a->aa);
    arc_print_space(ctx);
    arc_print_simm(ctx, a->simm_src);
    arc_print_ldst_address_with_signed_offset(ctx, a->b, a->simm_offset, true);

    return true;
}

static bool trans_sth_w6(DisasContext *ctx, arg_sth_w6 *a)
{
    return arc_print_store(ctx, "sth", a->simm_src, a->b, a->simm_offset,
                           a->aa, a->di, false, true);
}

static bool trans_st_reg(DisasContext *ctx, arg_st_reg *a)
{
    return arc_print_store(ctx, "st", a->c, a->b, a->imm, a->aa, a->di,
                           false, false);
}

static bool trans_st_w6(DisasContext *ctx, arg_st_w6 *a)
{
    return arc_print_store(ctx, "st", a->simm_src, a->b, a->simm_offset,
                           a->aa, a->di, false, true);
}

static bool trans_stdl_reg(DisasContext *ctx, arg_stdl_reg *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "stdl");
    arc_print_aa(ctx, a->aa);
    arc_print_space(ctx);
    arc_print_src_reg_pair(ctx, a->c);
    arc_print_ldst_address_with_signed_offset(ctx, a->b, a->imm, true);

    return true;
}

static bool trans_std_reg(DisasContext *ctx, arg_std_reg *a)
{
    return arc_print_store(ctx, "std", a->c, a->b, a->imm, a->aa, a->di,
                           true, false);
}

static bool trans_stl_reg(DisasContext *ctx, arg_stl_reg *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "stl");
    arc_print_aa(ctx, a->aa);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->c);
    arc_print_ldst_address_with_signed_offset(ctx, a->b, a->imm,
                                              !arc_regnum_is_limm(ctx, a->b));

    return true;
}

static bool trans_stl_w6(DisasContext *ctx, arg_stl_w6 *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "stl");
    arc_print_aa(ctx, a->aa);
    arc_print_space(ctx);
    arc_print_simm(ctx, a->simm_src);
    arc_print_ldst_address_with_signed_offset(ctx, a->b, a->simm_offset, true);

    return true;
}

static bool trans_std_w6(DisasContext *ctx, arg_std_w6 *a)
{
    arc_print_str(ctx, "std");
    arc_print_ldst_suffixes(ctx, a->aa, a->di, false);
    arc_print_space(ctx);
    arc_print_simm(ctx, a->simm_src);
    arc_print_ldst_address_with_signed_offset(ctx, a->b, a->simm_offset,
                                               false);
    return true;
}

static bool trans_pushl_s(DisasContext *ctx, arg_pushl_s *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "pushl_s ");
    arc_print_src_reg(ctx, a->b);

    return true;
}

static bool trans_pushdl_s(DisasContext *ctx, arg_pushdl_s *a)
{
    if (!arc_is_arcv3_64(ctx)) {
        return false;
    }

    arc_print_str(ctx, "pushdl_s ");
    arc_print_src_reg(ctx, a->b);

    return true;
}

ARC_DEF_DISAS_DOP(mpy)
ARC_DEF_DISAS_S_DOP_3OP(mpy_s)
ARC_DEF_DISAS_DOP(mpyu)
ARC_DEF_DISAS_DOP(mpym)
ARC_DEF_DISAS_DOP(mpymu)
ARC_DEF_DISAS_DOP(mpyw)
ARC_DEF_DISAS_S_DOP_3OP(mpyw_s)
ARC_DEF_DISAS_DOP(mpyuw)
ARC_DEF_DISAS_S_DOP_3OP(mpyuw_s)
ARC_DEF_DISAS_DOP(mpyd)
ARC_DEF_DISAS_DOP(mpydu)
ARC_DEF_DISAS_DOP(mac)
ARC_DEF_DISAS_DOP(macu)
ARC_DEF_DISAS_DOP(macd)
ARC_DEF_DISAS_DOP(macdu)
ARC_DEF_DISAS_DOP_IMM16(dmpyh)
ARC_DEF_DISAS_DOP_IMM16(dmpyhu)
ARC_DEF_DISAS_DOP_IMM16(dmach)
ARC_DEF_DISAS_DOP_IMM16(dmachu)
ARC_DEF_DISAS_DOP_IMM16(dmpywh)
ARC_DEF_DISAS_DOP_IMM16(dmpywhu)
ARC_DEF_DISAS_DOP_IMM16(dmacwh)
ARC_DEF_DISAS_DOP_IMM16(dmacwhu)
ARC_DEF_DISAS_DOP_IMM16(qmpyh)
ARC_DEF_DISAS_DOP_IMM16(qmpyhu)
ARC_DEF_DISAS_DOP_IMM16(qmach)
ARC_DEF_DISAS_DOP_IMM16(qmachu)
ARC_DEF_DISAS_SIMD_DOP(vadd2, true, true, true, false,
                       (uint32_t)a->imm, (int32_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vaddsub, false, false, false, false,
                       (uint32_t)a->imm, (int32_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vsub2, false, false, false, false,
                       (uint32_t)a->imm, (int32_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vsubadd, false, false, false, false,
                       (uint32_t)a->imm, (int32_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vadd2h, false, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vaddsub2h, false, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vsub2h, false, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vsubadd2h, false, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vadd4h, true, true, true, true,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vaddsub4h, false, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vsub4h, true, true, true, true,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vsubadd4h, false, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vmac2h, true, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vmac2hu, false, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vmpy2h, true, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)
ARC_DEF_DISAS_SIMD_DOP(vmpy2hu, false, false, false, false,
                       (uint16_t)a->imm, (int16_t)a->imm)

static bool arc_print_op_s_h_h_limm(DisasContext *ctx, const char *mnemonic, uint32_t h)
{
    arc_print_str(ctx, mnemonic);
    arc_print_space(ctx);
    arc_print_dst_reg_h(ctx, h);
    arc_print_dot(ctx);
    arc_print_dst_reg_h(ctx, h);
    arc_print_dot(ctx);
    arc_print_uimm(ctx, arc_parse_limm(ctx));
    return true;
}

static bool arc_print_op_s_h_pcl_limm(DisasContext *ctx, const char *mnemonic, uint32_t h)
{
    arc_print_str(ctx, mnemonic);
    arc_print_space(ctx);
    arc_print_dst_reg_h(ctx, h);
    arc_print_dot(ctx);
    arc_print_src_reg(ctx, ARC_REGNUM_PCL);
    arc_print_dot(ctx);
    arc_print_uimm(ctx, arc_parse_limm(ctx));
    return true;
}

static bool arc_print_aex_like(DisasContext *ctx, const char *name, uint32_t b,
                               bool has_cc, uint32_t cond, bool is_reg,
                               bool is_u6, uint32_t c, uint32_t imm)
{
    arc_print_str(ctx, name);
    if (has_cc) {
        arc_print_cc(ctx, cond, true);
    }
    arc_print_space(ctx);
    arc_print_src_reg(ctx, b);
    arc_print_str(ctx, ",[");
    if (is_reg) {
        arc_print_src_reg(ctx, c);
    } else if (is_u6) {
        arc_print_uimm(ctx, imm);
    } else {
        arc_print_simm(ctx, imm);
    }
    arc_print_str(ctx, "]");
    return true;
}

static bool arc_print_lr_like(DisasContext *ctx, const char *name, uint32_t b,
                              bool is_reg, uint32_t c, uint32_t imm)
{
    arc_print_str(ctx, name);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, b);
    arc_print_str(ctx, ",[");
    if (is_reg) {
        arc_print_src_reg(ctx, c);
    } else {
        arc_print_aux_reg(ctx, imm);
    }
    arc_print_str(ctx, "]");
    return true;
}

static bool arc_print_sr_like(DisasContext *ctx, const char *name, uint32_t b,
                              bool is_reg, uint32_t c, uint32_t imm)
{
    arc_print_str(ctx, name);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, b);
    arc_print_str(ctx, ",[");
    if (is_reg) {
        arc_print_src_reg(ctx, c);
    } else {
        arc_print_aux_reg(ctx, imm);
    }
    arc_print_str(ctx, "]");
    return true;
}

static bool arc_print_bbit_like(DisasContext *ctx, const char *name, uint32_t b,
                                bool is_reg, uint32_t c, uint32_t imm,
                                int32_t offset, bool delay)
{
    arc_print_str(ctx, name);
    arc_print_delay(ctx, delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, b);
    arc_print_str(ctx, ",");
    if (is_reg) {
        arc_print_src_reg(ctx, c);
    } else {
        arc_print_uimm(ctx, imm);
    }
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, offset);
    return true;
}

static const char *arc_get_setccl_mnemonic(uint32_t op)
{
    switch (op) {
    case ARC_CC_EQ:
        return "seteql";
    case ARC_CC_NE:
        return "setnel";
    case ARC_CC_LT:
        return "setltl";
    case ARC_CC_GE:
        return "setgel";
    case ARC_CC_LO:
        return "setlol";
    case ARC_CC_HS:
        return "sethsl";
    case ARC_CC_LE:
        return "setlel";
    case ARC_CC_GT:
        return "setgtl";
    default:
        g_assert_not_reached();
    }
}

ARC_DEF_DISAS_SOP_REG_REG(absl)
ARC_DEF_DISAS_SOP_REG_U6(absl)

ARC_DEF_DISAS_DOP(adcl)

ARC_DEF_DISAS_DOP(addl)

ARC_DEF_DISAS_RS32_RS32_RS32(addl_s, addl_s_b_b_c, a->b, a->b, a->c)

static bool trans_addl_s_h_h_limm(DisasContext *ctx, arg_addl_s_h_h_limm *a)
{
    return arc_print_op_s_h_h_limm(ctx, "addl_s", a->h);
}

static bool trans_addl_s_h_pcl_limm(DisasContext *ctx, arg_addl_s_h_pcl_limm *a)
{
    return arc_print_op_s_h_pcl_limm(ctx, "addl_s", a->h);
}

static bool trans_addl_s_b_sp_u7(DisasContext *ctx, arg_addl_s_b_sp_u7 *a)
{
    arc_print_str(ctx, "addl_s ");
    arc_print_reg_s(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    return true;
}

static bool trans_addl_s_sp_sp_u9(DisasContext *ctx, arg_addl_s_sp_sp_u9 *a)
{
    arc_print_str(ctx, "addl_s ");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    return true;
}

static bool trans_addl_s_r0_gp_s11(DisasContext *ctx, arg_addl_s_r0_gp_s11 *a)
{
    arc_print_str(ctx, "addl_s r0,gp");
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->imm);
    return true;
}

ARC_DEF_DISAS_DOP(addhl)

static bool trans_addhl_s_h_h_limm(DisasContext *ctx, arg_addhl_s_h_h_limm *a)
{
    return arc_print_op_s_h_h_limm(ctx, "addhl_s", a->h);
}

static bool trans_addhl_s_h_pcl_limm(DisasContext *ctx, arg_addhl_s_h_pcl_limm *a)
{
    return arc_print_op_s_h_pcl_limm(ctx, "addhl_s", a->h);
}

ARC_DEF_DISAS_DOP(add1l)

ARC_DEF_DISAS_DOP(add2l)

ARC_DEF_DISAS_DOP(add3l)

static bool trans_aexl_dop_reg_reg(DisasContext *ctx, arg_aexl_dop_reg_reg *a)
{
    return arc_print_aex_like(ctx, "aexl", a->b, false, ARC_CC_AL,
                              true, false, a->c, 0);
}

static bool trans_aexl_dop_reg_u6(DisasContext *ctx, arg_aexl_dop_reg_u6 *a)
{
    return arc_print_aex_like(ctx, "aexl", a->b, false, ARC_CC_AL,
                              false, true, 0, a->imm);
}

static bool trans_aexl_dop_reg_s12(DisasContext *ctx, arg_aexl_dop_reg_s12 *a)
{
    return arc_print_aex_like(ctx, "aexl", a->b, false, ARC_CC_AL,
                              false, false, 0, a->imm);
}

static bool trans_aexl_dop_cond_reg(DisasContext *ctx, arg_aexl_dop_cond_reg *a)
{
    return arc_print_aex_like(ctx, "aexl", a->b, true, a->cond,
                              true, false, a->c, 0);
}

static bool trans_aexl_dop_cond_u6(DisasContext *ctx, arg_aexl_dop_cond_u6 *a)
{
    return arc_print_aex_like(ctx, "aexl", a->b, true, a->cond,
                              false, true, 0, a->imm);
}

ARC_DEF_DISAS_DOP(andl)
ARC_DEF_DISAS_S_DOP_3OP(andl_s)

ARC_DEF_DISAS_SOP_REG_REG(asll)
ARC_DEF_DISAS_SOP_REG_U6(asll)

ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(asll, aslml_dop_reg_reg, a->a, a->b, a->c, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(asll, aslml_dop_reg_u6, a->a, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_SIMM32_F_COND(asll, aslml_dop_reg_s12, a->b, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(asll, aslml_dop_cond_reg, a->b, a->b, a->c, a->f, a->cond)
ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(asll, aslml_dop_cond_u6, a->b, a->b, a->imm, a->f, a->cond)

ARC_DEF_DISAS_SOP_REG_REG(asrl)
ARC_DEF_DISAS_SOP_REG_U6(asrl)

ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(asrl, asrml_dop_reg_reg, a->a, a->b, a->c, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(asrl, asrml_dop_reg_u6, a->a, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_SIMM32_F_COND(asrl, asrml_dop_reg_s12, a->b, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(asrl, asrml_dop_cond_reg, a->b, a->b, a->c, a->f, a->cond)
ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(asrl, asrml_dop_cond_u6, a->b, a->b, a->imm, a->f, a->cond)

static bool trans_bbit0l_reg(DisasContext *ctx, arg_bbit0l_reg *a)
{
    return arc_print_bbit_like(ctx, "bbit0l", a->b, true, a->c, 0, a->offset, a->delay);
}

static bool trans_bbit0l_imm(DisasContext *ctx, arg_bbit0l_imm *a)
{
    return arc_print_bbit_like(ctx, "bbit0l", a->b, false, 0, a->imm, a->offset, a->delay);
}

static bool trans_bbit1l_reg(DisasContext *ctx, arg_bbit1l_reg *a)
{
    return arc_print_bbit_like(ctx, "bbit1l", a->b, true, a->c, 0, a->offset, a->delay);
}

static bool trans_bbit1l_imm(DisasContext *ctx, arg_bbit1l_imm *a)
{
    return arc_print_bbit_like(ctx, "bbit1l", a->b, false, 0, a->imm, a->offset, a->delay);
}

ARC_DEF_DISAS_DOP(bclrl)

ARC_DEF_DISAS_DOP(bicl)

ARC_DEF_DISAS_DOP(bmskl)

ARC_DEF_DISAS_DOP(bmsknl)

static bool trans_brccl_reg(DisasContext *ctx, arg_brccl_reg *a)
{
    arc_print_str(ctx, arc_get_brcc_mnemonic(a->cond));
    arc_print_str(ctx, "l");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->offset);
    return true;
}

static bool trans_brccl_u6(DisasContext *ctx, arg_brccl_u6 *a)
{
    arc_print_str(ctx, arc_get_brcc_mnemonic(a->cond));
    arc_print_str(ctx, "l");
    arc_print_delay(ctx, a->delay);
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    arc_print_str(ctx, ",");
    arc_print_simm(ctx, a->offset);
    return true;
}

ARC_DEF_DISAS_DOP(bsetl)

ARC_DEF_DISAS_DOP_2OP_REG_REG(btstl)
ARC_DEF_DISAS_DOP_2OP_REG_U6(btstl)
ARC_DEF_DISAS_DOP_2OP_REG_S12(btstl)
ARC_DEF_DISAS_DOP_2OP_COND_REG(btstl)
ARC_DEF_DISAS_DOP_2OP_COND_U6(btstl)

ARC_DEF_DISAS_DOP(bxorl)

ARC_DEF_DISAS_DOP_2OP_REG_REG(cmpl)
ARC_DEF_DISAS_DOP_2OP_REG_U6(cmpl)
ARC_DEF_DISAS_DOP_2OP_REG_S12(cmpl)
ARC_DEF_DISAS_DOP_2OP_COND_REG(cmpl)
ARC_DEF_DISAS_DOP_2OP_COND_U6(cmpl)

ARC_DEF_DISAS_DOP(divl)

ARC_DEF_DISAS_DOP(divul)

static bool trans_exl(DisasContext *ctx, arg_exl *a)
{
    arc_print_str(ctx, "exl");
    arc_print_di(ctx, a->di, true);
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");
    return true;
}

ARC_DEF_DISAS_SOP_REG_REG(ffsl)
ARC_DEF_DISAS_SOP_REG_U6(ffsl)
ARC_DEF_DISAS_SOP_REG_REG(flsl)
ARC_DEF_DISAS_SOP_REG_U6(flsl)

static bool trans_llockl(DisasContext *ctx, arg_llockl *a)
{
    arc_print_str(ctx, "llockl");
    if (a->aq) {
        arc_print_str(ctx, ".aq");
    }
    arc_print_space(ctx);
    arc_print_dst_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");
    return true;
}

static bool trans_lrl_dop_reg_reg(DisasContext *ctx, arg_lrl_dop_reg_reg *a)
{
    return arc_print_lr_like(ctx, "lrl", a->b, true, a->c, 0);
}

static bool trans_lrl_dop_reg_u6(DisasContext *ctx, arg_lrl_dop_reg_u6 *a)
{
    return arc_print_lr_like(ctx, "lrl", a->b, false, 0, a->imm);
}

static bool trans_lrl_dop_reg_s12(DisasContext *ctx, arg_lrl_dop_reg_s12 *a)
{
    return arc_print_lr_like(ctx, "lrl", a->b, false, 0, a->imm);
}

ARC_DEF_DISAS_SOP_REG_REG(lsrl)
ARC_DEF_DISAS_SOP_REG_U6(lsrl)

ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(lsrl, lsrml_dop_reg_reg, a->a, a->b, a->c, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(lsrl, lsrml_dop_reg_u6, a->a, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_SIMM32_F_COND(lsrl, lsrml_dop_reg_s12, a->b, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_R32SRC_F_COND(lsrl, lsrml_dop_cond_reg, a->b, a->b, a->c, a->f, a->cond)
ARC_DEF_DISAS_R32DST_R32SRC_UIMM32_F_COND(lsrl, lsrml_dop_cond_u6, a->b, a->b, a->imm, a->f, a->cond)

ARC_DEF_DISAS_DOP(minl)

ARC_DEF_DISAS_DOP(maxl)

ARC_DEF_DISAS_R32DST_R32SRC_F_COND(movl, movl_dop_reg_reg, a->b, a->c, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_UIMM32_F_COND(movl, movl_dop_reg_u6, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_SIMM32_F_COND(movl, movl_dop_reg_s12, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_F_COND(movl, movl_dop_cond_reg, a->b, a->c, a->f, a->cond)
ARC_DEF_DISAS_R32DST_UIMM32_F_COND(movl, movl_dop_cond_u6, a->b, a->imm, a->f, a->cond)

static bool trans_movl_s_g_h(DisasContext *ctx, arg_movl_s_g_h *a)
{
    arc_print_str(ctx, "movl_s ");
    arc_print_dst_reg_h(ctx, a->g);
    arc_print_str(ctx, ",");
    arc_print_src_reg_h(ctx, a->h);
    return true;
}

ARC_DEF_DISAS_R32DST_R32SRC_F_COND(movhl, movhl_dop_reg_reg, a->b, a->c, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_UIMM32_F_COND(movhl, movhl_dop_reg_u6, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_SIMM32_F_COND(movhl, movhl_dop_reg_s12, a->b, a->imm, a->f, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_R32SRC_F_COND(movhl, movhl_dop_cond_reg, a->b, a->c, a->f, a->cond)
ARC_DEF_DISAS_R32DST_UIMM32_F_COND(movhl, movhl_dop_cond_u6, a->b, a->imm, a->f, a->cond)

static bool trans_movhl_s_h_limm(DisasContext *ctx, arg_movhl_s_h_limm *a)
{
    arc_print_str(ctx, "movhl_s ");
    arc_print_dst_reg_h(ctx, a->h);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, arc_parse_limm(ctx));
    return true;
}

ARC_DEF_DISAS_DOP(mpyl)

ARC_DEF_DISAS_DOP(mpyml)

ARC_DEF_DISAS_DOP(mpymul)

ARC_DEF_DISAS_DOP(mpymsul)

ARC_DEF_DISAS_SOP_REG_REG(norml)
ARC_DEF_DISAS_SOP_REG_U6(norml)

ARC_DEF_DISAS_SOP_REG_REG(notl)
ARC_DEF_DISAS_SOP_REG_U6(notl)

ARC_DEF_DISAS_DOP(orl)
ARC_DEF_DISAS_RS32_RS32_RS32(orl_s, orl_s_b_b_c, a->b, a->b, a->c)

static bool trans_orl_s_h_h_limm(DisasContext *ctx, arg_orl_s_h_h_limm *a)
{
    return arc_print_op_s_h_h_limm(ctx, "orl_s", a->h);
}

static bool trans_orl_s_h_pcl_limm(DisasContext *ctx, arg_orl_s_h_pcl_limm *a)
{
    return arc_print_op_s_h_pcl_limm(ctx, "orl_s", a->h);
}

ARC_DEF_DISAS_DOP_2OP_REG_REG(rcmpl)
ARC_DEF_DISAS_DOP_2OP_REG_U6(rcmpl)
ARC_DEF_DISAS_DOP_2OP_REG_S12(rcmpl)
ARC_DEF_DISAS_DOP_2OP_COND_REG(rcmpl)
ARC_DEF_DISAS_DOP_2OP_COND_U6(rcmpl)

ARC_DEF_DISAS_DOP(reml)

ARC_DEF_DISAS_DOP(remul)

ARC_DEF_DISAS_DOP(rsubl)

ARC_DEF_DISAS_DOP(sbcl)

static bool trans_scondl(DisasContext *ctx, arg_scondl *a)
{
    arc_print_str(ctx, "scondl");
    if (a->rl) {
        arc_print_str(ctx, ".rl");
    }
    arc_print_space(ctx);
    arc_print_src_reg(ctx, a->b);
    arc_print_str(ctx, ",[");
    arc_print_src_reg(ctx, a->c);
    arc_print_str(ctx, "]");
    return true;
}

static bool trans_setccl_reg_reg(DisasContext *ctx, arg_setccl_reg_reg *a)
{
    arc_print_r32dst_r32src_r32src_f_cond(ctx, arc_get_setccl_mnemonic(a->op), a->a, a->b, a->c, a->f, ARC_CC_AL);
    return true;
}

static bool trans_setccl_reg_u6(DisasContext *ctx, arg_setccl_reg_u6 *a)
{
    arc_print_r32dst_r32src_uimm32_f_cond(ctx, arc_get_setccl_mnemonic(a->op), a->a, a->b, a->imm, a->f, ARC_CC_AL);
    return true;
}

static bool trans_setccl_reg_s12(DisasContext *ctx, arg_setccl_reg_s12 *a)
{
    arc_print_r32dst_r32src_simm32_f_cond(ctx, arc_get_setccl_mnemonic(a->op), a->b, a->b, a->imm, a->f, ARC_CC_AL);
    return true;
}

static bool trans_setccl_cond_reg(DisasContext *ctx, arg_setccl_cond_reg *a)
{
    arc_print_r32dst_r32src_r32src_f_cond(ctx, arc_get_setccl_mnemonic(a->op), a->b, a->b, a->c, a->f, a->cond);
    return true;
}

static bool trans_setccl_cond_u6(DisasContext *ctx, arg_setccl_cond_u6 *a)
{
    arc_print_r32dst_r32src_uimm32_f_cond(ctx, arc_get_setccl_mnemonic(a->op), a->b, a->b, a->imm, a->f, a->cond);
    return true;
}

ARC_DEF_DISAS_SOP_REG_REG(sexbl)
ARC_DEF_DISAS_SOP_REG_U6(sexbl)
ARC_DEF_DISAS_SOP_REG_REG(sexhl)
ARC_DEF_DISAS_SOP_REG_U6(sexhl)
ARC_DEF_DISAS_SOP_REG_REG(sexwl)
ARC_DEF_DISAS_SOP_REG_U6(sexwl)

ARC_DEF_DISAS_DOP(subl)
ARC_DEF_DISAS_RS32_RS32_RS32(subl_s, subl_s_b_b_c, a->b, a->b, a->c)

static bool trans_subl_s_sp_sp_u9(DisasContext *ctx, arg_subl_s_sp_sp_u9 *a)
{
    arc_print_str(ctx, "subl_s ");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_src_reg(ctx, ARC_REGNUM_SP);
    arc_print_str(ctx, ",");
    arc_print_uimm(ctx, a->imm);
    return true;
}

ARC_DEF_DISAS_DOP(sub1l)

ARC_DEF_DISAS_DOP(sub2l)

ARC_DEF_DISAS_DOP(sub3l)

static bool trans_srl_dop_reg_reg(DisasContext *ctx, arg_srl_dop_reg_reg *a)
{
    return arc_print_sr_like(ctx, "srl", a->b, true, a->c, 0);
}

static bool trans_srl_dop_reg_u6(DisasContext *ctx, arg_srl_dop_reg_u6 *a)
{
    return arc_print_sr_like(ctx, "srl", a->b, false, 0, a->imm);
}

static bool trans_srl_dop_reg_s12(DisasContext *ctx, arg_srl_dop_reg_s12 *a)
{
    return arc_print_sr_like(ctx, "srl", a->b, false, 0, a->imm);
}

ARC_DEF_DISAS_SOP_REG_REG(swapl)
ARC_DEF_DISAS_SOP_REG_U6(swapl)

ARC_DEF_DISAS_SOP_REG_REG(swapel)
ARC_DEF_DISAS_SOP_REG_U6(swapel)

ARC_DEF_DISAS_DOP_2OP_REG_REG(tstl)
ARC_DEF_DISAS_DOP_2OP_REG_U6(tstl)
ARC_DEF_DISAS_DOP_2OP_REG_S12(tstl)
ARC_DEF_DISAS_DOP_2OP_COND_REG(tstl)
ARC_DEF_DISAS_DOP_2OP_COND_U6(tstl)

ARC_DEF_DISAS_DOP(vpack2hl)

ARC_DEF_DISAS_DOP_NO_F(vpack2hm)

ARC_DEF_DISAS_DOP(vpack4hl)

ARC_DEF_DISAS_DOP_NO_F(vpack4hm)

ARC_DEF_DISAS_DOP(vpack2wl)

ARC_DEF_DISAS_DOP_NO_F(vpack2wm)

ARC_DEF_DISAS_R32DST_R32SRC_F_COND(vrep2hl, vrep2hl_dop_reg_reg, a->b, a->c, false, ARC_CC_AL)
ARC_DEF_DISAS_R32DST_UIMM32_F_COND(vrep2hl, vrep2hl_dop_reg_u6, a->b, a->imm, false, ARC_CC_AL)

ARC_DEF_DISAS_DOP(xbful)

ARC_DEF_DISAS_DOP(xorl)

ARC_DEF_DISAS_DOP_NO_F(vmax2)

ARC_DEF_DISAS_DOP_NO_F(vmin2)

static bool decode(DisasContext *ctx)
{
    switch (ctx->insn_len) {
    case 4:
        if (!decode_insn32(ctx, ctx->insn)) {
            return false;
        }
        break;
    case 2:
        if (!decode_insn16(ctx, ctx->insn)) {
            return false;
        }
        break;
    default:
        g_assert_not_reached();
    }

    return true;
}

int print_insn_arc(bfd_vma memaddr, struct disassemble_info *info)
{
    bfd_byte buffer[8];
    int status;
    uint16_t hw0;
    uint16_t hw1;
    int major;
    bool is_arc64 = false;

    DisasContext ctx = {
        .info = info,
        .memaddr = memaddr,
        .insn = 0,
        .insn_len = 0,
        .has_limm = false,
        .limm = 0,
    };

    info->bytes_per_line  = 8;
    info->bytes_per_chunk = 2;
    info->display_endian = info->endian;

    status = (*info->read_memory_func)(memaddr, buffer, 2, info);
    if (status != 0) {
        (*info->memory_error_func)(status, memaddr, info);
        return -1;
    }

    /* Retrieve a first half word of the instruction. */
    hw0 = buffer[1] << 8 | buffer[0];
    major = (hw0 >> 11) & 0x1F;

    is_arc64 = info->mach == bfd_mach_arcv3_64;

    if ((is_arc64 && (major <= 0x07 || major == 0x0B)) || major <= 0x07) {
        /*
         * Retrieve a second half word of the instruction if it's
         * a 4-byte instruction.
         */
        status = (*info->read_memory_func)(memaddr + 2, &buffer[2], 2, info);
        if (status != 0) {
            (*info->memory_error_func)(status, memaddr + 2, info);
            return -1;
        }

        hw1 = buffer[3] << 8 | buffer[2];
        ctx.insn = ((uint32_t)hw0 << 16) | hw1;
        ctx.insn_len = 4;
    } else {
        ctx.insn = hw0;
        ctx.insn_len = 2;
    }

    if (!decode(&ctx)) {
        switch (ctx.insn_len) {
        case 2:
            (*info->fprintf_func)(info->stream, ".short %#04x", ctx.insn & 0xffff);
            break;
        case 4:
            (*info->fprintf_func)(info->stream, ".word %#08x", ctx.insn & 0xffffffff);
            break;
        default:
            g_assert_not_reached();
        }

        info->insn_type = dis_noninsn;
    }

    return ctx.insn_len;
}

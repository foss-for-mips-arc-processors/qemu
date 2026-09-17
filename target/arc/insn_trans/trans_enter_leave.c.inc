#include "translate.h"

FIELD(ENTER_IMM_FORMAT, GPRS,  0, 4)
FIELD(ENTER_IMM_FORMAT, FP,    4, 1)
FIELD(ENTER_IMM_FORMAT, BLINK, 5, 1)

FIELD(LEAVE_IMM_FORMAT, GPRS,  0, 4)
FIELD(LEAVE_IMM_FORMAT, FP,    4, 1)
FIELD(LEAVE_IMM_FORMAT, BLINK, 5, 1)
FIELD(LEAVE_IMM_FORMAT, JUMP,  6, 1)

/*
 * Frame layout, from the lowest address upwards:
 *
 *     ARCv2: BLINK, R13 ... R13+n-1, FP
 *     ARCv3: FP, BLINK, R14 ... R14+n-1
 */
#ifdef TARGET_ARCV2
#define ARC_FRAME_FIRST_GPR ARC_REGNUM_R13
#else
#define ARC_FRAME_FIRST_GPR ARC_REGNUM_R14
#endif

#ifdef TARGET_ARCV3_64
#define ARC_FRAME_SLOT_SIZE 8
#define ARC_FRAME_MEMOP     (MO_TEUQ | MO_ALIGN_4)
#else
#define ARC_FRAME_SLOT_SIZE 4
#define ARC_FRAME_MEMOP     (MO_TEUL | MO_ALIGN_4)
#endif

/* On ARCv3 the frame pointer (R27) must not be saved twice */
static int arc_frame_max_gprs(bool frame_pointer)
{
#ifdef TARGET_ARCV2
    return 14;
#else
    return frame_pointer ? 13 : 14;
#endif
}

static void arc_gen_frame_store(DisasContext *ctx, TCGv addr, int regnum)
{
    tcg_gen_qemu_st_tl(cpu_gpr[regnum], addr, ctx->mem_idx, ARC_FRAME_MEMOP);
    tcg_gen_addi_tl(addr, addr, ARC_FRAME_SLOT_SIZE);
}

static void arc_gen_frame_load(DisasContext *ctx, TCGv addr, int regnum)
{
    tcg_gen_qemu_ld_tl(cpu_gpr[regnum], addr, ctx->mem_idx, ARC_FRAME_MEMOP);
    tcg_gen_addi_tl(addr, addr, ARC_FRAME_SLOT_SIZE);
}

static void arc_gen_enter_s(DisasContext *ctx, int gprs, bool save_fp,
                          bool save_blink)
{
    int slots = gprs + save_fp + save_blink;
    TCGv addr = tcg_temp_new();

    if (gprs > arc_frame_max_gprs(save_fp)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    arc_gen_check_not_delay_slot(ctx);

    /* Preserve SP for cases when memory operations fail */
    tcg_gen_subi_tl(addr, cpu_gpr[ARC_REGNUM_SP], slots * ARC_FRAME_SLOT_SIZE);

#ifdef TARGET_ARCV2
    if (save_blink) {
        arc_gen_frame_store(ctx, addr, ARC_REGNUM_BLINK);
    }

    for (int i = 0; i < gprs; i++) {
        arc_gen_frame_store(ctx, addr, ARC_FRAME_FIRST_GPR + i);
    }

    if (save_fp) {
        arc_gen_frame_store(ctx, addr, ARC_REGNUM_FP);
    }
#else
    if (save_fp) {
        arc_gen_frame_store(ctx, addr, ARC_REGNUM_FP);
    }

    if (save_blink) {
        arc_gen_frame_store(ctx, addr, ARC_REGNUM_BLINK);
    }

    for (int i = 0; i < gprs; i++) {
        arc_gen_frame_store(ctx, addr, ARC_FRAME_FIRST_GPR + i);
    }
#endif

    tcg_gen_subi_tl(cpu_gpr[ARC_REGNUM_SP], cpu_gpr[ARC_REGNUM_SP], slots * ARC_FRAME_SLOT_SIZE);

    if (save_fp) {
        tcg_gen_mov_tl(cpu_gpr[ARC_REGNUM_FP], cpu_gpr[ARC_REGNUM_SP]);
    }
}

/* TODO: Should we save all restored values in temp variables until all memops will succeed? */
static void arc_gen_leave_s(DisasContext *ctx, int gprs, bool restore_fp, bool restore_blink, bool jump)
{
    int slots = gprs + restore_fp + restore_blink;
    TCGv addr;

    if (gprs > arc_frame_max_gprs(restore_fp)) {
        arc_gen_exception_illegal_instruction(ctx);
    }

    arc_gen_check_not_delay_slot(ctx);

    if (restore_fp) {
        tcg_gen_mov_tl(cpu_gpr[ARC_REGNUM_SP], cpu_gpr[ARC_REGNUM_FP]);
    }

    addr = tcg_temp_new();

#ifdef TARGET_ARCV2
    tcg_gen_mov_tl(addr, cpu_gpr[ARC_REGNUM_SP]);

    if (restore_blink) {
        arc_gen_frame_load(ctx, addr, ARC_REGNUM_BLINK);
    }

    for (int i = 0; i < gprs; i++) {
        arc_gen_frame_load(ctx, addr, ARC_FRAME_FIRST_GPR + i);
    }

    if (restore_fp) {
        arc_gen_frame_load(ctx, addr, ARC_REGNUM_FP);
    }
#else
    /* FP occupies the lowest slot but is restored last. */
    tcg_gen_addi_tl(addr, cpu_gpr[ARC_REGNUM_SP],
                    restore_fp * ARC_FRAME_SLOT_SIZE);

    if (restore_blink) {
        arc_gen_frame_load(ctx, addr, ARC_REGNUM_BLINK);
    }

    for (int i = 0; i < gprs; i++) {
        arc_gen_frame_load(ctx, addr, ARC_FRAME_FIRST_GPR + i);
    }

    if (restore_fp) {
        tcg_gen_qemu_ld_tl(cpu_gpr[ARC_REGNUM_FP], cpu_gpr[ARC_REGNUM_SP], ctx->mem_idx, ARC_FRAME_MEMOP);
    }
#endif

    tcg_gen_addi_tl(cpu_gpr[ARC_REGNUM_SP], cpu_gpr[ARC_REGNUM_SP], slots * ARC_FRAME_SLOT_SIZE);

    if (jump) {
        tcg_gen_mov_tl(cpu_pc, cpu_gpr[ARC_REGNUM_BLINK]);

        ctx->base.is_jmp = DISAS_JUMP_INDIRECT;
    }
}

static bool trans_enter_s(DisasContext *ctx, arg_enter_s *a)
{
    if (a->imm == 0) {
        return true;
    }

    int gprs = FIELD_EX32(a->imm, ENTER_IMM_FORMAT, GPRS);
    bool fp = FIELD_EX32(a->imm, ENTER_IMM_FORMAT, FP);
    bool blink = FIELD_EX32(a->imm, ENTER_IMM_FORMAT, BLINK);

    arc_gen_enter_s(ctx, gprs, fp, blink);

    return true;
}

static bool trans_leave_s(DisasContext *ctx, arg_leave_s *a)
{
    if (a->imm == 0) {
        return true;
    }

    int gprs = FIELD_EX32(a->imm, LEAVE_IMM_FORMAT, GPRS);
    bool fp = FIELD_EX32(a->imm, LEAVE_IMM_FORMAT, FP);
    bool blink = FIELD_EX32(a->imm, LEAVE_IMM_FORMAT, BLINK);
    bool jump = FIELD_EX32(a->imm, LEAVE_IMM_FORMAT, JUMP);

    arc_gen_leave_s(ctx, gprs, fp, blink, jump);

    return true;
}

ARC_DEF_TRANS_STUB(enter)
ARC_DEF_TRANS_STUB(leave)

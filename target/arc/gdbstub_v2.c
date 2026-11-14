#include "qemu/osdep.h"
#include "exec/gdbstub.h"
#include "gdbstub/helpers.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "gdbstub.h"

int arc_cpu_gdb_read_register(CPUState *cs, GByteArray *mem_buf, int n)
{
    ARCCPU *cpu = ARC_CPU(cs);
    CPUARCState *env = &cpu->env;
    target_ulong regval = 0;

    switch (n) {
    case 0 ... 31:
        regval = env->gpr[n];
        break;
    case GDB_ARCV2_REG_CORE_R58:
        regval = env->gpr[58];
        break;
    case GDB_ARCV2_REG_CORE_R59:
        regval = env->gpr[59];
        break;
    case GDB_ARCV2_REG_CORE_R60:
        regval = env->gpr[60];
        break;
    case GDB_ARCV2_REG_CORE_R63:
        regval = arc_pc_to_pcl(env->pc);
        break;
    default:
        return 0;
    }

    return gdb_get_reg32(mem_buf, regval);
}

int arc_cpu_gdb_write_register(CPUState *cs, uint8_t *mem_buf, int n)
{
    ARCCPU *cpu = ARC_CPU(cs);
    CPUARCState *env = &cpu->env;
    target_ulong regval = ldl_p(mem_buf);

    switch (n) {
    case 0 ... 31:
        env->gpr[n] = regval;
        break;
    case GDB_ARCV2_REG_CORE_R58:
        env->gpr[58] = regval;
        break;
    case GDB_ARCV2_REG_CORE_R59:
        env->gpr[59] = regval;
        break;
    case GDB_ARCV2_REG_CORE_R60:
        env->gpr[60] = regval;
        break;
    case GDB_ARCV2_REG_CORE_R63:
        /* Ignore writes to PCL */
        break;
    default:
        return 0;
    }

    return sizeof(regval);
}

static int arc_cpu_gdb_read_aux(CPUState *cs, GByteArray *mem_buf, int regnum)
{
    ARCCPU *cpu = ARC_CPU(cs);
    CPUARCState *env = &cpu->env;
    target_ulong regval = 0;

    switch (regnum) {
    case GDB_ARCV2_REG_AUX_PC:
        regval = env->pc;
        break;
    case GDB_ARCV2_REG_AUX_LP_START:
        regval = env->aux_lp_start;
        break;
    case GDB_ARCV2_REG_AUX_LP_END:
        regval = env->aux_lp_end;
        break;
    case GDB_ARCV2_REG_AUX_STATUS32:
        regval = arc_pack_status32(&env->aux_status32);
        break;
    case GDB_ARCV2_REG_AUX_BTA:
        regval = env->aux_bta;
        break;
    case GDB_ARCV2_REG_AUX_ERSTATUS:
        regval = arc_pack_aux_erstatus(&env->aux_erstatus);
        break;
    case GDB_ARCV2_REG_AUX_ERBTA:
        regval = env->aux_erbta;
        break;
    case GDB_ARCV2_REG_AUX_ECR:
        regval = arc_pack_aux_ecr(&env->aux_ecr);
        break;
    case GDB_ARCV2_REG_AUX_ERET:
        regval = env->aux_eret;
        break;
    case GDB_ARCV2_REG_AUX_EFA:
        regval = env->aux_efa;
        break;
    default:
        return 0;
    }

    return gdb_get_reg32(mem_buf, regval);
}

static void arc_gdb_write_status32(CPUARCState *env, uint32_t value)
{
    arc_aux_status_t status;
    uint32_t new_bank;

    arc_unpack_status32(&status, value);

    /* Halt flag cannot be changed by a debugger */
    status.halt = env->aux_status32.halt;

    /* Switch registers banks if needed */
    new_bank = status.register_bank;
    status.register_bank = env->aux_status32.register_bank;
    env->aux_status32 = status;

    arc_cpu_switch_gpr_bank(env, new_bank);
}

static int arc_cpu_gdb_write_aux(CPUState *cs, uint8_t *mem_buf, int regnum)
{
    ARCCPU *cpu = ARC_CPU(cs);
    CPUARCState *env = &cpu->env;
    uint32_t regval = ldl_p(mem_buf);

    switch (regnum) {
    case GDB_ARCV2_REG_AUX_PC:
        cpu_set_pc(cs, arc_align_2_bytes(regval));
        break;
    case GDB_ARCV2_REG_AUX_LP_START:
        /* TODO: TBs must be flushed here */
        env->aux_lp_start = arc_align_2_bytes(regval);
        break;
    case GDB_ARCV2_REG_AUX_LP_END:
        //* TODO: TBs must be flushed here */
        env->aux_lp_end = arc_align_2_bytes(regval);
        break;
    case GDB_ARCV2_REG_AUX_STATUS32:
        arc_gdb_write_status32(env, regval);
        break;
    case GDB_ARCV2_REG_AUX_BTA:
        env->aux_bta = regval;
        break;
    case GDB_ARCV2_REG_AUX_ERSTATUS:
        arc_unpack_aux_erstatus(&env->aux_erstatus, regval);
        break;
    case GDB_ARCV2_REG_AUX_ERBTA:
        env->aux_erbta = regval;
        break;
    case GDB_ARCV2_REG_AUX_ECR:
        arc_unpack_aux_ecr(&env->aux_ecr, regval);
        break;
    case GDB_ARCV2_REG_AUX_ERET:
        env->aux_eret = regval;
        break;
    case GDB_ARCV2_REG_AUX_EFA:
        env->aux_efa = regval;
        break;
    default:
        return 0;
    }

    return sizeof(regval);
}

void arc_cpu_register_gdb_regs_for_features(CPUState *cs)
{
    gdb_register_coprocessor(cs, arc_cpu_gdb_read_aux, arc_cpu_gdb_write_aux, gdb_find_static_feature(GDB_ARCV2_REG_AUX_XML), 0);
}

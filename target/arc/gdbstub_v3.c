#include "qemu/osdep.h"
#include "exec/gdbstub.h"
#include "gdbstub/helpers.h"
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
    case GDB_ARCV3_REG_CORE_R58:
        regval = env->gpr[58];
        break;
#ifdef TARGET_ARCV3_32
    case GDB_ARCV3_REG_CORE_R59:
        regval = env->gpr[59];
        break;
#endif
    case GDB_ARCV3_REG_CORE_R63:
        regval = arc_pc_to_pcl(env->pc);
        break;
    default:
        return 0;
    }

    return gdb_get_regl(mem_buf, regval);
}

int arc_cpu_gdb_write_register(CPUState *cs, uint8_t *mem_buf, int n)
{
    ARCCPU *cpu = ARC_CPU(cs);
    CPUARCState *env = &cpu->env;
    target_ulong regval = ldtul_p(mem_buf);

    switch (n) {
    case 0 ... 31:
        env->gpr[n] = regval;
        break;
    case GDB_ARCV3_REG_CORE_R58:
        env->gpr[58] = regval;
        break;
#ifdef TARGET_ARCV3_32
    case GDB_ARCV3_REG_CORE_R59:
        env->gpr[59] = regval;
        break;
#endif
    case GDB_ARCV3_REG_CORE_R63:
        /* Ignore writes to PCL */
        break;
    default:
        return 0;
    }

    return sizeof(regval);
}

#ifdef TARGET_ARCV3_32
#define GDB_ARCV3_REG_AUX_XML GDB_ARCV3_32_REG_AUX_XML
#else
#define GDB_ARCV3_REG_AUX_XML GDB_ARCV3_64_REG_AUX_XML
#endif

static int arc_cpu_gdb_read_aux(CPUState *cs, GByteArray *mem_buf, int regnum)
{
    ARCCPU *cpu = ARC_CPU(cs);
    CPUARCState *env = &cpu->env;

    switch (regnum) {
    case GDB_ARCV3_REG_AUX_PC:
        return gdb_get_regl(mem_buf, env->pc);
    case GDB_ARCV3_REG_AUX_STATUS32:
        return gdb_get_reg32(mem_buf, arc_gdb_read_status32(env));
    case GDB_ARCV3_REG_AUX_BTA:
        return gdb_get_regl(mem_buf, env->aux_bta);
    case GDB_ARCV3_REG_AUX_ERSTATUS:
        return gdb_get_reg32(mem_buf,
                             arc_pack_aux_erstatus(&env->aux_erstatus));
    case GDB_ARCV3_REG_AUX_ERBTA:
        return gdb_get_regl(mem_buf, env->aux_erbta);
    case GDB_ARCV3_REG_AUX_ECR:
        return gdb_get_reg32(mem_buf, arc_pack_aux_ecr(&env->aux_ecr));
    case GDB_ARCV3_REG_AUX_ERET:
        return gdb_get_regl(mem_buf, env->aux_eret);
    case GDB_ARCV3_REG_AUX_EFA:
        return gdb_get_regl(mem_buf, env->aux_efa);
    default:
        return 0;
    }
}

static int arc_cpu_gdb_write_aux(CPUState *cs, uint8_t *mem_buf, int regnum)
{
    ARCCPU *cpu = ARC_CPU(cs);
    CPUARCState *env = &cpu->env;

    switch (regnum) {
    case GDB_ARCV3_REG_AUX_PC:
        cpu_set_pc(cs, arc_align_2_bytes(ldtul_p(mem_buf)));
        return sizeof(target_ulong);
    case GDB_ARCV3_REG_AUX_STATUS32:
        arc_gdb_write_status32(env, ldl_p(mem_buf));
        return sizeof(uint32_t);
    case GDB_ARCV3_REG_AUX_BTA:
        env->aux_bta = ldtul_p(mem_buf);
        return sizeof(target_ulong);
    case GDB_ARCV3_REG_AUX_ERSTATUS:
        arc_unpack_aux_erstatus(&env->aux_erstatus, ldl_p(mem_buf));
        return sizeof(uint32_t);
    case GDB_ARCV3_REG_AUX_ERBTA:
        env->aux_erbta = ldtul_p(mem_buf);
        return sizeof(target_ulong);
    case GDB_ARCV3_REG_AUX_ECR:
        arc_unpack_aux_ecr(&env->aux_ecr, ldl_p(mem_buf));
        return sizeof(uint32_t);
    case GDB_ARCV3_REG_AUX_ERET:
        env->aux_eret = ldtul_p(mem_buf);
        return sizeof(target_ulong);
    case GDB_ARCV3_REG_AUX_EFA:
        env->aux_efa = ldtul_p(mem_buf);
        return sizeof(target_ulong);
    default:
        return 0;
    }
}

void arc_cpu_register_gdb_regs_for_features(CPUState *cs)
{
    gdb_register_coprocessor(cs, arc_cpu_gdb_read_aux, arc_cpu_gdb_write_aux,
                             gdb_find_static_feature(GDB_ARCV3_REG_AUX_XML), 0);
}

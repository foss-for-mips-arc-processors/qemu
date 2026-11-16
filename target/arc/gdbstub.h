#ifndef ARC_GDBSTUB_H
#define ARC_GDBSTUB_H

#define GDB_ARCV2_ARCH            "arc:ARCv2"
#define GDB_ARCV2_REG_CORE_XML    "arcv2-core.xml"
#define GDB_ARCV2_REG_AUX_XML     "arcv2-aux.xml"

#define GDB_ARCV3_32_ARCH         "arc64:32"
#define GDB_ARCV3_32_REG_CORE_XML "arcv3-32bit-core.xml"
#define GDB_ARCV3_32_REG_AUX_XML  "arcv3-32bit-aux.xml"

#define GDB_ARCV3_64_ARCH         "arc64:64"
#define GDB_ARCV3_64_REG_CORE_XML "arcv3-64bit-core.xml"
#define GDB_ARCV3_64_REG_AUX_XML  "arcv3-64bit-aux.xml"

enum gdb_v2_core_regs {
    GDB_ARCV2_REG_CORE_R0,
    GDB_ARCV2_REG_CORE_R1,
    GDB_ARCV2_REG_CORE_R2,
    GDB_ARCV2_REG_CORE_R3,
    GDB_ARCV2_REG_CORE_R4,
    GDB_ARCV2_REG_CORE_R5,
    GDB_ARCV2_REG_CORE_R6,
    GDB_ARCV2_REG_CORE_R7,
    GDB_ARCV2_REG_CORE_R8,
    GDB_ARCV2_REG_CORE_R9,
    GDB_ARCV2_REG_CORE_R10,
    GDB_ARCV2_REG_CORE_R11,
    GDB_ARCV2_REG_CORE_R12,
    GDB_ARCV2_REG_CORE_R13,
    GDB_ARCV2_REG_CORE_R14,
    GDB_ARCV2_REG_CORE_R15,
    GDB_ARCV2_REG_CORE_R16,
    GDB_ARCV2_REG_CORE_R17,
    GDB_ARCV2_REG_CORE_R18,
    GDB_ARCV2_REG_CORE_R19,
    GDB_ARCV2_REG_CORE_R20,
    GDB_ARCV2_REG_CORE_R21,
    GDB_ARCV2_REG_CORE_R22,
    GDB_ARCV2_REG_CORE_R23,
    GDB_ARCV2_REG_CORE_R24,
    GDB_ARCV2_REG_CORE_R25,
    GDB_ARCV2_REG_CORE_R26, /* GP */
    GDB_ARCV2_REG_CORE_R27, /* FP */
    GDB_ARCV2_REG_CORE_R28, /* SP */
    GDB_ARCV2_REG_CORE_R29, /* ILINK */
    GDB_ARCV2_REG_CORE_R30,
    GDB_ARCV2_REG_CORE_R31, /* BLINK */
    GDB_ARCV2_REG_CORE_R58, /* ACCL (little endian) */
    GDB_ARCV2_REG_CORE_R59, /* ACCH (little endian) */
    GDB_ARCV2_REG_CORE_R60, /* LP_COUNT */
    GDB_ARCV2_REG_CORE_R63, /* PCL */
    GDB_ARCV2_REG_CORE_LAST
};

enum gdb_v2_aux_regs {
    GDB_ARCV2_REG_AUX_PC,       /* program counter */
    GDB_ARCV2_REG_AUX_LP_START, /* loop body start */
    GDB_ARCV2_REG_AUX_LP_END,   /* loop body end */
    GDB_ARCV2_REG_AUX_STATUS32, /* status flag */
    GDB_ARCV2_REG_AUX_BTA,      /* branch target address */
    GDB_ARCV2_REG_AUX_ERSTATUS, /* exception return status */
    GDB_ARCV2_REG_AUX_ERBTA,    /* exception return BTA */
    GDB_ARCV2_REG_AUX_ECR,      /* exception cause register */
    GDB_ARCV2_REG_AUX_ERET,     /* exception return address */
    GDB_ARCV2_REG_AUX_EFA,      /* exception fault address */
    GDB_ARCV2_REG_AUX_LAST
};

enum gdb_v3_core_regs {
    GDB_ARCV3_REG_CORE_R0,
    GDB_ARCV3_REG_CORE_R1,
    GDB_ARCV3_REG_CORE_R2,
    GDB_ARCV3_REG_CORE_R3,
    GDB_ARCV3_REG_CORE_R4,
    GDB_ARCV3_REG_CORE_R5,
    GDB_ARCV3_REG_CORE_R6,
    GDB_ARCV3_REG_CORE_R7,
    GDB_ARCV3_REG_CORE_R8,
    GDB_ARCV3_REG_CORE_R9,
    GDB_ARCV3_REG_CORE_R10,
    GDB_ARCV3_REG_CORE_R11,
    GDB_ARCV3_REG_CORE_R12,
    GDB_ARCV3_REG_CORE_R13,
    GDB_ARCV3_REG_CORE_R14,
    GDB_ARCV3_REG_CORE_R15,
    GDB_ARCV3_REG_CORE_R16,
    GDB_ARCV3_REG_CORE_R17,
    GDB_ARCV3_REG_CORE_R18,
    GDB_ARCV3_REG_CORE_R19,
    GDB_ARCV3_REG_CORE_R20,
    GDB_ARCV3_REG_CORE_R21,
    GDB_ARCV3_REG_CORE_R22,
    GDB_ARCV3_REG_CORE_R23,
    GDB_ARCV3_REG_CORE_R24,
    GDB_ARCV3_REG_CORE_R25,
    GDB_ARCV3_REG_CORE_R26,
    GDB_ARCV3_REG_CORE_R27, /* FP */
    GDB_ARCV3_REG_CORE_R28, /* SP */
    GDB_ARCV3_REG_CORE_R29, /* ILINK */
    GDB_ARCV3_REG_CORE_R30, /* GP */
    GDB_ARCV3_REG_CORE_R31, /* BLINK */
#ifdef TARGET_ARCV3_32
    GDB_ARCV3_REG_CORE_R58, /* ACCL (little endian) */
    GDB_ARCV3_REG_CORE_R59, /* ACCH (little endian) */
#else
    GDB_ARCV3_REG_CORE_R58, /* ACC0 */
#endif
    GDB_ARCV3_REG_CORE_R63, /* PCL */
    GDB_ARCV3_REG_CORE_LAST
};

enum gdb_v3_aux_regs {
    GDB_ARCV3_REG_AUX_PC,       /* program counter */
    GDB_ARCV3_REG_AUX_STATUS32, /* status flag */
    GDB_ARCV3_REG_AUX_BTA,      /* branch target address */
    GDB_ARCV3_REG_AUX_ERSTATUS, /* exception return status */
    GDB_ARCV3_REG_AUX_ERBTA,    /* exception return BTA */
    GDB_ARCV3_REG_AUX_ECR,      /* exception cause register */
    GDB_ARCV3_REG_AUX_ERET,     /* exception return address */
    GDB_ARCV3_REG_AUX_EFA,      /* exception fault address */
    GDB_ARCV3_REG_AUX_LAST
};

uint32_t arc_gdb_read_status32(CPUARCState *env);
void arc_gdb_write_status32(CPUARCState *env, uint32_t value);

void arc_cpu_register_gdb_regs_for_features(CPUState *cs);

#endif

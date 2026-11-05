#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/bitops.h"
#include "exec/cputlb.h"
#include "exec/cpu-common.h"
#include "exec/page-protection.h"
#include "exec/target_page.h"
#include "system/memory.h"
#include "cpu.h"
#include "mmu.h"

typedef enum {
    ARC_MMU_TYPE_V32     = 0x0,
    ARC_MMU_TYPE_V48_4K  = 0x1,
    ARC_MMU_TYPE_V48_16K = 0x2,
    ARC_MMU_TYPE_V48_64K = 0x3,
    ARC_MMU_TYPE_END
} ARCMMUType;

typedef enum {
    ARC_MMU_TABLE_SIZE_V48_16 = 16,
    ARC_MMU_TABLE_SIZE_V48_25 = 25
} ARCMMUTableSize;

typedef enum {
    ARC_MMU_REGION_RTP0,
    ARC_MMU_REGION_RTP1,
    ARC_MMU_REGION_HOLE
} ARCMMURegion;

typedef enum {
    ARC_MMU_RECORD_INVALID,
    ARC_MMU_RECORD_TABLE,
    ARC_MMU_RECORD_BLOCK,
    ARC_MMU_RECORD_PAGE
} ARCMMURecordKind;

#define ARC_MMU_MAX_LEVELS 4

/*
 * Per-level geometry. A zeroed level is skipped (T0SZ/T1SZ shrinks the
 * high VA). table_alignment is the next-table pointer; block_alignment
 * is the block or page output address.
 */
typedef struct {
    uint8_t index_bits;
    uint8_t block_alignment;
    uint8_t table_alignment;
    bool allow_table;
    bool allow_block;
    bool allow_page;
} ARCMMULevel;

typedef struct {
    ARCMMUType type;
    uint32_t tsz;
    uint8_t pa_bits;
    uint8_t nlevels;
    uint8_t root_shift;
    ARCMMULevel levels[ARC_MMU_MAX_LEVELS];
} ARCMMUScheme;

typedef struct {
    bool af;
    int ap;
    bool kxn;
    bool uxn;
} arc_mmu_block_attributes_t;

typedef struct {
    uint8_t ap_nxt;
    bool kxn_nxt;
    bool uxn_nxt;
} arc_mmu_table_attributes_t;

typedef struct {
    ARCMMURecordKind kind;
    hwaddr addr;
    union {
        arc_mmu_block_attributes_t block;
        arc_mmu_table_attributes_t table;
    };
} arc_mmu_record_t;

/*
 * Page-table schemes. levels[i] is architectural level i+1.
 * A zeroed level is skipped (T0SZ/T1SZ shrinks the high VA).
 *
 * V32:     2-9-9-12, L2 2MB, L3 4KB. T0SZ 0..7; T0SZ>=2 skips L1.
 * V48-4K:  9-9-9-9-12, L2 1GB, L3 2MB, L4 4KB. T0SZ=25 skips L1.
 * V48-16K: 1-11-11-11-14, L2 table-only, L3 32MB. T0SZ=25 skips L1 (L2 keeps 3).
 * V48-64K: 6-13-13-16, L2 512MB, L3 64KB page (no L4). T0SZ=25 skips L1 (L2 keeps 10).
 */
static const ARCMMUScheme arc_mmu_schemes[] = {
    {
        .type = ARC_MMU_TYPE_V32,
        .tsz = 0,
        .pa_bits = 40,
        .nlevels = 3,
        .root_shift = 5,
        .levels = {
            { .index_bits = 2, .table_alignment = 12, .allow_table = true },
            { .index_bits = 9, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
            { 0 },
        },
    },
    {
        .type = ARC_MMU_TYPE_V32,
        .tsz = 1,
        .pa_bits = 40,
        .nlevels = 3,
        .root_shift = 4,
        .levels = {
            { .index_bits = 1, .table_alignment = 12, .allow_table = true },
            { .index_bits = 9, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
            { 0 },
        },
    },
    {
        .type = ARC_MMU_TYPE_V32,
        .tsz = 2,
        .pa_bits = 40,
        .nlevels = 3,
        .root_shift = 12,
        .levels = {
            { 0 },
            { .index_bits = 9, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
            { 0 },
        },
    },
    {
        .type = ARC_MMU_TYPE_V32,
        .tsz = 3,
        .pa_bits = 40,
        .nlevels = 3,
        .root_shift = 11,
        .levels = {
            { 0 },
            { .index_bits = 8, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
            { 0 },
        },
    },
    {
        .type = ARC_MMU_TYPE_V32,
        .tsz = 4,
        .pa_bits = 40,
        .nlevels = 3,
        .root_shift = 10,
        .levels = {
            { 0 },
            { .index_bits = 7, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
            { 0 },
        },
    },
    {
        .type = ARC_MMU_TYPE_V32,
        .tsz = 5,
        .pa_bits = 40,
        .nlevels = 3,
        .root_shift = 9,
        .levels = {
            { 0 },
            { .index_bits = 6, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
            { 0 },
        },
    },
    {
        .type = ARC_MMU_TYPE_V32,
        .tsz = 6,
        .pa_bits = 40,
        .nlevels = 3,
        .root_shift = 8,
        .levels = {
            { 0 },
            { .index_bits = 5, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
            { 0 },
        },
    },
    {
        .type = ARC_MMU_TYPE_V32,
        .tsz = 7,
        .pa_bits = 40,
        .nlevels = 3,
        .root_shift = 7,
        .levels = {
            { 0 },
            { .index_bits = 4, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
            { 0 },
        },
    },
    {
        .type = ARC_MMU_TYPE_V48_4K,
        .tsz = ARC_MMU_TABLE_SIZE_V48_16,
        .pa_bits = 48,
        .nlevels = 4,
        .root_shift = 12,
        .levels = {
            { .index_bits = 9, .table_alignment = 12, .allow_table = true },
            { .index_bits = 9, .table_alignment = 12, .block_alignment = 30, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
        },
    },
    {
        .type = ARC_MMU_TYPE_V48_4K,
        .tsz = ARC_MMU_TABLE_SIZE_V48_25,
        .pa_bits = 48,
        .nlevels = 4,
        .root_shift = 12,
        .levels = {
            { 0 },
            { .index_bits = 9, .table_alignment = 12, .block_alignment = 30, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .table_alignment = 12, .block_alignment = 21, .allow_table = true, .allow_block = true },
            { .index_bits = 9, .block_alignment = 12, .allow_page = true },
        },
    },
    {
        .type = ARC_MMU_TYPE_V48_16K,
        .tsz = ARC_MMU_TABLE_SIZE_V48_16,
        .pa_bits = 48,
        .nlevels = 4,
        .root_shift = 4,
        .levels = {
            { .index_bits = 1, .table_alignment = 14, .allow_table = true },
            { .index_bits = 11, .table_alignment = 14, .allow_table = true },
            { .index_bits = 11, .table_alignment = 14, .block_alignment = 25, .allow_table = true, .allow_block = true },
            { .index_bits = 11, .block_alignment = 14, .allow_page = true },
        },
    },
    {
        .type = ARC_MMU_TYPE_V48_16K,
        .tsz = ARC_MMU_TABLE_SIZE_V48_25,
        .pa_bits = 48,
        .nlevels = 4,
        .root_shift = 6,
        .levels = {
            { 0 },
            { .index_bits = 3, .table_alignment = 14, .allow_table = true },
            { .index_bits = 11, .table_alignment = 14, .block_alignment = 25, .allow_table = true, .allow_block = true },
            { .index_bits = 11, .block_alignment = 14, .allow_page = true },
        },
    },
    {
        .type = ARC_MMU_TYPE_V48_64K,
        .tsz = ARC_MMU_TABLE_SIZE_V48_16,
        .pa_bits = 48,
        .nlevels = 3,
        .root_shift = 9,
        .levels = {
            { .index_bits = 6, .table_alignment = 16, .allow_table = true },
            { .index_bits = 13, .table_alignment = 16, .block_alignment = 29, .allow_table = true, .allow_block = true },
            { .index_bits = 13, .block_alignment = 16, .allow_page = true },
            { 0 },
        },
    },
    {
        .type = ARC_MMU_TYPE_V48_64K,
        .tsz = ARC_MMU_TABLE_SIZE_V48_25,
        .pa_bits = 48,
        .nlevels = 3,
        .root_shift = 13,
        .levels = {
            { 0 },
            { .index_bits = 10, .table_alignment = 16, .block_alignment = 29, .allow_table = true, .allow_block = true },
            { .index_bits = 13, .block_alignment = 16, .allow_page = true },
            { 0 },
        },
    },
};

static ARCMMUType arc_mmu_get_type(CPUARCState *env)
{
    ARCMMUType type = FIELD_EX32(env_archcpu(env)->aux_mmu_build,
                                 AUX_MMU_BUILD, TYPE);

    g_assert(type < ARC_MMU_TYPE_END);
#ifdef TARGET_ARCV3_32
    g_assert(type == ARC_MMU_TYPE_V32);
#else
    g_assert(type > ARC_MMU_TYPE_V32 && type <= ARC_MMU_TYPE_V48_64K);
#endif

    return type;
}

static uint32_t arc_mmu_sanitize_tsz(ARCMMUType type, uint32_t tsz)
{
    switch (type) {
    case ARC_MMU_TYPE_V32:
        if (tsz > 7) {
            return 0;
        }
        return tsz;
    case ARC_MMU_TYPE_V48_4K:
    case ARC_MMU_TYPE_V48_16K:
    case ARC_MMU_TYPE_V48_64K:
        if (tsz != ARC_MMU_TABLE_SIZE_V48_16 && tsz != ARC_MMU_TABLE_SIZE_V48_25) {
            return ARC_MMU_TABLE_SIZE_V48_16;
        }
        return tsz;
    default:
        g_assert_not_reached();
    }
}

static target_ulong arc_mmu_get_high_bits(target_ulong addr, uint32_t tsz)
{
    if (tsz == 0) {
        return 0;
    }

    return addr >> (TARGET_LONG_BITS - tsz);
}

static ARCMMURegion arc_mmu_get_region(target_ulong addr, uint32_t t0sz, uint32_t t1sz)
{
    target_ulong t0sz_high_bits = arc_mmu_get_high_bits(addr, t0sz);
    target_ulong t1sz_high_bits = arc_mmu_get_high_bits(addr, t1sz);

#ifdef TARGET_ARCV3_32
    /*
     * T1SZ != 0: the top T1SZ bits all-1s are RTP1 (also when T0SZ == 0).
     * T0SZ == 0: everything else is RTP0. Otherwise RTP0 is the bottom
     * T0SZ bits all-0s. T1SZ == 0 then takes the remainder.
     */
    if (t1sz != 0 && t1sz_high_bits == MAKE_64BIT_MASK(0, t1sz)) {
        return ARC_MMU_REGION_RTP1;
    }

    if (t0sz == 0 || t0sz_high_bits == 0) {
        return ARC_MMU_REGION_RTP0;
    }

    if (t1sz == 0) {
        return ARC_MMU_REGION_RTP1;
    }

    return ARC_MMU_REGION_HOLE;
#else
    if (t1sz_high_bits == MAKE_64BIT_MASK(0, t1sz)) {
        return ARC_MMU_REGION_RTP1;
    }

    if (t0sz_high_bits == 0) {
        return ARC_MMU_REGION_RTP0;
    }

    return ARC_MMU_REGION_HOLE;
#endif
}

static hwaddr arc_mmu_extract_addr(uint64_t raw, uint8_t addr_shift,
                                   uint8_t pa_bits)
{
    return raw & MAKE_64BIT_MASK(addr_shift, pa_bits - addr_shift);
}

static hwaddr arc_mmu_pte_addr(uint64_t raw, uint8_t addr_shift,
                               const ARCMMUScheme *scheme)
{
    /* PA[pa_bits-1:alignment] is stored in the same PTE bits */
    return arc_mmu_extract_addr(raw, addr_shift, scheme->pa_bits);
}

static arc_mmu_record_t arc_mmu_unpack_record(uint64_t raw, const ARCMMULevel *lvl,
                                             const ARCMMUScheme *scheme)
{
    arc_mmu_record_t rec = { 0 };
    uint32_t type = FIELD_EX64(raw, ARC_MMU_PTE_TABLE, TYPE);

    if (type == ARC_MMU_PTE_TYPE_TABLE) {
        if (lvl->allow_page) {
            rec.kind = ARC_MMU_RECORD_PAGE;
            rec.block.af = FIELD_EX64(raw, ARC_MMU_PTE_BLOCK, AF);
            rec.block.ap = FIELD_EX64(raw, ARC_MMU_PTE_BLOCK, AP);
            rec.block.kxn = FIELD_EX64(raw, ARC_MMU_PTE_BLOCK, KXN);
            rec.block.uxn = FIELD_EX64(raw, ARC_MMU_PTE_BLOCK, UXN);
            rec.addr = arc_mmu_pte_addr(raw, lvl->block_alignment, scheme);
        } else if (lvl->allow_table) {
            rec.kind = ARC_MMU_RECORD_TABLE;
            rec.table.kxn_nxt = FIELD_EX64(raw, ARC_MMU_PTE_TABLE, KXN_NXT);
            rec.table.uxn_nxt = FIELD_EX64(raw, ARC_MMU_PTE_TABLE, UXN_NXT);
            rec.table.ap_nxt = FIELD_EX64(raw, ARC_MMU_PTE_TABLE, AP_NXT);
            rec.addr = arc_mmu_pte_addr(raw, lvl->table_alignment, scheme);
        } else {
            rec.kind = ARC_MMU_RECORD_INVALID;
        }
    } else if (type == ARC_MMU_PTE_TYPE_BLOCK && lvl->allow_block) {
        rec.kind = ARC_MMU_RECORD_BLOCK;
        rec.block.af = FIELD_EX64(raw, ARC_MMU_PTE_BLOCK, AF);
        rec.block.ap = FIELD_EX64(raw, ARC_MMU_PTE_BLOCK, AP);
        rec.block.kxn = FIELD_EX64(raw, ARC_MMU_PTE_BLOCK, KXN);
        rec.block.uxn = FIELD_EX64(raw, ARC_MMU_PTE_BLOCK, UXN);
        rec.addr = arc_mmu_pte_addr(raw, lvl->block_alignment, scheme);
    } else {
        rec.kind = ARC_MMU_RECORD_INVALID;
    }

    return rec;
}

static int arc_mmu_leaf_prot(CPUARCState *env, const arc_mmu_record_t *rec, bool user, arc_mmu_table_attributes_t table_attributes)
{
    int prot = 0;

    int kernel_read = 0;
    int kernel_write = 0;
    int kernel_execute = 0;

    int user_read = 0;
    int user_write = 0;
    int user_execute = 0;

    bool kxn = rec->block.kxn | table_attributes.kxn_nxt;
    bool uxn = rec->block.uxn | table_attributes.uxn_nxt;

    bool ku = FIELD_EX32(env->aux_mmu_ctrl, AUX_MMU_CTRL, KU);
    bool wx = FIELD_EX32(env->aux_mmu_ctrl, AUX_MMU_CTRL, WX);

    /* Apply block/page RW permissions */

    switch (rec->block.ap) {
    case 0x0:
        kernel_read = 1;
        kernel_write = 1;
        break;
    case 0x1:
        kernel_read = 1 & ku;
        kernel_write = 1 & ku;
        user_read = 1;
        user_write = 1;
        break;
    case 0x2:
        kernel_read = 1;
        break;
    case 0x3:
        kernel_read = 1 & ku;
        user_read = 1;
        break;
    default:
        g_assert_not_reached();
    }

    /* Apply block/page X permissions */

    kernel_execute = !kxn;
    user_execute = !uxn;

    /* Apply table RW permissions */

    switch (table_attributes.ap_nxt) {
    case 0x0:
        break;
    case 0x1: /* User mode accesses are not permitted */
        user_read = 0;
        user_write = 0;
        break;
    case 0x2: /* Write accesses are not permitted */
        kernel_write = 0;
        user_write = 0;
        break;
    case 0x3: /* Write accesses are not permitted, read accesses not permitted in user mode */
        kernel_write = 0;
        user_read = 0;
        user_write = 0;
        break;
    default:
        g_assert_not_reached();
    }

    /* Restrict X permissions using WX */

    if (kernel_write && !wx) {
        kernel_execute = 0;
    }

    if (user_write && !wx) {
        user_execute = 0;
    }

    /* Construct QEMU permissions */

    if (user) {
        prot |= user_read ? PAGE_READ : 0;
        prot |= user_write ? PAGE_WRITE : 0;
        prot |= user_execute ? PAGE_EXEC : 0;
    } else {
        prot |= kernel_read ? PAGE_READ : 0;
        prot |= kernel_write ? PAGE_WRITE : 0;
        prot |= kernel_execute ? PAGE_EXEC : 0;
    }

    return prot;
}

static bool arc_mmu_access_ok(int prot, MMUAccessType type)
{
    switch (type) {
    case MMU_DATA_LOAD:
        return prot & PAGE_READ;
    case MMU_DATA_STORE:
        return prot & PAGE_WRITE;
    case MMU_INST_FETCH:
        return prot & PAGE_EXEC;
    default:
        g_assert_not_reached();
    }
}

static ARCMMUTranslateResult arc_mmu_walk(CPUARCState *env, const ARCMMUScheme *scheme,
                                 uint32_t tsz, target_ulong vaddr, hwaddr root,
                                 MMUAccessType type, bool user,
                                 hwaddr *paddr, int *prot)
{
    hwaddr table_addr = root;
    unsigned remain = TARGET_LONG_BITS - tsz;
    arc_mmu_table_attributes_t table_attributes = {0};
    int level;

    for (level = 0; level < ARC_MMU_MAX_LEVELS; level++) {
        const ARCMMULevel *lvl = &scheme->levels[level];
        int arch_level = level + 1;
        unsigned index;
        hwaddr pte_addr;
        MemTxResult tx;
        uint64_t raw;
        arc_mmu_record_t rec;

        if (lvl->index_bits == 0) {
            continue;
        }

        remain -= lvl->index_bits;
        index = (vaddr >> remain) & ((1u << lvl->index_bits) - 1);
        pte_addr = table_addr + ((uint64_t)index * 8);

        raw = address_space_ldq(env_cpu(env)->as, pte_addr, MEMTXATTRS_UNSPECIFIED, &tx);

        /* Failed to get a record from memory */
        if (tx != MEMTX_OK) {
            env->aux_mmu_fault_sts = arch_level;
            return ARC_MMU_TRANSLATE_MISS;
        }

        qemu_log_mask(CPU_LOG_MMU,
                      "arc: mmu: walk L%d pte_addr=0x%" HWADDR_PRIx
                      " raw=0x%" PRIx64 " index=%u\n",
                      arch_level, pte_addr, raw, index);

        rec = arc_mmu_unpack_record(raw, lvl, scheme);
        if (rec.kind == ARC_MMU_RECORD_INVALID) {
            env->aux_mmu_fault_sts = arch_level;
            return ARC_MMU_TRANSLATE_MISS;
        }

        if (rec.kind == ARC_MMU_RECORD_TABLE) {
            table_attributes.kxn_nxt |= rec.table.kxn_nxt;
            table_attributes.uxn_nxt |= rec.table.uxn_nxt;
            table_attributes.ap_nxt |= rec.table.ap_nxt;
            table_addr = rec.addr;
            continue;
        }

        if (!rec.block.af) {
            env->aux_mmu_fault_sts = arch_level;
            return ARC_MMU_TRANSLATE_ACCESS_FLAG;
        }

        *paddr = rec.addr | (vaddr & MAKE_64BIT_MASK(0, lvl->block_alignment));
        *prot = arc_mmu_leaf_prot(env, &rec, user, table_attributes);

        if (!arc_mmu_access_ok(*prot, type)) {
            return ARC_MMU_TRANSLATE_PROTV;
        }

        return ARC_MMU_TRANSLATE_OK;
    }

    env->aux_mmu_fault_sts = scheme->nlevels;
    return ARC_MMU_TRANSLATE_MISS;
}

ARCMMUTranslateResult arc_mmu_translate(CPUARCState *env, target_ulong vaddr,
                               MMUAccessType type, bool user,
                               hwaddr *paddr, int *prot)
{
    bool enabled = FIELD_EX32(env->aux_mmu_ctrl, AUX_MMU_CTRL, EN);
    ARCMMUType mmu_type = arc_mmu_get_type(env);
    uint32_t t0sz;
    uint32_t t1sz;
    uint32_t tsz;
    ARCMMURegion region;
    const ARCMMUScheme *scheme;
    hwaddr root_table_addr;
    uint64_t rtp;

    if (!enabled) {
        *paddr = vaddr;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return ARC_MMU_TRANSLATE_OK;
    }

    t0sz = arc_mmu_sanitize_tsz(arc_mmu_get_type(env), FIELD_EX32(env->aux_mmu_ttbc, AUX_MMU_TTBC, T0SZ));
    t1sz = arc_mmu_sanitize_tsz(arc_mmu_get_type(env), FIELD_EX32(env->aux_mmu_ttbc, AUX_MMU_TTBC, T1SZ));
    region = arc_mmu_get_region(vaddr, t0sz, t1sz);

    if (region == ARC_MMU_REGION_HOLE) {
        env->aux_mmu_fault_sts = 0;
        return ARC_MMU_TRANSLATE_HOLE;
    }

    if (region == ARC_MMU_REGION_RTP0) {
        rtp = env->aux_mmu_rtp0;
        tsz = t0sz;
    } else {
        rtp = env->aux_mmu_rtp1;
        tsz = t1sz;
    }

    /* Find a scheme which corresponds to the current MMU configuration */
    for (int i = 0; i < ARRAY_SIZE(arc_mmu_schemes); i++) {
        if (arc_mmu_schemes[i].type == mmu_type && arc_mmu_schemes[i].tsz == tsz) {
            scheme = &arc_mmu_schemes[i];
        }
    }

    g_assert(scheme != NULL);

    root_table_addr = arc_mmu_extract_addr(rtp, scheme->root_shift, scheme->pa_bits);

    qemu_log_mask(CPU_LOG_MMU,
                  "arc: mmu: translate vaddr=0x" TARGET_FMT_lx
                  " %s region=%s root=0x%" HWADDR_PRIx "\n",
                  vaddr,
                  type == MMU_INST_FETCH ? "fetch" :
                  type == MMU_DATA_STORE ? "store" : "load",
                  region == ARC_MMU_REGION_RTP0 ? "RTP0" : "RTP1",
                  root_table_addr);

    return arc_mmu_walk(env, scheme, tsz, vaddr, root_table_addr, type, user, paddr, prot);
}

G_NORETURN void arc_mmu_raise(CPUARCState *env, ARCMMUTranslateResult result,
                              MMUAccessType access_type, target_ulong address,
                              uintptr_t retaddr)
{
    ARCException excp;
    int parameter = 0;

    if (result == ARC_MMU_TRANSLATE_HOLE) {
        switch (access_type) {
        case MMU_INST_FETCH:
            excp = ARC_EXCP_TLB_MISS_I_INV_ADDR;
            break;
        case MMU_DATA_STORE:
        case MMU_DATA_LOAD:
            excp = ARC_EXCP_TLB_MISS_D_INV_ADDR;
            break;
        default:
            g_assert_not_reached();
        }
    } else if (result == ARC_MMU_TRANSLATE_ACCESS_FLAG) {
        switch (access_type) {
        case MMU_INST_FETCH:
            excp = ARC_EXCP_TLB_MISS_I_ACCESS_FLAG;
            break;
        case MMU_DATA_STORE:
        case MMU_DATA_LOAD:
            excp = ARC_EXCP_TLB_MISS_D_ACCESS_FLAG;
            break;
        default:
            g_assert_not_reached();
        }
    } else if (result == ARC_MMU_TRANSLATE_MISS) {
        switch (access_type) {
        case MMU_INST_FETCH:
            excp = ARC_EXCP_TLB_MISS_I;
            break;
        case MMU_DATA_STORE:
            excp = ARC_EXCP_TLB_MISS_D_ST;
            break;
        case MMU_DATA_LOAD:
            excp = ARC_EXCP_TLB_MISS_D_LD;
            break;
        default:
            g_assert_not_reached();
        }
    } else if (result == ARC_MMU_TRANSLATE_PROTV) {
        parameter = ARC_EXCP_PROTV_PARAM_MMU;

        switch (access_type) {
        case MMU_INST_FETCH:
            excp = ARC_EXCP_PROTV_EX;
            break;
        case MMU_DATA_STORE:
            excp = ARC_EXCP_PROTV_ST;
            break;
        case MMU_DATA_LOAD:
            excp = ARC_EXCP_PROTV_LD;
            break;
        default:
            g_assert_not_reached();
        }
    } else {
        g_assert_not_reached();
    }

    qemu_log_mask(CPU_LOG_MMU,
                  "arc: mmu: fault result=%d vaddr=0x" TARGET_FMT_lx
                  " sts=0x%x\n",
                  result, address, env->aux_mmu_fault_sts);

    env->excp_mem_addr = address;
    arc_raise_exception(env, excp, parameter, retaddr);
}

static void arc_mmu_flush(CPUARCState *env)
{
    tlb_flush(env_cpu(env));
}

/* Common ARCv3 AUX registers */

target_ulong arc_aux_mmu_tlb_data0_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_tlb_data0;
}

void arc_aux_mmu_tlb_data0_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_tlb_data0 = value;
}

target_ulong arc_aux_mmu_tlb_data1_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_tlb_data1;
}

void arc_aux_mmu_tlb_data1_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_tlb_data1 = value;
}

target_ulong arc_aux_mmu_tlb_idx_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_tlb_idx;
}

void arc_aux_mmu_tlb_idx_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_tlb_idx = value;
}

void arc_aux_mmu_tlb_cmd_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    uint32_t cmd = value & 0x3f;

    env->aux_mmu_tlb_cmd = value;

    switch (cmd) {
    case ARC_MMU_TLB_CMD_READ:
        break;
    default:
        arc_mmu_flush(env);
        break;
    }
}

target_ulong arc_aux_mmu_ctrl_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_ctrl;
}

void arc_aux_mmu_ctrl_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_ctrl = value;
    arc_mmu_flush(env);
}

target_ulong arc_aux_mmu_ttbc_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_ttbc;
}

void arc_aux_mmu_ttbc_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_ttbc = value;
    arc_mmu_flush(env);
}

target_ulong arc_aux_mmu_fault_sts_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_fault_sts;
}

#ifdef TARGET_ARCV3_64

target_ulong arc_aux_mmu_rtp0_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_rtp0;
}

void arc_aux_mmu_rtp0_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_rtp0 = value;
    arc_mmu_flush(env);
}

target_ulong arc_aux_mmu_rtp1_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_rtp1;
}

void arc_aux_mmu_rtp1_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_rtp1 = value;
    arc_mmu_flush(env);
}

target_ulong arc_aux_mmu_mem_attr_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_mem_attr;
}

void arc_aux_mmu_mem_attr_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_mem_attr = value;
}

#else

target_ulong arc_aux_memseg_read(CPUARCState *env, uintptr_t retaddr)
{
    return 0;
}

void arc_aux_memseg_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
}

target_ulong arc_aux_mmu_rtp0lo_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_rtp0 & 0xffffffffull;
}

void arc_aux_mmu_rtp0lo_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_rtp0 = (env->aux_mmu_rtp0 & 0xffffffff00000000ull) |
                        ((uint64_t)value & 0xffffffffull);
    arc_mmu_flush(env);
}

target_ulong arc_aux_mmu_rtp0hi_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_rtp0 >> 32;
}

void arc_aux_mmu_rtp0hi_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_rtp0 = (env->aux_mmu_rtp0 & 0xffffffffull) |
                        ((uint64_t)value << 32);
    arc_mmu_flush(env);
}

target_ulong arc_aux_mmu_rtp1lo_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_rtp1 & 0xffffffffull;
}

void arc_aux_mmu_rtp1lo_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_rtp1 = (env->aux_mmu_rtp1 & 0xffffffff00000000ull) |
                        ((uint64_t)value & 0xffffffffull);
    arc_mmu_flush(env);
}

target_ulong arc_aux_mmu_rtp1hi_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_rtp1 >> 32;
}

void arc_aux_mmu_rtp1hi_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_rtp1 = (env->aux_mmu_rtp1 & 0xffffffffull) |
                        ((uint64_t)value << 32);
    arc_mmu_flush(env);
}

target_ulong arc_aux_mmu_mem_attr_lo_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_mem_attr & 0xffffffffull;
}

void arc_aux_mmu_mem_attr_lo_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_mem_attr = (env->aux_mmu_mem_attr & 0xffffffff00000000ull) |
                            ((uint64_t)value & 0xffffffffull);
}

target_ulong arc_aux_mmu_mem_attr_hi_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_mem_attr >> 32;
}

void arc_aux_mmu_mem_attr_hi_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_mem_attr = (env->aux_mmu_mem_attr & 0xffffffffull) |
                            ((uint64_t)value << 32);
}

#endif

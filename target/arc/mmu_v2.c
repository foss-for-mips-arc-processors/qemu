#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "mmu.h"
#include "exec/cputlb.h"
#include "exec/cpu-common.h"
#include "exec/page-protection.h"
#include "exec/target_page.h"

/* TODO: Use combined MMU index with User bit + ASID bits */
/* TODO: Implement super pages */

/*
 * Helpers operating on packed page descriptors and the TLB array.
 */

/* Virtual page number of an address (page offset and bit 31 cleared) */
static inline uint32_t arc_mmu_vpn(uint32_t addr)
{
    return addr & ARC_MMU_VPN_MASK;
}

/* Index of the TLB set serving the given VPN */
static inline uint32_t arc_mmu_set_of(uint32_t vpn)
{
    return (vpn >> ARC_MMU_PAGE_BITS) & (ARC_MMU_TLB_SETS - 1);
}

/* First TLB way of the set serving the given VPN */
static inline arc_mmu_tlb_entry_t *arc_mmu_set_base(CPUARCState *env,
                                                    uint32_t vpn)
{
    return &env->mmu_tlb[arc_mmu_set_of(vpn) * ARC_MMU_TLB_WAYS];
}

static bool arc_mmu_entry_matches(uint32_t pd0, uint32_t vpn, uint32_t asid)
{
    if (!(pd0 & R_AUX_MMU_TLBPD0_V_MASK)) {
        return false;
    }

    if (arc_mmu_vpn(pd0) != vpn) {
        return false;
    }

    if (pd0 & R_AUX_MMU_TLBPD0_G_MASK) {
        return true;
    }

    if (pd0 & R_AUX_MMU_TLBPD0_S_MASK) {
        return false;
    }

    return FIELD_EX32(pd0, AUX_MMU_TLBPD0, A) == asid;
}

/* Whether the access is permitted by the entry's permission bits */
static bool arc_mmu_permitted(uint32_t pd1, bool user, MMUAccessType type)
{
    switch (type) {
    case MMU_DATA_LOAD:
        return pd1 & (user ? R_AUX_MMU_TLBPD1_RU_MASK : R_AUX_MMU_TLBPD1_RK_MASK);
    case MMU_DATA_STORE:
        return pd1 & (user ? R_AUX_MMU_TLBPD1_WU_MASK : R_AUX_MMU_TLBPD1_WK_MASK);
    case MMU_INST_FETCH:
        return pd1 & (user ? R_AUX_MMU_TLBPD1_EU_MASK : R_AUX_MMU_TLBPD1_EK_MASK);
    default:
        return false;
    }
}

/* QEMU page protection flags granted by the entry's permission bits */
static int arc_mmu_page_prot(uint32_t pd1, bool user)
{
    int prot = 0;

    if (pd1 & (user ? R_AUX_MMU_TLBPD1_RU_MASK : R_AUX_MMU_TLBPD1_RK_MASK)) {
        prot |= PAGE_READ;
    }

    if (pd1 & (user ? R_AUX_MMU_TLBPD1_WU_MASK : R_AUX_MMU_TLBPD1_WK_MASK)) {
        prot |= PAGE_WRITE;
    }

    if (pd1 & (user ? R_AUX_MMU_TLBPD1_EU_MASK : R_AUX_MMU_TLBPD1_EK_MASK)) {
        prot |= PAGE_EXEC;
    }

    return prot;
}

/*
 * Translate a virtual address to a physical address. Side-effect free: the
 * caller decides whether to update TLBPD0 and raise an exception.
 */
ARCMMUTranslateResult arc_mmu_translate(CPUARCState *env, target_ulong vaddr,
                               MMUAccessType type, bool user, bool debug,
                               hwaddr *paddr, int *prot)
{
    arc_mmu_tlb_entry_t *base, *hit = NULL;
    uint32_t vpn;
    int matches = 0;

    /* When the MMU is disabled every address is mapped directly */
    if (!env->aux_mmu_pid.enabled) {
        *paddr = vaddr;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return ARC_MMU_TRANSLATE_OK;
    }

    /* The upper 2 GB are not translated and reserved for the kernel */
    if (vaddr >= ARC_MMU_TRANSLATED_END) {
        /* Upper 2 GB are not available in user mode when MMU is enabled */
        if (user && !debug) {
            return ARC_MMU_TRANSLATE_PROTV;
        }

        *paddr = vaddr;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return ARC_MMU_TRANSLATE_OK;
    }

    vpn = arc_mmu_vpn(vaddr);
    base = arc_mmu_set_base(env, vpn);

    for (int way = 0; way < ARC_MMU_TLB_WAYS; way++) {
        if (arc_mmu_entry_matches(base[way].pd0, vpn, env->aux_mmu_pid.asid)) {
            hit = &base[way];
            matches++;
        }
    }

    /* It's OS's responsibility to provide missing pages */
    if (matches == 0) {
        return ARC_MMU_TRANSLATE_MISS;
    }

    /* It's OS's responsibility to fix overlapping pages */
    if (matches > 1) {
        return ARC_MMU_TRANSLATE_OVERLAP;
    }

    if (!debug && !arc_mmu_permitted(hit->pd1, user, type)) {
        return ARC_MMU_TRANSLATE_PROTV;
    }

    *paddr = (hit->pd1 & ARC_MMU_PAGE_MASK) | (vaddr & ~ARC_MMU_PAGE_MASK);
    *prot = arc_mmu_page_prot(hit->pd1, user);
    return ARC_MMU_TRANSLATE_OK;
}

/* Human-readable name of an access type, for logging */
static const char *arc_mmu_access_name(MMUAccessType type)
{
    switch (type) {
    case MMU_DATA_LOAD:
        return "load";
    case MMU_DATA_STORE:
        return "store";
    case MMU_INST_FETCH:
        return "fetch";
    default:
        return "unknown";
    }
}

G_NORETURN void arc_mmu_raise(CPUARCState *env, ARCMMUTranslateResult result,
                              MMUAccessType access_type, target_ulong address,
                              uintptr_t retaddr)
{
    ARCException excp;
    int parameter = 0;
    bool user = arc_in_user_mode(env);

    switch (result) {
    case ARC_MMU_TRANSLATE_MISS:
        qemu_log_mask(CPU_LOG_MMU,
                      "arc: mmu: TLB miss: vaddr=0x%08x %s asid=0x%02x at pc=0x%08x\n",
                      (uint32_t)address, arc_mmu_access_name(access_type),
                      env->aux_mmu_pid.asid, env->pc);

        /*
         * Load TLBPD0 with the faulting VPN and the current ASID and set the
         * valid bit (the global bit stays clear) to aid the TLB miss handler.
         */
        env->aux_mmu_tlbpd0 = FIELD_DP32(arc_mmu_vpn(address) | R_AUX_MMU_TLBPD0_V_MASK, AUX_MMU_TLBPD0, A, env->aux_mmu_pid.asid);

        switch (access_type) {
        case MMU_DATA_STORE:
            excp = ARC_EXCP_TLB_MISS_D_ST;
            break;
        case MMU_INST_FETCH:
            excp = ARC_EXCP_TLB_MISS_I;
            break;
        case MMU_DATA_LOAD:
            excp = ARC_EXCP_TLB_MISS_D_LD;
            break;
        default:
            g_assert_not_reached();
        }
        break;

    case ARC_MMU_TRANSLATE_PROTV:
        qemu_log_mask(CPU_LOG_MMU,
                      "arc: mmu: protection violation: vaddr=0x%08x %s %s asid=0x%02x at pc=0x%08x\n",
                      (uint32_t)address, arc_mmu_access_name(access_type),
                      user ? "user" : "kernel", env->aux_mmu_pid.asid, env->pc);

        switch (access_type) {
        case MMU_DATA_STORE:
            excp = ARC_EXCP_PROTV_ST;
            break;
        case MMU_INST_FETCH:
            excp = ARC_EXCP_PROTV_EX;
            break;
        case MMU_DATA_LOAD:
            excp = ARC_EXCP_PROTV_LD;
            break;
        default:
            g_assert_not_reached();
        }

        parameter = ARC_EXCP_PROTV_PARAM_MMU;
        break;

    case ARC_MMU_TRANSLATE_OVERLAP:
        qemu_log_mask(CPU_LOG_MMU,
                      "arc: mmu: TLB overlap (machine check): vaddr=0x%08x asid=0x%02x at pc=0x%08x\n",
                      (uint32_t)address, env->aux_mmu_pid.asid, env->pc);

        excp = ARC_EXCP_TLB_OVERLAP;
        break;

    default:
        g_assert_not_reached();
    }

    env->excp_mem_addr = address;
    arc_raise_exception(env, excp, parameter, retaddr);
}

/*
 * TLB maintenance commands.
 */

/* Human-readable name of a TLB command, for logging */
static const char *arc_mmu_cmd_name(uint32_t cmd)
{
    switch (cmd) {
    case ARC_MMU_TLB_CMD_WRITE:
        return "TLBWrite";
    case ARC_MMU_TLB_CMD_WRITENI:
        return "TLBWriteNI";
    case ARC_MMU_TLB_CMD_READ:
        return "TLBRead";
    case ARC_MMU_TLB_CMD_GETINDEX:
        return "TLBGetIndex";
    case ARC_MMU_TLB_CMD_PROBE:
        return "TLBProbe";
    case ARC_MMU_TLB_CMD_IVUTLB:
        return "TLBIVUTLB";
    case ARC_MMU_TLB_CMD_INSERT:
        return "TLBInsert";
    case ARC_MMU_TLB_CMD_DELETE:
        return "TLBDelete";
    default:
        return "unknown";
    }
}

/* Report the outcome of a TLB command through TLBIndex */
static void arc_mmu_tlbindex_result(CPUARCState *env, uint32_t index, bool error)
{
    env->aux_mmu_tlbindex.index = index;
    env->aux_mmu_tlbindex.rc = 0;
    env->aux_mmu_tlbindex.error = error;
}

/* Write the staged TLBPD0/TLBPD1 to the entry selected by TLBIndex */
static void arc_mmu_cmd_write(CPUARCState *env)
{
    uint32_t index = env->aux_mmu_tlbindex.index;
    arc_mmu_tlb_entry_t *entry;

    if (index >= ARC_MMU_TLB_ENTRIES) {
        qemu_log_mask(CPU_LOG_MMU,
                      "arc: mmu: TLBWrite: index=%u out of range\n", index);
        arc_mmu_tlbindex_result(env, 0, true);
        return;
    }

    entry = &env->mmu_tlb[index];
    entry->pd0 = env->aux_mmu_tlbpd0;
    entry->pd1 = env->aux_mmu_tlbpd1;

    qemu_log_mask(CPU_LOG_MMU,
                  "arc: mmu: TLBWrite: index=%u pd0=0x%08x pd1=0x%08x\n",
                  index, entry->pd0, entry->pd1);

    /* The entry contents changed, drop the cached QEMU translations */
    tlb_flush(env_cpu(env));
}

/* Read the entry selected by TLBIndex into TLBPD0/TLBPD1 */
static void arc_mmu_cmd_read(CPUARCState *env)
{
    uint32_t index = env->aux_mmu_tlbindex.index;
    arc_mmu_tlb_entry_t *entry;

    if (index >= ARC_MMU_TLB_ENTRIES) {
        qemu_log_mask(CPU_LOG_MMU,
                      "arc: mmu: TLBRead: index=%u out of range\n", index);
        arc_mmu_tlbindex_result(env, 0, true);
        env->aux_mmu_tlbpd0 = 0;
        env->aux_mmu_tlbpd1 = 0;
        return;
    }

    entry = &env->mmu_tlb[index];
    env->aux_mmu_tlbpd0 = entry->pd0;
    env->aux_mmu_tlbpd1 = entry->pd1;

    qemu_log_mask(CPU_LOG_MMU,
                  "arc: mmu: TLBRead: index=%u pd0=0x%08x pd1=0x%08x\n",
                  index, env->aux_mmu_tlbpd0, env->aux_mmu_tlbpd1);

    /* A successful read clears the error flag and result code */
    arc_mmu_tlbindex_result(env, index, false);
}

/* Insert the staged entry, replacing any existing match for its VPN */
static void arc_mmu_cmd_insert(CPUARCState *env)
{
    uint32_t pd0 = env->aux_mmu_tlbpd0;
    uint32_t pd1 = env->aux_mmu_tlbpd1;
    uint32_t vpn = arc_mmu_vpn(pd0);
    uint32_t asid = FIELD_EX32(pd0, AUX_MMU_TLBPD0, A);
    uint32_t set = arc_mmu_set_of(vpn);
    arc_mmu_tlb_entry_t *base = &env->mmu_tlb[set * ARC_MMU_TLB_WAYS];
    int matched = -1, invalid = -1, way;

    /*
     * Drop all cached QEMU translations. A full flush is required because an
     * ARC page (8 KiB) spans two QEMU softmmu pages (4 KiB), and because the
     * round-robin path below may evict a victim entry mapping a different VPN.
     */
    tlb_flush(env_cpu(env));

    for (way = 0; way < ARC_MMU_TLB_WAYS; way++) {
        uint32_t entry_pd0 = base[way].pd0;
        if (arc_mmu_entry_matches(entry_pd0, vpn, asid)) {
            matched = way;
            break;
        }
        if (invalid < 0 && !(entry_pd0 & R_AUX_MMU_TLBPD0_V_MASK)) {
            invalid = way;
        }
    }

    if (matched >= 0) {
        way = matched;
    } else if (invalid >= 0) {
        way = invalid;
    } else {
        way = env->mmu_way_next[set];
        env->mmu_way_next[set] = (way + 1) & (ARC_MMU_TLB_WAYS - 1);
    }

    base[way].pd0 = pd0;
    base[way].pd1 = pd1;

    qemu_log_mask(CPU_LOG_MMU,
                  "arc: mmu: TLBInsert: vpn=0x%08x asid=0x%02x pd1=0x%08x -> index=%u (%s)\n",
                  vpn, asid, pd1, set * ARC_MMU_TLB_WAYS + way,
                  matched >= 0 ? "replaced" : "allocated");

    /*
     * Report the chosen index. When the entry did not replace an existing
     * match the hardware sets the error flag (a freshly allocated slot).
     */
    arc_mmu_tlbindex_result(env, set * ARC_MMU_TLB_WAYS + way, matched < 0);
}

/* Invalidate every entry matching the VPN/ASID staged in TLBPD0 */
static void arc_mmu_cmd_delete(CPUARCState *env)
{
    uint32_t pd0 = env->aux_mmu_tlbpd0;
    uint32_t vpn = arc_mmu_vpn(pd0);
    uint32_t asid = FIELD_EX32(pd0, AUX_MMU_TLBPD0, A);
    uint32_t set = arc_mmu_set_of(vpn);
    arc_mmu_tlb_entry_t *base = &env->mmu_tlb[set * ARC_MMU_TLB_WAYS];
    int found = -1, way;

    /* See arc_mmu_cmd_insert: a full flush keeps both 4 KiB halves coherent */
    tlb_flush(env_cpu(env));

    for (way = 0; way < ARC_MMU_TLB_WAYS; way++) {
        if (arc_mmu_entry_matches(base[way].pd0, vpn, asid)) {
            base[way].pd0 &= ~R_AUX_MMU_TLBPD0_V_MASK;
            found = set * ARC_MMU_TLB_WAYS + way;
        }
    }

    qemu_log_mask(CPU_LOG_MMU,
                  "arc: mmu: TLBDelete: vpn=0x%08x asid=0x%02x -> %s index=%u\n",
                  vpn, asid, (found < 0) ? "no match" : "deleted",
                  (found < 0) ? 0 : found);

    arc_mmu_tlbindex_result(env, (found < 0) ? 0 : found, found < 0);
}

/*
 * AUX register accessors.
 */

target_ulong arc_aux_pid_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_pack_aux_mmu_pid(&env->aux_mmu_pid);
}

void arc_aux_pid_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    arc_unpack_aux_mmu_pid(&env->aux_mmu_pid, value);

    qemu_log_mask(CPU_LOG_MMU,
                  "arc: mmu: PID write: enabled=%d asid=0x%02x at pc=0x%08x\n",
                  env->aux_mmu_pid.enabled, env->aux_mmu_pid.asid, env->pc);

    /* A new ASID changes the active address space, drop cached translations */
    tlb_flush(env_cpu(env));
}

target_ulong arc_aux_tlbindex_read(CPUARCState *env, uintptr_t retaddr)
{
    return arc_pack_aux_mmu_tlbindex(&env->aux_mmu_tlbindex);
}

void arc_aux_tlbindex_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    /* Only the INDEX field is writable; the E and RC fields are read-only */
    env->aux_mmu_tlbindex.index = FIELD_EX32(value, AUX_MMU_TLBINDEX, INDEX);
}

void arc_aux_tlbcommand_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    uint32_t cmd = FIELD_EX32(value, AUX_MMU_TLBCOMMAND, CMD);

    qemu_log_mask(CPU_LOG_MMU, "arc: mmu: command %s (0x%x) at pc=0x%08x\n",
                  arc_mmu_cmd_name(cmd), cmd, env->pc);

    switch (cmd) {
    case ARC_MMU_TLB_CMD_WRITE:
    case ARC_MMU_TLB_CMD_WRITENI:
        /* WRITE and WRITENI behave identically as uTLBs are not modelled */
        arc_mmu_cmd_write(env);
        break;
    case ARC_MMU_TLB_CMD_READ:
        arc_mmu_cmd_read(env);
        break;
    case ARC_MMU_TLB_CMD_INSERT:
        arc_mmu_cmd_insert(env);
        break;
    case ARC_MMU_TLB_CMD_DELETE:
        arc_mmu_cmd_delete(env);
        break;
    case ARC_MMU_TLB_CMD_IVUTLB:
        /* uTLBs are not modelled, nothing to invalidate */
        break;
    default:
        qemu_log_mask(LOG_UNIMP,
                      "arc: mmu: unsupported TLB command 0x%x at pc=0x%08x\n",
                      cmd, env->pc);
        break;
    }
}

target_ulong arc_aux_tlbpd0_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_tlbpd0;
}

void arc_aux_tlbpd0_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_tlbpd0 = value;
}

target_ulong arc_aux_tlbpd1_read(CPUARCState *env, uintptr_t retaddr)
{
    return env->aux_mmu_tlbpd1;
}

void arc_aux_tlbpd1_write(CPUARCState *env, target_ulong value, uintptr_t retaddr)
{
    env->aux_mmu_tlbpd1 = value;
}

target_ulong arc_aux_scratch_data0_read(CPUARCState *env, uintptr_t retaddr) {
    return env->aux_mmu_scratch_data0;
}

void arc_aux_scratch_data0_write(CPUARCState *env, target_ulong value, uintptr_t retaddr) {
    env->aux_mmu_scratch_data0 = value;
}

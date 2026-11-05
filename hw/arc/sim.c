#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "elf.h"
#include "system/reset.h"
#include "system/system.h"
#include "semihosting/semihost.h"
#include "cpu.h"
#include "hw/arc/cpudevs.h"

#define ARC_SIM_RAM_BASE 0x00000000

static void arc_sim_load_kernel(ARCCPU *cpu, MachineState *machine) {
    const char *kernel_filename = machine->kernel_filename;
    uint64_t elf_entry;
    int elf_machine;
    ssize_t success;

    if (kernel_filename) {
#if defined(TARGET_ARCV2)
        elf_machine = EM_ARC_COMPACT2;
#elif defined(TARGET_ARCV3_32)
        elf_machine = EM_ARC_COMPACT3_32;
#elif defined(TARGET_ARCV3_64)
        elf_machine = EM_ARC_COMPACT3_64;
#else
#error "Unsupported target"
#endif

        success = load_elf(kernel_filename, NULL, NULL, NULL, &elf_entry,
                           NULL, NULL, NULL, 0, elf_machine, 0, 0);
        if (success < 0) {
            error_report("could not load kernel '%s': %s",
                         kernel_filename, load_elf_strerror(success));
            exit(EXIT_FAILURE);
        }

        cpu->env.pc = (target_ulong) elf_entry;
        cpu->env.gpr[ARC_REGNUM_PCL] = (target_ulong) arc_pc_to_pcl(elf_entry);
    }
}

static void arc_sim_init(MachineState *machine)
{
    ARCCPU *cpu = ARC_CPU(cpu_create(machine->cpu_type));

    cpu_arc_pic_init(cpu);
    cpu_arc_clock_init(cpu);

    memory_region_add_subregion(get_system_memory(), ARC_SIM_RAM_BASE, machine->ram);

    arc_sim_load_kernel(cpu, machine);
}

#if defined(TARGET_ARCV2)
static void arc_sim_machine_init(MachineClass *mc)
{
    mc->desc = "ARCv2 simulator (bare-metal)";
    mc->is_default = true;
    mc->init = arc_sim_init;
    mc->max_cpus = 1;
    mc->no_serial = 1;
    mc->default_cpu_type = TYPE_ARC_CPU_HS;
    mc->default_ram_size = 4 * GiB;
    mc->default_ram_id = "arc.ram";
}
#elif defined(TARGET_ARCV3_32)
static void arc_sim_machine_init(MachineClass *mc)
{
    mc->desc = "ARCv3 32-bit simulator (bare-metal)";
    mc->is_default = true;
    mc->init = arc_sim_init;
    mc->max_cpus = 1;
    mc->no_serial = 1;
    mc->default_cpu_type = TYPE_ARC_CPU_HS5X;
    mc->default_ram_size = 4 * GiB;
    mc->default_ram_id = "arc.ram";
}
#elif defined(TARGET_ARCV3_64)
static void arc_sim_machine_init(MachineClass *mc)
{
    mc->desc = "ARCv3 64-bit simulator (bare-metal)";
    mc->is_default = true;
    mc->init = arc_sim_init;
    mc->max_cpus = 1;
    mc->no_serial = 1;
    mc->default_cpu_type = TYPE_ARC_CPU_HS6X;
    mc->default_ram_size = 4 * GiB;
    mc->default_ram_id = "arc.ram";
}
#else
#error "Unsupported target"
#endif

DEFINE_MACHINE("arc-sim", arc_sim_machine_init)

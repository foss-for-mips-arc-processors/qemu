#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/loader.h"
#include "elf.h"
#include "system/reset.h"
#include "system/system.h"
#include "hw/pci-host/gpex.h"
#include "hw/sysbus.h"
#include "hw/char/serial-mm.h"
#include "cpu.h"
#include "hw/arc/cpudevs.h"

#if defined(TARGET_ARCV2)
#define ARC_VIRT_RAM_BASE  0x80000000
#else
#define ARC_VIRT_RAM_BASE  0x0
#endif

#define ARC_UBOOT_CMDLINE  1

#define VIRT_IO_BASE       0xf0000000
#define VIRT_IO_SIZE       0x10000000

/* UART */
#define VIRT_UART_NUMBER   2
#define VIRT_UART_OFFSET   0x0
#define VIRT_UART_IRQ      24
#define VIRT_UART_SIZE     0x2000

/* VirtIO */
#define VIRT_VIRTIO_NUMBER 5
#define VIRT_VIRTIO_OFFSET 0x100000
#define VIRT_VIRTIO_BASE   (VIRT_IO_BASE + VIRT_VIRTIO_OFFSET)
#define VIRT_VIRTIO_SIZE   0x2000
#define VIRT_VIRTIO_IRQ    31

/* PCI */
#define VIRT_PCI_ECAM_BASE 0xe0000000
#define VIRT_PCI_ECAM_SIZE 0x01000000
#define VIRT_PCI_MMIO_BASE 0xd0000000
#define VIRT_PCI_MMIO_SIZE 0x10000000
#define VIRT_PCI_PIO_BASE  0xc0000000
#define VIRT_PCI_PIO_SIZE  0x00004000
#define PCIE_IRQ           40  /* IRQs 40-43 as GPEX_NUM_IRQS=4 */

static void create_pcie(ARCCPU *cpu)
{
    hwaddr base_ecam = VIRT_PCI_ECAM_BASE;
    hwaddr size_ecam = VIRT_PCI_ECAM_SIZE;
    hwaddr base_pio  = VIRT_PCI_PIO_BASE;
    hwaddr size_pio  = VIRT_PCI_PIO_SIZE;
    hwaddr base_mmio = VIRT_PCI_MMIO_BASE;
    hwaddr size_mmio = VIRT_PCI_MMIO_SIZE;

    MemoryRegion *ecam_alias;
    MemoryRegion *ecam_reg;
    MemoryRegion *pio_alias;
    MemoryRegion *pio_reg;
    MemoryRegion *mmio_alias;
    MemoryRegion *mmio_reg;

    DeviceState *dev;
    int i;

    dev = qdev_new(TYPE_GPEX_HOST);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);

    /* Map only the first size_ecam bytes of ECAM space. */
    ecam_alias = g_new0(MemoryRegion, 1);
    ecam_reg = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0);
    memory_region_init_alias(ecam_alias, OBJECT(dev), "pcie-ecam",
                             ecam_reg, 0, size_ecam);
    memory_region_add_subregion(get_system_memory(), base_ecam, ecam_alias);

    /*
     * Map the MMIO window into system address space so as to expose
     * the section of PCI MMIO space which starts at the same base address
     * (ie 1:1 mapping for that part of PCI MMIO space visible through
     * the window).
     */
    mmio_alias = g_new0(MemoryRegion, 1);
    mmio_reg = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 1);
    memory_region_init_alias(mmio_alias, OBJECT(dev), "pcie-mmio",
                             mmio_reg, base_mmio, size_mmio);
    memory_region_add_subregion(get_system_memory(), base_mmio, mmio_alias);

    /* Map IO port space. */
    pio_alias = g_new0(MemoryRegion, 1);
    pio_reg = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 2);
    memory_region_init_alias(pio_alias, OBJECT(dev), "pcie-pio",
                             pio_reg, 0, size_pio);
    memory_region_add_subregion(get_system_memory(), base_pio, pio_alias);

    /* Connect IRQ lines. */
    for (i = 0; i < PCI_NUM_PINS; i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(dev), i, cpu->env.irq[PCIE_IRQ + i]);
        gpex_set_irq_num(GPEX_HOST(dev), i, PCIE_IRQ + i);
    }
}

static void arc_load_kernel(ARCCPU *cpu, MachineState *machine)
{
    hwaddr elf_entry;
    int elf_machine;

    if (!machine->kernel_filename) {
        error_report("Missing kernel file");
        exit(EXIT_FAILURE);
    }

#if defined(TARGET_ARCV2)
    elf_machine = EM_ARC_COMPACT2;
#elif defined(TARGET_ARCV3_32)
    elf_machine = EM_ARC_COMPACT3_32;
#elif defined(TARGET_ARCV3_64)
    elf_machine = EM_ARC_COMPACT3_64;
#else
#error "Unsupported target"
#endif

    ssize_t success = load_elf(machine->kernel_filename, NULL, NULL, NULL, &elf_entry,
                               NULL, NULL, NULL, 0, elf_machine, 0, 0);

    if (success < 0) {
        int is_linux = 0;

        success = load_uimage(machine->kernel_filename, &elf_entry, NULL,
                              &is_linux, NULL, NULL);
        if (success >= 0 && !is_linux) {
            error_report("Wrong U-Boot image, only Linux kernel is supported");
            exit(EXIT_FAILURE);
        }
    }

    if (success < 0) {
        error_report("could not load kernel '%s'", machine->kernel_filename);
        exit(EXIT_FAILURE);
    }

    if (machine->kernel_cmdline && strlen(machine->kernel_cmdline)) {
        /* Load "cmdline" far enough from the kernel image. */
        hwaddr cmdline_offset, cmdline_addr;
        const hwaddr max_page_size = 64 * KiB;

        /*
         * During early boot only first 1 GiB is mapped by kernel.
         * So do not place cmdline after that point.
         */
        cmdline_offset = MIN(1 * GiB, machine->ram_size) - strlen(machine->kernel_cmdline);
        cmdline_addr = ARC_VIRT_RAM_BASE + QEMU_ALIGN_DOWN(cmdline_offset, max_page_size);

        cpu_physical_memory_write(cmdline_addr, machine->kernel_cmdline,
                                  strlen(machine->kernel_cmdline));

        /* We're passing "cmdline" */
        cpu->env.gpr[0] = ARC_UBOOT_CMDLINE;
        cpu->env.gpr[2] = cmdline_addr;
    }

    cpu->env.pc = (target_ulong) elf_entry;
    cpu->env.gpr[ARC_REGNUM_PCL] = (target_ulong) arc_pc_to_pcl(elf_entry);
}

static void arc_virt_init(MachineState *machine)
{
    MemoryRegion *system_ram;
    MemoryRegion *system_io;
    ARCCPU *cpu = NULL;

    cpu = ARC_CPU(cpu_create(machine->cpu_type));

    cpu_arc_pic_init(cpu);
    cpu_arc_clock_init(cpu);

    /* Init system DDR */
    system_ram = g_new(MemoryRegion, 1);
    memory_region_init_ram(system_ram, NULL, "arc.ram", machine->ram_size, &error_fatal);
    memory_region_add_subregion(get_system_memory(), 0x0, system_ram);

    /* Init IO area */
    system_io = g_new(MemoryRegion, 1);
    memory_region_init_io(system_io, NULL, NULL, NULL, "arc.io", VIRT_IO_SIZE);
    memory_region_add_subregion(get_system_memory(), VIRT_IO_BASE, system_io);

    for (int i = 0; i < VIRT_UART_NUMBER; i++) {
        serial_mm_init(system_io, VIRT_UART_OFFSET + VIRT_UART_SIZE * i, 2,
                       cpu->env.irq[VIRT_UART_IRQ + i], 115200, serial_hd(i),
                       DEVICE_NATIVE_ENDIAN);
    }

    for (int i = 0; i < VIRT_VIRTIO_NUMBER; i++) {
        sysbus_create_simple("virtio-mmio",
                             VIRT_VIRTIO_BASE + VIRT_VIRTIO_SIZE * i,
                             cpu->env.irq[VIRT_VIRTIO_IRQ + i]);
    }

    create_pcie(cpu);

    arc_load_kernel(cpu, machine);
}

static void arc_virt_machine_init(MachineClass *mc)
{
#if defined(TARGET_ARCV2)
    mc->desc = "ARCv2 simulator for Linux";
    mc->default_cpu_type = TYPE_ARC_CPU_HS;
#elif defined(TARGET_ARCV3_32)
    mc->desc = "ARCv3 32-bit simulator for Linux";
    mc->default_cpu_type = TYPE_ARC_CPU_HS5X;
#elif defined(TARGET_ARCV3_64)
    mc->desc = "ARCv3 64-bit simulator for Linux";
    mc->default_cpu_type = TYPE_ARC_CPU_HS6X;
#else
#error "Unsupported target"
#endif
    mc->is_default = false;
    mc->init = arc_virt_init;
    mc->max_cpus = 1;
    mc->default_ram_size = 4 * GiB;
}

DEFINE_MACHINE("virt", arc_virt_machine_init)

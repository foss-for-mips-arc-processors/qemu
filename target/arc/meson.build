gen = [
  decodetree.process('insn16.decode', extra_args: ['--static-decode=decode_insn16', '--insnwidth=16']),
  decodetree.process('insn32.decode', extra_args: '--static-decode=decode_insn32'),
]

arc_ss = ss.source_set()
arc_ss.add(gen)

arc_ss.add(files(
  'atomic_helper.c',
  'cpu.c',
  'helper.c',
  'op_helper.c',
  'translate.c'
))

arc_ss.add(when: 'TARGET_ARCV2', if_true: files('gdbstub_v2.c'))
arc_ss.add(when: 'TARGET_ARCV3_32', if_true: files('gdbstub_v3_32.c'))
arc_ss.add(when: 'TARGET_ARCV3_64', if_true: files('gdbstub_v3_64.c'))

arc_system_ss = ss.source_set()
arc_system_ss.add(files(
  'aux_helper.c',
  'cache.c',
  'irq.c',
  'mmu.c',
  'semihosting.c',
  'timer.c'
))

arc_system_ss.add(when: 'TARGET_ARCV2', if_true: files('mmu_v2.c'))
arc_system_ss.add(when: 'TARGET_ARCV3_32', if_true: files('mmu_v3.c'))
arc_system_ss.add(when: 'TARGET_ARCV3_64', if_true: files('mmu_v3.c'))

target_arch += {'arc': arc_ss}
target_system_arch += {'arc': arc_system_ss}

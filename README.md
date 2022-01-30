# gdb-tricore

A gdb which supports a TriCore processor.

Tested with https://github.com/volumit/qemu

set qemu_command "/home/dummy/qemu_tricore_6250/bin/qemu-system-tricore -nographic -M tricore_tsim161 -S -gdb tcp::1234 -kernel"

Still work to be done:

Fix the remaining unexpected failures

Fix the unexpected successes

Fix the unknow successes

Recheck if untested/unsupported testcases are plausible

extension of testcases/unwinding towards more complicated use case (e.g. Interrupt,Trap etc.)

extension to check multicore thread/inferior 

Remarks:

Fails in the gdb test suite are maybe related:

gcc, binutils, newlib, gdb, qemu

It is a hard task to findout the root cause.



Test run by dummy on Sun Jan 30 08:06:44 2022

Target is tricore-unknown-elf

Host   is x86_64-pc-linux-gnu

=== gdb tests ===

Schedule of variations:
    tricore-qemu
    
=== gdb Summary ===

nr of expected passes		62983

nr of unexpected failures	20

nr of unexpected successes	12

nr of expected failures		291

nr of unknown successes		2

nr of known failures			71

nr of unresolved testcases	7

nr of untested testcases		183

nr of unsupported tests		385

nr of paths in test names	2

nr of duplicate test names	114

/home/dummy/aurix_gdb_10/bin/tricore-elf-gdb version  10.0.50.20200909-git -nw -nx -iex "set height 0" -iex "set width 0" 


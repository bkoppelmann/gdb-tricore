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

# of expected passes		62983
# of unexpected failures	20
# of unexpected successes	12
# of expected failures		291
# of unknown successes		2
# of known failures			71
# of unresolved testcases	7
# of untested testcases		183
# of unsupported tests		385
# of paths in test names	2
# of duplicate test names	114
/home/dummy/aurix_gdb_10/bin/tricore-elf-gdb version  10.0.50.20200909-git -nw -nx -iex "set height 0" -iex "set width 0" 


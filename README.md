# gdb_arm
**Inline assembler of ARM assembly instructions and data directives for gdb:**<br>
`assemble` is a user command extension for assembling ARM instructions right in gdb’s console.<br>
This command is implemented in python 2.7. Its source code is allocated within the ´inline-assembler´ directory.<br>

## Purpose
I created this user command to allow ARM learners to type machine language instructions (and data directives) directly in the gdb’s console.<br>
`assemble` transforms a single assembly line (typed after the command) into machine-level bytes, and copies those bytes into the memory space of the ARM simulator managed by the `arm-eabi-gdb` debugger.<br>
After byte insertion, one should be able to test how those instructions work by executing them with regular gdb commands (`stepi`, `nexti`, `continue`, etc.).<br>
This way, one can check out the behavior of tiny programs or single instructions quickly, avoiding the burden of the full development process (creating a project, creating a source file, defining segments and main routine, assembling and linking, loading the executable, etc.).<br>

## Related
The interested machine language learners can look for much more elaborated user commands intended for enhancing the native gdb’s functionality. Namely, one can check out [GEF]( https://github.com/hugsy/gef), [gdb-dashboard](https://github.com/cyrus-and/gdb-dashboard) or [pwngdb](https://github.com/pwndbg/pwndbg) github projects. I think GEF is the only one that allows assembling ARM code inside gdb, though.<br>
One can also find other environments specifically designed to learn ARM machine language, such as [VisUAL](https://salmanarif.bitbucket.io/visual/) or [gdbgui](https://pypi.org/project/gdbgui/0.7.9.4/).<br>
However, my goal is much more modest, since I was just looking for the assembly command, so I decided to build my own lightweight gdb’s extension.<br>

## Requisites
To run the Python scripts that make the assembly, you will need a version of `arm-eabi-gdb` compiled with the Python flag enabled, pointing to a Python 2 installation in your hard drive. I also recommend enabling the gdb’s TUI (Textual User Interface), but it is not mandatory.<br>
Unfortunately, I found that latest gdb versions can **NOT** execute fresh ARM instructions inserted with the `assemble` command. I was able to exec fresh instructions with version 7.3.1 (or older), but perhaps it would also work with a proper gdb configuration in newer versions, I don’t know.<br>
Finally, you’ll need to load a dummy (empty) program into gdb before you can start inserting new ARM data and instructions. For this purpose, the file ´dummy.elf´ is included in this repo, which is a mere sequence of 15 `nop` instructions (`mov r0, r0`) followed by an infinite loop.<br>


## Installation
You must copy the ´inline-assembler´ directory into your gdb's python directory (´<gdb's binary directory>/../share/gdb/python´).<br>
To enable the new `assemble` command, you must type the following into gdb's console:
```
(gdb) source <path>/install_gdb
```
where <path > must be the path to file ´install_gdb.gdb´, which is included within the ´inline-assembler´ directory but you can copy it into another directory of your convenience.<br> 

## Usage
```
(gdb) assemble ADDRESS INSTRUCTION
```
You can also use shortcuts for `assemble`, like `assem` or `as`.<br>
For `ADDRESS`, you can type any hexadecimal value that fits in 32 bits, such as `0x82FC`, or you can simply type `>` for assembling into the memory address after the last assembled instruction or directive.<br>
For `INSTRUCTION`, you can type any data directive or ARM instruction recognized by the GNU GAS assembler.<br>
Examples:<br>
```
(gdb) as 0x200 .byte 34, -1, 0x6A, 'h', 89
(gdb) as > .hword 0b10010011101010, 35921
(gdb) assem 0x8000 add r0, pc, lsr #2
(gdb) assem > eorhi r8, #0b011000
(gdb) assemble > umull r4, r5, r8, r3
(gdb) as 0x8028 cmp r5, r6, asr r2
(gdb) as > bne 0x801C
(gdb) as > ldsh r12, [sp, #0x80]
(gdb) as > ldr r4, =0x8BE45002
(gdb) as > strgtb r0, [pc, r2, lsl #3]
```
To check the assembly, you can use gdb commands like `disassemble ADDRESS` or `x /i ADDRESS`. If your gdb is TUI enabled, you can also view the machine language code in a curses-driven window, but you must update its content by moving the view around (e.g., pressing any arrow key) after the inline assembly.

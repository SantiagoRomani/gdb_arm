# gdb_arm
**In-line assembler for ARM assembly instructions and data directives**<br>
'assemble' is a user command extension for assembling ARM instructions right in gdb’s console.<br>
This command is implemented in python 2.7. The source code for ‘assemble’ command is entirely allocated within the 'inline-assembler' directory of this github repository.<br>

## Purpose
I created this software to allow ARM machine language learners to type ARM instructions (and data) directly in the gdb’s console, using the ‘assemble’ user command (not available as native gdb command).<br>
This added command transforms a single assembly line (typed after the command) in the corresponding machine-level bytes, and copies those bytes right into the memory space of the ARM simulator managed by the ‘arm-eabi-gdb’ debugger.<br>
After byte insertion, we should be able test how those instructions work by executing them with regular gdb commands (stepi, nexti, continue, etc.).<br>
This way, one can check out the behavior of tiny programs or single instructions quickly, avoiding the burden of the full development process (creating a project, creating a source file, defining segments and main routine, assembling and linking, loading the executable, etc.).<br>

## Related
The interested learner can look for much more elaborated user commands intended for enhancing the native gdb’s functionality. Namely, you can search github projects [GEF]( https://github.com/hugsy/gef), [gdb-dashboard](https://github.com/cyrus-and/gdb-dashboard) or [pwngdb](https://github.com/pwndbg/pwndbg). I think GEF is the only one that allows assembling code inside gdb, though.<br>
One can also find other environments specifically designed to learn ARM machine language, such as [VisUAL](https://salmanarif.bitbucket.io/visual/) or [gdbgui](https://pypi.org/project/gdbgui/0.7.9.4/).<br>
However, my goal is much more modest, since I was just looking for the assembly command, so I decided to build my own lightweight gdb’s extension.

## Requisites
To run the script, you will need a version of ‘arm-eabi-gdb’ compiled with the Python flag enabled, pointing to a Python 2 installation in your hard drive. I also recommend using the gdb’s TUI (Textual User Interface), but it is not mandatory for running my ‘assemble’ command.<br>
For executing the ARM instructions inserted with the ‘assemble’ command, I discovered that old gdb versions are required: I was able to exec fresh instructions with version 7.3.1 (or older), but maybe it’s a matter of setting a proper gdb configuration in newer gdb versions, I don’t know.<br>
Finally, you’ll need to load a dummy (empty) program into gdb before you can start inserting new ARM data and instructions. For this purpose, the file ‘dummy.s’ is included in this repo, which is a mere list of 15 ‘nop’ instructions followed by an infinite loop. You can assembly with regular GNU tools (arm-none-eabi-as and arm-none-eabi-ld), or you can just load de file ‘dummy.elf’.

## Installation
You must copy the ‘inline-assembler’ directory into your gdb's python directory (e.g., <gdb's binary directory>/../share/gdb/python).  
To enable the new command, you must type the following into gdb`s console:
	(gdb) source <path>/install_gdb. 
where <path > must be set to allow gdb to reach the file ‘install_gdb.gdb’, which is included within the ‘inline-assembler’ directory, but you can copy it into anther directoy of your convenience (e.g. the 

## Usage
	assemble ADDRESS INSTRUCTION
You can also use shortcuts for 'assemble', like 'assem' or 'as'.<br>
For 'ADDRESS', you can type an hexadecimal value, such as '0x82FC' or
![image](https://user-images.githubusercontent.com/766182/118974490-2c448e00-b973-11eb-9104-1f4b958da907.png)

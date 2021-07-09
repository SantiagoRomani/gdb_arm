python
import sys

sys.path[0] = 'c:\\URV\\bmde\\devkitPro\\insight\\share\\gdb\\python\\inline-assembly'

from arm_analyzer import ArmAnalyzer
from gerrors import gerror_dict


class Assemble(gdb.Command):
    """Inline assembler of ARM assembly instructions and data directives;
       'assemble' is a user command extension for assembling ARM instructions
       right in gdb's console.
       This command is implemented in python 2.7. Its code allocated within
	   the 'inline-assembly' directory, which must be placed into the gdb's
       python directory (e.g., <gdb's binary directory>/../share/gdb/python).
       
       Usage (after gdb's prompt):
	   
			(gdb) assemble ADDRESS INSTRUCTION
		
       You can also use shortcuts for 'assemble', like 'assem' or 'as'
       For 'ADDRESS', you can type an hexadecimal value, such as '0x82FC' or
       any other value up to 2^32, or you can simply type '>' for assembling
       into next memory address after last assembled instruction or data.
       For 'INSTRUCTION', you can type a data directive or an ARM instruction
       recognized by the GNU GAS assembler.
       Examples:
           (gdb) as 0x200 .byte 34, -1, 0x6A, 'h', 89
           (gdb) as > .hword 0b10010011101010, 35921
           (gdb) assem 0x8000 add r0, pc, lsr #2
           (gdb) assem > eorhi r8, #0b011000
           (gdb) assemble > umull r4, r5, r8, r3
           (gdb) as 0x8018 cmp r5, r6, asr r2
           (gdb) as > bne 0x802C
           (gdb) as > ldsh r12, [sp, #0x80]
           (gdb) as > ldr r4, =0x8BE45002
           (gdb) as > strgtb r0, [lr, r2, lsl #3]
           etc.
        To check the assembly, you can use gdb commands like 'disassemble ADDR'
        or 'x /i ADDR'. If your gdb is TUI enabled, you can also view the
        machine language code in a curses-driven window, but you must update
        its content by moving the view around (e.g., pressing any arrow key)
		after the inline assembly.
		
		The source code and extra information of this command is available at
		the following github repository:
			https://github.com/SantiagoRomani/gdb_arm.git
    """

    def __init__(self):
        super(Assemble, self).__init__("assemble", gdb.COMMAND_DATA, gdb.COMPLETE_COMMAND)
        self.ARM_analyzer = ArmAnalyzer()
        print "The 'assemble' command has been succesfully installed."
        print "You may feedback comments or bugs to <santiago.romani@urv.cat>."
        print "Type 'help assemble' for details."

    def invoke(self, arg, from_tty):
        (result, state, pos) = self.ARM_analyzer.analyze(arg, 0, len(arg), [])
        if state > 0:
            rid = 0  # Reference InDex: for accessing several (address, content) tuples
            while rid < len(result):  # while there are (address, content) tuples),
                address = result[rid]  # get the address and type of content
                data_type = ('char', 'short', 'unknown', 'int')[result[rid + 1][0] - 1]
                for data in result[rid + 1][1:]:  # traverse all data values and issue a gdb 'set' command
                    gdb_command = "set *(unsigned {0:s} *)(0x{1:X}) = 0x{2:0{width}X}".format(data_type, address, data,
                                                                                              width=result[rid + 1][
                                                                                                        0] * 2)
                    print gdb_command
                    gdb.execute(gdb_command)
                    address = address + result[rid + 1][0]  # advance address for next data value
                rid = rid + 2  # advance to next (address, content) tuple
        else:
            print arg
            print '{message: >{width}}'.format(message='^', width=pos + 1)
            print 'ERROR: ' + gerror_dict[state]


Assemble()
end

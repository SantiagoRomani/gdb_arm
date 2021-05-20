from analyzer import Analyzer
from num_analyzer import NumberAnalyzer
from reg_analyzer import RegisterAnalyzer
from instcond_analyzer import InstcondAnalyzer


class InstjmpAnalyzer(Analyzer):
    """Analyzer 33: branch instructions (b, bl, blo, bhs, etc.)"""

    # creation of subanalyzers
    num_analyzer = NumberAnalyzer()
    reg_analyzer = RegisterAnalyzer()
    instcond_analyzer = InstcondAnalyzer()

    # definition of basic transition entries (lists)
    ent0 = [('bleq', 0x0B000000), ('blo', 0x3A000000), ('bls', 0x9A000000), ('blt', 0xBA000000), ('ble', 0xDA000000)]
    ent1 = [('bx', 0xE12FFF10), ('blx', 0xE12FFF30)]
    ent2 = [('bl', 0xEB000000), ('b', 0xEA000000)]

    # definition of internal transition actions (methods)
    def get_opcode(self, match, sub_result, sub_state, super_result):
        if match:
            self.result.append(4)                           # append number of bytes of instruction
        return 0

    def catch_cond(self, match, sub_result, sub_state, super_result):
        if match:                                           # clear most significant nyble and
            self.result[1] = (self.result[1] & 0x0FFFFFFF) | sub_result[0]   # include cond bits into result
            sub_result *= 0                                 # avoid automatic inclusion of sub_result
        return 0

    def catch_reg(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if sub_result[0] == 15:                         # if any register is pc
                print 'WARNING: it does not make sense to use pc (r15) as Rm in \'bx\' instructions'
            self.result[1] = self.result[1] | sub_result[0]
            sub_result *= 0                                 # avoid automatic inclusion of sub_result
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def catch_offset(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if (sub_result[0] % 4) != 0:                    # if destination address is not word aligned
                override = -3307                                # issue an error
            else:
                base_address = -8 if len(super_result) == 0 else super_result[0][0]
                offset = sub_result[0] - (base_address + 8)     # subtract the base address plus 8 to the target address
                if (offset < -2**25) or (offset >= 2**25):      # if offset outside the branch range (26 - 1 sign bit)
                    override = -3308                                # issue an error
                else:                                       # otherwise, join the 24 bit imm_offset
                    self.result[1] = self.result[1] | ((offset >> 2) & 0x00FFFFFF)
                    sub_result *= 0  # avoid automatic inclusion of sub_result
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1006, -1301, -1302, -1303, -1304]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -3301, None),  # T33.0.0 EOSeq -> missing branch instruction
                            (' ', None, 0, None),       # T33.0.1 skip leading spaces
                            (self.ent0, ' ', -3302, None,               # T33.0.2a missing branch offset
                                                 3, self.get_opcode,    # T33.0.2b 'blo'/'bls'/'blt'/'ble'+ ' ', go to 3
                                             -3303, self.get_opcode),   # T33.0.2c 'blo'/'bls'/'blt'/'ble' + unexpected
                            (self.ent1, ' ', -3304, None,               # T33.0.3a missing branch reg
                                                 4, self.get_opcode,    # T33.0.3b 'bx'/'blx' + ' ', go to 4
                                                 2, self.get_opcode),   # T33.0.3c 'bx'/'blx' + extra text, go to 2
                            (self.ent2, ' ', -3302, None,               # T33.0.4a missing branch offset
                                                 3, self.get_opcode,    # T33.0.4b 'b'/'bl' + ' ', go to 3
                                                 1, self.get_opcode)],  # T33.0.4c 'b'/'bl' + extra text, go to 1
                           -3303),                      # T33.0.5 unrecognizable branch instruction
                      1:  # check for condition in 'b'/'bl'
                          ([(None, None, -3302, None),  # T33.1.0 EOSeq -> missing branch offset (NEVER happens)
                            (self.instcond_analyzer, ' ', -3302, None,  # T33.1.1a missing branch offset
                                                  3, self.catch_cond,   # T33.1.1b 'b'/'bl' + cond + ' ', go to 3
                                              -3303, self.catch_cond)], # T33.1.1c 'b'/'bl' + cond + unexpected text
                           -3303),                      # T33.1.2 wrong text after instruction
                      2:  # check for condition in 'bx'/'blx'
                          ([(None, None, -3304, None),  # T33.2.0 EOSeq -> missing branch register (NEVER happens)
                            (self.instcond_analyzer, ' ', -3302, None,  # T33.2.1a missing branch offset
                                                  4, self.catch_cond,   # T33.2.1b 'bx'/'blx' + cond + ' ', go to 4
                                              -3303, self.catch_cond)], # T33.2.1c 'bx'/'blx' + cond + unexpected text
                           -3303),                      # T33.2.2 wrong text after instruction
                      3:  # parsing branch offset
                          ([(None, None, -3302, None),  # T33.3.0 EOSeq -> missing branch offset
                            (self.num_analyzer, None, 1000, self.catch_offset)], # T33.3.1 branch offset
                           -3305),                      # T33.3.2 unrecognized branch offset
                      4:  # parsing branch register
                          ([(None, None, -3304, None),  # T33.4.0 EOSeq -> missing branch register
                            (self.reg_analyzer, None, 1000, self.catch_reg)],    # T33.4.1 branch reg
                           -3306)                       # T33.4.2 unrecognized branch register (NEVER happens)
                      }
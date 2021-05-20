from analyzer import Analyzer
from reg_analyzer import RegisterAnalyzer
from reg_analyzer import RegisterListAnalyzer
from instcond_analyzer import InstcondAnalyzer


class InstmscAnalyzer(Analyzer):
    """Analyzer 35: miscellanea instructions (push, pop, clz, etc.)"""

    # creation of subanalyzers
    reg_analyzer = RegisterAnalyzer()
    reglist_analyzer = RegisterListAnalyzer()
    instcond_analyzer = InstcondAnalyzer()

    # definition of basic transition entries (lists)
    ent0 = [('push', 0x092D0000), ('pop', 0x08BD0000)]
    ent1 = [('clz', 0x01600010)]

    # definition of internal transition actions (methods)
    def get_opcode(self, match, sub_result, sub_state, super_result):
        if match:
            self.result.append(4)                           # append number of bytes of instruction
            sub_result[0] = 0xE0000000 | sub_result[0]      # mix opcode with no condition (always exec)
        return 0

    def catch_cond(self, match, sub_result, sub_state, super_result):
        if match:                                           # clear most significant nyble and
            self.result[1] = (self.result[1] & 0x0FFFFFFF) | sub_result[0]   # include cond bits into result
            sub_result *= 0                                 # avoid automatic inclusion of sub_result
        return 0

    def catch_reglist(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            self.result[1] = self.result[1] | sub_result[0]     # copy reglist bits into result bits 15..0
            sub_result *= 0                                 # avoid automatic inclusion of sub_result
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def catch_reg(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if self.state == 4:
                self.result[1] = self.result[1] | (sub_result[0] << 12)     # copy Rd bits into result bits 15..12
            else:
                self.result[1] = self.result[1] | sub_result[0]             # copy Rm bits into result bits 3..0
            sub_result *= 0                                 # avoid automatic inclusion of sub_result
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1302, -1303, -1304, -1403, -1502, -1503, -1504]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -3501, None),  # T35.0.0 EOSeq -> missing miscellanea inst.
                            (' ', None, 0, None),       # T35.0.1 skip leading spaces
                            (self.ent0, ' ', -3502, None,                   # T35.0.2a missing 'push'/'pop' list
                                                2, self.get_opcode,         # T32.0.2b inst + ' ', go to 2
                                                1, self.get_opcode),        # T32.0.2c inst + something else, go to 1
                            (self.ent1, ' ', -3502, None,                   # T35.0.3a missing 'clz' operands
                                                4, self.get_opcode,         # T32.0.3b inst + ' ', go to 4
                                                3, self.get_opcode)],       # T32.0.3c inst + something else, go to 3
                           -3503),                      # T35.0.4 unrecognizable miscellanea instruction
                      1:  # check for condition
                          ([(None, None, -3599, None),  # T35.1.0 EOSeq -> wrong text after instruction (NEVER happens)
                            (self.instcond_analyzer, ' ', -3502, None,      # T35.1.1a missing 'push'/'pop' list
                                                    2, self.catch_cond,     # T35.1.1b 'push'/'pop' + cond + ' ', goto 3
                                                -3504, self.catch_cond)],   # T35.1.1c inst + cond + something (error)
                           -3504),                      # T32.1.3 wrong text after instruction
                      2:  # get the register list
                          ([(None, None, -3502, None),  # T35.2.0 EOSeq -> missing 'push'/'pop' list
                            (self.reglist_analyzer, None, 1000, self.catch_reglist)],   # T35.2.1 get the reg list
                           -3599),                      # T35.2.2 wrong text after instruction (NEVER happens)
                      3:  # check for condition
                          ([(None, None, -3599, None),  # T35.3.0 EOSeq -> wrong text after instruction (NEVER happens)
                            (self.instcond_analyzer, ' ', -3502, None,      # T35.3.1a missing 'clz' list
                                                    4, self.catch_cond,     # T35.3.1b 'clz' + cond + ' ', go to 4
                                                -3504, self.catch_cond)],   # T35.3.1c 'clz' + cond + something (error)
                           -3504),                      # T32.3.2 wrong text after instruction
                      4:  # parsing first register
                          ([(None, None, -3502, None),  # T35.4.0 EOSeq -> missing first reg
                            (self.reg_analyzer, ',', -3502, self.error_spring,  # T35.4.1a missing operands
                                                         5, self.catch_reg,     # T35.4.1b Rd + ',', go to 5
                                                     -3505, self.error_spring)],    # T35.4.1c wrong text after Rd
                           -3599),                      # T35.4.2 unrecognized operands (NEVER happens)
                      5:  # parsing second register
                          ([(None, None, -3502, None),  # T35.5.0 EOSeq -> missing second reg
                            (self.reg_analyzer, None, 1000, self.catch_reg)],   # T35.5.1 Rm
                           -3505)                       # T35.5.2 unrecognized operands
                      }
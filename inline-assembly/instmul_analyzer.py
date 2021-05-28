from analyzer import Analyzer
from reg_analyzer import RegisterAnalyzer
from instcond_analyzer import InstcondAnalyzer


class InstmulAnalyzer(Analyzer):
    """Analyzer 32: multiplication instructions (mul, mla, umull, smull, etc.)"""

    # creation of subanalyzers
    reg_analyzer = RegisterAnalyzer()
    instcond_analyzer = InstcondAnalyzer()

    # definition of basic transition entries (lists)
    ent0 = [('mul', 0x00000090), ('mla', 0x00200090),
            ('umull', 0x00800090), ('umlal', 0x00A00090), ('smull', 0x00C00090), ('smlal', 0x00E00090)]

    # definition of internal transition actions (methods)
    def get_opcode(self, match, sub_result, sub_state, super_result):
        if match:
            self.result.append(4)  # append number of bytes of instruction
            sub_result[0] = 0xE0000000 | sub_result[0]  # mix opcode with no condition (always exec)
        return 0

    def catch_cond(self, match, sub_result, sub_state, super_result):
        if match:  # clear most significant nyble and
            self.result[1] = (self.result[1] & 0x0FFFFFFF) | sub_result[0]  # include cond bits into result
            sub_result *= 0  # avoid automatic inclusion of sub_result
        return 0

    def catch_setflags(self, match, sub_result, sub_state, super_result):
        if match:
            self.result[1] = self.result[1] | 0x00100000  # include set flags (bit 20) into result
            sub_result *= 0  # avoid automatic inclusion of sub_result
        return 0

    reg_shifts = [[16, 0, 8, 12],  # register shifts for short multiplies
                  [12, 16, 0, 8]]  # register shifts for long multiplies

    def catch_reg(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if sub_result[0] == 15:  # if any register is pc
                override = -3208  # issue an error
            elif ((self.result[1] & 0x00E00000) == 0) and (self.state == 6):  # if it is 'mul' & reg4
                override = -3207  # issue an error
            elif ((self.result[1] & 0x00800000) == 0) and (self.state == 4):  # if 'mul'/'mla' & reg2
                if ((self.result[1] >> 16) & 0xF) == sub_result[0]:  # and Rd = Rm
                    print 'WARNING: Rd should not be equal to Rm in multiply instructions'
            elif (self.result[1] & 0x00800000) != 0:  # if long multiply & reg2
                if (self.state == 4) and (((self.result[1] >> 12) & 0xF) == sub_result[0]):  # and RdLo = RdHi
                    print 'WARNING: RdHi, RdLo and Rm must all be different in long multiply instructions'
                if (self.state == 5) and ((((self.result[1] >> 12) & 0xF) == sub_result[0])  # if long multiply & reg3
                                          or (((self.result[1] >> 16) & 0xF) == sub_result[0])):  # and RdLo = Rm
                    print 'WARNING: RdHi and RdLo must be different in long multiply instructions'
            if override == 0:
                mul_type = (self.result[1] >> 23) & 1  # 0: short mult, 1: long mult
                # shift reg bits according to type of multiplication and number of reg operand
                self.result[1] = self.result[1] | (sub_result[0] << self.reg_shifts[mul_type][self.state - 3])
            sub_result *= 0  # avoid automatic inclusion of sub_result
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def catch_reg3(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            override = self.catch_reg(match, sub_result, sub_state, super_result)
            if (override == 0) and ((self.result[1] & 0x00E00000) == 0):  # if it is 'mul'
                override = 1000  # set up a success
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1301, -1302, -1303, -1304]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -3201, None),  # T32.0.0 EOSeq -> missing multiplication instruction
                            (' ', None, 0, None),  # T32.0.1 skip leading spaces
                            (self.ent0, ' ', -3202, None,  # T32.0.2a missing multiplication operands
                             3, self.get_opcode,  # T32.0.2b inst + ' ', go to 3
                             1, self.get_opcode)],  # T32.0.2c inst + something else, go to 1
                           -3203),  # T32.0.3 unrecognizable multiplication instruction
                      1:  # check for condition
                          ([(None, None, -3204, None),  # T32.1.0 EOSeq -> wrong text after instruction (NEVER happens)
                            (self.instcond_analyzer, ' ', -3202, None,  # T32.1.1a missing multiplication operands
                             3, self.catch_cond,  # T32.1.1b inst + cond + ' ', go to 3
                             2, self.catch_cond),  # T32.1.1c inst + cond + something (maybe 's')
                            ('s', ' ', -3202, None,  # T32.1.2a missing multiplication operands
                             3, self.catch_setflags,  # T32.1.2b inst + 's' + ' ', go to 3
                             -3205, None)],  # T32.1.2c found other text after 's'
                           -3204),  # T32.1.3 wrong text after instruction
                      2:  # check for 's'
                          ([(None, None, -3205, None),  # T32.2.0 EOSeq -> missing space after inst. (NEVER happens)
                            ('s', ' ', -3202, None,  # T32.2.1a missing multiplication operands
                             3, self.catch_setflags,  # T32.2.1b inst + 's' + ' ', go to 3
                             -3205, None)],  # T32.2.1c found other text after 's'
                           -3205),  # T32.2.2 wrong text after instruction
                      3:  # parsing first register
                          ([(None, None, -3202, None),  # T32.3.0 EOSeq -> missing multiplication operands
                            (self.reg_analyzer, ',', -3202, self.error_spring,  # T32.3.1a missing mult. operands
                             4, self.catch_reg,  # T32.3.1b reg1 + ',', go to 4
                             -3206, self.error_spring)],  # T32.3.1c wrong text after register
                           -3206),  # T32.3.2 unrecognized multiplication operands (NEVER happens)
                      4:  # parsing second register
                          ([(None, None, -3202, None),  # T32.4.0 EOSeq -> missing multiplication operands
                            (self.reg_analyzer, ',', -3202, self.error_spring,  # T32.4.1a missing mult. operands
                             5, self.catch_reg,  # T32.4.1b reg2 + ',', go to 5
                             -3206, self.error_spring)],  # T32.4.1c wrong text after register
                           -3206),  # T32.4.2 unrecognized multiplication operands (NEVER happens)
                      5:  # parsing third register
                          ([(None, None, -3202, None),  # T32.5.0 EOSeq -> missing multiplication operands
                            (self.reg_analyzer, ',', -3202, self.catch_reg3,  # T32.5.1a catch three mult. operands
                             6, self.catch_reg,  # T32.5.1b reg3 + ',', go to 6
                             -3206, self.error_spring)],  # T32.5.1c wrong text after register
                           -3206),  # T32.5.2 unrecognized multiplication operands (NEVER happens)
                      6:  # parsing fourth register
                          ([(None, None, -3202, None),  # T32.6.0 EOSeq -> missing multiplication operands
                            (self.reg_analyzer, None, 1000, self.catch_reg)],  # T32.6.1 reg4
                           -3206)  # T32.6.2 unrecognized multiplication operands (NEVER happens)
                      }

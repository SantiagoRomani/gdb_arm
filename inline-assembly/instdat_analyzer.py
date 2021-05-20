from analyzer import Analyzer
from opdat_analyzer import OpdatAnalyzer
from instcond_analyzer import InstcondAnalyzer


class InstdatAnalyzer(Analyzer):
    """Analyzer 31: data instructions (add, mov, cmp, and, etc.)"""

    # creation of subanalyzers
    opdat_analyzer = OpdatAnalyzer()
    instcond_analyzer = InstcondAnalyzer()

    # definition of basic transition entries (lists)
    ent0 = [('and', 0), ('eor', 1), ('sub', 2), ('rsb', 3), ('add', 4), ('adc', 5), ('sbc', 6), ('rsc', 7),
            ('tst', 8), ('teq', 9), ('cmp', 10), ('cmn', 11), ('orr', 12), ('mov', 13), ('bic', 14), ('mvn', 15)]

    # definition of internal transition actions (methods)
    def get_opcode(self, match, sub_result, sub_state, super_result):
        if match:
            self.result.append(4)                           # append number of bytes of instruction
            opcode = sub_result[0]
            sub_result[0] = 0xE0000000 | opcode << 21       # shift opcode, no condition (always exec)
            if (opcode >= 8) and (opcode <= 11):                # if instructions 'tst', 'teq', 'cmp', 'cmn'
                sub_result[0] = sub_result[0] | 0x00100000          # force set flags (bit 25)
        return 0

    def catch_cond(self, match, sub_result, sub_state, super_result):
        if match:                                           # clear most significant nyble and
            self.result[1] = (self.result[1] & 0x0FFFFFFF) | sub_result[0]   # include cond bits into result
            sub_result *= 0                                 # avoid automatic inclusion of sub_result
        return 0

    def catch_setflags(self, match, sub_result, sub_state, super_result):
        if match:
            self.result[1] = self.result[1] | 0x00100000    # include set flags (bit 20) into result
            sub_result *= 0                                 # avoid automatic inclusion of sub_result
        return 0

    def catch_operands(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            self.result[1] = self.result[1] | sub_result[0]           # include operands bits
            sub_result *= 0                                 # avoid automatic inclusion of sub_result
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1102, -1103, -1104, -1105, -1302, -1303, -1304,
                           -1603, -1604, -1605, -1606, -1607, -1703, -1704, -1705, -1706,
                           -2204, -2205, -2207, -2302, -2303, -2304, -2306, -2308, -2310, -2311]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -3101, None),  # T31.0.0 EOSeq -> missing instruction
                            (' ', None, 0, None),       # T31.0.1 skip leading spaces
                            (self.ent0, ' ', -3102, None,               # T31.0.2a missing data operands
                                                 3, self.get_opcode,    # T31.0.2b inst + ' ', go to 3
                                                 1, self.get_opcode)],  # T31.0.2c inst + something else, go to 1
                           -3103),                      # T31.0.3 unrecognizable data instruction
                      1:  # check for condition
                          ([(None, None, -3104, None),  # T31.1.0 EOSeq -> wrong text after instruction (NEVER happens)
                            (self.instcond_analyzer, ' ', -3102, None,  # T31.1.1a missing data operands
                                                  3, self.catch_cond,   # T31.1.1b inst + cond + ' ', go to 3
                                                  2, self.catch_cond),  # T31.1.1c inst + cond + something (maybe 's')
                            ('s', ' ', -3102, None,                     # T31.1.2a missing data operands
                                           3, self.catch_setflags,      # T31.1.2b inst + 's' + ' ', go to 3
                                       -3105, None)],                   # T31.1.2c found other text after 's'
                           -3104),                      # T31.1.3 wrong text after instruction
                      2:  # check for 's'
                          ([(None, None, -3105, None),  # T31.2.0 EOSeq -> missing space after inst. (NEVER happens)
                            ('s', ' ', -3102, None,                     # T31.2.1a missing data operands
                                           3, self.catch_setflags,      # T31.2.1b inst + 's' + ' ', go to 3
                                       -3105, None)],                   # T31.2.1c found other text after 's'
                           -3105),                      # T31.2.3 wrong text after instruction
                      3:  # parsing operands
                          ([(None, None, -3102, None),  # T31.3.0 EOSeq -> missing data operands
                            (self.opdat_analyzer, None, 1000, self.catch_operands)],  # T31.3.1 get the operands
                           -3106)                       # T31.3.2 unrecognized data operands (NEVER happens)
                      }
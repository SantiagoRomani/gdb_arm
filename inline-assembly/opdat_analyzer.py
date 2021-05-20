from analyzer import Analyzer
from reg_analyzer import RegisterAnalyzer
from op2_analyzer import Op2Analyzer


class OpdatAnalyzer(Analyzer):
    """Analyzer 23: operands analyzer for data instructions, with 2 or 3 operands (and, sub, add, cmp, mov, etc.)"""

    # creation of subanalyzers
    register_analyzer = RegisterAnalyzer()
    op2_analyzer = Op2Analyzer()

    # definition of internal transition actions (methods)
    def catch_dest(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            self.result.append(sub_result[0] << 12)          # memorize destination register
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def catch_source1(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            self.result[0] = self.result[0] | (sub_result[0] << 16)   # memorize source 1 operand (register)
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def catch_source2(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            opcode = 0
            index = 0                               # seek a list with format [4, inst_code] within super_result list
            while (index < len(super_result)) and not (isinstance(super_result[index], list)
                    and (len(super_result[index]) == 2) and (super_result[index][0] == 4)):
                index = index + 1
            if index < len(super_result):               # if it has found the instruction list entry in super_result
                instruction = super_result[index][1]        # get the instruction
                opcode = (instruction >> 21) & 0xF          # get the opcode
            if self.state == 1:                             # in case there is just one source operand
                if (opcode != 13) and (opcode != 15):           # in case of NOT a move instruction
                    self.result[0] = self.result[0] | (self.result[0] << 4)     # copy destination reg field into
                                                                                # source 1 reg field
                if (opcode >= 8) and (opcode <= 11):            # in case of a compare instruction
                    self.result[0] = self.result[0] & 0xFFFF0FFF    # clear destination register
            else:                                           # in case there are two source operands
                if (opcode >= 8) and (opcode <= 11):            # in case of a compare instruction
                    override = -2310                                # issue an error
                if (opcode == 13) or (opcode == 15):            # in case of a move instruction
                    override = -2311                                # issue an error
            self.result[0] = self.result[0] | sub_result[0]     # memorize source 2 (immediate or reg or shifted reg)
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1102, -1103, -1104, -1105, -1302, -1303, -1304,
                           -1603, -1604, -1605, -1606, -1607, -1703, -1704, -1705, -1706,
                           -2204, -2205, -2207]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -2301, None),  # T23.0.0 EOSeq -> missing operands
                            (self.register_analyzer, ',', -2302, self.error_spring,     # T23.0.1a only destination reg
                                                              1, self.catch_dest,       # T23.0.1b dest reg, continue
                                                          -2309, self.error_spring)],   # T23.0.1c NEVER happens
                           -2303),                      # T23.0.2 unrecognizable destination register
                      1:  # parsing source operand (source 1 or source 2)
                          ([(None, None, -2304, None),  # T23.1.0 EOSeq -> missing source operands
                            (self.op2_analyzer, None, 1000, self.catch_source2),        # T23.1.1 parse imm-based shift
                            (self.register_analyzer, ',', 1000, self.catch_source2,     # T23.1.2a only one source reg
                                                             2, self.catch_source1,     # T23.1.2b source 1, continue
                                                         -2305, None)],                 # T23.1.2c NEVER happens
                            -2306),                     # T23.1.3 unrecognized source operand
                      2:  # parsing second source operand
                          ([(None, None, -2307, None),  # T23.2.0 EOSeq -> missing second operand (NEVER happens)
                            (self.op2_analyzer, None, 1000, self.catch_source2)],       # T23.2.1 parse second op
                           -2308)                       # T23.2.2 wrong text after second register
                      }
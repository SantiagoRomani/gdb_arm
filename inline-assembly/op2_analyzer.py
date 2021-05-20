from analyzer import Analyzer
from reg_analyzer import RegisterAnalyzer
from imm_analyzer import ImmediateRSAnalyzer
from imm_analyzer import ImmediateOpAnalyzer


class Op2Analyzer(Analyzer):
    """Analyzer 22: second operand analyzer (immediate, reg or or shifted reg operand)"""

    # creation of subanalyzers
    register_analyzer = RegisterAnalyzer()
    immediate_sr_analyzer = ImmediateRSAnalyzer()
    immediate_op_analyzer = ImmediateOpAnalyzer()

    # definition of basic transition entries (lists)
    ent0 = [('lsl', 0), ('lsr', 1), ('asr', 2), ('ror', 3)]

    # definition of internal transition actions (methods)
    def imm_operand(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            sub_result[0] = sub_result[0] | 0x02000000  # activate bit 25 for immediate operands
        override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def catch_mode(self, match, sub_result, sub_state, super_result):
        if match:
            self.mode = sub_result[0]                   # memorize mode
            sub_result *= 0
        return 0

    def reg_shifting(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            self.result[0] = (sub_result[0] << 8) | (self.mode << 5) | 0x10 | self.result[0]
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def imm_shifting(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if (self.mode != 0) and (sub_result[0] == 0):
                if (self.mode == 1) or (self.mode == 2):
                    print "WARNING: '%s #0' has been converted into 'LSL #0'" % ('LSR' if self.mode == 1 else 'ASR')
                else:
                    print "WARNING: 'ROR #0' will be interpreted as 'RRX' by ARM processors"
                # do not pack "LSR #0" nor "ASR #0", which must be coded as "LSL #0"
            if (self.mode == 0) or (self.mode == 3) or (sub_result[0] != 0):
                self.result[0] = (sub_result[0] << 7) | (self.mode << 5) | self.result[0]
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of inner variables
        self.mode = 0
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1006, -1102, -1103, -1104, -1105, -1303, -1304,
                           -1603, -1604, -1605, -1606, -1607, -1703, -1704, -1705, -1706]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -2201, None),  # T22.0.0 EOSeq -> missing second operand
                            (self.immediate_op_analyzer, None, 1000, self.imm_operand), # T22.0.1 immediate operand
                            (self.register_analyzer, ',', 1000, self.error_spring,      # T22.0.2a single register
                                                             1, self.error_spring,      # T22.0.2b maybe shifted reg
                                                         -2202, self.error_spring)],    # T22.0.2c NEVER happens
                           -2203),                      # T22.0.3 unrecognizable second operand
                      1:  # parsing shift mode
                          ([(None, None, -2204, None),  # T22.1.0 EOSeq -> missing shift mode
                            (' ', None, 1, None),       # T22.1.1 skip spaces
                            (self.ent0, ' ', -2205, None,               # T22.1.2a missing info after shift mode
                                                 2, self.catch_mode,    # T22.1.2b continue parsing shift info
                                             -2206, None)],             # T22.1.2c missing space after shift mode
                            -2206),                     # T22.1.3 unrecognized shift mode
                      2:  # parsing shift info
                          ([(None, None, -2205, None),  # T22.2.0 EOSeq -> missing info after shift mode
                            (self.register_analyzer, None, 1000, self.reg_shifting),     # T22.2.1 parse reg-based shift
                            (self.immediate_sr_analyzer, None, 1000, self.imm_shifting)],# T22.2.2 parse imm-based shift
                           -2207)                       # T22.2.3 wrong info after shift mode (NEVER happens)
                      }
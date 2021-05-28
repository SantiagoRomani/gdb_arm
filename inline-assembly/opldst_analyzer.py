from analyzer import Analyzer
from num_analyzer import NumberAnalyzer
from reg_analyzer import RegisterAnalyzer
from imm_analyzer import ImmediateRSAnalyzer


class Opldst2Analyzer(Analyzer):
    """Analyzer 24: second addressing mode analyzer (for 'ldr', 'str', 'ldrb', 'strb')"""

    # creation of subanalyzers
    number_analyzer = NumberAnalyzer()
    register_analyzer = RegisterAnalyzer()
    immediate_sr_analyzer = ImmediateRSAnalyzer()

    # definition of basic transition entries (lists)
    ent0 = [('lsl', 0), ('lsr', 1), ('asr', 2), ('ror', 3)]

    # definition of internal transition actions (methods)
    def catch_base(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:  # shift Rn bits into bits 19..16 and set bit P = 1 (offset indexing)
            sub_result[0] = 0x1800000 | (sub_result[0] << 16)  # as well as bit U = 1 (positive addition)
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def neg_displ(self, match, sub_result, sub_state, super_result):
        if match:
            self.result[0] = self.result[0] & 0xFF7FFFFF  # set bit U = 0
            sub_result *= 0
        return 0

    def imm_displ(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:  # if immediate outside the displacement range (12 bits, positive or negative)
            if (sub_result[0] <= -(2 ** 12)) or (sub_result[0] >= 2 ** 12):
                override = -2411  # issue an error
            else:  # otherwise, join the 12 lower bit displacement
                if sub_result[0] < 0:  # in case of negative immediate value
                    sub_result[0] = -sub_result[0]  # change sign of value
                    self.result[0] = self.result[0] & 0xFF7FFFFF  # set bit U = 0
                self.result[0] = self.result[0] | sub_result[0]  # join 12 lower bits of displacement
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def reg_displ(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if sub_result[0] != 15:  # join Rm bits into lower bits (3..0) of result, plus bit 25 = 1 (reg. displ.)
                self.result[0] = self.result[0] | 0x02000000 | sub_result[0]
            else:
                override = -2412  # pc (r15) is not allowed as reg. displacement
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def catch_mode(self, match, sub_result, sub_state, super_result):
        if match:
            self.mode = sub_result[0]  # memorize mode
            sub_result *= 0
        return 0

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
        self.error_list = [-1002, -1003, -1004, -1005, -1006, -1303, -1304, -1702, -1703, -1704, -1705, -1706]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -2401, None),  # T24.0.0 EOSeq -> missing address
                            (' ', None, 0, None),  # T24.0.1 skip spaces
                            ('[', None, 1, None)],  # T24.0.2 detection of '['
                           -2402),  # T24.0.3 failed to detect '['
                      1:  # parsing Rn (base register)
                          ([(None, None, -2403, None),  # T24.1.0 EOSeq -> missing Rn
                            (self.register_analyzer, ',]', -2404, self.error_spring,  # T24.1.1a missing ']'
                             2, self.catch_base,  # T24.1.1b found Rn + ','
                             7, self.catch_base,  # T24.1.1c found Rn + ']'
                             -2499, self.error_spring)],  # T24.1.1d NEVER happens
                           -2403),  # T24.1.2 unrecognizable base register
                      2:  # parsing displacement
                          ([(None, None, -2405, None),  # T24.2.0 EOSeq -> missing offset or reg displacement
                            (' ', None, 2, None),  # T24.2.1 skip spaces
                            ('+', None, 3, None),  # T24.2.2 positive displacement, got to 3
                            ('-', None, 3, self.neg_displ),  # T24.2.3 negative displacement, set U=1 and go to 3
                            ('#', None, 4, None),  # T24.2.4 start of immediate displacement
                            (self.register_analyzer, ',]', -2404, self.error_spring,  # T24.2.5a missing ']'
                             5, self.reg_displ,  # T24.2.5b scaled reg. displ
                             7, self.reg_displ,  # T24.2.5c register displ.
                             -2499, self.error_spring)],  # T24.2.5d NEVER happens
                           -2406),  # T24.2.6 unrecognized displacement
                      3:  # parsing reg displacement after '+' or '-'
                          ([(None, None, -2405, None),  # T24.3.0 EOSeq -> missing offset or reg displacement
                            (self.register_analyzer, ',]', -2404, self.error_spring,  # T24.3.1a missing ']'
                             5, self.reg_displ,  # T24.3.1b scaled reg. displ
                             7, self.reg_displ,  # T24.3.1c register displ.
                             -2499, self.error_spring)],  # T24.3.1d NEVER happens
                           -2406),  # T24.3.2 unrecognized reg displacement
                      4:  # parsing immediate displacement after '#'
                          ([(None, None, -2405, None),  # T24.4.0 EOSeq -> missing offset or reg displacement
                            (self.number_analyzer, ']', -2404, self.error_spring,  # T24.4.1a missing ']'
                             7, self.imm_displ,  # T24.4.1b immediate displ.
                             -2499, self.error_spring)],  # T24.4.1c NEVER happens
                           -2406),  # T24.4.2 unrecognized immediate displacement
                      5:  # parsing scaling shift mode
                          ([(None, None, -2407, None),  # T24.5.0 EOSeq -> missing shift mode
                            (' ', None, 5, None),  # T24.5.1 skip spaces
                            (self.ent0, ' ', -2408, None,  # T24.5.2a missing info after shift mode
                             6, self.catch_mode,  # T24.5.2b continue parsing shift info
                             -2409, None)],  # T24.5.2c missing space after shift mode
                           -2409),  # T24.5.3 unrecognized shift mode
                      6:  # parsing shift info
                          ([(None, None, -2408, None),  # T24.6.0 EOSeq -> missing info after shift mode
                            (self.immediate_sr_analyzer, ']', -2404, self.error_spring,  # T24.6.1a missing ']'
                             7, self.imm_shifting,  # T24.6.1b immediate shift
                             -2499, self.error_spring)],  # T24.6.1c NEVER happens
                           -2409),  # T24.6.2 wrong info after shift mode
                      7:  # check EOSeq
                          ([(None, None, 1000, None),  # T24.7.0 EOSeq -> complete addressing mode 2 (offset variant)
                            (' ', None, 7, None)],  # T24.7.1 trim trailing spaces
                           -2410)  # T24.7.2 error: post and pre-indexing currently not supported
                      }


class Opldst3Analyzer(Analyzer):
    """Analyzer 25: third addressing mode analyzer (for 'ldrh', 'strh', 'ldrsb', 'ldrsh')"""

    # creation of subanalyzers
    number_analyzer = NumberAnalyzer()
    register_analyzer = RegisterAnalyzer()

    # definition of internal transition actions (methods)
    def catch_base(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:  # shift Rn bits into bits 19..16 and set bit P = 1 (offset indexing)
            sub_result[0] = 0x01C00000 | (sub_result[0] << 16)  # as well as bit I = 1 (immediate displacement)
        else:  # as well as bit U = 1 (positive addition
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def neg_displ(self, match, sub_result, sub_state, super_result):
        if match:
            self.result[0] = self.result[0] & 0xFF7FFFFF  # set bit U = 0
            sub_result *= 0
        return 0

    def imm_displ(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:  # if immediate outside the displacement range (8 bits, positive or negative)
            if (sub_result[0] <= -(2 ** 8)) or (sub_result[0] >= 2 ** 8):
                override = -2511  # issue an error
            else:  # otherwise, join the 8 bits displacement
                if sub_result[0] < 0:  # in case of negative immediate value
                    sub_result[0] = -sub_result[0]  # change sign of value
                    self.result[0] = self.result[0] & 0xFF7FFFFF  # set bit U = 0
                high_nyble = sub_result[0] >> 4
                low_nyble = sub_result[0] & 0xF  # mix high and low nybles of the 8 bits displacement
                self.result[0] = self.result[0] | (high_nyble << 8) | low_nyble
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def reg_displ(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if sub_result[0] != 15:  # join Rm bits into lower bits (3..0) of result
                self.result[0] = (self.result[0] & 0xFFBFFFFF) | sub_result[0]  # and clear bit I = 0
            else:
                override = -2512  # pc (r15) is not allowed as reg. displacement
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1006, -1303, -1304]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -2501, None),  # T25.0.0 EOSeq -> missing address
                            (' ', None, 0, None),  # T25.0.1 skip spaces
                            ('[', None, 1, None)],  # T25.0.2 detection of '['
                           -2502),  # T25.0.3 failed to detect '['
                      1:  # parsing Rn (base register)
                          ([(None, None, -2503, None),  # T25.1.0 EOSeq -> missing Rn
                            (self.register_analyzer, ',]', -2504, self.error_spring,  # T25.1.1a missing ']'
                             2, self.catch_base,  # T25.1.1b found Rn + ','
                             7, self.catch_base,  # T25.1.1c found Rn + ']'
                             -2599, self.error_spring)],  # T25.1.1d NEVER happens
                           -2503),  # T25.1.2 unrecognizable base register
                      2:  # parsing displacement
                          ([(None, None, -2505, None),  # T25.2.0 EOSeq -> missing offset or reg displacement
                            (' ', None, 2, None),  # T25.2.1 skip spaces
                            ('+', None, 3, None),  # T25.2.2 positive displacement, got to 3
                            ('-', None, 3, self.neg_displ),  # T25.2.3 negative displacement, set U=1 and go to 3
                            ('#', None, 4, None),  # T25.2.4 start of immediate displacement
                            (self.register_analyzer, ',]', -2504, self.error_spring,  # T25.2.5a missing ']'
                             -2513, self.error_spring,  # T25.2.5b forbid scaled reg
                             7, self.reg_displ,  # T25.2.5c register displ.
                             -2599, self.error_spring)],  # T25.2.5d NEVER happens
                           -2506),  # T25.2.6 unrecognized displacement
                      3:  # parsing reg displacement after '+' or '-'
                          ([(None, None, -2505, None),  # T25.3.0 EOSeq -> missing offset or reg displacement
                            (self.register_analyzer, ',]', -2504, self.error_spring,  # T25.3.1a missing ']'
                             -2513, self.error_spring,  # T25.3.1b scaled reg. displ
                             7, self.reg_displ,  # T25.3.1c register displ.
                             -2599, self.error_spring)],  # T25.3.1d NEVER happens
                           -2506),  # T25.3.2 unrecognized reg displacement
                      4:  # parsing immediate displacement after '#'
                          ([(None, None, -2505, None),  # T25.4.0 EOSeq -> missing offset or reg displacement
                            (self.number_analyzer, ']', -2504, self.error_spring,  # T25.4.1a missing ']'
                             7, self.imm_displ,  # T25.4.1b immediate displ.
                             -2599, self.error_spring)],  # T25.4.1c NEVER happens
                           -2506),  # T25.4.2 unrecognized immediate displacement
                      7:  # check EOSeq
                          ([(None, None, 1000, None),  # T25.7.0 EOSeq -> complete addressing mode 2 (offset variant)
                            (' ', None, 7, None)],  # T25.7.1 trim trailing spaces
                           -2510)  # T25.7.2 error: post and pre-indexing currently not supported
                      }

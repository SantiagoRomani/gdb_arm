from analyzer import Analyzer
from num_analyzer import RadixNumberAnalyzer


class RegisterAnalyzer(Analyzer):
    """Analyze 13: processor registers"""

    # definition of subanalyzers
    dec_number_analyzer = RadixNumberAnalyzer(10)

    # definition of basic transition entries (lists)
    ent0 = [('sp', 13), ('lr', 14), ('pc', 15)]

    # definition of internal transition actions (methods)
    def check_error(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if (sub_result[0] < 0) or (sub_result[0] >= 16):
                override = -1304            # wrong reg number
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -1301, None),  # T13.0.0 EOSeq -> missing register error
                            (' ', None, 0, None),       # T13.0.1 white spaces -> keep state
                            ('r', None, 1, None),       # T13.0.2 possibly a register -> go to 1
                            (self.ent0, None, 1000, None)], # T13.0.3 known reg alias
                           -1302),                      # T13.0.4 unknown register identifier
                      1:  # parse numeric register identifier
                          ([(None, None, -1303, None),  # T13.1.0 EOSeq -> missing register number
                            (self.dec_number_analyzer, None, 1000, self.check_error)], # T13.1.1 maybe good reg number
                           -1304)                       # T13.1.2 wrong reg number
                      }



class RegisterBitsAnalyzer(Analyzer):
    """Analyze 14: processor registers as a bit mask"""

    # definition of subanalyzers
    register_analyzer = RegisterAnalyzer()

    # definition of internal transition actions (methods)
    def encode_one(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            sub_result[0] = 1 << sub_result[0]          # convert number to bit mask
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def encode_range(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            mask1 = self.result[0]
            mask2 = 1 << sub_result[0]                  # convert number to bit mask
            mask3 = mask1 - 1                           # obtain all lower weight bits equal to one
            mask4 = mask2 - 1                           # for both masks
            self.result[0] = mask1 | (mask3 ^ mask4) | mask2    # activate all bits in-between
            sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1302, -1303, -1304]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -1401, None),  # T14.0.0 EOSeq -> missing register id error
                            (' ', None, 0, None),       # T14.0.1 white spaces -> keep state
                            (self.register_analyzer, '-', 1000, self.encode_one,    # T14.0.2a single register
                                                             1, self.encode_one,    # T14.0.2b range list
                                                         -1402, self.error_spring)],# T14.0.2c rubish after register
                           -1402),                      # T14.0.3 unknown register identifier
                      1:  # parse second register identifier
                          ([(None, None, -1403, None),  # T14.1.0 EOSeq -> missing second register in a range list
                            (self.register_analyzer, None, 1000, self.encode_range)],  # T14.1.1 encode binary reg list
                           -1402)                       # T14.1.2 wrong second register identifier
                      }


class RegisterListAnalyzer(Analyzer):
    """Analyze 15: processor register list, as a bit mask"""

    # definition of subanalyzers
    reg_bits_analyzer = RegisterBitsAnalyzer()

    # definition of internal transition actions (methods)
    def encode_list(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if len(self.result) > 0:                    # if result is not empty,
                self.result[0] = self.result[0] | sub_result[0]   # merge the new reg mask
                sub_result *= 0
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1302, -1303, -1304, -1402, -1403]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -1501, None),  # T15.0.0 EOSeq -> missing register list error
                            (' ', None, 0, None),       # T15.0.1 skip leading spaces
                            ('{', None, 1, None)],      # T15.0.2 opening '{' detected, go to 1
                           -1502),                      # T15.0.3 missing opening '{'
                      1:  # parse reg list
                          ([(None, None, -1503, None),  # T15.1.0 EOSeq -> missing registers
                            (self.reg_bits_analyzer, ',}', -1503, self.error_spring,    # T15.1.1a unclosed reg list
                                                               1, self.encode_list,     # T15.1.1b comma separated list
                                                            1000, self.encode_list,     # T15.1.1c closed reg list
                                                           -1599, self.error_spring)],  # T15.1.1d (NEVER happens)
                           -1504)                       # T15.1.2 rubbish after register list
                      }
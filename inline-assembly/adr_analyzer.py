from analyzer import Analyzer
from num_analyzer import RadixNumberAnalyzer


class AddressAnalyzer(Analyzer):
    """Analyze 20: hexadecimal addresses"""

    # definition of subanalyzers
    hex_number_analyzer = RadixNumberAnalyzer(16)

    # definition of internal transition actions (methods)
    def check_error(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if sub_result[0] >= 2**32:
                override = -2004            # too big address error
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -2001, None),  # T20.0.0 EOSeq -> missing hex error
                            (' ', None, 0, None),       # T20.0.1 white spaces -> keep state
                            ('0x', None, 1, None)],     # T20.0.2 possibly hex address -> go to 1
                           -2001),                      # T20.0.3 missing initial hex address error
                      1:  # parse hexadecimal address
                          ([(None, None, -2002, None),  # T20.1.0 EOSeq -> wrong hex number
                            (self.hex_number_analyzer, ' ', -2003, None,  # T20.1.1a EOSeq after address
                                                             1000, self.check_error,  # T20.1.1b catched address
                                                            -2003, None)],# T20.1.1c missing space after address
                           -2003)                       # T20.1.2 wrong hex number
                      }
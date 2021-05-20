from analyzer import Analyzer

class RangeCharAnalyzer(Analyzer):
    """Parses one input character (first of the sequence), if it is in-between a fixed range"""

    def analyze(self, text, init_pos, end_pos, super_result):
        self.result = []                    # initially creates an empty result
        self.state = 1000                   # assume success detection state
        pos = init_pos
        value = ord(text[init_pos])         # obtain the ordinal (ASCII code) of the first char of the sequence
        if (value < self.rlow) or (value > self.rhigh):
            self.state = -1                 # if char not between range, set a failure state
        else:
            self.result.append(value)       # add ASCII code into result
            pos = pos + 1                   # advance position
        return self.result, self.state, pos

    def __init__(self, rlow, rhigh):
        Analyzer.__init__(self)
        self.rlow = rlow
        self.rhigh = rhigh


class CharAnalyzer(Analyzer):
    """Analyzer 11: characters in single quotes"""

    # creation of subanalyzers
    char_range_analyzer = RangeCharAnalyzer(32, 126)

    def __init__(self):
        Analyzer.__init__(self)
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -1101, None),  # T11.0.0 EOSeq -> missing char error
                            (' ', None, 0, None),       # T11.0.1 white spaces -> keep state
                            ('\'', None, 1, None)],     # T11.0.2 char starting quote -> go to 1
                           -1101),                      # T11.0.3 missing char error error
                      1:  # parsing one char in single quotes
                          ([(None, None, -1101, None),  # T11.1.0 EOSeq -> missing char error
                            ('\'', None, -1102, None),  # T11.1.1 empty single quotes
                            (self.char_range_analyzer, None, 2, None)],  # T11.1.2 store one character -> go to 2
                           -1103),                      # T11.1.3 invalid character error
                      2:  # parsing end of single quotes
                          ([(None, None, -1104, None),  # T11.2.0 EOSeq -> unclosed char definition
                            ('\'', None, 1000, None)],  # T11.2.1 successful char capture
                           -1105)                       # T11.2.2 use of single quote for more than one character
                      }


class StringAnalyzer(Analyzer):
    """Analyzer 12: strings in double quotes"""

    # creation of subanalyzers
    char_range_analyzer = RangeCharAnalyzer(32, 126)

    def __init__(self):
        Analyzer.__init__(self)
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -1201, None),  # T12.0.0 EOSeq -> missing string error
                            (' ', None, 0, None),       # T12.0.1 white spaces -> keep state
                            ('\"', None, 1, None)],     # T12.0.2 string starting quote -> go to 1
                           -1201),                      # T12.0.3 missing string error
                      1:  # parsing one char in single quotes
                          ([(None, None, -1201, None),  # T12.1.0 EOSeq -> missing string error
                            ('\"', None, -1202, None),  # T12.1.1 empty string error
                            (self.char_range_analyzer, None, 2, None)],  # T12.1.2 store one character -> go to 2
                           -1203),                      # T12.1.3 invalid character error
                      2:  # parsing characters in a string, ended with double quotes
                          ([(None, None, -1204, None),  # T12.2.0 EOSeq -> unclosed string error
                            ('\"', None, 1000, None),   # T12.2.1 successful string capture
                            (self.char_range_analyzer, None, 2, None)],  # T12.2.2 store one character -> keep state
                           -1203)                       # T12.2.3 invalid character error
                      }
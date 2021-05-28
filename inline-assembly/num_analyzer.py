from analyzer import Analyzer


class RangeDigitDetector(Analyzer):
    """Detects if an input digit is in-between a fixed range"""

    def analyze(self, text, init_pos, end_pos, super_result):
        value = 0
        self.result = []  # initially create an empty result
        self.state = 1000  # assume success detection state
        try:
            value = int(text[init_pos])  # try to obtain one digit value (base = 10)
        except ValueError:
            self.state = -1  # if not a digit, set a failure state
        if (value < self.rlow) or (value > self.rhigh):
            self.state = -2  # if digit not between range, set a failure state
        return self.result, self.state, init_pos  # do NOT advance the position of detected digit

    def __init__(self, rlow, rhigh):
        Analyzer.__init__(self)
        self.rlow = rlow
        self.rhigh = rhigh


class RadixNumberAnalyzer(Analyzer):
    """Parses numbers of a fixed radix"""

    digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

    def find_wrongpos(self, text, init_pos, end_pos):
        # type: (str, int, int) -> (int)
        pos = init_pos  # position to look for wrong digits
        # if (self.radix == 10) and (text[pos] == '-'):
        #    pos = pos + 1                       # skip initial '-' for decimal negative numbers
        wrong_digit = False  # boolean for stating if a wrong digit has been found
        while (pos < end_pos) and not wrong_digit:  # search for the wrong digit
            digit = text[pos].lower()  # avoid lower/upper confusion
            wrong_digit = (not digit in self.digits) or (self.digits.index(digit) >= self.radix)
            if not wrong_digit:  # the digit is wrong if not in the list or
                pos = pos + 1  # it's numeric value (index) is above the radix
        return pos

    def analyze(self, text, init_pos, end_pos, super_result):
        value = 0
        self.result = []  # initially create an empty result
        self.state = 1000  # assume success parsing state
        pos = init_pos
        try:  # up to next delimiter or end of string,
            value = int(text[init_pos:end_pos], base=self.radix)
        except ValueError:  # try to convert string to current radix
            self.state = -1  # when wrong conversion, set a failure state
            pos = self.find_wrongpos(text, init_pos, end_pos)
        if self.state == 1000:
            self.result.append(value)
            pos = end_pos

        return self.result, self.state, pos

    def __init__(self, radix):
        Analyzer.__init__(self)
        self.radix = radix


class NumberAnalyzer(Analyzer):
    """Analyzer 10: numbers of four possible radix: binary, decimal, octal, hexadecimal"""

    # creation of subanalyzers
    bin_number_analyzer = RadixNumberAnalyzer(2)
    oct_number_analyzer = RadixNumberAnalyzer(8)
    dec_number_analyzer = RadixNumberAnalyzer(10)
    hex_number_analyzer = RadixNumberAnalyzer(16)
    dec_range_detector = RangeDigitDetector(1, 9)

    # definition of internal transition actions (methods)
    def check_limits(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if (sub_result[0] >= 2 ** 32) or (sub_result[0] < -2 ** 31):
                override = -1006  # too big number error
        return override

    def invert_number(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            sub_result[0] = -sub_result[0]
            override = self.check_limits(match, sub_result, sub_state, super_result)
        return override

    def insert_zero(self, match, sub_result, sub_state, super_result):
        if match:
            self.result.append(0)
        return 0

    def __init__(self):
        Analyzer.__init__(self)
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -1001, None),  # T10.0.0 EOSeq -> missing number error
                            (' ', None, 0, None),  # T10.0.1 white spaces -> keep state
                            ('0b', None, 1, None),  # T10.0.2 binary prefix -> go to 1
                            ('0x', None, 2, None),  # T10.0.3 hexadecimal prefix -> go to 2
                            ('0', None, 3, None),  # T10.0.4 possibly octal prefix -> go to 3
                            ('-', None, 4, None),  # T10.0.5 negative decimal prefix -> go to 4
                            ('+', None, 6, None),  # T10.0.6 positive decimal prefix -> go to 6
                            (self.dec_range_detector, None, 5, None)],  # T10.0.7 decimal digit -> go to 5
                           -1001),  # T10.0.8 missing number error
                      1:  # parsing next binary digits
                          ([(None, None, -1002, None),  # T10.1.0 EOSeq -> malformed number error
                            (self.bin_number_analyzer, None, 1000, self.check_limits)],  # T10.1.1
                           -1002),  # T10.1.2
                      2:  # parsing next hexadecimal digits
                          ([(None, None, -1005, None),  # T10.2.0 EOSeq -> malformed number error
                            (self.hex_number_analyzer, None, 1000, self.check_limits)],  # T10.2.1
                           -1005),  # T10.2.2
                      3:  # parsing next octal digits
                          ([(None, None, 1000, self.insert_zero),  # T10.3.0 EOSeq -> keep first octal digit
                            (self.oct_number_analyzer, None, 1000, self.check_limits)],  # T10.3.1
                           -1003),  # T10.3.2
                      4:  # parsing next decimal digits (negative number)
                          ([(None, None, -1004, None),  # T10.4.0 EOSeq -> malformed number error
                            (self.dec_number_analyzer, None, 1000, self.invert_number)],
                           # T10.4.1 decimal digit -> invert value
                           -1004),  # T10.4.2 malformed number error
                      5:  # parsing next decimal digits
                          ([(None, None, 1000, None),  # T10.5.0 EOSeq -> NEVER followed (T10.0.6 don't advance pos)
                            (self.dec_number_analyzer, None, 1000, self.check_limits)],  # T10.5.1
                           -1004),  # T10.5.2 malformed number error
                      6:  # parsing next decimal digits
                          ([(None, None, -1004, None),  # T10.5.0 EOSeq -> malformed number error
                            (self.dec_number_analyzer, None, 1000, self.check_limits)],  # T10.5.1
                           -1004),  # T10.5.2 malformed number error
                      }

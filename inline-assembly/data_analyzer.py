from analyzer import Analyzer
from num_analyzer import NumberAnalyzer
from string_analyzer import CharAnalyzer
from string_analyzer import StringAnalyzer

# definition of external helper functions (not class members)
def number_processing(match, result, sub_result, size):
    # type: (bool, list, list, int) -> int
    """Helper function to process numbers of different number of bytes (size)"""
    override = 0
    if match:                                   # in case of successful parsing and number is within range of size
        if (sub_result[0] < 2 ** (8 * size)) and (sub_result[0] >= -2 ** ((8 * size) - 1)):
            result.append(sub_result[0] & (2 ** (8 * size) - 1)) # capture the relevant (lower) bytes according to size
            sub_result *= 0                                 # empty sub_result to avoid automatic merging into result
        else:
            override = -2107                    # out of range data error
    return override


class DataAnalyzer(Analyzer):
    """Analyzer 21: data directives (.byte, .hword, .word, .ascii, .asciz) and following values"""

    # definition of subanalyzers
    number_analyzer = NumberAnalyzer()
    char_analyzer = CharAnalyzer()
    string_analyzer = StringAnalyzer()

    # definition of internal transition actions (methods)
    def stack_size(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:                               # in case of successful parsing,
            size = 1                                # (default) number of bytes of next parsed data
            if sub_state == 3:
                size = 2                                # size for halfwords
            elif sub_state == 4:
                size = 4                                # size for words
            self.result.append(size)
        return override

    def stack_byte(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            override = number_processing(match, self.result, sub_result, 1)
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def stack_hword(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            override = number_processing(match, self.result, sub_result, 2)
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def stack_word(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            override = number_processing(match, self.result, sub_result, 4)
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def stack_chars(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:                               # in case of successful parsing,
            for character in sub_result:
                self.result.append(character)
            sub_result *= 0                         # empty sub_result to avoid merging into results
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def stack_chars_0(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:                               # in case of successful parsing,
            self.stack_chars(match, sub_result, sub_state, super_result)
            self.result.append(0)
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def find_delimiter(self, text, init_pos, end_pos, delimiters):
        # type: (str, int, int, str) -> (int, int)
        """returns the position within the text sequence (from init_pos up to end_pos-1)
            where the closer delimiter occurs, or end_pos if no delimiter is present;
            also returns the index of the closer delimiter inside the 'delimiters' string
            (first -> index 0, second -> index 1, etc.), or -1 if no delimiter has been found

            This method overrides the superclass method to avoid detecting delimiter ',' inside
            strings of chars, by suppressing positions inside single or double quoted sequences
        """
        d_pos = end_pos                             # default delimiter position (end of the sequence)
        d_index = -1                                # default index (no delimiter has been found yet)
        if delimiters is not None:                  # if there are delimiters
            inside_string = 0                           # code of checking quotes (0-> none, 1-> single, 2-> double)
            for j in range(init_pos, end_pos):          # sequential traversal
                if inside_string == 0:                      # if not inside string
                    d_index = delimiters.find(text[j])          # check if current char is a delimiter
                    if d_index > -1:                            # if found,
                        d_pos = j                                   # it is the closest delimiter from the beggining
                        break                                       # stop traversal
                    else:                                       # else, check if an initial quote is found
                        if text[j] == '\'':
                            inside_string = 1                       # initial single quote
                        elif text[j] == '\"':
                            inside_string = 2                       # initial double quote
                else:                                       # when inside string
                    if (inside_string == 1) and (text[j] == '\''):  # check if an ending single quote
                        inside_string = 0
                    elif (inside_string == 2) and (text[j] == '\"'):# check if an ending double quote
                        inside_string = 0

        return d_pos, d_index


    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1006, -1102, -1103, -1104, -1105, -1202, -1203, -1204]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -2101, None),  # T21.0.0 EOSeq -> missing data directive error
                            (' ', None, 0, None),       # T21.0.1 white spaces -> keep state
                            ('.', None, 1, None)],      # T21.0.2 '.' prefix -> go to 1
                           -2101),                      # T21.0.3 missing '.' error
                      1:  # decoder state
                          ([(None, None, -2101, None),  # T21.1.0 EOSeq -> missing data directive error
                            ('byte', ' ', -2102, None,  # T21.1.1a EOSeq after '.byte'
                                              2, self.stack_size,  # T21.1.1b '.byte ' -> go to 2
                                          -2103, None), # T21.1.1c missing space after '.byte'
                            ('hword', ' ', -2102, None, # T21.1.2a EOSeq after '.hword'
                                              3, self.stack_size,  # T21.1.2b '.hword ' -> go to 3
                                          -2103, None), # T21.1.2c missing space after '.hword'
                            ('word', ' ', -2102, None,  # T21.1.3a EOSeq after '.word'
                                              4, self.stack_size,  # T21.1.3b '.word ' -> go to 4
                                          -2103, None), # T21.1.3c missing space after '.word'
                            ('ascii', ' ', -2102, None, # T21.1.4a EOSeq after '.ascii'
                                              5, self.stack_size,  # T21.1.4b '.ascii ' -> go to 5
                                          -2103, None), # T21.1.4c missing space after '.ascii'
                            ('asciz', ' ', -2102, None, # T21.1.5a EOSeq after '.asciz'
                                              6, self.stack_size,  # T21.1.5b '.asciz ' -> go to 6
                                          -2103, None)],# T21.1.5c missing space after '.asciz'
                           -2104),                      # T21.1.6 unknown data directive
                      2:  # parsing bytes
                          ([(None, None, -2102, None),  # T21.2.0 EOSeq -> missing bytes
                            (self.number_analyzer, ',', 1000, self.stack_byte,  # T21.2.1a last number
                                                           2, self.stack_byte,  # T21.2.1b intermediate number
                                                        -1002, self.error_spring),  # T21.2.1c wrong digit
                            (self.char_analyzer, ',', 1000, self.stack_chars,   # T21.2.2a last char
                                                         2, self.stack_chars,   # T21.2.2b intermediate char
                                                     -2105, None)],             # T21.2.2c unexpected separator
                           -2106),                      # T21.2.3 non-recognizable info
                      3:  # parsing halfwords
                          ([(None, None, -2102, None),  # T21.3.0 EOSeq -> missing halfwords
                            (self.number_analyzer, ',', 1000, self.stack_hword, # T21.3.1a last number
                                                           3, self.stack_hword, # T21.3.1b intermediate number
                                                        -1002, self.error_spring)],  # T21.3.1c wrong digit
                           -2106),                      # T21.3.2 non-recognizable info
                      4:  # parsing words
                          ([(None, None, -2102, None),  # T21.4.0 EOSeq -> missing words
                            (self.number_analyzer, ',', 1000, self.stack_word,  # T21.4.1a last number
                                                           4, self.stack_word,  # T21.4.1b intermediate number
                                                        -1002, self.error_spring)],  # T21.4.1c wrong digit
                           -2106),                      # T21.4.2 non-recognizable info
                      5:  # parsing string characters
                          ([(None, None, -2102, None),  # T21.5.0 EOSeq -> missing strings
                            (self.char_analyzer, ',', 1000, self.stack_chars,   # T21.5.1a last char
                                                         5, self.stack_chars,   # T21.5.1b intermediate char
                                                     -2105, self.error_spring),  # T21.5.1c unexpected separator
                            (self.string_analyzer, ',', 1000, self.stack_chars, # T21.5.2a last string
                                                           5, self.stack_chars, # T21.5.2b intermediate string
                                                       -2105, self.error_spring)],  # T21.5.2c unexpected separator
                           -2106),                      # T21.5.3 non-recognizable info
                      6:  # parsing string characters, append a '\0'
                          ([(None, None, -2102, None),  # T21.6.0 EOSeq -> missing strings
                            (self.char_analyzer, ',', 1000, self.stack_chars_0, # T21.6.1a last char
                                                         6, self.stack_chars_0, # T21.6.1b intermediate char
                                                     -2105, self.error_spring),  # T21.6.1c unexpected separator
                            (self.string_analyzer, ',', 1000, self.stack_chars_0, # T21.6.2a last string
                                                           6, self.stack_chars_0, # T21.6.2b intermediate string
                                                       -2105, self.error_spring)],  # T21.6.2c unexpected separator
                           -2106)                       # T21.6.3 non-recognizable info
                      }
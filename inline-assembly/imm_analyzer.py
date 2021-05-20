from analyzer import Analyzer
from num_analyzer import NumberAnalyzer
from string_analyzer import CharAnalyzer


# definition of external helper functions (not class members)
def pack_value(value):
    # type: (int) -> (bool, int)
    """Helper function to transform an input parameter into an ARM 12 bits immediate operand package
        returns a boolean indicating if the fixup is possible, and the fixed up package
    """
    rotate_count = 0                                    # counter of two-bits left rotations
    fixed_value = value                                 # rotate until fixed value is within the 8 lowest weight bits
    while (rotate_count < 15) and (fixed_value & 0xFFFFFF00):
        top_bits = fixed_value & 0xC0000000                                 # capture two highest weight bits
        fixed_value = ((fixed_value << 2) & 0xFFFFFFFF) | (top_bits >> 30)  # left shift and merge top bits
        rotate_count = rotate_count + 1                                     # account for one two-bits left rotation
        # can_fixup = 24 high bits of fixed_value == 0, package = IR(4 bits) << 8 | IM(8 bits)
    return ((fixed_value & 0xFFFFFF00) == 0), ((rotate_count << 8) | fixed_value)


invcod = {0: ('and', 14), 13: ('mov', 15), 14: ('bic', 0), 15: ('mvn', 13)}
negcod = {2: ('sub', 4), 4: ('add', 2), 10: ('cmp', 11), 11: ('cmn', 10)}


def instruction_fixup(sub_result, super_result):
    # type: (list, list) -> int
    """Helper function to try to fit the immediate value by changing the instruction and inverting/negating the value"""
    override = -1606                            # by default, cannot do the instruction fixup
    index = 0                                   # seek a list with format [4, inst_code] within super_result list
    while (index < len(super_result)) and not (isinstance(super_result[index], list)
            and (len(super_result[index]) == 2) and (super_result[index][0] == 4)):
        index = index + 1
    if index < len(super_result):               # if it has found the instruction list entry in super_result
        instruction = super_result[index][1]                # get the instruction
        opcode = (instruction >> 21) & 0xF                  # get the opcode
        can_fixup = False
        cod_dict = None
        package = 0
        if opcode in invcod.keys():
            can_fixup, package = pack_value(~sub_result[0]) # try to pack inverted operand value
            cod_dict = invcod
        elif opcode in negcod.keys():
            can_fixup, package = pack_value(-sub_result[0]) # try to pack negated operand value
            cod_dict = negcod
        if can_fixup:                                       # in case of success,
            t_cod = cod_dict.get(opcode)                        # obtain tuple information about the opcode
            new_opcode = t_cod[1]                               # extract the opposite opcode and warn the user
            print "WARNING: intruction change due to immediate operand fixup ('%s'->'%s')"\
                  % (t_cod[0], cod_dict.get(new_opcode)[0])     # build the new instruction code
            instruction = (instruction & 0xFE100000) | (new_opcode << 21)
            super_result[index][1] = instruction                # update the super_result element (by reference)
            sub_result[0] = package                             # update sub_result with the new immediate package
            override = 0                                        # avoid overriding, since the new package is possible
    return override



class ImmediateOpAnalyzer(Analyzer):
    """Analyzer 16: immediate values after '#', either numbers of four possible radix or
                                                ASCII codes of a char (within single quotes)"""
    # creation of subanalyzers
    number_analyzer = NumberAnalyzer()
    char_analyzer = CharAnalyzer()

    # definition of internal transition actions (methods)
    def value_fixup(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            can_fixup, package = pack_value(sub_result[0])
            if can_fixup:
                sub_result[0] = package                 # IR|IM (IR: Immediate Rotate, IM: Immediate Mask)
            else:
                override = instruction_fixup(sub_result, super_result)    # try fixup instruction
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1006, -1102, -1103, -1104, -1105]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -1601, None),  # T16.0.0 EOSeq -> missing immediate error
                            (' ', None, 0, None),       # T16.0.1 white spaces -> keep state
                            ('#', None, 1, None)],      # T16.0.2 immediate prefix -> go to 1
                           -1602),                      # T16.0.3 missing '#' error
                      1:  # parsing next binary digits
                          ([(None, None, -1603, None),  # T16.1.0 EOSeq -> missing value after '#'
                            (' ', None, -1604, None),   # T16.1.1 unexpected space after '#
                            (self.number_analyzer, None, 2, self.value_fixup), # T16.1.2 parse number
                            (self.char_analyzer, None, 2, self.value_fixup)],  # T16.1.3 parse char
                           -1605),                      # T16.1.4 unrecognizable info after '#'
                      2:  # ensure end of sequence
                          ([(None, None, 1000, None)],  # T16.2.0 EOSeq -> right catch
                           -1607)                       # T16.2.1 unexpected data after immediate value
                      }


class ImmediateRSAnalyzer(Analyzer):
    """Analyzer 17: immediate values after '#', for reg shifting"""

    # creation of subanalyzers
    number_analyzer = NumberAnalyzer()

    # definition of internal transition actions (methods)
    def check_error(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if (sub_result[0] < 0) or (sub_result[0] >= 32):
                override = -1706            # wrong number of shiftings
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override


    def __init__(self):
        Analyzer.__init__(self)
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1006, -1102, -1103, -1104, -1105]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -1701, None),  # T17.0.0 EOSeq -> missing immediate error
                            (' ', None, 0, None),       # T17.0.1 white spaces -> keep state
                            ('#', None, 1, None)],      # T17.0.2 immediate prefix -> go to 1
                           -1702),                      # T16.0.3 missing '#' error
                      1:  # parsing next binary digits
                          ([(None, None, -1703, None),  # T17.1.0 EOSeq -> missing value after '#'
                            (' ', None, -1704, None),   # T17.1.1 unexpected space after '#
                            (self.number_analyzer, None, 2, self.check_error)], # T16.1.2 parse number
                           -1705),                      # T17.1.3 unrecognizable info after '#'
                      2:  # ensure end of sequence
                          ([(None, None, 1000, None)],  # T17.2.0 EOSeq -> right catch
                           -1707)                       # T17.2.1 unexpected data after immediate value (NEVER happens)
                      }
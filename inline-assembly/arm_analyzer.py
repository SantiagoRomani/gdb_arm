from analyzer import Analyzer
from data_analyzer import DataAnalyzer
from adr_analyzer import AddressAnalyzer
from instdat_analyzer import InstdatAnalyzer
from instmul_analyzer import InstmulAnalyzer
from instjmp_analyzer import InstjmpAnalyzer
from instmem_analyzer import InstmemAnalyzer
from instmsc_analyzer import InstmscAnalyzer


class ArmAnalyzer(Analyzer):
    """Analyzer 30: in-line assembling of low-level code and data into the gdb's arm simulator"""

    # definition of subanalyzers
    address_analyzer = AddressAnalyzer()
    data_analyzer = DataAnalyzer()
    instdat_analyzer = InstdatAnalyzer()
    instmul_analyzer = InstmulAnalyzer()
    instjmp_analyzer = InstjmpAnalyzer()
    instmem_analyzer = InstmemAnalyzer()
    instmsc_analyzer = InstmscAnalyzer()

    # definition of internal helper functions (methods)
    def update_address(self, match):
        override = 0
        if match:  # new address = specified address + size of elements * number of elements
            result = self.result  # helper variable to avoid using 'self.' so many times
            rid = 0 if len(result) == 2 else 2  # reference index (2 in case of relative PC addressing mode)
            if result[rid] % result[rid + 1][0] != 0:  # if current address is misaligned
                previous_address = result[rid]  # compute the remainder positions up to the next aligned address
                remainder_shift = result[rid + 1][0] - (previous_address % self.result[rid + 1][0])
                alignment_type = 'halfword' if (result[rid + 1][0] == 2) else 'word'
                if self.state == 2:  # in case of implicit address setting
                    result[rid] = previous_address + remainder_shift  # update current address
                    if result[rid] >= 2 ** 32:
                        override = -4006  # overriding error: too big address error after alignment
                    if rid == 2:  # if there is a second address + data entry
                        result[0] = result[0] + remainder_shift  # also move forward the second address
                        if result[0] >= 2 ** 32:
                            override = -4006  # second overriding error: too big address error after alignment
                    print "WARNING: implicit %s address automatically aligned skipping %d position%s,\n\tfrom 0x%X to 0x%X" \
                          % (alignment_type, remainder_shift, 's' if remainder_shift > 1 else '',
                             previous_address, result[rid])
                else:  # in case of explicit address (self.state == 1)
                    print "WARNING: explicit %s address misaligned by %d position%s" \
                          % (alignment_type, result[rid + 1][0] - remainder_shift,
                             's' if (result[rid + 1][0] - remainder_shift) > 1 else '')
                    # update the implicit address for next instructions
            self.next_address = result[rid] + result[rid + 1][0] * (len(result[rid + 1]) - 1)
        return override

    # definition of internal transition actions (methods)
    def implicit_address(self, match, sub_result, sub_state, super_result):
        if match:  # use the current address as starting address
            self.result.append(self.next_address)
        return 0

    def stack_info(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            self.result.append(list(sub_result))
            sub_result *= 0
            override = self.update_address(match)
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def __init__(self):
        Analyzer.__init__(self)
        self.next_address = 0x8000
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1006,
                           -1102, -1103, -1104, -1105, -1202, -1203, -1204,
                           -1301, -1302, -1303, -1304, -1403, -1502, -1503, -1504,
                           -1603, -1604, -1605, -1606, -1607, -1702, -1703, -1704, -1705, -1706,
                           -2002, -2003, -2004,
                           -2102, -2103, -2104, -2105, -2106, -2107,
                           -2204, -2205, -2207, -2302, -2303, -2304, -2306, -2308, -2310, -2311,
                           -2402, -2403, -2404, -2405, -2406, -2407, -2408, -2409, -2410, -2411, -2412,
                           -2502, -2503, -2504, -2505, -2506, -2510, -2511, -2512, -2513,
                           -3102, -3104, -3105,
                           -3202, -3204, -3205, -3207, -3208,
                           -3302, -3304, -3305, -3307, -3308,
                           -3403, -3404, -3405, -3406, -3407, -3408, -3409, -3410,
                           -3502, -3504, -3505
                           ]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -4001, None),  # T40.0.0 EOSeq -> missing hex address
                            (' ', None, 0, None),  # T40.0.1 skip initial spaces
                            ('>', ' ', -4003, None,  # T40.0.2a found '>' at end of seqence
                             2, self.implicit_address,  # T40.0.2b found '> ', stack address and go to 2
                             -4003, None),  # t40.0.2c found '>' followed by strange char
                            (self.address_analyzer, None, 1, self.error_spring)],  # T40.0.3 get the address
                           -4002),  # T40.0.4 wrong initial hex address
                      1:  # decoder state after hex address
                          ([(None, None, -4004, None),  # T40.1.0 EOSeq -> missing info
                            (self.data_analyzer, None, 1000, self.stack_info),  # T40.1.1 get the data
                            (self.instdat_analyzer, None, 1000, self.stack_info),  # T40.1.2 get data instr.
                            (self.instmul_analyzer, None, 1000, self.stack_info),  # T40.1.3 get multiply instr.
                            (self.instjmp_analyzer, None, 1000, self.stack_info),  # T40.1.4 get branch instr.
                            (self.instmem_analyzer, None, 1000, self.stack_info),  # T40.1.5 get mem transfer instr.
                            (self.instmsc_analyzer, None, 1000, self.stack_info)],  # T40.1.6 get miscellanea instr.
                           -4005),  # T40.1.7 unrecognized instruction or directive
                      2:  # decoder state after '>' symbol
                          ([(None, None, -4004, None),  # T40.2.0 EOSeq -> missing info
                            (self.data_analyzer, None, 1000, self.stack_info),  # T40.2.1 get the data
                            (self.instdat_analyzer, None, 1000, self.stack_info),  # T40.2.2 get data instr.
                            (self.instmul_analyzer, None, 1000, self.stack_info),  # T40.2.3 get multiply instr.
                            (self.instjmp_analyzer, None, 1000, self.stack_info),  # T40.2.4 get branch instr.
                            (self.instmem_analyzer, None, 1000, self.stack_info),  # T40.2.5 get mem transfer instr.
                            (self.instmsc_analyzer, None, 1000, self.stack_info)],  # T40.2.6 get miscellanea instr.
                           -4005)  # T40.2.7 unrecognized instruction or directive
                      }

from analyzer import Analyzer
from num_analyzer import NumberAnalyzer
from reg_analyzer import RegisterAnalyzer
from reg_analyzer import RegisterListAnalyzer
from opldst_analyzer import Opldst2Analyzer
from opldst_analyzer import Opldst3Analyzer
from instcond_analyzer import InstcondAnalyzer


class InstmemAnalyzer(Analyzer):
    """Analyzer 34: memory transfers instructions (ldr, str, ldrb, ldrsb, etc.)"""

    # creation of subanalyzers
    num_analyzer = NumberAnalyzer()
    reg_analyzer = RegisterAnalyzer()
    reglist_analyzer = RegisterListAnalyzer()
    opldst2_analyzer = Opldst2Analyzer()
    opldst3_analyzer = Opldst3Analyzer()
    instcond_analyzer = InstcondAnalyzer()

    # definition of basic transition entries (lists)
    ent0 = [('st', 0), ('ld', 1)]
    ent1 = [('b', 0), ('h', 1)]
    ent2 = [('da', 0), ('ia', 1), ('db', 2), ('ib', 3),
            ('fa', 0), ('fd', 1), ('ea', 2), ('ed', 3)]

    # definition of internal transition actions (methods)
    def get_mode(self, match, sub_result, sub_state, super_result):
        if match:
            self.result.append(4)  # append number of bytes of instruction
            self.mode = sub_result[0]  # memorize wich mode, load (1) or store (0)
            sub_result[0] = 0xE0000000  # initially, set no condition (always exec)
        return 0

    def check_ldmode(self, match, sub_result, sub_state, super_result):
        override = 0
        if match and (self.mode == 0):  # in case of store mode
            override = -3408  # issue an error
        return override

    def catch_cond(self, match, sub_result, sub_state, super_result):
        if match:  # clear most significant nyble and
            self.result[1] = (self.result[1] & 0x0FFFFFFF) | sub_result[0]  # include cond bits into result
            sub_result *= 0  # avoid automatic inclusion of sub_result
        return 0

    def set_ldstw(self, match, sub_result, sub_state, super_result):
        if match:  # word or unsigned byte inst. (bits 27..26 = '01')
            self.result[1] = self.result[1] | 0x04000000 | (self.mode << 20)  # plus load/store mode (bit 20)
            if self.state == 3:  # in case of unsigned byte
                self.result[1] = self.result[1] | 0x00400000  # set bit B = 1 (bit 22)
        return 0

    def set_ldsth(self, match, sub_result, sub_state, super_result):
        if match:  # signed byte or halfword inst. (bits 27..25 = '000'; bits 7 & 4 = '1')
            self.result[1] = self.result[1] | 0x00000090 | (self.mode << 20)  # plus load/store mode (bit 20)
            if (self.state == 2) or (self.state == 4):  # in case of unsigned halfword
                self.result[1] = self.result[1] | 0x20  # set bit H = 1 (bit 5)
            else:  # in case of signed halfword or byte, set bit S = 1 (bit 6)
                self.result[1] = self.result[1] | 0x40 | (sub_result[0] << 5)  # and bit H according to halfword
            sub_result *= 0  # avoid automatic inclusion of sub_result
        return 0

    def set_ldstm(self, match, sub_result, sub_state, super_result):
        if match:  # multiple mem. access inst. (bits 27..25 = '100')
            self.result[1] = self.result[1] | 0x08000000 | (sub_result[0] << 23) | (self.mode << 20)
            sub_result *= 0  # plus load/store mode (bit 20) and after/before|dec./inc. (bits 24..23)
        return 0

    def catch_rd(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if self.state == 16:  # in case of multiple mem. access inst.
                self.result[1] = self.result[1] | (sub_result[0] << 16)  # join Rd bits into bits 19..16 of result
            else:  # otherwise,
                self.result[1] = self.result[1] | (sub_result[0] << 12)  # join Rd bits into bits 15..12 of result
            sub_result *= 0  # avoid automatic inclusion of sub_result
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return 0

    def set_wreg(self, match, sub_result, sub_state, super_result):
        if match:  # multiple mem. access inst. (bits 27..25 = '100')
            self.result[1] = self.result[1] | 0x00200000  # set bit W = 1 (bit 21)
        return 0

    def catch_am(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            self.result[1] = self.result[1] | sub_result[0]  # include addressing mode bits
            sub_result *= 0  # avoid automatic inclusion of sub_result
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def check_ldr(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if (self.result[1] & 0x00500000) != 0x100000:  # if it is NOT an 'ldr' instruction
                override = -3409  # issue an error
        return override

    def set_relpc(self, match, sub_result, sub_state, super_result):
        override = 0
        if match:
            if len(super_result) > 0:  # if there is an instruction address
                super_result[0].insert(0, super_result[0][0] + 0x1000)  # offset for the loading value
                super_result[0].insert(1, list())  # create content list
                super_result[0][1].append(4)  # content list starts with value size (4 -> word values)
                data = sub_result[0]  # get the data value to loaded with relative PC addr. mode
                if data < 0:  # in case it is negative,
                    data = 0x100000000 + data  # convert to complementary to 2^32
                super_result[0][1].append(data)  # include the value to be loaded in the content list
            else:  # otherwise,
                self.result.append(sub_result[0])  # append the value for testing purposes
            self.result[1] = self.result[1] | 0x018F0FF8  # set P = 1, U = 1, Rn = PC, offset = (0x1000 - 8)
            sub_result *= 0  # avoid automatic inclusion of sub_result
        else:
            override = self.error_spring(match, sub_result, sub_state, super_result)
        return override

    def __init__(self):
        Analyzer.__init__(self)
        # definition of inner variables
        self.mode = 0
        # definition of error spring list
        self.error_list = [-1002, -1003, -1004, -1005, -1006, -1302, -1303, -1304, -1403,
                           -1502, -1503, -1504, -1702, -1703, -1704, -1705, -1706,
                           -2402, -2403, -2404, -2405, -2406, -2407, -2408, -2409, -2410, -2411, -2412,
                           -2502, -2503, -2504, -2505, -2506, -2510, -2511, -2512, -2513]
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -3401, None),  # T34.0.0 EOSeq -> missing inst.
                            (' ', None, 0, None),  # T34.0.1 skip leading spaces
                            (self.ent0, None, 1, self.get_mode)],  # T34.0.2 starting inst., go to 1
                           -3402),  # T34.0.3 unrecognizable memory transfer inst.
                      1:  # check for memory transfer type
                          ([(None, None, -3402, None),  # T34.1.0 EOSeq -> missing inst. continuation
                            ('r', None, 2, None),  # T34.1.1 go to 'r' subgraph
                            ('s', None, 8, self.check_ldmode),  # T34.1.2 if load, go to 's' subgraph
                            ('m', None, 13, None)],  # T34.1.3 go to 'm' subgraph
                           -3402),  # T34.1.4 unrecognizable memory transfer inst.
                      2:  # check for word or unsigned byte memory transfer
                          ([(None, None, -3403, None),  # T34.2.0 EOSeq ->  missing space after memory transfer inst.
                            (' ', None, 5, self.set_ldstw),  # T34.2.1 it is 'ldr' or 'str'
                            ('b', None, 3, None),  # T34.2.2 maybe 'ldrb'
                            (self.instcond_analyzer, None, 4, self.catch_cond),  # T34.2.3 inst. + cond, go to 4
                            ('h', None, 9, self.set_ldsth),  # T34.2.4 maybe 'ldrh'
                            ('s', None, 10, self.check_ldmode)],  # T34.2.5 if load, go to 's' (no cond.)
                           -3404),  # T34.2.6 wrong text after memory transfer inst.
                      3:  # check for 'ldrb'/'strb' completion
                          ([(None, None, -3403, None),  # T34.3.0 EOSeq -> missing space after memory transfer inst.
                            (' ', None, 5, self.set_ldstw)],  # T34.3.1 it is 'ldrb' or 'strb'
                           -3404),  # T34.3.2 wrong text after memory transfer inst.
                      4:  # check for instruction completion after condition
                          ([(None, None, -3403, None),  # T34.4.0 EOSeq -> missing space after memory transfer inst.
                            (' ', None, 5, self.set_ldstw),  # T34.4.1 it is 'ldr' or 'str'
                            ('b', None, 3, None),  # T34.4.2 maybe 'ldrb'
                            ('h', None, 9, self.set_ldsth),  # T34.4.3 maybe 'ldrh'
                            ('s', None, 10, self.check_ldmode)],  # T34.4.4 if load, go to 's' subgraph
                           -3404),  # T34.4.5 wrong text after memory transfer inst.
                      5:  # check for Rd
                          ([(None, None, -3405, None),  # T34.5.0 EOSeq -> missing destination reg in memory transfer
                            (self.reg_analyzer, ',', -3406, self.error_spring,  # T34.5.1a missing ','
                             6, self.catch_rd,  # T34.5.1b catch destination reg.
                             -3499, self.error_spring)],  # T34.5.1c NEVER happens
                           -3499),  # T34.5.2 wrong text after memory transfer inst. (NEVER happens)
                      6:  # check for word or unsigned byte memory transfer ending
                          ([(None, None, -3407, None),  # T34.6.0 EOSeq -> missing info after memory transfer inst.
                            (' ', None, 6, None),  # T34.6.1 skip spaces
                            ('=', None, 7, self.check_ldr),  # T34.6.2 maybe relative PC laoding
                            (self.opldst2_analyzer, None, 1000, self.catch_am)],  # T34.6.3 catch addressing mode
                           -3499),  # T34.6.4 wrong text after memory transfer inst. (NEVER happens)
                      7:  # check for number to be assigned using relative PC displacement
                          ([(None, None, -3410, None),  # T34.7.0 EOSeq -> missing number for load with relative pc
                            (' ', None, 7, None),  # T34.7.1 skip spaces
                            (self.num_analyzer, None, 1000, self.set_relpc)],  # T34.7.2 relative PC addressing mode
                           -3410),  # T34.7.3 wrong number for load with relative pc
                      8:  # check for load signed halfword or signed byte memory transfer
                          ([(None, None, -3404, None),  # T34.8.0 EOSeq -> wrong memory transfer inst.
                            (self.instcond_analyzer, None, 10, self.catch_cond),  # T34.8.1 inst. + cond, go to 10
                            (self.ent1, None, 9, self.set_ldsth)],  # T34.8.2 maybe 'ldsh' or 'ldsb'
                           -3404),  # T34.8.3 wrong text after memory transfer inst.
                      9:  # check for 'ldrh'/'strh'/'ldsh'/'ldsb'/'ldrsh'/'ldrsb' completion
                          ([(None, None, -3403, None),  # T34.9.0 EOSeq -> missing space after memory transfer inst.
                            (' ', None, 11, None)],  # T34.9.1 it is 'ldrb' or 'strb'
                           -3404),  # T34.9.2 wrong text after memory transfer inst.
                      10:  # check for instruction completion after condition
                          ([(None, None, -3404, None),  # T34.10.0 EOSeq -> wrong memory transfer inst.
                            (self.ent1, None, 9, self.set_ldsth)],  # T34.10.1 maybe 'ldsh'/'ldrsh'/'ldsb'/'ldrsb'
                           -3404),  # T34.10.2 wrong memory transfer inst.
                      11:  # check for Rd
                          ([(None, None, -3405, None),  # T34.11.0 EOSeq -> missing destination reg in memory transfer
                            (self.reg_analyzer, ',', -3406, self.error_spring,  # T34.11.1a missing ','
                             12, self.catch_rd,  # T34.11.1b catch destination reg.
                             -3499, self.error_spring)],  # T34.11.1c NEVER happens
                           -3499),  # T34.11.2 wrong text after mem. transfer inst. (NEVER happens)
                      12:  # check for signed byte or halfword memory transfer ending
                          ([(None, None, -3407, None),  # T34.12.0 EOSeq -> missing info after memory transfer inst.
                            (self.opldst3_analyzer, None, 1000, self.catch_am)],  # T34.12.1 catch addressing mode
                           -3499),  # T34.12.2 wrong text after mem. transfer inst. (NEVER happens)
                      13:  # check for multiple register memory transfer
                          ([(None, None, -3404, None),  # T34.13.0 EOSeq -> wrong memory transfer inst.
                            (self.instcond_analyzer, None, 14, self.catch_cond),  # T34.13.1 inst. + cond, go to 14
                            (self.ent2, None, 15, self.set_ldstm)],  # T34.13.2 maybe 'ldm__' or 'stm__'
                           -3404),  # T34.13.3 wrong text after memory transfer inst.
                      14:  # check for instruction completion after condition
                          ([(None, None, -3404, None),  # T34.14.0 EOSeq -> wrong memory transfer inst.
                            (self.ent2, None, 15, self.set_ldstm)],  # T34.14.1 maybe 'ldm<cond>__'/'stm<cond>__'
                           -3404),  # T34.14.2 wrong memory transfer inst.
                      15:  # check for 'ldm<cond>__'/'stm<cond>__' completion
                          ([(None, None, -3403, None),  # T34.15.0 EOSeq -> missing space after memory transfer inst.
                            (' ', None, 16, None)],  # T34.15.1 it is multiple reg memory inst.
                           -3404),  # T34.15.2 wrong text after memory transfer inst.
                      16:  # check for Rn
                          ([(None, None, -3405, None),  # T34.16.0 EOSeq -> missing destination reg in memory transfer
                            (self.reg_analyzer, ',!', -3406, self.error_spring,  # T34.16.1a missing ','
                             18, self.catch_rd,  # T34.16.1b catch Rn,
                             17, self.catch_rd,  # T34.16.1c catch Rn!
                             -3499, self.error_spring)],  # T34.16.1d NEVER happens
                           -3499),  # T34.16.2 wrong text after mem transfer inst. (NEVER happens)
                      17:  # check for ',' after Rn!
                          ([(None, None, -3406, None),  # T34.17.0 EOSeq -> missing ',' after Rn!
                            (' ', None, 17, None),  # T34.17.1 skip spaces
                            (',', None, 18, self.set_wreg)],  # T34.17.2 positive
                           -3404),  # T34.17.3 wrong text after memory transfer inst.
                      18:  # check for multiple memory transfer ending
                          ([(None, None, -3407, None),  # T34.18.0 EOSeq -> missing info after memory transfer inst.
                            (self.reglist_analyzer, None, 1000, self.catch_am)],  # T34.18.1 catch addressing mode
                           -3499),  # T34.18.2 wrong text after mem. transfer inst. (NEVER happens)
                      }

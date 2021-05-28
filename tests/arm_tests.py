""" Groups of tests for gdb_arm """
from num_analyzer import NumberAnalyzer
from string_analyzer import CharAnalyzer
from string_analyzer import StringAnalyzer
from data_analyzer import DataAnalyzer
from adr_analyzer import AddressAnalyzer
from reg_analyzer import RegisterAnalyzer
from reg_analyzer import RegisterBitsAnalyzer
from reg_analyzer import RegisterListAnalyzer
from imm_analyzer import ImmediateOpAnalyzer
from imm_analyzer import ImmediateRSAnalyzer
from op2_analyzer import Op2Analyzer
from opdat_analyzer import OpdatAnalyzer
from instdat_analyzer import InstdatAnalyzer
from instmul_analyzer import InstmulAnalyzer
from instjmp_analyzer import InstjmpAnalyzer
from opldst_analyzer import Opldst2Analyzer
from opldst_analyzer import Opldst3Analyzer
from instmem_analyzer import InstmemAnalyzer
from instmsc_analyzer import InstmscAnalyzer
from arm_analyzer import ArmAnalyzer

number_analyzer = NumberAnalyzer()
char_analyzer = CharAnalyzer()
string_analyzer = StringAnalyzer()
data_analyzer = DataAnalyzer()
address_analyzer = AddressAnalyzer()
register_analyzer = RegisterAnalyzer()
regbit_analyzer = RegisterBitsAnalyzer()
reglst_analyzer = RegisterListAnalyzer()
immediate_op_analyzer = ImmediateOpAnalyzer()
immediate_sr_analyzer = ImmediateRSAnalyzer()
op2_analyzer = Op2Analyzer()
opdat_analyzer = OpdatAnalyzer()
instdat_analyzer = InstdatAnalyzer()
instmul_analyzer = InstmulAnalyzer()
instjmp_analyzer = InstjmpAnalyzer()
opldst2_analyzer = Opldst2Analyzer()
opldst3_analyzer = Opldst3Analyzer()
instmem_analyzer = InstmemAnalyzer()
instmsc_analyzer = InstmscAnalyzer()
arm_analyzer = ArmAnalyzer()

hex_test = [('', [], -1001),  # T10.0.0                   error: empty input
            (' ', [], -1001),  # T10.0.1 > T10.0.0         error: white spaces
            ('0x', [], -1005),  # T10.0.3 > T10.2.0         error: leading '0x', missing hex digits
            (' 0x', [], -1005),  # T10.0.1 > T10.0.3 > T10.2.0   / idem with leading white space
            ('0x1', [1], 1000),  # T10.0.3 > T10.2.1         hex number: single digit
            (' 0x1', [1], 1000),  # T10.0.1 > T10.0.3 > T10.2.1   / idem with white leading space
            (' 0xA', [10], 1000),  # T10.0.1 > T10.0.3 > T10.2.1   / idem with a letter digit
            ('0x01', [1], 1000),  # T10.0.3 > T10.2.1             / with leading zeros
            ('  0x001', [1], 1000),  # T10.0.1 > T10.0.3 > T10.2.1   / idem with leading spaces
            ('0x10', [16], 1000),  # T10.0.3 > T10.2.1             / two digits
            ('0x2864', [10340], 1000),  # T10.0.3 > T10.2.1             / four digits
            ('0xF3AE', [62382], 1000),  # T10.0.3 > T10.2.1             / four digits, with hex letters
            ('0xb14a', [45386], 1000),  # T10.0.3 > T10.2.1             / (lower case hex letters)
            ('0xb14A', [45386], 1000),  # T10.0.3 > T10.2.1             / (mixed lower / upper case)
            ('0xR124', [], -1005),  # T10.0.3 > T10.2.2         error: illegal digits (first one)
            ('0x51V4', [], -1005),  # T10.0.3 > T10.2.2            / (third one)
            ('0x514W', [], -1005),  # T10.0.3 > T10.2.2            / (last one)
            ('0x10002EF0', [268447472], 1000),  # T10.0.3 > T10.2.1         big hex number: eight digits
            ('0x10002EF00', [], -1006)  # T10.0.3 > T10.2.1+override   too long number: nine digits (>=2^32)
            ]

dec_test = [('0', [0], 1000),  # T10.0.4 > T10.3.0         dec/oct number: the zero
            (' 0', [0], 1000),  # T10.0.1 > T10.0.4 > T10.3.0   / idem with leading space
            ('1', [1], 1000),  # T10.0.7 > T10.5.1         dec number: single digit
            (' 1', [1], 1000),  # T10.0.1 > T10.0.7 > T10.5.1   / idem with white space
            ('-1', [-1], 1000),  # T10.0.5 > T10.4.1             / negative number
            ('  -1', [-1], 1000),  # T10.0.1 > T10.0.5 > T10.4.1   / negative num. with leading spaces
            ('10', [10], 1000),  # T10.0.7 > T10.5.1             / two digits
            ('2864', [2864], 1000),  # T10.0.7 > T10.5.1             / four digits
            ('-2864', [-2864], 1000),  # T10.0.5 > T10.4.1             / four digits negative number
            ('+2864', [2864], 1000),  # T10.0.6 > T10.6.1             / four digits positive number
            ('r12', [], -1001),  # T10.0.8                   error: illegal digits (first one)
            ('5V6', [], -1004),  # T10.0.6 > T10.5.2             / (second one)
            ('514W', [], -1004),  # T10.0.6 > T10.5.2             / (last one)
            ('-', [], -1004),  # T10.0.5 > T10.4.0             / no digits digit after '-'
            ('+', [], -1004),  # T10.0.6 > T10.6.0             / no digits digit after '+'
            ('-r12', [], -1004),  # T10.0.5 > T10.4.2             / illegal first digit after '-'
            ('+r12', [], -1004),  # T10.0.6 > T10.6.2             / illegal first digit after '-'
            ('-5V6', [], -1004),  # T10.0.5 > T10.4.2             / illegal middle digit after '-'
            ('4684474720', [], -1006),  # T10.0.6 > T10.5.1+override    long dec number (>=2^32)
            ('-2147483649', [], -1006)  # T10.0.5 > T10.4.1+override    long neg. dec number (<-2^31)
            ]

oct_test = [('000', [0], 1000),  # T10.0.4 > T10.3.1             oct number: zeroes
            (' 00', [0], 1000),  # T10.0.1 > T10.0.4 > T10.3.1           / idem with leading space
            ('01', [1], 1000),  # T10.0.4 > T10.3.1             oct number: single digit
            (' 01', [1], 1000),  # T10.0.1 > T10.0.4 > T10.3.1           / idem with white space
            ('001', [1], 1000),  # T10.0.4 > T10.3.1                     / several zeros before digit
            ('010', [8], 1000),  # T10.0.4 > T10.3.1             oct number: two digits
            ('02764', [1524], 1000),  # T10.0.4 > T10.3.1                     / four digits
            ('02864', [], -1003),  # T10.0.4 > T10.3.2             error: malformed octal number
            ('0r12', [], -1003),  # T10.0.4 > T10.3.2  error: illegal digits (first one after first 0)
            ('05V6', [], -1003),  # T10.0.4 > T10.3.2                     / (second one)
            ('0514W', [], -1003),  # T10.0.4 > T10.3.2                     / (last one)
            ('00r12', [], -1003),  # T10.0.4 > T10.3.2           / illegal first digit after several 0s
            ('063710000000', [], -1006)  # T10.0.4 > T10.3.1+override    long oct number (>=2^32)
            ]

bin_test = [('0b', [], -1002),  # T10.0.2 > T10.1.0         error: leading '0b', missing bin digits
            (' 0b', [], -1002),  # T10.0.1 > T10.0.2 > T10.1.0       / idem with leading white space
            ('0b1', [1], 1000),  # T10.0.2 > T10.1.1         bin number: single bit
            (' 0b1', [1], 1000),  # T10.0.1 > T10.0.2 > T10.1.1       / idem with white space
            (' 0b0', [0], 1000),  # T10.0.1 > T10.0.2 > T10.1.1       / idem white space & zero bit
            ('0b01', [1], 1000),  # T10.0.2 > T10.1.1                 / leading zero
            ('  0b001', [1], 1000),  # T10.0.1 > T10.0.2 > T10.1.1       / leading spaces & leading zeros
            ('0b10', [2], 1000),  # T10.0.2 > T10.1.1         two bits
            ('0b0110', [6], 1000),  # T10.0.2 > T10.1.1         four bits
            ('0bR101', [], -1002),  # T10.0.2 > T10.1.2         error: illegal bits (first one)
            ('0b01V4', [], -1002),  # T10.0.2 > T10.1.2                 / (third one)
            ('0b110W', [], -1002),  # T10.0.2 > T10.1.2                 / (last one)
            ('0b0140', [], -1002),  # T10.0.2 > T10.1.2                 / (non-binary digit)
            ('0b10000000000000001000000000000000', [2147516416], 1000),  # T10.0.2 > T10.1.1             32 bits
            ('0b100000000000000010000000000000001', [], -1006)  # T10.0.2 > T10.1.1+override    33 bits
            ]

chr_test = [('', [], -1101),  # T11.0.0                   error: no single quote
            ("'", [], -1101),  # T11.0.2 > T11.1.0         error: open single quote, missing char
            (' n\'', [], -1101),  # T11.0.1 > T11.0.3         error: missing quote before characters
            ("''", [], -1102),  # T11.0.2 > T11.1.1         error: empty single quotes
            ("' ", [32], -1104),  # T11.0.2 > T11.1.2 > T11.2.0   error: unclosed single quoted char
            ("' 0", [32], -1105),  # T11.0.2 > T11.1.2 > T11.2.2   error: more than one character
            ("' '", [32], 1000),  # T11.0.2 > T11.1.2 > T11.2.1   successful single char capture
            (" ' '", [32], 1000),  # T11.0.1 > T11.0.2 > T11.1.2 > T11.2.1 / idem with leading space
            ('" "', [], -1101),  # T11.0.3                   error: missing single quote
            ('\'\"\'', [34], 1000),  # T11.0.2 > T11.1.2 > T11.2.1  capture double quote as single char
            ('\'\n\'', [], -1103)  # T11.0.2 > T11.1.3         illegal character in single quotes
            ]

str_test = [('', [], -1201),  # T12.0.0                   error: no double quote
            ("'", [], -1201),  # T12.0.3                   error: unexpected single quote
            ('"', [], -1201),  # T12.0.2 > T12.1.0         error: open double quote, missing string
            (' n\"', [], -1201),  # T12.0.1 > T12.0.3         error: missing quote before characters
            ('""', [], -1202),  # T12.0.2 > T12.1.1         error: empty double quotes
            ('" ', [32], -1204),  # T12.0.2 > T12.1.2 > T12.2.0   error: unclosed double quotes
            ('" 0', [32, 48], -1204),  # T12.0.2 > T12.1.2 > T12.2.2 > T12.2.0 / idem with two chars
            ('" "', [32], 1000),  # T12.0.2 > T12.1.2 > T12.2.1   successful single-char string
            (' " "', [32], 1000),  # T12.0.1 > T12.0.2 > T12.1.2 > T12.2.1 / idem with leading space
            ('"0123456789"', [48, 49, 50, 51, 52, 53, 54, 55, 56, 57], 1000),  # T12.0.2 > T12.1.2 > T12.2.2 > T12.2.1
            ('"abcdefghijklmnopqrstuvwxyz"', [97, 98, 99, 100, 101, 102, 103,  # alphabetic digits
                                              104, 105, 106, 107, 108, 109, 110, 111, 112,
                                              113, 114, 115, 116, 117, 118, 119, 120, 121,
                                              122], 1000),  # lower case letters
            ('"ABCDEFGHIJKLMNOPQRSTUVWXYZ"', [65, 66, 67, 68, 69, 70, 71, 72,
                                              73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
                                              84, 85, 86, 87, 88, 89, 90], 1000),  # upper case letters
            ('"!#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"', [33, 35, 36, 37, 38, 39,
                                                     40, 41, 42, 43, 44, 45, 46, 47, 58, 59, 60,
                                                     61, 62, 63, 64, 91, 92, 93, 94, 95, 96, 123,
                                                     124, 125, 126], 1000),  # punctuation letters
            ('\"\'\"', [39], 1000),  # T12.0.2 > T12.1.2 > T12.2.1  capture single quote as a string
            ('\"\n\"', [], -1203),  # T12.0.2 > T12.1.3          illegal character after double quote
            ('\" \n\"', [32], -1203)  # T12.0.2 > T12.1.2 > T12.2.2 > T12.2.3  idem after a valid char
            ]

dat_test = [('', [], -2101),  # T21.0.0                   error: missing data directive
            (' ', [], -2101),  # T21.0.1 > T21.0.0         idem with leading space
            ('.', [], -2101),  # T21.0.2 > T21.1.0         error: missing directive after '.'
            ('f', [], -2101),  # T21.0.3                   error: missing '.'
            ('.f', [], -2104),  # T21.0.2 > T21.1.6         error: unknown data directive
            ('.byte', [], -2102),  # T21.0.2 > T21.1.1a        error: missing data values
            ('.byte ', [1], -2102),  # T21.0.2 > T21.1.1b > T21.2.0     error: missing data values
            ('.byte2', [], -2103),  # T21.0.2 > T21.1.1c        error: missing space after directive
            ('.byte 2', [1, 2], 1000),  # T21.0.2 > T21.1.1b > T21.2.1a    success: get one byte
            ('.byte 20', [1, 20], 1000),  # T21.0.2 > T21.1.1b > T21.2.1a    idem with two digits
            ('.byte -20', [1, 236], 1000),  # T21.0.2 > T21.1.1b > T21.2.1a    idem with negative number
            ('.byte 2000', [1], -2107),  # T21.0.2 > T21.1.1b > T21.2.1a + override  data >= 2**8
            ('.byte -200', [1], -2107),  # T21.0.2 > T21.1.1b > T21.2.1a + override  data < -2**7
            ('.byte 45r', [1], -1004),  # T21.0.2 > T21.1.1b > T21.2.1a + override  unexpected decimal digit
            ('.byte 45,', [1, 45], -2102),  # T21.0.2 > T21.1.1b > T21.2.1b > T21.2.0    error: missing data
            ('.byte 45, ', [1, 45], -2106),  # T21.0.2 > T21.1.1b > T21.2.1b > T21.2.3    unrecognizeable info
            ('.byte 200, 0xF4', [1, 200, 244], 1000),  # T21.0.2 > T21.1.1b > T21.2.1b > T21.2.1a   get two bytes
            ('.byte \'2\'', [1, 50], 1000),  # T21.0.2 > T21.1.1b > T21.2.2a    success: get one char
            ('.byte \'2\', \'F\'', [1, 50, 70], 1000),  # T21.0.2 > T21.1.1b > T21.2.2b > T21.2.2a   get two chars
            ('.byte \'2\', 0123', [1, 50, 83], 1000),  # T21.0.2 > T21.1.1b > T21.2.2b > T21.2.1a   one char + one num.
            ('.byte \'2\' , 0123', [1, 50, 83], 1000),  # T21.0.2 > T21.1.1b > T21.2.2b > T21.2.1a   with extra space
            ('.byte \'2\', 0123 ', [1, 50, 83], 1000),  # T21.0.2 > T21.1.1b > T21.2.2b > T21.2.1a   with trailing space
            ('.byte 0b110, \'e\'', [1, 6, 101], 1000),  # T21.0.2 > T21.1.1b > T21.2.1b > T21.2.2a   one num. + one char
            ('.byte 0b110 , \'e\'', [1, 6, 101], 1000),  # T21.0.2 > T21.1.1b > T21.2.1b > T21.2.2a   with extra space
            ('.byte 0b110, \'e\' ', [1, 6, 101], 1000),
            # T21.0.2 > T21.1.1b > T21.2.1b > T21.2.2a   with trailing space
            ('.byte \'e\' c', [1], -2105),  # T21.0.2 > T21.1.1b > T21.2.1b > T21.2.1c   wrong delimiter
            ('.byte \'e\', c', [1, 101], -2106),  # T21.0.2 > T21.1.1b > T21.2.1b > T21.2.3    unrecognizeable info
            ('.byte c', [1], -2106),  # T21.0.2 > T21.1.1b > T21.2.3     unrecognizeable info
            ('.hword', [], -2102),  # T21.0.2 > T21.1.2a        error: missing data values
            ('.hword ', [2], -2102),  # T21.0.2 > T21.1.2b > T21.3.0     error missing halfwords
            ('.hword2', [], -2103),  # T21.0.2 > T21.1.2c        error: missing space after directive
            ('.hword 2000', [2, 2000], 1000),  # T21.0.2 > T21.1.2b > T21.3.1a    success: capture a halfword
            ('.hword 2000, 0b0010', [2, 2000, 2], 1000),  # T21.0.2 > T21.1.2b > T21.3.1b > T21.3.1a  two halfwords
            ('.hword 02000, -1, 0xF00A', [2, 1024, 65535, 61450], 1000),  # success: three halfwords
            ('.hword \'e\'', [2], -2106),  # T21.0.2 > T21.1.2b > T21.3.2     unrecognizeable info
            ('.hword 045r', [2], -1003),  # T21.0.2 > T21.1.2b > T21.3.1a + override  unexpected hexa digit
            ('.hword 45,', [2, 45], -2102),  # T21.0.2 > T21.1.2b > T21.3.1b > T21.3.0    error: missing data
            ('.hword 2 , -0123 ', [2, 2, 0xFF85], 1000),  # T21.0.2 > T21.1.2b > T21.3.1b > T21.3.1a  extra space
            ('.hword -45000', [2], -2107),  # T21.0.2 > T21.1.2b > T21.3.1a + overrride  error: data < -2**15
            ('.word', [], -2102),  # T21.0.2 > T21.1.3a        error: missing data values
            ('.word ', [4], -2102),  # T21.0.2 > T21.1.3b > T21.4.0     error missing words
            ('.wordh', [], -2103),  # T21.0.2 > T21.1.3c        error: missing space after directive
            ('.word 2000', [4, 2000], 1000),  # T21.0.2 > T21.1.3b > T21.4.1a    success: capture a word
            ('.word -2147483648, 0b0010', [4, 2147483648, 0b0010], 1000),  # T21.0.2 > T21.1.3b > T21.4.1b > T21.4.1a
            ('.word 020000000, -1, 0x1F00A', [4, 0o20000000, 4294967295, 0x1F00A], 1000),  # three words
            ('.word r45', [4], -2106),  # T21.0.2 > T21.1.3b > T21.4.2     unrecognizeable info
            ('.word 0b45', [4], -1002),  # T21.0.2 > T21.1.3b > T21.4.1a + override   unexpected binary digit
            ('.word 0x4X5', [4], -1005),  # T21.0.2 > T21.1.3b > T21.4.1a + override   unexpected hexa digit
            ('.word 0x400000000', [4], -1006),  # T21.0.2 > T21.1.3b > T21.4.1a + override   too long value (>2^32)
            ('.word 45,', [4, 45], -2102),  # T21.0.2 > T21.1.3b > T21.4.1b > T21.4.0    error: missing data
            ('.word 2 , -0123 ', [4, 2, 4294967173], 1000),  # T21.0.2 > T21.1.3b > T21.4.1b > T21.4.1a
            ('.word 4294967295', [4, 4294967295], 1000),  # T21.0.2 > T21.1.3b > T21.4.1a  success: maximum int
            ('.ascii', [], -2102),  # T21.0.2 > T21.1.4a         error: missing string
            ('.asciz', [], -2102),  # T21.0.2 > T21.1.5a         error: missing string
            ('.ascii ', [1], -2102),  # T21.0.2 > T21.1.4b > T21.5.0    : missing string
            ('.asciz ', [1], -2102),  # T21.0.2 > T21.1.5b > T21.6.0    : missing string
            ('.ascii5', [], -2103),  # T21.0.2 > T21.1.4c         error: missing space after directive
            ('.asciz8', [], -2103),  # T21.0.2 > T21.1.5c         error: missing space after directive
            ('.ascii \' \'', [1, 32], 1000),  # T21.0.2 > T21.1.4b > T21.5.1a     success: get one char
            ('.asciz \' \'', [1, 32, 0], 1000),  # T21.0.2 > T21.1.5b > T21.6.1a     success: get one char + '\0'
            ('.ascii  \'a\', \'b\' ,\'c\' , \'d\' ', [1, 97, 98, 99, 100], 1000),  # > T21.5.1b > T21.5.1a
            ('.asciz  \'a\', \'b\' ,\'c\' , \'d\' ', [1, 97, 0, 98, 0, 99, 0, 100, 0], 1000),  # > T21.6.1b > T21.6.1a
            ('.ascii "0123456789"', [1, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57], 1000),  # T21.0.2 > T21.1.4b > T21.5.2a
            ('.asciz "abcdef"', [1, 97, 98, 99, 100, 101, 102, 0], 1000),  # T21.0.2 > T21.1.5b > T21.6.2a
            ('.ascii \"b\", \"a\"', [1, 98, 97], 1000),  # T21.0.2 > T21.1.4b > T21.5.2b > T21.5.2a
            ('.asciz \"a\", \"b\"', [1, 97, 0, 98, 0], 1000),  # T21.0.2 > T21.1.5b > T21.6.2b > T21.6.2a
            ('.ascii \"b\", \'a\'', [1, 98, 97], 1000),  # T21.0.2 > T21.1.4b > T21.5.2b > T21.5.1a
            ('.asciz \'a\', \"b\"', [1, 97, 0, 98, 0], 1000),  # T21.0.2 > T21.1.5b > T21.6.1b > T21.6.2a
            ('.ascii \' ', [1], -1104),  # T21.0.2 > T21.1.4b > T21.5.1a + override unclosed char
            ('.ascii \" ', [1], -1204),  # T21.0.2 > T21.1.4b > T21.5.2a + override unclosed string
            ('.asciz \' ', [1], -1104),  # T21.0.2 > T21.1.5b > T21.6.1a + override unclosed char
            ('.asciz \" ', [1], -1204),  # T21.0.2 > T21.1.5b > T21.6.2a + override unclosed string
            ('.ascii \'\'', [1], -1102),  # T21.0.2 > T21.1.4b > T21.5.1a + override empty char
            ('.ascii \"\"', [1], -1202),  # T21.0.2 > T21.1.4b > T21.5.2a + override empty string
            ('.asciz \'\'', [1], -1102),  # T21.0.2 > T21.1.5b > T21.6.1a + override empty char
            ('.asciz \"\"', [1], -1202),  # T21.0.2 > T21.1.5b > T21.6.2a + override empty string
            ('.ascii \' 0\'', [1], -1105),  # T21.0.2 > T21.1.4b > T21.5.2a + override more than one character
            ('.asciz \' 0\'', [1], -1105),  # T21.0.2 > T21.1.5b > T21.6.2a + override idem after .ascii
            ('.ascii \'a\', \"bc , \'d\"', [1, 97, 98, 99, 32, 44, 32, 39, 100], 1000),  # > T21.5.1b > T21.5.2a
            ('.asciz \',\', \",,\"', [1, 44, 0, 44, 44, 0], 1000),  # T21.0.2 > T21.1.5b > T21.6.1a success capture ','
            ('.ascii \'\t\'', [1], -1103),  # T21.0.2 > T21.1.4b > T21.5.1c + override illegal character ''
            ('.asciz \'\t\'', [1], -1103),  # T21.0.2 > T21.1.5b > T21.6.1c + override idem after .ascii
            ('.ascii \"\t\"', [1], -1203),  # T21.0.2 > T21.1.4b > T21.5.2c + override illegal character ""
            ('.asciz \" \t\"', [1], -1203),  # T21.0.2 > T21.1.5b > T21.6.2c + override idem after valid char
            ('.ascii \'"\'a', [1], -2105),  # T21.0.2 > T21.1.4b > T21.5.1c unexpected separator
            ('.ascii \"\'a\"b', [1], -2105),  # T21.0.2 > T21.1.4b > T21.5.2c unexpected separator
            ('.asciz \'"\'a', [1], -2105),  # T21.0.2 > T21.1.5b > T21.6.1c unexpected separator
            ('.asciz \"\'a\"b', [1], -2105),  # T21.0.2 > T21.1.5b > T21.6.2c unexpected separator
            ('.ascii \' a\'', [1], -1105),  # T21.0.2 > T21.1.4b > T21.5.2a + override more than one character
            ('.asciz \' a\'', [1], -1105),  # T21.0.2 > T21.1.5b > T21.6.2a + override idem after .ascii
            ('.ascii a\'', [1], -2106),  # T21.0.2 > T21.1.4b > T21.5.3  non recognizable info
            ('.asciz a\'', [1], -2106),  # T21.0.2 > T21.1.5b > T21.6.3  non recognizable info
            (' .asciz \'a\'', [1, 97, 0], 1000)  # T21.0.1 > T21.0.2 > T21.1.5b > T21.6.1a success with leading space
            ]

adr_test = [('', [], -2001),  # T20.0.0                   error: missing address
            (' ', [], -2001),  # T20.0.1 > T20.0.0         idem white leading space
            ('0x', [], -2002),  # T20.0.2 > T20.1.0         error: '0x' but missing hex digits
            ('x0', [], -2001),  # T20.0.3                   error: missing address start
            ('  0x8001', [], -2003),  # T20.0.1 > T20.0.2 > T20.1.1a  address but missing trailing space
            ('0xF3AE ', [0xF3AE], 1000),  # T20.0.2 > T20.0.2 > T20.1.1b  success address with trailing space
            ('0xR124', [], -2003),  # T20.0.2 > T20.1.2         illegal address (first digit)
            ('0x51V4', [], -2003),  # T20.0.2 > T20.1.1c        illegal address (in-the-middle)
            ('0x514W', [], -2003),  # T20.0.2 > T20.1.1c        illegal address (last one)
            ('0xF0002E00 ', [0xF0002E00], 1000),  # T20.0.2 > T20.1.1b        big hex address: eight digits
            ('0x10002EF00 ', [], -2004)  # T20.0.2 > T20.1.1b + override  long hex address (> 2^32)
            ]

reg_test = [('', [], -1301),  # T13.0.0                   error: missing register
            (' ', [], -1301),  # T13.0.1 > T13.0.0             / idem with leading space
            ('1', [], -1302),  # T13.0.4                   error: unknown register identifier
            ('r', [], -1303),  # T13.0.2 > T13.1.0         error: missing register number
            ('ra', [], -1304),  # T13.0.2 > T13.1.2         error: wrong reg number
            ('r1a', [], -1304),  # T13.0.2 > T13.1.2         error: wrong reg number
            ('r-1', [], -1304),  # T13.0.2 > T13.1.1 + override   : negative reg number
            ('r16', [], -1304),  # T13.0.2 > T13.1.1 + override   : too high reg number
            ('r12', [12], 1000),  # T13.0.2 > T13.1.1         success: two digit reg number
            ('r0', [0], 1000),  # T13.0.2 > T13.1.1         success: one digit reg number
            ('sp', [13], 1000),  # T13.0.3                   success: stack pointer
            ('lr', [14], 1000),  # T13.0.3                   success: link register
            ('pc', [15], 1000)  # T13.0.3                   success: program counter
            ]

rbt_test = [('', [], -1401),  # T14.0.0                   error: missing register
            (' ', [], -1401),  # T14.0.1 > T14.0.0             / idem with leading space
            ('1', [], -1302),  # T14.0.2c + override       unknown register identifier
            ('r', [], -1303),  # T14.0.2a + override       missing register number
            ('ra', [], -1304),  # T14.0.2a + override       wrong reg number
            ('r1a', [], -1304),  # T14.0.2c + override       wrong reg number
            ('r-1', [], -1303),  # T14.0.2b + override       negative reg number
            ('r16', [], -1304),  # T14.0.2a + override       too high reg number
            ('r0', [0x1], 1000),  # T14.0.2a                  success: single register
            ('r15', [0x8000], 1000),  # T14.0.2a                         : maximum single reg value
            ('r0-r5', [0x3F], 1000),  # T14.0.2b > T14.1.1        success: reg range (min, max)
            ('r12-r2', [0x1FFC], 1000),  # T14.0.2b > T14.1.1               :  (max, min)
            ('lr-pc', [0xC000], 1000),  # T14.0.2b > T14.1.1               :  (symbolic)
            ('sp-r12', [0x3000], 1000),  # T14.0.2b > T14.1.1               :  (symbolic & numeric, two bits)
            ('sp-r13', [0x2000], 1000),  # T14.0.2b > T14.1.1               :  (symbolic & numeric, one bit)
            ('r4-', [0x10], -1403),  # T14.0.2b > T14.1.0        error: missing second reg in range list
            ('r8-1', [0x100], -1302),  # T14.0.2a > T14.1.1 + override       wrong second reg
            ('r9-r16', [0x200], -1304)  # T14.0.2a > T14.1.1 + override       too high second reg number
            ]

rlt_test = [('', [], -1501),  # T15.0.0                   error: missing register list
            (' ', [], -1501),  # T15.0.1 > T15.0.0              : idem with leading space
            ('1', [], -1502),  # T15.0.3                   error: missing '{'
            ('{', [], -1503),  # T15.0.2 > T15.1.0         error: missing registers
            ('{1', [], -1302),  # T15.0.2 > T15.1.1a + override  : unknown register identifier
            ('{r', [], -1303),  # T15.0.2 > T15.1.1a + override  : missing register number
            ('{ra', [], -1304),  # T15.0.2 > T15.1.1a + override  : wrong reg number
            ('{r1a', [], -1304),  # T15.0.2 > T15.1.1a + override  : wrong reg number
            ('{r-1', [], -1303),  # T15.0.2 > T15.1.1a + override  : negative reg number
            ('{r16', [], -1304),  # T15.0.2 > T15.1.1a + override  : too high reg number
            ('{r0', [], -1503),  # T15.0.2 > T15.1.1a        error: unclosed single register
            ('{r0}', [0x1], 1000),  # T15.0.2 > T15.1.1c      success: single register
            ('{r0-r5}', [0x3F], 1000),  # T15.0.2 > T15.1.1c      success: single range
            ('{r0-r5 }', [0x3F], 1000),  # : idem with trailing space
            ('{r12-r2, lr', [0x1FFC], -1503),  # > T15.1.1b > T15.1.1a     error: missing '}' after list
            ('{r12 - r2, lr}', [0x5FFC], 1000),  # > T15.1.1b > T15.1.1c   success: range + single register
            ('{ pc, r1 -r2, sp- r12, r5}', [0xB026], 1000),  # : several ranges, with spaces
            ('{r4-}', [], -1403),  # > T15.1.1a + override          : missing second reg in range list
            ('{r14, r8-1', [0x4000], -1302),  # > T15.1.1a + override          : wrong second reg
            ('{r9-r16, r13}', [], -1304),  # > T15.1.1a + override          : too high second reg number
            ('{r14,r8}', [0x4100], 1000),  # success: no space after ','
            ('{ r9 , r13 }', [0x2200], 1000),  # success: extra spaces
            ('{r14,}', [0x4000], -1504),  # > T15.1.1b > T15.1.2      error: missing register after ','
            ('{r14, }', [0x4000], -1504),  # > T15.1.1b > T15.1.2           : missing register after ', '
            ('{r9-r15, sp13}', [0xFE00], -1402)  # > T15.1.1b + override          : unrecognized register id
            ]

imo_test = [('', [], -1601),  # T16.0.0                   error: missing immediate value
            (' ', [], -1601),  # T16.0.1 > T16.0.0         idem with leading space
            ('2', [], -1602),  # T16.0.3                   error: missing '#'
            ('#', [], -1603),  # T16.0.2 > T16.1.0         error: missing value after '#'
            ('# ', [], -1604),  # T16.0.2 > T16.1.1         error: unexpected space after '#'
            ('#f', [], -1605),  # T16.0.2 > T16.1.4         error: unrecognizable info after '#'
            ('#20', [20], 1000),  # T16.0.2 > T16.1.2 > T16.2.0   success: simple byte value
            ('#\'f\'', [102], 1000),  # T16.0.2 > T16.1.3 > T16.2.0   success: simple char value
            ('#-20', [], -1606),  # T16.0.2 > T16.1.2 + override : impossible fixup for negative number
            ('#2000', [0xE7D], 1000),  # T16.0.2 > T16.1.2 > T16.2.0   success fixup: in-the-middle bits
            ('#0xC0000034', [0x1D3], 1000),  # T16.0.2 > T16.1.2 > T16.2.0   success fixup: split bits
            ('#0xFF000000', [0x4FF], 1000),  # T16.0.2 > T16.1.2 > T16.2.0   success fixup: maximum rotation
            ('#0xFF0000FF', [], -1606),  # T16.0.2 > T16.1.2 + override : impossible fixup for 16 bits
            ('#0x102', [], -1606),  # T16.0.2 > T16.1.2 + override : impossible fixup for odd rotations
            ('#0x104', [0xF41], 1000),  # T16.0.2 > T16.1.2 > T16.2.0   success fixup: odd immediate mask
            ('#0x108', [0xF42], 1000),  # T16.0.2 > T16.1.2 > T16.2.0                : even immediate mask
            ('#45r', [], -1004),  # T16.0.2 > T16.1.2 + override : unexpected decimal digit
            ('#\'e\' c', [101], -1607),  # T16.0.2 > T16.1.3 > T16.2.1  error: unexpected text after imm val.
            ('#0b111111100000000000', [0xBFE], 1000),  # T16.0.2 > T16.1.2 > T16.2.0    success fixup: binary
            ('#0b1002000', [], -1002),  # T16.0.2 > T16.1.2 + override : invalid binary digit
            ('#012000000005', [0x255], 1000),  # T16.0.2 > T16.1.2 > T16.2.0   success fixup: octal
            ('#012000900005', [], -1003),  # T16.0.2 > T16.1.2 + override : invalid octal digit
            ('#45d', [], -1004),  # T16.0.2 > T16.1.2 + override : invalid decimal digit
            ('#0x4X5', [], -1005),  # T16.0.2 > T16.1.2 + override : invalid hexa digit
            ('#0x400000000', [], -1006),  # T16.0.2 > T16.1.2 + override : too long value (>2^32)
            ('#0x08000002', [0x382], 1000),  # T16.0.2 > T16.1.2 > T16.2.0   success fixup: MSB = 1 at IM
            ('#\'', [], -1605),  # T16.0.2 > T16.1.4         error: unclosed char
            ('#\' ', [], -1104),  # T16.0.2 > T16.1.3 + override : unclosed char
            ('#\'\'', [], -1102),  # T16.0.2 > T16.1.3 + override : empty char
            ('#\' 0\'', [], -1105),  # T16.0.2 > T16.1.3 + override : more than one character
            ('#\'\t\'', [], -1103),  # T16.0.2 > T16.1.3 + override : illegal character ''
            ('#\"t\"', [], -1605),  # T16.0.2 > T16.1.4         error: illegal character '"'
            (' #\'a\'', [97], 1000)  # T16.0.1 > T16.0.2 > T16.1.3 > T16.2.0  success with leading space
            ]

ims_test = [('', [], -1701),  # T17.0.0                   error: missing immediate value
            (' ', [], -1701),  # T17.0.1 > T17.0.0         idem with leading space
            ('2', [], -1702),  # T17.0.3                   error: missing '#'
            ('#', [], -1703),  # T17.0.2 > T17.1.0         error: missing value after '#'
            ('# ', [], -1704),  # T17.0.2 > T17.1.1         error: unexpected space after '#'
            ('#f', [], -1705),  # T17.0.2 > T17.1.3         error: unrecognizable info after '#'
            ('#2', [2], 1000),  # T17.0.2 > T17.1.2 > T17.2.0   success: valid number of shifts
            ('#-20', [], -1706),  # T17.0.2 > T17.1.2 + override : negative number of shifts
            ('#040', [], -1706),  # T17.0.2 > T17.1.2 + override : too high number of shifts
            ('#0x1C', [28], 1000),  # T17.0.2 > T17.1.2 > T17.2.0   success: hexa number
            ('#0b10101', [21], 1000),  # T17.0.2 > T17.1.2 > T17.2.0   success: binary number
            ('#0b10020', [], -1002),  # T17.0.2 > T17.1.2 + override : invalid binary digit
            ('#019', [], -1003),  # T17.0.2 > T17.1.2 + override : invalid octal digit
            ('#4d', [], -1004),  # T17.0.2 > T17.1.2 + override : invalid decimal digit
            ('#0xX', [], -1005),  # T17.0.2 > T17.1.2 + override : invalid hexa digit
            (' #0x1F', [31], 1000)  # T17.0.1 > T17.0.2 > T17.1.2 > T17.2.0  success with leading space
            ]

op2_test = [('', [], -2201),  # T22.0.0                   error: missing second operand
            (' ', [], -2203),  # T22.0.3                   idem with leading space
            ('2', [], -2203),  # T22.0.3                   error: missing '#'
            ('#', [], -1603),  # T22.0.1 + override        : missing value after '#'
            ('# ', [], -1604),  # T22.0.1 + override        : unexpected space after '#'
            ('#f', [], -1605),  # T22.0.1 + override        : unrecognizable info after '#'
            ('#20', [0x02000014], 1000),  # T22.0.1                   success: simple byte value
            ('#\'f\'', [0x02000066], 1000),  # T22.0.1                   success: simple char value
            ('#-20', [], -1606),  # T22.0.1 + override        : impossible fixup for negative number
            ('#0xC0000034', [0x020001D3], 1000),  # T22.0.1                   success fixup: split bits
            ('#0x102', [], -1606),  # T22.0.1 + override        : impossible fixup for odd rotations
            ('#\'e\' c', [], -1607),  # T22.0.1 + override        : unexpected text after imm val.
            ('#0b1002000', [], -1002),  # T22.0.1 + override        : invalid binary digit
            ('#012000900005', [], -1003),  # T22.0.1 + override        : invalid octal digit
            ('#45d', [], -1004),  # T22.0.1 + override        : invalid decimal digit
            ('#0x4X5', [], -1005),  # T22.0.1 + override        : invalid hexa digit
            ('#0x400000000', [], -1006),  # T22.0.1 + override        : too long value (2^32)
            ('#\'', [], -1605),  # T22.0.1 + override        : unclosed char
            ('#\' ', [], -1104),  # T22.0.1 + override        : unclosed char
            ('#\'\'', [], -1102),  # T22.0.1 + override        : empty char
            ('#\' 0\'', [], -1105),  # T22.0.1 + override        : more than one character
            ('#\'\t\'', [], -1103),  # T22.0.1 + override        : illegal character ''
            ('#\"t\"', [], -1605),  # T22.0.1 + override        : illegal character '"'
            (' #\'a\'', [0x02000061], 1000),  # T22.0.1                   success with leading space
            ('r', [], -1303),  # T22.0.2a + override       : missing register number
            ('ra', [], -1304),  # T22.0.2a + override       : wrong reg number
            ('r1a', [], -1304),  # T22.0.2a + override       : wrong reg number
            ('r-1', [], -1304),  # T22.0.2a + override       : negative reg number
            ('r16', [], -1304),  # T22.0.2a + override       : too high reg number
            ('r12', [12], 1000),  # T22.0.2a                  success: single reg
            ('r0 ', [0], 1000),  # T22.0.2a                  success: single reg with trailing space
            (' sp', [13], 1000),  # T22.0.2a                  success: single reg with leading space
            ('r1,', [1], -2204),  # T22.0.2b > T22.1.0        error: missing shift mode
            ('r2, ', [2], -2204),  # T22.0.2b > T22.1.1 > T22.1.0   : idem with trailing space
            ('r3, lslx', [3], -2206),  # T22.0.2b > T22.1.1 > T22.1.2c  : missing space after shift mode
            ('r3, r0', [3], -2206),  # T22.0.2b > T22.1.1 > T22.1.2c  : missing space after shift mode
            ('r3, #0', [3], -2206),  # T22.0.2b > T22.1.1 > T22.1.2c  : missing space after shift mode
            ('r4, xl', [4], -2206),  # T22.0.2b > T22.1.1 > T22.1.3   : unrecognized shift mode
            ('r5, lsl', [5], -2205),  # T22.0.2b > T22.1.1 > T22.1.2a  : missing space after shift mode
            ('r6, lsr ', [6], -2205),  # > T22.1.2b > T22.2.0           : missing info after shift mode
            ('r7, asr x', [7], -2207),  # > T22.1.2b > T22.2.3           : wrong info after shift mode
            ('r8, ror r', [8], -1303),  # > T22.1.2b > T22.2.1 + override: missing register number
            ('r9, lsl ra', [9], -1304),  # > T22.1.2b > T22.2.1 + override: wrong reg number
            ('r10, lsr r1a', [10], -1304),  # > T22.1.2b > T22.2.1 + override: wrong reg number
            ('r11, asr r-1', [11], -1304),  # > T22.1.2b > T22.2.1 + override: negative reg number
            ('r12, ror r16', [12], -1304),  # > T22.1.2b > T22.2.1 + override: too high reg number
            ('r13, lsl r12', [0xC1D], 1000),  # > T22.1.2b > T22.2.1             success: LSL reg
            ('sp, lsr r0 ', [0x3D], 1000),  # > T22.1.2b > T22.2.1             : LSR reg with trailing space
            ('r1,asr lr', [0xE51], 1000),  # > T22.1.2b > T22.2.1             : ASR reg no space after ','
            ('r8, ror #', [8], -1703),  # > T22.1.2b > T22.2.2 + override: missing value after '#'
            ('r9, lsl # ', [9], -1704),  # > T22.1.2b > T22.2.2 + override: unexpected space after '#'
            ('r10, lsr #f', [10], -1705),  # > T22.1.2b > T22.2.2 + override: unrecognizable info after '#'
            ('r11, asr #2', [0x14B], 1000),  # > T22.1.2b > T22.2.2             success: valid number of shifts
            ('r12, ror #-20', [12], -1706),  # > T22.1.2b > T22.2.2 + override: negative number of shifts
            ('r13, lsl #040', [13], -1706),  # > T22.1.2b > T22.2.2 + override: too high number of shifts
            ('pc, lsr #0x1C ', [0xE2F], 1000),  # > T22.1.2b > T22.2.2           success LSR imm with trailing space
            ('r1,asr #0b10101', [0xAC1], 1000),  # > T22.1.2b > T22.2.2           : ASR bin imm, no space after ','
            ('r8, ror #0b10020', [8], -1002),  # > T22.1.2b > T22.2.2 + override: invalid binary digit
            ('r9, lsl #019', [9], -1003),  # > T22.1.2b > T22.2.2 + override: invalid octal digit
            ('r10, lsr #4d', [10], -1004),  # > T22.1.2b > T22.2.2 + override: invalid decimal digit
            ('r11, asr #0xX', [11], -1005),  # > T22.1.2b > T22.2.2 + override: invalid hexa digit
            (' r12  , ror  #0x1F ', [0xFEC], 1000),  # > T22.1.2b > T22.2.2           success with lead/trail spaces
            ('r13, lsl r12 a', [13], -1304),  # > T22.1.2b > T22.2.1 + override: unexpected text after parse
            ('r12, ror #0x1F b', [12], -1005)  # > T22.1.2b > T22.2.2 + override: idem for immediate parsing
            ]

opd_test = [('', [], -2301),  # T23.0.0                   error: missing operands
            (' ', [], -2303),  # T23.0.2                   error: idem with leading space
            ('2', [], -1302),  # T23.0.1a + override       : unrecognizable register
            ('2,', [], -1302),  # T23.0.1b + override       : unrecognizable operand with ','
            ('r', [], -1303),  # T23.0.1a + override       : missing register number
            ('ra', [], -1304),  # T23.0.1a + override       : wrong reg number
            ('r16', [], -1304),  # T23.0.1a + override       : too high reg number
            ('r12', [], -2302),  # T23.0.1a                  error: good dest reg, missing other ops
            ('r0 ', [], -2302),  # T23.0.1a                  error: missing ',' after dest reg
            ('r1,', [0x1000], -2304),  # T23.0.1b > T23.1.0        error: missing source operands
            ('r2, ', [0x2000], -2306),  # T23.0.1b > T23.1.3        error: missing source operands
            ('r3, 3', [0x3000], -2306),  # T23.0.1b > T23.1.3        error: wrong source op 1
            ('r4, ra', [0x4000], -1304),  # T23.0.1b > T23.1.1 > T23.1.2a + override  : wrong reg number
            ('r5, r1a', [0x5000], -1304),  # T23.0.1b > T23.1.1 > T23.1.2a + override  : wrong reg number
            ('r6, r-1', [0x6000], -1304),  # T23.0.1b > T23.1.1 > T23.1.2a + override  : negative reg number
            ('r7, r16', [0x7000], -1304),  # T23.0.1b > T23.1.1 > T23.1.2a + override  : too high reg number
            ('r8, r12', [0x8800C], 1000),  # T23.0.1b > T23.1.1        success: two registers
            ('r9,r1 ', [0x99001], 1000),  # T23.0.1b > T23.1.1        success: idem with no space after ','
            (' sp , lr ', [0xDD00E], 1000),  # T23.0.1b > T23.1.1        success: idem with extra spaces
            ('r10, r1,', [0x0A000], -2204),  # T23.0.1b > T23.1.1 + override         : missing shift register
            ('r11, r2, ', [0x0B000], -2204),  # T23.0.1b > T23.1.1 + override         : idem with space
            ('r12, r3, 3', [0x3C000], -2308),  # T23.0.1b > T23.1.2b > T23.2.2    error: wrong op 2
            ('r13, r4, ra', [0x4D000], -1304),  # T23.0.1b > T23.1.2b > T23.2.1 + override  : wrong reg number
            ('r14, r5, r1a', [0x5E000], -1304),  # T23.0.1b > T23.1.2b > T23.2.1 + override  : wrong reg number
            ('r15, r6, r-1', [0x6F000], -1304),  # T23.0.1b > T23.1.2b > T23.2.1 + override  : negative reg number
            ('r0, r7, r16', [0x70000], -1304),  # T23.0.1b > T23.1.2b > T23.2.1 + override  : too high reg number
            ('r1, r8, r12', [0x8100C], 1000),  # T23.0.1b > T23.1.2b > T23.2.1 success: three registers
            ('r2,r9,r1 ', [0x92001], 1000),  # T23.0.1b > T23.1.2a       : idem with no space after ','
            ('r3, #', [0x03000], -1603),  # T23.0.1b > T23.1.1 + override : missing value after '#'
            ('r4, # ', [0x04000], -1604),  # T23.0.1b > T23.1.1 + override : unexpected space after '#'
            ('r5, #f', [0x05000], -1605),  # T23.0.1b > T23.1.1 + override : unrecognizable info after '#'
            ('r6, #20', [0x02066014], 1000),  # T23.0.1b > T23.1.1        success: dest reg + immediate value
            ('r7, #\'f\'', [0x02077066], 1000),  # T23.0.1b > T23.1.1        success: dest reg + immediate char
            ('r8, #-20', [0x08000], -1606),  # T23.0.1b > T23.1.1 + override : impossible fixup for negative num.
            ('r9,#0xC0000034', [0x020991D3], 1000),  # T23.0.1b > T23.1.1        success fixup: split bits
            ('r10, #0x102', [0x0A000], -1606),  # T23.0.1b > T23.1.1 + override : impossible fixup for odd rotations
            ('r11, #\'e\' c', [0xB000], -1607),  # T23.0.1b > T23.1.1 + override : unexpected text after imm val.
            ('r12, #0b1002000', [0x0C000], -1002),  # T23.0.1b > T23.1.1 + override : invalid binary digit
            ('r13, #012000900005', [0x0D000], -1003),  # > T23.1.1 + override : invalid octal digit
            ('r14, #45d', [0x0E000], -1004),  # T23.0.1b > T23.1.1 + override : invalid decimal digit
            ('r15, #0x4X5', [0x0F000], -1005),  # T23.0.1b > T23.1.1 + override : invalid hexa digit
            ('r0, #\'', [0x0], -1605),  # T23.0.1b > T23.1.1 + override : unclosed char
            ('r1, #\' ', [0x01000], -1104),  # T23.0.1b > T23.1.1 + override : unclosed char
            ('r2, #\'\'', [0x02000], -1102),  # T23.0.1b > T23.1.1 + override : empty char
            ('r3, #\' 0\'', [0x03000], -1105),  # T23.0.1b > T23.1.1 + override : more than one character
            ('r4, #\'\t\'', [0x04000], -1103),  # T23.0.1b > T23.1.1 + override : illegal character ''
            ('r5, lslx', [0x05000], -2306),  # T23.0.1b > T23.1.3            error: unrecognized source operand
            ('r5, r10, lslx', [0xA5000], -2308),  # T23.0.1b > T23.1.2b > T23.2.2 error: wrong second operand
            ('r5, r10, r1', [0xA5001], 1000),  # T23.0.1b > T23.1.2b > T23.2.1 success: three registers
            ('r5, r10, #2', [0x20A5002], 1000),  # T23.0.1b > T23.1.2b > T23.2.1 success: two regs, one immediate
            ('r6, r1, xl', [0x16000], -2308),  # T23.0.1b > T23.1.2b > T23.2.2 error: wrong second operand
            ('r7, r2, lsl', [0x07000], -2205),  # T23.0.1b > T23.1.1 + override : missing space after shift mode
            ('r8, r3, lsr ', [0x08000], -2205),  # T23.0.1b > T23.1.1 + override : missing info after shift mode
            ('r9, r4, asr x', [0x09000], -2207),  # T23.0.1b > T23.1.1 + override : wrong info after shift mode
            ('r10, r5, ror r', [0x0A000], -1303),  # T23.0.1b > T23.1.1 + override : missing register number
            ('r11, r6, lsl ra', [0x0B000], -1304),  # T23.0.1b > T23.1.1 + override : wrong reg number
            ('r12, r7, ror r16', [0x0C000], -1304),  # T23.0.1b > T23.1.1 + override : too high reg number
            ('r13, r8, lsl r12', [0xDDC18], 1000),  # T23.0.1b > T23.1.1            success: LSL reg
            ('r14, sp, lsr r0 ', [0xEE03D], 1000),  # T23.0.1b > T23.1.1            : LSR reg with trailing space
            ('r15, r1,asr lr', [0xFFE51], 1000),  # T23.0.1b > T23.1.1            : ASR reg no space after ','
            ('r0, r8, ror #', [0], -1703),  # T23.0.1b > T23.1.1 + override : missing value after '#'
            ('r1, r9, lsl # ', [0x01000], -1704),  # T23.0.1b > T23.1.1 + override : unexpected space after '#'
            ('r2, r10, lsr #f', [0x02000], -1705),  # T23.0.1b > T23.1.1 + override : unrecognizable info after '#'
            ('r3, r11, asr #2', [0x3314B], 1000),  # T23.0.1b > T23.1.1            success: valid number of shifts
            ('r4, r12, ror #-20', [0x04000], -1706),  # > T23.1.1 + override  : negative number of shifts
            ('r5, r13, lsl #040', [0x05000], -1706),  # > T23.1.1 + override  : too high number of shifts
            ('r5, r13, lsl #00', [0x05500D], 1000),  # > T23.1.1             success: true LSL #0
            ('r6, pc, lsr #0x1C ', [0x66E2F], 1000),  # > T23.1.1             success LSR imm with trailing space
            ('r6, pc, lsr #0x0 ', [0x6600F], 1000),  # > T23.1.1             converting LSR #0 into LSL #0
            ('r7,r1,asr #0b10101', [0x77AC1], 1000),  # > T23.1.1             : ASR bin imm, no space after ','
            ('r7,r1,asr #0b0', [0x77001], 1000),  # > T23.1.1             converting ASR #0 into LSL #0
            ('r8, r13, lsl r12 a', [0x08000], -1304),  # > T23.1.1 + override  : unexpected text after parse
            ('r9, r12, ror #0x1F b', [0x09000], -1005),  # > T23.1.1 + override  : idem for immediate parsing
            ('r9, r12, ror #0x1F', [0x99FEC], 1000),  # > T23.1.1             success ROR with 31 shifts
            ('r9, r12, ror #0x0', [0x9906C], 1000),  # > T23.1.1             coding ROR #0 as RRX
            ('r13, r7, r8, lsl r12 ', [0x7DC18], 1000),  # > T23.1.2 > T23.2.1   success: three regs, last shift reg
            ('r14 , r8 , sp , lsr  r10', [0x8EA3D], 1000),  # > T23.1.2 > T23.2.1          : idem with trailing spaces
            ('r15,r9,r1,asr lr', [0x9FE51], 1000),  # > T23.1.2 > T23.2.1          : idem with space after ','
            ('r13, r7, r8, lsl #12 ', [0x7D608], 1000),  # > T23.1.2 > T23.2.1   success: three regs, last shift imm
            ('r14 , r8 , sp , lsr  #10', [0x8E52D], 1000),  # > T23.1.2 > T23.2.1      : idem with trailing spaces
            ('r15,r9,r1,asr #31', [0x9FFC1], 1000),  # > T23.1.2 > T23.2.1      : idem with space after ','
            ('r15,r9,r1,asr r32', [0x9F000], -1304),  # > T23.1.2 > T23.2.1 + override : wrong range reg number
            ('r15,r9,r1,asr #32', [0x9F000], -1706),  # > T23.1.2 > T23.2.1 + override : invalid number of shifts
            ('r15,r9,r1,asr r', [0x9F000], -1303),  # > T23.1.2 > T23.2.1 + override : missing reg number
            ('r15,r9,r1,asr ', [0x9F000], -2205)  # > T23.1.2 > T23.2.1 + override : missing info after shift
            ]

idt_test = [('', [], -3101),  # T31.0.0                  error: missing data instruction
            (' ', [], -3101),  # T31.0.1 > T31.0.0        error: idem with leading space
            ('2', [], -3103),  # T31.0.3                  error: unrecognizable instruction
            ('and', [], -3102),  # T31.0.2a                 error: missing operands after instr.
            ('eor ', [4, 0xE0200000], -3102),  # T31.0.2b > T31.3.0       error: missing operands after instr.
            ('sub 2,', [4, 0xE0400000], -1302),  # T31.0.2b > T31.3.1 + override : unrecognizable operand with ','
            ('rsb r', [4, 0xE0600000], -1303),  # T31.0.2b > T31.3.1 + override : missing register number
            ('add r16', [4, 0xE0800000], -1304),  # T31.0.2b > T31.3.1 + override : too high reg number
            ('adc r12', [4, 0xE0A00000], -2302),  # T31.0.2b > T31.3.1 + override : good dest reg, missing other ops
            ('sbc  ', [4, 0xE0C00000], -2303),  # T31.0.2b > T31.3.1 + override : missing dest reg
            ('rsc  r1,', [4, 0xE0E00000], -2304),  # T31.0.2b > T31.3.1 + override : missing source operands
            ('orr r2, ', [4, 0xE1800000], -2306),  # T31.0.2b > T31.3.1 + override : missing source operands
            ('bic r3, 3', [4, 0xE1C00000], -2306),  # T31.0.2b > T31.3.1 + override : wrong source op 1
            ('and r12, r3, 3', [4, 0xE0000000], -2308),  # > T31.3.1 + override : wrong op 2
            ('eor r3, #', [4, 0xE0200000], -1603),  # > T31.3.1 + override : missing value after '#'
            ('sub r4, # ', [4, 0xE0400000], -1604),  # > T31.3.1 + override : unexpected space after '#'
            ('rsb r5, #f', [4, 0xE0600000], -1605),  # > T31.3.1 + override : unrecognizable info after '#'
            ('add r10, #0x102', [4, 0xE0800000], -1606),  # > T31.3.1 + override : impossible fixup for odd rotations
            ('adc r11, #\'e\' c', [4, 0xE0A00000], -1607),  # > T31.3.1 + override : unexpected text after imm val.
            ('sbc r10, r1,', [4, 0xE0C00000], -2204),  # > T31.3.1 + override : missing shift register
            ('rsc r7, r2, lsl', [4, 0xE0E00000], -2205),  # > T31.3.1 + override : missing space after shift mode
            ('orr r9, r4, asr x', [4, 0xE1800000], -2207),  # > T31.3.1 + override : wrong info after shift mode
            ('bic r0, r8, ror #', [4, 0xE1C00000], -1703),  # > T31.3.1 + override : missing value after '#'
            ('and r1, r9, lsl # ', [4, 0xE0000000], -1704),  # > T31.3.1 + override : unexpected space after '#'
            ('eor r2, r10, lsr #f', [4, 0xE0200000], -1705),  # > T31.3.1 + override : unrecognizable info after '#'
            ('sub r4, r12, ror #-20', [4, 0xE0400000], -1706),  # > T31.3.1 + override : negative number of shifts
            ('rsb r12, #0b1002000', [4, 0xE0600000], -1002),  # > T31.3.1 + override : invalid binary digit
            ('add r13, #012000900005', [4, 0xE0800000], -1003),  # > T31.3.1 + override : invalid octal digit
            ('adc r14, #45d', [4, 0xE0A00000], -1004),  # > T31.3.1 + override : invalid decimal digit
            ('sbc r15, #0x4X5', [4, 0xE0C00000], -1005),  # > T31.3.1 + override : invalid hexa digit
            ('rsc r2, #\'\'', [4, 0xE0E00000], -1102),  # > T31.3.1 + override : empty char
            ('orr r4, #\'\t\'', [4, 0xE1800000], -1103),  # > T31.3.1 + override : illegal character ''
            ('bic r1, #\' ', [4, 0xE1C00000], -1104),  # > T31.3.1 + override : unclosed char
            ('and r3, #\' 0\'', [4, 0xE0000000], -1105),  # > T31.3.1 + override : more than one character
            ('eors', [4, 0xE0200000], -3102),  # T31.0.2c > T31.1.2a       error: data operands
            ('eoral', [4, 0xE0200000], -3102),  # T31.0.2c > T31.1.1a       error: data operands
            ('tsts', [4, 0xE1100000], -3102),  # T31.0.2c > T31.1.2a            : missing operands
            ('tsts ', [4, 0xE1100000], -3102),  # T31.0.2c > T31.1.2b > T31.3.0  : missing operands
            ('teqst', [4, 0xE1300000], -3105),  # T31.0.2c > T31.1.2c       error: wrong text after instruction
            ('cmpxx', [4, 0xE1500000], -3104),  # T31.0.2c > T31.1.3        error: unknown instruction condition
            ('cmneq', [4, 0xE1700000], -3102),  # T31.0.2c > T31.1.1a       error: missing ops after pred.inst.
            ('movne ', [4, 0x11A00000], -3102),  # T31.0.2c > T31.1.1b > T31.3.0  : idem after space
            ('mvncss', [4, 0x21E00000], -3102),  # T31.0.2c > T31.1.1c > T31.2.1a : idem after set flag
            ('mvncsx', [4, 0x21E00000], -3105),  # T31.0.2c > T31.1.1c > T31.2.2  : wrong text after pred.inst
            ('mvncssx', [4, 0x21E00000], -3105),  # T31.0.2c > T31.1.1c > T31.2.1c : wrong text after pred.inst + flag
            ('andhss', [4, 0x20000000], -3102),  # T31.0.2c > T31.1.1c > T31.2.1a : missing operands after set flag
            ('andhss ', [4, 0x20100000], -3102),  # T31.0.2c > T31.1.1c > T31.2.1b > T31.3.0 : after set flag + space
            ('eorccx', [4, 0x30200000], -3105),  # T31.0.2c > T31.1.1c > T31.2.2  : wrong text after pred.inst
            ('sublosx', [4, 0x30400000], -3105),  # T31.0.2c > T31.1.1c > T31.2.1c : wrong text after pred.inst + flag
            ('cmp', [], -3102),  # T31.0.2a                 error: missing operands after instr.
            ('cmn ', [4, 0xE1700000], -3102),  # T31.0.2b > T31.3.0       error: missing operands after instr.
            ('mov 2,', [4, 0xE1A00000], -1302),  # T31.0.2b > T31.3.1 + override : unrecognizable operand with ','
            ('mvn r', [4, 0xE1E00000], -1303),  # T31.0.2b > T31.3.1 + override : missing register number
            ('tst r16', [4, 0xE1100000], -1304),  # T31.0.2b > T31.3.1 + override : too high reg number
            ('teq r12', [4, 0xE1300000], -2302),  # T31.0.2b > T31.3.1 + override : good dest reg, missing other ops
            ('cmp  ', [4, 0xE1500000], -2303),  # T31.0.2b > T31.3.1 + override : missing source 1 reg
            ('cmn  r1,', [4, 0xE1700000], -2304),  # T31.0.2b > T31.3.1 + override : missing source operands
            ('mov r2, ', [4, 0xE1A00000], -2306),  # T31.0.2b > T31.3.1 + override : missing source operands
            ('mvn r3, 3', [4, 0xE1E00000], -2306),  # T31.0.2b > T31.3.1 + override : wrong source op 1
            ('tst r3, #', [4, 0xE1100000], -1603),  # > T31.3.1 + override : missing value after '#'
            ('teq r4, # ', [4, 0xE1300000], -1604),  # > T31.3.1 + override : unexpected space after '#'
            ('cmp r5, #f', [4, 0xE1500000], -1605),  # > T31.3.1 + override : unrecognizable info after '#'
            ('mov r10, #0x102', [4, 0xE1A00000], -1606),  # > T31.3.1 + override : impossible fixup for odd rotations
            ('mvn r11, #\'e\' c', [4, 0xE1E00000], -1607),  # > T31.3.1 + override : unexpected text after imm val.
            ('tst r7, r2, lsl', [4, 0xE1100000], -2205),  # > T31.3.1 + override : missing space after shift mode
            ('teq r9, r4, asr x', [4, 0xE1300000], -2207),  # > T31.3.1 + override : wrong info after shift mode
            ('cmp r0, r8, ror #', [4, 0xE1500000], -1703),  # > T31.3.1 + override : missing value after '#'
            ('cmn r1, r9, lsl # ', [4, 0xE1700000], -1704),  # > T31.3.1 + override : unexpected space after '#'
            ('mov r2, r10, lsr #f', [4, 0xE1A00000], -1705),  # > T31.3.1 + override : unrecognizable info after '#'
            ('mvn r4, r12, ror #-20', [4, 0xE1E00000], -1706),  # > T31.3.1 + override : negative number of shifts
            ('tst r12, #0b1002000', [4, 0xE1100000], -1002),  # > T31.3.1 + override : invalid binary digit
            ('teq r13, #012000900005', [4, 0xE1300000], -1003),  # > T31.3.1 + override : invalid octal digit
            ('cmp r14, #45d', [4, 0xE1500000], -1004),  # > T31.3.1 + override : invalid decimal digit
            ('cmn r15, #0x4X5', [4, 0xE1700000], -1005),  # > T31.3.1 + override : invalid hexa digit
            ('mov r2, #\'\'', [4, 0xE1A00000], -1102),  # > T31.3.1 + override : empty char
            ('mvn r4, #\'\t\'', [4, 0xE1E00000], -1103),  # > T31.3.1 + override : illegal character ''
            ('tst r1, #\' ', [4, 0xE1100000], -1104),  # > T31.3.1 + override : unclosed char
            ('teq r3, #\' 0\'', [4, 0xE1300000], -1105),  # > T31.3.1 + override : more than one character
            ('eorsx', [4, 0xE0200000], -3105),  # T31.0.2c > T31.1.2c   error: wrong text after 's'
            ('eorx', [4, 0xE0200000], -3104),  # T31.0.2c > T31.1.3    error: wrong text after inst.
            ('rsb r5, r10, #2', [4, 0xE26A5002], 1000),  # T31.0.2b > T31.3.1  success: two regs, one immediate
            ('add r13, r8, lsl r12', [4, 0xE08DDC18], 1000),  # T31.0.2b > T31.3.1    : LSL reg
            ('adc r14, sp, lsr r0 ', [4, 0xE0AEE03D], 1000),  # T31.0.2b > T31.3.1    : LSR reg with trailing space
            ('sbc r15, r1,asr lr', [4, 0xE0CFFE51], 1000),  # T31.0.2b > T31.3.1    : ASR reg no space after ','
            ('rsc r6, pc, lsr #0x1C ', [4, 0xE0E66E2F], 1000),  # T31.0.2b > T31.3.1    : LSR imm with trailing space
            ('rsc r6, pc, lsr #0x0 ', [4, 0xE0E6600F], 1000),  # : LSR #0 -> LSL #0
            ('orrs r7,r1,asr #0b10101', [4, 0xE1977AC1], 1000),  # > T31.1.2b > T31.3.1:ASR bin imm, no space after ','
            ('orrs r7,r1,asr #0b0', [4, 0xE1977001], 1000),  # : ASR #0 -> LSL #0
            ('bicmi r13, r7, r8, lsl r12 ', [4, 0x41C7DC18], 1000),  # > T31.1.1b > T31.3.1    : three regs, shift reg
            ('andpls r14 , r8 , sp , lsr  r10', [4, 0x5018EA3D], 1000),  # > T31.1.1c > T31.2.1b > T31.3.1 : cond. + 's'
            ('eorvss r15,r9,#\'f\'', [4, 0x6239F066], 1000),  # > T31.1.1c > T31.2.1b > T31.3.1 : cond.+'s'+ imm.
            ('subvc r9,#0xC0000034', [4, 0x724991D3], 1000),  # T31.0.2c > T31.1.1b > T31.3.1 : one reg + one imm.
            ('rsbhis r8 , sp , lsr  #10', [4, 0x8078852D], 1000),  # > T31.1.1c > T31.2.1b > T31.3.1: reg + shifted reg
            ('addls r9,r1,asr r15', [4, 0x90899F51], 1000),  # > T31.1.1b > T31.3.1      : idem with no 's'
            ('tst r7,r1, #0b10101', [4, 0xE1100000], -2310),  # T31.0.2b > T31.3.1 + override : 3 ops with 'tst'
            ('teq r13,r7,r8,lsl r12', [4, 0xE1300000], -2310),  # T31.0.2b > T31.3.1 + override : 3 ops with 'teq'
            ('cmppl r14,r8,sp,lsr r10', [4, 0x51500000], -2310),  # T31.0.2b > T31.3.1 + override : 3 ops with 'cmp'
            ('cmnvss r15,r9,#\'f\'', [4, 0x61700000], -2310),  # T31.0.2b > T31.3.1 + override : 3 ops with 'cmn'
            ('movvc r1,r9, #0xC000', [4, 0x71A00000], -2311),  # T31.0.2b > T31.3.1 + override : 3 ops with 'mov'
            ('mvnhis r8, lr, sp, lsr pc', [4, 0x81F00000], -2311),  # > T31.3.1 + override : 3 os with 'mvn'
            ('tst r7, #0b10101', [4, 0xE3170015], 1000),  # T31.0.2b > T31.3.1            : 'tst' + reg + imm
            ('teqlss r7,r8,lsl r12', [4, 0x91370C18], 1000),  # > T31.1.1c > T31.2.1b > T31.3.1: 'teq'+reg+shifted reg
            ('cmpge r14, r8', [4, 0xA15E0008], 1000),  # > T31.1.1c > T31.3.1          : 'cmp' + reg + reg
            ('cmnlt r15, #\'f\'', [4, 0xB37F0066], 1000),  # > T31.1.1c > T31.3.1          : 'cmn' + reg + char
            ('movgts r1, #0xC000', [4, 0xC3B01903], 1000),  # > T31.1.1c > T31.2.1b > T31.3.1: 'mov' + reg + imm
            ('mvnle lr, sp, lsr #15', [4, 0xD1E0E7AD], 1000),  # > T31.1.1c > T31.3.1          : 'mvn'+reg+shifted reg
            ('mov r2, #-1', [4, 0xE3E02000], 1000),  # T31.0.2b > T31.3.1 : 'mov' + reg + NOT imm
            ('mvn r3, #0xFFF00FFF', [4, 0xE3A03AFF], 1000),  # T31.0.2b > T31.3.1 : 'mvn' + reg + NOT imm
            ('and r4, #-200', [4, 0xE3C440C7], 1000),  # T31.0.2b > T31.3.1 : 'and' + reg + NOT imm
            ('bic r5, #0xFFC03FFF', [4, 0xE20559FF], 1000),  # T31.0.2b > T31.3.1 : 'bic' + reg + NOT imm
            ('add r6, #-300', [4, 0xE2466F4B], 1000),  # T31.0.2b > T31.3.1 : 'add' + reg + NOT imm
            ('sub r7, #0xFF100000', [4, 0xE287760F], 1000),  # T31.0.2b > T31.3.1 : 'mvn' + reg + NOT imm
            ('cmp r8, #-1000', [4, 0xE3780FFA], 1000),  # T31.0.2b > T31.3.1 : 'cmp' + reg + NOT imm
            ('cmn r9, #0xFFC04000', [4, 0xE35909FF], 1000)  # T31.0.2b > T31.3.1 : 'cmn' + reg + NOT imm
            ]

iml_test = [('', [], -3201),  # T32.0.0                   error: missing multiplication instr.
            (' ', [], -3201),  # T32.0.1 > T32.0.0         error: idem with leading space
            ('2', [], -3203),  # T32.0.3                   error: unrecognizable instruction
            ('mul', [], -3202),  # T32.0.2a                  error: missing operands after instr.
            ('mla ', [4, 0xE0200090], -3202),  # T32.0.2b > T32.3.0        error: missing operands after instr.
            ('umull 2,', [4, 0xE0800090], -1302),  # T32.0.2b > T32.3.1b + override : unrecognizable operand with ','
            ('smull r', [4, 0xE0C00090], -1303),  # T32.0.2b > T32.3.1b + override : missing register number
            ('umlal r16', [4, 0xE0A00090], -1304),  # T32.0.2b > T32.3.1b + override : too high reg number
            ('smlal r12', [4, 0xE0E00090], -3202),  # T32.0.2b > T32.3.1a       error: good dest reg, missing other ops
            ('mul  ', [4, 0xE0000090], -1301),  # T32.0.2b > T32.3.1a + override : missing reg1
            ('mla  r1,', [4, 0xE0210090], -3202),  # T32.0.2b > T32.3.1b > T32.4.0  : missing source operands
            ('umull r2, ', [4, 0xE0802090], -1301),  # > T32.4.1b + override      : missing reg2
            ('smull r3, gu', [4, 0xE0C03090], -1302),  # > T32.4.1b + override      : wrong op 2
            ('umlal r12, r3, e3', [4, 0xE0A3C090], -1302),  # > T32.5.1b + override  : wrong op 3
            ('smlal r3, r4, r5, ', [4, 0xE0E43095], -1301),  # > T32.6.1 + override   : missing reg4
            ('mul r3, r4, r5, r6', [4, 0xE0030594], -3207),  # > T32.6.1 + override   : four regs with 'mul'
            ('mla r3, r4, r5', [4, 0xE0230594], -3202),  # > T32.6.1 + override   : three regs with 'mla'
            ('mul r3, r4, r5', [4, 0xE0030594], 1000),  # > T32.5.1a      success: three regs with 'mul'
            ('mla r3, r4, r5, r6', [4, 0xE0236594], 1000),  # > T32.6.1       success: four regs with 'mla'
            ('umull r10, r11, r12, r13', [4, 0xE08BAD9C], 1000),  # > T32.6.1      : four regs with 'umull'
            ('umlal r1, r11, r2, r3', [4, 0xE0AB1392], 1000),  # > T32.6.1      : four regs with 'umlal'
            ('smull r10, r11, lr, r10', [4, 0xE0CBAA9E], 1000),  # > T32.6.1      : four regs with 'smull'
            ('smlal sp, lr, r0, r7', [4, 0xE0EED790], 1000),  # > T32.6.1      : four regs with 'smlal'
            ('mul pc, r0, r7', [4, 0xE0000090], -3208),  # > T32.5.1a + override  : use of PC as Rd
            ('mul r0, pc, r8', [4, 0xE0000090], -3208),  # > T32.5.1a + override  : use of PC as Rm
            ('mla r0, r7, pc', [4, 0xE0200097], -3208),  # > T32.5.1a + override  : use of PC as Rs
            ('umlal r10, pc, r6, r9', [4, 0xE0A0A090], -3208),  # + override     : use of PC as RdHi
            ('smlal pc, r9, r8, r7', [4, 0xE0E00090], -3208),  # + override     : use of PC as RdLo
            ('mul r3, r3, r5', [4, 0xE0030593], 1000),  # + warning      : Rd should be different from Rm
            ('mla r5, r5, r5, r1', [4, 0xE0251595], 1000),  # + warning      : Rd should be different from Rm
            ('mla r3, r4, r3, r4', [4, 0xE0234394], 1000),  # success : should work
            ('mla r3, r4, r3, r3', [4, 0xE0233394], 1000),  # success : should work
            ('umull r6, r7, r7, r6', [4, 0xE0876697], 1000),  # + warning      : RdHi, RdLo and Rm must all be dif
            ('smull r9, r10, r9,r9', [4, 0xE0CA9999], 1000),  # + warning      : RdHi, RdLo and Rm must all be dif
            ('umlal r6, r6, r7, r6', [4, 0xE0A66697], 1000),  # + warning      : RdHi and RdLo must be different
            ('smlal r8, r9, r10,r8', [4, 0xE0E9889A], 1000),  # success : should work
            ('muleq', [4, 0xE0000090], -3202),  # T32.0.2c > T32.1.1a     error : cond & missing ops
            ('muls', [4, 0xE0000090], -3202),  # T32.0.2c > T32.1.2a     error : 's'' & missing ops
            ('mulz', [4, 0xE0000090], -3204),  # T32.0.2c > T32.1.3      error : wrong text after
            ('muleqs', [4, 0x00000090], -3202),  # > T32.1.1c > T32.2.1a   error : missing ops
            ('muleqsz', [4, 0x00000090], -3205),  # > T32.1.2b > T32.2.1c   error : missing ops
            ('smull r3, r4', [4, 0xE0C03090], -3202),  # > T32.4.1a              error : missing ops
            ('smull r3, r4,', [4, 0xE0C43090], -3202),  # > T32.5.0               error : missing ops
            ('smull r3, r4, r5', [4, 0xE0C43095], -3202),  # > T32.5.1a              error : missing ops
            ('smull r3, r4, r5,', [4, 0xE0C43095], -3202),  # > T32.6.0               error : missing ops
            ('muleq r3, r4, r5', [4, 0x00030594], 1000),  # T32.0.2c > T32.1.1b > success : 'mul' + cond
            ('mlanes r3, r4, r5, r6', [4, 0x10336594], 1000),  # > T32.1.1c > T32.2.1b >       : 'mla' + cond + 's'
            ('umulls r10, r11, r12, r13', [4, 0xE09BAD9C], 1000),  # T32.0.2c > T32.1.2b >         : 'umull' + 's'
            ('umlalle r1, r11, r2, r3', [4, 0xD0AB1392], 1000),  # T32.0.2c > T32.1.1b >         : 'umlal' + cond
            ('smulllex r10, r11, lr, r10', [4, 0xD0C00090], -3205),  # T32.0.2c > T32.1.1c > T32.2.2 : error after cond
            ('smlalsy sp, lr, r0, r7', [4, 0xE0E00090], -3205)  # T32.0.2c > T32.1.2c           : error after 's'
            ]

ibr_test = [('', [], -3301),  # T33.0.0                   error: missing branch instr.
            (' ', [], -3301),  # T33.0.1 > T33.0.0         error: idem with leading space
            ('2', [], -3303),  # T33.0.5                   error: unrecognizable instruction
            ('blo', [], -3302),  # T33.0.2a                  error: missing offset after instr.
            ('bleq ', [4, 0x0B000000], -3302),  # T33.0.2b > T33.3.0             : missing offset after instr.
            ('blox', [4], -3303),  # T33.0.2c                  error: unexpected text after instr.
            ('bx', [], -3304),  # T33.0.3a                  error: missing reg after instr.
            ('blx ', [4, 0xE12FFF30], -3304),  # T33.0.3b > T33.4.0        error: missing reg after instr.
            ('blxo', [4, 0xE12FFF30], -3303),  # T33.0.3c > T33.2.2        error: unexpected text after instr.
            ('b', [], -3302),  # T33.0.4a                  error: missing offset after instr.
            ('bl ', [4, 0xEB000000], -3302),  # T33.0.4b > T33.3.0        error: missing offset after instr.
            ('bly', [4, 0xEB000000], -3303),  # T33.0.4c > T33.1.2        error: unexpected text after instr.
            ('beq', [4, 0xEA000000], -3302),  # T33.0.4c > T33.1.1a       error: missing offset after instr.
            ('blne ', [4, 0x1B000000], -3302),  # T33.0.4c > T33.1.1b > T 33.3.0 : missing offset after instr.
            ('blnex', [4, 0x1B000000], -3303),  # T33.0.4c > T33.1.1c            : unexpected text after instr.
            ('bxeq', [4, 0xE12FFF10], -3302),  # T33.0.3c > T33.2.1a       error: missing offset after instr.
            ('blxeq ', [4, 0x012FFF30], -3304),  # T33.0.3c > T33.2.1b > T 33.4.0 : missing offset after instr.
            ('blxeqx', [4, 0x012FFF30], -3303),  # T33.0.3c > T33.2.1c            : unexpected text after instr.
            ('blt f', [4, 0xBA000000], -3305),  # T33.0.2b > T33.3.2        error: wrong offset
            ('bls 0b12', [4, 0x9A000000], -1002),  # T33.0.2b > T33.3.1 + override  : unexpected binary digit
            ('blls 0192', [4, 0x9B000000], -1003),  # > T33.1.1b > T33.3.1 + override: unexpected octal digit
            ('bllo -192a', [4, 0x3B000000], -1004),  # > T33.1.1b > T33.3.1 + override: unexpected decimal digit
            ('blvc 0xA3G0', [4, 0x7B000000], -1005),  # > T33.1.1b > T33.3.1 + override: unexpected hexa digit
            ('bvc 0xA30000000', [4, 0x7A000000], -1006),  # > T33.3.1 + override: too long hex address
            ('bxvc 0xA300', [4, 0x712FFF10], -1302),  # > T33.2.1b > T33.4.1 + override: unrecognized reg
            ('blxcc r', [4, 0x312FFF30], -1303),  # > T33.2.1b > T33.4.1 + override: missing reg number
            ('bxcc rf', [4, 0x312FFF10], -1304),  # > T33.2.1b > T33.4.1 + override: wrong reg number
            ('bxmi r16', [4, 0x412FFF10], -1304),  # > T33.2.1b > T33.4.1 + override: wrong reg number
            ('bx r6', [4, 0xE12FFF16], 1000),  # T33.0.3b > T33.4.1      success: 'bx' jump
            ('blxpl r6', [4, 0x512FFF36], 1000),  # > T33.2.1b > T33.4.1    success: 'blx' jump
            ('blxlt r15', [4, 0xB12FFF3F], 1000),  # > T33.2.1b > T33.4.1    warning: use of pc (r15)
            ('b 0xA300', [4, 0xEA0028C0], 1000),  # T33.0.4b > T33.3.1      success: 'b' jump
            ('bl -1300', [4, 0xEBFFFEBB], 1000),  # T33.0.4b > T33.3.1      success: 'bl' negative jump
            ('blt 073000000', [4, 0xBA3B0000], 1000),  # > T33.3.1      success: 'blt' octal jump
            ('bleq 0x730000', [4, 0x0B1CC000], 1000),  # > T33.3.1      success: 'bleq' hexa jump
            ('bhi 0xA30000', [4, 0x8A28C000], 1000),  # > T33.3.1      success: 'b' jump
            ('blgt 0x1302', [4, 0xCB000000], -3307),  # > T33.3.1 + override  : misaligned address
            ('bllt 0x73000000', [4, 0xBB000000], -3308),  # > T33.3.1 + override  : out of range offset
            ('blal -73000000', [4, 0xEB000000], -3308),  # > T33.3.1 + override  : out of range negative offset
            ('bal -7300001', [4, 0xEA000000], -3307)  # > T33.3.1 + override  : misaligned negative address
            ]

am2_test = [('', [], -2401),  # T24.0.0                   error: missing addressing mode
            (' ', [], -2401),  # T24.0.1 > T24.0.0         error: idem with leading space
            ('2', [], -2402),  # T24.0.3                   error: missing '['
            ('[', [], -2403),  # T24.0.2 > T24.1.0         error: missing info after '['
            ('[2', [], -2403),  # T24.0.2 > T24.1.2              : unrecognizable register
            ('[r', [], -1303),  # T24.0.2 > T24.1.1a + override  : missing register number
            ('[ra', [], -1304),  # T24.0.2 > T24.1.1a + override  : wrong reg number
            ('[r16', [], -1304),  # T24.0.2 > T24.1.1a + override  : too high reg number
            ('[r12', [], -2404),  # T24.0.2 > T24.1.1a        error: good base reg, missing closure
            ('[r0 ', [], -2404),  # T24.0.2 > T24.1.1a        error: missing ',' after base reg
            ('[r1,', [0x01810000], -2405),  # T24.0.2 > T24.1.1b > T24.2.0   : missing displacement
            ('[r2]!', [0x01820000], -2410),  # T24.0.2 > T24.1.1c > T24.7.2   : unexpected text after ']'
            ('[r3, 3', [0x01830000], -2406),  # > T24.1.1b > T24.2.1 > T24.2.6 : wrong displacement
            ('[r4, ra', [0x01840000], -1304),  # > T24.2.1 > T24.2.5a + override: wrong reg number
            ('[r5, r1a', [0x01850000], -1304),  # > T24.2.1 > T24.2.5a + override: wrong reg number
            ('[r6, +r1', [0x01860000], -2404),  # > T24.2.1 > T24.2.2 > T24.3.1a : check positive reg displ.
            ('[r7, -r6', [0x01070000], -2404),  # > T24.2.1 > T24.2.3 > T24.3.1a : check negative reg displ.
            ('[r8, -', [0x01080000], -2405),  # > T24.2.3 > T24.3.0            : EOSeq after '-'
            ('[r8, -3.2', [0x01080000], -2406),  # > T24.2.3 > T24.3.2            : wrong reg after '-'
            ('[r5, r10, ', [0x0385000A], -2407),  # > T24.2.5b > T24.5.1 > T24.5.0 : missing shift mode
            ('[r7, r2, lsl', [0x03870002], -2408),  # > T24.2.5b > T24.5.1 > T24.5.2a: missing space after shift
            ('[r8, r3, lsr ', [0x03880003], -2408),  # > T24.5.2b > T24.6.0       : missing info after shift mode
            ('[r10, r5, ror r', [0x038A0005], -1702),  # > T24.5.2b > T24.6.2       : idem
            ('[r1, r9, lsl # ', [0x03810009], -1704),  # > T24.5.2b > T24.6.1a + override  : unexpected space after '#'
            ('[r3, r11, asr #2', [0x0383000B], -2404),  # > T24.5.2b > T24.6.1a      : valid scaled reg, missing ']'
            ('[r8, #', [0x01880000], -2405),  # > T24.2.1 > T24.2.4 > T24.4.0  : missing displacement
            ('[r4, # ', [0x01840000], -2406),  # > T24.2.1 > T24.2.4 > T24.4.2  : unexpected space after '#'
            ('[r5, #\'f\'', [0x01850000], -2406),  # > T24.2.1 > T24.2.4 > T24.4.2  : unrecognizable info after '#'
            ('[r6, #20', [0x01860000], -2404),  # > T24.2.1 > T24.2.4 > T24.4.1a : base + imm. displ., missing ']'
            ('[r8, #-20', [0x01880000], -2404),  # > T24.2.1 > T24.2.4 > T24.4.1a : idem for negative imm. displ.
            ('[r9,#0xC0000034]', [0x1890000], -2411),  # > T24.4.1b + override      : too long immediate displacement
            ('[r12, #0b1002000]', [0x018C0000], -1002),  # + override      : invalid binary digit
            ('[r13, #012000900005]', [0x018D0000], -1003),  # + override      : invalid octal digit
            ('[r14, #45d]', [0x018E0000], -1004),  # + override      : invalid decimal digit
            ('[r15, #0x4X5]', [0x018F0000], -1005),  # + override      : invalid hexa digit
            ('[ r6, #+0]', [0x01860000], 1000),  # > T24.2.4 > T24.4.1b > T24.7.0 : success base + imm. displ.
            ('[r6, #20]', [0x01860014], 1000),  # > T24.2.4 > T24.4.1b > T24.7.0 : success base + imm. displ.
            ('[r7, #+4095]', [0x01870FFF], 1000),  # > T24.2.4 > T24.4.1b > T24.7.0 : maximum positive imm. displ.
            ('[r8, #-20]', [0x01080014], 1000),  # > T24.2.4 > T24.4.1b > T24.7.0 : base + negative imm. displ.
            ('[r9, #-4095]', [0x01090FFF], 1000),  # > T24.2.4 > T24.4.1b > T24.7.0 : minimum negative imm. displ.
            ('[r10]', [0x018A0000], 1000),  # T24.0.2 > T24.1.1c > T24.7.0   : success base only
            ('[sp ]', [0x018D0000], 1000),  # T24.0.2 > T24.1.1c > T24.7.0   : idem with trailing space
            ('[r9,r1]', [0x03890001], 1000),  # > T24.1.1b > T24.2.5c > T24.7.0: success base + reg. displacement
            ('[ sp , lr ]', [0x038D000E], 1000),  # > T24.1.1b > T24.2.5c > T24.7.0: idem with extra spaces
            ('[r1, +r6]', [0x03810006], 1000),  # > T24.2.2 > T24.3.1c > T24.7.0 : check positive reg displ.
            ('[r6, -r7]', [0x03060007], 1000),  # > T24.2.3 > T24.3.1c > T24.7.0 : check negative reg displ.
            ('[r5, r15]', [0x01850000], -2412),  # > T24.2.5b + override          : PC not allowed as Rm
            ('[r5, r10, ]', [0x0385000A], -2409),  # > T24.2.5b > T24.5.1 > T24.5.3 : missing shift mode
            ('[r5, r10, lslx]', [0x0385000A], -2409),  # > T24.2.5b > T24.5.1 > T24.5.3    : wrong shift mode
            ('[r7, +r2, lsl]', [0x03870002], -2409),  # > T24.3.1b > T24.5.1 > T24.5.2c   : missing space after shift
            ('[r8, -r3, lsr ]', [0x03080003], -2409),  # > T24.3.1b > T24.6.2       : missing info after shift mode
            ('[r9, r4, asr x]', [0x03890004], -1702),  # > T24.5.2b > T24.6.2       : wrong info after shift mode
            ('[r0, r8, ror #]', [0x03800008], -1703),  # > T24.5.2b > T24.6.1a + override  : missing value after '#'
            ('[r2, r10, lsr #f]', [0x0382000A], -1705),  # > T24.5.2b > T24.6.1a + override  : unrecogn. info after '#'
            ('[r4, r12, ror #-20]', [0x0384000C], -1706),  # > T24.6.1b + override  : negative number of shifts
            ('[r5, r13, lsl #040]', [0x0385000D], -1706),  # > T24.6.1b + override  : too high number of shifts
            ('[r5, r13, lsl #0]', [0x0385000D], 1000),  # > T24.6.1b > T24.7.0   : true LSL #0
            ('[r6, lr, lsr #0x1C] ', [0x03860E2E], 1000),  # > T24.6.1b > T24.7.1> T24.7.0: success with trailing space
            ('[r5, r13, lsl #00]', [0x0385000D], 1000),  # > T24.6.1b > T24.7.0   : true LSL #0
            ('[r6, sp, lsr #0x0 ]', [0x0386000D], 1000),  # > T24.6.1b > T24.7.0   : converting LSR #0 into LSL #0
            ('[r7,-r1,asr #0b10101]', [0x03070AC1], 1000),  # : ASR bin imm, no space after ','
            ('[r7,+r1,asr #0b0]', [0x03870001], 1000),  # : converting ASR #0 into LSL #0
            ('[r9, r12, ror #0x1F]', [0x03890FEC], 1000),  # : success ROR with 31 shifts
            ('[r9, r12, ror #0x0]', [0x0389006C], 1000)  # : coding ROR #0 as RRX
            ]

am3_test = [('', [], -2501),  # T25.0.0                   error: missing addressing mode
            (' ', [], -2501),  # T25.0.1 > T25.0.0         error: idem with leading space
            ('2', [], -2502),  # T25.0.3                   error: missing '['
            ('[', [], -2503),  # T25.0.2 > T25.1.0         error: missing info after '['
            ('[2', [], -2503),  # T25.0.2 > T25.1.2              : unrecognizable register
            ('[r', [], -1303),  # T25.0.2 > T25.1.1a + override  : missing register number
            ('[ra', [], -1304),  # T25.0.2 > T25.1.1a + override  : wrong reg number
            ('[r16', [], -1304),  # T25.0.2 > T25.1.1a + override  : too high reg number
            ('[r12', [], -2504),  # T25.0.2 > T25.1.1a        error: good base reg, missing closure
            ('[r0+', [], -1304),  # T25.0.2 > T25.1.1a + override  : missing ',' after base reg
            ('[r1,', [0x01C10000], -2505),  # T25.0.2 > T25.1.1b > T25.2.0   : missing displacement
            ('[r2]!', [0x01C20000], -2510),  # T25.0.2 > T25.1.1c > T25.7.2   : unexpected text after ']'
            ('[r3, 3', [0x01C30000], -2506),  # > T25.1.1b > T25.2.1 > T25.2.6 : wrong displacement
            ('[r4, ra', [0x01C40000], -1304),  # > T25.2.1 > T25.2.5a + override: wrong reg number
            ('[r5, r1a', [0x01C50000], -1304),  # > T25.2.1 > T25.2.5a + override: wrong reg number
            ('[r6, +r1', [0x01C60000], -2504),  # > T25.2.1 > T25.2.2 > T25.3.1a : check positive reg displ.
            ('[r7, -r6', [0x01470000], -2504),  # > T25.2.1 > T25.2.3 > T25.3.1a : check negative reg displ.
            ('[r8, -', [0x01480000], -2505),  # > T25.2.3 > T25.3.0            : EOSeq after '-'
            ('[r8, -3.2', [0x01480000], -2506),  # > T25.2.3 > T25.3.2            : wrong reg after '-'
            ('[r5, r10, ', [0x01C50000], -2513),  # > T25.2.5b                     : scaled reg. displ. not allowed
            ('[r7, r2, lsl', [0x01C70000], -2513),  # > T24.2.5b                     : idem
            ('[r8, #', [0x01C80000], -2505),  # > T25.2.1 > T25.2.4 > T25.4.0  : missing displacement
            ('[r4, # ', [0x01C40000], -2506),  # > T25.2.1 > T25.2.4 > T25.4.2  : unexpected space after '#'
            ('[r5, #\'f\'', [0x01C50000], -2506),  # > T25.2.1 > T25.2.4 > T25.4.2  : unrecognizable info after '#'
            ('[r6, #20', [0x01C60000], -2504),  # > T25.2.1 > T25.2.4 > T25.4.1a : base + imm. displ., missing ']'
            ('[r9, #0x134]', [0x1C90000], -2511),  # > T25.4.1b + override          : too long immediate displacement
            ('[r12, #0b0001103]', [0x01CC0000], -1002),  # + override      : invalid binary digit
            ('[r13, #012009005]', [0x01CD0000], -1003),  # + override      : invalid octal digit
            ('[r14, #4+5]', [0x01CE0000], -1004),  # + override      : invalid decimal digit
            ('[r15, #0xX45]', [0x01CF0000], -1005),  # + override      : invalid hexa digit
            ('[ r6, #+0]', [0x01C60000], 1000),  # > T25.2.4 > T25.4.1b > T25.7.0 : success base + imm. displ.
            ('[r6 ,#195]', [0x01C60C03], 1000),  # > T25.2.4 > T25.4.1b > T25.7.0 : success base + imm. displ.
            (' [r7, #+255]', [0x01C70F0F], 1000),  # > T25.2.4 > T25.4.1b > T25.7.0 : maximum positive imm. displ.
            ('[r8, # -80]', [0x01480500], 1000),  # > T25.2.4 > T25.4.1b > T25.7.0 : base + negative imm. displ.
            ('[r9, #-255 ]', [0x01490F0F], 1000),  # > T25.2.4 > T25.4.1b > T25.7.0 : minimum negative imm. displ.
            ('[r9,# - 25]', [0x01490109], 1000),  # > T25.2.4 > T25.4.1b > T25.7.0 : negative with white spaces
            ('[r9, # + 25]', [0x01C90109], 1000),  # > T25.2.4 > T25.4.1b > T25.7.0 : positive with white spaces
            ('[r10]', [0x01CA0000], 1000),  # T25.0.2 > T25.1.1c > T25.7.0   : success base only
            ('[sp ]', [0x01CD0000], 1000),  # T25.0.2 > T25.1.1c > T25.7.0   : idem with trailing space
            ('[r9,r1]', [0x01890001], 1000),  # > T25.1.1b > T25.2.5c > T25.7.0: success base + reg. displacement
            ('[ sp , lr ]', [0x018D000E], 1000),  # > T25.1.1b > T25.2.5c > T25.7.0: idem with extra spaces
            ('[r1, +r6]', [0x01810006], 1000),  # > T25.2.2 > T25.3.1c > T25.7.0 : check positive reg displ.
            ('[r1, + r6]', [0x01810006], 1000),  # > T25.2.2 > T25.3.1c > T25.7.0 : idem with white space
            ('[r6, -r7]', [0x01060007], 1000),  # > T25.2.3 > T25.3.1c > T25.7.0 : check negative reg displ.
            ('[r6,- r7] ', [0x01060007], 1000),  # > T25.3.1c > T25.7.1 > T25.7.0 : idem with white space
            ('[r5, r15]', [0x01C50000], -2512),  # > T25.2.5b + override          : PC not allowed as Rm
            ('[r5, r10+]', [0x01C50000], -1304),  # > T25.2.5b + override          : wrong text after reg. number
            ('[r5, +r10,]', [0x01C50000], -2513)  # > T25.2.2 > T25.3.1b           : scaled reg. displ. not allowed
            ]

im2_test = [('', [], -3401),  # T34.0.0                   error: missing memory transfer inst.
            (' ', [], -3401),  # T34.0.1 > T34.0.0         error: idem with leading space
            ('2', [], -3402),  # T34.0.3                   error: missing 'ld' or 'st'
            ('ld', [4, 0xE0000000], -3402),  # T34.0.2 > T34.1.0         error: missing inst. continuation
            ('st ', [4, 0xE0000000], -3402),  # T34.0.2 > T34.1.4         error: missing inst. continuation
            ('str', [4, 0xE0000000], -3403),  # T34.0.2 > T34.1.1 > T34.2.0    : missing space after inst.
            ('ldr ', [4, 0xE4100000], -3405),  # > T34.1.1 > T34.2.1 > T34.5.0  : missing destination register
            ('sts', [4, 0xE0000000], -3408),  # T34.0.2 > T34.1.2 + override   : 's' not allowed for store inst.
            ('ldx', [4, 0xE0000000], -3402),  # T34.0.2 > T34.1.4              : unrecognized mem. transfer inst.
            ('ldrb', [4, 0xE0000000], -3403),  # > T34.1.1 > T34.2.2 > T34.3.0  : missing space after inst.
            ('strb ', [4, 0xE4400000], -3405),  # > T34.2.2 > T34.3.1 > T34.5.0  : missing destination register
            ('ldrby', [4, 0xE0000000], -3404),  # > T34.2.2 > T34.3.2            : wrong text after inst.
            ('ldrb e', [4, 0xE4500000], -1302),  # > T34.3.1 > T34.5.1a + override: unknown reg
            ('str r', [4, 0xE4000000], -1303),  # > T34.2.1 > T34.5.1a + override: missing reg number
            ('ldr rb', [4, 0xE4100000], -1304),  # > T34.2.1 > T34.5.1a + override: wrong reg number
            ('ldrb r1', [4, 0xE4500000], -3406),  # > T34.2.1 > T34.5.1a      error: missing ',' after dest. reg
            ('strb r2,', [4, 0xE4402000], -3407),  # > T34.5.1b > T34.6.0      error: missing info after dest. reg
            ('streq', [4, 0x00000000], -3403),  # > T34.2.3 > T34.4.0            : missing space after inst.
            ('ldrne ', [4, 0x14100000], -3405),  # > T34.2.3 > T34.4.1 > T34.5.0  : missing destination register
            ('strles', [4, 0xD0000000], -3408),  # > T34.2.3 > T34.4.4 + override : 's' not allowed for store inst.
            ('ldrlox', [4, 0x30000000], -3404),  # > T34.2.3 > T34.4.5            : unrecognized mem. transfer inst.
            ('ldrmib', [4, 0x40000000], -3403),  # > T34.2.3 > T34.4.2 > T34.3.0  : missing space after inst.
            ('strmib ', [4, 0x44400000], -3405),  # > T34.4.2 > T34.3.1 > T34.5.0  : missing destination register
            ('ldrhsbx', [4, 0x20000000], -3404),  # > T34.4.2 > T34.3.2            :  wrong text after inst.
            ('ldrhsb r2, 2', [4, 0x24502000], -2402),  # > T34.6.1 > T34.6.3 + override    : missing '['
            ('strvcb r3, [', [4, 0x74403000], -2403),  # > T34.6.3 + override       : missing info after '['
            ('ldrge r4, [2', [4, 0xA4104000], -2403),  # > T34.6.3 + override       : unrecognizable register
            ('strltb r5,[r', [4, 0xB4405000], -1303),  # > T34.6.3 + override       : missing register number
            ('ldrvc r6, [r16', [4, 0x74106000], -1304),  # + override       : too high reg number
            ('ldr lr, [r12', [4, 0xE410E000], -2404),  # + override       : good base reg, missing closure
            ('str sp, [r0 ', [4, 0xE400D000], -2404),  # + override       : missing ',' after base reg
            ('ldrb r15, [r1,', [4, 0xE450F000], -2405),  # + override       : missing displacement
            ('strb pc, [r2]!', [4, 0xE440F000], -2410),  # + override       : unexpected text after ']'
            ('ldrvsb r4,[r3, 3', [4, 0x64504000], -2406),  # + override       : wrong displacement
            ('strge r5, [r5, r1a', [4, 0xA4005000], -1304),  # + override       : wrong reg number
            ('ldrltb r6, [r5, r10, ', [4, 0xB4506000], -2407),  # + override       : missing shift mode
            ('strlsb r7, [r7, r2, lsl', [4, 0x94407000], -2408),  # + override     : missing space after shift
            ('strgt r9, [r8, r3, lsr ', [4, 0xC4009000], -2408),  # + override     : missing info after shift mode
            ('ldr r11, [r10, r5, ror r', [4, 0xE410B000], -1702),  # + override     : idem
            ('ldrb r12, [r1, r9, lsl # ', [4, 0xE450C000], -1704),  # + override : unexpected space after '#'
            ('strb r13,[r9,#0xC0000034]', [4, 0xE440D000], -2411),  # + override : too long immediate displacement
            ('ldr r0, [r12, #0b1002000]', [4, 0xE4100000], -1002),  # + override : invalid binary digit
            ('strhi r1, [r13, #018000005]', [4, 0x84001000], -1003),  # + override : invalid octal digit
            ('strlob r2, [r14, #5d4]', [4, 0x34402000], -1004),  # + override : invalid decimal digit
            ('ldrplb r3, [r15, #0x4r]', [4, 0x54503000], -1005),  # + override : invalid hexa digit
            ('ldrb r3, [r15, #0x400000000]', [4, 0xE4503000], -1006),  # + override : too big number
            ('ldrcsb r4, [ r6, #+0]', [4, 0x25D64000], 1000),  # > T34.6.3  : success base + imm. displ.
            ('ldr r5, [r6, #20]', [4, 0xE5965014], 1000),  # : success base + imm. displ.
            ('str r6,[r7, #+4095]', [4, 0xE5876FFF], 1000),  # : maximum positive imm. displ.
            ('ldreqb r7, [r8, #-20]', [4, 0x05587014], 1000),  # : base + negative imm. displ.
            ('strccb r8, [r9, #-4095] ', [4, 0x35498FFF], 1000),  # : minimum negative imm. displ.
            ('ldr r9, [r10]', [4, 0xE59A9000], 1000),  # : success base only
            ('str r10,[r9,+r1]', [4, 0xE789A001], 1000),  # : success base + reg. displacement
            ('str r10, [r5, r15]', [4, 0xE400A000], -2412),  # + override : PC not allowed as Rm
            ('strb r11, [r0, r8, ror #]', [4, 0xE440B000], -1703),  # + override : missing value after '#'
            ('ldrle r12, [r2, r10, lsr #f]', [4, 0xD410C000], -1705),  # + override : unrecogn. info after '#'
            ('strmib r13, [r4, r12, ror #-20]', [4, 0x4440D000], -1706),  # override : negative number of shifts
            ('ldrplb r14, [r5, r13, lsl #040]', [4, 0x5450E000], -1706),  # override : too high number of shifts
            ('ldrvs r15,[r6, lr, lsr #0x1C] ', [4, 0x6796FE2E], 1000),  # : success with trailing space
            ('str r0, [r5, r13, lsl #00]', [4, 0xE785000D], 1000),  # : true LSL #0
            ('ldr r1, [r6, sp, lsr #0x0 ]', [4, 0xE796100D], 1000),  # : converting LSR #0 into LSL #0
            ('str r2, [r7,-r1,asr #0b10101]', [4, 0xE7072AC1], 1000),  # : ASR bin imm, no space after ','
            ('ldr r3 ,[r7,+r1,asr #0b0]', [4, 0xE7973001], 1000),  # : converting ASR #0 into LSL #0
            ('ldrb r4,[r9, r12, ror #0x1F]', [4, 0xE7D94FEC], 1000),  # : success ROR with 31 shifts
            ('strb r5, [r9, r12, ror #0x0]', [4, 0xE7C9506C], 1000)  # : coding ROR #0 as RRX
            ]

im3_test = [('lds', [4, 0xE0000000], -3404),  # T34.0.2 > T34.1.2 > T34.8.0   error: wrong memory transfer inst.
            ('strz', [4, 0xE0000000], -3404),  # T34.0.2 > T34.1.1 > T34.2.6   error: wrong memory transfer inst.
            ('strs', [4, 0xE0000000], -3408),  # > T34.1.1 > T34.2.5 + override     : 's' not allowed for store inst.
            ('strh', [4, 0xE00000B0], -3403),  # > T34.1.1 > T34.2.4 > T34.9.0 error: missing space after inst.
            ('ldrs', [4, 0xE0000000], -3404),  # > T34.1.1 > T34.2.5 > T34.10.0     : wrong memory transfer inst.
            ('ldrh ', [4, 0xE01000B0], -3405),  # > T34.2.4 > T34.9.1 > T34.11.0 : missing destination reg
            ('ldrsb', [4, 0xE01000D0], -3403),  # > T34.2.5 > T34.10.1 > T34.9.0 : missing space after inst.
            ('ldrsh', [4, 0xE01000F0], -3403),  # > T34.2.5 > T34.10.1 > T34.9.0 : missing space after inst.
            ('ldrsi', [4, 0xE0000000], -3404),  # > T34.2.5 > T34.10.2           : missing space after inst.
            ('ldrsb ', [4, 0xE01000D0], -3405),  # > T34.10.1 > T34.9.1 > T34.11.0: missing destination reg
            ('ldrsb e', [4, 0xE01000D0], -1302),  # > T34.11.1a + override         : wrong text after inst.
            ('ldrsbt', [4, 0xE01000D0], -3404),  # > T34.10.1 > T34.9.2           : wrong memory transfer inst.
            ('ldsb', [4, 0xE01000D0], -3403),  # > T34.8.2 > T34.9.0            : missing space after inst.
            ('ldsh ', [4, 0xE01000F0], -3405),  # > T34.8.2 > T34.9.1 > T34.11.0 : missing destination reg
            ('ldsu ', [4, 0xE0000000], -3404),  # T34.0.2 > T34.1.2 > T34.8.3    : wrong memory transfer inst.
            ('strneh', [4, 0x100000B0], -3403),  # > T34.2.3 > T34.4.3 > T34.9.0  : missing space after inst.
            ('ldscc', [4, 0x30000000], -3404),  # > T34.1.2 > T34.8.1 > T34.10.0 : wrong memory transfer inst.
            ('ldreqs', [4, 0x00000000], -3404),  # > T34.2.3 > T34.4.4 > T34.10.0 : wrong memory transfer inst.
            ('ldrlssb', [4, 0x901000D0], -3403),  # > T34.4.4 > T34.10.1 > T34.9.0 : missing space after inst.
            ('ldshsb r2', [4, 0x201000D0], -3406),  # > T34.9.1 > T34.11.1a error: missing ',' after destination reg
            ('ldrhsh r2,', [4, 0x201020B0], -3407),  # > T34.11.1b > T34.12.0     : missing info after dest. reg
            ('strleh r10, r12', [4, 0xD000A0B0], -2502),  # T34.11.1b > T34.12.1 + override   : missing '['
            ('strlsh r10, [12', [4, 0x9000A0B0], -2503),  # T34.11.1b > T34.12.1 + override   : missing reg after '['
            ('strloh r8, [r12', [4, 0x300080B0], -2504),  # T34.11.1b > T34.12.1 + override   : missing closure
            ('streqh r9, [r1,', [4, 0x000090B0], -2505),  # T34.11.1b > T34.12.1 + override   : missing displacement
            ('ldsccb r1,[r2]!', [4, 0x301010D0], -2510),  # T34.11.1b > T34.12.1 + override: unexpected text after ']'
            ('strh r2, [r3, 3', [4, 0xE00020B0], -2506),  # + override : wrong displacement
            ('ldsvch r4, [r5, r1a', [4, 0x701040F0], -1304),  # + override : wrong reg number
            ('ldrvssb r5, [r7, -r6', [4, 0x601050D0], -2504),  # + override : check negative reg displ.
            ('strplh r9, [r5, r10, ', [4, 0x500090B0], -2513),  # + override : scaled reg. displ. not allowed
            ('ldsmib r10, [r9, #0x134]', [4, 0x4010A0D0], -2511),  # + override : too long immediate displacement
            ('ldrgtsb r11 , [ r6, #+0]', [4, 0xC1D6B0D0], 1000),  # > T34.11.1b > T34.12.1 success: base + imm. displ.
            ('strh r12, [r6 ,#195]', [4, 0xE1C6CCB3], 1000),  # : base + imm. displ.
            ('ldrlsh r3, [r10, #-180]', [4, 0x915A3BB4], 1000),  # : base + negative imm. displ.
            ('ldsgeh r13, [r8, # -80]', [4, 0xA158D5F0], 1000),  # : base + negative imm. displ.
            ('ldshsb r14,[r9, #-255 ]', [4, 0x2159EFDF], 1000),  # : minimum negative imm. displ.
            ('strhih pc, [r10]', [4, 0x81CAF0B0], 1000),  # : success base only
            (' ldrgtsh lr, [ pc ]', [4, 0xC1DFE0F0], 1000),  # : idem with trailing space
            ('ldsvsb r10,[r9,r1]', [4, 0x6199A0D1], 1000),  # : success base + reg. displacement
            ('ldrlssh r0, [ sp , lr ]', [4, 0x919D00FE], 1000),  # : idem with extra spaces
            ('strleh r1, [r6, -r7]', [4, 0xD10610B7], 1000),  # : check negative reg displ.
            ('ldsb r9, [r5, r15]', [4, 0xE01090D0], -2512)  # + override : PC not allowed as Rm
            ]

imm_test = [('ldm', [4, 0xE0000000], -3404),  # T34.0.2 > T34.1.3 > T34.13.0  error: wrong memory transfer inst.
            ('stmz', [4, 0xE0000000], -3404),  # T34.0.2 > T34.1.3 > T34.13.3  error: wrong memory transfer inst.
            ('ldmia', [4, 0xE8900000], -3403),  # > T34.13.2 > T34.15.0          : missing space after inst.
            ('stmdb ', [4, 0xE9000000], -3405),  # > T34.15.1 > T34.16.0          : missing destination reg
            ('ldmibe', [4, 0xE9900000], -3404),  # > T34.13.2 > T34.15.2          : wrong memory transfer inst.
            ('ldmib e', [4, 0xE9900000], -1302),  # > T34.16.1a + override         : wrong register
            ('stmne', [4, 0x10000000], -3404),  # > T34.13.1 > T34.14.0          : wrong memory transfer inst.
            ('ldmccda', [4, 0x38100000], -3403),  # > T34.14.1 > T34.15.0          : missing space after inst.
            ('ldmccde', [4, 0x30000000], -3404),  # > T34.14.2                error: missing space after inst.
            ('ldmeqia r', [4, 0x08900000], -1303),  # > T34.16.1a + override     : missing reg number
            ('ldmhsfd r2', [4, 0x28900000], -3406),  # > T34.16.1a           error: missing ',' after destination reg
            ('ldmhsfa r2,', [4, 0x28120000], -3407),  # > T34.16.1b > T34.18.0     : missing info after dest. reg
            ('stmhiea r2!', [4, 0x89020000], -3406),  # > T34.16.1c > T34.17.0     : missing ',' after destination reg
            ('stmhiea r2!,', [4, 0x89220000], -3407),  # > T34.17.2 > T34.18.0      : missing info after dest. reg
            ('stmea r2!d', [4, 0xE9020000], -3404),  # > T34.17.3            error: wrong text after '!'
            ('stmccib r3,1', [4, 0x39830000], -1502),  # > T34.18.1 + override      : missing '{'
            ('ldmmied r4!, {', [4, 0x49B40000], -1503),  # + override  : missing registers
            ('ldmplia r5, {1', [4, 0x58950000], -1302),  # + override  : unknown register identifier
            ('stmneda r6! , {r', [4, 0x18260000], -1303),  # > T34.17.1 + override  : missing register number
            ('stmia r7,{ra', [4, 0xE8870000], -1304),  # + override  : wrong reg number
            ('ldmfd r8, {r0', [4, 0xE8980000], -1503),  # + override  : unclosed single register
            ('stmed r9, {r14,}', [4, 0xE9890000], -1504),  # + override  : missing register after ','
            ('ldmfd r13!, {r4-}', [4, 0xE8BD0000], -1403),  # + override  : missing second reg in range list
            ('ldmfd r13!, {r14, }', [4, 0xE8BD0000], -1504),  # + override  : missing register after ', '
            ('ldmeqda r10!, {r0}', [4, 0x083A0001], 1000),  # > T34.18.1  success: single register
            ('ldmalib r11 , {r0-r5}', [4, 0xE99B003F], 1000),  # : single range
            ('stmccdb r12!, {pc, r1-r2, sp-r12, r5}', [4, 0x392CB026], 1000),  # : several ranges, with spaces
            ('stmea r13!, {r14,r8}', [4, 0xE92D4100], 1000),  # : no space after ','
            ('ldmfd r13!, { r9 , r13 }', [4, 0xE8BD2200], 1000)  # : extra spaces
            ]

iil_test = [('str r0, =', [4, 0xE4000000], -3409),  # > T34.6.2 + override       : 'str' cannot use '=' loading
            ('ldrb r0,=', [4, 0xE4500000], -3409),  # > T34.6.2 + override       : neither 'ldrb'
            ('ldrh r0,=', [4, 0xE01000B0], -2502),  # > T34.12.1 + override error: nor 'ldrh'
            ('ldr r0, =', [4, 0xE4100000], -3410),  # > T34.6.2 > T34.7.0   error: missing number for immediate load
            ('ldr r0, = ', [4, 0xE4100000], -3410),  # > T34.7.1 > T34.7.0        : idem with tranling space
            ('ldr r0, =t', [4, 0xE4100000], -3410),  # > T34.7.1 > T34.7.3        : idem with tranling rubbish
            ('ldr r1, =0b00130', [4, 0xE4101000], -1002),  # > T34.7.2 + override: invalid binary digit
            ('ldr r2, =00180', [4, 0xE4102000], -1003),  # + override: invalid octal digit
            ('ldr r3, = -18a', [4, 0xE4103000], -1004),  # + override: invalid decimal digit
            ('ldr r4, =0x10GA', [4, 0xE4104000], -1005),  # + override: invalid hexa digit
            ('ldr r5, =0x100000000', [4, 0xE4105000], -1006),  # + override: too big number
            ('ldr r6, =+0', [4, 0xE59F6FF8, 0], 1000),  # > T34.7.2       success: set a relative pc loading
            ('ldrhi r7, = 00317652', [4, 0x859F7FF8, 0x19FAA], 1000),  # : octal number
            ('ldrlt lr, =-1000', [4, 0xB59FEFF8, -1000], 1000),  # : negative number
            ('ldr pc, = 0x8000', [4, 0xE59FFFF8, 0x8000], 1000)  # : hexa number (load PC)
            ]

imi_test = [('', [], -3501),  # T35.0.0              error: missing miscellanea instruction
            (' ', [], -3501),  # T35.0.1 > T35.0.0         : idem with space
            ('ldr', [], -3503),  # T35.0.4              error: unrecognizable instruction
            ('push', [], -3502),  # T35.0.2a             error: missing operands
            (' clz', [], -3502),  # T35.0.1 > T35.0.3a   error: idem with leading space
            ('pop ', [4, 0xE8BD0000], -3502),  # > T35.0.2b > T35.2.0      : idem with a trailing space
            ('clz ', [4, 0xE1600010], -3502),  # > T35.0.3b > T35.4.0      : idem for 'clz'
            ('clz 2', [4, 0xE1600010], -1302),  # > T35.4.1a + override     : unrecognizable register
            ('clz r', [4, 0xE1600010], -1303),  # > T35.4.1a + override     : missing register number
            ('clz r16', [4, 0xE1600010], -1304),  # > T35.4.1a + override     : too high reg number
            ('push 1', [4, 0xE92D0000], -1502),  # > T35.2.1 + override      : missing '{'
            ('pop {', [4, 0xE8BD0000], -1503),  # + override    : missing registers
            ('pushne {1', [4, 0x192D0000], -1302),  # + override    : unknown register identifier
            ('pophs {r', [4, 0x28BD0000], -1303),  # + override    : missing register number
            ('pushhi  {ra', [4, 0x892D0000], -1304),  # + override    : wrong reg number
            ('poplo {r0', [4, 0x38BD0000], -1503),  # + override    : unclosed single register
            ('pushge  {r14,}', [4, 0xA92D0000], -1504),  # + override    : missing register after ','
            ('popcc {r4-}', [4, 0x38BD0000], -1403),  # + override    : missing second reg in range list
            ('pushvs {r14, }', [4, 0x692D0000], -1504),  # + override    : missing register after ', '
            ('pusheq', [4, 0xE92D0000], -3502),  # T35.0.2c > T35.1.1a  error: missing operands
            ('popcce', [4, 0x38BD0000], -3504),  # T35.0.2c > T35.1.1c  error: wrong text after inst.
            ('popce', [4, 0xE8BD0000], -3504),  # T35.0.2c > T35.1.2   error: wrong text after inst.
            ('pushle ', [4, 0xD92D0000], -3502),  # > T35.1.1b > T35.2.0 error: missing operands
            ('clzh', [4, 0xE1600010], -3504),  # T35.0.3c > T35.3.2   error: wrong text after inst.
            ('clzhi', [4, 0xE1600010], -3502),  # T35.0.3c > T35.3.1a  error: missing operands
            ('clzhi ', [4, 0x81600010], -3502),  # > T35.3.1b > T35.4.0   err: missing operands
            ('clzhii', [4, 0x81600010], -3504),  # T35.0.3c > T35.3.1c  error: wrong text after inst.
            ('clzhs r15,', [4, 0x2160F010], -3502),  # > T35.4.1b > T35.5.0  : missing operands
            ('clzhs r15 z,', [4, 0x21600010], -1304),  # > T35.4.1a + override : wrong reg
            ('clzhs r15, ', [4, 0x2160F010], -3505),  # > T35.4.1c > T35.5.2  : wrong info after Rd
            ('clzls r15,r6', [4, 0x9160F016], 1000),  # > T35.4.1b > T35.5.1  : success 'clz' + cond
            ('pushls {r14}', [4, 0x992D4000], 1000),  # > T35.1.1b > T35.2.1  : success 'push' + cond
            ('pop {r0, r4-r10, r14}', [4, 0xE8BD47F1], 1000)  # > T35.2.1     : success 'pop'
            ]

data_arm = [('', [], -4001),  # T40.0.0                  error: missing initial hex address
            ('2', [], -4002),  # T40.0.4                  error: wrong initial address
            ('>', [], -4003),  # T40.0.2a                 error: missing space after '>'
            ('>a', [], -4003),  # T40.0.2c                 error: unexpected char after '>'
            (' ', [], -4001),  # T40.0.1 > T40.0.0        error: white leading space
            ('0x', [], -2002),  # T40.0.3 + override            : leading '0x', missing hex digits
            ('  0x8001', [], -2003),  # T40.0.1 > T40.0.3 + override  : missing space after address
            (' 0x8001 ', [0x8001], -4004),  # T40.0.1 > T40.0.3 > T40.1.0   error: right address, missing info
            ('0x10002EF00 .byte 2', [], -2004),  # T40.0.3 + override            : long hex address (> 2^32)
            ('0x8000.f', [], -2003),  # T40.0.3 + override            : missing space after address
            ('0x8000 .f', [0x8000], -2104),  # T40.0.3 > T40.1.1 + override  : unknown data dir
            ('0x8024 .byte', [0x8024], -2102),  # T40.0.3 > T40.1.1 + override  : address & directive, missing val
            ('0x8000 .byte ', [0x8000], -2102),  # T40.0.3 > T40.1.1 + override  : missing data values
            ('0x8000 .byte2', [0x8000], -2103),  # T40.0.3 > T40.1.1 + override  : missing space after directive
            ('0x8024 .byte 23', [0x8024, [1, 23]], 1000),  # T40.0.3 > T40.1.1     success: capture one byte
            ('> ', [0x8025], -4004),  # T40.0.2b > T40.2.0       error: missing info after '>'
            ('> .byte 2', [0x8025, [1, 2]], 1000),  # T40.0.2b > T40.2.1     success: .byte directive after '>'
            ('> .byte 3', [0x8026, [1, 3]], 1000),  # T40.0.2b > T40.2.1     success: '>' after '>'
            ('>  .byte 230', [0x8027, [1, 230]], 1000),  # T40.0.2b > T40.2.1    success : '>' after .byte (1 value)
            ('0x802F .byte 23, 0xCB', [0x802F, [1, 23, 0xCB]], 1000),  # T40.0.3 > T40.1.1 success: capture two bytes
            ('0x802F .byte \'e\' c', [0x802F], -2105),  # T40.0.3 > T40.1.1 + override  : wrong delimiter
            ('0x802F .byte \'e\', c', [0x802F], -2106),  # T40.0.3 > T40.1.1 + override  : unrecognizeable info
            ('0x802F .byte 2000', [0x802F], -2107),  # T40.0.3 > T40.1.1 + override : data >= 2**8
            ('0x901B .hword 2300, 0xCB0', [0x901B, [2, 2300, 0xCB0]], 1000),  # T40.0.2b > T40.1.1 / misaligned h
            (' > .hword 230', [0x9020, [2, 230]], 1000),  # T40.0.2b > T40.2.1          '>' after .hword (2 values)
            ('0x901A .hword 2300, 0xCB0', [0x901A, [2, 2300, 0xCB0]], 1000),  # T40.0.3 > T40.1.1   / aligned h
            (' >  .hword 320', [0x901E, [2, 320]], 1000),  # T40.0.2b > T40.2.1          '>' after .hword (h aligned)
            ('0xCbf8 .word 230000, 0xCB000', [0xCBF8, [4, 230000, 0xCB000]], 1000),  # T40.0.3 > T40.1.1 / aligned w
            ('0xCbf9 .word 230000, 0xCB000', [0xCBF9, [4, 230000, 0xCB000]], 1000),  # / misaligned w (1)
            ('0xCbfa .word 230000, 0xCB000', [0xCBFA, [4, 230000, 0xCB000]], 1000),  # / misaligned w (2)
            ('0xCbfb .word 230000, 0xCB000', [0xCBFB, [4, 230000, 0xCB000]], 1000),  # / misaligned w (3)
            ('> .word 010', [0xCC04, [4, 8]], 1000),  # T40.0.2b > T40.2.1          '>' after .word (2 values)
            ('0xa03c .ascii \'2\'', [0xA03C, [1, 50]], 1000),  # T40.0.3 > T40.1.1  success: .ascii directive
            ('> .word 0x010', [0xA040, [4, 16]], 1000),  # T40.0.2b > T40.2.1          '>' after .ascii (1 value)
            ('0xa03b .asciz \'2\', \"0xCB\"', [0xA03B, [1, 50, 0, 48, 120, 67, 66, 0]], 1000),  # / two strings
            ('> .word 0b010', [0xA044, [4, 2]], 1000),  # T40.0.2b > T40.2.1          '>' after .asciz (7 values)
            ('0xa03c .ascii \' ', [0xA03C], -1104),  # T40.0.3 > T40.1.1 + override  : unclosed char
            ('0xa03c .ascii \" ', [0xA03C], -1204),  # : unclosed string
            ('0xa03c .asciz \' ', [0xA03C], -1104),  # : unclosed char
            ('0xa03c .asciz \" ', [0xA03C], -1204),  # : unclosed string
            ('0xa03c .ascii \'\'', [0xA03C], -1102),  # : empty char
            ('0xa03c .ascii \"\"', [0xA03C], -1202),  # : empty string
            ('0xa03c .asciz \'\'', [0xA03C], -1102),  # : empty char
            ('0xa03c .asciz \"\"', [0xA03C], -1202),  # : empty string
            ('0xc30a .ascii \'\t\'', [0xC30A], -1103),  # : illegal character ''
            ('0xc30a .asciz \'\t\'', [0xC30A], -1103),  # : idem after .ascii
            ('0xc30a .ascii \"\t\"', [0xC30A], -1203),  # : illegal character ""
            ('0xc30a .asciz \" \t\"', [0xC30A], -1203),  # : idem after valid char
            ('0x3000 .ascii \' t\'', [0x3000], -1105),  # : more than one character
            ('0x3000 .asciz \' t\'', [0x3000], -1105),  # : idem after .ascii
            ('0x1000 .byte 0b012', [0x1000], -1002),  # : unexpected binary digit
            ('0x2000 .hword 0408', [0x2000], -1003),  # : unexpected octal digit
            ('0x2000 .hword 4oo8', [0x2000], -1004),  # : unexpected decimal digit
            ('0x2000 .hword 408000', [0x2000], -2107),  # : out of range dec. number
            ('0x2000 .hword -48000', [0x2000], -2107),  # : out of range neg. number
            ('0x4000 .word 0x40x', [0x4000], -1005),  # : unexpected hexa digit
            ('0x4000 .word 0x400000000', [0x4000], -1006),  # : too long num. (>2^32 bits)
            ('0x4000 .word 0x4, 0x', [0x4000], -1005),  # : unexpected hexa digit
            ('0xfffffffc .ascii \'0\'', [0xFFFFFFFC, [1, 48]], 1000),  # almost in the address space limit
            ('> .word 0b1', [0x100000000, [4, 1]], -4006),  # T40.0.2b > T40.2.1            '>' after .asciz (7 values)
            ]

idat_arm = [('0x8000 2', [0x8000], -4005),  # T40.0.3 > T40.1.7        error: unrecognizable instruction
            ('0x8004 and', [0x8004], -3102),  # T40.0.3 > T40.1.2 + override  : missing operands after instr.
            ('0x8008 eor ', [0x8008], -3102),  # T40.0.3 > T40.1.2 + override  : missing operands after instr.
            ('0x800C sub 20,', [0x800C], -1302),  # : unrecognizable operand with ','
            ('0x8010 rsb r', [0x8010], -1303),  # : missing register number
            ('0x8014 add r65', [0x8014], -1304),  # : too high reg number
            ('0x8018 adc r12', [0x8018], -2302),  # : good dest reg, missing other ops
            ('0x801C sbc  ', [0x801C], -2303),  # : missing dest reg
            ('0x8020 rsc  r1,', [0x8020], -2304),  # : missing source operands
            ('0x8024 orr r2, ', [0x8024], -2306),  # : missing source operands
            ('0x8028 bic r3, gu', [0x8028], -2306),  # : wrong source op 1
            ('0x802C and r12, r3, e3', [0x802C], -2308),  # : wrong op 2
            ('0x8030 eor r3, #', [0x8030], -1603),  # : missing value after '#'
            ('0x8034 sub r4, # ', [0x8034], -1604),  # : unexpected space after '#'
            ('0x8038 rsb r5, #f', [0x8038], -1605),  # : unrecognizable info after '#'
            ('0x803C add r10, #0x1002', [0x803C], -1606),  # : impossible fixup for odd rotations
            ('0x8040 adc r11, #\'c\' 5', [0x8040], -1607),  # : unexpected text after imm val.
            ('0x8044 sbc r10, r1,', [0x8044], -2204),  # : missing shift register
            ('0x8048 rsc r7, r2, lsl', [0x8048], -2205),  # : missing space after shift mode
            ('0x804C orr r9, r4, asr x', [0x804C], -2207),  # : wrong info after shift mode
            ('0x8050 bic r0, r8, ror #', [0x8050], -1703),  # : missing value after '#'
            ('0x8054 and r1, r9, lsl # ', [0x8054], -1704),  # : unexpected space after '#'
            ('0x8058 eor r2, r10, lsr #f3', [0x8058], -1705),  # : unrecognizable info after '#'
            ('0x805C sub r4, r12, ror #-2', [0x805C], -1706),  # : negative number of shifts
            ('0x8060 orrs', [0x8060], -3102),  # : missing data instruction operands
            ('0x8064 teqslo', [0x8064], -3105),  # : wrong text after instruction
            ('0x8068 cmnlyy', [0x8068], -3104),  # : unknown instruction condition
            ('0x8068 cmnls r0, #90', [0x8068, [4, 0x9370005A]], 1000),  # T40.0.3 > T40.1.2  success: 1 reg, 1 imm.
            ('> rsbals r6, r11, #256', [0x806C, [4, 0xE27B6C01]], 1000),  # T40.0.2b > T40.2.2 success: 2 regs, 1 imm.
            ('> addgt r12, r12, lsl r12', [0x8070, [4, 0xC08CCC1C]], 1000),  # T40.0.2b > T40.2.2 : LSL reg
            ('0x8080 adcs r1, r2, lsr r0 ', [0x8080, [4, 0xE0B11032]], 1000),  # T40.0.3 > T40.1.2  : LSR reg with space
            ('> rscles pc, lr, lsr #0x1F ', [0x8084, [4, 0xD0FFFFAE]], 1000),  # 40.0.2b > T40.2.2  : LSR imm with space
            ('0x8088 bicmis r10, r11, r12, lsl r12', [0x8088, [4, 0x41DBAC1C]], 1000),  # : three regs, shift reg
            ('0x8088 bicmis r0, r1, r2, lsl #0', [0x8088, [4, 0x41D10002]], 1000),  # : three regs, LSL #0
            ('0x8088 bicmis r0, r1, r2, ror #0', [0x8088, [4, 0x41D10062]], 1000),  # : three regs, ROR #0 -> RRX
            ('> tst r7,r1, #01010', [0x808C], -2310),  # > T40.2.2 + override  : 3 ops with 'tst'
            ('> movvc r1,r9, #0xC000', [0x808C], -2311),  # > T40.2.2 + override  : 3 ops with 'mov'
            ('> tst r7, #01010', [0x808C, [4, 0xE3170F82]], 1000),  # T40.0.2b > T40.2.2    : 'tst' + reg + imm
            ('> teqlts r7,r8,lsl #12', [0x8090, [4, 0xB1370608]], 1000),  # T40.0.2b > T40.2.2 : 'teq'+reg+shifted reg
            ('> mov r2, #-100', [0x8094, [4, 0xE3E02063]], 1000),  # T40.0.2b > T40.2.2 : 'mov' + reg + NOT imm
            ('> and r4, #-250', [0x8098, [4, 0xE3C440F9]], 1000),  # T40.0.2b > T40.2.2 : 'and' + reg + NOT imm
            ('> add r6, #-3120', [0x809C, [4, 0xE2466EC3]], 1000),  # T40.0.2b > T40.2.2 : 'add' + reg + NOT imm
            ('0xA0008 cmp r8, #-1004', [0xA0008, [4, 0xE3780FFB]], 1000),  # T40.0.3 > T40.1.2  : 'cmp' + reg + NOT imm
            ('> .byte -1', [0xA000C, [1, 255]], 1000),  # T40.0.2b > T40.2.1 : automatic inc. +1
            ('> bics r5, #-255', [0xA0010, [4, 0xE21550FE]], 1000),  # T40.0.2b > T40.2.2 : adjust adr. 3 bytes
            ('> .hword -2', [0xA0014, [2, 65534]], 1000),  # T40.0.2b > T40.2.1 : automatic inc. +2
            ('>   movvss r9,#0xC0000', [0xA0018, [4, 0x63B09703]], 1000),  # T40.0.2b > T40.2.2 : adjust adr. 2 bytes
            (' >  .byte -1, -2, -3', [0xA001C, [1, 255, 254, 253]], 1000),  # T40.0.2b > T40.2.1 : automatic inc. +3
            (' > cmnne r5, #-256', [0xA0020, [4, 0x13550C01]], 1000),  # T40.0.2b > T40.2.2 : adjust adr. 1 byte
            ('> r5, #-256', [0xA0024], -4005),  # T40.0.2b > T40.2.7 : unrecognized inst.
            ('0xA0025   cmp r9, #1004', [0xA0025, [4, 0xE3590FFB]], 1000),  # warning : address missaligned 1 byte
            ('0xA0026  cmp r10, #1008', [0xA0026, [4, 0xE35A0E3F]], 1000),  # warning : address missaligned 1 byte
            (' 0xA0027 cmp r11, #1012', [0xA0027, [4, 0xE35B0FFD]], 1000),  # warning : address missaligned 1 byte
            ('0x8068 .word -4', [0x8068, [4, 4294967292]], 1000)  # final test: set auto-address as before the first
            #        test in this series that makes use of '>'
            ]

imul_arm = [('0x7FFC .word -4', [0x7FFC, [4, 4294967292]], 1000),  # set auto-address as before the first use of '>'
            ('>  ', [0x8000], -4005),  # T40.0.2b > T40.1.7        error: unrecognizable instruction
            ('> 2', [0x8000], -4005),  # T40.0.2b > T40.1.7        error: unrecognizable instruction
            ('> mul', [0x8000], -3202),  # T40.0.2b > T40.2.3 + override  : missing operands after instr.
            ('> mla ', [0x8000], -3202),  # T40.0.2b > T40.2.3 + override  : missing operands after instr.
            ('> umull 2', [0x8000], -1302),  # : wrong register
            ('> umull 2,', [0x8000], -1302),  # : wrong register with ','
            ('> umull r', [0x8000], -1303),  # : missing register number
            ('> smull r65', [0x8000], -1304),  # : too high reg number
            ('> umlal r12', [0x8000], -3202),  # : missing other regs
            ('> mul  ', [0x8000], -1301),  # : missing other regs
            ('0x90FC mul  r1,', [0x90FC], -3202),  # : missing source operands
            ('> mla r2, ', [0x8000], -1301),  # : missing source operands
            ('> smlal r3, gu', [0x8000], -1302),  # : wrong reg2
            ('> umlal r12, r3, e3', [0x8000], -1302),  # : wrong reg3
            ('> mul r3, r4, r5, r6', [0x8000], -3207),  # : four registers with 'mul'
            ('> smlal r3, r4, r5, ', [0x8000], -1301),  # : missing reg4
            ('> mla r3, r4, r5', [0x8000], -3202),  # : three regs with 'mla'
            ('> mul r1, r10, r8', [0x8000, [4, 0xE001089A]], 1000),  # success: three regs with 'mul'
            ('0xA000 mla r13, r14, r0, r0', [0xA000, [4, 0xE02D009E]], 1000),  # success: four regs with 'mla'
            ('> umull sp, lr, r12, r13', [0xA004, [4, 0xE08EDD9C]], 1000),  # success: four regs with 'umull'
            ('> mul r10, pc, r7', [0xA008], -3208),  # + override: use of PC as Rm
            ('> smulllex r10, r11, lr, r10', [0xA008], -3205),  # + override: error after cond
            ('> mulz', [0xA008], -3204)  # + override: wrong text after
            ]

ijmp_arm = [('0x7FFC .word -4', [0x7FFC, [4, 4294967292]], 1000),  # set auto-address as before the first use of '>'
            ('> blo', [0x8000], -3302),  # T40.0.2b > T40.2.4 + override: missing offset
            ('0x9004 bleq ', [0x9004], -3302),  # T40.0.3 > T40.1.4 + override : missing offset
            ('> blox', [0x8000], -4005),  # T40.0.2b > T40.2.4 + override: unexpected text after inst
            ('0xA0000  bx', [0xA0000], -3304),  # T40.0.3 > T40.1.4 + override : missing reg after instr.
            ('> blxo', [0x8000], -4005),  # T40.0.2b > T40.2.4 + override: unexpected text after inst
            ('0x10 blt f', [0x10], -3305),  # T40.0.3 > T40.1.4 + override : wrong offset
            ('> bls 0b12', [0x8000], -1002),  # T40.0.3 > T40.1.4 + override : unexpected binary digit
            ('> blls 0192', [0x8000], -1003),  # : unexpected octal digit
            ('> bllo -192a', [0x8000], -1004),  # : unexpected decimal digit
            ('> blvc 0xA3G0', [0x8000], -1005),  # : unexpected hexa digit
            ('> bvc 0xA30000000', [0x8000], -1006),  # : too long hex address
            ('> bxvc 0xA300', [0x8000], -1302),  # : unrecognized reg
            ('> blxcc r', [0x8000], -1303),  # : missing reg number
            ('> bxcc rf', [0x8000], -1304),  # : wrong reg number
            ('> bxmi r16', [0x8000], -1304),  # : wrong reg number
            ('> blgt 0x1302', [0x8000], -3307),  # : misaligned address
            ('> bllt 0x73000000', [0x8000], -3308),  # : out of range offset
            ('> blal -73000000', [0x8000], -3308),  # : out of range neg. offset
            ('> bal -7300001', [0x8000], -3307),  # : misaligned negative address
            ('>  bx  r6 ', [0x8000, [4, 0xE12FFF16]], 1000),  # T40.0.2b > T40.2.4  success: 'bx' jump
            ('> blxpl r6', [0x8004, [4, 0x512FFF36]], 1000),  # : 'blx' jump
            ('0x7A0C  blxlt r15', [0x7A0C, [4, 0xB12FFF3F]], 1000),  # > T40.1.4 warning: use of pc (r15)
            ('> b 0xA300', [0x7A10, [4, 0xEA000A3A]], 1000),  # > T40.2.4 success: 'b' jump
            ('0xFFF8 bl 1300', [0xFFF8, [4, 0xEBFFC145]], 1000),  # > T40.1.4 success: 'bl' negative jump
            ('> blt 073000000', [0xFFFC, [4, 0xBA3ABFFF]], 1000),  # > T40.2.4 success: 'blt' octal jump
            ('> bleq 0x730000', [0x10000, [4, 0x0B1C7FFE]], 1000),  # > T40.2.4 success: 'bleq' hexa jump
            ('0x7FF8 bhi 0xA30000', [0x7FF8, [4, 0x8A28A000]], 1000),  # > T40.1.4 success: 'bhi' jump
            ('> bge 0x2008000', [0x7FFC, [4, 0xAA7FFFFF]], 1000),  # : forward jump limit
            ('0x2000000 blhs 0x8', [0x2000000, [4, 0x2B800000]], 1000),  # : backward jump limit
            ('0x400000 blhs 0xC', [0x400000, [4, 0x2BF00001]], 1000),  # : another backward jump
            ('0x4000 blhi 0x4000', [0x4000, [4, 0x8BFFFFFE]], 1000),  # : jump onto same address
            ('0x4000 blhi 0x4008', [0x4000, [4, 0x8B000000]], 1000),  # : jump onto advanced pc
            ('0x4001 blhi 0x4008', [0x4001, [4, 0x8BFFFFFF]], 1000)  # : jump from misaligned adr.
            ]

imem_arm = [('0x7FFC .word -4', [0x7FFC, [4, 4294967292]], 1000),  # set auto-address as before the first use of '>'
            ('> ld', [0x8000], -4005),  # T40.0.2b > T40.2.5 + override: missing inst. continuation
            ('> st ', [0x8000], -4005),  # + override: missing inst. continuation
            ('> str', [0x8000], -3403),  # + override: missing space after inst.
            ('> ldr ', [0x8000], -3405),  # + override: missing destination register
            ('> sts', [0x8000], -3408),  # + override: 's' not allowed for store inst.
            ('> ldx', [0x8000], -4005),  # + override: unrecognized mem. transfer inst.
            ('> ldrby', [0x8000], -3404),  # + override: wrong text after inst.
            ('> ldrb e', [0x8000], -1302),  # + override: unknown reg
            ('> str r', [0x8000], -1303),  # + override: missing reg number
            ('> ldr rb', [0x8000], -1304),  # + override: wrong reg number
            ('> ldrb r1', [0x8000], -3406),  # + override: missing ',' after dest. reg
            ('> strb r2,', [0x8000], -3407),  # + override: missing info after dest. reg
            ('> ldrhsb r2, 2', [0x8000], -2402),  # + override: missing '['
            ('> strvcb r3, [', [0x8000], -2403),  # + override: missing info after '['
            ('> ldrge r4, [2', [0x8000], -2403),  # + override: unrecognizable register
            ('> strltb r5,[r', [0x8000], -1303),  # + override: missing register number
            ('> ldrvc r6, [r16', [0x8000], -1304),  # + override: too high reg number
            ('> ldr lr, [r12', [0x8000], -2404),  # + override: good base reg, missing closure
            ('> ldrb r15, [r1,', [0x8000], -2405),  # + override: missing displacement
            ('> strb pc, [r2]!', [0x8000], -2410),  # + override: unexpected text after ']'
            ('> ldrvsb r4,[r3, 3', [0x8000], -2406),  # + override: wrong displacement
            ('> ldrltb r6, [r5, r10, ', [0x8000], -2407),  # + override: missing shift mode
            ('> strlsb r7, [r7, r2, lsl', [0x8000], -2408),  # + override: missing space after shift
            ('> ldr r11, [r10, r5, ror r', [0x8000], -1702),  # + override: missing info after shift mode
            ('> ldrb r12, [r1, r9, lsl # ', [0x8000], -1704),  # + override: unexpected space after '#'
            ('> strb r13,[r9,#0xC0000034]', [0x8000], -2411),  # + override: too long immediate displacement
            ('> ldr r0, [r12, #0b1002000]', [0x8000], -1002),  # + override: invalid binary digit
            ('> strhi r1, [r13, #018000005]', [0x8000], -1003),  # + override: invalid octal digit
            ('> strlob r2, [r14, #5d4]', [0x8000], -1004),  # + override: invalid decimal digit
            ('> ldrplb r3, [r15, #0x4r]', [0x8000], -1005),  # + override: invalid hexa digit
            ('> ldrb r3, [r15, #0x400000000]', [0x8000], -1006),  # + override: too big number
            ('> ldrcsb r4, [ r6, #+0]', [0x8000, [4, 0x25D64000]], 1000),  # success: base + imm. displ.
            ('> ldr r5, [r6, #20]', [0x8004, [4, 0xE5965014]], 1000),  # success: base + imm. displ.
            ('> str r6,[r7, #+4095]', [0x8008, [4, 0xE5876FFF]], 1000),  # success: maximum positive imm. displ.
            ('> ldreqb r7, [r8, #-20]', [0x800C, [4, 0x05587014]], 1000),  # success: base + negative imm. displ.
            ('> strccb r8, [r9, #-4095] ', [0x8010, [4, 0x35498FFF]], 1000),  # : minimum negative imm. displ.
            ('> ldr r9, [r10]', [0x8014, [4, 0xE59A9000]], 1000),  # : base only
            ('> str r10,[r9,+r1]', [0x8018, [4, 0xE789A001]], 1000),  # : base + reg. displacement
            ('> str r10, [r5, r15]', [0x801C], -2412),  # + override: PC not allowed as Rm
            ('> strb r11, [r0, r8, ror #]', [0x801C], -1703),  # + override: missing value after '#'
            ('> ldrle r12, [r2, r10, lsr #f]', [0x801C], -1705),  # + override: unrecogn. info after '#'
            ('> strmib r13, [r4, r12, ror #-20]', [0x801C], -1706),  # + override: negative number of shifts
            ('> ldrplb r14, [r5, r13, lsl #040]', [0x801C], -1706),  # + override: too high number of shifts
            ('> ldrvs r15,[r6, lr, lsr #0x1C] ', [0x801C, [4, 0x6796FE2E]], 1000),  # success: with trailing space
            ('> str r0, [r5, r13, lsl #00]', [0x8020, [4, 0xE785000D]], 1000),  # success: true LSL #0
            ('0x904A ldr r1, [r6, sp, lsr #0x0 ]', [0x904A, [4, 0xE796100D]], 1000),  # : converting LSR #0 into LSL #0
            ('> str r2, [r7,-r1,asr #0b10101]', [0x9050, [4, 0xE7072AC1]], 1000),  # : ASR bin imm, no space after ','
            ('0x8090 ldr r3 ,[r7,+r1,asr #0b0]', [0x8090, [4, 0xE7973001]], 1000),  # : converting ASR #0 into LSL #0
            ('> ldrb r4,[r9, r12, ror #0x1F]', [0x8094, [4, 0xE7D94FEC]], 1000),  # : success ROR with 31 shifts
            ('> strb r5, [r9, r12, ror #0x0]', [0x8098, [4, 0xE7C9506C]], 1000),  # : coding ROR #0 as RRX
            ('> lds', [0x809C], -3404),  # + override: wrong memory transfer inst.
            ('> strz', [0x809C], -3404),  # + override: wrong memory transfer inst.
            ('> strs', [0x809C], -3408),  # + override: 's' not allowed for store inst.
            ('> ldrsb e', [0x809C], -1302),  # + override: wrong text after inst.
            ('> strleh r10, r12', [0x809C], -2502),  # + override: missing '['
            ('> strlsh r10, [12', [0x809C], -2503),  # + override: missing reg after '['
            ('> strloh r8, [r12', [0x809C], -2504),  # + override: missing closure
            ('> streqh r9, [r1,', [0x809C], -2505),  # + override: missing displacement
            ('> ldsccb r1,[r2]!', [0x809C], -2510),  # + override: unexpected text after ']'
            ('> strh r2, [r3, 3', [0x809C], -2506),  # + override: wrong displacement
            ('> strplh r9, [r5, r10, ', [0x809C], -2513),  # + override: scaled reg. displ. not allowed
            ('> ldsmib r10, [r9, #0x134]', [0x809C], -2511),  # + override: too long immediate displacement
            ('> ldsb r9, [r5, r15]', [0x809C], -2512),  # + override: PC not allowed as Rm
            ('> ldrgtsb r11 , [ r6, #+0]', [0x809C, [4, 0xC1D6B0D0]], 1000),  # success: base + imm. displ.
            ('0x20030 strh r12, [r6 ,#195]', [0x20030, [4, 0xE1C6CCB3]], 1000),  # success: base + imm. displ.
            ('0x2000  ldrlsh r3, [r10, #-180]', [0x2000, [4, 0x915A3BB4]], 1000),  # : base + negative imm. displ.
            ('> stmz', [0x2004], -3404),  # + override: wrong memory transfer inst.
            ('> ldmia', [0x2004], -3403),  # + override: missing space after inst.
            ('> stmdb ', [0x2004], -3405),  # + override: missing destination reg
            ('> ldmhsfd r2', [0x2004], -3406),  # + override: missing ',' after destination reg
            ('> ldmhsfa r2,', [0x2004], -3407),  # + override: missing info after dest. reg
            ('> stmccib r3,1', [0x2004], -1502),  # + override: missing '{'
            ('> ldmmied r4!, {', [0x2004], -1503),  # + override: missing registers
            ('> stmed r9, {r14,}', [0x2004], -1504),  # + override: missing register after ','
            ('> ldmfd r13!, {r4-}', [0x2004], -1403),  # + override: missing second reg in range list
            ('0x70FC  ldmalib r11 , {r0-r5}', [0x70FC, [4, 0xE99B003F]], 1000),  # success: single range
            ('> stmccdb r12!, {pc, r1-r2, sp-r12, r5}', [0x7100, [4, 0x392CB026]], 1000),  # : several ranges, with spcs
            ('> str r0, =', [0x7104], -3409),  # + override: 'str' cannot use '=' loading
            ('> ldrh r0,=', [0x7104], -2502),  # + override: nor 'ldrh'
            ('> ldr r0, =t', [0x7104], -3410),  # + override: idem with tranling rubbish
            ('> ldr r5, =0x100000000', [0x7104], -1006),  # + override: too big number
            ('> ldr r6, =+0', [0x8104, [4, 0], 0x7104, [4, 0xE59F6FF8]], 1000),  # success: set a relative pc loading
            ('> ldrhi r7, = 00317652', [0x8108, [4, 0x19FAA], 0x7108, [4, 0x859F7FF8]], 1000),  # : octal number
            ('0x801C ldrlt lr, =-1000', [0x901C, [4, 0xFFFFFC18], 0x801C, [4, 0xB59FEFF8]], 1000),  # : negative number
            ('> ldr pc, = 0x8000', [0x9020, [4, 0x8000], 0x8020, [4, 0xE59FFFF8]], 1000),  # : hexa num. (load PC)
            ('0x801A ldrgt lr, =0x1FF80', [0x901A, [4, 0x1FF80], 0x801A, [4, 0xC59FEFF8]], 1000),  # : explicit misalign
            ('> ldr sp , =0x80000', [0x9020, [4, 0x80000], 0x8020, [4, 0xE59FDFF8]], 1000),  # : implicit misalign
            ('0xfffffffc .ascii \'1\'', [0xFFFFFFFC, [1, 49]], 1000),  # almost in the address space limit
            ('> ldr r0, =8', [0x100001000, [4, 8], 0x100000000, [4, 0xE59F0FF8]], -4006),  # crossing addr. space limit
            ('0xffffeffc .ascii \'2\'', [0xFFFFEFFC, [1, 50]], 1000),  # almost in the address space limit
            ('> ldr r2,=-8', [0x100000000, [4, 0xFFFFFFF8], 0xFFFFF000, [4, 0xE59F2FF8]], -4006)  # crossing addr. limit
            ]

imsc_arm = [('0x7FFC .word -4', [0x7FFC, [4, 4294967292]], 1000),  # set auto-address as before the first use of '>'
            ('> push', [0x8000], -3502),  # T40.0.2b > T40.2.6 + override : missing operands
            ('0x8000 clz 2', [0x8000], -1302),  # T40.0.3 > T40.1.6 + override  : unrecognizable register
            ('> clz r', [0x8000], -1303),  # + override  : missing register number
            ('> clz r16', [0x8000], -1304),  # + override  : too high reg number
            ('> push 1', [0x8000], -1502),  # + override  : missing '{'
            ('> pop {', [0x8000], -1503),  # + override  : missing registers
            ('> pushge  {r14,}', [0x8000], -1504),  # + override  : missing register after ','
            ('> popcc {r4-}', [0x8000], -1403),  # + override  : missing second reg in range list
            ('0x9004 popcce', [0x9004], -3504),  # + override  : wrong text after inst.
            ('> clzhs r15, ', [0x8000], -3505),  # + override  : wrong info after Rd
            ('> clzls r15,r6', [0x8000, [4, 0x9160F016]], 1000),  # success : 'clz' + cond
            ('0xA00 pushls {r14}', [0xA00, [4, 0x992D4000]], 1000),  # success : 'push' + cond
            ('> pop {r0, r4-r10, r14}', [0xA04, [4, 0xE8BD47F1]], 1000)  # success : 'pop'
            ]

test_groups = [(number_analyzer, hex_test, 'hexadecimal numbers'),
               (number_analyzer, dec_test, 'decimal numbers'),
               (number_analyzer, oct_test, 'octal numbers'),
               (number_analyzer, bin_test, 'binary numbers'),
               (char_analyzer, chr_test, 'single quoted chars'),
               (string_analyzer, str_test, 'double quoted strings'),
               (data_analyzer, dat_test, 'data directives'),
               (address_analyzer, adr_test, 'hex addresses'),
               (register_analyzer, reg_test, 'register identifiers'),
               (regbit_analyzer, rbt_test, 'registers bit mask'),
               (reglst_analyzer, rlt_test, 'registers list mask'),
               (immediate_op_analyzer, imo_test, 'immediate operand'),
               (immediate_sr_analyzer, ims_test, 'immediate shift register'),
               (op2_analyzer, op2_test, 'second operand'),
               (opdat_analyzer, opd_test, 'data instruction operands'),
               (instdat_analyzer, idt_test, 'data instructions'),
               (instmul_analyzer, iml_test, 'multiplication instructions'),
               (instjmp_analyzer, ibr_test, 'branch instructions'),
               (opldst2_analyzer, am2_test, 'addressing mode 2'),
               (opldst3_analyzer, am3_test, 'addressing mode 3'),
               (instmem_analyzer, im2_test, 'memory transfer instructions, addressing mode 2'),
               (instmem_analyzer, im3_test, 'memory transfer instructions, addressing mode 3'),
               (instmem_analyzer, imm_test, 'memory transfer instructions, multiple registers'),
               (instmem_analyzer, iil_test, 'memory transfer instructions, immediate load'),
               (instmsc_analyzer, imi_test, 'miscellanea instructions'),
               (arm_analyzer, data_arm, 'arm data directives'),
               (arm_analyzer, idat_arm, 'arm data instructions'),
               (arm_analyzer, imul_arm, 'arm multiplication instructions'),
               (arm_analyzer, ijmp_arm, 'arm branch instructions'),
               (arm_analyzer, imem_arm, 'arm memory transfer instructions'),
               (arm_analyzer, imsc_arm, 'arm miscellanea instructions')
               ]

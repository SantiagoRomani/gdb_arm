from analyzer import Analyzer


class InstcondAnalyzer(Analyzer):
    """Analyzer 30: condition modifiers for instructions (eq, ne, hs, lo, etc.)"""

    # definition of basic transition entries (lists)
    ent0 = [('eq', 0x00000000), ('ne', 0x10000000), ('cs', 0x20000000), ('hs', 0x20000000),
            ('cc', 0x30000000), ('lo', 0x30000000), ('mi', 0x40000000), ('pl', 0x50000000),
            ('vs', 0x60000000), ('vc', 0x70000000), ('hi', 0x80000000), ('ls', 0x90000000),
            ('ge', 0xA0000000), ('lt', 0xB0000000), ('gt', 0xC0000000), ('le', 0xD0000000),
            ('al', 0xE0000000)]


    def __init__(self):
        Analyzer.__init__(self)
        # definition of the (instance) parsing graph
        self.graph = {0:  # initial state
                          ([(None, None, -3001, None),  # T30.0.0 EOSeq -> missing instruction condition
                            (self.ent0, None, 1000, None)], # T30.0.1 positive detection
                           -3002)                       # T30.0.2 unrecognizable condition
                      }
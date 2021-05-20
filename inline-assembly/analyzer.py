from gerrors import gerror_dict

class Analyzer:
    """Basic class for analyzing text according to a multilevel Mealy graph"""

    def error_spring(self, match, sub_result, sub_state, super_result):
        # type: (bool, list, int, list) -> (int)
        """default method for propagating one error code emitted by a sub-analyzer into the graph flow
           of the current analyzer; for activating this method, it must be specified as a transition method
           (or part of a transition method) and a specific list of errors must be included in the class
           variable 'self.error_list' of the current analyzer
        """
        override = 0                                # default override value (not override)
        if not match:                               # in case there is no match
            if sub_state in self.error_list:            # and the error code is in the list of the current analyzer
                override = sub_state                        # transmit the overriding error code
            else:                                       # if error code ends with 99 or error message starts with '___'
                if ((-sub_state % 100) == 99) or (gerror_dict[sub_state].find('___') == 0):
                    print("WARNING: unexpected error code " + str(sub_state))
        return override


    def find_delimiter(self, text, init_pos, end_pos, delimiters):
        # type: (str, int, int, str) -> (int, int)
        """returns the position within the text sequence (from init_pos up to end_pos-1)
            where the closer delimiter occurs, or end_pos if no delimiter is present;
            also returns the index of the closer delimiter inside the 'delimiters' string
            (first -> index 0, second -> index 1, etc.), or -1 if no delimiter has been found
        """
        d_pos = end_pos                             # default delimiter position (end of the sequence)
        d_index = -1                                # default index (no delimiter has been found yet)
        if delimiters is not None:                  # if there are delimiters
            i = 0
            for d_char in delimiters:                   # search every delimiter
                dp = text.find(d_char, init_pos, end_pos)
                if (dp > -1) and (dp < d_pos):              # if it finds a delimiter in a closer position
                    d_pos = dp                                  # update current position and index
                    d_index = i
                i = i + 1                                   # advance index of next delimiter
        return d_pos, d_index


    def process_transition(self, trans, text, init_pos, end_pos, super_result):
        # type: (list, str, int, int, list) -> (bool, list, int, int)
        """process the given transition according to current context"""
        match = False                               # initially assume there is no match
        sub_result = []                             # initial sub-values
        sub_state = 0
        sub_pos = init_pos
        cut_pos = end_pos                           # cutting position of subsequence, defoults current end of sequence
        d_ind = -1                                  # delimiter index, defaults no delimiter found
        t_subind = 0                                # transition subindex, defaults 0 (EOSeq)
        delim = trans[1]                            # catch current delimiters
        if delim is not None:                       # if there are delimiters, look for the closer one
            (cut_pos, d_ind) = self.find_delimiter(text, init_pos, end_pos, delim)

        if trans[0] is None:                        # if there is no condition, it must be the EOSeq transition
            match = (sub_pos == cut_pos)            # match will be true if position is at the end of sequence
        else:
            if isinstance(trans[0], str):           # if the condition is a string
                if text.find(trans[0], init_pos) == init_pos:   # if that string is at the beginning of the sequence
                    sub_pos = init_pos + len(trans[0])              # advance position
                    match = True                                    # prepare for executing transition
            elif isinstance(trans[0], list):        # if the condition is a list
                for ent_tt in trans[0]:                 # traverse all transition tuple entries
                    ets_len = len(ent_tt[0])                # get lenght of entry tuple string
                    if (ets_len <= (cut_pos - init_pos)) \
                            and (ent_tt[0] == text[init_pos:init_pos + ets_len]):   # if there is a match
                        sub_result = [ent_tt[1]]                        # get the entry tuple value (as a list)
                        sub_pos = init_pos + ets_len                    # advance position
                        match = True                                    # prepare for executing transition
                        break                                           # stop traversing
            else:                                   # else, the condition must be a subgraph
                super_result.append(self.result)
                (sub_result, sub_state, sub_pos) = trans[0].analyze(text, init_pos, cut_pos, super_result)
                super_result.pop()
                match = (sub_state == 1000)         # there is a match if the subgraph has found a valid token

            if delim is not None:                   # if there are delimitiers
                while (sub_pos < cut_pos) and (text[sub_pos] == ' '):   # skip extra spaces until end of sequence
                    sub_pos = sub_pos + 1
                if (d_ind != -1) and (text[sub_pos] == delim[d_ind]):   # if one delimiter has been detected
                    t_subind = 1 + d_ind                # set transition subindex according to delimiter index
                elif sub_pos < cut_pos:             # if no delimiter has been detected and not at end of sequence
                    t_subind = 1 + len(delim)           # set transition subindex to the last subtransition

        if match:                                   # in the case of successful matching
            sub_state = trans[2 + t_subind * 2]         # proceed with the transition (change state or set error code)
            if (d_ind != -1) and (text[sub_pos] == delim[d_ind]):   # when a delimiter has been found
                sub_pos = sub_pos + 1                                   # automatically skip it

        if trans[3 + t_subind * 2] is not None:     # whenever there is a post-processing function
            override = trans[3 + t_subind * 2](match, sub_result, sub_state, super_result)
            if override != 0:                       # if the function reports a new error,
                sub_state = override                    # update the new error value
                match = True                            # force a match for overriding the current state value

        return match, sub_result, sub_state, sub_pos


    def analyze(self, text, init_pos, end_pos, super_result):
        # type: (str, int, int, list) -> (list, int, int)
        """core engine for analyzing a text sequence"""
        self.result = []                            # initially create an empty result
        self.state = 0                              # current graph state
        pos = init_pos                              # current position of the input text
        sub_result = []                             # initial sub-values
        sub_state = 0
        sub_pos = pos
        change = False                              # initially assume there is no change
        while (self.state >= 0) and (self.state < 1000):    # while no error and not in success state
            trans_tuple = self.graph.get(self.state)            # get the transition tuple of the current state
            for trans in trans_tuple[0]:                        # traverse the list of transitions
                (change, sub_result, sub_state, sub_pos) = self.process_transition(trans, text, pos, end_pos,
                                                                                   super_result)
                if change:                              # if there has been a match or an stopping error
                    break                                   # stop traversing the list of transitions

            if change:                                  # if a transition has been executed
                self.state = sub_state                      # update current context
                if self.state >= 0:                         # for actual change states (not errors), do postprocessing
                    if sub_result != []:                        # when there are sub results,
                        self.result.extend(sub_result)              # merge them at the end of the current result list
            else:                                       # if no transition has been fulfilled
                self.state = trans_tuple[1]                 # set up the no-match error code
            pos = sub_pos                               # update position even for mismatches (pointing wrong positions)
        return self.result, self.state, pos


    def __init__(self):
        self.error_list = []
        self.graph = None
        self.result = None
        self.state = 0
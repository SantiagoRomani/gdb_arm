""" ARM assembly """
from arm_tests import test_groups


def test_group(analyzer, test_list, verbose):
    i = 1
    s = 0
    p = 0
    for test_tuple in test_list:
        (result, state, pos) = analyzer.analyze(test_tuple[0], 0, len(test_tuple[0]), [])
        success = (result == test_tuple[1]) and (state == test_tuple[2])
        if verbose:
            print "\ttest %2d:  %s\t{%s}  \t(pos/len: %d/%d)" % (i, success, test_tuple[0], pos, len(test_tuple[0]))
        if success:
            s = s + 1
            if test_tuple[2] > 0:
                p = p + 1
        elif verbose:
            if result != test_tuple[1]:
                if (len(test_tuple[1]) == 1) and (len(result) == 1):
                    print "\t\t\t\t\texpected result: [%#x] \tobtained result: [%#x]" % (test_tuple[1][0], result[0])
                elif (len(test_tuple[1]) == 2) and (len(result) == 2) and isinstance(result[1], int):
                    print "\t\t\t\t\texpected result: [%d, %#x] \tobtained result: [%d, %#x]" %\
                          (test_tuple[1][0], test_tuple[1][1], result[0], result[1])
                else:
                    print "\t\t\t\t\texpected result: " + str(test_tuple[1]) + "\tobtained result: " + str(result)
            if state != test_tuple[2]:
                print "\t\t\t\t\texpected state: %d \tobtained state: %d" % (test_tuple[2], state)
        i = i + 1
    if verbose: print()
    return p, s, i - 1


def main():
    total_tests = 0
    succeded_tests = 0
    positive_tests = 0
    for test in test_groups:
        print("\ntesting " + test[2])
        (positive, success, num_tests) = test_group(test[0], test[1], False)
        print "\tsuccess fraction: %d/%d" % (success, num_tests)
        if success < num_tests:
            test_group(test[0], test[1], True)
        total_tests += num_tests
        succeded_tests += success
        positive_tests += positive

    print "\nTotal tests = %d\nTotal succeded tests = %d\n\t> positive cases = %d\n\t> negative cases = %d"\
          % (total_tests, succeded_tests, positive_tests, (succeded_tests - positive_tests))


if __name__ == "__main__":
    main()

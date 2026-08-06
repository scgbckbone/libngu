try:
    import _ngu_random_test
except ImportError:
    print('SKIP - STM32 random core')
else:
    _ngu_random_test.run()

    for fault in (
        _ngu_random_test.zero_fault,
        _ngu_random_test.duplicate_fault,
        _ngu_random_test.history_fault,
    ):
        try:
            fault()
        except OSError:
            pass
        else:
            raise AssertionError('entropy fault accepted')

    print('PASS - STM32 random core')

from apex.local_lab_sweep import prefix_space


def test_infers_three_digit_suffix_space_from_multiple_ids():
    space = prefix_space(('300123', '300214', '300327', '300481'))
    assert len(space) == 1000
    assert space[0] == '300000'
    assert space[-1] == '300999'


def test_refuses_unbounded_or_weak_prefix_spaces():
    assert prefix_space(('123456', '223456', '323456')) == ()
    assert prefix_space(('300123', '300214')) == ()
    assert prefix_space(('3000123', '3001214', '3002327'), max_space=100) == ()

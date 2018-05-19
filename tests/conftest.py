from os import cpu_count


def pytest_generate_tests(metafunc):
    metafunc.parametrize("test_workers", [None, cpu_count()])
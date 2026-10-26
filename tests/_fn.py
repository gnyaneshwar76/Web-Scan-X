"""Helper: expose a script-style module's bare test_* functions to unittest."""
import unittest


def collect(mod):
    s = unittest.TestSuite()
    for name in sorted(dir(mod)):
        fn = getattr(mod, name)
        if name.startswith("test_") and callable(fn) and getattr(fn, "__module__", "") == mod.__name__:
            s.addTest(unittest.FunctionTestCase(fn, description=f"{mod.__name__.split('.')[-1]}.{name}"))
    return s

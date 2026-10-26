"""AI helper: fake Ollama server, bad JSON, errors, cloud redaction. Run: python tests/test_ai.py"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from webscanx import ai  # noqa: E402


def test_ai_demo():
    ai.demo()


def load_tests(loader, standard_tests, pattern):   # lets unittest/discover run the bare test_* functions
    from tests._fn import collect
    return collect(sys.modules[__name__])


if __name__ == "__main__":
    test_ai_demo()

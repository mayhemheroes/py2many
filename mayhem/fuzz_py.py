#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports(include=['py2many']):
    from pycpp.transpiler import transpile

from py2many.exceptions import AstNotImplementedError

@atheris.instrument_func
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        transpile(fdp.ConsumeRemainingString())
    except (SyntaxError, ValueError, AstNotImplementedError):
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

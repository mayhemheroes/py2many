# Atheris fuzzing utilities written by Bailey Capuano
import io
import tempfile
import atheris
import contextlib
from typing import List, Set, Dict, Tuple, Any


def _handle_type(fdp: atheris.FuzzedDataProvider, ty_queue: List[type]) -> Any:
    """
    Handles the fuzzing of a single type.
    :param fdp: FuzzedDataProvider object
    :param ty_queue: The current stack of types to be used for fuzzing
    :return: The fuzzed element
    """
    if not ty_queue:
        return None
    ty = ty_queue.pop(0)
    if ty is bytes:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 100))
    elif ty is bytearray:
        return bytearray(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 100)))
    elif ty is str:
        return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
    elif ty is float:
        return fdp.ConsumeRegularFloat()
    elif ty is bool:
        return fdp.ConsumeBool()
    elif ty is int:
        return fdp.ConsumeInt(4)
    elif ty is dict:
        return build_fuzz_dict(fdp, ty_queue)
    elif ty is list:
        return build_fuzz_list(fdp, ty_queue)
    elif ty is set:
        return build_fuzz_set(fdp, ty_queue)
    elif ty is tuple:
        return build_fuzz_tuple(fdp, ty_queue)
    else:
        return None


def build_fuzz_list(fdp: atheris.FuzzedDataProvider, ty_queue: List[type]) -> List[Any]:
    """
    Builds a list with fuzzer-defined elements.
    :param fdp: FuzzedDataProvider object
    :param ty_queue: The current stack of types to be used for fuzzing
    :return: The list
    """
    if not ty_queue:
        return []
    elem_count = fdp.ConsumeIntInRange(1, 5)
    gen_list = []

    for _ in range(elem_count):
        passed_queue = ty_queue.copy()
        elem = _handle_type(fdp, passed_queue)
        if elem is not None:
            gen_list.append(elem)
    ty_queue.pop(0)  # Pop elem type

    return gen_list


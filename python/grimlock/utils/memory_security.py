"""Memory security utilities for Grimlock crypto module.

Note: Python's memory management makes true secure erasure difficult,
but we provide best-effort clearing of sensitive data.
"""


def secure_erase(data: bytearray) -> None:
    """Securely erase sensitive data from memory (best-effort in Python).

    Note: Due to Python's memory management, we cannot guarantee complete
    erasure, but we clear the data to the best of our ability.

    Args:
        data: Bytearray to erase (must be mutable)
    """
    if isinstance(data, bytearray):
        data[:] = b"\x00" * len(data)
    elif isinstance(data, bytes):
        # For immutable bytes, we can't erase, but we try to clear references
        # The caller should use bytearray for mutable data
        pass


def secure_erase_multiple(*data: bytearray) -> None:
    """Securely erase multiple bytearrays.

    Args:
        *data: Variable number of bytearrays to erase
    """
    for d in data:
        secure_erase(d)

"""How policy buckets (read, write, execute) map to Landlock access rights.

This is the single place that decides what "read" or "write" means at the kernel level.
ADR 0004 records the reasoning; docs/policy.md shows the table to users.
"""

from __future__ import annotations

from typing import Literal

from convergence.kernel import landlock as ll
from convergence.kernel.landlock import AccessFs

Bucket = Literal["read", "write", "execute"]
BUCKETS: tuple[Bucket, ...] = ("read", "write", "execute")

_READ = AccessFs.READ_FILE | AccessFs.READ_DIR
_EXECUTE = AccessFs.EXECUTE | _READ
_MODIFY_FILE = AccessFs.WRITE_FILE | AccessFs.TRUNCATE | AccessFs.IOCTL_DEV
_MODIFY_DIR = (
    AccessFs.MAKE_REG
    | AccessFs.MAKE_DIR
    | AccessFs.MAKE_SYM
    | AccessFs.MAKE_FIFO
    | AccessFs.MAKE_SOCK
    | AccessFs.REMOVE_FILE
    | AccessFs.REMOVE_DIR
    | AccessFs.REFER
)

BUCKET_RIGHTS: dict[Bucket, AccessFs] = {
    "read": _READ,
    "write": _READ | _MODIFY_FILE | _MODIFY_DIR,
    "execute": _EXECUTE,
}

# Never granted by any bucket: creating device nodes, and pathname unix-socket connections
# (that is controlled by network.unix_sockets instead).
NEVER_GRANTED = AccessFs.MAKE_CHAR | AccessFs.MAKE_BLOCK | AccessFs.RESOLVE_UNIX


def rights_for(bucket: Bucket, *, is_directory: bool, abi: int) -> AccessFs:
    """The rights a rule grants on this kernel.

    Rights the kernel does not know are dropped (it would reject them). Rights that only make
    sense on directories are dropped for files, because the kernel rejects those too.
    """
    rights = BUCKET_RIGHTS[bucket] & ll.features_for_abi(abi).fs
    if not is_directory:
        rights &= ll.FILE_ACCESS
    return rights


def handled_rights(abi: int, *, unix_sockets: Literal["deny", "allow"]) -> AccessFs:
    """The filesystem rights the ruleset handles: everything the kernel knows.

    Handling a right with no rule granting it means that right is denied everywhere.
    ``RESOLVE_UNIX`` is only handled when unix sockets are denied.
    """
    handled = ll.features_for_abi(abi).fs
    if unix_sockets == "allow":
        handled &= ~AccessFs.RESOLVE_UNIX
    return handled


def names(rights: AccessFs) -> list[str]:
    """Right names in bit order, for display."""
    return [flag.name for flag in AccessFs if flag & rights and flag.name is not None]

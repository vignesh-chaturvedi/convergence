"""The Landlock ABI feature table and structure encodings (pure logic)."""

from __future__ import annotations

import struct

import pytest

from convergence.kernel import landlock as ll
from convergence.kernel.landlock import AccessFs, AccessNet, Permission, Scope


def test_no_rights_without_landlock() -> None:
    features = ll.features_for_abi(0)
    assert features.fs == AccessFs(0)
    assert features.net == AccessNet(0)
    assert features.scope == Scope(0)
    assert features.permissions == Permission(0)


def test_abi1_is_the_thirteen_original_filesystem_rights() -> None:
    features = ll.features_for_abi(1)
    assert int(features.fs) == (1 << 13) - 1
    assert features.net == AccessNet(0)


@pytest.mark.parametrize(
    ("abi", "fs", "net", "scope", "permissions"),
    [
        (2, AccessFs.REFER, AccessNet(0), Scope(0), Permission(0)),
        (3, AccessFs.TRUNCATE, AccessNet(0), Scope(0), Permission(0)),
        (4, AccessFs(0), AccessNet.BIND_TCP | AccessNet.CONNECT_TCP, Scope(0), Permission(0)),
        (5, AccessFs.IOCTL_DEV, AccessNet(0), Scope(0), Permission(0)),
        (6, AccessFs(0), AccessNet(0), Scope.ABSTRACT_UNIX_SOCKET | Scope.SIGNAL, Permission(0)),
        (7, AccessFs(0), AccessNet(0), Scope(0), Permission(0)),
        (8, AccessFs(0), AccessNet(0), Scope(0), Permission(0)),
        (9, AccessFs.RESOLVE_UNIX, AccessNet(0), Scope(0), Permission(0)),
        (10, AccessFs(0), AccessNet.BIND_UDP | AccessNet.CONNECT_SEND_UDP, Scope(0), Permission(0)),
        (11, AccessFs(0), AccessNet(0), Scope(0), Permission(0)),
        (
            12,
            AccessFs(0),
            AccessNet(0),
            Scope(0),
            Permission.NAMESPACE_USE | Permission.CAPABILITY_USE,
        ),
    ],
)
def test_each_abi_adds_exactly_what_the_kernel_documents(
    abi: int, fs: AccessFs, net: AccessNet, scope: Scope, permissions: Permission
) -> None:
    before = ll.features_for_abi(abi - 1)
    after = ll.features_for_abi(abi)
    assert after.fs & ~before.fs == fs
    assert after.net & ~before.net == net
    assert after.scope & ~before.scope == scope
    assert after.permissions & ~before.permissions == permissions
    # Features are cumulative: nothing is ever taken away.
    assert before.fs & after.fs == before.fs


def test_newer_abi_than_known_is_capped() -> None:
    newest = ll.features_for_abi(ll.KNOWN_MAX_ABI)
    future = ll.features_for_abi(ll.KNOWN_MAX_ABI + 5)
    assert future.abi == ll.KNOWN_MAX_ABI
    assert future == newest


def test_bits_match_the_uapi_header() -> None:
    assert AccessFs.EXECUTE == 1 << 0
    assert AccessFs.MAKE_SYM == 1 << 12
    assert AccessFs.REFER == 1 << 13
    assert AccessFs.TRUNCATE == 1 << 14
    assert AccessFs.IOCTL_DEV == 1 << 15
    assert AccessFs.RESOLVE_UNIX == 1 << 16
    assert AccessNet.CONNECT_SEND_UDP == 1 << 3
    assert Scope.SIGNAL == 1 << 1


def test_file_rights_are_the_kernel_access_file_set() -> None:
    assert ll.FILE_ACCESS == (
        AccessFs.EXECUTE
        | AccessFs.WRITE_FILE
        | AccessFs.READ_FILE
        | AccessFs.TRUNCATE
        | AccessFs.IOCTL_DEV
        | AccessFs.RESOLVE_UNIX
    )


@pytest.mark.parametrize(
    ("kwargs", "size"),
    [
        ({"fs": AccessFs.READ_FILE}, 8),
        ({"fs": AccessFs.READ_FILE, "net": AccessNet.BIND_TCP}, 16),
        ({"net": AccessNet.BIND_TCP}, 16),
        ({"scope": Scope.SIGNAL}, 24),
        ({"permissions": Permission.NAMESPACE_USE}, 56),
    ],
)
def test_ruleset_attr_is_truncated_after_the_last_used_field(
    kwargs: dict[str, int], size: int
) -> None:
    fs = AccessFs(kwargs.get("fs", 0))
    net = AccessNet(kwargs.get("net", 0))
    scope = Scope(kwargs.get("scope", 0))
    perms = Permission(kwargs.get("permissions", 0))
    encoded = ll._ruleset_attr(fs, net, scope, perms)
    assert len(encoded) == size
    fields = struct.unpack("=7Q", encoded.ljust(56, b"\0"))
    assert fields[0] == fs
    assert fields[1] == net
    assert fields[2] == scope
    assert fields[6] == perms


def test_path_beneath_attr_is_packed_to_twelve_bytes() -> None:
    assert struct.calcsize("=Qi") == 12

"""Shared test configuration.

Tests marked ``kernel`` exercise real kernel features and are never mocked. They only run
on Linux. Everything else is pure logic and runs anywhere.
"""

from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.uname().sysname == "Linux":
        return
    skip = pytest.mark.skip(reason="needs a real Linux kernel")
    for item in items:
        if "kernel" in item.keywords:
            item.add_marker(skip)

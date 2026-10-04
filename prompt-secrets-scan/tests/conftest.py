"""Shared fixtures for the prompt-secrets-scan tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from leaky_fixture import build


@pytest.fixture(scope="session")
def leaky(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The credential-filled fixture tree, generated once per session in a directory outside the repository."""
    return build(tmp_path_factory.mktemp("leaky"))

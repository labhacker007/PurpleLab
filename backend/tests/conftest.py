"""Pytest configuration for pipeline tests."""
import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "asyncio: mark test as async")

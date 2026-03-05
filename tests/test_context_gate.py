"""Tests for context resolution feature gate."""
import pytest
from unittest.mock import patch
from dbl_gateway.config import context_resolution_enabled


@patch.dict("os.environ", {}, clear=True)
def test_default_off():
    """Context resolution is OFF by default."""
    assert context_resolution_enabled() is False


@patch.dict("os.environ", {"GATEWAY_ENABLE_CONTEXT_RESOLUTION": "true"})
def test_enabled_true():
    assert context_resolution_enabled() is True


@patch.dict("os.environ", {"GATEWAY_ENABLE_CONTEXT_RESOLUTION": "1"})
def test_enabled_one():
    assert context_resolution_enabled() is True


@patch.dict("os.environ", {"GATEWAY_ENABLE_CONTEXT_RESOLUTION": "yes"})
def test_enabled_yes():
    assert context_resolution_enabled() is True


@patch.dict("os.environ", {"GATEWAY_ENABLE_CONTEXT_RESOLUTION": "TRUE"})
def test_enabled_case_insensitive():
    assert context_resolution_enabled() is True


@patch.dict("os.environ", {"GATEWAY_ENABLE_CONTEXT_RESOLUTION": "false"})
def test_disabled_false():
    assert context_resolution_enabled() is False


@patch.dict("os.environ", {"GATEWAY_ENABLE_CONTEXT_RESOLUTION": ""})
def test_disabled_empty():
    assert context_resolution_enabled() is False


@patch.dict("os.environ", {"GATEWAY_ENABLE_CONTEXT_RESOLUTION": "0"})
def test_disabled_zero():
    assert context_resolution_enabled() is False

import pytest
from unittest.mock import MagicMock, patch
from dbl_gateway.providers import openai, ollama, anthropic
from dbl_gateway.providers.errors import ProviderError
from dbl_gateway.ports.execution_port import NormalizedResponse

@patch("httpx.Client")
def test_openai_messages_payload(mock_client_cls):
    # Setup mock
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "choices": [{"message": {"content": "OK"}}]
    }
    
    # Execute
    openai.execute(
        model_id="gpt-4",
        messages=[{"role": "user", "content": "Hello"}],
        api_key="sk-test"
    )
    
    # Verify payload has 'messages' list
    args, kwargs = mock_instance.post.call_args
    payload = kwargs["json"]
    assert payload["messages"] == [{"role": "user", "content": "Hello"}]
    assert payload["model"] == "gpt-4"

@patch("httpx.Client")
def test_anthropic_messages_payload(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "content": [{"type": "text", "text": "OK"}]
    }
    
    # Execute
    anthropic.execute(
        model_id="claude-3-opus",
        messages=[
            {"role": "assistant", "content": "prev"},
            {"role": "user", "content": "Current"}
        ],
        api_key="sk-ant"
    )
    
    # Verify processing (extracts last user message as per logic)
    args, kwargs = mock_instance.post.call_args
    payload = kwargs["json"]
    # Our logic extracts last user message
    expected_content = [{"type": "text", "text": "Current"}]
    assert payload["messages"][0]["content"] == expected_content
    assert payload["model"] == "claude-3-opus"

@patch("httpx.Client")
def test_ollama_payload(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "message": {"content": "OllamaOK"}
    }
    
    ollama.execute(
        model_id="llama3",
        messages=[{"role": "user", "content": "Hi"}],
        base_url="http://host:11434"
    )
    
    args, kwargs = mock_instance.post.call_args
    assert args[0] == "http://host:11434/api/chat"
    payload = kwargs["json"]
    assert payload["model"] == "llama3"
    assert payload["messages"] == [{"role": "user", "content": "Hi"}]
    assert payload["stream"] is False


# --- NormalizedResponse return type ---

@patch("httpx.Client")
def test_openai_returns_normalized_response(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "choices": [{"message": {"content": "hello"}}]
    }
    result = openai.execute(
        model_id="gpt-4", messages=[{"role": "user", "content": "hi"}], api_key="sk-test"
    )
    assert isinstance(result, NormalizedResponse)
    assert result.text == "hello"
    assert result.tool_calls == []


@patch("httpx.Client")
def test_anthropic_returns_normalized_response(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "content": [{"type": "text", "text": "world"}]
    }
    result = anthropic.execute(
        model_id="claude-3-opus",
        messages=[{"role": "user", "content": "hi"}],
        api_key="sk-ant",
    )
    assert isinstance(result, NormalizedResponse)
    assert result.text == "world"
    assert result.tool_calls == []


@patch("httpx.Client")
def test_ollama_returns_normalized_response(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "message": {"content": "ok"}
    }
    result = ollama.execute(
        model_id="llama3",
        messages=[{"role": "user", "content": "hi"}],
        base_url="http://host:11434",
    )
    assert isinstance(result, NormalizedResponse)
    assert result.text == "ok"
    assert result.tool_calls == []


# --- Tool calls parsing ---

@patch("httpx.Client")
def test_openai_parses_tool_calls(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "choices": [{
            "message": {
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "web.search",
                        "arguments": '{"query": "test"}',
                    }
                }]
            }
        }]
    }
    result = openai.execute(
        model_id="gpt-4", messages=[{"role": "user", "content": "search"}], api_key="sk-test"
    )
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["tool_name"] == "web.search"
    assert result.tool_calls[0]["arguments"] == {"query": "test"}


@patch("httpx.Client")
def test_anthropic_parses_tool_use(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "content": [
            {"type": "text", "text": "Let me search"},
            {"type": "tool_use", "name": "web.search", "input": {"query": "test"}},
        ]
    }
    result = anthropic.execute(
        model_id="claude-3-opus",
        messages=[{"role": "user", "content": "search"}],
        api_key="sk-ant",
    )
    assert result.text == "Let me search"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["tool_name"] == "web.search"
    assert result.tool_calls[0]["arguments"] == {"query": "test"}


@patch("httpx.Client")
def test_ollama_parses_tool_calls(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "message": {
            "content": "",
            "tool_calls": [{
                "function": {"name": "calculator", "arguments": {"x": 1}}
            }]
        }
    }
    result = ollama.execute(
        model_id="llama3",
        messages=[{"role": "user", "content": "calc"}],
        base_url="http://host:11434",
    )
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["tool_name"] == "calculator"


# --- max_tokens passthrough ---

@patch("httpx.Client")
def test_openai_max_tokens_passthrough(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "choices": [{"message": {"content": "ok"}}]
    }
    openai.execute(
        model_id="gpt-4",
        messages=[{"role": "user", "content": "hi"}],
        api_key="sk-test",
        max_tokens=512,
    )
    _, kwargs = mock_instance.post.call_args
    payload = kwargs["json"]
    assert payload["max_tokens"] == 512


@patch("httpx.Client")
def test_anthropic_max_tokens_passthrough(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "content": [{"type": "text", "text": "ok"}]
    }
    anthropic.execute(
        model_id="claude-3-opus",
        messages=[{"role": "user", "content": "hi"}],
        api_key="sk-ant",
        max_tokens=1024,
    )
    _, kwargs = mock_instance.post.call_args
    payload = kwargs["json"]
    assert payload["max_tokens"] == 1024


@patch("httpx.Client")
def test_ollama_max_tokens_passthrough(mock_client_cls):
    mock_instance = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_instance
    mock_instance.post.return_value.status_code = 200
    mock_instance.post.return_value.json.return_value = {
        "message": {"content": "ok"}
    }
    ollama.execute(
        model_id="llama3",
        messages=[{"role": "user", "content": "hi"}],
        base_url="http://host:11434",
        max_tokens=256,
    )
    _, kwargs = mock_instance.post.call_args
    payload = kwargs["json"]
    assert payload["options"]["num_predict"] == 256

import pytest
from unittest.mock import MagicMock, patch
from dbl_gateway.providers import openai, ollama, anthropic
from dbl_gateway.providers.errors import ProviderError

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

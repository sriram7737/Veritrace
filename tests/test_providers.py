import json
import io
import urllib.error

import pytest

from pramagent.providers import (GeminiProvider, OpenAICompatibleProvider,
                                 OpenAIProvider)


class FakeHTTPResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


@pytest.mark.asyncio
async def test_openai_compatible_provider_parses_chat_completion(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return FakeHTTPResponse({
            "model": "local-llama",
            "choices": [{"message": {"content": "hello from local"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4},
        })

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = OpenAICompatibleProvider(
        model="local-llama",
        base_url="http://localhost:8001/v1",
        api_key=None,
    )

    result = await provider.complete("hi")

    assert seen["url"] == "http://localhost:8001/v1/chat/completions"
    assert seen["body"]["messages"][0]["content"] == "hi"
    assert result.text == "hello from local"
    assert result.model == "local-llama"


@pytest.mark.asyncio
async def test_openai_provider_retries_with_max_completion_tokens(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout):
        body = json.loads(req.data.decode("utf-8"))
        calls.append(body)
        if len(calls) == 1:
            payload = json.dumps({
                "error": {
                    "message": (
                        "Unsupported parameter: 'max_tokens' is not supported "
                        "with this model. Use 'max_completion_tokens' instead."
                    )
                }
            }).encode("utf-8")
            raise urllib.error.HTTPError(
                req.full_url,
                400,
                "Bad Request",
                {},
                io.BytesIO(payload),
            )
        return FakeHTTPResponse({
            "model": "gpt-new",
            "choices": [{"message": {"content": "hello from new model"}}],
        })

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = OpenAIProvider(model="gpt-new", api_key="sk-test", max_tokens=12)

    result = await provider.complete("hi")

    assert result.text == "hello from new model"
    assert calls[0]["max_tokens"] == 12
    assert "max_completion_tokens" not in calls[0]
    assert calls[1]["max_completion_tokens"] == 12
    assert "max_tokens" not in calls[1]


def test_openai_provider_uses_openai_defaults(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    provider = OpenAIProvider(model="gpt-test")

    assert provider.name == "openai"
    assert provider.base_url == "https://api.openai.com/v1"
    assert provider.model == "gpt-test"
    assert provider.api_key == "sk-test"


@pytest.mark.asyncio
async def test_gemini_provider_parses_generate_content(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data.decode("utf-8"))
        return FakeHTTPResponse({
            "candidates": [{
                "content": {"parts": [{"text": "hello from gemini"}]}
            }]
        })

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    provider = GeminiProvider(
        model="gemini-test",
        api_key="gemini-key",
        base_url="https://gemini.example/v1beta",
    )

    result = await provider.complete("hi gemini")

    assert seen["url"] == "https://gemini.example/v1beta/models/gemini-test:generateContent?key=gemini-key"
    assert seen["body"]["contents"][0]["parts"][0]["text"] == "hi gemini"
    assert result.text == "hello from gemini"
    assert result.model == "gemini-test"

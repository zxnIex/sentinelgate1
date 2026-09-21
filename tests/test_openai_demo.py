from types import SimpleNamespace

from sentinelgate import openai_demo


class FakeHTTPResponse:
    def __init__(self, body):
        self.body = body
        self.is_error = False

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


def test_demo_replays_output_when_storage_is_disabled(monkeypatch, capsys):
    function_call = SimpleNamespace(
        type="function_call",
        name="search_knowledge",
        arguments='{"query":"security policy"}',
        call_id="call-1",
    )
    first = SimpleNamespace(id="resp-1", output=[function_call], output_text="")
    second = SimpleNamespace(id="resp-2", output=[], output_text="Policy result")
    calls = []

    class FakeResponses:
        def create(self, **kwargs):
            calls.append(kwargs)
            return first if len(calls) == 1 else second

    class FakeOpenAI:
        def __init__(self):
            self.responses = FakeResponses()

    def fake_post(url, **kwargs):
        if url.endswith("/v1/provenance/attest"):
            return FakeHTTPResponse({"token": "provenance-token"})
        return FakeHTTPResponse({"status": "succeeded", "result": {"hits": []}})

    dotenv_calls = []
    monkeypatch.setattr(openai_demo, "load_dotenv", lambda **kw: dotenv_calls.append(kw))
    monkeypatch.setattr(openai_demo, "OpenAI", FakeOpenAI)
    monkeypatch.setattr(openai_demo.httpx, "post", fake_post)
    monkeypatch.setattr("builtins.input", lambda _: "Find the security policy")
    monkeypatch.setenv("SENTINEL_AGENT_TOKEN", "agent-token")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5.6-luna")

    openai_demo.run()

    assert dotenv_calls == [{"override": False}]
    assert calls[0]["store"] is False
    assert calls[1]["store"] is False
    assert "previous_response_id" not in calls[1]
    assert calls[1]["input"][1] is function_call
    assert calls[1]["input"][2] == {
        "type": "function_call_output",
        "call_id": "call-1",
        "output": '{"status": "succeeded", "result": {"hits": []}}',
    }
    assert calls[1]["model"] == "gpt-5.6-luna"
    assert capsys.readouterr().out.strip() == "Policy result"

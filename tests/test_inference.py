"""Inference client tests. No network: a fake transport replays fixture bodies.

Fixture provenance: error_401.json is the body Vultr returned on 2026-11-04 for a request
without a key. The chat.completion fixtures follow the response shape in Vultr's tool-calling
guide (tool_calls with ids like "functions.<name>:<n>"); their content is written for PQ-Proof.
error_429/503 follow the 401 envelope. Replace them with recorded responses once a key exists.
"""
import json
import pathlib
import unittest

from pqproof import inference
from pqproof.inference import Client, InferenceError, parse_reply, tool_result

FIX = pathlib.Path(__file__).resolve().parent / "fixtures" / "inference"
KEY = "test-key-not-real-0123456789"
TOOLS = [{"type": "function", "function": {
    "name": "read_file", "description": "Read one file from the repo snapshot",
    "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}}]


def body(name):
    return (FIX / name).read_bytes()


class FakeSend:
    """Replays (status, headers, body) or raises an exception, one item per call."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers, data, timeout):
        self.calls.append({"url": url, "headers": headers, "payload": json.loads(data), "timeout": timeout})
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def client(send, **kw):
    sleeps = []
    return Client(api_key=KEY, send=send, sleep=sleeps.append, **kw), sleeps


class ToolCallParsing(unittest.TestCase):
    def test_one_tool_call(self):
        send = FakeSend((200, {}, body("tool_call_one.json")))
        c, _ = client(send)
        reply = c.chat([{"role": "user", "content": "migrate"}], tools=TOOLS)
        self.assertEqual(reply.finish_reason, "tool_calls")
        self.assertEqual(len(reply.tool_calls), 1)
        call = reply.tool_calls[0]
        self.assertEqual((call.id, call.name, call.arguments, call.error),
                         ("functions.read_file:0", "read_file", {"path": "nginx/nginx.conf"}, None))
        self.assertEqual(reply.usage["total_tokens"], 853)
        self.assertEqual(tool_result(call, "..."),
                         {"role": "tool", "tool_call_id": "functions.read_file:0", "content": "..."})

    def test_request_shape(self):
        send = FakeSend((200, {}, body("tool_call_one.json")))
        c, _ = client(send, timeout=42)
        c.chat([{"role": "user", "content": "migrate"}], tools=TOOLS, max_tokens=512)
        call = send.calls[0]
        self.assertEqual(call["url"], "https://api.vultrinference.com/v1/chat/completions")
        self.assertEqual(call["headers"]["Authorization"], f"Bearer {KEY}")
        self.assertEqual(call["payload"]["model"], "glm-5.3")
        self.assertEqual(call["payload"]["tools"], TOOLS)
        self.assertEqual(call["payload"]["max_tokens"], 512)
        self.assertNotIn("tool_choice", call["payload"])
        self.assertEqual(call["timeout"], 42)

    def test_several_tool_calls_keep_order(self):
        c, _ = client(FakeSend((200, {}, body("tool_calls_two.json"))))
        reply = c.chat([{"role": "user", "content": "x"}], tools=TOOLS)
        self.assertIsNone(reply.content)
        self.assertEqual([t.name for t in reply.tool_calls], ["read_file", "write_file"])
        self.assertEqual(reply.tool_calls[1].arguments["content"],
                         "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\n")

    def test_no_tool_call(self):
        c, _ = client(FakeSend((200, {}, body("no_tool.json"))))
        reply = c.chat([{"role": "user", "content": "summarize"}], model=inference.SUMMARY_MODEL)
        self.assertEqual(reply.tool_calls, [])
        self.assertEqual(reply.finish_reason, "stop")
        self.assertIn("go.mod", reply.content)
        self.assertEqual(reply.model, "deepseek-v4.1-flash-1017")

    def test_invalid_json_arguments_do_not_raise(self):
        c, _ = client(FakeSend((200, {}, body("bad_arguments.json"))))
        call = c.chat([{"role": "user", "content": "x"}], tools=TOOLS).tool_calls[0]
        self.assertIsNone(call.arguments)
        self.assertIn("not valid JSON", call.error)
        self.assertTrue(call.raw_arguments.startswith('{"path": "main.go"'))

    def test_arguments_must_be_an_object(self):
        reply = parse_reply({"choices": [{"finish_reason": "tool_calls", "message": {"tool_calls": [
            {"function": {"name": "read_file", "arguments": "[\"go.mod\"]"}}]}}]})
        self.assertIsNone(reply.tool_calls[0].arguments)
        self.assertIn("JSON object", reply.tool_calls[0].error)

    def test_missing_id_and_empty_arguments(self):
        # Vultr's chat docs show a tool call with no "id".
        reply = parse_reply({"choices": [{"finish_reason": "tool_calls", "message": {"tool_calls": [
            {"type": "function", "function": {"name": "list_files", "arguments": ""}}]}}]})
        self.assertEqual((reply.tool_calls[0].id, reply.tool_calls[0].arguments), ("call_0", {}))

    def test_response_without_choices(self):
        with self.assertRaises(InferenceError):
            parse_reply({"object": "chat.completion"})


class Retries(unittest.TestCase):
    def test_429_then_ok_honours_retry_after(self):
        send = FakeSend((429, {"Retry-After": "2"}, body("error_429.json")), (200, {}, body("no_tool.json")))
        c, sleeps = client(send)
        self.assertEqual(c.chat([{"role": "user", "content": "x"}]).finish_reason, "stop")
        self.assertEqual((len(send.calls), sleeps), (2, [2.0]))

    def test_5xx_backs_off_exponentially(self):
        send = FakeSend((503, {}, body("error_503.json")), (502, {}, b"bad gateway"),
                        (200, {}, body("no_tool.json")))
        c, sleeps = client(send)
        c.chat([{"role": "user", "content": "x"}])
        self.assertEqual(sleeps, [1.0, 2.0])

    def test_gives_up_after_max_attempts(self):
        send = FakeSend(*[(503, {}, body("error_503.json"))] * 4)
        c, sleeps = client(send)
        with self.assertRaises(InferenceError) as cm:
            c.chat([{"role": "user", "content": "x"}])
        self.assertEqual(cm.exception.status, 503)
        self.assertIn("Service temporarily unavailable", str(cm.exception))
        self.assertEqual((len(send.calls), len(sleeps)), (4, 3))

    def test_network_error_is_retried(self):
        send = FakeSend(TimeoutError("timed out"), (200, {}, body("no_tool.json")))
        c, sleeps = client(send)
        c.chat([{"role": "user", "content": "x"}])
        self.assertEqual(len(send.calls), 2)

    def test_retry_after_is_capped(self):
        send = FakeSend((429, {"retry-after": "3600"}, body("error_429.json")), (200, {}, body("no_tool.json")))
        c, sleeps = client(send)
        c.chat([{"role": "user", "content": "x"}])
        self.assertEqual(sleeps, [inference.MAX_DELAY_S])

    def test_401_is_not_retried_and_hides_the_key(self):
        send = FakeSend((401, {}, body("error_401.json")))
        c, sleeps = client(send)
        with self.assertRaises(InferenceError) as cm:
            c.chat([{"role": "user", "content": "x"}])
        self.assertEqual((cm.exception.status, len(send.calls), sleeps), (401, 1, []))
        self.assertIn("No API key provided", str(cm.exception))
        self.assertNotIn(KEY, str(cm.exception))


class Key(unittest.TestCase):
    def test_key_from_environment(self):
        old = inference.os.environ.pop(inference.API_KEY_ENV, None)
        try:
            with self.assertRaises(InferenceError) as cm:
                Client(send=FakeSend())
            self.assertIn("VULTR_INFERENCE_API_KEY", str(cm.exception))
            inference.os.environ[inference.API_KEY_ENV] = KEY
            send = FakeSend((200, {}, body("no_tool.json")))
            Client(send=send, sleep=lambda s: None).chat([{"role": "user", "content": "x"}])
            self.assertEqual(send.calls[0]["headers"]["Authorization"], f"Bearer {KEY}")
        finally:
            inference.os.environ.pop(inference.API_KEY_ENV, None)
            if old is not None:
                inference.os.environ[inference.API_KEY_ENV] = old


if __name__ == "__main__":
    unittest.main()

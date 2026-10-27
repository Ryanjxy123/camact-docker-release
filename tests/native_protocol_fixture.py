"""Original CamAct deterministic protocol fixtures; never a real model."""
import json
TEXT = "CAMACT_OFFLINE_OK"

def anthropic(tool=None):
    events = [
        ("message_start", {"type": "message_start", "message": {"id": "msg_fixture", "type": "message", "role": "assistant",
          "model": "fixture-model", "content": [], "stop_reason": None, "stop_sequence": None,
          "usage": {"input_tokens": 10, "output_tokens": 0}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": TEXT}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 5}}),
        ("message_stop", {"type": "message_stop"})]
    if tool:
        name, arguments = tool
        events = [events[0],
                  ("content_block_start", {"type": "content_block_start", "index": 0,
                    "content_block": {"type": "tool_use", "id": "toolu_fixture", "name": name, "input": {}}}),
                  ("content_block_delta", {"type": "content_block_delta", "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": json.dumps(arguments)}}),
                  events[3],
                  ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 5}}),
                  events[-1]]
    return "".join("event: " + t + "\ndata: " + json.dumps(e) + "\n\n" for t,e in events).encode()

def responses(tool=None):
    item = {"id": "msg_fixture", "type": "message", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": TEXT, "annotations": []}]}
    response = {"id": "resp_fixture", "object": "response", "created_at": 1, "model": "fixture-model",
                "status": "completed", "output": [item], "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}}
    events = [{"type": "response.created", "response": {**response, "status": "in_progress", "output": []}},
              {"type": "response.output_item.added", "output_index": 0, "item": {**item, "status": "in_progress", "content": []}},
              {"type": "response.content_part.added", "item_id": item["id"], "output_index": 0, "content_index": 0,
               "part": {"type": "output_text", "text": "", "annotations": []}},
              {"type": "response.output_text.delta", "item_id": item["id"], "output_index": 0, "content_index": 0, "delta": TEXT},
              {"type": "response.output_text.done", "item_id": item["id"], "output_index": 0, "content_index": 0, "text": TEXT},
              {"type": "response.output_item.done", "output_index": 0, "item": item},
              {"type": "response.completed", "response": response}]
    if tool:
        name, args = tool
        call = {"type": "function_call", "id": "fc_fixture", "call_id": "call_fixture", "name": name,
                "arguments": json.dumps(args), "status": "completed"}
        events = [events[0],
                  {"type": "response.output_item.added", "output_index": 0, "item": {**call, "arguments": "", "status": "in_progress"}},
                  {"type": "response.function_call_arguments.delta", "item_id": call["id"], "output_index": 0, "delta": call["arguments"]},
                  {"type": "response.function_call_arguments.done", "item_id": call["id"], "output_index": 0, "arguments": call["arguments"]},
                  {"type": "response.output_item.done", "output_index": 0, "item": call},
                  {"type": "response.completed", "response": {**response, "output": [call]}}]
    return "".join("event: " + e["type"] + "\ndata: " + json.dumps({**e, "sequence_number": i}) + "\n\n" for i,e in enumerate(events)).encode()

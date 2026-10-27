"""Normalize actual model wire capture; pure offline reader, no model calls.

Protocol parsing is shared with the existing Native vision audit. Source files
are read only; normalized facts are produced outside the agent workspace.
"""
from __future__ import annotations
import base64, gzip, hashlib, io, json, math, re, shlex
import posixpath
import os
from email import policy as email_policy
from email.parser import BytesParser
from benchmark.evaluator.datetime_compat import CompatibleDateTime as datetime
from pathlib import Path, PurePosixPath
from PIL import Image
from benchmark.evaluator.visual_evidence import (VERSION, sha, walk, attachment_events,
                                               business_image_ids, final_attachment_integrity_issues, image_ids)

CAPTURE_READER_VERSION = 'camact.visual_capture.v6-native-exact-fallback'

def documents(raw):
    try: return [json.loads(raw)]
    except (ValueError,UnicodeDecodeError):
        found=[]
        for line in raw.decode(errors='replace').splitlines():
            if not line.startswith('data:'): continue
            try: found.append(json.loads(line[5:]))
            except ValueError: pass
        return found
def response(raw):
    docs=documents(raw); tools=[]; text=[]; ids=[]; models=[]
    failed=any(d.get('error') or d.get('status') in ('failed','cancelled','incomplete') or
               d.get('type') in ('error','response.failed','response.incomplete') for d in docs)
    completed=[d['response'] for d in docs if d.get('type')=='response.completed']
    if completed: docs=completed
    failed=failed or any(d.get('error') or d.get('status') in ('failed','cancelled','incomplete') for d in docs)
    def content_blocks(blocks):
        if not isinstance(blocks,list):
            return
        for block in blocks:
            if not isinstance(block,dict):
                continue
            if block.get('type')=='tool_use':
                tools.append({'id':block.get('id'),'name':block.get('name'),'input':block.get('input')})
            elif block.get('type') in ('text','output_text') and isinstance(block.get('text'),str):
                text.append(block['text'])
    for d in docs:
        if d.get('id'): ids.append(d['id'])
        if d.get('model'): models.append(d['model'])
        for choice in d.get('choices', []):
            message = choice.get('message', {})
            if isinstance(message.get('content'), str):
                text.append(message['content'])
            else:
                content_blocks(message.get('content'))
            for call in message.get('tool_calls', []):
                function = call.get('function', {})
                try: args = json.loads(function.get('arguments', '{}'))
                except (ValueError, TypeError): args = None
                tools.append({'id': call.get('id'), 'name': function.get('name'), 'input': args})
        if d.get('type')=='message':
            content_blocks(d.get('content'))
        for node in d.get('output',[]):
            if not isinstance(node,dict):
                continue
            if node.get('type')=='function_call' and node.get('arguments') is not None:
                try: args=json.loads(node['arguments'])
                except (ValueError,TypeError): args=node['arguments']
                tools.append({'id':node.get('call_id',node.get('id')),'name':node.get('name'),'input':args})
            elif node.get('type')=='message':
                content_blocks(node.get('content'))
        for candidate in d.get('candidates',[]):
            for part in candidate.get('content',{}).get('parts',[]):
                if 'functionCall' in part:
                    function=part['functionCall']
                    tools.append({'id':function.get('id'),'name':function.get('name'),'input':function.get('args')})
                elif isinstance(part.get('text'),str):
                    text.append(part['text'])
    # Reconstruct Anthropic SSE tool JSON without dropping deltas.
    starts={}; parts={}
    for d in docs:
        if d.get('type')=='message_start':
            ids.append(d.get('message',{}).get('id')); models.append(d.get('message',{}).get('model'))
        if d.get('type')=='content_block_start' and d.get('content_block',{}).get('type')=='tool_use':
            block=d['content_block']; starts[d['index']]=block;parts[d['index']]=[]
        elif d.get('type')=='content_block_start':
            content_blocks([d.get('content_block',{})])
        if d.get('type')=='content_block_delta' and d.get('delta',{}).get('type')=='input_json_delta':
            parts.setdefault(d['index'],[]).append(d['delta'].get('partial_json',''))
        if d.get('type')=='content_block_delta' and d.get('delta',{}).get('type')=='text_delta':
            text.append(d['delta'].get('text',''))
    for index,t in starts.items():
        try: args=json.loads(''.join(parts[index])) if parts[index] else t.get('input',{})
        except ValueError: args={'unparsed_partial_json':''.join(parts[index])}
        tools=[v for v in tools if v['id']!=t.get('id')]
        tools.append({'id':t.get('id'),'name':t['name'],'input':args})
    unique=[]
    for t in tools:
        if t not in unique: unique.append(t)
    terminal=bool(completed or any(d.get('type')=='message_stop' or
        (d.get('status')=='completed' and d.get('object')=='response') or
        (d.get('type')=='message' and d.get('stop_reason')) or
        (d.get('choices') and all(c.get('finish_reason') for c in d['choices'])) or
        (d.get('candidates') and all(c.get('finishReason') for c in d['candidates'])) for d in docs))
    return {'message_ids':list(dict.fromkeys(filter(None,ids))),'models':list(dict.fromkeys(filter(None,models))),'tools':unique,'text':''.join(text),
            'completion_observed':not failed and terminal,'failure_observed':bool(failed)}

def _input_content_blocks(doc):
    """Walk actual protocol content, never metadata, schemas or tool arguments."""
    def content(value,path):
        if isinstance(value,str):
            yield path,{'type':'text','text':value}
            return
        if not isinstance(value,list):
            return
        for index,block in enumerate(value):
            if not isinstance(block,dict):
                continue
            block_path=f'{path}[{index}]'
            yield block_path,block
            if block.get('type')=='tool_result':
                yield from content(block.get('content'),block_path+'.content')
    yield from content(doc.get('system'),'$.system')
    for index,message in enumerate(doc.get('messages',[])):
        if isinstance(message,dict):
            yield from content(message.get('content'),f'$.messages[{index}].content')
    items=doc.get('input',[])
    if isinstance(items,list):
        for index,item in enumerate(items):
            if not isinstance(item,dict):
                continue
            path=f'$.input[{index}]'
            if item.get('type')=='function_call_output':
                yield path,item
                yield from content(item.get('output'),path+'.output')
            elif item.get('type') in ('image','image_url','input_image'):
                yield path,item
            elif item.get('type')=='message' or (item.get('role') in ('user','assistant','system','developer','tool') and 'content' in item):
                yield from content(item.get('content'),path+'.content')
    for index,message in enumerate(doc.get('contents',[])):
        if not isinstance(message,dict):
            continue
        for part_index,part in enumerate(message.get('parts',[])):
            if isinstance(part,dict):
                yield f'$.contents[{index}].parts[{part_index}]',part

def _input_image_blocks(doc):
    for path,node in _input_content_blocks(doc):
        if path.startswith('$.system'):
            continue
        if node.get('type') in ('image','image_url','input_image') or (path.startswith('$.contents[') and
                any(key in node for key in ('inlineData','inline_data','fileData','file_data'))):
            yield path,node
def extract_images(doc):
    result=[]
    for path,node in _input_image_blocks(doc):
        source=node.get('source',{})
        if node.get('type')=='image' and source.get('type')=='base64':
            result.append((path,source.get('media_type'),base64.b64decode(source['data'],validate=True),None))
        if node.get('type')=='image' and source.get('type')=='file': result.append((path,None,None,source.get('file_id')))
        if node.get('type')=='image' and source.get('type')=='url': result.append((path,None,None,source.get('url')))
        if node.get('type')=='input_image' and node.get('file_id'): result.append((path,None,None,node['file_id']))
        uri=node.get('image_url')
        if isinstance(uri,dict): uri=uri.get('url')
        if isinstance(uri,str) and uri.startswith('data:image/'):
            kind,data=uri.split(',',1)
            if not kind.endswith(';base64'):
                raise ValueError('image data URL has no base64 encoding')
            result.append((path,kind[5:].split(';')[0],base64.b64decode(data,validate=True),None))
        elif isinstance(uri,str):
            result.append((path,None,None,uri))
        if 'inlineData' in node or 'inline_data' in node:
            s=node.get('inlineData',node.get('inline_data'));result.append((path,s.get('mimeType',s.get('mime_type')),base64.b64decode(s['data'],validate=True),None))
        if 'fileData' in node or 'file_data' in node:
            s=node.get('fileData',node.get('file_data'));result.append((path,s.get('mimeType',s.get('mime_type')),None,s.get('fileUri',s.get('file_uri'))))
    return result
def command_text(tool):
    args=tool.get('input')
    if not isinstance(args,dict): return ''
    return args.get('cmd',args.get('command',''))
def command_arguments(cmd,operation):
    # Recognize a literal gateway call, optionally after a literal workspace cd.
    # Never execute a shell or infer arguments from echo, substitutions or files.
    try:
        tokens=shlex.split(cmd)
        if tokens[:3] == ['cd', '/tmp', '&&']:
            tokens = tokens[3:]
        if not tokens or not re.fullmatch(r'python(?:\d+(?:\.\d+)*)?',Path(tokens[0]).name):return None
        index=1
        while index<len(tokens) and tokens[index] in ('-B','-u'):index+=1
        if index>=len(tokens) or tokens[index] not in ('.camact/adapter.py','/tmp/.camact/adapter.py'):return None
        if tokens[index+1:index+4]!=['action',operation,'--json'] or len(tokens)!=index+5:return None
        return json.loads(tokens[index+4])
    except (ValueError,IndexError): return None
def replay_tool_ids(tool,doc):
    ids={tool.get('id')}
    replay={block.get('id') for message in doc.get('messages',[]) if message.get('role')=='assistant'
            for block in (message.get('content') or []) if isinstance(block,dict) and
            block.get('type')=='tool_use' and block.get('name')==tool.get('name') and block.get('input')==tool.get('input')}
    # An explicit assistant replay of the exact call records vendor ID rewriting.
    # Ambiguous repeated identical calls cannot introduce an inferred alias.
    if len(replay)==1: ids.update(replay)
    return ids


def read_jsonl(path):
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def _captured_file_upload(record, prefix):
    """Resolve a provider-issued id from hash-verified actual multipart wire.

    This is evidence decoding only. The native request and provider response
    stay byte-identical; unresolved or inconsistent references receive no credit.
    """
    raw = gzip.open(str(prefix)+'.request.gz', 'rb').read()
    reply = gzip.open(str(prefix)+'.response.gz', 'rb').read()
    if sha(raw) != record.get('upstream_request_sha256') or sha(reply) != record.get('response_sha256'):
        raise ValueError('file upload wire hash mismatch')
    content_type = record.get('request_content_type', '')
    if '\r' in content_type or '\n' in content_type:
        raise ValueError('invalid file upload content type')
    message = BytesParser(policy=email_policy.default).parsebytes(
        ('Content-Type: '+content_type+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+raw)
    if not message.is_multipart():
        raise ValueError('file upload is not multipart')
    files = [part for part in message.iter_parts()
             if part.get_param('name', header='content-disposition') == 'file']
    if len(files) != 1:
        raise ValueError('file upload requires one captured file')
    data, mime = files[0].get_payload(decode=True), files[0].get_content_type()
    metadata = json.loads(reply)
    identity = metadata.get('id')
    if not isinstance(identity, str) or not identity or metadata.get('size_bytes', len(data)) != len(data):
        raise ValueError('file upload response does not bind id and bytes')
    if not mime.startswith('image/') or metadata.get('mime_type', mime) != mime:
        raise ValueError('file upload is not a matching image')
    return identity, {'data': data, 'media_type': mime, 'provenance': {
        'file_id': identity, 'upload_sequence': record['sequence'],
        'upload_request_sha256': sha(raw), 'upload_response_sha256': sha(reply),
        'source_upload_request': str(Path(str(prefix)+'.request.gz').resolve()),
        'source_upload_response': str(Path(str(prefix)+'.response.gz').resolve())}}


def _verified_http_error_annotation_chain(rows):
    """Bind a failed attempt's start, HTTPError note and captured final body.

    The note is a lifecycle observation of one failed HTTP attempt. It never
    supplies successful model input or a completed generation.
    """
    if len(rows) != 3:
        return False
    initial, note, final = rows
    if (initial.get('schema_version') != 'camact.visual_wire.v1'
            or initial.get('capture_stage') != 'started'
            or initial.get('success') is not False
            or any(key in initial for key in ('exception_type', 'http_status',
                       'response_body', 'response_sha256', 'completed_at', 'capture_incomplete_reason'))):
        return False
    status = note.get('http_status')
    started, completed = initial.get('started_at'), final.get('completed_at')
    if (type(status) is not int or not 400 <= status < 600
            or type(started) not in (int, float) or type(completed) not in (int, float)
            or not math.isfinite(started) or not math.isfinite(completed)
            or not completed >= started):
        return False
    expected_note = {**initial, 'exception_type': 'HTTPError', 'http_status': status,
                     'capture_incomplete_reason': 'http_error_body_not_observed'}
    if note != expected_note:
        return False
    reply = final.get('response_body')
    if not isinstance(reply, str) or not reply:
        return False
    expected_final = {**initial, 'capture_stage': 'completed',
                      'exception_type': 'HTTPError', 'http_status': status,
                      'capture_incomplete_reason': None, 'completed_at': completed,
                      'response_body': reply, 'response_sha256': sha(reply.encode('utf-8'))}
    if final != expected_final:
        return False
    raw = initial.get('request_body')
    return (isinstance(raw, str) and sha(raw.encode('utf-8')) == initial.get('request_sha256')
            and not response(reply.encode('utf-8'))['completion_observed'])


def load_requests(root):
    """All supported captures enter one normalized request representation."""
    requests, issues = [], []
    index = root / 'capture/requests.json'
    if index.exists():
        records = json.loads(index.read_text(encoding='utf-8'))
        file_payloads, conflicted_file_ids = {}, set()
        for record in records:
            if record.get('component') == 'file_api':
                successful = record.get('status') == 'succeeded' and 200 <= record.get('http_status', 0) < 300
                route = record.get('route', '').split('?', 1)[0]
                if successful and record.get('method') == 'POST' and route == '/v1/files':
                    try:
                        identity, upload = _captured_file_upload(record, root / 'capture' / f"request-{record['sequence']:05d}")
                        previous = file_payloads.get(identity)
                        if identity in conflicted_file_ids or (previous and previous['data'] != upload['data']):
                            conflicted_file_ids.add(identity)
                            file_payloads.pop(identity, None)
                            raise ValueError('provider file id has conflicting captured bytes')
                        file_payloads[identity] = upload
                    except (OSError, ValueError, TypeError, KeyError) as exc:
                        issues.append(f"unverified file upload {record['sequence']}: {exc}")
                elif successful and record.get('method') == 'DELETE':
                    file_payloads.pop(route.rsplit('/', 1)[-1], None)
                continue
            if record.get('component') not in {'agent_with_tools', 'utility_generation'}:
                # Uploads/countTokens are not inference. Unresolved file IDs in
                # subsequent inference inputs remain unknown independently.
                continue
            prefix = root / 'capture' / f"request-{record['sequence']:05d}"
            req, resp = Path(str(prefix)+'.request.gz'), Path(str(prefix)+'.response.gz')
            if not req.exists() or not resp.exists():
                issues.append(f"missing wire body {record['sequence']}")
                continue
            raw, reply = gzip.open(req, 'rb').read(), gzip.open(resp, 'rb').read()
            if sha(raw) != record.get('upstream_request_sha256') or sha(reply) != record.get('response_sha256'):
                issues.append(f"wire hash mismatch {record['sequence']}")
                continue
            try:
                doc = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                # Non-generation file upload bodies do not prove model input.
                if record.get('component') in {'agent_with_tools','utility_generation'}:
                    issues.append(f"unreadable model request {record['sequence']}")
                continue
            parsed = response(reply)
            if (record.get('status')=='succeeded' and 200 <= record.get('http_status',0) < 300 and
                    not parsed['completion_observed'] and not parsed['failure_observed']):
                issues.append(f"model response has no terminal completion {record['sequence']}")
            requests.append({'id': str(record['sequence']), 'sequence': record['sequence'],
                'component': record['component'],
                'request_sha256': sha(raw), 'response_sha256': sha(reply),
                'source_request': str(req.resolve()), 'source_response': str(resp.resolve()),
                'model': doc.get('model'), 'document': doc, 'response': parsed,
                '_file_payloads': dict(file_payloads),
                'success': record.get('status') == 'succeeded' and 200 <= record.get('http_status',0) < 300 and parsed['completion_observed'],
                'started_at': record.get('started_at'), 'completed_at': record.get('completed_at')})
        return requests, issues
    # Existing Claude Native stores exact post-policy requests and attempt-level
    # complete upstream responses outside the workspace.
    files = [p for pattern in ('provider_requests.jsonl*', 'execution_limits/provider_requests.jsonl*',
                               'sessions/*/*/execution_limits/provider_requests.jsonl*')
             for p in root.glob(pattern) if p.name in {'provider_requests.jsonl','provider_requests.jsonl.gz'}]
    if len(files) == 1:
        reqfile = files[0]
        respfile = reqfile.with_name(reqfile.name.replace('requests','responses'))
        if not respfile.exists():
            return [], ['missing Claude provider response capture']
        replies = read_jsonl(respfile)
        request_rows = read_jsonl(reqfile)
        def capture_identity(row):
            # Older native captures wrote generation=null before committing the
            # step. A unique exact request hash still identifies its retries.
            # Repeated identical requests cannot be disambiguated this way.
            return row.get('generation') if row.get('generation') is not None else 'sha256:' + str(row.get('request_sha256'))
        identities = [capture_identity(row) for row in request_rows]
        if len(set(identities)) != len(identities):
            issues.append('ambiguous Claude request capture identity')
        matched = set()
        for row in request_rows:
            attempts = [r for r in replies if r.get('generation') == row['generation'] and r.get('request_sha256') == row['request_sha256']]
            if not attempts:
                issues.append(f"missing Claude response for generation {row['generation']} and request hash")
            for reply in attempts:
                matched.add(id(reply))
                doc = row['request']
                raw = json.dumps(doc, ensure_ascii=False).encode('utf-8')
                # The bridge hashes the exact bytes sent, before JSONL storage.
                if sha(raw) != row['request_sha256']:
                    issues.append(f"Claude request hash mismatch {row['generation']}")
                    continue
                parsed = response(reply.get('response','').encode('utf-8'))
                if (not reply.get('error') and 200 <= reply.get('http_status',0) < 300 and
                        not parsed['completion_observed'] and not parsed['failure_observed']):
                    issues.append(f"Claude response has no terminal completion {row['generation']}")
                requests.append({'id': f"{capture_identity(row)}:{reply.get('attempt',1)}", 'sequence': len(requests)+1,
                    'request_sha256': row['request_sha256'], 'response_sha256': sha(reply.get('response','').encode()),
                    'source_request': str(reqfile.resolve()), 'source_response': str(respfile.resolve()),
                    'model': doc.get('model'), 'document': doc, 'response': parsed,
                    'success': not reply.get('error') and 200 <= reply.get('http_status',0) < 300 and parsed['completion_observed'],
                    'started_at': reply.get('started_at'), 'completed_at': reply.get('ended_at')})
        if set(capture_identity(r) for r in replies) != set(identities) or any(id(r) not in matched for r in replies):
            issues.append('incomplete Claude request/response coverage')
        return requests, issues
    # The enhanced harness uses the same protocol wire representation below.
    wire = root / 'visual_wire.jsonl'
    if wire.exists():
        rows = read_jsonl(wire)
        starts = {r['request_id'] for r in rows if r.get('capture_stage') == 'started'}
        ends = {r['request_id'] for r in rows if r.get('capture_stage') != 'started'}
        if starts - ends:
            issues.append('provider request did not finish capture')
        if ends - starts:
            issues.append('provider response has no request-start capture')
        for request_id in starts | ends:
            begin=[r for r in rows if r.get('request_id')==request_id and r.get('capture_stage')=='started']
            finish=[r for r in rows if r.get('request_id')==request_id and r.get('capture_stage')=='completed']
            group=[r for r in rows if r.get('request_id')==request_id]
            ordinary_pair = (len(begin) == 1 and len(finish) == 1 and len(group) == 2
                             and group[0] is begin[0] and group[1] is finish[0]
                             and begin[0].get('capture_incomplete_reason') is None)
            if not ordinary_pair and not _verified_http_error_annotation_chain(group):
                issues.append('provider capture has duplicate or unsupported request stages')
            elif ordinary_pair and any(begin[0].get(key) != finish[0].get(key) for key in ('request_body','request_sha256','model','started_at')):
                issues.append('provider request-start and response capture disagree')
        for row in rows:
            if row.get('capture_stage') == 'started':
                continue
            if row.get('schema_version') != 'camact.visual_wire.v1':
                issues.append('unsupported enhanced capture'); continue
            raw = row['request_body'].encode('utf-8')
            reply = row.get('response_body','').encode('utf-8')
            parsed = response(reply)
            if row.get('success') is True and not parsed['completion_observed'] and not parsed['failure_observed']:
                issues.append('provider response has no terminal completion')
            if sha(raw) != row.get('request_sha256') or sha(reply) != row.get('response_sha256'):
                issues.append('enhanced wire hash mismatch'); continue
            requests.append({'id': row['request_id'], 'sequence': len(requests)+1,
                'request_sha256': sha(raw), 'response_sha256': sha(reply),
                'source_request': str(wire.resolve()), 'source_response': str(wire.resolve()),
                'model': row.get('model'), 'document': json.loads(raw), 'response': parsed,
                'success': row.get('success') is True and parsed['completion_observed'],
                'started_at': row.get('started_at'), 'completed_at': row.get('completed_at')})
        return requests, issues
    return [], ['no supported trusted model wire capture']


def _tool_arguments(tool, operation, originals=None):
    args = tool.get('input')
    if tool.get('name') == operation and isinstance(args, dict):
        return args
    command = command_text(tool)
    args = command_arguments(command, operation) if isinstance(command, str) else None
    if not isinstance(args, dict) or originals is None:
        return args
    # The native gateway accepts original filenames embedded in paths. Its
    # persisted request contains filenames, while the wire contains paths.
    # Reconcile only known originals, without touching arbitrary text or
    # deleting invalid/duplicate values. Pixel identity is checked separately.
    result = dict(args)
    lookup = {name.casefold(): name for name in originals}
    for field in ('attachments', 'images', 'image_ids', 'reference_images'):
        values = args.get(field)
        if not isinstance(values, list):
            continue
        normalized = []
        for value in values:
            if not isinstance(value, str):
                normalized.append(value)
                continue
            name = value.replace('\\', '/').rsplit('/', 1)[-1]
            normalized.append(lookup.get(name.casefold(), value))
        result[field] = normalized
    for field in ('image', 'image_id'):
        value = args.get(field)
        if isinstance(value, str):
            name = value.replace('\\', '/').rsplit('/', 1)[-1]
            result[field] = lookup.get(name.casefold(), value)
    return result


def _text(value):
    if isinstance(value, str):
        return value
    return '\n'.join(n.get('text','') for _,n in walk(value) if n.get('type') in ('text','output_text') and isinstance(n.get('text'),str))


def _timestamp(value):
    if value is None:
        return None
    return float(value) if isinstance(value,(float,int)) else datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()


def _precedes(completed, started):
    left,right = _timestamp(completed),_timestamp(started)
    return None if left is None or right is None else left <= right


def _native_tool_results(document):
    """Protocol tool-result slots only; never model prose/schema/arguments."""
    for path, node in _input_content_blocks(document):
        if node.get('type') in {'tool_result', 'function_call_output'}:
            yield path, node
    for index, message in enumerate(document.get('messages', [])):
        if isinstance(message, dict) and message.get('role') == 'tool' and message.get('tool_call_id'):
            yield f'$.messages[{index}]', {'type': 'function_call_output',
                'call_id': message['tool_call_id'], 'output': message.get('content', '')}


def _receipt_in_result(node, event):
    if node.get('is_error') is True:
        return None
    value = _text(node.get('output', node.get('content', '')))
    decoder = json.JSONDecoder()
    for match in re.finditer(r'\{', value):
        try:
            receipt, _ = decoder.raw_decode(value[match.start():])
        except ValueError:
            continue
        if (isinstance(receipt, dict) and receipt.get('ok') is True
                and receipt.get('tool') == event['operation']
                and receipt.get('result') == event['receipt']):
            return receipt
    return None


def _streamed_receipt_link(requests, decision, tool, event):
    """A CLI can execute a complete streamed call before the HTTP tail closes.

    Require its exact call ID and service receipt in a subsequent native tool
    result. A grace interval, matching prose, or the Agent's own claim is not
    causal evidence. This handles capture-finalization races without relaxing
    the requirement that the image-bearing request precede the business action.
    """
    identity = tool.get('id')
    if (not identity or _precedes(decision.get('started_at'), event.get('timestamp')) is not True
            or sum(t.get('id') == identity for r in requests for t in r['response']['tools']) != 1):
        return None
    for later in requests:
        if (later is decision or _precedes(event.get('timestamp'), later.get('started_at')) is not True):
            continue
        aliases = replay_tool_ids(tool, later['document'])
        for path, node in _native_tool_results(later['document']):
            kind = node.get('type')
            linked = ((kind == 'function_call_output' and node.get('call_id') in aliases)
                      or (kind == 'tool_result' and node.get('tool_use_id') in aliases))
            if not linked or node.get('is_error') is True:
                continue
            receipt = _receipt_in_result(node, event)
            if receipt is not None:
                return {'request_id': later['id'], 'tool_result_json_path': path,
                        'native_tool_id': identity, 'receipt_sha256': sha(
                            json.dumps(receipt, sort_keys=True).encode())}
    return None


def _receipt_producers(requests, event, events, originals):
    """Link arbitrary native executors by their actual successful service reply.

    Works for wrappers, file substitution and alternate gateways. The request
    must predate the real commit, and its unique native call must receive this
    exact service receipt in a later input. Ambiguous/reused receipts stay unknown.
    No shell evaluation or inference from the final workspace is performed.
    """
    if sum(e['operation'] == event['operation'] and e['receipt'] == event['receipt'] for e in events) != 1:
        return [], {}
    producers, links = [], {}
    for request in requests:
        if not request['success']:
            continue
        for tool in request['response']['tools']:
            parsed = _tool_arguments(tool, event['operation'], originals)
            if parsed is not None and parsed != event['request']:
                continue
            link = _streamed_receipt_link(requests, request, tool, event)
            if link:
                producers.append((request, tool))
                links[(request['id'], tool.get('id'))] = link
    return producers, links


def _decision_producers(requests, event, events, originals):
    """Resolve repeated matching calls only through a unique captured receipt.

    A repeated operation/request is not a unique causal decision. The existing
    exact call-ID/service-receipt chain can disambiguate it; ambiguous or absent
    receipt proof retains the original unknown result.
    """
    producers = [(request, tool) for request in requests if request['success']
                 for tool in request['response']['tools']
                 if _tool_arguments(tool, event['operation'], originals) == event['request']]
    if len(producers) == 1:
        return producers, {}
    proven, links = _receipt_producers(requests, event, events, originals)
    if len(proven) == 1:
        return proven, links
    return (producers, {}) if producers else (proven, links)


def _runtime_visual_observations(requests, submission, originals, issues):
    """Audit Runtime aliases as execution facts, never as a replacement for pixels.

    Canonical short references belong to one successful browse response in this
    Episode. Native readers have no such references and use the same pixel and
    causal decision checks without needing a CamAct image_view call.
    """
    refs,observations = {},[]
    for event in submission.get('execution_trace',[]):
        if event.get('kind') != 'tool_call' or event.get('status') != 'succeeded':
            continue
        result = event.get('response',{})
        if event.get('name') == 'album_browse':
            mapping = result.get('image_refs')
            if mapping is None:
                continue  # Older captures use raw IDs only.
            page = result.get('page_ref')
            expected = {f'{page}-{index}':photo.get('image')
                        for index,photo in enumerate(result.get('photos',[]),1)}
            if (not re.fullmatch(r'p[0-9]+',str(page)) or mapping != expected or
                    any(photo.get('image_ref') != f'{page}-{index}'
                        for index,photo in enumerate(result.get('photos',[]),1))):
                issues.append('inconsistent Runtime album page reference mapping')
                continue
            if any(ref in refs for ref in mapping):
                issues.append('Runtime album page reference reused in this Episode')
                continue
            refs.update({ref:{'image_id':identity,'browse_sequence':event.get('sequence'),
                             'browse_timestamp':event.get('timestamp')}
                         for ref,identity in mapping.items()})
        elif event.get('image_observation') is not None or (event.get('name') == 'image_view' and
                re.fullmatch(r'p[0-9]+-[0-9]+',str(event.get('request',{}).get('image_id')))):
            requested = event.get('request',{}).get('image_id')
            short = bool(re.fullmatch(r'p[0-9]+-[0-9]+',str(requested)))
            identity = result.get('image_id')
            source = refs.get(requested) if short else None
            observation = event.get('image_observation',{})
            row = {'runtime_sequence':event.get('sequence'),'requested_image_id':requested,
                   'image_id':identity,'image_ref':requested if short else None,
                   'mapping':source,'image_observation':observation,'model_inputs':[]}
            if short and (not source or source['image_id'] != identity or result.get('image_ref') != requested or
                          _precedes(source['browse_timestamp'],event.get('timestamp')) is not True):
                issues.append('successful Runtime image reference has no consistent prior mapping')
                row['status']='evidence_unknown';observations.append(row);continue
            original = originals.get(identity)
            if (original is None or observation.get('image_id') != identity or
                    observation.get('sha256') != sha(original.read_bytes()) or
                    observation.get('bytes') != original.stat().st_size):
                issues.append('Runtime image observation does not bind to the original payload')
                row['status']='evidence_unknown';observations.append(row);continue
            producers = [(r,t) for r in requests if r['success'] and
                         _precedes(r.get('completed_at'),event.get('timestamp')) is True
                         for t in r['response']['tools']
                         if t.get('name') == event.get('name') and t.get('input') == event.get('request')]
            if producers:
                latest = max(_timestamp(r['completed_at']) for r,t in producers)
                producers = [(r,t) for r,t in producers if _timestamp(r['completed_at']) == latest]
            if len({r['id'] for r,t in producers}) != 1:
                issues.append('Runtime visual observation has no unique successful model-issued call')
                row['status']='evidence_unknown';observations.append(row);continue
            producer,tool = producers[0]
            row.update(producer_request_id=producer['id'],
                       native_tool_ids=[t.get('id') for r,t in producers],
                       native_tool_id=tool.get('id') if len(producers)==1 else None)
            for req in requests:
                if _precedes(event.get('timestamp'),req.get('started_at')) is not True:
                    continue
                for payload in req['images']:
                    if (payload.get('payload_sha256') == observation['sha256'] and
                            payload.get('bytes') == observation.get('bytes')):
                        row['model_inputs'].append({'request_id':req['id'],'json_path':payload['json_path'],
                                                    'request_success':req['success']})
            row['status']='payload_observed' if row['model_inputs'] else 'not_forwarded'
            observations.append(row)
    return observations


def _native_album_alias(originals_root, submission):
    """Read one runner-created memory alias for this exact isolated album.

    The native workspace mounts .camact and context read-only. A path from
    model prose or a different user's policy never introduces an alias. Older
    workspaces without this contract retain the existing /tmp-only behavior.
    """
    images = Path(originals_root)
    if images.name != 'images' or images.parent.name != 'album':
        return None
    workspace = images.parent.parent
    policy_file = workspace / '.camact/prompt_policy.json'
    context_file = workspace / 'context/task.json'
    manifest_file = workspace / 'workspace_manifest.json'
    paths = (workspace, images.parent, images, policy_file.parent,
             context_file.parent, policy_file, context_file, manifest_file)
    if any(path.is_symlink() for path in paths) or not all(
            path.is_file() for path in (policy_file, context_file, manifest_file)):
        return None
    try:
        policy = json.loads(policy_file.read_text(encoding='utf-8'))
        context = json.loads(context_file.read_text(encoding='utf-8'))
        manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not all(isinstance(value, dict) for value in (policy, context, manifest)):
        return None
    if (policy.get('schema_version') != 'camact.system_prompt_policy.v1' or
            manifest.get('schema_version') not in ('camact.native_workspace.v1', 'camact.claude_code_native_workspace.v1') or
            context.get('task_id') != submission.get('task_id') or
            manifest.get('task_id') != submission.get('task_id')):
        return None
    root, user = policy.get('memory_root'), manifest.get('user_id')
    if not isinstance(root, str) or '\\' in root or '\x00' in root or not isinstance(user, str) or not user:
        return None
    target = PurePosixPath(root)
    if (not target.is_absolute() or root.startswith('//') or str(target) != root or
            '..' in target.parts or len(target.parts) < 5 or
            target.parts[-3:] != ('users', user, 'base_memory') or
            not str(submission.get('task_id', '')).startswith(user + '_') or
            target.parts[1] in {'usr', 'bin', 'sbin', 'lib', 'lib64', 'etc', 'dev', 'proc', 'sys', 'run', 'opt', 'transport'}):
        return None
    return root


def _native_image_path(value, album_alias=None):
    """Normalize only the exact trusted alias; leave raw capture untouched."""
    if album_alias and isinstance(value, str):
        identity = posixpath.basename(value)
        if value == album_alias + '/images/' + identity:
            return '/tmp/album/images/' + identity
    return posixpath.normpath(value if value.startswith('/') else '/tmp/' + value)


def _bound_original_source(value, originals, album_alias=None):
    """Bind only an approved native alias or the exact current raw source.

    Official tools can read the public memory through its absolute host path.
    A basename, another user's directory, or a path suffix never certifies that
    source. The canonical file path and bytes must match the task's raw album;
    the transmitted pixels still need the independent provenance proof below.
    """
    normalized = _native_image_path(value, album_alias)
    identity = posixpath.basename(normalized)
    if identity not in originals:
        return None
    if normalized == '/tmp/album/images/' + identity:
        return identity
    original = Path(originals[identity])
    try:
        expected = original.resolve(strict=True)
        if normalized != expected.as_posix() or not expected.is_file():
            return None
        if sha(Path(normalized).read_bytes()) != sha(original.read_bytes()):
            return None
    except (OSError, RuntimeError):
        return None
    return identity


def _payloads(requests, originals, issues, *, album_alias=None, required=None, native_context=None):
    if not requests:
        return  # No wire payload can use the album hash index; all gates remain below.
    from .visual_provenance import ImageProvenance, collage_recipes
    resolver = ImageProvenance(originals, collage_recipes(requests), required=required)
    hashes = resolver.hashes
    source_bindings = {}
    for req in requests:
        req['images'] = []
        # Index aliases once per request. Earlier code rebuilt the complete
        # assistant replay set for every payload x every prior tool call.
        blocks = list(_input_content_blocks(req['document']))
        origin_index = {}
        for prior in requests:
            if not prior['success'] or prior['sequence'] >= req['sequence']:
                continue
            for tool in prior['response']['tools']:
                for alias in replay_tool_ids(tool, req['document']):
                    if alias:
                        origin_index.setdefault(alias, []).append((prior, tool))
        for path, mime, data, ref in extract_images(req['document']):
            upload = req.get('_file_payloads', {}).get(ref) if data is None else None
            if upload is not None:
                data, mime = upload['data'], upload['media_type']
            if data is None:
                req['images'].append({'json_path':path, 'unresolved_file_reference':ref, 'image_ids':[]})
                continue
            digest = sha(data)
            try:
                with Image.open(io.BytesIO(data)) as im:
                    im.verify()
                with Image.open(io.BytesIO(data)) as im:
                    dimensions = list(im.size)
            except (ValueError, OSError):
                issues.append('invalid image payload'); continue
            image = {'json_path':path, 'payload_sha256':digest, 'bytes':len(data),
                     'media_type':mime, 'dimensions':dimensions, 'image_ids':hashes.get(digest,[]) if len(hashes.get(digest,[])) == 1 else [],
                     'identity_route':'byte_identical' if len(hashes.get(digest, [])) == 1 else 'unresolved'}
            if upload is not None:
                image['file_reference_provenance'] = upload['provenance']
            origins=[]
            native_origins=[]
            for parent_path,parent in blocks:
                if parent.get('type') not in ('tool_result','function_call_output') or not path.startswith(parent_path+'.'):
                    continue
                call_id=parent.get('tool_use_id',parent.get('call_id'))
                for prior,tool in origin_index.get(call_id, []):
                    origin = {'producer_request_id':prior['id'],'native_tool':tool,
                              'tool_result_id':call_id,'tool_result_json_path':parent_path}
                    origins.append(origin)
                    native_origins.append({**origin, 'producer_sequence':prior['sequence'],
                                           'producer_success':True})
            if origins:
                image['native_tool_results']=origins
            # Tool paths propose sources; the transmitted pixels must independently
            # verify a full-frame transform. A source filename alone earns nothing.
            bound = set()
            for origin in origins:
                args = origin['native_tool'].get('input', {})
                if not isinstance(args, dict):
                    continue
                for value in args.values():
                    if not isinstance(value, str):
                        continue
                    if value not in source_bindings:
                        source_bindings[value] = _bound_original_source(value, originals, album_alias)
                    identity = source_bindings[value]
                    if identity is not None:
                        bound.add(identity)
            if image['identity_route'] != 'byte_identical':
                context = ({**native_context, 'native_tool_results':native_origins,
                            'request_id':req['id'], 'request_sequence':req['sequence'],
                            'request_sha256':req['request_sha256'], 'response_sha256':req['response_sha256'],
                            'source_request':req['source_request'], 'source_response':req['source_response']}
                           if native_context else None)
                image.update(resolver.resolve(data, bound_sources=bound, native_context=context))
            req['images'].append(image)


def _auxiliary_routes(requests, decision, identity, issues):
    routes = []
    for auxiliary in requests:
        if not auxiliary['success'] or auxiliary['sequence'] >= decision['sequence']:
            continue
        payloads = [p for p in auxiliary['images'] if identity in p['image_ids']]
        reply = auxiliary['response'].get('text','').strip()
        if not payloads or not reply:
            continue
        for parent in requests:
            if not parent['success'] or parent['sequence'] >= auxiliary['sequence']:
                continue
            for tool in parent['response']['tools']:
                args = tool.get('input',{})
                if not isinstance(args,dict):
                    continue
                paths = [v for _,n in walk(args) for v in n.values() if isinstance(v,str)]
                paths += [v for v in args.values() if isinstance(v,str)]
                referenced = any(Path(v).name == identity for v in paths)
                for value in args.values():
                    if isinstance(value,list):
                        referenced |= any(isinstance(v,str) and Path(v).name == identity for v in value)
                prompt = args.get('prompt')
                if not referenced or not isinstance(prompt,str) or not prompt:
                    continue
                texts = '\n'.join(node.get('text','') for _,node in _input_content_blocks(auxiliary['document'])
                                  if node.get('type') in ('text','output_text') and isinstance(node.get('text'),str))
                if prompt not in texts:
                    continue
                aliases = replay_tool_ids(tool, decision['document'])
                for path,node in _input_content_blocks(decision['document']):
                    if node.get('type') == 'tool_result' and node.get('tool_use_id') in aliases and reply in _text(node.get('content')):
                        before_auxiliary=_precedes(parent.get('completed_at'),auxiliary.get('started_at'))
                        before_decision=_precedes(auxiliary.get('completed_at'),decision.get('started_at'))
                        if before_auxiliary is None or before_decision is None:
                            issues.append('missing auxiliary visual handoff causal timestamps')
                            continue
                        if not before_auxiliary or not before_decision:
                            continue
                        routes.append({'route':'auxiliary_visual_response', 'visual_request_id':auxiliary['id'],
                            'parent_request_id':parent['id'], 'native_tool':tool,
                            'main_request_id':decision['id'], 'forwarded_tool_id':node['tool_use_id'],
                            'forwarded_result_json_path':path, 'visual_response_text_sha256':sha(reply.encode()),
                            'payloads':payloads, 'main_received':'analysis_text'})
    return routes


def _retained_analysis_routes(requests, decision, identity, issues):
    """Verify a structured visual assertion retained across model generations.

    This also covers the enhanced harness's existing compaction: the assertion
    must be generated by a successful image-bearing response, then forwarded
    unchanged with its image identity. A viewed/selected flag is insufficient.
    """
    retained=[]
    for path,node in _input_content_blocks(decision['document']):
        text=node.get('text')
        if node.get('type') not in ('text','output_text') or not isinstance(text,str):
            continue
        for offset in (m.start() for m in re.finditer(r'\{',text)):
            try: value=json.JSONDecoder().raw_decode(text[offset:])[0]
            except ValueError:continue
            for inner,record in walk(value):
                if record.get('image_id')==identity and isinstance(record.get('grounded_fact'),str):
                    retained.append((path,inner,record['grounded_fact']))
                image=record.get(identity)
                if isinstance(image,dict) and isinstance(image.get('grounded_fact'),str):
                    retained.append((path,inner+'.'+identity,image['grounded_fact']))
            # The first valid enclosing object already traverses its children.
            break
    routes=[]
    for prior in requests:
        if not prior['success'] or prior['sequence']>=decision['sequence']:
            continue
        images=[i for i in prior['images'] if identity in i['image_ids']]
        if not images:continue
        for call in prior['response']['tools']:
            args=call.get('input',{})
            if not isinstance(args,dict) or args.get('image_id')!=identity:
                continue
            fact=args.get('grounded_fact')
            if not isinstance(fact,str) or not fact.strip():continue
            for path,inner,actual in retained:
                if actual==fact:
                    ordered=_precedes(prior.get('completed_at'),decision.get('started_at'))
                    if ordered is None:
                        issues.append('missing retained visual analysis causal timestamps')
                        continue
                    if not ordered:
                        continue
                    routes.append({'route':'retained_visual_analysis','visual_request_id':prior['id'],
                        'analysis_response_sha256':prior['response_sha256'],'analysis_native_tool':call,
                        'analysis_text_sha256':sha(fact.encode()),'forwarded_context_json_path':path,
                        'forwarded_assertion_path':inner,'main_request_id':decision['id'],
                        'source_model':prior['model'],'destination_model':decision['model'],
                        'main_received':'structured_analysis_text','payloads':images})
    return routes


def _prior_agent_routes(requests, decision, identity):
    """Earlier successful visual input in the same captured Episode suffices.

    Utility requests retain their explicit handoff rule. The Agent does not
    need a separate turn, a particular tool, or a retained structured claim.
    """
    routes = []
    for prior in requests:
        if (prior['id'] == decision['id'] or not prior['success']
                or prior.get('component', 'agent_with_tools') != 'agent_with_tools'
                or prior['sequence'] >= decision['sequence']
                or _precedes(prior.get('completed_at'), decision.get('started_at')) is not True):
            continue
        payloads = [p for p in prior['images'] if identity in p['image_ids']]
        if payloads:
            routes.append({'route':'prior_agent_image', 'visual_request_id':prior['id'],
                           'main_request_id':decision['id'], 'payloads':payloads,
                           'main_received':'earlier_successful_agent_image_input'})
            break
    return routes


def _collect_visual_evidence(root, submission, originals_root):
    root, originals_root = Path(root), Path(originals_root)
    requests, issues = load_requests(root)
    snapshots=[]
    episode_paths = [root/'episode.json',root/'session/episode.json',*root.glob('sessions/*/*/episode.json')]
    for path in episode_paths:
        if not path.is_file():
            continue
        try:
            document=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError):
            continue
        if (document.get('task_id')==submission.get('task_id') and
                document.get('runtime_metadata',{}).get('session_id')==submission.get('runtime_metadata',{}).get('session_id') and
                document.get('execution_trace')==submission.get('execution_trace') and
                document.get('final_environment')==submission.get('final_environment')):
            snapshots.append({'path':str(path.resolve()),'sha256':sha(path.read_bytes())})
    if len(snapshots)!=1:
        issues.append('capture root does not uniquely bind to this Episode trace')
    originals = {p.name:p for p in originals_root.iterdir() if p.is_file()} if originals_root.is_dir() else {}
    if not originals:
        issues.append('missing original image album')
    album_alias = _native_album_alias(originals_root, submission)
    if album_alias is None:
        # Canonical replay supplies the authoritative raw album, outside the
        # isolated workspace. Recover only its existing runner-created alias
        # after proving every copied source file is the same canonical album.
        copied = root / "workspace/album/images"
        candidate_alias = _native_album_alias(copied, submission)
        if candidate_alias is not None:
            copied_files = {p.name: p for p in copied.iterdir() if p.is_file()}
            if (set(copied_files) == set(originals) and originals
                    and all(not path.is_symlink() for path in copied_files.values())
                    and all(sha(copied_files[name].read_bytes()) == sha(path.read_bytes())
                            for name, path in originals.items())):
                album_alias = candidate_alias
    # Limit expensive reconstruction to actual business uses and evidence.
    # The album remains the full uniqueness search universe, independent of GT.
    registry = json.loads((Path(__file__).resolve().parents[2] /
                           'benchmark/evaluator/visual_check_registry.json').read_text())
    entries = registry.get('tasks', {}).get(submission.get('task_id'), {})
    any_view = any(e.get('policy', {}).get('mode') == 'any_before_creation'
                   or e.get('policy', {}).get('requires_any_before_operation') for e in entries.values())
    required = None if any_view else (image_ids(submission.get('evidence', [])) |
        set().union(*(set(e['images']) for e in attachment_events(submission))) |
        set().union(*(business_image_ids(e.get('request', {}), task_id=submission.get('task_id'))
                      for e in submission.get('execution_trace', []) if e.get('kind') == 'tool_call')))
    from .visual_native_exact import native_capture_context
    native_context = native_capture_context(root, submission)
    _payloads(requests, originals, issues, album_alias=album_alias, required=required,
              native_context=native_context)
    runtime_observations=_runtime_visual_observations(requests,submission,originals,issues)
    issues.extend(final_attachment_integrity_issues(submission))
    attachments = []
    events = list(attachment_events(submission))
    for event in events:
        producers, receipt_links = _decision_producers(requests, event, events, originals)
        for identity in event['images']:
            row = {'image_id':identity, 'original_sha256':sha(originals[identity].read_bytes()) if identity in originals else None,
                   'binding':event['binding'],
                   'business_sequence':event['sequence'], 'business_operation':event['operation'],
                   'business_request':event['request'], 'business_receipt':event['receipt'],
                   'status':'evidence_unknown', 'routes':[], 'producer_count':len(producers)}
            for field in ('final_state_issue','final_state_records'):
                if field in event:
                    row[field]=event[field]
            if event.get('final_state_issue'):
                row['reason']=event['final_state_issue']
                attachments.append(row)
                continue
            if identity not in originals:
                row['reason']='the attached original is unavailable for identity verification'
                attachments.append(row)
                continue
            if identity not in business_image_ids(event['request'],event['binding'], task_id=submission.get('task_id')):
                row.update(status='visual_not_verified',reason='persisted image has no corresponding attachment decision')
                attachments.append(row)
                continue
            if len(producers) == 1:
                decision, tool = producers[0]
                row.update(decision_request_id=decision['id'], decision_request_sha256=decision['request_sha256'],
                           decision_response_sha256=decision['response_sha256'], decision_response_ids=decision['response']['message_ids'],
                           decision_native_tool=tool)
                if receipt_links:
                    row['decision_association'] = {'route': 'native_service_receipt',
                        **receipt_links[(decision['id'], tool.get('id'))]}
                payloads = [p for p in decision['images'] if identity in p['image_ids']]
                if payloads:
                    row['routes'].append({'route':'direct_image', 'visual_request_id':decision['id'],
                                           'payloads':payloads, 'main_received':'image'})
                if not payloads:
                    row['routes'] += _auxiliary_routes(requests,decision,identity,issues)
                    row['routes'] += _retained_analysis_routes(requests,decision,identity,issues)
                    row['routes'] += _prior_agent_routes(requests,decision,identity)
                unresolved = any(p['identity_route']=='unresolved' if 'identity_route' in p else True for p in decision['images'])
                row['status'] = ('visual_verified' if row['routes'] else 'evidence_unknown' if unresolved else 'visual_not_verified')
                if not row['routes']:
                    row.setdefault('reason', 'image_provenance_unresolved' if unresolved else 'no_successful_prior_model_image_input')
                # Equal-turn input/output is valid, but a response completed
                # after the business commit cannot have caused that commit.
                if event.get('timestamp') and decision.get('completed_at'):
                    if _timestamp(decision['completed_at']) > _timestamp(event['timestamp']):
                        link = _streamed_receipt_link(requests, decision, tool, event)
                        if link:
                            row['streamed_receipt_link'] = link
                        elif _precedes(decision.get('started_at'), event['timestamp']) is True:
                            row.update(status='evidence_unknown', reason='response finalization overlaps attachment without a linked native receipt')
                        else:
                            row.update(status='visual_not_verified', reason='decision request is after attachment')
                else:
                    row.update(status='evidence_unknown', reason='missing causal timestamps')
            elif not producers and requests and not issues:
                # An unrecognized shell/script is an association gap, not proof
                # the model did not see the original.
                row['reason'] = 'missing or failed decision request association'
                failed = [(r,t) for r in requests if not r['success'] for t in r['response']['tools']
                          if _tool_arguments(t,event['operation'], originals) == event['request']]
                if failed:
                    row.update(status='visual_not_verified', reason='only failed model responses contain the attachment decision')
            attachments.append(row)
    complete = bool(requests) and not issues
    statuses = {a['status'] for a in attachments}
    status = ('evidence_unknown' if not complete or 'evidence_unknown' in statuses else
              'visual_verified' if statuses == {'visual_verified'} else 'visual_not_verified')
    return {'schema_version':VERSION, 'capture_reader_version':CAPTURE_READER_VERSION, 'task_id':submission.get('task_id'),
            'session_id':submission.get('runtime_metadata',{}).get('session_id'),
            'capture_root':str(root.resolve()), 'originals_root':str(originals_root.resolve()),
            'complete':complete, 'status':status, 'issues':issues, 'attachments':attachments,
            'runtime_image_observations':runtime_observations,
            'source_episode_snapshots':snapshots,
            'requests':[{k:v for k,v in r.items() if k not in {'document', '_file_payloads'}} for r in requests],
            'trust_boundary':'runner-owned wire capture outside agent workspace',
            'provider_internal_processing_observable':False}


def native_capture_path(value):
    """Keep saved WSL/Windows capture references usable on the shared disk."""
    text=str(value).replace('\\','/')
    mounted=re.fullmatch(r'/mnt/([a-zA-Z])/(.*)',text)
    drive=re.fullmatch(r'([a-zA-Z]):/(.*)',text)
    if os.name=='nt' and mounted:
        return mounted[1].upper()+':/'+mounted[2]
    if os.name!='nt' and drive:
        return '/mnt/'+drive[1].lower()+'/'+drive[2]
    return str(value)


def collect_visual_evidence(root, submission, originals_root):
    """Corrupt/missing capture is an explicit audit gap, never an Agent zero."""
    root=Path(native_capture_path(root))
    originals_root=Path(native_capture_path(originals_root))
    try:
        from . import visual_capture_legacy_v4
        legacy = visual_capture_legacy_v4.collect_visual_evidence(root, submission, originals_root)
        if legacy_primary_resolves_active_checks(legacy, submission):
            return legacy
        return _collect_visual_evidence(root,submission,originals_root)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        rows=[{'image_id':identity,'business_sequence':event['sequence'],'binding':event['binding'],
               'business_request':event['request'],'business_receipt':event['receipt'],
               'status':'evidence_unknown','routes':[]}
              for event in attachment_events(submission) for identity in event['images']]
        return {'schema_version':VERSION,'task_id':submission.get('task_id'),
                'session_id':submission.get('runtime_metadata',{}).get('session_id'),
                'capture_root':str(Path(root).resolve()),'originals_root':str(Path(originals_root).resolve()),
                'complete':False,'status':'evidence_unknown','requests':[],'attachments':rows,
                'issues':[f'{type(exc).__name__}: {exc}'],'provider_internal_processing_observable':False}


def legacy_primary_resolves_active_checks(evidence, submission):
    """All registered active gates, including legitimate zeroes, retain v4.

    Unrelated unresolved payloads do not opt accepted scoring inputs into a new
    reader. Use the formal scoring bindings and policies, never aggregate score.
    """
    from benchmark.evaluator.visual_evidence import judge_visual_evidence
    from benchmark.evaluator.visual_policy import score_visual_policy
    registry = json.loads((Path(__file__).resolve().parents[2] /
        'benchmark/evaluator/visual_check_registry.json').read_text())
    entries = registry.get('tasks', {}).get(submission.get('task_id'), {})
    for entry in entries.values():
        if entry.get('policy'):
            result = score_visual_policy(evidence, submission, entry.get('binding'), entry['policy'])
        else:
            result = judge_visual_evidence(evidence, submission, entry.get('binding'))
        if result.get('status') == 'evidence_unknown':
            return False
    return True

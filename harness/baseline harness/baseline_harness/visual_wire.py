"""Runner-owned observation of actual provider HTTP bytes; no headers stored."""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
import uuid
from benchmark.services.http_compression import decoded_body, request_diagnostics


@contextmanager
def capture_json_http(path: Path, endpoint: str, credential: str, *, component: str):
    """Observe one endpoint, preserving response bytes, exceptions and retries."""
    original = urllib.request.urlopen
    def append(record):
        path.parent.mkdir(parents=True, exist_ok=True)
        value = json.dumps(record, ensure_ascii=False)
        if credential:
            value = value.replace(credential, '[REDACTED]')
        with path.open('a', encoding='utf-8') as stream:
            stream.write(value+'\n')
    def observed(request, *args, **kwargs):
        if not isinstance(request, urllib.request.Request) or request.full_url != endpoint:
            return original(request, *args, **kwargs)
        wire_data = request.data or b''
        data = decoded_body(wire_data, request.headers)
        text = data.decode('utf-8')
        body = json.loads(text)
        record = {**request_diagnostics(wire_data, request.headers),
                  'schema_version':'camact.visual_wire.v1','request_id':uuid.uuid4().hex,
                  'model':body.get('model'),'component':component,'request_body':text,
                  'request_sha256':hashlib.sha256(data).hexdigest(),
                  'started_at':time.time(),'success':False,'response_encoding':'original_http_json'}
        append({**record,'capture_stage':'started'})
        def finish(response_bytes, success, **fields):
            reply = response_bytes.decode('utf-8', errors='replace')
            record.update(response_body=reply,response_sha256=hashlib.sha256(response_bytes).hexdigest(),
                          completed_at=time.time(),success=success,**fields)
            if credential and (credential in text or credential in reply):
                record.update(success=False,capture_incomplete_reason='credential redaction')
            append({**record,'capture_stage':'completed'})
        try:
            response = original(request, *args, **kwargs)
        except urllib.error.HTTPError as exc:
            # HTTPError is also the caller's readable response. Observe its
            # existing read path without consuming, replacing or suppressing
            # the exception; the provider's error payload may contain Usage.
            chunks = []
            status_code = exc.code
            error_type = type(exc).__name__
            append({**record, 'capture_stage':'started', 'exception_type':error_type,
                    'http_status':status_code, 'capture_incomplete_reason':'http_error_body_not_observed'})
            def wrap_read(original_read):
                def read(*read_args, **read_kwargs):
                    chunk = original_read(*read_args, **read_kwargs)
                    chunks.append(chunk)
                    finish(b''.join(chunks), False, exception_type=error_type, http_status=status_code,
                           capture_incomplete_reason=None)
                    return chunk
                return read
            for method in ('read', 'read1', 'readline'):
                if hasattr(exc, method):
                    setattr(exc, method, wrap_read(getattr(exc, method)))
            raise
        except Exception as exc:
            finish(b'',False,exception_type=type(exc).__name__,http_status=getattr(exc,'code',None))
            raise
        class ObservedResponse:
            def __init__(self): self.chunks=[]
            def __enter__(self):
                response.__enter__()
                return self
            def read(self,*read_args,**read_kwargs):
                result=response.read(*read_args,**read_kwargs)
                self.chunks.append(result)
                return result
            def __getattr__(self,name): return getattr(response,name)
            def __exit__(self,exc_type,exc,tb):
                try:
                    return response.__exit__(exc_type,exc,tb)
                finally:
                    raw=b''.join(self.chunks)
                    try: valid=isinstance(json.loads(raw),dict)
                    except (ValueError,UnicodeError): valid=False
                    code=int(getattr(response,'status',200))
                    finish(raw,exc_type is None and valid and 200<=code<300,http_status=code)
        return ObservedResponse()
    urllib.request.urlopen=observed
    try:
        yield
    finally:
        urllib.request.urlopen=original

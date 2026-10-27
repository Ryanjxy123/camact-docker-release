"""Run the unchanged canonical Baseline with trusted observation adapters.

Observation is installed before importing the canonical entrypoint.  The
wrapper neither chooses tools nor changes the canonical agent transcript.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import runpy
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'benchmark'),str(ROOT),str(Path(__file__).resolve().parents[1])]
from baseline_harness.visual_wire import capture_json_http


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    def argument(flag): return argv[argv.index(flag)+1]
    session=Path(argument('--session-dir')).resolve()
    simulator_key_env=argument('--simulator-api-key-env')
    from benchmark_runner import mllm_adapter as provider
    from benchmark_runner import run_task
    original_request=provider._json_request
    original_resolve=provider.resolve_provider_config
    def resolve_role(**kwargs):
        # Canonical CLI has no simulator-provider flag. Bind only that role's
        # existing adapter configuration; do not replace its generation loop.
        if kwargs.get('api_key_env') == simulator_key_env:
            kwargs['provider']=os.environ.get('CAMACT_BASELINE_SIMULATOR_PROVIDER', kwargs['provider'])
        return original_resolve(**kwargs)
    def observed_request(url,body,headers,config,**kwargs):
        component=kwargs.get('component','agent_model')
        if component=='agent_model':
            body={**body,**json.loads(os.environ.get('CAMACT_BASELINE_AGENT_PARAMETERS','{}'))}
        filename='simulator_provider_wire.jsonl' if component=='simulator_model' else 'visual_wire.jsonl'
        with capture_json_http(session/filename,url,config.api_key,component=component):
            return original_request(url,body,headers,config,**kwargs)
    provider._json_request=observed_request
    provider.resolve_provider_config=resolve_role
    original_evaluate=run_task.evaluate
    def observed_evaluate(task_dir,submission,state,*args,**kwargs):
        from benchmark.services.api import raw_root
        from evaluation.camact_eval.visual_capture import collect_visual_evidence
        evidence=collect_visual_evidence(session,submission,raw_root(task_dir)/'images')
        # A derived evaluator input only; never alter the persisted Episode.
        endpoint=os.environ.get('CAMACT_JUDGE_BASE_URL','').rstrip('/')
        if endpoint and not endpoint.endswith('/v1'):
            endpoint+='/v1'
        credential=os.environ.get(os.environ.get('CAMACT_JUDGE_API_KEY_ENV','CAMACT_JUDGE_API_KEY'),'')
        if endpoint and credential:
            with capture_json_http(session/'judge_provider_wire.jsonl',endpoint+'/chat/completions',credential,component='judge_model'):
                return original_evaluate(task_dir,{**submission,'visual_evidence':evidence},state,*args,**kwargs)
        return original_evaluate(task_dir,{**submission,'visual_evidence':evidence},state,*args,**kwargs)
    run_task.evaluate=observed_evaluate
    canonical=ROOT/'benchmark/benchmark_runner/run_model.py'
    previous_argv=sys.argv
    try:
        sys.argv=[str(canonical),*argv]
        runpy.run_path(str(canonical),run_name='__main__')
    finally:
        sys.argv=previous_argv
        provider._json_request=original_request
        provider.resolve_provider_config=original_resolve
        run_task.evaluate=original_evaluate


if __name__=='__main__':
    main()

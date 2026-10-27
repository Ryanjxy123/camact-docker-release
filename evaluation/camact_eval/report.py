"""Human-readable CamAct completion reporting, independent of legacy aliases."""
from __future__ import annotations
import json
from benchmark.evaluator.dimensions import DIMENSION_LABELS

LABELS=(('safety_pass','Safety Pass'),('final_state_success','Final-State Success'),('semantic_completion','Semantic Completion'),('overall_task_success','Overall Task Success'))
CAPABILITIES=(('retrieval','Retrieval'),('inspection','Inspection'),('evidence_grounding','Evidence Grounding'),('semantic_role','Semantic Role'),('output_communication','Output / Communication'),('final_state','Final State'))

def status(value):return 'PASS' if value is True else 'FAIL' if value is False else 'NOT EVALUATED'
def number(value):return 'N/A' if value is None else f'{value:.4f}'

def render_evaluation(document):
    summary=document['summary'];lines=['# CamAct Evaluation','']
    for field,label in LABELS:
        value=summary.get(field+'_rate');text='N/A' if value is None else f'{100*value:.2f}%'
        lines.append(f"{label} Rate: {text} (evaluated {summary.get(field+'_evaluated_tasks',0)}, unknown {summary.get(field+'_unknown_tasks',summary.get('total_tasks',0))})  ")
    lines.extend(['',f"Completion / Mean Capability: {number(summary.get('mean_capability'))}",'','Completion dimensions (applicable scored tasks only; no second weighting)',''])
    for field,label in DIMENSION_LABELS.items():
        group=summary.get('completion_dimensions',{}).get(field,{})
        lines.append(f"- {label}: {number(group.get('score'))} (evaluated {group.get('evaluated_tasks',0)})")
    lines.extend(['','Legacy capability breakdown (recorded fields only)',''])
    for field,label in CAPABILITIES:lines.append(f"- {label}: {number(summary.get('capability_breakdown',{}).get(field))}")
    for key,label in [('by_category','Category'),('by_interaction','Interaction'),('by_user','User')]:
        lines.extend(['',f'## {label} slices','', '| Slice | Safety | Final-State | Semantic | Overall | Mean Capability |','|---|---:|---:|---:|---:|---:|'])
        for name,values in sorted(summary.get(key,{}).items()):
            rates=[number(values.get(field+'_rate')) for field,_ in LABELS]
            lines.append('| '+str(name)+' | '+' | '.join(rates+[number(values.get('mean_capability'))])+' |')
    for result in document.get('evaluations',[]):
        lines.extend(['',f"## Task: {result['task_id']}",''])
        for field,label in LABELS:lines.append(f'{label}: {status(result.get(field))}  ')
        lines.extend([f"Capability: {number(result.get('capability_score'))}",'','Failure Details:',''])
        for field,label in DIMENSION_LABELS.items():
            lines.append(f"- {label}: {number(result.get('completion_dimensions',{}).get(field,{}).get('score'))}")
        failures=[]
        for failure in result.get('failure_reason',[]):
            if failure.get('type')!='criterion_failure':failures.append(failure)
        failures.extend(result.get('completion_failure_details',[]))
        for failure in failures:lines.append('- '+json.dumps(failure,ensure_ascii=False))
        if not failures:lines.append('- No failed evaluated hard constraints.')
        if result.get('semantic_completion') is None:lines.append('- Semantic completion was not established: '+str(result.get('semantic_completion_status','not evaluated'))+'.')
    return '\n'.join(lines)+'\n'

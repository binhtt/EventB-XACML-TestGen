"""Rerun the three datasets and verify deterministic recorded counts."""
import argparse,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
FIELDS=['rules','policies','domain_requests','reference_evaluations','selected_test_evaluations','unique_request_values','mutants','killed','equivalent_finite']
def main(output):
    out=Path(output).resolve();out.mkdir(parents=True,exist_ok=True)
    commands=[('fms_results',['fms_experiment.py','inputs/FMS.json']),('hacs_results',['hacs_experiment.py','inputs/HACS.json','inputs/HACS_memberships.json']),('sis_results',['hacs_experiment.py','inputs/SIS.json','inputs/SIS_memberships.json','--dataset','SIS'])]
    for name,args in commands:
        subprocess.run([sys.executable,*args,'--output',str(out/name)],cwd=ROOT,check=True)
        actual=json.loads((out/name/'summary.json').read_text());expected=json.loads((ROOT/'results'/name/'summary.json').read_text())
        differences={f:(expected[f],actual[f]) for f in FIELDS if actual[f]!=expected[f]}
        if differences:raise RuntimeError(f'{name}: recorded/reproduced mismatch {differences}')
        print(name+': recorded counts reproduced',flush=True)
    print('All three datasets reproduced successfully.')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',default='reproduced');main(p.parse_args().output)

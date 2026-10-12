"""Read native Rodin XML; structural extraction only, not an Event-B interpreter."""
import argparse,json,hashlib
from pathlib import Path
import xml.etree.ElementTree as E
P='org.eventb.core.'
def attrs(e):return {k.removeprefix(P):v.replace('\\r\\n','\n') for k,v in e.attrib.items()}
def children(e,kind):return [attrs(x) for x in e if x.tag==P+kind]
def inspect(root):
    result={'scope':'Native XML structural extraction; stored proof-status audit; not proof replay or Event-B execution','contexts':[],'machines':[],'proof_status':[],'source_files':[]}
    for path in sorted(Path(root).rglob('*')):
        if path.suffix not in ['.buc','.bum','.bps']:continue
        tree=E.parse(path).getroot()
        result['source_files'].append({'file':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        if path.suffix=='.buc':
            result['contexts'].append({'name':path.stem,'sets':children(tree,'carrierSet'),'constants':children(tree,'constant'),'axioms':children(tree,'axiom'),'extends':children(tree,'extendsContext')})
        elif path.suffix=='.bum':
            events=[]
            for el in tree:
                if el.tag==P+'event':events.append({**attrs(el),'parameters':children(el,'parameter'),'guards':children(el,'guard'),'actions':children(el,'action'),'refines':children(el,'refinesEvent')})
            result['machines'].append({'name':path.stem,'refines':children(tree,'refinesMachine'),'sees':children(tree,'seesContext'),'invariants':children(tree,'invariant'),'events':events})
        else:
            states=children(tree,'psStatus');high=sum(s.get('confidence')=='1000' for s in states);broken=sum(s.get('psBroken')=='true' for s in states)
            result['proof_status'].append({'component':path.stem,'stored_status_entries':len(states),'confidence_1000':high,'confidence_0':sum(s.get('confidence')=='0' for s in states),'broken':broken,'manual_flag':sum(s.get('psManual')=='true' for s in states),'entries':states})
    return result
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('project');ap.add_argument('--output',default='rodin_audit.json');args=ap.parse_args()
    data=inspect(args.project);Path(args.output).write_text(json.dumps(data,ensure_ascii=False,indent=2))
    print(json.dumps([{k:v for k,v in x.items() if k!='entries'} for x in data['proof_status']],indent=2))

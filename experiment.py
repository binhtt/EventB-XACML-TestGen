"""Finite-domain pilot. NOT a Rodin/ProB importer or production PDP benchmark."""
import argparse, copy, csv, hashlib, itertools, json, platform, random, statistics, time
from pathlib import Path
import xml.etree.ElementTree as E
NS='urn:oasis:names:tc:xacml:3.0:core:schema:wd-17'
FN='urn:oasis:names:tc:xacml:1.0:function:'
ALG='urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:'
CAT='urn:oasis:names:tc:xacml:3.0:attribute-category:environment'
DOMAIN=list(itertools.product(range(4),range(4),range(21)))
ALGS=['deny-overrides','permit-overrides','first-applicable']
OPS={'eq':lambda a,b:a==b,'lt':lambda a,b:a<b,'le':lambda a,b:a<=b,'ge':lambda a,b:a>=b}
FUN={'eq':'integer-equal','lt':'integer-less-than','le':'integer-less-than-or-equal','ge':'integer-greater-than-or-equal'}
def make_policy(n,alg,seed):
    rng=random.Random(seed)
    return {'id':f'SYN_{n}_{alg}_{seed}','algorithm':alg,'rules':[
      {'id':f'R{i}', 'effect':rng.choice(['Permit','Deny']), 'predicates':[
      ['role','eq',rng.randrange(4)],['resource','eq',rng.randrange(4)],
      ['amount',rng.choice(['lt','le','ge']),rng.randrange(1,20)]]} for i in range(n)]}
def applicable(p,q):
    vals=dict(zip(['role','resource','amount'],q))
    return tuple(all(OPS[op](vals[k],v) for k,op,v in r['predicates']) for r in p['rules'])
def decision(p,q):
    a=applicable(p,q); effects=[r['effect'] for r,b in zip(p['rules'],a) if b]
    if not effects:return 'NotApplicable'
    if p['algorithm']=='first-applicable':return effects[0]
    preferred='Deny' if p['algorithm']=='deny-overrides' else 'Permit'
    return preferred if preferred in effects else effects[0]
def sub(parent,tag,attrs=None,text=None):
    el=E.SubElement(parent,'{'+NS+'}'+tag,attrs or {}); el.text=text; return el
def policy_xml(p):
    root=E.Element('{'+NS+'}Policy',{'PolicyId':p['id'],'Version':'1.0','RuleCombiningAlgId':ALG+p['algorithm']})
    sub(root,'Target')
    for r in p['rules']:
        rr=sub(root,'Rule',{'RuleId':r['id'],'Effect':r['effect']});sub(rr,'Target')
        cond=sub(rr,'Condition'); conjunction=sub(cond,'Apply',{'FunctionId':FN+'and'})
        for key,op,value in r['predicates']:
            app=sub(conjunction,'Apply',{'FunctionId':FN+FUN[op]})
            one=sub(app,'Apply',{'FunctionId':FN+'integer-one-and-only'})
            sub(one,'AttributeDesignator',{'AttributeId':'urn:test:'+key,'Category':CAT,'DataType':'http://www.w3.org/2001/XMLSchema#integer','MustBePresent':'true'})
            sub(app,'AttributeValue',{'DataType':'http://www.w3.org/2001/XMLSchema#integer'},str(value))
    return root
def request_xml(q):
    root=E.Element('{'+NS+'}Request',{'ReturnPolicyIdList':'false','CombinedDecision':'false'})
    attrs=sub(root,'Attributes',{'Category':CAT})
    for k,v in zip(['role','resource','amount'],q):
        a=sub(attrs,'Attribute',{'AttributeId':'urn:test:'+k,'IncludeInResult':'false'})
        sub(a,'AttributeValue',{'DataType':'http://www.w3.org/2001/XMLSchema#integer'},str(v))
    return root
# Separate XML evaluator for this generated subset; not an external PDP.
def tag(el):return el.tag.split('}')[-1]
def eval_expr(el,values):
    name=tag(el)
    if name=='AttributeValue':return int(el.text)
    if name=='AttributeDesignator':return [values[el.attrib['AttributeId']]]
    if name!='Apply':raise ValueError('unsupported expression: '+name)
    fn=el.attrib['FunctionId'].split(':')[-1];args=[eval_expr(c,values) for c in el]
    if fn=='and':return all(args)
    if fn=='integer-one-and-only':
        if len(args[0])!=1:raise ValueError('non-singleton bag')
        return args[0][0]
    if fn=='integer-equal':return args[0]==args[1]
    if fn=='integer-less-than':return args[0]<args[1]
    if fn=='integer-less-than-or-equal':return args[0]<=args[1]
    if fn=='integer-greater-than-or-equal':return args[0]>=args[1]
    raise ValueError('unsupported function: '+fn)
def xml_decision(policy,request):
    values={a.attrib['AttributeId']:int(next(iter(a)).text) for group in request for a in group}
    outcomes=[]
    for rule in policy:
        if tag(rule)!='Rule':continue
        cond=next(c for c in rule if tag(c)=='Condition')
        if eval_expr(next(iter(cond)),values):outcomes.append(rule.attrib['Effect'])
    alg=policy.attrib['RuleCombiningAlgId'].split(':')[-1]
    if not outcomes:return 'NotApplicable'
    if alg=='first-applicable':return outcomes[0]
    if alg=='deny-overrides':return 'Deny' if 'Deny' in outcomes else 'Permit'
    if alg=='permit-overrides':return 'Permit' if 'Permit' in outcomes else 'Deny'
    raise ValueError('unsupported algorithm')
def objective_sets(p):
    apps=[applicable(p,q) for q in DOMAIN];dec=[decision(p,q) for q in DOMAIN]
    rule={};event={};combo={};boundary={};influence={}
    for j,q in enumerate(DOMAIN):
        for i,a in enumerate(apps[j]):rule.setdefault(f'R{i}:{a}',set()).add(j)
        event.setdefault(dec[j],set()).add(j)
        effects={r['effect'] for r,a in zip(p['rules'],apps[j]) if a}
        key=','.join(sorted(effects)) or 'empty';combo.setdefault(key,set()).add(j)
        for i,r in enumerate(p['rules']):
            # Predicate boundary with the other two predicates satisfied.
            k,op,v=r['predicates'][2]
            if q[0]==r['predicates'][0][2] and q[1]==r['predicates'][1][2] and q[2] in [v-1,v,v+1]:
                boundary.setdefault(f'R{i}:amount={q[2]}',set()).add(j)
    for i in range(len(p['rules'])):
        groups={}
        for j,a in enumerate(apps):
            key=a[:i]+a[i+1:];groups.setdefault(key,[]).append(j)
        pairs=[]
        for indices in groups.values():
            for x,y in itertools.combinations(indices,2):
                if apps[x][i]!=apps[y][i] and dec[x]!=dec[y]:pairs.append((x,y))
        if pairs:influence[f'R{i}']=pairs
    return rule,event,combo,boundary,influence

def select_single(objectives):
    chosen=set()
    for witnesses in objectives.values():
        if not chosen.intersection(witnesses):chosen.add(min(witnesses))
    return chosen
def guided(objs):
    rule,event,combo,boundary,influence=objs
    s=select_single(rule)
    for group in (event,combo,boundary):
        for w in group.values():
            if not s.intersection(w):s.add(min(w))
    for pairs in influence.values():
        if not any(x in s and y in s for x,y in pairs):
            x,y=min(pairs,key=lambda pair:(len(set(pair)-s),pair));s.update([x,y])
    return s
def coverage(s,obj,pairs=False):
    if not obj:return None
    return 100*sum(any(x in s and y in s for x,y in w) if pairs else bool(s.intersection(w)) for w in obj.values())/len(obj)
def mutants(p):
    out=[]
    for i,r in enumerate(p['rules']):
        m=copy.deepcopy(p);m['rules'][i]['effect']='Deny' if r['effect']=='Permit' else 'Permit';out.append(('effect',m))
        m=copy.deepcopy(p);m['rules'].pop(i);out.append(('remove',m))
        m=copy.deepcopy(p);pr=m['rules'][i]['predicates'][2];pr[1]={'lt':'le','le':'lt','ge':'lt'}[pr[1]];out.append(('comparison',m))
        m=copy.deepcopy(p);m['rules'][i]['predicates'][0][2]=(r['predicates'][0][2]+1)%4;out.append(('target_value',m))
    for alg in ALGS:
        if alg!=p['algorithm']:
            m=copy.deepcopy(p);m['algorithm']=alg;out.append(('algorithm',m))
    if p['algorithm']=='first-applicable':
        for i in range(len(p['rules'])-1):
            m=copy.deepcopy(p);m['rules'][i],m['rules'][i+1]=m['rules'][i+1],m['rules'][i];out.append(('order',m))
    return out

def main(output):
    out=Path(output);out.mkdir(parents=True,exist_ok=True);records=[];characteristics=[];runs=[];mutation_rows=[]
    for n in [8,16,32,64]:
      for ai,alg in enumerate(ALGS):
        p=make_policy(n,alg,730+n+ai);name=p['id'];folder=out/name;folder.mkdir(exist_ok=True)
        (folder/'model.json').write_text(json.dumps(p,indent=2))
        E.ElementTree(policy_xml(p)).write(folder/'policy.xml',encoding='utf-8',xml_declaration=True)
        start=time.perf_counter();objs=objective_sets(p);objective_time=time.perf_counter()-start
        expected=[decision(p,q) for q in DOMAIN]
        parsed=E.parse(folder/'policy.xml').getroot()
        agreement=sum(xml_decision(parsed,E.fromstring(E.tostring(request_xml(q))))==d for q,d in zip(DOMAIN,expected))
        assert agreement==len(DOMAIN)
        mm=mutants(p);kills=[];equivalent=0
        for typ,m in mm:
            root=E.fromstring(E.tostring(policy_xml(m)))
            differing={j for j,q in enumerate(DOMAIN) if xml_decision(root,request_xml(q))!=expected[j]}
            kills.append((typ,differing));equivalent+=not differing
        start=time.perf_counter();full=guided(objs);select_time=time.perf_counter()-start
        suites={'Event':select_single(objs[1]),'Rule':select_single(objs[0]),'Proposed':full}
        for seed in range(30):suites[f'Random:{seed}']=set(random.Random(seed).sample(range(len(DOMAIN)),len(full)))
        for method,s in suites.items():
            killed=sum(bool(s.intersection(w)) for _,w in kills)
            row={'policy':name,'rules':n,'algorithm':alg,'method':method.split(':')[0], 'seed':method.split(':')[1] if ':' in method else '', 'requests':len(s),'rule_cov':coverage(s,objs[0]),'event_cov':coverage(s,objs[1]),'combining_cov':coverage(s,objs[2]),'boundary_cov':coverage(s,objs[3]),'influence_cov':coverage(s,objs[4],True),'mutants':len(kills),'equivalent_finite':equivalent,'killed':killed,'raw_ms':100*killed/len(kills),'adjusted_ms':100*killed/(len(kills)-equivalent) if len(kills)>equivalent else None}
            runs.append(row)
            if method=='Proposed':
                tests=[]
                for j in sorted(s):
                    E.ElementTree(request_xml(DOMAIN[j])).write(folder/f'request_{j}.xml',encoding='utf-8',xml_declaration=True)
                    tests.append({'index':j,'request':DOMAIN[j],'expected':expected[j]})
                (folder/'tests.json').write_text(json.dumps(tests,indent=2))
            for typ in sorted({t for t,_ in kills}):
                selected=[w for t,w in kills if t==typ]
                mutation_rows.append({'policy':name,'method':row['method'],'seed':row['seed'],'operator':typ,'mutants':len(selected),'killed':sum(bool(s.intersection(w)) for w in selected)})
        characteristics.append({'policy':name,'rules':n,'predicates':3*n,'domain':len(DOMAIN),'feasible_rule_objectives':len(objs[0]),'feasible_combining_cases':len(objs[2]),'feasible_influence_rules':len(objs[4]),'xml_agreement':agreement,'objective_time_s':objective_time,'proposed_selection_s':select_time})
        print(name,len(full),len(mm),agreement,flush=True)
    for fn,rows in [('runs.csv',runs),('characteristics.csv',characteristics),('mutation_operators.csv',mutation_rows)]:
        with (out/fn).open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    metadata={'python':platform.python_version(),'platform':platform.platform(),'domain':{'role':[0,3],'resource':[0,3],'amount':[0,20]},'random_seeds':list(range(30)),'policies':12,'scope':'synthetic finite-domain pilot; XML subset evaluator; no Rodin verification, no ProB, no external PDP', 'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2))
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='results');main(ap.parse_args().output)

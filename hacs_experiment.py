"""Concrete HACS fragment pilot. Generated bindings remain unverified."""
import argparse,csv,hashlib,itertools,json,re,time
from pathlib import Path
import xml.etree.ElementTree as E
from experiment import NS,FN,ALG,sub,tag,select_single
from fms_experiment import P,CATS,STR,xml_evaluate
CATS['resource']='urn:oasis:names:tc:xacml:3.0:attribute-category:resource'
KEYS=['role','resource','action']
ATTR_PREFIX='urn:hacs:'

def load(source,members,dataset='HACS'):
    data=json.loads(Path(source).read_text());rules={}
    for row in data[dataset]:
        r=E.fromstring(row['xacml_policy'])
        if r.tag!='PolicyRule' or r.get('RuleId')!=row['rule_id']:raise ValueError('unsupported rule fragment')
        paths=['Target/Subjects/Subject','Target/Resources/Resource','Target/Actions/Action']
        values=[r.findtext(x) for x in paths]
        if any(v is None for v in values):raise ValueError('missing target')
        if r.find('Condition') is not None:raise ValueError('unsupported condition')
        rules[row['rule_id']]={**dict(zip(KEYS,values)),'effect':r.get('Effect')}
        if r.get('Effect') not in ['Permit','Deny']:raise ValueError('unsupported effect')
    entries=json.loads(Path(members).read_text())[dataset];policies={}
    for e in entries:
        if not set(e['rules_included'])<=set(rules):raise ValueError('unknown rule')
        policies[e['policy_id']]={'rules':e['rules_included'],'algorithm':'deny-overrides'}
    if set(i for p in policies.values() for i in p['rules'])!=set(rules):raise ValueError('membership fails to cover rule set')
    return rules,policies

def bindings(rules,policies,path):
    root=E.Element(P+'contextFile',{'version':'3'});E.SubElement(root,P+'extendsContext',{'name':'ext',P+'target':'XACML_Refined1_Context'})
    domains={k:sorted({r[k] for r in rules.values()})+['Other_'+k] for k in KEYS}
    # Attribute strings are mapped to separate Event-B identifiers.
    maps={k:{v:f'{k}_v{i}' for i,v in enumerate(domains[k])} for k in KEYS}
    constants=[v for m in maps.values() for v in m.values()]+list(rules)+list(policies)+['HEnv0','HPS0']
    for i,c in enumerate(constants):E.SubElement(root,P+'constant',{'name':f'c{i}',P+'identifier':c})
    exprs=[]
    def part(name,values):return 'partition('+name+', '+', '.join('{'+v+'}' for v in values)+')'
    for k,name in zip(KEYS,['SUBJECT','RESOURCE','ACTION']):exprs.append(part(name,list(maps[k].values())))
    exprs+=[part('ENVIRONMENT',['HEnv0']),part('RULE',list(rules)),part('POLICY',list(policies)),part('POLICY_SET',['HPS0'])]
    exprs.append('target = {'+', '.join(rid+' ↦ ({'+maps['role'][r['role']]+'} × {'+maps['resource'][r['resource']]+'} × {'+maps['action'][r['action']]+'} × ENVIRONMENT)' for rid,r in rules.items())+'}')
    exprs.append('effect = {'+', '.join(rid+' ↦ '+r['effect'] for rid,r in rules.items())+'}')
    exprs.append('condition = (λr·r ∈ RULE | (λq·q ∈ SUBJECT × RESOURCE × ACTION × ENVIRONMENT | TRUE))')
    exprs.append('policies = {'+', '.join(pid+' ↦ {'+', '.join(pol['rules'])+'}' for pid,pol in policies.items())+'}')
    exprs.append('policy_target = (λp·p ∈ POLICY | SUBJECT × RESOURCE × ACTION × ENVIRONMENT)')
    exprs.append('policy_set_target = (λps·ps ∈ POLICY_SET | SUBJECT × RESOURCE × ACTION × ENVIRONMENT)')
    exprs.append('policy_set_policies = {HPS0 ↦ POLICY}')
    exprs.append('combining_alg_policy = (λp·p ∈ POLICY | DenyOverrides)')
    exprs.append('combining_alg_policyset = {HPS0 ↦ DenyOverrides}')
    exprs.append('rule_order = (λp·p ∈ POLICY | {'+', '.join(rid+' ↦ '+str(i) for i,rid in enumerate(rules,1))+'})')
    for i,expr in enumerate(exprs):E.SubElement(root,P+'axiom',{'name':f'a{i}',P+'label':f'bind{i}',P+'predicate':expr,P+'theorem':'false'})
    E.ElementTree(root).write(path,encoding='utf-8',xml_declaration=True)
    (path.parent/'attribute_encoding.json').write_text(json.dumps(maps,indent=2))

def read_bindings(path):
    expr=[e.attrib[P+'predicate'] for e in E.parse(path).getroot() if e.tag==P+'axiom']
    def find(prefix):
        x=[s for s in expr if s.startswith(prefix)]
        if len(x)!=1:raise ValueError('missing/duplicate binding')
        return x[0]
    maps=json.loads((path.parent/'attribute_encoding.json').read_text());inverse={k:{v:s for s,v in m.items()} for k,m in maps.items()}
    domains=[]
    for k,name in zip(KEYS,['SUBJECT','RESOURCE','ACTION']):
        ids=re.findall(r'\{(\w+)\}',find('partition('+name+','));domains.append([inverse[k][i] for i in ids])
    effects=dict(re.findall(r'(\w+) ↦ (Permit|Deny)',find('effect = ')))
    matches=re.findall(r'(\w+) ↦ \(\{(\w+)\} × \{(\w+)\} × \{(\w+)\} × ENVIRONMENT\)',find('target = '))
    rules={rid:{'role':inverse['role'][s],'resource':inverse['resource'][r],'action':inverse['action'][a],'effect':effects[rid]} for rid,s,r,a in matches}
    pols={pid:{'rules':[r.strip() for r in rr.split(',') if r.strip()],'algorithm':'deny-overrides'} for pid,rr in re.findall(r'(\w+) ↦ \{([^}]*)\}',find('policies = '))}
    if set(rules)!=set(re.findall(r'\{(\w+)\}',find('partition(RULE,'))):raise ValueError('incomplete rules')
    if set(pols)!=set(re.findall(r'\{(\w+)\}',find('partition(POLICY,'))):raise ValueError('incomplete policies')
    if find('condition = ')!='condition = (λr·r ∈ RULE | (λq·q ∈ SUBJECT × RESOURCE × ACTION × ENVIRONMENT | TRUE))':raise ValueError('unsupported condition')
    if find('combining_alg_policy = ')!='combining_alg_policy = (λp·p ∈ POLICY | DenyOverrides)':raise ValueError('unsupported algorithm')
    return rules,pols,list(itertools.product(*domains))

def policy_xml(pid,pol,rules):
    root=E.Element('{'+NS+'}Policy',{'PolicyId':pid,'Version':'1.0','RuleCombiningAlgId':ALG+pol['algorithm']});sub(root,'Target')
    for rid in pol['rules']:
        r=rules[rid];rr=sub(root,'Rule',{'RuleId':rid,'Effect':r['effect']});t=sub(rr,'Target')
        for k in KEYS:
            a=sub(t,'AnyOf');b=sub(a,'AllOf');m=sub(b,'Match',{'MatchId':FN+'string-equal'})
            sub(m,'AttributeValue',{'DataType':STR},r[k]);sub(m,'AttributeDesignator',{'Category':CATS[k],'AttributeId':ATTR_PREFIX+k,'DataType':STR,'MustBePresent':'true'})
    return root

def request_xml(q):
    root=E.Element('{'+NS+'}Request',{'ReturnPolicyIdList':'false','CombinedDecision':'false'})
    for k,v in zip(KEYS,q):
        g=sub(root,'Attributes',{'Category':CATS[k]});a=sub(g,'Attribute',{'AttributeId':ATTR_PREFIX+k,'IncludeInResult':'false'});sub(a,'AttributeValue',{'DataType':STR},v)
    return root

def compile_xml(root):
    # Compile only the exact generated singleton-equality-target subset.
    rules=[]
    for r in root:
        if tag(r)!='Rule':continue
        target=next(x for x in r if tag(x)=='Target');vals={}
        for anyof in target:
            if len(anyof)!=1 or len(anyof[0])!=1:raise ValueError('unsupported target structure')
            m=anyof[0][0]
            if m.get('MatchId')!=FN+'string-equal':raise ValueError('unsupported match')
            value,des=list(m);k=des.attrib['AttributeId'].removeprefix(ATTR_PREFIX)
            if k not in KEYS or k in vals or des.get('Category')!=CATS[k]:raise ValueError('unsupported attribute')
            vals[k]=value.text
        if set(vals)!=set(KEYS):raise ValueError('incomplete target')
        rules.append((tuple(vals[k] for k in KEYS),r.attrib['Effect']))
    return root.attrib['RuleCombiningAlgId'].split(':')[-1],rules

def evaluate_xml(compiled,q):
    alg,rules=compiled;effects=[effect for values,effect in rules if values==q]
    if not effects:return 'NotApplicable'
    if alg=='deny-overrides':return 'Deny' if 'Deny' in effects else 'Permit'
    if alg=='permit-overrides':return 'Permit' if 'Permit' in effects else 'Deny'
    if alg=='first-applicable':return effects[0]
    raise ValueError('unsupported algorithm')

def reference(pol,rules,q):
    applicable=[rid for rid in pol['rules'] if all(rules[rid][k]==v for k,v in zip(KEYS,q))]
    if not applicable:return 'NotApplicable'
    return 'Deny' if any(rules[rid]['effect']=='Deny' for rid in applicable) else 'Permit'

def main(source,members,outdir,dataset='HACS'):
    global ATTR_PREFIX
    ATTR_PREFIX='urn:'+dataset.lower()+':'
    out=Path(outdir);out.mkdir(parents=True,exist_ok=True);rules,pols=load(source,members,dataset)
    bindings(rules,pols,out/(dataset+'_Concrete_Bindings.buc'));rr,pp,domain=read_bindings(out/(dataset+'_Concrete_Bindings.buc'));assert rr==rules and pp==pols
    rows=[];mutant_rows=[];alltests=[];qindex={q:j for j,q in enumerate(domain)}
    for pid,pol in pp.items():
        folder=out/pid;folder.mkdir(exist_ok=True);root=policy_xml(pid,pol,rr);E.ElementTree(root).write(folder/'policy.xml',encoding='utf-8',xml_declaration=True)
        compiled=compile_xml(E.parse(folder/'policy.xml').getroot());expected=[reference(pol,rr,q) for q in domain]
        assert all(evaluate_xml(compiled,q)==d for q,d in zip(domain,expected))
        start=time.perf_counter();obj={}
        for j,q in enumerate(domain):
            for rid in pol['rules']:
                app=all(rr[rid][k]==v for k,v in zip(KEYS,q));obj.setdefault(rid+':'+str(app),set()).add(j)
            obj.setdefault('decision:'+expected[j],set()).add(j)
        selected=select_single(obj);elapsed=time.perf_counter()-start
        # Validate serialized selected requests through the uncompiled XML evaluator as well.
        for j in selected:assert xml_evaluate(root,E.fromstring(E.tostring(request_xml(domain[j]))))==expected[j]
        mutants=[]
        for rid in pol['rules']:
            for typ in ['effect','remove','role_value','resource_value','action_value']:
                m=E.fromstring(E.tostring(root));rule=next(x for x in m if tag(x)=='Rule' and x.get('RuleId')==rid)
                if typ=='effect':rule.set('Effect','Deny' if rule.get('Effect')=='Permit' else 'Permit')
                elif typ=='remove':m.remove(rule)
                else:
                    key=typ.removesuffix('_value')
                    match=next(x for x in rule.iter() if tag(x)=='Match' and list(x)[1].get('AttributeId')==ATTR_PREFIX+key)
                    list(match)[0].text='Other_'+key
                mutants.append((typ,rid,m))
        for alg in ['permit-overrides','first-applicable']:
            m=E.fromstring(E.tostring(root));m.set('RuleCombiningAlgId',ALG+alg);mutants.append(('algorithm','',m))
        killed=equiv=0
        for typ,rid,m in mutants:
            c=compile_xml(m);diff={j for j,q in enumerate(domain) if evaluate_xml(c,q)!=expected[j]};detected=bool(selected.intersection(diff));killed+=detected;equiv+=not diff
            mutant_rows.append({'policy':pid,'operator':typ,'rule':rid,'killed':int(detected),'equivalent_finite':int(not diff)})
        tests=[]
        for j in sorted(selected):
            E.ElementTree(request_xml(domain[j])).write(folder/f'request_{j}.xml',encoding='utf-8',xml_declaration=True)
            tests.append({'policy':pid,'request':domain[j],'expected':expected[j],'index':j})
        alltests+=tests;(folder/'tests.json').write_text(json.dumps(tests,indent=2))
        rows.append({'policy':pid,'rules':len(pol['rules']),'domain_requests':len(domain),'xml_agree':len(domain),'generated_tests':len(selected),'feasible_objectives':len(obj),'coverage_percent':100,'generation_s':elapsed,'mutants':len(mutants),'killed':killed,'equivalent_finite':equiv,'raw_ms':100*killed/len(mutants),'adjusted_ms':100*killed/(len(mutants)-equiv) if len(mutants)>equiv else None})
    for filename,records in [(dataset.lower()+'_results.csv',rows),(dataset.lower()+'_mutants.csv',mutant_rows)]:
        with (out/filename).open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
    summary={'dataset':dataset,'rules':len(rr),'permit_rules':sum(r['effect']=='Permit' for r in rr.values()),'deny_rules':sum(r['effect']=='Deny' for r in rr.values()),'policies':len(pp),'domain_requests':len(domain),'reference_evaluations':sum(r['xml_agree'] for r in rows),'selected_test_evaluations':len(alltests),'unique_request_values':len({tuple(t['request']) for t in alltests}),'mutants':sum(r['mutants'] for r in rows),'killed':sum(r['killed'] for r in rows),'equivalent_finite':sum(r['equivalent_finite'] for r in rows),'source_sha256':hashlib.sha256(Path(source).read_bytes()).hexdigest(),'membership_sha256':hashlib.sha256(Path(members).read_bytes()).hexdigest(),'assumptions':['PolicyRule fragments normalized to singleton-equality XACML 3.0 targets',f'policy membership from public repository; all {len(rr)} rules accounted for','DenyOverrides assumed because combining algorithm absent from provided data','missing conditions are true; policy targets universal; environment singleton',f'{len(pp)} policies tested independently, no root PolicySet result','new concrete context not verified by Rodin','restricted binding parser; original machine events not executed','local compiled XML-subset evaluator, not independent PDP; no XSD validation']}
    (out/'summary.json').write_text(json.dumps(summary,indent=2));(out/'all_tests.json').write_text(json.dumps(alltests,indent=2));print(json.dumps(summary,indent=2))
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('source');ap.add_argument('membership');ap.add_argument('--output',default='hacs_results');ap.add_argument('--dataset',choices=['HACS','SIS'],default='HACS');a=ap.parse_args();main(a.source,a.membership,a.output,a.dataset)

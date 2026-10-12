"""Instantiate supplied shorthand, export concrete Event-B context, read it back.
Restricted parser of generated bindings; no general Event-B execution or proof replay.
"""
import argparse,csv,hashlib,itertools,json,re,time
from pathlib import Path
import xml.etree.ElementTree as E
from experiment import NS,FN,ALG,sub,tag,select_single
P='org.eventb.core.'
CATS={'role':'urn:oasis:names:tc:xacml:1.0:subject-category:access-subject','action':'urn:oasis:names:tc:xacml:3.0:attribute-category:action'}
STR='http://www.w3.org/2001/XMLSchema#string'

def normalize(source):
    data=json.loads(Path(source).read_text());rules={}
    for row in data['FMS_rules']:
        el=E.fromstring(row['xacml_policy']);target=el.find('Target');condition=el.find('Condition')
        if target is None or list(target):raise ValueError('expected text Target')
        m=re.fullmatch(r'(Role\d+)\s*/\s*(Action\d+)',(target.text or '').strip())
        if not m:raise ValueError('unsupported target shorthand')
        if condition is not None and ((condition.text or '').strip() or list(condition)):raise ValueError('nonempty condition is unsupported')
        rid=row['rule_id']
        if rid in rules or el.attrib['RuleId']!=rid:raise ValueError('rule identifier mismatch')
        rules[rid]={'role':m[1],'action':m[2],'effect':el.attrib['Effect']}
        if rules[rid]['effect'] not in ['Permit','Deny']:raise ValueError('unsupported effect')
    policies={}
    for row in data['FMS_policies']:
        if row['combining_alg']!='deny-overrides':raise ValueError('unsupported input algorithm')
        ids=row['rules_included']
        if not set(ids)<=set(rules):raise ValueError('unknown rule')
        policies[row['policy_id']]={'rules':ids,'algorithm':'deny-overrides'}
    return rules,policies

def write_binding_context(rules,policies,path):
    root=E.Element(P+'contextFile',{'version':'3'})
    E.SubElement(root,P+'extendsContext',{'name':'ext','org.eventb.core.target':'XACML_Refined1_Context'})
    roles=sorted({r['role'] for r in rules.values()})+['OtherRole'];actions=sorted({r['action'] for r in rules.values()})+['OtherAction']
    constants=roles+actions+list(rules)+list(policies)+['Res0','Env0','PS0']
    for i,c in enumerate(constants):E.SubElement(root,P+'constant',{'name':f'c{i}','org.eventb.core.identifier':c})
    expressions=[]
    def part(name,values):return 'partition('+name+', '+', '.join('{'+v+'}' for v in values)+')'
    expressions += [part('SUBJECT',roles),part('ACTION',actions),part('RESOURCE',['Res0']),part('ENVIRONMENT',['Env0']),part('RULE',list(rules)),part('POLICY',list(policies)),part('POLICY_SET',['PS0'])]
    expressions.append('target = {'+', '.join(rid+' ↦ ({'+r['role']+'} × RESOURCE × {'+r['action']+'} × ENVIRONMENT)' for rid,r in rules.items())+'}')
    expressions.append('effect = {'+', '.join(rid+' ↦ '+r['effect'] for rid,r in rules.items())+'}')
    expressions.append('condition = (λr·r ∈ RULE | (λq·q ∈ SUBJECT × RESOURCE × ACTION × ENVIRONMENT | TRUE))')
    expressions.append('policies = {'+', '.join(pid+' ↦ {'+', '.join(pol['rules'])+'}' for pid,pol in policies.items())+'}')
    expressions.append('policy_target = (λp·p ∈ POLICY | SUBJECT × RESOURCE × ACTION × ENVIRONMENT)')
    expressions.append('policy_set_target = (λps·ps ∈ POLICY_SET | SUBJECT × RESOURCE × ACTION × ENVIRONMENT)')
    expressions.append('policy_set_policies = {PS0 ↦ POLICY}')
    expressions.append('combining_alg_policy = (λp·p ∈ POLICY | DenyOverrides)')
    expressions.append('combining_alg_policyset = {PS0 ↦ DenyOverrides}')
    expressions.append('rule_order = (λp·p ∈ POLICY | {'+', '.join(rid+' ↦ '+str(i) for i,rid in enumerate(rules,1))+'})')
    for i,expr in enumerate(expressions):E.SubElement(root,P+'axiom',{'name':f'a{i}','org.eventb.core.label':f'bind{i}','org.eventb.core.predicate':expr,'org.eventb.core.theorem':'false'})
    E.ElementTree(root).write(path,encoding='utf-8',xml_declaration=True)

def read_binding_context(path):
    # Exact generated subset, with fail-closed guards; not a parser for arbitrary formulas.
    root=E.parse(path).getroot();exprs=[e.attrib[P+'predicate'] for e in root if e.tag==P+'axiom']
    def find(prefix):
        candidates=[s for s in exprs if s.startswith(prefix)]
        if len(candidates)!=1:raise ValueError('missing/duplicate binding '+prefix)
        return candidates[0]
    def enum(name):
        s=find('partition('+name+',');return re.findall(r'\{(\w+)\}',s)
    target=find('target = ');effect=find('effect = ');members=find('policies = ')
    targets=re.findall(r'(\w+) ↦ \(\{(\w+)\} × RESOURCE × \{(\w+)\} × ENVIRONMENT\)',target)
    effects=dict(re.findall(r'(\w+) ↦ (Permit|Deny)',effect))
    rules={rid:{'role':role,'action':action,'effect':effects[rid]} for rid,role,action in targets}
    policies={pid:{'rules':[r.strip() for r in ids.split(',') if r.strip()],'algorithm':'deny-overrides'} for pid,ids in re.findall(r'(\w+) ↦ \{([^}]*)\}',members)}
    if set(rules)!=set(enum('RULE')) or set(policies)!=set(enum('POLICY')):raise ValueError('incomplete concrete binding')
    if find('condition = ')!='condition = (λr·r ∈ RULE | (λq·q ∈ SUBJECT × RESOURCE × ACTION × ENVIRONMENT | TRUE))':raise ValueError('unsupported condition')
    if find('combining_alg_policy = ')!='combining_alg_policy = (λp·p ∈ POLICY | DenyOverrides)':raise ValueError('unsupported combination')
    if find('policy_target = ')!='policy_target = (λp·p ∈ POLICY | SUBJECT × RESOURCE × ACTION × ENVIRONMENT)':raise ValueError('unsupported policy targets')
    return rules,policies,list(itertools.product(enum('SUBJECT'),enum('ACTION')))

def policy_xml(pid,pol,rules):
    root=E.Element('{'+NS+'}Policy',{'PolicyId':pid,'Version':'1.0','RuleCombiningAlgId':ALG+pol['algorithm']});sub(root,'Target')
    for rid in pol['rules']:
        r=rules[rid];rr=sub(root,'Rule',{'RuleId':rid,'Effect':r['effect']});target=sub(rr,'Target')
        for key in ['role','action']:
            anyof=sub(target,'AnyOf');allof=sub(anyof,'AllOf');match=sub(allof,'Match',{'MatchId':FN+'string-equal'})
            sub(match,'AttributeValue',{'DataType':STR},r[key]);sub(match,'AttributeDesignator',{'Category':CATS[key],'AttributeId':'urn:fms:'+key,'DataType':STR,'MustBePresent':'true'})
    return root

def request_xml(q):
    root=E.Element('{'+NS+'}Request',{'ReturnPolicyIdList':'false','CombinedDecision':'false'})
    for key,val in zip(['role','action'],q):
        group=sub(root,'Attributes',{'Category':CATS[key]});attr=sub(group,'Attribute',{'AttributeId':'urn:fms:'+key,'IncludeInResult':'false'});sub(attr,'AttributeValue',{'DataType':STR},val)
    return root

def xml_evaluate(root,req):
    vals={(g.attrib['Category'],a.attrib['AttributeId']):[v.text for v in a] for g in req for a in g}
    outcomes=[]
    for r in root:
        if tag(r)!='Rule':continue
        target=next(x for x in r if tag(x)=='Target')
        matches=True
        for anyof in target:
            alternatives=[]
            for allof in anyof:
                terms=[]
                for match in allof:
                    if match.attrib['MatchId']!=FN+'string-equal':raise ValueError('unsupported match')
                    value,designator=list(match)
                    terms.append(value.text in vals[(designator.attrib['Category'],designator.attrib['AttributeId'])])
                alternatives.append(all(terms))
            matches=matches and any(alternatives)
        if matches:outcomes.append(r.attrib['Effect'])
    alg=root.attrib['RuleCombiningAlgId'].split(':')[-1]
    if not outcomes:return 'NotApplicable'
    if alg=='first-applicable':return outcomes[0]
    if alg=='deny-overrides':return 'Deny' if 'Deny' in outcomes else 'Permit'
    if alg=='permit-overrides':return 'Permit' if 'Permit' in outcomes else 'Deny'
    raise ValueError('unsupported algorithm')

def ref_eval(pol,rules,q):
    applicable=[rid for rid in pol['rules'] if rules[rid]['role']==q[0] and rules[rid]['action']==q[1]]
    effects=[rules[rid]['effect'] for rid in applicable]
    return ('Deny' if 'Deny' in effects else 'Permit') if effects else 'NotApplicable'

def main(source,outdir):
    out=Path(outdir);out.mkdir(parents=True,exist_ok=True);rules,policies=normalize(source)
    write_binding_context(rules,policies,out/'FMS_Concrete_Bindings.buc')
    rr,pp,domain=read_binding_context(out/'FMS_Concrete_Bindings.buc')
    assert rr==rules and pp==policies
    cached_requests=[E.fromstring(E.tostring(request_xml(q))) for q in domain]
    rows=[];mutant_rows=[];alltests=[]
    for pid,pol in pp.items():
        folder=out/pid;folder.mkdir(exist_ok=True);root=policy_xml(pid,pol,rr)
        E.ElementTree(root).write(folder/'policy.xml',encoding='utf-8',xml_declaration=True);root=E.parse(folder/'policy.xml').getroot()
        expected=[ref_eval(pol,rr,q) for q in domain]
        assert all(xml_evaluate(root,req)==d for req,d in zip(cached_requests,expected))
        start=time.perf_counter();objectives={}
        for j,q in enumerate(domain):
            for rid in pol['rules']:
                app=rr[rid]['role']==q[0] and rr[rid]['action']==q[1]
                objectives.setdefault(rid+':'+str(app),set()).add(j)
            objectives.setdefault('decision:'+expected[j],set()).add(j)
        selected=select_single(objectives);elapsed=time.perf_counter()-start
        mutants=[]
        for rid in pol['rules']:
            for typ in ['effect','remove','role_value']:
                m=E.fromstring(E.tostring(root));rule=next(x for x in m if tag(x)=='Rule' and x.attrib['RuleId']==rid)
                if typ=='effect':rule.attrib['Effect']='Deny'
                elif typ=='remove':m.remove(rule)
                else:
                    val=next(x for x in rule.iter() if tag(x)=='AttributeValue');val.text='OtherRole'
                mutants.append((typ,rid,m))
        for alg in ['permit-overrides','first-applicable']:
            m=E.fromstring(E.tostring(root));m.attrib['RuleCombiningAlgId']=ALG+alg;mutants.append(('algorithm','',m))
        killed=equiv=0
        for mi,(typ,rid,m) in enumerate(mutants):
            differ={j for j,req in enumerate(cached_requests) if xml_evaluate(m,req)!=expected[j]}
            detected=bool(selected.intersection(differ));killed+=detected;equiv+=not differ
            mutant_rows.append({'policy':pid,'operator':typ,'rule':rid,'killed':int(detected),'equivalent_finite':int(not differ)})
        tests=[]
        for j in sorted(selected):
            E.ElementTree(cached_requests[j]).write(folder/f'request_{j}.xml',encoding='utf-8',xml_declaration=True)
            tests.append({'policy':pid,'request':domain[j],'expected':expected[j],'model_event':'Combine_DenyOverrides_'+expected[j],'index':j})
        alltests.extend(tests);(folder/'tests.json').write_text(json.dumps(tests,indent=2))
        rows.append({'policy':pid,'rules':len(pol['rules']),'domain_requests':len(domain),'xml_agree':len(domain),'generated_tests':len(selected),'feasible_objectives':len(objectives),'coverage_percent':100,'generation_s':elapsed,'mutants':len(mutants),'killed':killed,'equivalent_finite':equiv,'raw_ms':100*killed/len(mutants),'adjusted_ms':100*killed/(len(mutants)-equiv) if len(mutants)>equiv else None})
    for filename,records in [('fms_results.csv',rows),('fms_mutants.csv',mutant_rows)]:
        with (out/filename).open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
    summary={'source_sha256':hashlib.sha256(Path(source).read_bytes()).hexdigest(),'rules':len(rr),'policies':len(pp),'empty_policies':sum(not p['rules'] for p in pp.values()),'domain_requests':len(domain),'reference_evaluations':sum(r['xml_agree'] for r in rows),'selected_test_evaluations':len(alltests),'unique_request_values':len({tuple(t['request']) for t in alltests}),'mutants':sum(r['mutants'] for r in rows),'killed':sum(r['killed'] for r in rows),'equivalent_finite':sum(r['equivalent_finite'] for r in rows),'assumptions':['Rolei/Actioni means equality on role and action','empty Condition means true','policy targets are universal','resource and environment are singleton and irrelevant','evaluate 18 policies separately; no root PolicySet test','generated concrete Event-B context has NOT been Rodin-verified','restricted generated-binding parser, not arbitrary Event-B interpreter','XML-subset evaluator, not independent PDP; no XSD validation']}
    (out/'summary.json').write_text(json.dumps(summary,indent=2));(out/'all_tests.json').write_text(json.dumps(alltests,indent=2));print(json.dumps(summary,indent=2))
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('source');ap.add_argument('--output',default='fms_results');a=ap.parse_args();main(a.source,a.output)

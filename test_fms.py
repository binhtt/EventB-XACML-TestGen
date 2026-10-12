import tempfile,unittest
from pathlib import Path
from fms_experiment import *
class FMSTests(unittest.TestCase):
    def setUp(self):
        self.rules={'R1':{'role':'Role1','action':'Action1','effect':'Permit'},'R2':{'role':'Role2','action':'Action2','effect':'Permit'}}
        self.pols={'P1':{'rules':['R1','R2'],'algorithm':'deny-overrides'},'P2':{'rules':[],'algorithm':'deny-overrides'}}
    def test_concrete_context_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bindings.buc';write_binding_context(self.rules,self.pols,p);r,pol,domain=read_binding_context(p)
            self.assertEqual(r,self.rules);self.assertEqual(pol,self.pols);self.assertEqual(len(domain),9)
    def test_positive_and_cross_negative(self):
        root=policy_xml('P1',self.pols['P1'],self.rules)
        for q,expected in [(('Role1','Action1'),'Permit'),(('Role1','Action2'),'NotApplicable'),(('OtherRole','Action1'),'NotApplicable')]:
            self.assertEqual(xml_evaluate(root,request_xml(q)),expected)
            self.assertEqual(ref_eval(self.pols['P1'],self.rules,q),expected)
    def test_empty_policy(self):
        self.assertEqual(xml_evaluate(policy_xml('P2',self.pols['P2'],self.rules),request_xml(('Role1','Action1'))),'NotApplicable')
    def test_overlap_deny_precedence(self):
        self.rules['R2']={'role':'Role1','action':'Action1','effect':'Deny'}
        self.assertEqual(xml_evaluate(policy_xml('P1',self.pols['P1'],self.rules),request_xml(('Role1','Action1'))),'Deny')
if __name__=='__main__':unittest.main()

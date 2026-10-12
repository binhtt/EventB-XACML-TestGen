import tempfile,unittest
from pathlib import Path
import hacs_experiment as h
class HACSTests(unittest.TestCase):
    def setUp(self):
        self.rules={'R1':{'role':'Doctor','resource':'Record','action':'read','effect':'Permit'},'R2':{'role':'Nurse','resource':'Record','action':'read','effect':'Deny'}}
        self.pols={'P1':{'rules':['R1','R2'],'algorithm':'deny-overrides'}}
    def test_bindings_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'b.buc';h.bindings(self.rules,self.pols,p);r,pol,domain=h.read_bindings(p)
            self.assertEqual(r,self.rules);self.assertEqual(pol,self.pols);self.assertEqual(len(domain),12)
    def test_resource_and_action_mismatch(self):
        root=h.policy_xml('P1',self.pols['P1'],self.rules);compiled=h.compile_xml(root)
        for q,d in [(('Doctor','Record','read'),'Permit'),(('Nurse','Record','read'),'Deny'),(('Doctor','Other_resource','read'),'NotApplicable'),(('Doctor','Record','write'),'NotApplicable')]:
            self.assertEqual(h.evaluate_xml(compiled,q),d)
            self.assertEqual(h.xml_evaluate(root,h.request_xml(q)),d)
    def test_compiled_and_xml_overlap(self):
        self.rules['R2']['role']='Doctor';root=h.policy_xml('P1',self.pols['P1'],self.rules);q=('Doctor','Record','read')
        self.assertEqual(h.evaluate_xml(h.compile_xml(root),q),'Deny');self.assertEqual(h.xml_evaluate(root,h.request_xml(q)),'Deny')
if __name__=='__main__':unittest.main()

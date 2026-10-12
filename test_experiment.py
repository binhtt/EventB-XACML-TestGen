import unittest
from experiment import *
class SemanticsTests(unittest.TestCase):
    def setUp(self):
        self.p={'id':'manual','algorithm':'deny-overrides','rules':[
          {'id':'permit','effect':'Permit','predicates':[['role','eq',1],['resource','eq',0],['amount','lt',10]]},
          {'id':'deny','effect':'Deny','predicates':[['role','eq',1],['resource','eq',0],['amount','ge',5]]}]}
    def check(self,q,expected):
        self.assertEqual(decision(self.p,q),expected)
        self.assertEqual(xml_decision(policy_xml(self.p),request_xml(q)),expected)
    def test_overrides(self):
        self.check((1,0,7),'Deny');self.p['algorithm']='permit-overrides';self.check((1,0,7),'Permit')
    def test_order(self):
        self.p['algorithm']='first-applicable';self.check((1,0,7),'Permit')
        self.p['rules'].reverse();self.check((1,0,7),'Deny')
    def test_not_applicable(self):self.check((3,0,7),'NotApplicable')
    def test_boundary(self):
        self.p['rules']=self.p['rules'][:1];self.check((1,0,9),'Permit');self.check((1,0,10),'NotApplicable')
    def test_influence_and_selection(self):
        objs=objective_sets(self.p);s=guided(objs)
        for obj in objs[:4]:self.assertEqual(coverage(s,obj),100)
        self.assertEqual(coverage(s,objs[4],True),100)
    def test_mutant_reference_fixed(self):
        ref=decision(self.p,(1,0,7));m=copy.deepcopy(self.p);m['algorithm']='permit-overrides'
        self.assertNotEqual(xml_decision(policy_xml(m),request_xml((1,0,7))),ref)
if __name__=='__main__':unittest.main()

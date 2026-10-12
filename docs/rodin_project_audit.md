# Native Rodin project audit

Source: uploaded Event-B.zip. This audit reads stored XML and does not rerun Rodin or replay proofs.

| Component | Stored entries | Confidence 1000 | Confidence 0 | Broken |
|---|---:|---:|---:|---:|
| XACML_AbsMachine | 4 | 4 | 0 | 0 |
| XACML_Context | 0 | 0 | 0 | 0 |
| XACML_Refined1_Context | 1 | 1 | 0 | 0 |
| XACML_Refined1_Machine | 30 | 22 | 8 | 0 |
| XACML_Refined2_Machine | 32 | 23 | 9 | 1 |

The archive contains 67 stored status entries: 50 have confidence 1000 and 17 have confidence 0. One of the confidence-1000 statuses is also marked broken. Confidence 1000 must not be equated with an automatic proof, and manually attempted proofs must not be equated with discharged proofs. Stored entries are not an independently replayed verification result.

## Extracted model structure

- XACML_Context: 6 carrier sets, 6 constants, 5 axioms.
- XACML_Refined1_Context: 3 carrier sets, 10 constants, 9 axioms.
- XACML_AbsMachine: 3 locally declared events, 4 locally declared invariants. Extended events and inherited invariants are not flattened or counted twice.
- XACML_Refined1_Machine: 10 locally declared events, 2 locally declared invariants. Extended events and inherited invariants are not flattened or counted twice.
- XACML_Refined2_Machine: 10 locally declared events, 3 locally declared invariants. Extended events and inherited invariants are not flattened or counted twice.

## Why concrete requests cannot yet be generated from this project alone

The contexts declare the types of target, condition, effect, policies, policy_target, combining_alg_policy and rule_order. They do not bind these constants to the HACS/FMS/SIS rule instances. Carrier sets have no concrete enumeration or attribute encoding. Thus the model represents a family of policies, not one executable policy instance. Choosing arbitrary interpretations would create synthetic instances rather than reproduce the original experiments.

The available combining events write a shared decision variable for individual policies. There is no extracted completed root-policy-set evaluation protocol. A test oracle therefore requires a concrete evaluation interface rather than observing an arbitrary intermediate decision.

## Required inputs

Provide executable XACML policies and their concrete attribute domains, or concrete Event-B contexts defining target/condition/effect and policy membership/order. If this archive predates final proof completion, provide the latest Rodin export. Otherwise review the stored confidence-zero and broken entries in Rodin before describing the models as fully verified.

## Tool status

rodin_import.py now reads .buc/.bum/.bps and exports formulas, local events, refinement links and proof-status evidence into rodin_audit.json. It does not execute these formulas or fabricate missing constants. The previously executed synthetic results remain unchanged; the uploaded project has not been counted as an additional benchmark.

Run: `python rodin_import.py PATH_TO_PROJECT --output rodin_audit.json`.

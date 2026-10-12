# EventB-XACML-TestGen

Reproducible preliminary experiments for **Automated Test Case Generation for XACML Policies from Verified Event-B Specifications**.

The present artifact implements concrete binding extraction and finite-domain test selection. **It does not yet substantiate the full “verified specifications” claim:** newly generated concrete contexts have not been proved in Rodin; original machine guards/actions are not executed; XML is evaluated by a local subset evaluator rather than an independent PDP.

## Recorded results

| Dataset | Rules | Policies | Policy-specific tests | Detected / generated mutants | Raw mutation score |
|---|---:|---:|---:|---:|---:|
| FMS | 45 | 18 | 63 | 135 / 171 | 78.95% |
| HACS | 50 | 20 | 70 | 250 / 290 | 86.21% |
| SIS | 40 | 15 | 55 | 200 / 230 | 86.96% |
| Total | 135 | 53 | 188 | 585 / 691 | 84.66% |

All feasible rule-applicability and policy-decision objectives are covered in the stated domains. There are 106 surviving combining-algorithm mutant instances, all equivalent **within those finite domains**. Their equivalence reflects mutually exclusive rule targets, not general effectiveness against combining faults. Adjusted finite-domain scores are 100%; use the raw scores above for the main report.

## Reproduce

Python 3.12.14 was used on Linux x86_64. The scripts use only the standard library; no package installation is required.

```bash
python -m unittest discover -s . -v
python reproduce.py --output reproduced
```

The second command reruns all three experiments and checks deterministic test counts, reference agreement counts and mutation results against the recorded summaries. Timing values vary and are excluded from equality checks.

Individual runs:

```bash
python fms_experiment.py inputs/FMS.json --output reproduced/fms_results
python hacs_experiment.py inputs/HACS.json inputs/HACS_memberships.json --output reproduced/hacs_results
python hacs_experiment.py inputs/SIS.json inputs/SIS_memberships.json --dataset SIS --output reproduced/sis_results
python rodin_import.py models/supplied_rodin --output reproduced/rodin_audit.json
```

## Data and assumptions

- FMS: 45 Permit-only rule fragments; role/action shorthand is interpreted as equality; 18 supplied DenyOverrides policies, including three empty policies.
- HACS: 50 fragments, 25 Permit and 25 Deny; subject/resource/action values become singleton string-equality targets.
- SIS: 40 fragments, 20 Permit and 20 Deny; the same target normalization is applied.
- HACS/SIS memberships come from [XACML2EventB](https://github.com/binhtt/XACML2EventB), commit `8cc1782f3df354cd80552a0f4499482a3ce6bbd5`. The repository's placeholder policy XML is not executed. DenyOverrides is explicitly **assumed** for these two datasets because their supplied rule fragments omit it.
- Policy targets are universal; absent/empty conditions are true. Environment is singleton. Each policy is evaluated separately; no root PolicySet result is claimed.
- Domains contain each named attribute value plus one unmatched value: FMS 2,116 requests per policy; HACS 13,005; SIS 5,043.

This is a concretization of simplified supplied fragments, not an evaluation of independently obtained deployed systems or external benchmarks.

## Pipeline

1. Normalize supplied fragments and membership metadata.
2. Export explicit bindings as a candidate native Rodin `.buc` context.
3. Read the generated axiom subset back and check correspondence with the input.
4. Enumerate the finite request domain and select objective witnesses.
5. Emit XML requests, XML policies and expected decisions.
6. Evaluate unchanged policies and XML mutants using local evaluators.

The binding parsers accept only the generated formula subset; they are **not general Event-B interpreters**. Oracle decisions use hand-implemented combining semantics over extracted bindings. Native XML extraction in `rodin_import.py` is structural, not a Rodin proof replay.

## Contents

- `inputs/`: source fragments and membership metadata.
- `models/supplied_rodin/`: unmodified supplied project and historical proof records.
- `results/`: per-policy CSV, mutant outcomes, summaries, context candidates, XML requests, policies and expected decisions.
- `docs/concrete_experimental_results.md`: consolidated experimental analysis.
- `docs/Experimental_Evaluation_XACML.tex`: manuscript section.
- `docs/rodin_project_audit.md`: stored proof-status audit.
- `docs/source_audit.json`: public repository data audit.

Generated contexts are in `results/*_results/*_Concrete_Bindings.buc`. Their accompanying attribute encodings are included where required.

## Limits of the results

No new Rodin proof, ProB execution, direct machine-event interpretation, independent PDP run, or XACML XSD validation is claimed. Unsupported cases include Indeterminate, missing or multivalued attributes, nontrivial conditions, and policy-set aggregation. These three datasets do not contain overlapping rule targets. No existing-generator comparison, MC/DC measurement, ablation or repeated timing study is included here. Mutation scores count generated operator instances without behavioral deduplication.

The supplied historical proof records include confidence-zero and broken entries; see the audit rather than assuming every recorded obligation was discharged. Correspondence between local evaluators is internal consistency evidence only.

# Experimental evaluation: three concretized datasets

This report supersedes the earlier two-system concrete-data report. Measurements come from executed finite-domain pilots. The generated concrete contexts have not been verified in Rodin; original machine events are not executed, and the XML evaluator is local rather than an independent PDP. These limitations prevent presenting this as the finished verified-specification experiment.

## Dataset preparation

FMS uses supplied role/action text targets interpreted as conjunctions of equality predicates. Empty conditions are true. HACS and SIS use supplied PolicyRule fragments with subject/resource/action values, normalized into singleton-equality XACML 3.0 targets. Missing conditions are true. Policy targets are assumed universal, and environment attributes are irrelevant singleton values.

FMS supplies its own rule membership and DenyOverrides algorithm. HACS and SIS policy membership comes from the public repository at commit 8cc1782f3df354cd80552a0f4499482a3ce6bbd5. Repository policy XML strings are placeholders and are not executed. DenyOverrides is assumed for HACS and SIS because the supplied data does not declare a combining algorithm. All source hashes are recorded. Each policy is evaluated separately; no root PolicySet result is claimed.

The source formats and equality assumptions are documented rather than described as already valid XACML deployments. FMS includes three empty policies, which are preserved.

## Table 1. Dataset characteristics

| Dataset | Rules | Policies | Permit / Deny rules | Empty policies | Request domain per policy |
|---|---:|---:|---:|---:|---:|
| FMS | 45 | 18 | 45 / 0 | 3 | 2,116 |
| HACS | 50 | 20 | 25 / 25 | 0 | 13,005 |
| SIS | 40 | 15 | 20 / 20 | 0 | 5,043 |

FMS has 46 roles and 46 actions. HACS has 51 subjects, 51 resources and five actions. SIS has 41 subjects, 41 resources and three actions. The domains include one unmatched value per attribute. The counts above are resulting concretized instances, not a verification result for their semantics.

## Test generation and execution

The prototype emits explicit target, condition, effect, membership and ordering bindings into a concrete Event-B context, then reads them back with a parser for the generated formula subset. Round-trip checks compare these bindings with the input data. Feasible rule-applicability and policy-decision objectives are identified through exhaustive enumeration. The prototype selects witness requests and emits request XML and expected decisions.

The reference oracle is a hand-implemented evaluator using the extracted bindings; it does not execute the supplied Event-B machine guards or actions. The local XML evaluator uses a separate representation. HACS and SIS XML policies are compiled into equality predicates for exhaustive evaluation, and selected serialized requests are also checked through an uncompiled XML evaluator. Agreement checks are internal consistency evidence only.

## Table 2. Test suites and internal consistency

| Dataset | Policy-specific test evaluations | Distinct request values | Feasible applicability/decision coverage | Reference evaluations | Internal agreement |
|---|---:|---:|---:|---:|---:|
| FMS | 63 | 46 | 100% | 38,088 | 100% |
| HACS | 70 | 51 | 100% | 260,100 | 100% |
| SIS | 55 | 41 | 100% | 75,645 | 100% |

A request reused across different policies counts once in the distinct-request column but once per policy in test evaluations. Coverage refers only to feasible rule applicable/non-applicable outcomes and feasible Permit/Deny/NotApplicable outcomes. Numeric boundaries, MC/DC, actual Event-B event coverage and combining interactions are not evaluated by these concrete-data pilots.

## Table 3. Mutation results

| Dataset | Mutants | Detected | Equivalent within finite domain | Raw mutation score | Adjusted finite-domain score |
|---|---:|---:|---:|---:|---:|
| FMS | 171 | 135 | 36 | 78.95% | 100.00% |
| HACS | 290 | 250 | 40 | 86.21% | 100.00% |
| SIS | 230 | 200 | 30 | 86.96% | 100.00% |

Mutation analysis keeps the reference bindings unchanged. Effect replacement, rule removal and role/subject replacement are evaluated for all datasets. Resource and action replacements are additionally evaluated for HACS and SIS. Combining mutants replace DenyOverrides with PermitOverrides or FirstApplicable. All executable mutant instances are retained, including instances with identical behavior; scores describe operator instances rather than unique fault behaviors.

| Operator | FMS detected / generated | HACS detected / generated | SIS detected / generated |
|---|---:|---:|---:|
| Effect replacement | 45 / 45 | 50 / 50 | 40 / 40 |
| Rule removal | 45 / 45 | 50 / 50 | 40 / 40 |
| Role/subject replacement | 45 / 45 | 50 / 50 | 40 / 40 |
| Resource replacement | Not evaluated | 50 / 50 | 40 / 40 |
| Action replacement | Not evaluated | 50 / 50 | 40 / 40 |
| Combining-algorithm replacement | 0 / 36 | 0 / 40 | 0 / 30 |

All combining mutants are equivalent on the exhaustively examined finite domains. The rule targets are mutually exclusive: Permit and Deny cannot participate simultaneously in a policy decision. Consequently, adjusted scores of 100% mainly reflect detection of straightforward rule-level changes. They do not demonstrate general detection of combining faults or superiority over existing XACML testing methods.

## Manuscript text

The concrete-data pilot evaluated 135 rule fragments organized into 53 policies across FMS, HACS and SIS. After normalizing the supplied target representations and recording the additional assumptions, the prototype exported concrete Event-B bindings and read them back to derive finite request domains. The generator selected 63 FMS, 70 HACS and 55 SIS policy-specific tests, covering all feasible rule-applicability and policy-decision objectives. The extracted-binding reference evaluators agreed with the local XML-subset evaluators on 38,088, 260,100 and 75,645 reference evaluations, respectively. The generated suites detected 135 of 171 FMS mutants, 250 of 290 HACS mutants and 200 of 230 SIS mutants, giving raw mutation scores of 78.95%, 86.21% and 86.96%. The remaining mutants changed combining algorithms and were equivalent within the evaluated domains. These results establish feasibility of the implemented concretization and witness-selection workflow under the stated assumptions. They do not yet establish generation from fully verified concrete Event-B models or conformance with an independent PDP.

## Remaining experiments

To substantiate the intended paper, the framework must execute or faithfully translate the original Event-B events, verify the concrete models in Rodin, validate XML against the XACML schema, and run an independent PDP. Policies with overlapping Permit/Deny rules and nontrivial conditions are needed to assess combining and boundary objectives. Existing-method comparisons, ablation and repeated timing measurements remain necessary. Earlier synthetic comparisons are available separately and must not be mixed with these concrete-data results as if they use the same semantics and objectives.

## Reproduction

Run from the extracted xacml_testlab directory:

    python fms_experiment.py inputs/FMS.json --output fms_results
    python hacs_experiment.py inputs/HACS.json inputs/HACS_memberships.json --output hacs_results
    python hacs_experiment.py inputs/SIS.json inputs/SIS_memberships.json --dataset SIS --output sis_results
    python -m unittest discover -s . -v

The scripts use only the Python standard library. Per-policy timing columns are single-run objective-construction and selection measurements, excluding serialization, exhaustive reference checks and mutation analysis.

## FMS per-policy measurements

| Policy | Rules | Tests | Objectives | Coverage % | Mutants | Detected | Finite-equivalent |
|---|---:|---:|---:|---:|---:|---:|---:|
| P1 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P2 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P3 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P4 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P5 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P6 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P7 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P8 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P9 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P10 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P11 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P12 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P13 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P14 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P15 | 3 | 4 | 8 | 100 | 11 | 9 | 2 |
| P16 | 0 | 1 | 1 | 100 | 2 | 0 | 2 |
| P17 | 0 | 1 | 1 | 100 | 2 | 0 | 2 |
| P18 | 0 | 1 | 1 | 100 | 2 | 0 | 2 |

## HACS per-policy measurements

| Policy | Rules | Tests | Objectives | Coverage % | Mutants | Detected | Finite-equivalent |
|---|---:|---:|---:|---:|---:|---:|---:|
| HACS_POLICY_1 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_2 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_3 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_4 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_5 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_6 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_7 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_8 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_9 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_10 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| HACS_POLICY_11 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| HACS_POLICY_12 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| HACS_POLICY_13 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| HACS_POLICY_14 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| HACS_POLICY_15 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| HACS_POLICY_16 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| HACS_POLICY_17 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| HACS_POLICY_18 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| HACS_POLICY_19 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| HACS_POLICY_20 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |

## SIS per-policy measurements

| Policy | Rules | Tests | Objectives | Coverage % | Mutants | Detected | Finite-equivalent |
|---|---:|---:|---:|---:|---:|---:|---:|
| SIS_POLICY_1 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_2 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_3 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_4 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_5 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_6 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_7 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_8 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_9 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_10 | 3 | 4 | 9 | 100 | 17 | 15 | 2 |
| SIS_POLICY_11 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| SIS_POLICY_12 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| SIS_POLICY_13 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| SIS_POLICY_14 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |
| SIS_POLICY_15 | 2 | 3 | 7 | 100 | 12 | 10 | 2 |

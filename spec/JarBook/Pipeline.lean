import VersoManual
import Jar.Services
import Jar.State

open Verso.Genre Manual
open Jar

set_option verso.docstring.allowMissing true

#doc (Manual) "Work-Report Pipeline" =>

The work-report pipeline is the core data flow of JAM: work packages are
refined off-chain, guaranteed on-chain, checked for availability, and
accumulated into state. Disputes resolve disagreements about work results.

The pipeline stages, in block processing order:

1. *Guarantees*: validators guarantee work reports (attach to extrinsic)
2. *Availability*: 2/3 of validators attest that erasure-coded data is available
3. *Accumulation*: available work reports are accumulated into service state
4. *Disputes*: any validator can dispute a work report's correctness

# Work-Report Computation

Off-chain, a guarantor runs the service's refine code to produce a work report
from a work package. This combines authorization checking and refinement.

{docstring Jar.Services.computeWorkReport}

# Guarantee Integration

New guarantees from the extrinsic are integrated into the pending reports pool.
Each guarantee references a work report and is signed by the guarantor.

{docstring reportsPostGuarantees}

# Availability

Assurance extrinsics signal that validators hold their erasure-coded chunks.
Once a report reaches the availability threshold (2/3 of validators), it
becomes available for accumulation. Reports that time out are dropped.

{docstring reportsPostAssurance}

# Disputes and Judgments

Any validator can raise a dispute about a work report by submitting a verdict.
Verdicts carry judgments (valid/invalid) signed by individual validators. If
a report is judged bad, its guarantors may be penalized (culprits) and the
report is removed from the available set.

{docstring updateJudgments}

Reports judged as bad are cleared from the pending pool:

{docstring reportsPostJudgment}

Offending validators (guarantors of bad reports) have their keys zeroed,
effectively ejecting them from the active set:

{docstring filterOffenders}

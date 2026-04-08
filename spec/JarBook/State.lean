import VersoManual
import Jar.State

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "State Transition" =>

The block-level state transition function `Υ(σ, B) = σ'` (GP eq 4.1).

# Timekeeping

{docstring Jar.newTimeslot}

{docstring Jar.epochIndex}

{docstring Jar.epochSlot}

{docstring Jar.isEpochChange}

# Header Validation (§5)

{docstring Jar.validateHeader}

{docstring Jar.validateExtrinsic}

# Recent History (§4.2)

{docstring Jar.updateParentStateRoot}

{docstring Jar.computeAccumulateRoot}

{docstring Jar.collectReportedPackages}

{docstring Jar.updateRecentHistory}

# Entropy (§6.3)

{docstring Jar.updateEntropy}

# Validator Management (§6)

{docstring Jar.updateActiveValidators}

{docstring Jar.updatePreviousValidators}

# Work-Report Pipeline and Disputes

Judgment processing, report availability, and guarantee integration are covered
in the *Work-Report Pipeline* chapter. The key functions — `updateJudgments`,
`reportsPostJudgment`, `reportsPostAssurance`, `reportsPostGuarantees`, and
`filterOffenders` — are documented there.

# Authorization Pool

{docstring Jar.updateAuthPool}

# Accumulation (§12)

{docstring Jar.performAccumulation}

# Preimages (§12.7)

{docstring Jar.integratePreimages}

# Statistics (§13)

{docstring Jar.updateStatistics}

# State Transition

{docstring Jar.stateTransition}

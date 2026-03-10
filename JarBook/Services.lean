import VersoManual
import Jar.Services

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Service Invocations" =>

Service entry points that the protocol invokes via the PVM (GP §11, Appendix B).

# Balance

{docstring Jar.minimumBalance}

# Is-Authorized (Ψ_I)

The is-authorized invocation checks whether a work-package's authorization token
is accepted by the service's authorizer code.

{docstring Jar.isAuthorized}

# Refinement (Ψ_R)

Refinement transforms a work item into a work result by running the service's
refine code in the PVM.

{docstring Jar.refine}

# Work-Report Computation (Ξ)

Combines is-authorized and refinement to produce a complete work report
from a work package.

{docstring Jar.computeWorkReport}

# On-Transfer (Ψ_T)

Invoked when a deferred transfer arrives at a service during accumulation.

{docstring Jar.onTransfer}

# Auditing

{docstring Jar.auditWorkReport}

import VersoManual
import Jar.Accumulation

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Accumulation" =>

The accumulation pipeline integrates refined work results into on-chain state
(GP §12). It proceeds in three stages: `accseq` orchestrates sequentially,
`accpar` parallelizes across services, and `accone` handles a single service
via PVM execution with 27 host calls.

# Data Types

{docstring Jar.OperandTuple}

{docstring Jar.PartialState}

{docstring Jar.AccOneOutput}

{docstring Jar.AccContext}

# Host Calls (§12.4)

All 27 host-call handlers (indices 0–26) are dispatched by `handleHostCall`.
Each host call costs a base gas of 10. Operations include reading/writing
service storage, transferring balance, managing preimages, and creating
or upgrading services.

{docstring Jar.handleHostCall}

# Single-Service Accumulation

{docstring Jar.encodeAccArgs}

{docstring Jar.accone}

# Pipeline

{docstring Jar.groupByService}

{docstring Jar.groupTransfersByDest}

{docstring Jar.accpar}

{docstring Jar.accseq}

# Block-Level Accumulation

{docstring Jar.AccumulationResult}

{docstring Jar.accumulate}

import VersoManual
import Jar.Consensus

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Safrole Consensus" =>

The Safrole block-production mechanism — a SNARK-based, slot-auction
consensus protocol (GP §6).

# Block Sealing

{docstring Jar.outsideInSequencer}

{docstring Jar.fallbackKeySequence}

{docstring Jar.verifySealTicketed}

{docstring Jar.verifySealFallback}

{docstring Jar.verifyEntropyVrf}

# Ticket Accumulation

{docstring Jar.verifyTicketProof}

{docstring Jar.accumulateTickets}

# State Update

{docstring Jar.updateSafrole}

# Chain Selection

{docstring Jar.chainMetric}

{docstring Jar.isAcceptable}

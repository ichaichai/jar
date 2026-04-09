import VersoManual
import Jar.Types

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Type Definitions" =>

Core type definitions for the JAM protocol, mapping Gray Paper structures
to Lean 4 (GP §4, §6–§12).

# Validator Types (§6)

{docstring Jar.ValidatorKey}

{docstring Jar.Ticket}

{docstring Jar.SealKeySeries}

{docstring Jar.SafroleState}

{docstring Jar.Entropy}

# Service Account Types (§8)

{docstring Jar.ServiceAccount}

{docstring Jar.PrivilegedServices}

{docstring Jar.DeferredTransfer}

{docstring Jar.BalanceEcon}

{docstring Jar.BalanceTransfer}

{docstring Jar.QuotaEcon}

{docstring Jar.QuotaTransfer}

# Work Types (§11)

{docstring Jar.WorkError}

{docstring Jar.WorkResult}

{docstring Jar.WorkDigest}

{docstring Jar.AvailabilitySpec}

{docstring Jar.RefinementContext}

{docstring Jar.WorkReport}

{docstring Jar.PendingReport}

{docstring Jar.WorkItem}

{docstring Jar.WorkPackage}

{docstring Jar.Segment}

# Block Header Types (§5)

{docstring Jar.EpochMarker}

{docstring Jar.Header}

# Extrinsic Types (§7–§10)

{docstring Jar.TicketsExtrinsic}

{docstring Jar.PreimagesExtrinsic}

{docstring Jar.AssurancesExtrinsic}

{docstring Jar.GuaranteesExtrinsic}

{docstring Jar.Judgment}

{docstring Jar.Verdict}

{docstring Jar.Culprit}

{docstring Jar.Fault}

{docstring Jar.DisputesExtrinsic}

{docstring Jar.TicketProof}

{docstring Jar.Guarantee}

{docstring Jar.Assurance}

{docstring Jar.Extrinsic}

{docstring Jar.Block}

# State Types (§4)

{docstring Jar.JudgmentsState}

{docstring Jar.RecentBlockInfo}

{docstring Jar.RecentHistory}

{docstring Jar.ValidatorRecord}

{docstring Jar.CoreStatistics}

{docstring Jar.ServiceStatistics}

{docstring Jar.ActivityStatistics}

{docstring Jar.AccumulationOutputs}

{docstring Jar.State}

# Protocol Configuration

{docstring Jar.Params}

{docstring Jar.Params.Valid}

{docstring Jar.Params.isValidValCount}

{docstring Jar.MemoryModel}

{docstring Jar.GasModel}

{docstring Jar.CapabilityModel}

{docstring Jar.EconModel}

{docstring Jar.JarConfig}

{docstring Jar.Params.full}

{docstring Jar.Params.tiny}

{docstring Jar.cfg}

/-
  Genesis Protocol — Execution Model & State

  ## Execution

  The spec is executed per-signed-commit, where each signed commit is
  evaluated by the spec version at the PREVIOUS signed commit:

  1. Gather all signed commits from git history.
  2. Check out genesis commit. Feed it the first signed commit.
     → produces CommitIndex (weight changes, score, reviewers, deltas).
  3. Check out the first signed commit. Input = (genesis state, [index_0]).
     Evaluate the second signed commit → produces index_1.
  4. Continue: each step receives all past indices as input.
  5. Finalization: current master spec computes end balances from all indices.

  This ensures:
  - A malicious spec change only affects the NEXT commit's evaluation.
  - Each CommitIndex is produced by a specific, immutable spec version.
  - The finalization step (summing balances) is trivially auditable.
-/

import Genesis.Types
import Genesis.Scoring

/-! ### Genesis Constants -/

/-- GPG key fingerprints of trusted commit signers. -/
def trustedSigningKeys : Array String := #[
  "B5690EEEBB952194"  -- GitHub web-flow (2024-01-16, no expiry)
]

/-- The founding reviewer. -/
def founder : ContributorId := "sorpaas"

/-- The genesis commit. TBD at launch. -/
def genesisCommit : CommitId := "0000000000000000000000000000000000000000"

/-- Initial weight for the founder. -/
def founderWeight : Nat := 1

/-! ### CommitIndex — Output of evaluating one signed commit -/

/-- The output of evaluating a single signed commit.
    Produced by the spec version at the PREVIOUS signed commit.

    Contains only the raw facts needed for state reconstruction and
    future finalization. Token amounts are NOT stored here — they are
    computed during finalization using the current spec's parameters.
    This allows changing reward splits (e.g., 70/30 → 80/20) without
    re-evaluating history. -/
structure CommitIndex where
  /-- Hash of the signed commit that was evaluated. -/
  commitHash : CommitId
  /-- Epoch / timestamp of the commit. -/
  epoch : Epoch
  /-- The commit's score on each dimension. -/
  score : CommitScore
  /-- Who authored the commit. -/
  contributor : ContributorId
  /-- Weight change for the contributor (= score.weighted).
      Needed at each step for reconstructing reviewer weights. -/
  weightDelta : Nat
  /-- Approved reviewers who participated. Their weights can be
      reconstructed from prior indices' weightDeltas. -/
  reviewers : List ContributorId
  /-- Meta-review results: who approved/rejected which reviews. -/
  metaReviews : List MetaReview
  /-- Reviewers who voted to merge. -/
  mergeVotes : List ContributorId
  /-- Reviewers who voted not to merge. -/
  rejectVotes : List ContributorId
  /-- Whether the founder used the escape hatch to force this merge. -/
  founderOverride : Bool
  deriving Repr

/-! ### Intermediate State

  Reconstructed from past CommitIndices for evaluating the next commit.
  This is NOT the final balance — it's the working state needed to
  run the scoring algorithm (reviewer weights, reference scores, etc).
-/

/-- Intermediate state reconstructed from past indices. -/
structure EvalState where
  /-- Current contributor weights (for reviewer weight lookups). -/
  contributors : List Contributor
  /-- Scored commit history (for comparison target selection and scoring). -/
  scoredCommits : List (CommitId × CommitScore)

/-- Update or insert a contributor in a list. -/
private def upsertContributor (cs : List Contributor) (updated : Contributor) : List Contributor :=
  if cs.any (fun (c : Contributor) => c.id == updated.id) then
    cs.map (fun (c : Contributor) => if c.id == updated.id then updated else c)
  else
    cs ++ [updated]

/-- Reconstruct the evaluation state from genesis + past indices.
    Only needs weight and reviewer status — not balances (those are
    computed during finalization). -/
def reconstructState (pastIndices : List CommitIndex) (rp : RewardParams := .default) : EvalState :=
  let init : EvalState := {
    contributors := [⟨founder, 0, founderWeight, true⟩],
    scoredCommits := []
  }
  pastIndices.foldl (fun state (idx : CommitIndex) =>
    -- Apply weight change to the contributor (author)
    let contributors :=
      if idx.weightDelta == 0 then state.contributors
      else
        let existing := state.contributors.find? (fun (c : Contributor) => c.id == idx.contributor)
        let c := existing.getD ⟨idx.contributor, 0, 0, false⟩
        let newWeight := c.weight + idx.weightDelta
        let meetsThreshold := newWeight ≥ rp.reviewerThreshold
        let updated : Contributor := ⟨c.id, c.balance, newWeight, c.isReviewer || meetsThreshold⟩
        upsertContributor state.contributors updated
    -- Record score for future comparisons
    let scoredCommits := state.scoredCommits ++ [(idx.commitHash, idx.score)]
    { contributors := contributors, scoredCommits := scoredCommits }
  ) init

/-- Get reviewer weight from an EvalState. -/
def EvalState.reviewerWeight (s : EvalState) (id : ContributorId) : Nat :=
  match s.contributors.find? (fun (c : Contributor) => c.id == id) with
  | some c => if c.isReviewer then c.weight else 0
  | none => 0

/-- Get past commit IDs from an EvalState. -/
def EvalState.pastCommitIds (s : EvalState) : List CommitId :=
  s.scoredCommits.map (fun (id, _) => id)

/-! ### Evaluate — Produce a CommitIndex from a signed commit -/

/-- Evaluate a single signed commit, producing a CommitIndex.

    This is THE core function. It takes:
    - All past indices (produced by previous spec versions)
    - The current signed commit to evaluate

    It reconstructs the evaluation state from past indices, then
    runs the scoring algorithm to produce the new index.

    In the actual execution, this function is run using the spec
    checked out at the PREVIOUS signed commit. -/
def evaluate
    (pastIndices : List CommitIndex)
    (commit : SignedCommit)
    (rp : RewardParams := .default) : CommitIndex :=
  let state := reconstructState pastIndices rp
  let (_, score) := commitRewards rp commit
    state.pastCommitIds state.scoredCommits (state.reviewerWeight ·)
  let weightedScore := score.weighted
  let approved := filterReviews commit.reviews commit.metaReviews (state.reviewerWeight ·)
  let approvedReviewers := approved
    |>.filter (fun (r : EmbeddedReview) => state.reviewerWeight r.reviewer > 0)
    |>.map (fun (r : EmbeddedReview) => r.reviewer)
  let mergeVoters := commit.reviews
    |>.filter (fun (r : EmbeddedReview) => r.verdict == .merge)
    |>.map (fun (r : EmbeddedReview) => r.reviewer)
  let rejectVoters := commit.reviews
    |>.filter (fun (r : EmbeddedReview) => r.verdict == .notMerge)
    |>.map (fun (r : EmbeddedReview) => r.reviewer)
  { commitHash := commit.id,
    epoch := commit.mergeEpoch,
    score := score,
    contributor := commit.author,
    weightDelta := weightedScore,
    reviewers := approvedReviewers,
    metaReviews := commit.metaReviews,
    mergeVotes := mergeVoters,
    rejectVotes := rejectVoters,
    founderOverride := commit.founderOverride }

/-- Evaluate a full sequence of signed commits, producing all indices.
    Each commit is evaluated with all prior indices as context. -/
def evaluateAll
    (signedCommits : List SignedCommit)
    (rp : RewardParams := .default) : List CommitIndex :=
  signedCommits.foldl (fun indices commit =>
    indices ++ [evaluate indices commit rp]
  ) []

/-! ### Finalize — Compute end balances from all indices

  This step uses the CURRENT master spec's parameters (not historical).
  Token deltas are computed here, not stored in CommitIndex. This allows
  changing reward splits (e.g., 70/30 → 80/20) without re-evaluating
  the full history.
-/

/-- Helper: add amount to a contributor in an association list. -/
private def addToBalance (acc : List (ContributorId × TokenAmount))
    (id : ContributorId) (amount : TokenAmount) : List (ContributorId × TokenAmount) :=
  if amount == 0 then acc
  else
    match acc.find? (fun (cid, _) => cid == id) with
    | some _ => acc.map (fun (cid, b) => if cid == id then (cid, b + amount) else (cid, b))
    | none => acc ++ [(id, amount)]

/-- Compute token deltas for a single CommitIndex using current parameters.
    Reviewer weights are reconstructed from prior indices.
    This is the reward logic applied at finalization, not at evaluation time. -/
def indexTokenDeltas (idx : CommitIndex) (rp : RewardParams)
    (getWeight : ContributorId → Nat) : List RewardDelta :=
  let weightedScore := idx.score.weighted
  -- Contributor reward
  let contributorShare := rp.emission * (rp.reviewerShareDen - rp.reviewerShareNum) / rp.reviewerShareDen
  let contributorReward := min contributorShare rp.contributorCap
  let contributorDelta : RewardDelta := {
    recipient := idx.contributor,
    amount := if weightedScore == 0 then 0 else contributorReward,
    kind := .contribution
  }
  -- Reviewer rewards (weights reconstructed from prior indices)
  let reviewerPool := rp.emission * rp.reviewerShareNum / rp.reviewerShareDen
  let reviewerDeltas := if idx.reviewers.isEmpty then []
    else
      let reviewerWeights := idx.reviewers.map (fun r => (r, getWeight r))
      let totalReviewWeight := reviewerWeights.foldl (fun acc (_, w) => acc + w) 0
      if totalReviewWeight == 0 then []
      else reviewerWeights.map fun (reviewer, w) =>
        let raw := reviewerPool * w / totalReviewWeight
        let capped := min raw rp.reviewerCap
        { recipient := reviewer, amount := capped, kind := .review : RewardDelta }
  contributorDelta :: reviewerDeltas

/-- Final balance for each contributor, computed from all indices
    using the current spec's reward parameters. Reconstructs reviewer
    weights progressively from prior indices. -/
def finalize (indices : List CommitIndex) (rp : RewardParams := .default)
    : List (ContributorId × TokenAmount) :=
  let (balances, _) := indices.foldl (fun (acc, pastIndices) (idx : CommitIndex) =>
    let state := reconstructState pastIndices rp
    let deltas := indexTokenDeltas idx rp (state.reviewerWeight ·)
    let newAcc := deltas.foldl (fun acc2 (d : RewardDelta) =>
      addToBalance acc2 d.recipient d.amount
    ) acc
    (newAcc, pastIndices ++ [idx])
  ) ([], [])
  balances

/-- Final weight for each contributor, computed from all indices.
    Weight = founderWeight + Σ weightDelta for authored commits. -/
def finalWeights (indices : List CommitIndex) : List (ContributorId × Nat) :=
  let init := [(founder, founderWeight)]
  indices.foldl (fun acc (idx : CommitIndex) =>
    if idx.weightDelta == 0 then acc
    else addToBalance acc idx.contributor idx.weightDelta
  ) init

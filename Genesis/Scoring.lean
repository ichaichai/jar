/-
  Genesis Protocol — Scoring & Reward Computation

  Scoring is based on rankings of past commits + the current PR.

  Flow:
  1. PR opened → bot selects N comparison targets from hash(prId)
  2. Reviewers rank all N+1 commits (targets + current PR) on 3 dimensions
  3. Reviewers submit detailed comments + merge verdict
  4. Other reviewers meta-review (thumbs up/down) to filter bad reviews
  5. Bot merges when >50% weighted merge votes (or founder override)
  6. Bot records rankings + meta-reviews in the signed merge commit
  7. Spec validates targets, filters reviews by meta-review, derives
     score using weighted lower-quantile

  See Design.lean for deferred features.
-/

import Genesis.Types

/-! ### Configurable Parameters

  These are Lean constants, easy to adjust for experimentation.
-/

/-- Number of past commits a reviewer must rank alongside the current PR.
    Total items ranked = rankingSize + 1 (targets + current PR).
    Higher = more context for scoring, more effort per review.
    Lower = faster reviews, less context. -/
def rankingSize : Nat := 7

/-- Quantile for the weighted quantile scoring function, as num/den.
    The score is the value at this quantile of the weighted distribution.

    - 1/2 (median): safe up to 50% honest. Symmetric.
    - 1/3 (lower third): safe up to 66% honest for inflation.
      Meta-review covers deflation below 50%.
    - 2/5 (lower two-fifths): safe up to 60% honest for inflation.

    Lower quantile = more conservative scoring, higher Sybil resistance. -/
def quantileNum : Nat := 1
def quantileDen : Nat := 3

/-! ### Reward Parameters -/

/-- Protocol parameters for reward and scoring. -/
structure RewardParams where
  /-- Maximum tokens a contributor can earn per signed commit. -/
  contributorCap : TokenAmount
  /-- Maximum tokens a single reviewer can earn per signed commit. -/
  reviewerCap : TokenAmount
  /-- Base emission per signed commit. -/
  emission : TokenAmount
  /-- Fraction of emission allocated to reviewers (numerator). -/
  reviewerShareNum : Nat
  /-- Fraction of emission allocated to reviewers (denominator). -/
  reviewerShareDen : Nat
  reviewerShareDen_pos : reviewerShareDen > 0 := by omega
  /-- Score step size: score points between adjacent ranks.
      Rank 1 gets referenceScore + (N-1)*step, rank N gets referenceScore. -/
  rankStep : Nat
  /-- Base score assigned to the very first commit (bootstrap anchor). -/
  bootstrapScore : Nat
  /-- Minimum weight to activate as a reviewer. -/
  reviewerThreshold : Nat
  /-- Minimum number of approved reviews required for scoring. -/
  minReviews : Nat
  deriving Repr

def RewardParams.default : RewardParams where
  contributorCap := 100
  reviewerCap := 20
  emission := 1000
  reviewerShareNum := 30
  reviewerShareDen := 100
  rankStep := 50
  bootstrapScore := 250
  reviewerThreshold := 500
  minReviews := 1

/-! ### Comparison Target Selection -/

/-- Maps a PR ID to a pseudo-random natural number for target selection. -/
def prIdHash (prId : PRId) : Nat :=
  let a := 2654435761
  (prId * a) % (2^32)

/-- Select comparison targets from past scored commits.
    Divides into buckets, picks one per bucket using hash(prId). -/
def selectComparisonTargets
    (pastCommitIds : List CommitId)
    (numTargets : Nat)
    (prId : PRId) : List CommitId :=
  let n := pastCommitIds.length
  if n == 0 then []
  else
    let k := min numTargets n
    let hash := prIdHash prId
    List.range k |>.map fun i =>
      let bucketStart := n * i / k
      let bucketEnd := n * (i + 1) / k
      let bucketSize := bucketEnd - bucketStart
      if bucketSize == 0 then
        pastCommitIds[bucketStart]!
      else
        let idx := bucketStart + (hash + i * 7) % bucketSize
        pastCommitIds[idx]!

/-- Validate comparison targets in a signed commit. -/
def validateComparisonTargets
    (commit : SignedCommit)
    (pastCommitIds : List CommitId) : Bool :=
  if pastCommitIds.isEmpty then commit.comparisonTargets.isEmpty
  else
    let expected := selectComparisonTargets pastCommitIds
      (min rankingSize pastCommitIds.length) commit.prId
    commit.comparisonTargets == expected

/-! ### Meta-Review Filtering

  Reviews are filtered by meta-reviews (thumbs up/down) before scoring.
  A review is excluded if its net meta-review weight is negative
  (more weighted thumbs-down than thumbs-up).
-/

/-- Compute net meta-review weight for a specific reviewer's review.
    Positive = approved, negative = rejected, zero = no meta-reviews. -/
def metaReviewNet
    (metaReviews : List MetaReview)
    (targetReviewer : ContributorId)
    (getWeight : ContributorId → Nat) : Int :=
  metaReviews.foldl (fun acc (mr : MetaReview) =>
    if mr.targetReviewer == targetReviewer then
      let w := (getWeight mr.metaReviewer : Int)
      if mr.approve then acc + w else acc - w
    else acc
  ) 0

/-- Filter reviews: keep only those with non-negative meta-review net weight.
    Reviews with no meta-reviews are kept (net = 0). -/
def filterReviews
    (reviews : List EmbeddedReview)
    (metaReviews : List MetaReview)
    (getWeight : ContributorId → Nat) : List EmbeddedReview :=
  reviews.filter fun (r : EmbeddedReview) =>
    metaReviewNet metaReviews r.reviewer getWeight ≥ 0

/-! ### Score Derivation from Rankings

  Each reviewer ranks N+1 commits (targets + current PR).
  The rank of the current PR implies a score relative to the reference
  commits' known scores.

  If the current PR is ranked at position P (1-indexed, 1=best) among
  N+1 items, its implied score for that dimension is interpolated from
  the reference commits' scores based on its rank position.
-/

/-- Look up a reference commit's score. -/
def getReferenceScore
    (scores : List (CommitId × CommitScore))
    (commitId : CommitId) : CommitScore :=
  match scores.find? (fun (id, _) => id == commitId) with
  | some (_, s) => s
  | none => { difficulty := 0, novelty := 0, designQuality := 0 }

/-- Extract a single dimension's score from a CommitScore. -/
def getDimension (s : CommitScore) (dim : Nat) : Int :=
  match dim with
  | 0 => s.difficulty
  | 1 => s.novelty
  | _ => s.designQuality

/-- Compute the implied score for the current PR on one dimension,
    given a ranking and the known scores of reference commits.

    The ranking orders all items best-to-worst. We find where the
    current PR sits relative to the reference commits and interpolate.
    If ranked above all references: highest reference score + step.
    If ranked below all: lowest reference score - step.
    If between two references: average of their scores. -/
def impliedScoreFromRanking
    (ranking : Ranking)
    (currentPR : CommitId)
    (referenceScores : List (CommitId × CommitScore))
    (dim : Nat)
    (step : Nat) : Int :=
  -- Get reference scores sorted by their rank position
  let refScoresInOrder := ranking.filterMap fun cid =>
    if cid == currentPR then none
    else some (getDimension (getReferenceScore referenceScores cid) dim)
  match refScoresInOrder with
  | [] => 0
  | _ =>
    -- Find the current PR's position in the ranking (0-indexed)
    let prPos := match ranking.findIdx? (· == currentPR) with
      | some idx => idx
      | none => ranking.length
    -- Scores of refs ranked above and below the PR
    let above := ranking.take prPos |>.filterMap fun cid =>
      if cid == currentPR then none
      else some (getDimension (getReferenceScore referenceScores cid) dim)
    let below := ranking.drop (prPos + 1) |>.filterMap fun cid =>
      if cid == currentPR then none
      else some (getDimension (getReferenceScore referenceScores cid) dim)
    match above.getLast?, below.head? with
    | none, none => 0
    | none, some belowScore => belowScore + step  -- ranked above all refs
    | some aboveScore, none => aboveScore - step  -- ranked below all refs
    | some aboveScore, some belowScore => (aboveScore + belowScore) / 2

/-- Derive a score for the current PR from one reviewer's rankings. -/
def scoreFromReview
    (review : EmbeddedReview)
    (currentPR : CommitId)
    (referenceScores : List (CommitId × CommitScore))
    (step : Nat) : CommitScore :=
  { difficulty := impliedScoreFromRanking review.difficultyRanking currentPR referenceScores 0 step,
    novelty := impliedScoreFromRanking review.noveltyRanking currentPR referenceScores 1 step,
    designQuality := impliedScoreFromRanking review.designQualityRanking currentPR referenceScores 2 step }

/-! ### Weighted Lower-Quantile

  The score at the configured quantile of the weighted distribution.
  With quantile = 1/3: the value where 1/3 of weight is below.
  Sybil inflation scores sit at the top and are ignored.
  Safe up to 66% honest for inflation; meta-review covers deflation.
-/

/-- Weighted quantile of a list of (weight, value) pairs.
    Returns the value at the point where `quantileNum/quantileDen`
    of the total weight has been accumulated (walking from low to high). -/
def weightedQuantile (entries : List (Nat × Int))
    (qNum : Nat := quantileNum) (qDen : Nat := quantileDen) : Int :=
  if entries.isEmpty then 0
  else
    let sorted := entries.toArray.qsort (fun a b => a.2 < b.2) |>.toList
    let totalWeight := sorted.foldl (fun acc (w, _) => acc + w) 0
    if totalWeight == 0 then 0
    else
      -- Target: first value where cumulative weight ≥ totalWeight * qNum / qDen
      let target := totalWeight * qNum / qDen
      let (_, result) := sorted.foldl (fun (cumWeight, best) (w, v) =>
        let newCum := cumWeight + w
        if cumWeight ≤ target then (newCum, v) else (newCum, best)
      ) (0, sorted.head!.2)
      result

/-- Derive a score for the current PR from all approved reviews.

    For each reviewer, compute the implied score from their rankings.
    Then take the weighted quantile across all reviewers per dimension.

    Reviews from non-reviewers (weight = 0) are silently ignored. -/
def deriveScore
    (reviews : List EmbeddedReview)
    (currentPR : CommitId)
    (referenceScores : List (CommitId × CommitScore))
    (step : Nat)
    (getWeight : ContributorId → Nat) : CommitScore :=
  let weightedScores := reviews.filterMap fun (r : EmbeddedReview) =>
    let w := getWeight r.reviewer
    if w == 0 then none
    else some (w, scoreFromReview r currentPR referenceScores step)
  if weightedScores.isEmpty then { difficulty := 0, novelty := 0, designQuality := 0 }
  else
    let dEntries := weightedScores.map (fun (w, s) => (w, s.difficulty))
    let nEntries := weightedScores.map (fun (w, s) => (w, s.novelty))
    let qEntries := weightedScores.map (fun (w, s) => (w, s.designQuality))
    { difficulty := weightedQuantile dEntries
      novelty := weightedQuantile nEntries
      designQuality := weightedQuantile qEntries }

/-! ### Reward Computation -/

/-- Compute reward deltas for a single signed commit.

    Steps:
    1. Validate comparison targets against hash(prId).
    2. Filter reviews by meta-review (exclude thumbed-down reviews).
    3. Check minimum approved reviews from weighted reviewers.
    4. Derive score from rankings using weighted lower-quantile.
    5. Compute contributor reward (capped, zero if score is zero).
    6. Compute reviewer rewards (split by weight, capped).

    Returns (deltas, commitScore). -/
def commitRewards
    (rp : RewardParams)
    (commit : SignedCommit)
    (pastCommitIds : List CommitId)
    (referenceScores : List (CommitId × CommitScore))
    (getWeight : ContributorId → Nat)
    : List RewardDelta × CommitScore :=
  let zeroScore : CommitScore := { difficulty := 0, novelty := 0, designQuality := 0 }
  -- Step 1: Validate comparison targets
  if !validateComparisonTargets commit pastCommitIds then
    ([], zeroScore)
  else
    -- Step 2: Filter reviews by meta-review
    let approvedReviews := filterReviews commit.reviews commit.metaReviews getWeight
    -- Step 3: Check minimum approved reviews from weighted reviewers
    let weightedReviews := approvedReviews.filter fun (r : EmbeddedReview) =>
      getWeight r.reviewer > 0
    if weightedReviews.length < rp.minReviews then
      ([], zeroScore)
    else
      -- Step 4: Derive score
      let score :=
        if pastCommitIds.isEmpty then
          let bs := (rp.bootstrapScore : Int)
          { difficulty := bs, novelty := bs, designQuality := bs : CommitScore }
        else
          deriveScore weightedReviews commit.id referenceScores rp.rankStep getWeight
      let weightedScore := score.weighted
      -- Step 5: Contributor reward
      let contributorShare := rp.emission * (rp.reviewerShareDen - rp.reviewerShareNum) / rp.reviewerShareDen
      let contributorReward := min contributorShare rp.contributorCap
      let contributorDelta : RewardDelta := {
        recipient := commit.author,
        amount := if weightedScore == 0 then 0 else contributorReward,
        kind := .contribution
      }
      -- Step 6: Reviewer rewards (only for weighted approved reviewers)
      let reviewerPool := rp.emission * rp.reviewerShareNum / rp.reviewerShareDen
      let reviewerDeltas := if weightedReviews.isEmpty then []
        else
          let totalReviewWeight := weightedReviews.foldl
            (fun acc (r : EmbeddedReview) => acc + getWeight r.reviewer) 0
          if totalReviewWeight == 0 then []
          else weightedReviews.map fun (r : EmbeddedReview) =>
            let w := getWeight r.reviewer
            let raw := reviewerPool * w / totalReviewWeight
            let capped := min raw rp.reviewerCap
            { recipient := r.reviewer, amount := capped, kind := .review : RewardDelta }
      (contributorDelta :: reviewerDeltas, score)

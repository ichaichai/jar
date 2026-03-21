/-
  genesis_finalize CLI

  Input:  {"indices": [...]}
  Output: {"balances": [{"id": "...", "amount": N}, ...],
           "weights": [{"id": "...", "weight": N}, ...]}
-/

import Genesis.Cli.Common

open Lean (Json ToJson toJson fromJson? FromJson)
open Genesis.Cli

def main : IO UInt32 := runJsonPipe fun j => do
  let indices ← IO.ofExcept (j.getObjValAs? (List CommitIndex) "indices")
  let balances := finalize indices
  let weights := finalWeights indices
  let balancesJson := balances.map fun (id, amount) =>
    Json.mkObj [("id", toJson id), ("amount", toJson amount)]
  let weightsJson := weights.map fun (id, weight) =>
    Json.mkObj [("id", toJson id), ("weight", toJson weight)]
  return Json.mkObj [
    ("balances", Json.arr balancesJson.toArray),
    ("weights", Json.arr weightsJson.toArray)
  ]

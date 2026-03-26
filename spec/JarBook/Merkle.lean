import VersoManual
import Jar.Merkle

open Verso.Genre Manual
open Jar.Merkle

set_option verso.docstring.allowMissing true

#doc (Manual) "Merkle Structures" =>

Merkle trie, binary Merkle tree, and Merkle Mountain Range constructions
used for state commitment and availability (GP Appendix D).

# Trie Nodes

{docstring Jar.Merkle.Node}

{docstring Jar.Merkle.encodeBranch}

{docstring Jar.Merkle.encodeLeaf}

# State Trie

{docstring Jar.Merkle.trieRoot}

{docstring Jar.Merkle.stateRoot}

# Binary Merkle Tree

{docstring Jar.Merkle.binaryMerkleRoot}

{docstring Jar.Merkle.constDepthMerkleRoot}

# Merkle Mountain Range

MMR operations (`mmrAppend`, `mmrSuperPeak`) are defined in `Jar.State` as part of
the block-level state transition (GP Appendix E).

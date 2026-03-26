import VersoManual
import Jar.Erasure

open Verso.Genre Manual
open Jar.Erasure

set_option verso.docstring.allowMissing true

#doc (Manual) "Erasure Coding" =>

Reed-Solomon erasure coding over GF(2^16) for data availability (GP Appendix H).
Ensures that any 342 of 1023 chunks suffice to reconstruct the original data.

# Galois Field GF(2^16)

{docstring Jar.Erasure.GF16}

GF(2^16) arithmetic uses log/exp tables built from the Cantor basis
(see `CANTOR_BASIS`, `buildExpLog`, `buildSkew` in `Jar.Erasure`).

# Encoding and Recovery

{docstring Jar.Erasure.erasureCode}

{docstring Jar.Erasure.erasureRecover}

# Segment Operations

{docstring Jar.Erasure.split}

{docstring Jar.Erasure.join}

{docstring Jar.Erasure.erasureCodeSegment}

{docstring Jar.Erasure.recoverSegment}

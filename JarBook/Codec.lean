import VersoManual
import Jar.Codec

open Verso.Genre Manual

set_option verso.docstring.allowMissing true

#doc (Manual) "Serialization Codec" =>

Binary encoding of protocol types for hashing and network transmission (GP Appendix C).
All encodings are little-endian.

# Primitive Encoders

{docstring Jar.encodeFixedNat}

{docstring Jar.decodeFixedNat}

{docstring Jar.encodeNat}

{docstring Jar.encodeOption}

{docstring Jar.encodeLengthPrefixed}

{docstring Jar.encodeBits}

# Work Types

{docstring Jar.encodeWorkResult}

{docstring Jar.encodeAvailSpec}

{docstring Jar.encodeRefinementContext}

{docstring Jar.encodeWorkDigest}

{docstring Jar.encodeWorkReport}

# Extrinsic Encoders

{docstring Jar.encodeTicket}

{docstring Jar.encodeTicketProof}

{docstring Jar.encodeAssurance}

{docstring Jar.encodeGuarantee}

{docstring Jar.encodeDisputes}

{docstring Jar.encodePreimages}

# Block Encoding

{docstring Jar.encodeEpochMarker}

{docstring Jar.encodeUnsignedHeader}

{docstring Jar.encodeHeader}

{docstring Jar.encodeExtrinsic}

{docstring Jar.encodeBlock}

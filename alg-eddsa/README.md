EdDSA Algorithm for JWT / JWS
=============================

**Important:** This package relies on an external package to provide Ed448 and that package is marked as unstable by it's developers so use Ed448 with care.

This package implements a verification and siging provider using the EdDSA algorithms for JWT / JWS as specified in RFC 8037.

This package is fully covered by unit tests to ensure correctness.

Please note that this package is currently only tested against itself since there are not many implementations of RFC 8037 out there.
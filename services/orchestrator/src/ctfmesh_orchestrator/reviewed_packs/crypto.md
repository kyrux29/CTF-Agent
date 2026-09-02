# Crypto checklist — reviewed pack v1

Scope: work from supplied ciphertext, parameters, and observations; do not invent
missing values or replace verification with a plausible plaintext.

1. Normalize encodings and record exact parameters before choosing an attack family.
2. Check trivial structure, reuse, malformed padding, and small-parameter cases first.
3. Use local Python, `gmpy2`, `pycryptodome`, and Z3 in `/work` for reproducible calculations.
4. Validate a recovered relation against the original observed data before progressing.
5. Send a flag candidate only when a complete value appears in an observation artifact.

# Anti-exfil API

Implements the two-round BIP draft `bip-antiexfil-s2c:b2dcb96b`. Schnorr entry
points are available when `NGU_INCL_SCHNORR=1`; ECDSA is always available.

- `ngu.antiexfil.commit(key, digest, host_commitment)` returns compressed `Q` (33 bytes).
- `ngu.antiexfil.commit_schnorr(key, digest, host_commitment)` returns even-y x-only `Q` (32 bytes).
- `ngu.antiexfil.sign(key, digest, host_commitment, rho)` returns `(signature_object, Q)`.
- `ngu.antiexfil.sign_schnorr(key, digest, host_commitment, rho)` returns `(signature64, Q)`.
- `ngu.antiexfil.verify(signature_object, digest, pubkey_object, Q, rho)` returns a boolean.
- `ngu.antiexfil.verify_schnorr(signature64, digest, xonly_pubkey_object, Q, rho)` returns a boolean.

`key` is a 32-byte secret or a `ngu.secp256k1.keypair`. `digest`,
`host_commitment` and `rho` are each 32 bytes. Invalid signing inputs raise
`ValueError`; verification returns false for invalid points/signatures/bindings,
and raises for wrong argument types or lengths. `keypair.clear()` explicitly
wipes a caller-owned keypair; caller-owned secret buffers also remain the
caller's responsibility.

Host commitments use tagged SHA256 with `s2c/ecdsa/data` or
`s2c/schnorr/data`. Signing checks that `rho` opens the commitment. Nonces are
derived internally using libsecp256k1 RFC6979, including digest reduction
(ECDSA), or BIP340 with the host commitment as auxiliary data (Schnorr). Both
schemes reject tweak hashes >= the curve order, matching secp256k1-zkp; zero
tweaks are valid. Secret nonce/key copies are wiped before returning or raising. The API never exposes `q` or `k` to Python.

The caller must check round-2 `Q` against the round-1 commitment before
releasing a signature. The host must pin both round-1 commitments independently
of the signer's final output, then perform verification with the pinned `Q`.
The verification API checks the binding and ordinary signature; it cannot prove
that the supplied `Q` was received before revealing `rho`. This is not a
single-round protocol. Retry failures with the same transcript and never reuse
host entropy for a different signature.

## Compatibility checks

`ngu_tests/antiexfil_compat.py` runs under CPython and compares ngu's ECDSA
commitments and compact signatures byte-for-byte with separately built
secp256k1-zkp libraries. It also checks external host verification and the BIP
reference generator. Cases include digests `0`, `n-1`, `n`, `n+1`, and `2^256-1`.
The checked snapshots are:

- Jade: BlockstreamResearch/secp256k1-zkp `45f6f0f158c5ae80a2c8a53398ea4adbf19af6dc`.
- BitBox: BitBoxSwiss/secp256k1-zkp `e54d68ea3ad14600839513473c2959ee414972db`.

Build each snapshot as a shared library with `ENABLE_MODULE_ECDSA_S2C=1`,
then pass its path using `--jade` or `--bitbox`; see the script's usage text.
These checks cover ECDSA cryptography, not the devices' transport protocols.
Schnorr remains the BIP's extension.

For tweak boundaries, compile `ngu_tests/antiexfil_tweak_override.c` separately
with `-I/path/to/libngu/libs` and link a **test-only** MicroPython executable
with that object and `-Wl,--wrap=secp256k1_tagged_sha256`. Run
`ngu_tests/antiexfil_tweak_bounds.py` with `NGU_TEST_AE_TWEAK` set to the
64-digit hex encoding of `0`, `n-1`, `n`, `n+1`, or `2^256-1`. This forces hash
outputs that cannot feasibly be obtained from normal transcripts and checks
both signing and verification. Never include the override in production.

# Anti-exfil API

Implements the two-round BIP draft `bip-antiexfil-s2c:9781494c`. Schnorr entry
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
derived internally using raw-digest RFC6979 (ECDSA) or BIP340 with the host
commitment as auxiliary data (Schnorr). Secret nonce/key copies are wiped
before returning or raising. The API never exposes `q` or `k` to Python.

The caller must check round-2 `Q` against the round-1 commitment before
releasing a signature. The host must pin both round-1 commitments independently
of the signer's final output, then perform verification with the pinned `Q`.
The verification API checks the binding and ordinary signature; it cannot prove
that the supplied `Q` was received before revealing `rho`. This is not a
single-round protocol. Retry failures with the same transcript and never reuse
host entropy for a different signature.

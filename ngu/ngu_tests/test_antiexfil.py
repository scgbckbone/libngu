import ngu


for i in range(10):
    kp = ngu.secp256k1.keypair()
    msg = ngu.random.bytes(32)
    msg_hash = ngu.hash.sha256t(b"ngu_tests", msg)
    q = bytes(31) + b'\x02'
    rho = b'r' * 32

    sig_schnorr, Q = ngu.antiexfil.sign_schnorr(kp, msg_hash, q, rho)
    assert len(sig_schnorr) == 64
    assert len(Q) == 32
    assert ngu.antiexfil.verify_schnorr(sig_schnorr, msg_hash, kp.xonly_pubkey(), Q, rho)
    assert ngu.secp256k1.verify_schnorr(sig_schnorr, msg_hash, kp.xonly_pubkey())
    assert not ngu.antiexfil.verify_schnorr(
        sig_schnorr, msg_hash, kp.xonly_pubkey(), Q, bytes(32))

    sig, Q2 = ngu.antiexfil.sign(kp, msg_hash, q, rho)
    assert len(Q2) == 33
    assert ngu.antiexfil.verify(sig, msg_hash, kp.pubkey(), Q2, rho)
    assert sig.verify_recover(msg_hash).to_bytes() == kp.pubkey().to_bytes()
    assert not ngu.antiexfil.verify(sig, msg_hash, kp.pubkey(), Q2, bytes(32))

print('PASS - test_antiexfil')


#
# 1-round (non-interactive / airgap-compatible) anti-exfil
#
# The very same sign()/verify() primitives are driven as a SINGLE round: the host
# sends one value -- nonce_commit `n` (fresh entropy) -- alongside the message, and
# the device answers with (sig, Q). What makes a single round safe is that the
# device has no freedom to grind a key-leaking nonce: it derives its nonce
# contribution `q` *deterministically* from (seckey, msg, n), BIP-340 style. That
# derivation is the signing firmware's job (this mimics Coldcard doing it in
# afirmware), so it lives here in the test rather than in the C primitive.
#
# The host then checks the sign-to-contract binding R = Q + H(Q || msg || n)*G and
# a normal signature verify. Tags match scgbckbone/secp256k1#1 (BIP0XYZ).

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _xor32(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def device_nonce_ecdsa(kp, msg32, n, counter=0):
    # t = H_aux(n) ^ seckey ;  q = H_nonce(t || msg || n || counter)
    masked = _xor32(ngu.hash.sha256t(b"BIP0XYZ/aux", n), kp.privkey())
    return ngu.hash.sha256t(b"BIP0XYZ/nonce", masked + msg32 + n + bytes([counter]))


def device_nonce_schnorr(kp, msg32, n):
    # like ECDSA but on the BIP-340 even-Y effective key
    d = int.from_bytes(kp.privkey(), "big")
    if kp.xonly_pubkey().parity() == 1:
        d = CURVE_ORDER - d
    masked = _xor32(ngu.hash.sha256t(b"BIP0XYZ/aux", n), d.to_bytes(32, "big"))
    return ngu.hash.sha256t(b"BIP0XYZ/nonce", masked + msg32 + n)


for i in range(10):
    kp = ngu.secp256k1.keypair()
    msg = ngu.random.bytes(32)
    msg_hash = ngu.hash.sha256t(b"ngu_tests", msg)

    # HOST -> DEVICE: fresh per-signature entropy (the single round)
    n = ngu.random.bytes(32)
    n_other = ngu.random.bytes(32)

    # --- ECDSA ---
    q = device_nonce_ecdsa(kp, msg_hash, n)
    sig, Q = ngu.antiexfil.sign(kp, msg_hash, q, n)
    assert len(Q) == 33

    # non-interactive => fully deterministic: re-running yields an identical sig
    assert device_nonce_ecdsa(kp, msg_hash, n) == q
    sig_r, Q_r = ngu.antiexfil.sign(kp, msg_hash, q, n)
    assert sig_r.to_bytes() == sig.to_bytes()
    assert Q_r == Q

    # HOST verifies against the entropy it chose
    assert ngu.antiexfil.verify(sig, msg_hash, kp.pubkey(), Q, n)
    # it is also a normal, valid ECDSA signature
    assert sig.verify_recover(msg_hash).to_bytes() == kp.pubkey().to_bytes()
    # binding: any other host entropy must fail the anti-exfil check
    assert not ngu.antiexfil.verify(sig, msg_hash, kp.pubkey(), Q, n_other)
    # different host entropy forces a different nonce
    assert device_nonce_ecdsa(kp, msg_hash, n_other) != q

    # --- Schnorr ---
    qs = device_nonce_schnorr(kp, msg_hash, n)
    sig_s, Qs = ngu.antiexfil.sign_schnorr(kp, msg_hash, qs, n)
    assert len(sig_s) == 64 and len(Qs) == 32

    assert device_nonce_schnorr(kp, msg_hash, n) == qs
    sig_s_r, Qs_r = ngu.antiexfil.sign_schnorr(kp, msg_hash, qs, n)
    assert sig_s_r == sig_s and Qs_r == Qs

    assert ngu.antiexfil.verify_schnorr(sig_s, msg_hash, kp.xonly_pubkey(), Qs, n)
    assert ngu.secp256k1.verify_schnorr(sig_s, msg_hash, kp.xonly_pubkey())
    assert not ngu.antiexfil.verify_schnorr(sig_s, msg_hash, kp.xonly_pubkey(), Qs, n_other)
    assert device_nonce_schnorr(kp, msg_hash, n_other) != qs

print('PASS - test_antiexfil 1-round')


#
# negative / failure tests for the anti-exfil primitives
#
# Two distinct failure modes are covered:
#   * verify() must REJECT (return False, never crash) whenever the
#     sign-to-contract binding R = Q + H(Q || msg || rho)*G does not hold;
#   * sign()/verify() must RAISE on malformed input (bad length / type / scalar).

def raises(exc, fn, *args):
    try:
        fn(*args)
    except exc:
        return True
    except Exception:
        raise AssertionError("wrong exception type")
    raise AssertionError("no exception raised")


kp = ngu.secp256k1.keypair()
kp2 = ngu.secp256k1.keypair()                       # an unrelated key
md = ngu.hash.sha256t(b"ngu_tests", ngu.random.bytes(32))
other_md = ngu.hash.sha256t(b"ngu_tests", ngu.random.bytes(32))
rho = ngu.random.bytes(32)
q = bytes(31) + b"\x02"                              # a valid nonce scalar

# ---- ECDSA ----
sig, Q = ngu.antiexfil.sign(kp, md, q, rho)
assert ngu.antiexfil.verify(sig, md, kp.pubkey(), Q, rho)                        # sanity: good case

# verify must REJECT (return False) -- broken binding, must not crash:
assert not ngu.antiexfil.verify(sig, other_md, kp.pubkey(), Q, rho)             # invalid message
assert not ngu.antiexfil.verify(sig, md, kp.pubkey(), Q, ngu.random.bytes(32))  # wrong host entropy
_, Q_bad = ngu.antiexfil.sign(kp, md, bytes(31) + b"\x03", rho)
assert not ngu.antiexfil.verify(sig, md, kp.pubkey(), Q_bad, rho)               # wrong Q => wrong tweak
assert not ngu.antiexfil.verify(sig, md, kp2.pubkey(), Q, rho)                  # wrong pubkey
assert not ngu.antiexfil.verify(sig, md, kp.pubkey(), bytes(33), rho)           # unparseable Q (no crash)
# a normal, non-anti-exfil signature has an uncommitted nonce -> must be rejected
assert not ngu.antiexfil.verify(ngu.secp256k1.sign(kp, md, 0), md, kp.pubkey(), Q, rho)

# verify must RAISE on bad types / lengths:
assert raises(TypeError, ngu.antiexfil.verify, sig.to_bytes(), md, kp.pubkey(), Q, rho)   # sig not an object
assert raises(TypeError, ngu.antiexfil.verify, sig, md, kp.xonly_pubkey(), Q, rho)        # wrong pubkey type
assert raises(ValueError, ngu.antiexfil.verify, sig, md[:31], kp.pubkey(), Q, rho)        # md len
assert raises(ValueError, ngu.antiexfil.verify, sig, md, kp.pubkey(), Q[:32], rho)        # Q len != 33
assert raises(ValueError, ngu.antiexfil.verify, sig, md, kp.pubkey(), Q, rho[:31])        # rho len

# sign must RAISE on bad lengths / invalid scalars:
assert raises(ValueError, ngu.antiexfil.sign, kp, md[:31], q, rho)             # md len
assert raises(ValueError, ngu.antiexfil.sign, kp, md, q[:31], rho)             # q len
assert raises(ValueError, ngu.antiexfil.sign, kp, md, q, rho[:31])             # rho len
assert raises(ValueError, ngu.antiexfil.sign, kp, md, bytes(32), rho)         # q = 0 (invalid scalar)
assert raises(ValueError, ngu.antiexfil.sign, bytes(32), md, q, rho)          # seckey = 0 (invalid)

# ---- Schnorr ----
ssig, sQ = ngu.antiexfil.sign_schnorr(kp, md, q, rho)
assert ngu.antiexfil.verify_schnorr(ssig, md, kp.xonly_pubkey(), sQ, rho)                  # sanity

assert not ngu.antiexfil.verify_schnorr(ssig, other_md, kp.xonly_pubkey(), sQ, rho)              # invalid message
assert not ngu.antiexfil.verify_schnorr(ssig, md, kp.xonly_pubkey(), sQ, ngu.random.bytes(32))   # wrong entropy
_, sQ_bad = ngu.antiexfil.sign_schnorr(kp, md, bytes(31) + b"\x03", rho)
assert not ngu.antiexfil.verify_schnorr(ssig, md, kp.xonly_pubkey(), sQ_bad, rho)                # wrong Q => wrong tweak
assert not ngu.antiexfil.verify_schnorr(ssig, md, kp2.xonly_pubkey(), sQ, rho)                   # wrong pubkey
_tamper = bytearray(ssig)
_tamper[0] ^= 1
assert not ngu.antiexfil.verify_schnorr(bytes(_tamper), md, kp.xonly_pubkey(), sQ, rho)          # tampered R
assert not ngu.antiexfil.verify_schnorr(ssig, md, kp.xonly_pubkey(), bytes(32), rho)             # unparseable Q (no crash)
# a normal BIP-340 signature has an uncommitted nonce -> must be rejected
assert not ngu.antiexfil.verify_schnorr(
    ngu.secp256k1.sign_schnorr(kp, md, bytes(32)), md, kp.xonly_pubkey(), sQ, rho)

assert raises(ValueError, ngu.antiexfil.verify_schnorr, ssig[:63], md, kp.xonly_pubkey(), sQ, rho)  # sig len
assert raises(TypeError, ngu.antiexfil.verify_schnorr, ssig, md, kp.pubkey(), sQ, rho)              # wrong xonly type
assert raises(ValueError, ngu.antiexfil.verify_schnorr, ssig, md[:31], kp.xonly_pubkey(), sQ, rho)  # md len
assert raises(ValueError, ngu.antiexfil.verify_schnorr, ssig, md, kp.xonly_pubkey(), sQ[:31], rho)  # Q len != 32
assert raises(ValueError, ngu.antiexfil.verify_schnorr, ssig, md, kp.xonly_pubkey(), sQ, rho[:31])  # rho len

assert raises(ValueError, ngu.antiexfil.sign_schnorr, kp, md[:31], q, rho)        # md len
assert raises(ValueError, ngu.antiexfil.sign_schnorr, kp, md, q[:31], rho)        # q len
assert raises(ValueError, ngu.antiexfil.sign_schnorr, kp, md, q, rho[:31])        # rho len
assert raises(ValueError, ngu.antiexfil.sign_schnorr, kp, md, bytes(32), rho)    # q = 0 (invalid scalar)
assert raises(ValueError, ngu.antiexfil.sign_schnorr, bytes(32), md, q, rho)     # seckey = 0 (invalid)

print('PASS - test_antiexfil negative')

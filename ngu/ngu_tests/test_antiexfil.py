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

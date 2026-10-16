import ngu
from binascii import unhexlify as uh
from ngu_tests.ae_vectors import vectors


def raises(kind, fn, *args):
    try:
        fn(*args)
    except kind:
        return
    raise AssertionError('expected exception')


for vector in vectors:
    v = {key: uh(value) for key, value in vector.items()}
    sk, md, rho = v['sk'], v['md'], v['rho']
    kp = ngu.secp256k1.keypair(sk)
    for schnorr in (False, True):
        if schnorr and not hasattr(ngu.antiexfil, 'sign_schnorr'):
            continue
        commit = ngu.antiexfil.commit_schnorr if schnorr else ngu.antiexfil.commit
        sign = ngu.antiexfil.sign_schnorr if schnorr else ngu.antiexfil.sign
        verify = ngu.antiexfil.verify_schnorr if schnorr else ngu.antiexfil.verify
        prefix = 's' if schnorr else ''
        hc, Q, expected = v[prefix+'hc'], v[prefix+'Q'], v[prefix+'sig']
        pub = kp.xonly_pubkey() if schnorr else kp.pubkey()
        assert ngu.hash.sha256t(b's2c/schnorr/data' if schnorr else b's2c/ecdsa/data', rho) == hc
        assert commit(sk, md, hc) == Q
        assert commit(kp, md, hc) == Q
        sig, returned_Q = sign(sk, md, hc, rho)
        encoded = sig if schnorr else sig.to_bytes()[1:]
        assert encoded == expected and returned_Q == Q
        sig2, Q2 = sign(kp, md, hc, rho)
        assert (sig2 if schnorr else sig2.to_bytes()[1:]) == expected and Q2 == Q
        assert verify(sig, md, pub, Q, rho)
        assert not verify(sig, md, pub, Q, bytes(32))
        assert not verify(sig, b'\x42'*32, pub, Q, rho)
        assert not verify(sig, md, pub, bytes(len(Q)), rho)
        other = ngu.secp256k1.keypair(bytes(31) + b'\x07')
        assert not verify(sig, md, other.xonly_pubkey() if schnorr else other.pubkey(), Q, rho)
        other.clear()
        raises(ValueError, sign, sk, md, bytes(32), rho)
        raises(ValueError, sign, bytes(32), md, hc, rho)
        raises(ValueError, commit, bytes(32), md, hc)
        raises(ValueError, commit, sk, md[:31], hc)
        raises(ValueError, commit, sk, md, hc[:31])
        raises(ValueError, sign, sk, md, hc, rho[:31])
        raises(ValueError, verify, sig, md, pub, Q[:-1], rho)
        raises(TypeError, verify, sig, md, kp, Q, rho)
        changed_md = bytes([md[0] ^ 0x80]) + md[1:]
        assert commit(sk, changed_md, hc) != Q
        assert commit(sk, md, bytes(32)) != Q
        # A valid ordinary signature must not pass the anti-exfil binding.
        plain = (ngu.secp256k1.sign_schnorr(sk, md, bytes(32)) if schnorr else
                 ngu.secp256k1.sign(sk, md, 0))
        assert not verify(plain, md, pub, Q, rho)
    kp.clear()
    assert kp.privkey() == bytes(32)
    raises(ValueError, ngu.antiexfil.commit, kp, md, v["hc"])

# RFC6979 bits2octets must agree for digest representatives modulo n.
# These values are impractical to obtain as transaction hashes, so exercise
# them directly at the API boundary.
order = uh('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')
order_plus_one = uh('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142')
sk = bytes(31) + b'\x01'
rho = b'\x21' * 32
hc = ngu.hash.sha256t(b's2c/ecdsa/data', rho)
for md, reduced in ((order, bytes(32)), (order_plus_one, sk)):
    assert ngu.antiexfil.commit(sk, md, hc) == ngu.antiexfil.commit(sk, reduced, hc)
    assert ngu.antiexfil.sign(sk, md, hc, rho)[0].to_bytes() == ngu.antiexfil.sign(sk, reduced, hc, rho)[0].to_bytes()

print('PASS - anti-exfil BIP vectors, retries, and invalid transcripts')

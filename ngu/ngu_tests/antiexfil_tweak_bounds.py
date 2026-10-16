# Run with the test-only MicroPython linked with antiexfil_tweak_override.c:
# NGU_TEST_AE_TWEAK=<64 hex digits> /path/to/test-micropython this-file.py
import ngu
import os
from binascii import unhexlify

tweak = unhexlify(os.getenv('NGU_TEST_AE_TWEAK'))
order = unhexlify('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')
sk, md, rho = b'\x01' * 32, b'\x02' * 32, b'\x03' * 32
for schnorr in (False, True):
    if schnorr and not hasattr(ngu.antiexfil, 'sign_schnorr'):
        continue
    hc = ngu.hash.sha256t(b's2c/schnorr/data' if schnorr else b's2c/ecdsa/data', rho)
    commit = ngu.antiexfil.commit_schnorr if schnorr else ngu.antiexfil.commit
    sign = ngu.antiexfil.sign_schnorr if schnorr else ngu.antiexfil.sign
    verify = ngu.antiexfil.verify_schnorr if schnorr else ngu.antiexfil.verify
    kp = ngu.secp256k1.keypair(sk)
    pk = kp.xonly_pubkey() if schnorr else kp.pubkey()
    Q = commit(sk, md, hc)
    if tweak >= order:
        try:
            sign(sk, md, hc, rho)
        except ValueError:
            pass
        else:
            raise AssertionError('overflow tweak accepted')
        sig = (ngu.secp256k1.sign_schnorr(sk, md, bytes(32)) if schnorr
               else ngu.secp256k1.sign(sk, md, 0))
        assert not verify(sig, md, pk, Q, rho)
    else:
        sig, Q2 = sign(sk, md, hc, rho)
        assert Q == Q2
        assert verify(sig, md, pk, Q, rho)
    kp.clear()
print('PASS - tweak boundary signing and verification')

try:
    # Desktop: make test vectors
    from ecdsa import SigningKey
    from ecdsa.util import sigencode_string
    from ecdsa.curves import SECP256k1
    from ecdsa.util import number_to_string
    from hashlib import sha256

    my_k = SigningKey.from_string(b'za'*16, curve=SECP256k1, hashfunc=sha256)

    with open('test_k1_gen.py', 'wt') as fd:
        print("import gc, ngu  # auto-gen", file=fd)
        print("my_pubkey = b'\\x04' + %r" % my_k.get_verifying_key().to_string(), file=fd)

        for pk in [b'12'*16, b'\x0f'+(b'\xff'*31), bytes(31)+b'\x01']:
            key = SigningKey.from_string(pk, curve=SECP256k1, hashfunc=sha256)
            expect = key.get_verifying_key().to_string('compressed')
            print('x = ngu.secp256k1.keypair(%r)' % pk, file=fd)
            print('assert x.pubkey().to_bytes() == %r\n\n' % expect, file=fd)

            # ECDH
            pt = my_k.privkey.secret_multiplier * key.get_verifying_key().pubkey.point
            kk = number_to_string(pt.x(), SECP256k1.order) \
                                    + number_to_string(pt.y(), SECP256k1.order)
            md = sha256(kk).digest()
            print('assert x.ecdh_multiply(my_pubkey) == %r\n\n' % md, file=fd)

        print("print('PASS - %s')" % fd.name, file=fd)
        print("run code now in: %s" % fd.name)

    import sys
    sys.exit(0)
except ImportError: 
    pass

import ngu
from ubinascii import unhexlify

# pubkeys
p = ngu.secp256k1.pubkey(b'\x02'*33)
assert p.to_bytes() == p.to_bytes(False) == b'\x02'*33

odd = b'\x03'+'\x02'*32
p = ngu.secp256k1.pubkey(odd)
assert p.to_bytes() == odd

uncomp = p.to_bytes(True)
p2 = ngu.secp256k1.pubkey(uncomp)
assert p2.to_bytes(True) == uncomp
assert p.to_bytes() == odd != uncomp

# sigs
pk = b'x'*32
md = b'z'*32
sig = ngu.secp256k1.sign(pk, md, 0)
assert len(sig.to_bytes()) == 65
pubkey = sig.verify_recover(md)
assert len(pubkey.to_bytes()) == 33

sig2 = ngu.secp256k1.sign(pk, md, 0)
assert sig.to_bytes() == sig2.to_bytes()

pair = ngu.secp256k1.keypair(pk)
assert pair.privkey() == pk
sig4 = ngu.secp256k1.sign(pair, md, 0)
assert sig.to_bytes() == sig4.to_bytes()

sig3 = ngu.secp256k1.signature(sig2.to_bytes()[:-1] + b'\0')
pubkey3 = sig3.verify_recover(md)
assert pubkey3 != pubkey

# keypair tweaking
kp = ngu.secp256k1.keypair()
tweak32 = ngu.random.bytes(32)
kpt = kp.xonly_tweak_add(tweak32)
assert kpt.privkey() != kp.privkey()
assert kpt.pubkey().to_bytes() != kp.pubkey().to_bytes()
assert kpt.xonly_pubkey().to_bytes() != kp.xonly_pubkey().to_bytes()

secret = b'w\xdary\x19bs,\x05\xd4E\xeb\xf3\x0c2\xf2\x7f,\x81\xce\x8d[\xf9ONq\xf70C\x1d\xbfZ'
tweak = b'\xb8\xd5z\xaf\xd8\x1a\xe7\x9dtN\xfa\x86V\x83\xa0\xc7\xde\xa2\xd95T\x1bLC\xc0GC\xc6J\x8b\xcf\xd5'
target_tweaked_xonly_pub = b'lT\xe8\x84`\xbe0\x97c\x89\xc3\x90\xfa\xdeR!\xada\xe4\x18\xe4\x81\x8cL\xa7\n\xa3\x04|\x0eCK'
target_tweaked_pub = b'\x03' + target_tweaked_xonly_pub
target_tweaked_privkey = b'0\xaf\xed(\xf1}Z\xc9z#@rI\x8f\xd3\xbb\xa3 ~\x1d2.\xa5WN\xe6\xdci\xbdsM\xee'
kp = ngu.secp256k1.keypair(secret)
xo_pk = kp.xonly_pubkey()
kpt = kp.xonly_tweak_add(tweak)
xo_pkt = xo_pk.tweak_add(tweak)
assert xo_pkt.to_bytes() == target_tweaked_xonly_pub
assert kpt.privkey() == target_tweaked_privkey
assert kpt.pubkey().to_bytes() == target_tweaked_pub
assert kpt.xonly_pubkey().to_bytes() == target_tweaked_xonly_pub

# keypair tweaking with zero (MUST return the same keypair)
tweak = b"\x00" * 32
kp0 = kp.xonly_tweak_add(tweak)
assert kp0.privkey() == kp.privkey()
assert kp0.pubkey().to_bytes() == kp.pubkey().to_bytes()
assert kp0.xonly_pubkey().to_bytes() == kp.xonly_pubkey().to_bytes()
# xonly pubkey tweaking with zero (MUST return the same xonly pubkey)
xo_pk = kp.xonly_pubkey()
xo_pkt = xo_pk.tweak_add(tweak)
assert xo_pk.to_bytes() == xo_pkt.to_bytes()

# compare keypair and xonly tweaking
for i in range(10):
    tweak = ngu.random.bytes(32)
    kp = ngu.secp256k1.keypair()
    xo_pk = kp.xonly_pubkey()
    kpt = kp.xonly_tweak_add(tweak)
    xo_pkt = xo_pk.tweak_add(tweak)
    assert kpt.xonly_pubkey().to_bytes() == xo_pkt.to_bytes()
    assert kpt.xonly_pubkey().parity() == xo_pkt.parity()

# schnorr
for i in range(10):
    # random keypair
    kp = ngu.secp256k1.keypair()
    xonly_pub = kp.xonly_pubkey()
    parity = xonly_pub.parity()
    assert parity in (0, 1)
    # serialization
    xonly_pub_bytes = xonly_pub.to_bytes()
    # parsing
    xonly_pub_clone = ngu.secp256k1.xonly_pubkey(xonly_pub_bytes)
    assert xonly_pub_clone.to_bytes() == xonly_pub_bytes
    # random msg
    msg = ngu.random.bytes(32)
    msg_hash = ngu.hash.sha256t(b"ngu_tests", msg)
    aux_rand = ngu.random.bytes(32)
    sig_kp = ngu.secp256k1.sign_schnorr(kp, msg_hash, aux_rand)
    sig_raw = ngu.secp256k1.sign_schnorr(kp.privkey(), msg_hash, aux_rand)
    assert sig_kp == sig_raw
    assert ngu.secp256k1.verify_schnorr(sig_kp, msg_hash, kp.xonly_pubkey())

try:
    from b340_vectors import vectors
except ImportError:
    from ngu_tests.b340_vectors import vectors

for seckey, xonly_pub, aux_rand, msg, sig, ok in vectors:
    if seckey:
        seckey = unhexlify(seckey)
    if aux_rand:
        aux_rand = unhexlify(aux_rand)

    xonly_pub = unhexlify(xonly_pub)
    msg = unhexlify(msg)
    sig = unhexlify(sig)

    if seckey and aux_rand:
        # signing and verification
        assert sig == ngu.secp256k1.sign_schnorr(seckey, msg, aux_rand)
        assert ngu.secp256k1.verify_schnorr(sig, msg, ngu.secp256k1.xonly_pubkey(xonly_pub))
    else:
        # verification
        if ok:
            assert ngu.secp256k1.verify_schnorr(sig, msg, ngu.secp256k1.xonly_pubkey(xonly_pub))
        else:
            # must raise
            try:
                assert ngu.secp256k1.verify_schnorr(sig, msg, ngu.secp256k1.xonly_pubkey(xonly_pub))
                assert False  # MUST not get here
            except ValueError:
                pass


# privkeys look random
got = set()
for i in range(50):
    p1 = ngu.secp256k1.keypair()
    bs = p1.privkey()
    assert len(set(bs)) > 8
    assert bs not in got
    got.add(bs)
    assert p1.pubkey()


# musig

msg = 32*b"b"
tweak_bip32 = 32*b"a"
xonly_tweak = 32*b"c"
keyagg_cache = ngu.secp256k1.MusigKeyAggCache()

# not possible to get aggregate key from cache before aggregation happens
try:
    x = keyagg_cache.agg_pubkey()
    raise RuntimeError
except ValueError: pass

signer_data = []
for i in range(10):
    kp = ngu.secp256k1.keypair()
    pk = kp.pubkey()
    # onyl required arguemnt here is pubkey (first argument)
    sn, pn = ngu.secp256k1.musig_nonce_gen(pk)
    # musig_nonce_gen uses RNG for secrand if secrand is not provided (safest way)
    sn, pn = ngu.secp256k1.musig_nonce_gen(pk, ngu.random.bytes(32))
    # optionally one can also add secret key, MUST be the one sued for signing that corresponds to pk arg
    sn, pn = ngu.secp256k1.musig_nonce_gen(pk, ngu.random.bytes(32), kp.privkey())
    # optionally msg to be signed can be added - if already known
    sn, pn = ngu.secp256k1.musig_nonce_gen(pk, ngu.random.bytes(32), kp.privkey(), msg)
    # extra randomness for nonce derivation function
    # None is for optional key aggregation cache, but uninitialized key agg cache is not allowed
    sn, pn = ngu.secp256k1.musig_nonce_gen(pk, ngu.random.bytes(32), kp.privkey(), msg, None, ngu.random.bytes(32))

    pubnonce_bytes = pn.to_bytes()
    assert len(pubnonce_bytes) == 66
    pn1 = ngu.secp256k1.MusigPubNonce(pubnonce_bytes)
    assert pn1.to_bytes() == pubnonce_bytes
    signer_data.append((kp, sn, pn))

signer_pubkeys = [s[0].pubkey() for s in signer_data]

agg_xonly = ngu.secp256k1.musig_pubkey_agg(signer_pubkeys, keyagg_cache)

# ability to get proper non-xonly aggregate pubkey
agg_non_xonly = keyagg_cache.agg_pubkey()
assert agg_non_xonly.to_xonly().to_bytes() == agg_xonly.to_bytes()

# key aggregation cache is optional, if user does not intend to sign
agg_xonly1 = ngu.secp256k1.musig_pubkey_agg(signer_pubkeys, None)
assert agg_xonly.to_bytes() == agg_xonly1.to_bytes()

# without sorting (that happens by default) - aggregate key will be different
agg_xonly2 = ngu.secp256k1.musig_pubkey_agg(signer_pubkeys, None, False)  # last bool arg is for pubkey sorting
assert agg_xonly2.to_bytes() != agg_xonly.to_bytes()

tweaked_pk1 = ngu.secp256k1.musig_pubkey_xonly_tweak_add(keyagg_cache, xonly_tweak)
assert isinstance(tweaked_pk1, ngu.secp256k1.pubkey)

tweaked_pk = ngu.secp256k1.musig_pubkey_ec_tweak_add(keyagg_cache, tweak_bip32)
assert isinstance(tweaked_pk, ngu.secp256k1.pubkey)

# aggregate pubnonces
pubnonces = [tup[2] for tup in signer_data]
aggnonce = ngu.secp256k1.musig_nonce_agg(pubnonces)
aggnonce_bytes = aggnonce.to_bytes()
an1 = ngu.secp256k1.MusigAggNonce(aggnonce_bytes)
assert an1.to_bytes() == aggnonce_bytes

partial_signatures = []
for kp, sn, pn in signer_data:
    session = ngu.secp256k1.musig_nonce_process(aggnonce, msg, keyagg_cache)
    partial_signature = ngu.secp256k1.musig_partial_sign(sn, kp, keyagg_cache, session)

    # re-sign with the same secnonce causes error
    try:
        ngu.secp256k1.musig_partial_sign(sn, kp, keyagg_cache, session)
        raise RuntimeError
    except ValueError: pass

    part_sig_bytes = partial_signature.to_bytes()
    assert ngu.secp256k1.MusigPartSig(part_sig_bytes).to_bytes() == part_sig_bytes

    assert partial_signature.verify(pn, kp.pubkey(), keyagg_cache, session)

    partial_signatures.append(partial_signature)


agg_sig = ngu.secp256k1.musig_partial_sig_agg(partial_signatures, session)
assert len(agg_sig) == 64

# verify aggregate signature against aggregate tweaked pubkey
assert ngu.secp256k1.verify_schnorr(agg_sig, msg, tweaked_pk.to_xonly())


# musig type checks
kp = ngu.secp256k1.keypair()
xonly_pk = kp.xonly_pubkey()
pubkey = kp.pubkey()
keyagg_cache = ngu.secp256k1.MusigKeyAggCache()
bytes32 = ngu.random.bytes(32)
fake_keyagg_cache = ngu.random.bytes(197)
fake_nonce = ngu.random.bytes(132)
fake_session = ngu.random.bytes(133)
keyagg_cache = ngu.secp256k1.MusigKeyAggCache()
# valid nonces below
sn, pn = ngu.secp256k1.musig_nonce_gen(pubkey)

try:
    # pubkey list contains xonly keys - not classic pubkey
    ngu.secp256k1.musig_pubkey_agg([xonly_pk, xonly_pk])
    raise RuntimeError
except TypeError as e:
    assert str(e) == "pubkeys: pubkey type"

try:
    # key agg cache is wrong type
    ngu.secp256k1.musig_pubkey_agg([pubkey, pubkey], fake_keyagg_cache)
    raise RuntimeError
except TypeError as e:
    assert str(e) == "key aggregation cache type"

try:
    ngu.secp256k1.musig_pubkey_xonly_tweak_add(fake_keyagg_cache, bytes32)
    raise RuntimeError
except TypeError as e:
    assert str(e) == "key aggregation cache type"

try:
    ngu.secp256k1.musig_pubkey_ec_tweak_add(xonly_pk, bytes32)
    raise RuntimeError
except TypeError as e:
    assert str(e) == "key aggregation cache type"

for data in [kp.xonly_pubkey(), ngu.random.bytes(33)]:
    try:
        # not classic pubkey
        ngu.secp256k1.musig_nonce_gen(data)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "pubkey type"

try:
    ngu.secp256k1.musig_nonce_gen(pubkey, bytes32, kp.privkey(), bytes32, fake_keyagg_cache, bytes32)
    raise RuntimeError
except TypeError as e:
    assert str(e) == "key aggregation cache type"

for pnonces in [[pubkey,xonly_pk], [fake_nonce, fake_nonce]]:
    try:
        ngu.secp256k1.musig_nonce_agg(pnonces)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "pubnonces: pubnonce type"

try:
    ngu.secp256k1.musig_nonce_process(fake_nonce, msg, keyagg_cache)
    raise RuntimeError
except TypeError as e:
    assert str(e) == "aggnonce type"

try:
    ngu.secp256k1.musig_nonce_process(aggnonce, msg, fake_keyagg_cache)
    raise RuntimeError
except TypeError as e:
    assert str(e) == "key aggregation cache type"

for data in [
    ((pn, kp, keyagg_cache, fake_session), "secnonce type"),
    ((sn, pubkey, keyagg_cache, fake_session), "keypair type"),
    ((sn, kp, fake_keyagg_cache, fake_session), "key aggregation cache type"),
    ((sn, kp, keyagg_cache, fake_session), "session type"),
]:
    args = data[0]
    err = data[1]
    try:
        ngu.secp256k1.musig_partial_sign(*args)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == err

for data in [
    ((sn, pubkey, keyagg_cache, fake_session), "pubnonce type"),
    ((pn, xonly_pk, keyagg_cache, fake_session), "pubkey type"),
    ((pn, pubkey, fake_keyagg_cache, fake_session), "key aggregation cache type"),
    ((pn, pubkey, keyagg_cache, fake_session), "session type"),
]:
    args = data[0]
    err = data[1]
    try:
        partial_signatures[0].verify(*args)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == err


for data in [
    (([bytes32, bytes32], fake_session), "part_sigs: part sig type"),
    (([xonly_pk, pubkey], fake_session), "part_sigs: part sig type"),
    ((partial_signatures, fake_session), "session type"),
]:
    args = data[0]
    err = data[1]
    try:
        ngu.secp256k1.musig_partial_sig_agg(*args)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == err, str(e)

print("PASS - test_k1")

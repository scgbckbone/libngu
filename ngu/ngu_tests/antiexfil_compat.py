#!/usr/bin/env python3
"""Cross-check ngu against independently built Jade/BitBox secp256k1-zkp.

Run with CPython (not frozen into firmware):
  python3 antiexfil_compat.py --mpy /path/to/micropython \
      --jade /path/to/jade-secp.so --bitbox /path/to/bitbox-secp.so \
      --reference /path/to/bips/bip-antiexfil/generate-test-vectors.py

The shared libraries must enable ECDSA_S2C. BitBox's API adds a recid output.
"""
import argparse
import contextlib
import ctypes as c
import hashlib
import io
import json
import runpy
import subprocess


def check_library(path, bitbox, transcripts):
    lib = c.CDLL(path)
    ptr = c.c_void_p
    lib.secp256k1_context_create.argtypes = [c.c_uint]
    lib.secp256k1_context_create.restype = ptr
    lib.secp256k1_context_destroy.argtypes = [ptr]
    ctx = lib.secp256k1_context_create(1)
    assert ctx

    def call(name, *args):
        fn = getattr(lib, 'secp256k1_' + name)
        fn.argtypes = [ptr] * (len(args) + 1)
        fn.restype = c.c_int
        return fn(ctx, *args)

    try:
        for v in transcripts:
            sk, md, rho, hc, Q, sig = [bytes.fromhex(v[k]) for k in ('sk', 'md', 'rho', 'hc', 'Q', 'sig')]
            opening, pub, signature = (c.create_string_buffer(64) for _ in range(3))
            commitment, compact, host = c.create_string_buffer(33), c.create_string_buffer(64), c.create_string_buffer(32)
            assert call('ecdsa_anti_exfil_host_commit', host, rho)
            assert host.raw == hc
            assert call('ecdsa_anti_exfil_signer_commit', opening, md, sk, hc)
            assert call('ecdsa_s2c_opening_serialize', commitment, opening)
            assert commitment.raw == Q
            args = [signature, md, sk, rho]
            recid = c.c_int()
            if bitbox:
                args.append(c.byref(recid))
            assert call('anti_exfil_sign', *args)
            assert call('ecdsa_signature_serialize_compact', compact, signature)
            assert compact.raw == sig
            # Verify ngu's signature/binding with the external implementation.
            assert call('ecdsa_signature_parse_compact', signature, sig)
            assert call('ec_pubkey_create', pub, sk)
            assert call('anti_exfil_host_verify', signature, md, pub, rho, opening)
            assert not call('anti_exfil_host_verify', signature, md, pub, bytes(32), opening)
    finally:
        lib.secp256k1_context_destroy(ctx)
    print('PASS -', len(transcripts), 'exact ECDSA transcripts and binding checks:', path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mpy', required=True)
    parser.add_argument('--jade', required=True)
    parser.add_argument('--bitbox', required=True)
    parser.add_argument('--reference', required=True)
    args = parser.parse_args()
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    cases = []
    for i in range(105):
        sk = hashlib.sha256(b'key' + bytes([i])).digest()
        md = ((0, n - 1, n, n + 1, 2**256 - 1)[i].to_bytes(32, 'big') if i < 5
              else hashlib.sha256(b'digest' + bytes([i])).digest())
        rho = hashlib.sha256(b'host' + bytes([i])).digest()
        cases.append([b.hex() for b in (sk, md, rho)])
    script = '''import ngu, json
from binascii import unhexlify, hexlify
for case in CASES:
    sk, md, rho = [unhexlify(v) for v in case]
    hc = ngu.hash.sha256t(b's2c/ecdsa/data', rho)
    Q = ngu.antiexfil.commit(sk, md, hc)
    sig, Q2 = ngu.antiexfil.sign(sk, md, hc, rho)
    assert Q == Q2
    kp = ngu.secp256k1.keypair(sk)
    assert ngu.antiexfil.verify(sig, md, kp.pubkey(), Q, rho)
    kp.clear()
    print(json.dumps(dict(zip(('sk', 'md', 'rho', 'hc', 'Q', 'sig'),
        [hexlify(v).decode() for v in (sk, md, rho, hc, Q, sig.to_bytes()[1:])]))))
'''.replace('CASES', repr(cases))
    result = subprocess.run([args.mpy, '-c', script], check=True, text=True, capture_output=True)
    transcripts = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(transcripts) == len(cases)
    with contextlib.redirect_stdout(io.StringIO()):
        ref = runpy.run_path(args.reference)
    for v in transcripts:
        e = ref['ae_ecdsa'](*(bytes.fromhex(v[k]) for k in ('sk', 'md', 'rho')))
        assert e['Q33'].hex() == v['Q']
        assert (e['r'] + e['s']).hex() == v['sig']
    print('PASS -', len(transcripts), 'BIP reference transcripts')
    check_library(args.jade, False, transcripts)
    check_library(args.bitbox, True, transcripts)


if __name__ == '__main__':
    main()


try:
    import ngu

    sha512 = ngu.hash.sha512
    ripemd160 = ngu.hash.ripemd160
    double_sha256 = ngu.hash.sha256d
    sha256s = ngu.hash.sha256s

    def expect2(func, msg, dig):
        assert func(msg) == bytes.fromhex(dig), (msg,dig)


    import uctypes

    ba = bytearray(b'XXXabcYYY')
    addr = uctypes.addressof(ba)
    abc = uctypes.bytearray_at(addr + 3, 3)
    assert abc == b'abc'
    assert uctypes.addressof(abc) % 4 == 3

    expect2(sha256s, abc, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    expect2(double_sha256, abc, '4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358')
    expect2(lambda x: sha512(x).digest(), abc,
            'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f')

except ImportError:
    import hashlib
    from binascii import b2a_hex, a2b_hex
    from hashlib import sha512, sha256

    _ripemd160 = lambda x: hashlib.new('ripemd160', x).digest()

    cases = [
        ('ripemd160', _ripemd160),
        ('sha256d', lambda x: sha256(sha256(x).digest()).digest()),
        ('sha256s', lambda x: sha256(x).digest()),
        ('hash160', lambda x: _ripemd160(sha256(x).digest())),
    ]

    # gen tests
    import wallycore as w
    with open('test_hash_gen.py', 'wt') as fd:
        print("import ngu", file=fd)

        for nm, func in cases:
            for mlen in range(0, 64, 3):
                msg = (b'123abc'*40)[0:mlen]
                print("assert ngu.hash.%s(%r) == %r   #len%d" % (nm, msg, func(msg), mlen), file=fd)
            if nm != 'ripemd160':
                n = 2000
                print("assert ngu.hash.%s(bytes(%d)) == %r" % (nm, n, func(bytes(n))), file=fd)

        print("F = ngu.hash.pbkdf2_sha512", file=fd)
        for pw, salt, rounds in [ 
                (b'abc', b'def', 300), 
                (b'abc'*20, b'def'*20, 3000), 
                (b'\x01\x03\x04\x05\x06', b'\x04\x03\x02\x01\x00', 30), 
                (b'a', b'd', 30), 
            ]:
            expect = w.pbkdf2_hmac_sha512(pw, salt, 0, rounds)
            print("assert F(%r, %r, %d) == %r" % (pw, salt, rounds, bytes(expect)), file=fd)

        print("print('PASS - %s')" % fd.name, file=fd)
        print("run code now in: %s" % fd.name)

def expect(func, msg, dig):
    assert func(msg).digest().hex() == dig

    for sz in range(1, max(99, len(msg))):
        md = func()
        for pos in range(0, len(msg), sz):
            md.update(msg[pos:pos+sz])
        assert md.digest().hex() == dig



expect(sha512, b'', 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
expect(sha512, b'abc', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f')
expect(sha512, b'abc'*99, 'be0a8f07e572e068306b19fa0750f3cc6a11b5f0e0cf02ae7c944c9314be97ca4c8fb14e9c806a86aa40682a2688f63355879509a323d2896b45658a9f7f3755')
expect(sha512,
    b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
    '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909')

print('PASS - test_hash')


import ngu


def must_raise(exc, fn, arg):
    try:
        fn(arg)
    except exc:
        pass
    else:
        raise AssertionError('%s did not reject %r' % (fn, arg))


# Allocation boundaries. In particular, -1 used to wrap the vstr allocation
# length and then reach my_random_bytes() as UINT32_MAX.
must_raise(ValueError, ngu.random.bytes, -1)
assert ngu.random.bytes(0) == b''
assert len(ngu.random.bytes(4096)) == 4096
must_raise(ValueError, ngu.random.bytes, 4097)

for trial in range(100):
    v = [ngu.random.uint32() for i in range(100)]
    assert len(v) == len(set(v)), 'bad luck, try again'
    assert max(v) > 0x80000000
    assert min(v) < 0x80000000

for ln in range(1, 700):
    b = ngu.random.bytes(ln)
    assert len(b) == ln

for trial in range(100):
    b = ngu.random.bytes(4096)
    assert min(b) < 0x10
    assert max(b) > 0xe0

for trial in range(1000):
    b = ngu.random.uniform(100)
    assert 0 <= b < 100

for mx in range(10, 2000, 73):
    print("test: uniform[0 ..%3d)" % mx, end='')
    got = set()
    for nsamples in range(mx*10):
        b = ngu.random.uniform(mx)
        got.add(b)
    covered = (len(got)*100.0/mx)
    print(" => %.0f %%" % covered)
    assert covered >= 97        # maybe bad luck

# reseed API boundaries
for seed in (b'', bytes(31)):
    must_raise(ValueError, ngu.random.reseed, seed)

try:
    ngu.random.reseed(123)
except TypeError:
    pass
else:
    raise AssertionError('integer seed accepted')

ngu.random.reseed(bytes(32))
ngu.random.reseed(bytes(64))
ngu.random.reseed(bytearray(32))

print('PASS - test_random')

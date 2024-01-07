import os

if os.environ.get('BOARD', "") == 'ESP32_GENERIC_S3':
    include("$(PORT_DIR)/boards/manifest.py")

freeze_as_mpy('', [
    'bip39.py',
], opt=3)

if not int(os.environ.get('EXCLUDE_NGU_TESTS', 0)):
    print("NGU: including tests")
    freeze_as_mpy('', [
        "ngu_tests/run.py",
        "ngu_tests/b39_data.py",
        "ngu_tests/b39_vectors.py",
        "ngu_tests/b340_vectors.py",
        "ngu_tests/test_bip39.py",
        "ngu_tests/test_aes_gen.py",
        "ngu_tests/test_cert.py",
        "ngu_tests/test_codecs_gen.py",
        "ngu_tests/test_ec.py",
        "ngu_tests/test_ec_gen.py",
        "ngu_tests/test_hash.py",
        "ngu_tests/test_hash_gen.py",
        "ngu_tests/test_hdnode.py",
        "ngu_tests/test_hdnode_gen.py",
        "ngu_tests/test_hmac.py",
        "ngu_tests/test_k1.py",
        "ngu_tests/test_k1_gen.py",
        "ngu_tests/test_random.py",
    ], opt=0)       # need zero-optimization so asserts are included

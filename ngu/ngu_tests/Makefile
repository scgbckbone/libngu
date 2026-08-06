MPY = ../../ngu-micropython
PY = python3

.PHONY: test tests rng-tests hash-drbg-cavp random-integration
test tests: rng-tests
	test x$(VIRTUAL_ENV) != x		# need virtualenv
	$(PY) test_aes.py
	$(MPY) test_aes_gen.py
	$(PY) test_hdnode.py
	$(MPY) test_hdnode.py
	$(MPY) test_hdnode_gen.py
	$(PY) test_hash.py
	$(MPY) test_hash.py
	$(MPY) test_hash_gen.py
	$(PY) test_codecs.py
	$(PY) test_codecs_gen.py
	$(MPY) test_codecs_gen.py
	$(MPY) test_random.py
	$(PY) test_k1.py
	$(MPY) test_k1.py
	$(MPY) test_k1_gen.py
	$(PY) test_hmac.py
	$(MPY) test_cert.py
	$(PY) test_ec.py
	$(MPY) test_ec.py
	$(MPY) test_ec_gen.py
	$(PY) test_bip39.py
	$(MPY) test_bip39.py
	$(MPY) test_bip32.py

CIFRA_SRC = ../../libs/cifra/src
CIFRA_RANDOM_SRCS = $(CIFRA_SRC)/drbg.c $(CIFRA_SRC)/sha256.c \
	$(CIFRA_SRC)/blockwise.c $(CIFRA_SRC)/hmac.c $(CIFRA_SRC)/chash.c
CIFRA_DRBG_TEST_SRCS = $(CIFRA_SRC)/testdrbg.c $(CIFRA_RANDOM_SRCS) \
	$(CIFRA_SRC)/sha1.c $(CIFRA_SRC)/sha512.c
DRBG_TEST_CC = $(CC) -std=gnu99 -Wall -Wextra -Werror -DFULL_FAT_ASSERT \
	-I.. -I../../libs -I$(CIFRA_SRC) -I$(CIFRA_SRC)/ext

rng-tests: hash-drbg-cavp random-integration

# Exercise Cifra's own NIST CAVP known-answer tests for the exact Hash-DRBG
# implementation linked by ngu.random.
cifra-drbg-test: $(CIFRA_DRBG_TEST_SRCS)
	$(DRBG_TEST_CC) -o $@ $(CIFRA_DRBG_TEST_SRCS)

hash-drbg-cavp: cifra-drbg-test
	./cifra-drbg-test

# Match Coldcard's STM32 preprocessor path. Coldcard intentionally sets the
# MicroPython flag to zero and provides its own hardware-backed rng_get().
RANDOM_STM32_TEST_FLAGS = -U__linux__ -DMICROPY_PY_STM=1 \
	-DMICROPY_HW_ENABLE_RNG=0 -Imp_stubs -Wno-sign-compare

random-core-test: random_core_test.c ../random.c mp_stubs/py/runtime.h \
		mp_stubs/py/mperrno.h $(CIFRA_RANDOM_SRCS)
	$(DRBG_TEST_CC) $(RANDOM_STM32_TEST_FLAGS) -o $@ \
		random_core_test.c $(CIFRA_RANDOM_SRCS)

random-integration: random-core-test
	./random-core-test

# runs the test compiled in, not here
# or, on target
#	 import ngu_tests.run
run:
	$(MPY) run.py

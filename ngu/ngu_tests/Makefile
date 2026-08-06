MPY = ../../ngu-micropython
PY = python3

.PHONY: test tests rng-tests hash-drbg-cavp random-core stm32-rng-gates
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
RANDOM_CORE_CC = $(CC) -std=gnu99 -Wall -Wextra -Werror -DFULL_FAT_ASSERT \
	-I.. -I../../libs -I$(CIFRA_SRC) -I$(CIFRA_SRC)/ext

rng-tests: hash-drbg-cavp random-core stm32-rng-gates

# Exercise Cifra's own NIST CAVP known-answer tests for the exact Hash-DRBG
# implementation linked by ngu.random.
cifra-drbg-test: $(CIFRA_DRBG_TEST_SRCS)
	$(RANDOM_CORE_CC) -o $@ $(CIFRA_DRBG_TEST_SRCS)

hash-drbg-cavp: cifra-drbg-test
	./cifra-drbg-test

random-core-test: random_core_test.c ../random.c ../stm32_rng_guard.h $(CIFRA_RANDOM_SRCS)
	$(RANDOM_CORE_CC) -o $@ random_core_test.c $(CIFRA_RANDOM_SRCS)

random-core: random-core-test
	./random-core-test

STM32_GATE_CC = $(CC) -std=c99 -Wall -Werror -fsyntax-only -I..
STM32_GATE_SRC = stm32_rng_gate_test.c

# The STM32 port must never silently select MicroPython's software rng_get().
stm32-rng-gates:
	$(STM32_GATE_CC) $(STM32_GATE_SRC)
	! $(STM32_GATE_CC) -DMICROPY_PY_STM=1 $(STM32_GATE_SRC) 2>/dev/null
	! $(STM32_GATE_CC) -DMICROPY_PY_STM=0 $(STM32_GATE_SRC) 2>/dev/null
	! $(STM32_GATE_CC) -DMICROPY_PY_STM=1 -DMICROPY_HW_ENABLE_RNG=0 $(STM32_GATE_SRC) 2>/dev/null
	$(STM32_GATE_CC) -DMICROPY_PY_STM=1 -DMICROPY_HW_ENABLE_RNG=1 $(STM32_GATE_SRC)
	! $(STM32_GATE_CC) -DMICROPY_PY_STM=1 -DMICROPY_HW_ENABLE_RNG=2 $(STM32_GATE_SRC) 2>/dev/null
	@echo "PASS - STM32 hardware RNG compile gates"

# runs the test compiled in, not here
# or, on target
#	 import ngu_tests.run
run:
	$(MPY) run.py

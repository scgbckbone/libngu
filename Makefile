# Location of key submods
MPY_TOP ?= libs/mpy
S_TOP ?= libs/secp256k1
MBED_TOP ?= $(MPY_TOP)/lib/mbedtls

all: $(TARGET)

$(TARGET): $(REQUIRES)

# build a version of micropython (some port+board) that includes exactly what we need
$(TARGET): 
	cd $(MPY_PORT_DIR) && $(MAKE) $(MPY_MAKE_ARGS)

clean:
	cd $(MPY_PORT_DIR) && $(MAKE) $(MPY_MAKE_ARGS) clean

tags:
	ctags -f .tags ngu/*.[hc] \
	$(filter-out $(MPY_TOP)/py/dynruntime.h, $(wildcard $(MPY_TOP)/py/*.[hc])) \
	libs/secp256k1/{src,include}/*.[hc] \
	libs/secp256k1/src/modules/*/*.[hc] \
	libs/cifra/src/*.[hc] ngu/bech32/*.[hc] \
	$(MBED_TOP)/include/mbedtls/*.h $(MBED_TOP)/library/*.c

test tests:
	(cd ngu/ngu_tests; make tests)

K1_CONF_FLAGS = --with-bignum=no --with-ecmult-window=2 --with-ecmult-gen-precision=2 \
				--enable-module-recovery --enable-module-extrakeys --enable-experimental \
				--enable-module-ecdh \
				--enable-ecmult-static-precomputation

.PHONY: one-time
one-time:
	cd $(MPY_TOP); git submodule update
	cd $(MPY_TOP)/mpy-cross; make
	cd $(S_TOP); ./autogen.sh && ./configure $(K1_CONF_FLAGS) && make src/ecmult_static_context.h
	
# get ready to build library, but not full Micropython nor Unix test code
.PHONY: min-one-time
min-one-time:
	cd libs; git submodule update --init bech32 cifra secp256k1
	cd $(S_TOP); ./autogen.sh && ./configure $(K1_CONF_FLAGS) && make src/ecmult_static_context.h

esp:
	make -f Makefile.esp32 && make -f Makefile.esp32 deploy
	echo "Run: import ngu_tests.run"

quick:
	make -f makefile.unix
	(cd ngu/ngu_tests; make)

relink:
	$(RM) $(TARGET)

clobber:
	make -f makefile.unix clean
	make -f makefile.esp32 clean
	make -f makefile.stm32 clean


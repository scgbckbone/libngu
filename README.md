# LibNgU

All the things needed to make Bitcoin work on embedded µpy platforms like ESP32.

Name is "Number Go Up" ... because need that.

**Absoletely none of SHITCOINS allowed here**

**NEW POLICY** If I don't know you, I don't merge you! Thanks **XZ**!

## Primitives

- using [libsecp256k1](https://github.com/bitcoin-core/secp256k1) for everything, except:
- [mbedtls](https://github.com/ARMmbed/mbedtls) if already present on target (ESP32 uses for TLS)
- otherwise use [cifra](https://github.com/ctz/cifra)
- generic EC, certificates stuff, disabled if no mbedtls
- AES submodule disabled if you have mbedtls, because ucryptolib is same
- libwally-core used for testing only

## Notes

- might need, [see issue](https://github.com/micropython/micropython/issues/5224)

    export PKG_CONFIG_PATH=/usr/local/opt/libffi/lib/pkgconfig
    setenv PKG_CONFIG_PATH /usr/local/opt/libffi/lib/pkgconfig

## Install

- `make one-time` does submodule bullshit, configures K1 lib
- `make quick` compiles Unix micropython port, runs tests
- can play with `./ngu-micropython` binary on your desktop
- compile for ESP32 and burn onto TTGO board
```
make -f makefile.esp32
make -f makefile.esp32 deploy
```
- on target, do:
```
>>> import ngu_tests.run
```
or for single test:
```
>>> import ngu_tests.test_hash
```

- STM32 port builds, but untested:
```
make -f makefile.stm32 
```

### STM32 random-number provider

On STM32, libngu requires `rng_get()` to be backed by a hardware random-number
generator. Boards using MicroPython's standard hardware RNG set
`MICROPY_HW_ENABLE_RNG` to a true value. A board that replaces MicroPython's
RNG implementation while leaving that setting disabled must define
`NGU_RNG_GET_IS_HARDWARE=1` as an explicit security assertion.


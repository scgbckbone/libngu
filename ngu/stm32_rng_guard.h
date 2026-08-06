//
// Refuse MicroPython's software rng_get() fallback on STM32.
//
#pragma once

#if defined(MICROPY_PY_STM) && MICROPY_HW_ENABLE_RNG != 1
#error "ngu.random requires MICROPY_HW_ENABLE_RNG=1 on STM32"
#endif

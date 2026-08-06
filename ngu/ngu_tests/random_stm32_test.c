//
// On-device tests of the STM32 random.c composition. This file is only added
// to builds which include ngu_tests; production Coldcard builds exclude it.
//
#include "py/runtime.h"

#if MICROPY_PY_STM

// Compile a private copy of the unchanged production source. Only externally
// visible symbols are renamed; its static DRBG state remains private here.
#define rng_get random_test_rng_get
#define my_random_bytes random_test_bytes
#define _bit_length random_test_bit_length
#define _rand_below random_test_rand_below
#define mp_module_random random_test_module_copy
#include "../random.c"
#undef mp_module_random
#undef _rand_below
#undef _bit_length
#undef my_random_bytes
#undef rng_get
#undef CHIP_TRNG_32
#undef CHIP_TRNG_SETUP

static const uint32_t *trng_script;
static size_t trng_script_len;
static size_t trng_script_pos;
static uint32_t trng_fallback;
static size_t trng_calls;

uint32_t random_test_rng_get(void)
{
    trng_calls++;
    if (trng_script_pos < trng_script_len) {
        return trng_script[trng_script_pos++];
    }
    return trng_fallback++;
}

static void use_counter_trng(uint32_t first)
{
    trng_script = NULL;
    trng_script_len = 0;
    trng_script_pos = 0;
    trng_fallback = first;
    trng_calls = 0;
}

static void use_scripted_trng(const uint32_t *words, size_t count)
{
    trng_script = words;
    trng_script_len = count;
    trng_script_pos = 0;
    trng_fallback = 0x80000000;
    trng_calls = 0;
}

static void reset_random_state(void)
{
    mem_clean(&drbg, sizeof(drbg));
    drbg_ready = false;
    last_chip = 0;
}

static void init_expected_drbg(cf_hash_drbg_sha256 *expected)
{
    uint32_t entropy[DRBG_ENTROPY_WORDS];
    for (size_t i = 0; i < DRBG_ENTROPY_WORDS; i++) {
        entropy[i] = i + 1;
    }
    static const char domain[] = "libngu.random";
    cf_hash_drbg_sha256_init(expected, entropy, sizeof(entropy),
                             NULL, 0, domain, sizeof(domain) - 1);
    mem_clean(entropy, sizeof(entropy));
}

static void xor_words(uint8_t *dest, size_t count, uint32_t first_word)
{
    while (count) {
        uint32_t word = first_word++;
        size_t here = count < sizeof(word) ? count : sizeof(word);
        for (size_t i = 0; i < here; i++) {
            dest[i] ^= ((uint8_t *)&word)[i];
        }
        dest += here;
        count -= here;
    }
}

static void test_initial_seed_and_output_mix(void)
{
    uint8_t got[8], expected[8];
    cf_hash_drbg_sha256 expected_drbg;

    reset_random_state();
    use_counter_trng(1);
    random_test_bytes(got, sizeof(got));

    init_expected_drbg(&expected_drbg);
    cf_hash_drbg_sha256_gen(&expected_drbg, expected, sizeof(expected));
    xor_words(expected, sizeof(expected), 33);

    assert(drbg_ready);
    assert(trng_calls == DRBG_ENTROPY_WORDS + 2);
    assert(last_chip == 34);
    assert(memcmp(got, expected, sizeof(got)) == 0);
}

static void test_fresh_entropy_after_initialization(void)
{
    uint8_t ignored[4], got[7], expected[7];
    cf_hash_drbg_sha256 expected_drbg;

    reset_random_state();
    use_counter_trng(1);
    random_test_bytes(ignored, sizeof(ignored));
    expected_drbg = drbg;

    cf_hash_drbg_sha256_gen(&expected_drbg, expected, sizeof(expected));
    xor_words(expected, sizeof(expected), 34);
    random_test_bytes(got, sizeof(got));

    assert(trng_calls == DRBG_ENTROPY_WORDS + 3);
    assert(memcmp(got, expected, sizeof(got)) == 0);
}

static void test_automatic_reseed(void)
{
    uint8_t ignored[4], got[4], expected[4];
    uint32_t entropy[DRBG_ENTROPY_WORDS];
    cf_hash_drbg_sha256 expected_drbg;

    reset_random_state();
    use_counter_trng(1);
    random_test_bytes(ignored, sizeof(ignored));
    drbg.reseed_counter = 0;
    expected_drbg = drbg;
    for (size_t i = 0; i < DRBG_ENTROPY_WORDS; i++) {
        entropy[i] = 34 + i;
    }
    cf_hash_drbg_sha256_reseed(&expected_drbg, entropy, sizeof(entropy), NULL, 0);
    cf_hash_drbg_sha256_gen(&expected_drbg, expected, sizeof(expected));
    xor_words(expected, sizeof(expected), 66);

    random_test_bytes(got, sizeof(got));

    assert(trng_calls == (DRBG_ENTROPY_WORDS * 2) + 2);
    assert(memcmp(got, expected, sizeof(got)) == 0);
    mem_clean(entropy, sizeof(entropy));
}

static void test_external_reseed(void)
{
    uint8_t ignored[4];
    uint8_t seed[32];
    cf_hash_drbg_sha256 expected;
    size_t calls_before;

    memset(seed, 0xa5, sizeof(seed));
    reset_random_state();
    use_counter_trng(1);
    random_test_bytes(ignored, sizeof(ignored));
    calls_before = trng_calls;
    expected = drbg;
    cf_hash_drbg_sha256_reseed(&expected, seed, sizeof(seed), NULL, 0);

    drbg_setup(seed, sizeof(seed));

    assert(trng_calls == calls_before);
    assert(memcmp(&drbg, &expected, sizeof(drbg)) == 0);
    mem_clean(seed, sizeof(seed));
}

STATIC mp_obj_t random_core_run(void)
{
    test_initial_seed_and_output_mix();
    test_fresh_entropy_after_initialization();
    test_automatic_reseed();
    test_external_reseed();
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(random_core_run_obj, random_core_run);

STATIC mp_obj_t random_core_zero_fault(void)
{
    static const uint32_t words[] = { 0 };
    uint8_t out[4];

    reset_random_state();
    use_scripted_trng(words, MP_ARRAY_SIZE(words));
    random_test_bytes(out, sizeof(out));
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(random_core_zero_fault_obj, random_core_zero_fault);

STATIC mp_obj_t random_core_duplicate_fault(void)
{
    static const uint32_t words[] = { 0x12345678, 0x12345678 };
    uint8_t out[4];

    reset_random_state();
    use_scripted_trng(words, MP_ARRAY_SIZE(words));
    random_test_bytes(out, sizeof(out));
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(random_core_duplicate_fault_obj, random_core_duplicate_fault);

STATIC mp_obj_t random_core_history_fault(void)
{
    static const uint32_t words[] = { 33 };
    uint8_t out[4];

    reset_random_state();
    use_counter_trng(1);
    random_test_bytes(out, sizeof(out));
    use_scripted_trng(words, MP_ARRAY_SIZE(words));
    random_test_bytes(out, sizeof(out));
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(random_core_history_fault_obj, random_core_history_fault);

STATIC const mp_rom_map_elem_t random_core_test_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR__ngu_random_test) },
    { MP_ROM_QSTR(MP_QSTR_run), MP_ROM_PTR(&random_core_run_obj) },
    { MP_ROM_QSTR(MP_QSTR_zero_fault), MP_ROM_PTR(&random_core_zero_fault_obj) },
    { MP_ROM_QSTR(MP_QSTR_duplicate_fault), MP_ROM_PTR(&random_core_duplicate_fault_obj) },
    { MP_ROM_QSTR(MP_QSTR_history_fault), MP_ROM_PTR(&random_core_history_fault_obj) },
};
STATIC MP_DEFINE_CONST_DICT(random_core_test_globals, random_core_test_globals_table);

const mp_obj_module_t mp_module_ngu_random_test = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&random_core_test_globals,
};

MP_REGISTER_MODULE(MP_QSTR__ngu_random_test, mp_module_ngu_random_test, 1);

#endif // MICROPY_PY_STM

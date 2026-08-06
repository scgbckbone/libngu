//
// Deterministic tests of the exact DRBG/TRNG composition in random.c.
//
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t ngu_random_test_chip_trng_32(void);
void ngu_random_test_fault(void);

#define NGU_RANDOM_TEST 1
#include "../random.c"

static int failures;
static jmp_buf fault_env;
static bool fault_expected;
static const uint32_t *trng_script;
static size_t trng_script_len;
static size_t trng_script_pos;
static uint32_t trng_fallback;
static size_t trng_calls;

static void check(bool condition, const char *what)
{
    if (!condition) {
        printf("FAIL: %s\n", what);
        failures++;
    }
}

uint32_t ngu_random_test_chip_trng_32(void)
{
    trng_calls++;
    if (trng_script_pos < trng_script_len) {
        return trng_script[trng_script_pos++];
    }
    return trng_fallback++;
}

void ngu_random_test_fault(void)
{
    if (fault_expected) {
        longjmp(fault_env, 1);
    }
    abort();
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
    my_random_bytes(got, sizeof(got));

    init_expected_drbg(&expected_drbg);
    cf_hash_drbg_sha256_gen(&expected_drbg, expected, sizeof(expected));
    xor_words(expected, sizeof(expected), 33);

    check(drbg_ready, "DRBG is ready after first output");
    check(trng_calls == DRBG_ENTROPY_WORDS + 2,
          "first output uses 32 seed words and one fresh word per output word");
    check(last_chip == 34, "health history records the last mixed word");
    check(memcmp(got, expected, sizeof(got)) == 0,
          "output is Hash-DRBG XOR fresh TRNG words");
}

static void test_fresh_entropy_after_initialization(void)
{
    uint8_t ignored[4], got[7], expected[7];
    cf_hash_drbg_sha256 expected_drbg;

    reset_random_state();
    use_counter_trng(1);
    my_random_bytes(ignored, sizeof(ignored));
    expected_drbg = drbg;

    cf_hash_drbg_sha256_gen(&expected_drbg, expected, sizeof(expected));
    xor_words(expected, sizeof(expected), 34);
    my_random_bytes(got, sizeof(got));

    check(trng_calls == DRBG_ENTROPY_WORDS + 3,
          "later output consumes one fresh TRNG word per four bytes");
    check(memcmp(got, expected, sizeof(got)) == 0,
          "later output mixes the expected fresh TRNG words");
}

static void test_automatic_reseed(void)
{
    uint8_t ignored[4], got[4], expected[4];
    uint32_t entropy[DRBG_ENTROPY_WORDS];
    cf_hash_drbg_sha256 expected_drbg;

    reset_random_state();
    use_counter_trng(1);
    my_random_bytes(ignored, sizeof(ignored));
    drbg.reseed_counter = 0;
    expected_drbg = drbg;
    for (size_t i = 0; i < DRBG_ENTROPY_WORDS; i++) {
        entropy[i] = 34 + i;
    }
    cf_hash_drbg_sha256_reseed(&expected_drbg, entropy, sizeof(entropy), NULL, 0);
    cf_hash_drbg_sha256_gen(&expected_drbg, expected, sizeof(expected));
    xor_words(expected, sizeof(expected), 66);

    my_random_bytes(got, sizeof(got));

    check(trng_calls == (DRBG_ENTROPY_WORDS * 2) + 2,
          "expired DRBG consumes 32 new seed words before output");
    check(memcmp(got, expected, sizeof(got)) == 0,
          "automatic reseed uses all collected entropy");
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
    my_random_bytes(ignored, sizeof(ignored));
    calls_before = trng_calls;
    expected = drbg;
    cf_hash_drbg_sha256_reseed(&expected, seed, sizeof(seed), NULL, 0);

    drbg_setup(seed, sizeof(seed));

    check(trng_calls == calls_before,
          "external reseed preserves an existing hardware seed");
    check(memcmp(&drbg, &expected, sizeof(drbg)) == 0,
          "external seed is mixed into the full DRBG state");
    mem_clean(seed, sizeof(seed));
}

static void expect_initialization_fault(const uint32_t *words, size_t count,
                                        size_t expected_calls, const char *what)
{
    uint8_t out[4];

    reset_random_state();
    use_scripted_trng(words, count);
    fault_expected = true;
    if (setjmp(fault_env) == 0) {
        my_random_bytes(out, sizeof(out));
        check(false, what);
    }
    fault_expected = false;
    check(!drbg_ready, "failed entropy collection does not ready the DRBG");
    check(trng_calls == expected_calls, "fault occurs on the offending TRNG word");
}

static void test_entropy_faults(void)
{
    static const uint32_t zero[] = { 0 };
    static const uint32_t duplicate[] = { 0x12345678, 0x12345678 };
    static const uint32_t repeat_across_calls[] = { 33 };
    uint8_t out[4];

    expect_initialization_fault(zero, 1, 1, "zero entropy word must fault");
    expect_initialization_fault(duplicate, 2, 2,
                                "consecutive duplicate entropy words must fault");

    reset_random_state();
    use_counter_trng(1);
    my_random_bytes(out, sizeof(out));
    use_scripted_trng(repeat_across_calls, 1);
    fault_expected = true;
    if (setjmp(fault_env) == 0) {
        my_random_bytes(out, sizeof(out));
        check(false, "duplicate across calls must fault");
    }
    fault_expected = false;
    check(trng_calls == 1, "health history persists across API calls");
    check(last_chip == 33, "rejected word does not advance health history");
}

static void test_rand_below_retry(void)
{
    uint32_t candidates[64];
    cf_hash_drbg_sha256 expected_drbg;
    int chosen_mx = 0;
    int accepted_at = -1;

    init_expected_drbg(&expected_drbg);
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        cf_hash_drbg_sha256_gen(&expected_drbg, &candidates[i], sizeof(candidates[i]));
        candidates[i] ^= 33 + i;
    }

    for (int mx = 2; mx < 2000 && !chosen_mx; mx++) {
        uint32_t mask = rand_below_mask(_bit_length(mx));
        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
            if ((int)(candidates[i] & mask) < mx) {
                if (i > 0) {
                    chosen_mx = mx;
                    accepted_at = i;
                }
                break;
            }
        }
    }
    check(chosen_mx != 0, "found deterministic rejection-retry case");
    if (!chosen_mx) {
        return;
    }

    reset_random_state();
    use_counter_trng(1);
    int got = _rand_below(chosen_mx);
    uint32_t mask = rand_below_mask(_bit_length(chosen_mx));

    check(got == (int)(candidates[accepted_at] & mask),
          "rand_below returns the first accepted deterministic candidate");
    check(trng_calls == DRBG_ENTROPY_WORDS + (size_t)accepted_at + 1,
          "every rejection retry consumes another fresh TRNG word");
}

static void test_boundaries_and_mask(void)
{
    check(random_bytes_count_valid(-1) == false, "negative byte count is rejected");
    check(random_bytes_count_valid(0), "zero byte count is accepted");
    check(random_bytes_count_valid(4096), "maximum byte count is accepted");
    check(random_bytes_count_valid(4097) == false, "oversized byte count is rejected");
    check(rand_below_mask(1) == 0x1, "one-bit rejection mask");
    check(rand_below_mask(4) == 0xf, "four-bit rejection mask");
    check(rand_below_mask(30) == 0x3fffffff, "30-bit rejection mask is unsigned");
}

int main(void)
{
    test_initial_seed_and_output_mix();
    test_fresh_entropy_after_initialization();
    test_automatic_reseed();
    test_external_reseed();
    test_entropy_faults();
    test_rand_below_retry();
    test_boundaries_and_mask();

    if (failures) {
        printf("FAIL - random core: %d failure(s)\n", failures);
        return 1;
    }
    printf("PASS - random core\n");
    return 0;
}

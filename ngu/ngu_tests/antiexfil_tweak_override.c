// Test-only linker wrapper: force otherwise infeasible tweak boundary cases.
// Compile separately and link a test MicroPython with
// -Wl,--wrap=secp256k1_tagged_sha256. Never link this into production firmware.
#include <stdlib.h>
#include <string.h>
#include "secp256k1/include/secp256k1.h"

int __real_secp256k1_tagged_sha256(const secp256k1_context *, unsigned char *,
        const unsigned char *, size_t, const unsigned char *, size_t);
int __wrap_secp256k1_tagged_sha256(const secp256k1_context *, unsigned char *,
        const unsigned char *, size_t, const unsigned char *, size_t);

int __wrap_secp256k1_tagged_sha256(const secp256k1_context *ctx, unsigned char *out,
        const unsigned char *tag, size_t taglen, const unsigned char *msg, size_t msglen)
{
    const char *value = getenv("NGU_TEST_AE_TWEAK");
    if (value && strlen(value) == 64 && taglen >= 6 && !memcmp(tag + taglen - 6, "/point", 6)) {
        for (size_t i = 0; i < 32; ++i) {
            char byte[3] = {value[2*i], value[2*i+1], 0};
            out[i] = (unsigned char)strtoul(byte, NULL, 16);
        }
        return 1;
    }
    return __real_secp256k1_tagged_sha256(ctx, out, tag, taglen, msg, msglen);
}

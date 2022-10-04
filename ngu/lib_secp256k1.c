#ifndef NO_QSTR

# ifndef HAVE_CONFIG_H
#  define HAVE_CONFIG_H
# endif

# define USE_EXTERNAL_DEFAULT_CALLBACKS

# include "src/secp256k1.c"
# include "src/precomputed_ecmult.c"
# include "src/precomputed_ecmult_gen.c"
#endif

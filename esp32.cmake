set(ESP_PLATFORM 1)

set(MICROPY_FROZEN_MANIFEST ${CMAKE_CURRENT_LIST_DIR}/ngu/manifest.py)

add_library(usermod_ngu INTERFACE)

target_sources(usermod_ngu INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/ngu/aes.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/base32.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/base32.h
    ${CMAKE_CURRENT_LIST_DIR}/ngu/cert.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/codecs.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/ec.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/hash.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/hash.h
    ${CMAKE_CURRENT_LIST_DIR}/ngu/hdnode.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/hm.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/k1.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/lib_secp256k1.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/lib_segwit.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/libbase58.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/libbase58.h
    ${CMAKE_CURRENT_LIST_DIR}/ngu/modngu.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/my_assert.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/my_assert.h
    ${CMAKE_CURRENT_LIST_DIR}/ngu/rnd.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/rnd.h
    ${CMAKE_CURRENT_LIST_DIR}/ngu/rmd160.c
    ${CMAKE_CURRENT_LIST_DIR}/ngu/rmd160.h
    ${CMAKE_CURRENT_LIST_DIR}/ngu/sec_shared.h
)

target_include_directories(usermod_ngu INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/ngu
    ${CMAKE_CURRENT_LIST_DIR}/libs
    ${CMAKE_CURRENT_LIST_DIR}/libs/secp256k1
)

target_link_libraries(usermod INTERFACE usermod_ngu)

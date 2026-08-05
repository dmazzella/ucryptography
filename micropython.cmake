# Create an INTERFACE library for our C module.
add_library(usermod_cryptography INTERFACE)

# Add our source files to the lib
target_sources(usermod_cryptography INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/modcryptography.c
    ${CMAKE_CURRENT_LIST_DIR}/BLAKE2/ref/blake2s-ref.c
    ${CMAKE_CURRENT_LIST_DIR}/c25519/src/c25519.c
    ${CMAKE_CURRENT_LIST_DIR}/c25519/src/ed25519.c
    ${CMAKE_CURRENT_LIST_DIR}/c25519/src/edsign.c
    ${CMAKE_CURRENT_LIST_DIR}/c25519/src/f25519.c
    ${CMAKE_CURRENT_LIST_DIR}/c25519/src/fprime.c
    ${CMAKE_CURRENT_LIST_DIR}/c25519/src/morph25519.c
    ${CMAKE_CURRENT_LIST_DIR}/c25519/src/sha512.c
)

if(MICROPY_SSL_MBEDTLS EQUAL 0)
    set(MBEDTLS_DIR ${CMAKE_CURRENT_LIST_DIR}/mbedtls)
else()
    set(MBEDTLS_DIR ${MICROPY_DIR}/lib/mbedtls)
endif()

# Add the current directory as an include directory.
target_include_directories(usermod_cryptography INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/BLAKE2/ref
    ${CMAKE_CURRENT_LIST_DIR}/c25519/src
    ${MBEDTLS_DIR}/include
    ${MBEDTLS_DIR}/library
)

target_compile_definitions(usermod_cryptography INTERFACE
    MICROPY_PY_UCRYPTOGRAPHY_ED25519=1
    C25519_USE_MBEDTLS_SHA512=1
    # Expose PyCA-style nested packages (cryptography.hazmat.primitives...).
    MICROPY_MODULE_BUILTIN_SUBPACKAGES=1
    # mbedtls sources are INTERFACE-compiled into the main target, so this hook
    # reaches them too: applies our feature set with no patch to the shared config.
    MBEDTLS_USER_CONFIG_FILE="modcryptography_config.h"
)

if(DEFINED IDF_TARGET)
    # Add compiler flags to handle large code size on ESP32
    if(IDF_TARGET STREQUAL "esp32" OR IDF_TARGET STREQUAL "esp32s2" OR IDF_TARGET STREQUAL "esp32s3")
        target_compile_options(usermod_cryptography INTERFACE
            -mlongcalls
            -mtext-section-literals
        )
    endif()
endif()

# Link our INTERFACE library to the usermod target.
target_link_libraries(usermod INTERFACE usermod_cryptography)

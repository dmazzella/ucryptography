MOD_UCRYPTOGRAPHY_DIR := $(USERMOD_DIR)

ifeq ($(MICROPY_SSL_MBEDTLS),$(filter $(MICROPY_SSL_MBEDTLS),0))
    MBEDTLS_DIR := $(MOD_UCRYPTOGRAPHY_DIR)/mbedtls
else
    MBEDTLS_DIR := $(TOP)/lib/mbedtls
endif

CFLAGS_USERMOD += -DMICROPY_PY_UCRYPTOGRAPHY=1
# CFLAGS_USERMOD += -DMICROPY_PY_UCRYPTOGRAPHY_ED25519=1
# CFLAGS_USERMOD += -DC25519_USE_MBEDTLS_SHA512=1

CFLAGS_USERMOD += -I$(MBEDTLS_DIR)/include
CFLAGS_USERMOD += -I$(MOD_UCRYPTOGRAPHY_DIR)
ifeq ($(MCU_SERIES),wb)
    CFLAGS_USERMOD += -I$(MOD_UCRYPTOGRAPHY_DIR)/hw_alts/$(MCU_SERIES)/
endif
ifeq ($(MICROPY_SSL_MBEDTLS),$(filter $(MICROPY_SSL_MBEDTLS),0))
    ifneq ($(wildcard $(MBEDTLS_DIR)/crypto/*),)
        CFLAGS_USERMOD += -I$(MBEDTLS_DIR)/crypto/include
    endif
    CFLAGS_USERMOD += -DMBEDTLS_USER_CONFIG_FILE='"modcryptography_config.h"'
else
    ifeq ($(MCU_SERIES),wb)
        CFLAGS_USERMOD += -DMBEDTLS_GCM_ALT
        CFLAGS_USERMOD += -DMBEDTLS_AES_ALT
        CFLAGS_USERMOD += -DMBEDTLS_RSA_ALT
        CFLAGS_USERMOD += -DMBEDTLS_ECP_ALT
        CFLAGS_USERMOD += -DMBEDTLS_ECDSA_VERIFY_ALT
        CFLAGS_USERMOD += -DMBEDTLS_ECDSA_SIGN_ALT
    endif
endif
CFLAGS_USERMOD += -I$(MOD_UCRYPTOGRAPHY_DIR)/BLAKE2/ref
CFLAGS_USERMOD += -I$(MOD_UCRYPTOGRAPHY_DIR)/c25519/src

SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/modcryptography.c

SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/BLAKE2/ref/blake2s-ref.c

SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/c25519/src/c25519.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/c25519/src/ed25519.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/c25519/src/edsign.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/c25519/src/f25519.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/c25519/src/fprime.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/c25519/src/morph25519.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/c25519/src/sha512.c

ifeq ($(MICROPY_SSL_MBEDTLS),$(filter $(MICROPY_SSL_MBEDTLS),0))
    $(foreach src, $(wildcard $(MBEDTLS_DIR)/library/*.c), $(eval SRC_USERMOD += $(src)))
    ifneq ($(wildcard $(MBEDTLS_DIR)/crypto/*),)
        $(foreach src, $(wildcard $(MBEDTLS_DIR)/crypto/library/*.c), $(eval SRC_USERMOD += $(src)))
        ifneq ($(filter $(MBEDTLS_DIR)/crypto/library/error.c,$(SRC_USERMOD)),)
            SRC_USERMOD := $(filter-out $(MBEDTLS_DIR)/crypto/library/error.c, $(SRC_USERMOD))
        endif
    endif
    ifeq ($(MCU_SERIES),wb)
        SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/hw_alts/$(MCU_SERIES)/aes_alt.c
        SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/hw_alts/$(MCU_SERIES)/gcm_alt.c
        SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/hw_alts/$(MCU_SERIES)/ecp_curves_alt.c
        SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/hw_alts/$(MCU_SERIES)/ecp_alt.c
        SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/hw_alts/$(MCU_SERIES)/rsa_alt.c
        SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/hw_alts/$(MCU_SERIES)/ecdsa_alt.c
        HAL_SRC_C += $(addprefix $(HAL_DIR)/Src/stm32$(MCU_SERIES)xx_,\
            hal_cryp.c \
            hal_cryp_ex.c \
            hal_pka.c \
        )
    endif
endif

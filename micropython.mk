MOD_UCRYPTOGRAPHY_DIR := $(USERMOD_DIR)

ifeq ($(MICROPY_SSL_MBEDTLS),)
    MBEDTLS_DIR := $(MOD_UCRYPTOGRAPHY_DIR)/mbedtls
else
    MBEDTLS_DIR := $(TOP)/lib/mbedtls
endif

CFLAGS_USERMOD += -DMICROPY_PY_UCRYPTOGRAPHY=1
CFLAGS_USERMOD += -I$(MBEDTLS_DIR)/include
CFLAGS_USERMOD += -I$(MOD_UCRYPTOGRAPHY_DIR)
ifeq ($(MICROPY_SSL_MBEDTLS),)
    ifneq ($(wildcard $(MBEDTLS_DIR)/crypto/*),)
        CFLAGS_USERMOD += -I$(MBEDTLS_DIR)/crypto/include
    endif
    CFLAGS_USERMOD += -DMBEDTLS_USER_CONFIG_FILE='"modcryptography_config.h"'
else
ifeq ($(MCU_SERIES),wb)
CFLAGS_USERMOD += -DMBEDTLS_GCM_ALT
CFLAGS_USERMOD += -DMBEDTLS_AES_ALT
CFLAGS_USERMOD += -DMBEDTLS_ECP_ALT
CFLAGS_USERMOD += -DMBEDTLS_ECDSA_VERIFY_ALT
CFLAGS_USERMOD += -DMBEDTLS_ECDSA_SIGN_ALT
endif
endif

SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/modcryptography.c
ifeq ($(MICROPY_SSL_MBEDTLS),)
$(foreach src, $(wildcard $(MBEDTLS_DIR)/library/*.c), $(eval SRC_USERMOD += $(src)))
ifneq ($(wildcard $(MBEDTLS_DIR)/crypto/*),)
    $(foreach src, $(wildcard $(MBEDTLS_DIR)/crypto/library/*.c), $(eval SRC_USERMOD += $(src)))
    ifneq ($(filter $(MBEDTLS_DIR)/crypto/library/error.c,$(SRC_USERMOD)),)
        SRC_USERMOD := $(filter-out $(MBEDTLS_DIR)/crypto/library/error.c, $(SRC_USERMOD))
    endif
endif
ifeq ($(MCU_SERIES),wb)
    SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/aes_alt.c
    SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/gcm_alt.c
    SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/ecp_curves_alt.c
    SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/ecp_alt.c
    SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/ecdsa_alt.c
endif
endif
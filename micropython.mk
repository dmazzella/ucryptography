MOD_UCRYPTOGRAPHY_DIR := $(USERMOD_DIR)

ifeq ($(MICROPY_SSL_MBEDTLS),)
    MBEDTLS_DIR := $(MOD_UCRYPTOGRAPHY_DIR)/mbedtls
else
    MBEDTLS_DIR := $(TOP)/lib/mbedtls
endif

CFLAGS_USERMOD += -DMICROPY_PY_UCRYPTOGRAPHY=1
CFLAGS_USERMOD += -I$(MBEDTLS_DIR)/include
ifeq ($(MICROPY_SSL_MBEDTLS),)
    ifneq ($(wildcard $(MBEDTLS_DIR)/crypto/*),)
        CFLAGS_USERMOD += -I$(MBEDTLS_DIR)/crypto/include
    endif
    CFLAGS_USERMOD += -I$(MOD_UCRYPTOGRAPHY_DIR)
    CFLAGS_USERMOD += -DMBEDTLS_USER_CONFIG_FILE='"modcryptography_config.h"'
else
CFLAGS_USERMOD += -DMBEDTLS_PK_WRITE_C
CFLAGS_USERMOD += -DMBEDTLS_BASE64_C
CFLAGS_USERMOD += -DMBEDTLS_PEM_WRITE_C
CFLAGS_USERMOD += -DMBEDTLS_ECP_C
CFLAGS_USERMOD += -DMBEDTLS_ASN1_WRITE_C
CFLAGS_USERMOD += -DMBEDTLS_ECDSA_C
CFLAGS_USERMOD += -DMBEDTLS_ECDH_C
CFLAGS_USERMOD += -DMBEDTLS_GCM_C
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
endif
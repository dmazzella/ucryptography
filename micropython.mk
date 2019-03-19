MOD_UCRYPTOGRAPHY_DIR := $(USERMOD_DIR)

SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/modcryptography.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/asn1parse.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/asn1write.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/bignum.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/ecdsa.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/ecp_curves.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/ecp.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/hmac_drbg.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/md_wrap.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/md.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/md5.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/oid.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/pk_wrap.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/pk.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/pkparse.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/platform_util.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/ripemd160.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/rsa_internal.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/rsa.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/sha1.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/sha256.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/sha512.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/x509.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/x509_crt.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/version.c
SRC_USERMOD += $(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/library/version_features.c

CFLAGS_USERMOD += -I$(MOD_UCRYPTOGRAPHY_DIR)
CFLAGS_USERMOD += -I$(MOD_UCRYPTOGRAPHY_DIR)/mbed-crypto/include

CFLAGS_USERMOD += -DMICROPY_PY_UCRYPTOGRAPHY=1

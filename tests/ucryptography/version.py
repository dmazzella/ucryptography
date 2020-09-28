# -*- coding: utf-8 -*-
# pylint: disable=import-error
# pylint: disable=no-name-in-module
from cryptography import version

RESET = "\033[0m"
BLACK = "\033[30m"  # Black
RED = "\033[31m"  # Red
GREEN = "\033[32m"  # Green
YELLOW = "\033[33m"  # Yellow
BLUE = "\033[34m"  # Blue
MAGENTA = "\033[35m"  # Magenta
CYAN = "\033[36m"  # Cyan
WHITE = "\033[37m"  # White
BOLDBLACK = "\033[1m\033[30m"  # Bold Black
BOLDRED = "\033[1m\033[31m"  # Bold Red
BOLDGREEN = "\033[1m\033[32m"  # Bold Green
BOLDYELLOW = "\033[1m\033[33m"  # Bold Yellow
BOLDBLUE = "\033[1m\033[34m"  # Bold Blue
BOLDMAGENTA = "\033[1m\033[35m"  # Bold Magenta
BOLDCYAN = "\033[1m\033[36m"  # Bold Cyan
BOLDWHITE = "\033[1m\033[37m"  # Bold White

VERSION_FEATURES = (
    "MBEDTLS_HAVE_ASM",
    "MBEDTLS_NO_UDBL_DIVISION",
    "MBEDTLS_NO_64BIT_MULTIPLICATION",
    "MBEDTLS_HAVE_SSE2",
    "MBEDTLS_HAVE_TIME",
    "MBEDTLS_HAVE_TIME_DATE",
    "MBEDTLS_PLATFORM_MEMORY",
    "MBEDTLS_PLATFORM_NO_STD_FUNCTIONS",
    "MBEDTLS_PLATFORM_EXIT_ALT",
    "MBEDTLS_PLATFORM_TIME_ALT",
    "MBEDTLS_PLATFORM_FPRINTF_ALT",
    "MBEDTLS_PLATFORM_PRINTF_ALT",
    "MBEDTLS_PLATFORM_SNPRINTF_ALT",
    "MBEDTLS_PLATFORM_VSNPRINTF_ALT",
    "MBEDTLS_PLATFORM_NV_SEED_ALT",
    "MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT",
    "MBEDTLS_DEPRECATED_WARNING",
    "MBEDTLS_DEPRECATED_REMOVED",
    "MBEDTLS_CHECK_PARAMS",
    "MBEDTLS_TIMING_ALT",
    "MBEDTLS_AES_ALT",
    "MBEDTLS_ARC4_ALT",
    "MBEDTLS_ARIA_ALT",
    "MBEDTLS_BLOWFISH_ALT",
    "MBEDTLS_CAMELLIA_ALT",
    "MBEDTLS_CCM_ALT",
    "MBEDTLS_CHACHA20_ALT",
    "MBEDTLS_CHACHAPOLY_ALT",
    "MBEDTLS_CMAC_ALT",
    "MBEDTLS_DES_ALT",
    "MBEDTLS_DHM_ALT",
    "MBEDTLS_ECJPAKE_ALT",
    "MBEDTLS_GCM_ALT",
    "MBEDTLS_NIST_KW_ALT",
    "MBEDTLS_MD2_ALT",
    "MBEDTLS_MD4_ALT",
    "MBEDTLS_MD5_ALT",
    "MBEDTLS_POLY1305_ALT",
    "MBEDTLS_RIPEMD160_ALT",
    "MBEDTLS_RSA_ALT",
    "MBEDTLS_SHA1_ALT",
    "MBEDTLS_SHA256_ALT",
    "MBEDTLS_SHA512_ALT",
    "MBEDTLS_XTEA_ALT",
    "MBEDTLS_ECP_ALT",
    "MBEDTLS_MD2_PROCESS_ALT",
    "MBEDTLS_MD4_PROCESS_ALT",
    "MBEDTLS_MD5_PROCESS_ALT",
    "MBEDTLS_RIPEMD160_PROCESS_ALT",
    "MBEDTLS_SHA1_PROCESS_ALT",
    "MBEDTLS_SHA256_PROCESS_ALT",
    "MBEDTLS_SHA512_PROCESS_ALT",
    "MBEDTLS_DES_SETKEY_ALT",
    "MBEDTLS_DES_CRYPT_ECB_ALT",
    "MBEDTLS_DES3_CRYPT_ECB_ALT",
    "MBEDTLS_AES_SETKEY_ENC_ALT",
    "MBEDTLS_AES_SETKEY_DEC_ALT",
    "MBEDTLS_AES_ENCRYPT_ALT",
    "MBEDTLS_AES_DECRYPT_ALT",
    "MBEDTLS_ECDH_GEN_PUBLIC_ALT",
    "MBEDTLS_ECDH_COMPUTE_SHARED_ALT",
    "MBEDTLS_ECDSA_VERIFY_ALT",
    "MBEDTLS_ECDSA_SIGN_ALT",
    "MBEDTLS_ECDSA_GENKEY_ALT",
    "MBEDTLS_ECP_INTERNAL_ALT",
    "MBEDTLS_ECP_RANDOMIZE_JAC_ALT",
    "MBEDTLS_ECP_ADD_MIXED_ALT",
    "MBEDTLS_ECP_DOUBLE_JAC_ALT",
    "MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT",
    "MBEDTLS_ECP_NORMALIZE_JAC_ALT",
    "MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT",
    "MBEDTLS_ECP_RANDOMIZE_MXZ_ALT",
    "MBEDTLS_ECP_NORMALIZE_MXZ_ALT",
    "MBEDTLS_TEST_NULL_ENTROPY",
    "MBEDTLS_ENTROPY_HARDWARE_ALT",
    "MBEDTLS_AES_ROM_TABLES",
    "MBEDTLS_AES_FEWER_TABLES",
    "MBEDTLS_CAMELLIA_SMALL_MEMORY",
    "MBEDTLS_CIPHER_MODE_CBC",
    "MBEDTLS_CIPHER_MODE_CFB",
    "MBEDTLS_CIPHER_MODE_CTR",
    "MBEDTLS_CIPHER_MODE_OFB",
    "MBEDTLS_CIPHER_MODE_XTS",
    "MBEDTLS_CIPHER_NULL_CIPHER",
    "MBEDTLS_CIPHER_PADDING_PKCS7",
    "MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS",
    "MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN",
    "MBEDTLS_CIPHER_PADDING_ZEROS",
    "MBEDTLS_ENABLE_WEAK_CIPHERSUITES",
    "MBEDTLS_REMOVE_ARC4_CIPHERSUITES",
    "MBEDTLS_REMOVE_3DES_CIPHERSUITES",
    "MBEDTLS_ECP_DP_SECP192R1_ENABLED",
    "MBEDTLS_ECP_DP_SECP224R1_ENABLED",
    "MBEDTLS_ECP_DP_SECP256R1_ENABLED",
    "MBEDTLS_ECP_DP_SECP384R1_ENABLED",
    "MBEDTLS_ECP_DP_SECP521R1_ENABLED",
    "MBEDTLS_ECP_DP_SECP192K1_ENABLED",
    "MBEDTLS_ECP_DP_SECP224K1_ENABLED",
    "MBEDTLS_ECP_DP_SECP256K1_ENABLED",
    "MBEDTLS_ECP_DP_BP256R1_ENABLED",
    "MBEDTLS_ECP_DP_BP384R1_ENABLED",
    "MBEDTLS_ECP_DP_BP512R1_ENABLED",
    "MBEDTLS_ECP_DP_CURVE25519_ENABLED",
    "MBEDTLS_ECP_DP_CURVE448_ENABLED",
    "MBEDTLS_ECP_NIST_OPTIM",
    "MBEDTLS_ECP_RESTARTABLE",
    "MBEDTLS_ECDSA_DETERMINISTIC",
    "MBEDTLS_KEY_EXCHANGE_PSK_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_RSA_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED",
    "MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED",
    "MBEDTLS_PK_PARSE_EC_EXTENDED",
    "MBEDTLS_ERROR_STRERROR_DUMMY",
    "MBEDTLS_GENPRIME",
    "MBEDTLS_FS_IO",
    "MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES",
    "MBEDTLS_NO_PLATFORM_ENTROPY",
    "MBEDTLS_ENTROPY_FORCE_SHA256",
    "MBEDTLS_ENTROPY_NV_SEED",
    "MBEDTLS_PSA_CRYPTO_KEY_FILE_ID_ENCODES_OWNER",
    "MBEDTLS_MEMORY_DEBUG",
    "MBEDTLS_MEMORY_BACKTRACE",
    "MBEDTLS_PK_RSA_ALT_SUPPORT",
    "MBEDTLS_PKCS1_V15",
    "MBEDTLS_PKCS1_V21",
    "MBEDTLS_PSA_CRYPTO_SPM",
    "MBEDTLS_PSA_INJECT_ENTROPY",
    "MBEDTLS_RSA_NO_CRT",
    "MBEDTLS_SELF_TEST",
    "MBEDTLS_SHA256_SMALLER",
    "MBEDTLS_SSL_ALL_ALERT_MESSAGES",
    "MBEDTLS_SSL_ASYNC_PRIVATE",
    "MBEDTLS_SSL_DEBUG_ALL",
    "MBEDTLS_SSL_ENCRYPT_THEN_MAC",
    "MBEDTLS_SSL_EXTENDED_MASTER_SECRET",
    "MBEDTLS_SSL_FALLBACK_SCSV",
    "MBEDTLS_SSL_KEEP_PEER_CERTIFICATE",
    "MBEDTLS_SSL_HW_RECORD_ACCEL",
    "MBEDTLS_SSL_CBC_RECORD_SPLITTING",
    "MBEDTLS_SSL_RENEGOTIATION",
    "MBEDTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO",
    "MBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE",
    "MBEDTLS_SSL_MAX_FRAGMENT_LENGTH",
    "MBEDTLS_SSL_PROTO_SSL3",
    "MBEDTLS_SSL_PROTO_TLS1",
    "MBEDTLS_SSL_PROTO_TLS1_1",
    "MBEDTLS_SSL_PROTO_TLS1_2",
    "MBEDTLS_SSL_PROTO_DTLS",
    "MBEDTLS_SSL_ALPN",
    "MBEDTLS_SSL_DTLS_ANTI_REPLAY",
    "MBEDTLS_SSL_DTLS_HELLO_VERIFY",
    "MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE",
    "MBEDTLS_SSL_DTLS_BADMAC_LIMIT",
    "MBEDTLS_SSL_SESSION_TICKETS",
    "MBEDTLS_SSL_EXPORT_KEYS",
    "MBEDTLS_SSL_SERVER_NAME_INDICATION",
    "MBEDTLS_SSL_TRUNCATED_HMAC",
    "MBEDTLS_SSL_TRUNCATED_HMAC_COMPAT",
    "MBEDTLS_THREADING_ALT",
    "MBEDTLS_THREADING_PTHREAD",
    "MBEDTLS_USE_PSA_CRYPTO",
    "MBEDTLS_VERSION_FEATURES",
    "MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3",
    "MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION",
    "MBEDTLS_X509_CHECK_KEY_USAGE",
    "MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE",
    "MBEDTLS_X509_RSASSA_PSS_SUPPORT",
    "MBEDTLS_ZLIB_SUPPORT",
    "MBEDTLS_AESNI_C",
    "MBEDTLS_AES_C",
    "MBEDTLS_ARC4_C",
    "MBEDTLS_ASN1_PARSE_C",
    "MBEDTLS_ASN1_WRITE_C",
    "MBEDTLS_BASE64_C",
    "MBEDTLS_BIGNUM_C",
    "MBEDTLS_BLOWFISH_C",
    "MBEDTLS_CAMELLIA_C",
    "MBEDTLS_ARIA_C",
    "MBEDTLS_CCM_C",
    "MBEDTLS_CERTS_C",
    "MBEDTLS_CHACHA20_C",
    "MBEDTLS_CHACHAPOLY_C",
    "MBEDTLS_CIPHER_C",
    "MBEDTLS_CMAC_C",
    "MBEDTLS_CTR_DRBG_C",
    "MBEDTLS_DEBUG_C",
    "MBEDTLS_DES_C",
    "MBEDTLS_DHM_C",
    "MBEDTLS_ECDH_C",
    "MBEDTLS_ECDSA_C",
    "MBEDTLS_ECJPAKE_C",
    "MBEDTLS_ECP_C",
    "MBEDTLS_ENTROPY_C",
    "MBEDTLS_ERROR_C",
    "MBEDTLS_GCM_C",
    "MBEDTLS_HAVEGE_C",
    "MBEDTLS_HKDF_C",
    "MBEDTLS_HMAC_DRBG_C",
    "MBEDTLS_NIST_KW_C",
    "MBEDTLS_MD_C",
    "MBEDTLS_MD2_C",
    "MBEDTLS_MD4_C",
    "MBEDTLS_MD5_C",
    "MBEDTLS_MEMORY_BUFFER_ALLOC_C",
    "MBEDTLS_NET_C",
    "MBEDTLS_OID_C",
    "MBEDTLS_PADLOCK_C",
    "MBEDTLS_PEM_PARSE_C",
    "MBEDTLS_PEM_WRITE_C",
    "MBEDTLS_PK_C",
    "MBEDTLS_PK_PARSE_C",
    "MBEDTLS_PK_WRITE_C",
    "MBEDTLS_PKCS5_C",
    "MBEDTLS_PKCS11_C",
    "MBEDTLS_PKCS12_C",
    "MBEDTLS_PLATFORM_C",
    "MBEDTLS_POLY1305_C",
    "MBEDTLS_PSA_CRYPTO_C",
    "MBEDTLS_PSA_CRYPTO_STORAGE_C",
    "MBEDTLS_PSA_ITS_FILE_C",
    "MBEDTLS_RIPEMD160_C",
    "MBEDTLS_RSA_C",
    "MBEDTLS_SHA1_C",
    "MBEDTLS_SHA256_C",
    "MBEDTLS_SHA512_C",
    "MBEDTLS_SSL_CACHE_C",
    "MBEDTLS_SSL_COOKIE_C",
    "MBEDTLS_SSL_TICKET_C",
    "MBEDTLS_SSL_CLI_C",
    "MBEDTLS_SSL_SRV_C",
    "MBEDTLS_SSL_TLS_C",
    "MBEDTLS_THREADING_C",
    "MBEDTLS_TIMING_C",
    "MBEDTLS_VERSION_C",
    "MBEDTLS_X509_USE_C",
    "MBEDTLS_X509_CRT_PARSE_C",
    "MBEDTLS_X509_CRL_PARSE_C",
    "MBEDTLS_X509_CSR_PARSE_C",
    "MBEDTLS_X509_CREATE_C",
    "MBEDTLS_X509_CRT_WRITE_C",
    "MBEDTLS_X509_CSR_WRITE_C",
    "MBEDTLS_XTEA_C",
)


def main():
    print("number:", version.get_number())
    print("string:", version.get_string())
    print("string_full:", version.get_string_full())
    for feature in VERSION_FEATURES:
        enabled = version.check_feature(feature)
        color = GREEN if enabled else RED
        print("check_feature: {:s}{:s}{:s}".format(color, feature, RESET))


if __name__ == "__main__":
    main()
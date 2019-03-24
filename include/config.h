#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

//visual studio is not happy with mbedTLS using fopen()
#define _CRT_SECURE_NO_WARNINGS

//encode
#define MBEDTLS_BASE64_C
//rsa dependent
#define MBEDTLS_OID_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PK_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_MD_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_FS_IO
#define MBEDTLS_PKCS1_V21
//aes
#define MBEDTLS_AES_C
//GCM
#define MBEDTLS_GCM_C
//random
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
//sha
#define MBEDTLS_SHA512_C
//wrapper
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_MD_C


#endif  // MBEDTLS_CONFIG_H

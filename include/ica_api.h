/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Authors(s): Ralph Wuerthner <rwuerthn@de.ibm.com>
 *             Holger Dengler <hd@linux.vnet.ibm.com>
 *             Ingo Tuchscherer <ingo.tuchscherer@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2001, 2005, 2009, 2010, 2011, 2013
 */

#ifndef __ICA_API_H__
#define __ICA_API_H__

/***************************************************************************
***                                                                      ***
***       LICENSED MATERIALS  -  PROPERTY OF IBM                         ***
***                                                                      ***
***       All Rights Reserved                                            ***
***                                                                      ***
***       U.S. Government Users Restricted Rights - Use,                 ***
***       duplication or disclosure restricted by GSA ADP                ***
***       Schedule Contract with IBM Corp.                               ***
***                                                                      ***
***                                                                      ***
***       ORIGINS: IBM Charlotte, Department VM9A                        ***
***                                                                      ***
***************************************************************************/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ICA_EXPORT __attribute__((__visibility__("default")))
#define ICA_DEPRECATED __attribute__((deprecated))

#define ica_adapter_handle_t int
typedef ica_adapter_handle_t ICA_ADAPTER_HANDLE;
#define DRIVER_NOT_LOADED (-1)

/**
 * Definitions to determine the direction of the symmetric
 * encryption/decryption functions.
 */
#define ICA_ENCRYPT 1
#define ICA_DECRYPT 0

/**
 * Symetric encryption/decryption modes
 */
#define MODE_ECB		1
#define MODE_CBC		2
#define MODE_CFB		3
#define MODE_OFB		4
#define MODE_CTR		5
#define MODE_XTS		6
#define MODE_GCM		7
#define MODE_CBCCS		8
#define MODE_CCM		9

/**
 * CBC Ciphertext Stealing variants
 */
#define ICA_CBCCS_VARIANT1	1
#define ICA_CBCCS_VARIANT2	2
#define ICA_CBCCS_VARIANT3	3

/**
 * ICA flags
 */
#define ICA_FLAG_SHW 4 /* static hardware support (symmetric ops - CPACF) */
#define ICA_FLAG_DHW 2 /* dynamic hardware support (asymmetric ops - CEX) */
#define ICA_FLAG_SW  1 /* software implementation (fallback / backup) */

/**
 * ICA properties: key lengths
 */
#define ICA_PROPERTY_AES_128		0x00000001
#define ICA_PROPERTY_AES_192		0x00000002
#define ICA_PROPERTY_AES_256		0x00000004

#define ICA_PROPERTY_RSA_ALL		0x0000000F /* All RSA key lengths */
#define ICA_PROPERTY_RSA_FIPS		0x0000000C /* RSA 2k and higher */
#define ICA_PROPERTY_EC_BP			0x00000001 /* Brainpool curves */
#define ICA_PROPERTY_EC_NIST		0x00000002 /* NIST curves */
#define ICA_PROPERTY_EC_ED			0x00000004 /* Edwards curves */

/**
 * Algorithms
 */
#define SHA1            1
#define SHA224          2
#define SHA256          3
#define SHA384          4
#define SHA512          5
#define SHA3_224        6
#define SHA3_256        7
#define SHA3_384        8
#define SHA3_512        9
#define SHAKE128        11
#define SHAKE256        12
#define G_HASH          10
#define DES_ECB         20
#define DES_CBC         21
#define DES_CBC_CS      22
#define DES_OFB         23
#define DES_CFB         24
#define DES_CTR         25
#define DES_CTRLST      26
#define DES_CBC_MAC     27
#define DES_CMAC        28
#define DES3_ECB        41
#define DES3_CBC        42
#define DES3_CBC_CS     43
#define DES3_OFB        44
#define DES3_CFB        45
#define DES3_CTR        46
#define DES3_CTRLST     47
#define DES3_CBC_MAC    48
#define DES3_CMAC       49
#define AES_ECB         60
#define AES_CBC         61
#define AES_CBC_CS      62
#define AES_OFB         63
#define AES_CFB         64
#define AES_CTR         65
#define AES_CTRLST      66
#define AES_CBC_MAC     67
#define AES_CMAC        68
#define AES_CCM         69
#define AES_GCM         70
#define AES_XTS         71
#define AES_GCM_KMA     72
#define P_RNG           80
#define EC_DH           85
#define EC_DSA_SIGN     86
#define EC_DSA_VERIFY   87
#define EC_KGEN         88
#define RSA_ME          90
#define RSA_CRT         91
#define RSA_KEY_GEN_ME  92
#define RSA_KEY_GEN_CRT 93
#define SHA512_DRNG	94
#define SHA512_224      95
#define SHA512_256      96
#define ED25519_KEYGEN	100
#define ED25519_SIGN	101
#define ED25519_VERIFY	102
#define ED448_KEYGEN	103
#define ED448_SIGN	104
#define ED448_VERIFY	105
#define X25519_KEYGEN	106
#define X25519_DERIVE	107
#define X448_KEYGEN	108
#define X448_DERIVE	109

/*
 * Key length for DES/3DES encryption/decryption
 */
#define DES_KEY_LENGTH		(56/8)
#define DES3_KEY_LENGTH		(168/8)

/**
 * Key length for AES encryption/decryption
 */
#define AES_KEY_LEN128		(128/8)
#define AES_KEY_LEN192		(192/8)
#define AES_KEY_LEN256		(256/8)

/**
 * SHA Message parts
 */
#define SHA_MSG_PART_ONLY	0
#define SHA_MSG_PART_FIRST	1
#define SHA_MSG_PART_MIDDLE	2
#define SHA_MSG_PART_FINAL	3

/**
 * SHA hash lengths
 */
#define SHA_HASH_LENGTH		20
#define SHA1_HASH_LENGTH	SHA_HASH_LENGTH
#define SHA224_HASH_LENGTH	28
#define SHA256_HASH_LENGTH	32
#define SHA384_HASH_LENGTH	48
#define SHA512_HASH_LENGTH	64
#define SHA512_224_HASH_LENGTH	SHA224_HASH_LENGTH
#define SHA512_256_HASH_LENGTH	SHA256_HASH_LENGTH
#define SHA3_224_HASH_LENGTH	SHA224_HASH_LENGTH
#define SHA3_256_HASH_LENGTH	SHA256_HASH_LENGTH
#define SHA3_384_HASH_LENGTH	SHA384_HASH_LENGTH
#define SHA3_512_HASH_LENGTH	SHA512_HASH_LENGTH
#define SHA3_PARMBLOCK_LENGTH   200

/*
 * ica_drbg
 */
#define ICA_DRBG_NEW_STATE_HANDLE	NULL
#define ICA_DRBG_HEALTH_TEST_FAIL	(-1)
#define ICA_DRBG_ENTROPY_SOURCE_FAIL	(-2)

/*
 * The following status flags are used to examine the return value of the
 * status output interface ica_fips_status().
 */

/*
 * 'FIPS mode active'-flag
 */
#define ICA_FIPS_MODE		1

/*
 * 'Powerup test failed'-flags
 */
/* Cryptographic algorithm test (KAT or pair-wise consistency test) */
#define ICA_FIPS_CRYPTOALG	2
/* Software/Firmware integrity test */
#define ICA_FIPS_INTEGRITY	4
/* Critical functions test (N/A) */
#define ICA_FIPS_CRITICALFUNC	8

/*
 * 'Conditional test failed'-flags
 */
/* Pair-wise consistency test for public & private keys (N/A) */
#define ICA_FIPS_CONSISTENCY	16
/* Software/Firmware load test (N/A) */
#define ICA_FIPS_LOAD		32
/* Manual key entry test (N/A) */
#define ICA_FIPS_KEYENTRY	64
/* Continuous random number generator test */
#define ICA_FIPS_RNG		128
/* Bypass test (N/A) */
#define ICA_FIPS_BYPASS		256

/**
 * Context for SHA1 operations
 */
typedef struct {
	uint64_t runningLength;
	unsigned char shaHash[SHA_HASH_LENGTH];
} sha_context_t;

/**
 * Context for SHA256 and SHA224 operations
 */
typedef struct {
	uint64_t runningLength;
	unsigned char sha256Hash[SHA256_HASH_LENGTH];
} sha256_context_t;

/**
 * Context for SHA512 and SHA384 operations
 */
typedef struct {
	uint64_t runningLengthHigh;
	uint64_t runningLengthLow;
	unsigned char sha512Hash[SHA512_HASH_LENGTH];
} sha512_context_t;

/**
 * Context for SHA3_224 operations
 */
typedef struct {
	uint64_t runningLength;
	unsigned char sha3_224Hash[SHA3_PARMBLOCK_LENGTH];
} sha3_224_context_t;

/**
 * Context for SHA3_256 operations
 */
typedef struct {
	uint64_t runningLength;
	unsigned char sha3_256Hash[SHA3_PARMBLOCK_LENGTH];
} sha3_256_context_t;

/**
 * Context for SHA3_384 operations
 */
typedef struct {
	uint64_t runningLengthHigh;
	uint64_t runningLengthLow;
	unsigned char sha3_384Hash[SHA3_PARMBLOCK_LENGTH];
} sha3_384_context_t;

/**
 * Context for SHA3_512 operations
 */
typedef struct {
	uint64_t runningLengthHigh;
	uint64_t runningLengthLow;
	unsigned char sha3_512Hash[SHA3_PARMBLOCK_LENGTH];
} sha3_512_context_t;

/**
 * Context for SHAKE_128 operations with variable output length
 */
typedef struct {
	uint64_t runningLengthHigh;
	uint64_t runningLengthLow;
	unsigned int output_length;
	unsigned char shake_128Hash[SHA3_PARMBLOCK_LENGTH];
} shake_128_context_t;

/**
 * Context for SHAKE_256 operations with variable output length
 */
typedef struct {
	uint64_t runningLengthHigh;
	uint64_t runningLengthLow;
	unsigned int output_length;
	unsigned char shake_256Hash[SHA3_PARMBLOCK_LENGTH];
} shake_256_context_t;

/*
 * Assumption: *_ENCRYPT members of the kmc_funktion_t and kma_function_t
 * enums are even, while *_DECRYPT members are odd.
 */

typedef enum {
	DEA_ENCRYPT,
	DEA_DECRYPT,
	TDEA_192_ENCRYPT,
	TDEA_192_DECRYPT,
	AES_128_ENCRYPT,
	AES_128_DECRYPT,
	AES_192_ENCRYPT,
	AES_192_DECRYPT,
	AES_256_ENCRYPT,
	AES_256_DECRYPT,
/* XTS belongs to the KM family */
	AES_128_XTS_ENCRYPT,
	AES_128_XTS_DECRYPT,
	AES_256_XTS_ENCRYPT,
	AES_256_XTS_DECRYPT,
/* PRNG only for KMC */
	PRNG,
} kmc_functions_t;

typedef enum {
	AES_128_GCM_ENCRYPT,
	AES_128_GCM_DECRYPT,
	AES_192_GCM_ENCRYPT,
	AES_192_GCM_DECRYPT,
	AES_256_GCM_ENCRYPT,
	AES_256_GCM_DECRYPT,
} kma_functions_t;

typedef enum {
	ECDSA_VERIFY_P256,
	ECDSA_VERIFY_P384,
	ECDSA_VERIFY_P521,
	ECDSA_SIGN_P256,
	ECDSA_SIGN_P384,
	ECDSA_SIGN_P521,
	EDDSA_VERIFY_ED25519,
	EDDSA_VERIFY_ED448,
	EDDSA_SIGN_ED25519,
	EDDSA_SIGN_ED448,
} kdsa_functions_t;

typedef struct {
	unsigned int key_length;
	unsigned char* modulus;
	unsigned char* exponent;
} ica_rsa_key_mod_expo_t;

typedef struct {
	unsigned int key_length;
	unsigned char* p;
	unsigned char* q;
	unsigned char* dp;
	unsigned char* dq;
	unsigned char* qInverse;
} ica_rsa_key_crt_t;

/**
 *  DES and AES defines and typedefs
 */
typedef unsigned char ica_des_vector_t[8];
typedef unsigned char ica_des_key_single_t[8];
typedef struct {
	ica_des_key_single_t key1;
	ica_des_key_single_t key2;
	ica_des_key_single_t key3;
} ica_des_key_triple_t;

typedef unsigned char ica_key_t[8];

/**
 * AES defines and typedefs
 */
typedef unsigned char ica_aes_vector_t[16];
typedef unsigned char ica_aes_key_single_t[8];
typedef unsigned char ica_aes_key_len_128_t[16];
typedef unsigned char ica_aes_key_len_192_t[24];
typedef unsigned char ica_aes_key_len_256_t[32];

/**
 * Libica version information
 */
typedef struct {
	unsigned int major_version;
	unsigned int minor_version;
	unsigned int fixpack_version;
} libica_version_info;

/**
 * Definition of a mechanism type
 **/
typedef unsigned int libica_mechanism_type;

/**
 * Information for a particular crypto mechanism supported by libica.
 * Key sizes are specified in bytes and do not apply to all supported
 * mechanisms.
 **/
typedef struct {
	unsigned int min_key_size;
	unsigned int max_key_size;
	unsigned int flags;
} libica_mechanism_info;

/**
 * Definition for a particular crypto mechanism supported by libica.
 **/
typedef struct {
	libica_mechanism_type mech_type;
	libica_mechanism_info mech_info;
} libica_mechanism_list_element;

/*
 * internal specification for a specific crypto mechanism supported by libica
 **/
typedef struct {
	unsigned int mech_mode_id;
	unsigned int type;
	unsigned int id;
	unsigned int flags;
	unsigned int property;
} libica_func_list_element_int;

/*
 * external specification for a specific crypto mechanism supported by libica
 **/
typedef struct {
	unsigned int mech_mode_id;
	unsigned int flags;
	unsigned int property;
} libica_func_list_element;

typedef struct ica_drbg_mech ica_drbg_mech_t;
typedef struct ica_drbg ica_drbg_t;

/**
 * Definitions for the ica_set_fallback_mode function.
 */
#define ICA_FALLBACKS_ENABLED  1
#define ICA_FALLBACKS_DISABLED 0

/**
 * Environment variable for defining the default Libica fallback mode.
 * By default Libica starts with fallbacks enabled. When this environment
 * variable exists and has a numeric value, the fallback mode is set
 * via ica_set_fallback_mode().
 */
#define ICA_FALLBACK_ENV "LIBICA_FALLBACK_MODE"

/**
 * Set Libica fallback mode.
 * With fallbacks enabled (that's the default), when there is no hardware
 * support available (for example when the crypto cards are offline) Libica
 * attempts to cover the request by calling Openssl functions as fallback.
 * With fallback disabled, no attempts will be made to fulfill the request
 * if there is no hardware support or hardware invocation fails. Instead
 * the function will return with ENODEV.
 */
ICA_EXPORT
void ica_set_fallback_mode(int fallback_mode);

/**
 * Environment variable for setting libica offload mode.
 * By default libica may prefer to do crypto in cpacf instead of adapters.
 * If this environment variable is defined to be an integer not equal to zero,
 * adapters will always be preferred.
 */
#define ICA_OFFLOAD_ENV "LIBICA_OFFLOAD_MODE"

/**
 * Set libica offload mode.
 * By default libica may prefer to do crypto in cpacf instead of adapters.
 * If this function is called with offload_mode != 0, adapters will always
 * be preferred.
 */
ICA_EXPORT
void ica_set_offload_mode(int offload_mode);

/**
 * Environment variable for setting libica stats mode.
 * By default libica counts its crypto operations in shared memory.
 * If this environment variable is defined to be zero, libica will not
 * count crypto operations.
 */
#define ICA_STATS_ENV "LIBICA_STATS_MODE"

/**
 * Set libica stats mode.
 * By default libica counts its crypto operations in shared memory.
 * If this function is called with stats_mode = 0, libica will not
 * count crypto operations.
 */
ICA_EXPORT
void ica_set_stats_mode(int stats_mode);

/**
 * Opens the specified adapter
 * @param adapter_handle Pointer to the file descriptor for the adapter or
 * to DRIVER_NOT_LOADED if opening the crypto adapter failed.
 *
 * @return 0 as long as a valid parameter is given.
 * EINVAL for invalid parameter.
 */
ICA_EXPORT
unsigned int ica_open_adapter(ica_adapter_handle_t *adapter_handle);

/**
 * Closes a device handle.
 * @param adapter_handle Pointer to a previously opened device handle.
 *
 * @return 0 if successful.
 * errno of close() if unsuccessful
 */
ICA_EXPORT
unsigned int ica_close_adapter(ica_adapter_handle_t adapter_handle);

/**
 * Generate a random number.
 *
 * Required HW Support
 * KMC-PRNG
 *
 * @param output_length
 * Specifies the byte length of the output_data buffer and the desired length
 * of the random number.
 * @param output_data
 * Pointer to the buffer to contain the resulting random number.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * ENODEV if neither /dev/hwrng nor /dev/urandom are available.
 * EIO if the operation fails. This should never happen.
 */
ICA_EXPORT
unsigned int ica_random_number_generate(unsigned int output_length,
					unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-1 algorithm.
 *
 * Required HW Support
 * KIMD-SHA-1, or KLMD-SHA-1
 *
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-1 hashed and must be greater
 * than zero.
 * Note: For SHA_MSG_PART_FIRST and SHA_MSG_PART_MIDDLE calls, the byte length
 * must be a multiple of 64 i.e., SHA-1 block size.
 * @param input_data
 * Pointer to the input data data.
 * @param sha_context
 * Pointer to the SHA-1 context structure used to store intermediate values
 * needed when chaining is used. The contents are ignored for message part
 * SHA_MSG_PART_ONLY and SHA_MSG_PART_FIRST. This structure must
 * contain the returned value of the preceding call to ica_sha1 for message
 * part SHA_MSG_PART_MIDDLE and SHA_MSG_PART_FINAL. For message part
 * SHA_MSG_PART_FIRST and SHA_MSG_PART_FINAL, the returned value can
 * be used for a chained call of ica_sha1. Therefore, the application must
 * not modify the contents of this structure in between chained calls.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
ICA_EXPORT
unsigned int ica_sha1(unsigned int message_part,
		      unsigned int input_length,
		      const unsigned char *input_data,
		      sha_context_t *sha_context,
		      unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-224 algorithm.
 *
 * Required HW Support
 * KIMD-SHA-256, or KLMD-SHA-256
 *
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-224 hashed and must be greater
 * than zero.
 * Note: For SHA_MSG_PART_FIRST and SHA_MSG_PART_MIDDLE calls, the byte length
 * must be a multiple of 64 i.e., SHA-224 block size.
 * @param input_data
 * Pointer to the input data.
 * @param sha256_context
 * Pointer to the SHA-256 context structure used to store intermediate values
 * needed when chaining is used. The contents are ignored for message part
 * SHA_MSG_PART_ONLY and SHA_MSG_PART_FIRST. This structure must
 * contain the returned value of the preceding call to ica_sha224 for message
 * part SHA_MSG_PART_MIDDLE and SHA_MSG_PART_FINAL. For message part
 * SHA_MSG_PART_FIRST and SHA_MSG_PART_FINAL, the returned value can
 * be used for a chained call of ica_sha224. Therefore, the application must
 * not modify the contents of this structure in between chained calls.
 * Note: Due to the algorithm used by SHA-224, a SHA-256 context must be
 * used.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA224_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
ICA_EXPORT
unsigned int ica_sha224(unsigned int message_part,
			unsigned int input_length,
			const unsigned char *input_data,
			sha256_context_t *sha256_context,
			unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-256 algorithm.
 *
 * Required HW Support
 * KIMD-SHA-256, or KLMD-SHA-256
 *
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-256 hashed and must be greater
 * than zero.
 * Note: For SHA_MSG_PART_FIRST and SHA_MSG_PART_MIDDLE calls, the byte length
 * must be a multiple of 64 i.e., SHA-256 block size.
 * @param input_data
 * Pointer to the input data.
 * @param sha256_context
 * Pointer to the SHA-256 context structure used to store intermediate values
 * needed when chaining is used. The contents are ignored for message part
 * SHA_MSG_PART_ONLY and SHA_MSG_PART_FIRST. This structure must
 * contain the returned value of the preceding call to ica_sha256 for message part
 * SHA_MSG_PART_MIDDLE and SHA_MSG_PART_FINAL. For message part
 * SHA_MSG_PART_FIRST and SHA_MSG_PART_FINAL, the returned value can
 * be used for a chained call of ica_sha256. Therefore, the application must not
 * modify the contents of this structure in between chained calls.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting output
 * data will have a length of SHA256_HASH_LENGTH. Make sure that the buffer
 * has is at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
ICA_EXPORT
unsigned int ica_sha256(unsigned int message_part,
			unsigned int input_length,
			const unsigned char *input_data,
			sha256_context_t *sha256_context,
			unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-384 algorithm.
 *
 * Required HW Support
 * KIMD-SHA-512, or KLMD-SHA-512
 *
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-384 hashed and must be greater
 * than zero.
 * Note: For SHA_MSG_PART_FIRST and SHA_MSG_PART_MIDDLE calls, the byte length
 * must be a multiple of 128 i.e., SHA-384 block size.
 * @param input_data
 * Pointer to the input data.
 * @param sha512_context
 * Pointer to the SHA-512 context structure used to store intermediate values
 * needed when chaining is used. The contents are ignored for message part
 * SHA_MSG_PART_ONLY and SHA_MSG_PART_FIRST. This structure must
 * contain the returned value of the preceding call to ica_sha384 for message
 * part SHA_MSG_PART_MIDDLE and SHA_MSG_PART_FINAL. For message part
 * SHA_MSG_PART_FIRST and SHA_MSG_PART_FINAL, the returned value can
 * be used for a chained call of ica_sha384. Therefore, the application must
 * not modify the contents of this structure in between chained calls.
 * Note: Due to the algorithm used by SHA-384, a SHA-512 context must be
 * used.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA384_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
ICA_EXPORT
unsigned int ica_sha384(unsigned int message_part,
			uint64_t input_length,
			const unsigned char *input_data,
			sha512_context_t *sha512_context,
			unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-512 algorithm.
 *
 * Required HW Support
 * KIMD-SHA-512, or KLMD-SHA-512
 *
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-512 hashed and must be greater
 * than zero.
 * Note: For SHA_MSG_PART_FIRST and SHA_MSG_PART_MIDDLE calls, the byte length
 * must be a multiple of 128 i.e., SHA-512 block size.
 * @param input_data
 * Pointer to the input data.
 * @param sha512_context
 * Pointer to the SHA-512 context structure used to store intermediate values
 * needed when chaining is used. The contents are ignored for message part
 * SHA_MSG_PART_ONLY and SHA_MSG_PART_FIRST. This structure must
 * contain the returned value of the preceding call to ica_sha512 for message
 * part SHA_MSG_PART_MIDDLE and SHA_MSG_PART_FINAL. For message part
 * SHA_MSG_PART_FIRST and SHA_MSG_PART_FINAL, the returned value can
 * be used for a chained call of ica_sha512. Therefore, the application must
 * not modify the contents of this structure in between chained calls.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA512_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
ICA_EXPORT
unsigned int ica_sha512(unsigned int message_part,
			uint64_t input_length,
			const unsigned char *input_data,
			sha512_context_t *sha512_context,
			unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-512/224 algorithm.
 *
 * Required HW Support
 * KIMD-SHA-512, or KLMD-SHA-512
 *
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-512/224 hashed and must be greater
 * than zero.
 * Note: For SHA_MSG_PART_FIRST and SHA_MSG_PART_MIDDLE calls, the byte length
 * must be a multiple of 128 i.e., SHA-512 block size.
 * @param input_data
 * Pointer to the input data.
 * @param sha512_context
 * Pointer to the SHA-512 context structure used to store intermediate values
 * needed when chaining is used. The contents are ignored for message part
 * SHA_MSG_PART_ONLY and SHA_MSG_PART_FIRST. This structure must
 * contain the returned value of the preceding call to ica_sha512_224 for message
 * part SHA_MSG_PART_MIDDLE and SHA_MSG_PART_FINAL. For message part
 * SHA_MSG_PART_FIRST and SHA_MSG_PART_FINAL, the returned value can
 * be used for a chained call of ica_sha512_224. Therefore, the application must
 * not modify the contents of this structure in between chained calls.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA512_224_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
ICA_EXPORT
unsigned int ica_sha512_224(unsigned int message_part,
			    uint64_t input_length,
			    const unsigned char *input_data,
			    sha512_context_t *sha512_context,
			    unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-512/256 algorithm.
 *
 * Required HW Support
 * KIMD-SHA-512, or KLMD-SHA-512
 *
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-512/256 hashed and must be greater
 * than zero.
 * Note: For SHA_MSG_PART_FIRST and SHA_MSG_PART_MIDDLE calls, the byte length
 * must be a multiple of 128 i.e., SHA-512 block size.
 * @param input_data
 * Pointer to the input data.
 * @param sha512_context
 * Pointer to the SHA-512 context structure used to store intermediate values
 * needed when chaining is used. The contents are ignored for message part
 * SHA_MSG_PART_ONLY and SHA_MSG_PART_FIRST. This structure must
 * contain the returned value of the preceding call to ica_sha512_256 for message
 * part SHA_MSG_PART_MIDDLE and SHA_MSG_PART_FINAL. For message part
 * SHA_MSG_PART_FIRST and SHA_MSG_PART_FINAL, the returned value can
 * be used for a chained call of ica_sha512_256. Therefore, the application must
 * not modify the contents of this structure in between chained calls.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA512_256_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */ICA_EXPORT
unsigned int ica_sha512_256(unsigned int message_part,
			    uint64_t input_length,
			    const unsigned char *input_data,
			    sha512_context_t *sha512_context,
			    unsigned char *output_data);

ICA_EXPORT
unsigned int ica_sha3_224(unsigned int message_part,
			unsigned int input_length,
			const unsigned char *input_data,
			sha3_224_context_t *sha3_224_context,
			unsigned char *output_data);

ICA_EXPORT
unsigned int ica_sha3_256(unsigned int message_part,
			unsigned int input_length,
			const unsigned char *input_data,
			sha3_256_context_t *sha3_256_context,
			unsigned char *output_data);

ICA_EXPORT
unsigned int ica_sha3_384(unsigned int message_part,
			uint64_t input_length,
			const unsigned char *input_data,
			sha3_384_context_t *sha3_384_context,
			unsigned char *output_data);

ICA_EXPORT
unsigned int ica_sha3_512(unsigned int message_part,
			uint64_t input_length,
			const unsigned char *input_data,
			sha3_512_context_t *sha3_512_context,
			unsigned char *output_data);

ICA_EXPORT
unsigned int ica_shake_128(unsigned int message_part,
			uint64_t input_length,
			const unsigned char *input_data,
			shake_128_context_t *shake_128_context,
			unsigned char *output_data,
			unsigned int output_length);

ICA_EXPORT
unsigned int ica_shake_256(unsigned int message_part,
			uint64_t input_length,
			const unsigned char *input_data,
			shake_256_context_t *shake_256_context,
			unsigned char *output_data,
			unsigned int output_length);

/*******************************************************************************
 *
 *                          Begin of ECC API
 */
#ifndef NID_X25519
# define NID_X25519	1034
#endif
#ifndef NID_X448
# define NID_X448	1035
#endif
#ifndef NID_ED25519
# define NID_ED25519	1087
#endif
#ifndef NID_ED448
# define NID_ED448	1088
#endif

typedef struct ec_key_t ICA_EC_KEY;

/**
 * Allocate and return a new ICA_EC_KEY structure.
 *
 * @param nid
 * The identifier of the elliptic curve, on which the new ICA_EC_KEY
 * shall be based.
 *
 * NID Value  NID Name (OpenSSL)     Elliptic Curve    D Length (bytes)
 * ---------  ---------------------- ----------------  ----------------
 *       409  NID_X9_62_prime192v    secp192r1            24
 *       713  NID_secp224r1          secp224r1            28
 *       415  NID_X9_62_prime256v1   secp256r1            32
 *       715  NID_secp384r1          secp384r1            48
 *       716  NID_secp521r1          secp521r1            66
 *       921  NID_brainpoolP160r1    brainpoolP160r1      20
 *       923  NID_brainpoolP192r1    brainpoolP192r1      24
 *       925  NID_brainpoolP224r1    brainpoolP224r1      28
 *       927  NID_brainpoolP256r1    brainpoolP256r1      32
 *       929  NID_brainpoolP320r1    brainpoolP320r1      40
 *       931  NID_brainpoolP384r1    brainpoolP384r1      48
 *       933  NID_brainpoolP512r1    brainpoolP512r1      64
 *      1034  NID_X25519             X25519
 *      1035  NID_X448               X448
 *      1087  NID_ED25519            Ed25519              32
 *      1088  NID_ED448              Ed448                57
 *
 * @param privlen
 * A pointer to an unsigned integer buffer where the length of the
 * private D-value of the ICA_EC_KEY is returned.
 *
 * Note: The lengths of X and Y are the same as the length of D.
 * Therefore, the public key (X,Y) has twice the length of D.
 * Also an ECDSA signature has twice the length of D.
 *
 * @return Pointer to opaque ICA_EC_KEY structure if success.
 * NULL if no memory could be allocated.
 */
ICA_EXPORT
ICA_EC_KEY* ica_ec_key_new(unsigned int nid, unsigned int *privlen);

/**
 * Initialize an ICA_EC_KEY with given private (D) and/or public key
 * values (X,Y). D may be NULL, if no private key value shall be
 * specified. X and Y may both be NULL, if no public key shall be
 * specified. If X is specified, also Y must be specified, and vice
 * versa.
 *
 * @param X
 * Pointer to the public X-value that shall be assigned to the
 * ICA_EC_KEY object.
 *
 * @param Y
 * Pointer to the public Y-value that shall be assigned to the
 * ICA_EC_KEY object.
 *
 * @param D
 * Pointer to the private D-value that shall be assigned to the
 * ICA_EC_KEY object.
 *
 * @return 0 if success
 * EPERM if the EC curve is not supported in this environment
 * EINVAL if at least one invalid parameter is given.
 */
ICA_EXPORT
int ica_ec_key_init(const unsigned char *X, const unsigned char *Y,
		const unsigned char *D, ICA_EC_KEY *key);

/**
 * Generate private and public values for a given ICA_EC_KEY.
 *
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 *
 * @param key
 * Pointer to a previously allocated ICA_EC_KEY object.
 *
 * @return 0 if success
 * EPERM if the EC curve is not supported in this environment
 * EINVAL if at least one invalid parameter is given.
 * ENOMEM if memory could not be allocated.
 * EIO if an internal processing error occurred.
 */
ICA_EXPORT
int ica_ec_key_generate(ica_adapter_handle_t adapter_handle, ICA_EC_KEY *key);

/**
 * Calculate the Diffie-Hellman shared secret (z-value) of a given
 * private ICA_EC_KEY A (with given D-value) and a given public
 * ICA_EC_KEY B (with given X and Y values).
 *
 * @param privkey_A
 * A pointer to a private ICA_EC_KEY object.
 *
 * @param pubkey_B
 * A pointer to a public ICA_EC_KEY object.
 *
 * @param z
 * Pointer to a writable buffer where the shared secret (z) is returned.
 *
 * @param z_length
 * The length in bytes of the z buffer. This length must be greater or
 * equal to privlen, as returned when creating the ICA_EC_KEY objects.
 * Both keys are supposed to be based on the same elliptic curve, so
 * both keys have the same lengths of D, and (X,Y).
 *
 * @return 0 if success
 * EPERM if the EC curve is not supported in this environment
 * EINVAL if at least one invalid parameter is given.
 * EIO if an internal processing error occurred.
 */
ICA_EXPORT
int ica_ecdh_derive_secret(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey_A, const ICA_EC_KEY *pubkey_B,
		unsigned char *z, unsigned int z_length);

/**
 * Create an ECDSA signature for the given hash data using the given
 * private ICA_EC_KEY.
 *
 * @param privkey
 * Pointer to a readable private ICA_EC_KEY object.
 *
 * @param hash
 * Pointer to a readable buffer containing hashed data.
 *
 * @param
 * The length of the hashed data. Supported lengths are
 * 20, 28, 32, 48, and 64 bytes.
 *
 * @param signature
 * Pointer to a writable buffer where the ECDSA signature is returned.
 *
 * @param signature_length
 * The length of the buffer. It must be greater or equal to 2*privlen
 * as returned when creating the ICA_EC_KEY object.
 *
 * @return 0 if success
 * EINVAL if at least one invalid parameter is given.
 * EIO if an internal processing error occurred.
 */
ICA_EXPORT
int ica_ecdsa_sign(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey, const unsigned char *hash, unsigned int hash_length,
		unsigned char *signature, unsigned int signature_length);

/**
 * Create a deterministic ECDSA signature for the given hash data using
 * the given private ICA_EC_KEY and value k.
 *
 * Note: Creating deterministic signatures is only supported via CPACF on MSA9
 * or later. Check your icainfo [-c] output if ECDSA is available on your
 * hardware via CPACF. The function returns EPERM if ECDSA is not supported
 * via CPACF.
 *
 * @param privkey
 * Pointer to a readable private ICA_EC_KEY object.
 *
 * @param hash
 * Pointer to a readable buffer containing hashed data.
 *
 * @param
 * The length of the hashed data. Supported lengths are
 * 20, 28, 32, 48, and 64 bytes.
 *
 * @param signature
 * Pointer to a writable buffer where the ECDSA signature is returned.
 *
 * @param signature_length
 * The length of the buffer. It must be greater or equal to 2*privlen
 * as returned when creating the ICA_EC_KEY object.
 *
 * @param k
 * Pointer to a readable buffer containing the k-value, used together with
 * private key and input hash to create a deterministic signature. This
 * allows to implement known-answer tests using test vectors available
 * from various sources, e.g. NIST or RFCs. The length of k is expected
 * to be equal to the lengths of the r and s parts of the signature.
 *
 * @return 0 if success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if ECDSA is not supported via CPACF (MSA9 or later).
 * EIO if an internal processing error occurred.
 */
ICA_EXPORT
int ica_ecdsa_sign_ex(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *privkey, const unsigned char *hash, unsigned int hash_length,
		unsigned char *signature, unsigned int signature_length,
		const unsigned char *k);

/**
 * Verify a given ECDSA signature with given hash data and public ICA_EC_KEY.
 *
 * @param pubkey
 * Pointer to a readable public ICA_EC_KEY object.
 *
 * @param hash
 * Pointer to a readable buffer containing hashed data.
 *
 * @param
 * The length of the hashed data. Supported lengths are
 * 20, 28, 32, 48, and 64 bytes.
 *
 * @param signature
 * Pointer to a writable buffer where the ECDSA signature is returned.
 *
 * @param signature_length
 * The length of the buffer. It must be greater or equal to 2*privlen
 * as returned when creating the ICA_EC_KEY object.
 *
 * @return 0 if success
 * EINVAL if at least one invalid parameter is given.
 * EIO if an internal processing error occurred.
 * EFAULT if signature invalid
 */
ICA_EXPORT
int ica_ecdsa_verify(ica_adapter_handle_t adapter_handle,
		const ICA_EC_KEY *pubkey, const unsigned char *hash, unsigned int hash_length,
		const unsigned char *signature, unsigned int signature_length);

/**
 * provide the public key (X,Y) of the given ICA_EC_KEY.
 *
 * @param key
 * Pointer to a readable ICA_EC_KEY object.
 *
 * @param q
 * Pointer to a writable buffer where (X,Y) is returned.
 *
 * @param q_len
 * Pointer to a unsigned int where the byte length of (X,Y) is returned.
 *
 * @return 0 if success
 * EINVAL if at least one invalid parameter is given.
 */
ICA_EXPORT
int ica_ec_key_get_public_key(const ICA_EC_KEY *key, unsigned char *q, unsigned int *q_len);

/**
 * provide the private key (D) of the given ICA_EC_KEY.
 *
 * @param key
 * Pointer to a readable ICA_EC_KEY object.
 *
 * @param q
 * Pointer to a writable buffer where (D) is returned.
 *
 * @param q_len
 * Pointer to a unsigned int where the byte length of (D) is returned.
 *
 * @return 0 if success
 * EINVAL if at least one invalid parameter is given.
 */
ICA_EXPORT
int ica_ec_key_get_private_key(const ICA_EC_KEY *key, unsigned char *d, unsigned int *d_len);

/**
 * Free an ICA_EC_KEY.
 *
 * @param key
 * Pointer to ICA_EC_KEY.
 */
ICA_EXPORT
void ica_ec_key_free(ICA_EC_KEY *key);


typedef struct ica_x25519_ctx ICA_X25519_CTX;
typedef struct ica_x448_ctx ICA_X448_CTX;
typedef struct ica_ed25519_ctx ICA_ED25519_CTX;
typedef struct ica_ed448_ctx ICA_ED448_CTX;

/*
 * Allocate a new context. MSA9 required.
 * Returns 0 if successful. Otherwise, -1 is returned.
 */
ICA_EXPORT
int ica_x25519_ctx_new(ICA_X25519_CTX **ctx);
ICA_EXPORT
int ica_x448_ctx_new(ICA_X448_CTX **ctx);
ICA_EXPORT
int ica_ed25519_ctx_new(ICA_ED25519_CTX **ctx);
ICA_EXPORT
int ica_ed448_ctx_new(ICA_ED448_CTX **ctx);

/*
 * Copy the private and public key to the context. MSA9 required.
 * Returns 0 if successful. Otherwise, -1 is returned.
 */
ICA_EXPORT
int ica_x25519_key_set(ICA_X25519_CTX *ctx, const unsigned char priv[32],
		       const unsigned char pub[32]);
ICA_EXPORT
int ica_x448_key_set(ICA_X448_CTX *ctx, const unsigned char priv[56],
		     const unsigned char pub[56]);
ICA_EXPORT
int ica_ed25519_key_set(ICA_ED25519_CTX *ctx, const unsigned char priv[32],
			const unsigned char pub[32]);
ICA_EXPORT
int ica_ed448_key_set(ICA_ED448_CTX *ctx, const unsigned char priv[57],
		      const unsigned char pub[57]);

/*
 * Copy the private and public key from the context. MSA9 required.
 * Returns 0 if successful. Otherwise, -1 is returned.
 */
ICA_EXPORT
int ica_x25519_key_get(ICA_X25519_CTX *ctx, unsigned char priv[32],
		       unsigned char pub[32]);
ICA_EXPORT
int ica_x448_key_get(ICA_X448_CTX *ctx, unsigned char priv[56],
		     unsigned char pub[56]);
ICA_EXPORT
int ica_ed25519_key_get(ICA_ED25519_CTX *ctx, unsigned char priv[32],
			unsigned char pub[32]);
ICA_EXPORT
int ica_ed448_key_get(ICA_ED448_CTX *ctx, unsigned char priv[57],
		      unsigned char pub[57]);

/*
 * Generate a key. MSA9 required.
 * Returns 0 if successful. Otherwise, -1 is returned.
 */
ICA_EXPORT
int ica_x25519_key_gen(ICA_X25519_CTX *ctx);
ICA_EXPORT
int ica_x448_key_gen(ICA_X448_CTX *ctx);
ICA_EXPORT
int ica_ed25519_key_gen(ICA_ED25519_CTX *ctx);
ICA_EXPORT
int ica_ed448_key_gen(ICA_ED448_CTX *ctx);
/*
 * Derive a shared secret. Requires the context to hold the private key.
 * MSA9 required. Returns 0 if successful. Otherwise, -1 is returned.
 */
ICA_EXPORT
int ica_x25519_derive(ICA_X25519_CTX *ctx,
		      unsigned char shared_secret[32],
		      const unsigned char peer_pub[32]);
ICA_EXPORT
int ica_x448_derive(ICA_X448_CTX *ctx,
		    unsigned char shared_secret[56],
		    const unsigned char peer_pub[56]);

/*
 * Sign. Requires the context to hold the private key. MSA9 required.
 * Returns 0 if successful. Otherwise, -1 is returned.
 */
ICA_EXPORT
int ica_ed25519_sign(ICA_ED25519_CTX *ctx, unsigned char sig[64],
		     const unsigned char *msg, size_t msglen);
ICA_EXPORT
int ica_ed448_sign(ICA_ED448_CTX *ctx, unsigned char sig[114],
		   const unsigned char *msg, size_t msglen);

/*
 * Verify. Requires the public key. If the context only holds the private key,
 * the public key is derived. MSA9 required.
 * Returns 0 if signature is valid. Otherwise, -1 is returned.
 */
ICA_EXPORT
int ica_ed25519_verify(ICA_ED25519_CTX *ctx, const unsigned char sig[64],
		       const unsigned char *msg, size_t msglen);
ICA_EXPORT
int ica_ed448_verify(ICA_ED448_CTX *ctx, const unsigned char sig[114],
		     const unsigned char *msg, size_t msglen);

/*
 * Delete a context. Its sensitive data is erased. MSA9 required.
 * Returns 0 if successful. Otherwise, -1 is returned.
 */
ICA_EXPORT
int ica_x25519_ctx_del(ICA_X25519_CTX **ctx);
ICA_EXPORT
int ica_x448_ctx_del(ICA_X448_CTX **ctx);
ICA_EXPORT
int ica_ed25519_ctx_del(ICA_ED25519_CTX **ctx);
ICA_EXPORT
int ica_ed448_ctx_del(ICA_ED448_CTX **ctx);


/*
 *                             End of ECC API
 *
 ******************************************************************************/

/**
 * Generate RSA keys in modulus/exponent format.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param modulus_bit_length
 * Specifies the bit length of the modulus. This value should comply with
 * length of the keys.
 * @param public_key
 * Pointer to where the generated public key is to be placed. If the exponent
 * element in the public key is not set, it will be randomly generated. A not
 * well chosen exponent may result in the program looping endlessly. Common
 * public exponents are 3 and 65537.
 * @param private_key
 * Pointer to where the generated private key in modulus/exponent format is to
 * be placed. Length of both private and public key should be set in bytes.
 * This value should comply with modulus bit length. Make sure that buffers in
 * the keys fit to this length.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EPERM if modulus bit length is greater than 4096 (CEX adapter restriction).
 * EFAULT if OpenSSL key generation should fail.
 */
ICA_EXPORT
unsigned int ica_rsa_key_generate_mod_expo(ica_adapter_handle_t adapter_handle,
					   unsigned int modulus_bit_length,
					   ica_rsa_key_mod_expo_t *public_key,
					   ica_rsa_key_mod_expo_t *private_key);

/**
 * Generate RSA keys in CRT format.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param modulus_bit_length
 * Specifies the bit length of the modulus. This value should comply with
 * length of the keys.
 * @param public_key
 * Pointer to where the generated public key is to be placed. If the exponent
 * element in the public key is not set, it will be randomly generated. A not
 * well chosen exponent may result in the program looping endlessly. Common
 * public exponents are 3 and 65537.
 * @param private_key
 * Pointer to where the generated private key in CRT format is to be placed.
 * Length of both private and public key should be set in bytes. This value
 * should comply with modulus bit length. Make sure that buffers in the keys
 * fit to this length.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EPERM if modulus bit length is greater than 4096 (CEX adapter restriction).
 * EFAULT if OpenSSL key generation should fail.
 */
ICA_EXPORT
unsigned int ica_rsa_key_generate_crt(ica_adapter_handle_t adapter_handle,
				      unsigned int modulus_bit_length,
				      ica_rsa_key_mod_expo_t *public_key,
				      ica_rsa_key_crt_t *private_key);

/**
 * @brief Perform a RSA encryption/decryption operation using a key in
 * modulus/exponent form.
 *
 * Make sure your message is padded before using this function. Otherwise you
 * will risk security!
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param input_data
 * Pointer to input data to be encrypted/decrypted and is in big endian format.
 * Make sure input data is not longer than bit length of the key! Byte length
 * has to be the same. Thus right justify input data inside the data block.
 * @param rsa_key
 * Pointer to the key to be used, in modulus/exponent format.
 * @param output_data
 * Pointer to where the output results are to be placed.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EPERM if key bit length is greater than 4096 (CEX adapter restriction).
 * ENOMEM if memory allocation fails.
 * EIO if the operation fails. This should never happen.
 */
ICA_EXPORT
unsigned int ica_rsa_mod_expo(ica_adapter_handle_t adapter_handle,
			      const unsigned char *input_data,
			      ica_rsa_key_mod_expo_t *rsa_key,
			      unsigned char *output_data);

/**
 * @brief Perform a RSA encryption/decryption operation using a key in CRT
 *	  form.
 *
 * Make sure your message is padded before using this function. Otherwise you
 * will risk security!
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param input_data
 * Pointer to input data to be encrypted/decrypted and is in big endian format.
 * Make sure input data is not longer than bit length of the key! Byte length
 * has to be the same. Thus right justify input data inside the data block.
 * @param rsa_key
 * Pointer to the key to be used, in CRT format.
 * @param output_data
 * Pointer to where the output results are to be placed. Buffer has to be as
 * large as the input_data and length of the modulus specified in rsa_key.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EPERM if key bit length is greater than 4096 (CEX adapter restriction).
 * ENOMEM if memory allocation fails.
 * EIO if the operation fails. This should never happen.
 */
ICA_EXPORT
unsigned int ica_rsa_crt(ica_adapter_handle_t adapter_handle,
			 const unsigned char *input_data,
			 ica_rsa_key_crt_t *rsa_key,
			 unsigned char *output_data);

/*
 * Check if RSA key credentials in CRT format are presented in
 * privileged form, respectively prime 'p' > prime 'q'.
 *
 * In case of 'p' < 'q', key credentials 'p' and 'q' as well as 'dp'
 * and 'dq' will be swapped and qInverse will be recalculated.
 *
 * @return
 *  0 if all key credentials are in the correct format.
 *  1 if the key credentials were re-calculated.
 *  ENOMEM if memory allocation fails.
 */
ICA_EXPORT
unsigned int ica_rsa_crt_key_check(ica_rsa_key_crt_t *rsa_key);

/**
 * Encrypt or decrypt data with an DES key using Electronic Cook Book (ECB)
 * mode as described in NIST Special Publication 800-38A Chapter 6.1.
 *
 * Required HW Support
 * KM-DEA-192
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writeable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. data_length must be a multiple of the cipher block
 * size (i.e. a multiple of 8 for DES).
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_des_ecb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned int direction);

/**
 * Encrypt or decrypt data with an DES key using Cipher Block Chaining (CBC)
 * mode as described in NIST Special Publication 800-38A Chapter 6.2.
 *
 * Required HW Support
 * KMC-DEA
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. data_length must be a multiple of the cipher block
 * size (i.e. a multiple of 8 for DES).
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes. This
 * vector will be overwritten during the function. The result value in iv may
 * be used as initialization vector for a chained ica_des_cbc call with the
 * same key.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_des_cbc(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned char *iv,
			 unsigned int direction);

/**
 * Encrypt or decrypt data with an DES key using Cipher Block Chaining with
 * Ciphertext Stealing (CBC-CS) mode as described in NIST Special Publication
 * 800-38A Chapter 6.2 and the Addendum to NIST Special Publication 800-38A on
 * Recommendation for Block Cipher Modes of Operation: Three Variants of
 * Ciphertext Stealing for CBC Moder:
 * ica_des_cbc_cs may be used to encrypt or decrypt the last chunk of a
 * message consisting of multiple chunks where all but the last chunk are
 * encrypted or decrypted by chained calls to ica_des_cbc and the resulting
 * iv of the last call to ica_des_cbc is fed into the iv of the ica_des_cbc_cs
 * call provided the chunk is greater than cipher block size (greater than
 * 8 bytes for DES).
 *
 * Required HW Support
 * KMC-DEA
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer
 * in bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. data_length must be greater than or equal to the
 * cipher block size (i.e. a multiple of 8 bytes for DES).
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes.
 * This vector will be overwritten during the function. For variant equals 1
 * or variant equals 2 the result value in iv may be used as initialization
 * vector for a chained ica_des_cbc call with the same key if data_length is
 * a multiple of the cipher block size.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 * @param variant
 * 1 Use variant CBC-CS1 of the Addendum to NIST Special Publication 800-38A
 *   to encrypt or decrypt the message: keep last two blocks in order.
 * 2 Use variant CBC-CS2 of the Addendum to NIST Special Publication 800-38A
 *   to encrypt or decrypt the message: switch order of the last two blocks
 *   if data_length is not a multiple of the cipher block size (i.e. a
 *   multiple of 8 for DES).
 * 3 Use variant CBC-CS3 of the Addendum to NIST Special Publication 800-38A
 *   to encrypt or decrypt the message: always switch order of the last two
 *   blocks.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_des_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			    unsigned long data_length, unsigned char *key,
			    unsigned char *iv,
			    unsigned int direction,
			    unsigned int variant);

/**
 * Encrypt or decrypt data with an DES key using Cipher Feedback (CFB) mode as
 * described in NIST Special Publication 800-38A Chapter 6.3.
 *
 * Required HW Support
 * KMF-DEA
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data.
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes (8 bytes
 * for DES). This vector will be overwritten during the function. The result
 * value in iv may be used as initialization vector for a chained ica_des_cfb
 * call with the same key if data_length in the preceding call is a multiple of
 * lcfb.
 * @param lcfb
 * Length in bytes of the cipher feedback which is a value greater than or
 * equal to 1 and less than or equal to the cipher block size (i.e. 8 for DES).
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_des_cfb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned char *iv, unsigned int lcfb,
			 unsigned int direction);

/**
 * Encrypt or decrypt data with an DES key using Counter (CTR) mode as
 * described in NIST Special Publication 800-38A Chapter 6.5. With the counter
 * mode each message block of size cipher block size (i.e. 8 bytes for DES) is
 * combined with a counter value of the same size during encryption and
 * decryption. Starting with an initial counter value to be combined with the
 * first message block subsequent counter values to be combined with subsequent
 * message blocks will be derived from preceding counter values by an increment
 * function. The increment function used in ica_des_ctr is s an arithmetic
 * increment without carry on the U least significant bits in the counter
 * where M is a parameter to ica_des_ctr.
 *
 * Required HW Support
 * KMCTR-DEA
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data.
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param ctr
 * Pointer to a readable and writable buffer of size cipher block size bytes.
 * ctr contains an initialization value for a counter function and it will be
 * replaced by a new value. That new value can be used as an initialization
 * value for a counter function in a chained ica_des_ctr call with the same key
 * if data_length used in the preceding call is a multiple of the cipher block
 * size.
 * @param ctr_width
 * A number U between 8 and cipher block size in bits. The value is used by the
 * counter increment function which increments a counter value by incrementing
 * without carry the least significant U bits of the counter value. The value
 * must be a multiple of 8. When in FIPS mode, an additional counter overflow
 * check is performed, so that the given data length, divided by the cipher
 * block size, is not greater than 2 to the power of U.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_des_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 unsigned char *key,
			 unsigned char *ctr, unsigned int ctr_width,
			 unsigned int direction);

/**
 * Encrypt or decrypt data with an DES key using Counter (CTR) mode as
 * described in NIST Special Publication 800-38A, Chapter 6.5. With the counter
 * mode each message block of size cipher block size is combined with a counter
 * value of the same size during encryption and decryption. The ica_des_ctrlist
 * function assumes that a list n of precomputed counter values is provided
 * where n is the smallest integer that is less or equal to the message size
 * divided by the cipher block size. This function allows to optimally exploit
 * System z HW support for non-standard counter functions.
 *
 * Required HW Support
 * KMCTR-DEA
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. If data_length is a multiple of the cipher block size
 * then calls of ica_des_ctrlist with the same key can be chained if ctrlist
 * argument of the chained call contains a list of counters that follows the
 * counters used in the first call and data_length used in the preceding call
 * is a multiple of the cipher block size.
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param ctrlist
 * Pointer to a readable buffer of that is both of size greater than or equal
 * to data_length and a multiple of the cipher block size (i.e. 8 bytes for
 * DES). ctrlist should contain a list of precomputed counter values of size
 * cipher block size each.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_des_ctrlist(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     unsigned char *key,
			     const unsigned char *ctrlist,
			     unsigned int direction);

/**
 * Encrypt or decrypt data with an DES key using Output Feedback (OFB) mode as
 * described in NIST Special Publication 800-38A Chapter 6.4.
 *
 * Required HW Support
 * KMO-DEA
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that contains the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data.
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes (8 bytes
 * for DES). This vector will be overwritten during the function. If
 * data_length is a multiple of the cipher block size (i.e. a multiple of 8 for
 * DES) the result value in iv may be used as initialization vector for a
 * chained ica_des_ofb call with the same key.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_des_ofb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned char *iv, unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an DES key using
 * the Block Cipher Based Message Authetication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B. ica_des_cmac can be used to
 * authenticate or verify the authenticity of a complete message.
 *
 * Required HW Support
 * KMAC-DEA
 * PCC-Compute-Last_block-CMAC-Using-DEA
 *
 * @param message
 * Pointer to a readable buffer of size greater than or equal to message_length
 * bytes. It contains a message  to be authenticated or of which the
 * authenticity shall be verified.
 * @param message_length
 * Length in bytes of the message to be authenticated or verified.
 * @param mac
 * Pointer to a buffer of size greater than or equal to mac_length bytes. If
 * direction is 1 the buffer must be writable and a message authentication code
 * for the message in message of size mac_length bytes will be written to the
 * buffer. If direction is 0 the buffer must be readable and contain a message
 * authentication code that will be verified against the message in message.
 * @param mac_length
 * Length in bytes of the message authentication code mac in bytes that is less
 * than or equal to the cipher block size (i.e. 8 bytes for DES). It is
 * recommended to use values greater than or equal to 8.
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param direction
 * 0 or 1:
 * 0 Verify message authentication code
 * 1 Compute message authentication code for the message
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 * EFAULT if direction is 0 and the verification of the message authentication
 * code fails.
 */
ICA_EXPORT
unsigned int ica_des_cmac(const unsigned char *message, unsigned long message_length,
			  unsigned char *mac, unsigned int mac_length,
			  unsigned char *key,
			  unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an DES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B.
 * ica_des_cmc_intermediate and ica_des_cmac_last can be used when the message
 * to be authenticated or to be verified using CMAC is supplied in multiple
 * chunks. ica_des_cmac_intermediate is used to process all but the last
 * chunk. All message chunks to preprocessed by ica_des_cmac_intermediate
 * must have a size that is a multiple of the cipher block size (i.e a
 * multiple of 8 bytes for DES).
 * Note: ica_des_cmac_intermediate has no direction argument it can be used
 * during an authentication and during authenticity verification.
 *
 * Required HW Support
 * KMAC-DEA
 *
 * @param message
 * Pointer to a readable buffer of size greater than or equal to
 * message_length bytes. It contains a non final part of a message which
 * shall be authenticated or of which the authenticity shall be verified.
 * @param message_length
 * Length in bytes of the message part in message. It must be a multiple
 * of the cipher block size.
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param iv
 * Pointer to a valid  initialization vector of size cipher block size (i.e.
 * 8 bytes for DES). For the first message part it must be set to a string
 * of zeros. For processing the n-th message part it must be the resulting iv
 * value of the ica_des_cmac_intermediate applied to the (n-1)-th message
 * part. This vector will be overwritten during the function. The result value
 * in iv may be used as initialization vector for a chained call to
 * ica_des_cmac_initermediate or to ica_des_cmac_last with the same key.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_des_cmac_intermediate(const unsigned char *message,
				       unsigned long message_length,
				       unsigned char *key,
				       unsigned char *iv);

/**
 * Authenticate data or verify the authenticity of data with an DES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B.
 * ica_des_cmac_last can be used to authenticate or verify the authenticity of
 * a complete message or of the final part of a message for which all
 * preceding parts were preprocessed with ica_des_cmac_intermediate.
 *
 * Required HW Support
 * KMAC-DEA,
 * PCC-Compute-Last_block-CMAC-Using-DEA
 *
 * @param message
 * Pointer to a readable buffer of size greater than or equal to message_length
 * bytes. It contains a message or the final part of a message to be
 * authenticated or of which the authenticity shall be verified.
 * @param message_length
 * Length in bytes of the message to be authenticated or verified.
 * @param mac
 * Pointer to a buffer of size greater than or equal to mac_length bytes.
 * If direction is 1 the buffer must be writable and a message authentication
 * code for the message in message of size mac_length bytes will be written to
 * the buffer.
 * If direction is 0 the buffer must be readable and contain a message
 * authentication code that will be verified against the message in message.
 * @param mac_length
 * Length in bytes of the message authentication code mac in bytes that is less
 * than or equal to the cipher block size (i.e. 8 bytes for DES). It is
 * recommended to use values greater than or equal to 8.
 * @param key
 * Pointer to a valid DES key of 8 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of size cipher block size. If iv is
 * NULL message is assumed to be the complete message to be processed.
 * Otherwise message is the final part of a composite message to be processed
 * and iv contains the output vector resulting from processing all previous
 * parts with chained calls to ica_aes_cmac_intermediate, i.e. the value
 * returned in iv of the ica_des_cmac_intermediate call applied to the
 * penultimate message part.
 * @param direction
 * 0 or 1:
 * 0 Verify message authentication code
 * 1 Compute message authentication code for the message
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 * EFAULT if direction is 0 and the verification of the message authentication
 * code fails.
 */
ICA_EXPORT
unsigned int ica_des_cmac_last(const unsigned char *message, unsigned long message_length,
			       unsigned char *mac, unsigned int mac_length,
			       unsigned char *key,
			       unsigned char *iv,
			       unsigned int direction);

/**
 * Encrypt or decrypt data with an 3DES key using Electronic Cook Book (ECB)
 * mode as described in NIST Special Publication 800-38A Chapter 6.1.
 *
 * Required HW Support
 * KM-DEA-192
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writeable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. data_length must be a multiple of the cipher block
 * size (i.e. a multiple of 8 for 3DES).
 * @param key
 * Pointer to a valid 3DES key of 24 bytes length.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_3des_ecb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, unsigned char *key,
			  unsigned int direction);

/**
 * Encrypt or decrypt data with an 3DES key using Cipher Block Chaining (CBC)
 * mode as described in NIST Special Publication 800-38A Chapter 6.2.
 *
 * Required HW Support
 * KMC-TDEA-192
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. data_length must be a multiple of the cipher block
 * size (i.e. a multiple of 8 for 3DES).
 * @param key
 * Pointer to a valid 3DES key of 24 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes. This
 * vector will be overwritten during the function. The result value in iv may
 * be used as initialization vector for a chained ica_3des_cbc call with the
 * same key.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_3des_cbc(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, unsigned char *key,
			  unsigned char *iv,
			  unsigned int direction);

/**
 * Encrypt or decrypt data with an 3DES key using Cipher Block Chaining with
 * Ciphertext Stealing (CBC-CS) mode as described in NIST Special Publication
 * 800-38A Chapter 6.2 and the Addendum to NIST Special Publication 800-38A on
 * "Recommendation for Block Cipher Modes of Operation: Three Variants of
 * Ciphertext Stealing for CBC Mode":
 * ica_3des_cbc_cs may be used to encrypt o decrypt the last chunk of a
 * message consisting of multiple chunks where all but the last chunk are
 * encrypted or decrypted by chained calls to ica_3des_cbc and the resulting
 * iv of the last call to ica_3des_cbc is fed into the iv of the
 * ica_3des_cbc_cs call provided the chunk is greater than cipher block size
 * (greater than 8 bytes for 3DES).
 *
 * Required HW Support
 * KMC-TDEA-192
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer
 * in bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. data_length must be greater than or equal to the
 * cipher block size (i.e. a multiple of 8 bytes for 3DES).
 * @param key
 * Pointer to a valid 3DES key of 24 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes. This
 * vector will be overwritten during the function. For variant equals 1 or
 * variant equals 2 the result value in iv may be used as initialization vector
 * for a chained ica_3des_cbc call with the same key if data_length is a
 * multiple of the cipher block size.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 * @param variant
 * 1 Use variant CBC-CS1 of the Addendum to NIST Special Publication 800-38A
 *   to encrypt or decrypt the message: keep last two blocks in order.
 * 2 Use variant CBC-CS2 of the Addendum to NIST Special Publication 800-38A
 *   to encrypt or decrypt the message: switch order of the last two blocks
 *   if data_length is not a multiple of the cipher block size (i.e. a
 *   multiple of 8 for DES).
 * 3 Use variant CBC-CS3 of the Addendum to NIST Special Publication 800-38A
 *   to encrypt or decrypt the message: always switch order of the last two
 *   blocks.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_3des_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     unsigned char *key,
			     unsigned char *iv,
			     unsigned int direction, unsigned int variant);

/**
 * Encrypt or decrypt data with an 3DES key using Cipher Feedback (CFB) mode as
 * described in NIST Special Publication 800-38A Chapter 6.3.
 *
 * Required HW Support
 * KMF-TDEA-192
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data.
 * @param key
 * Pointer to a valid 3DES key of 24 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes (8 bytes
 * for 3DES). This vector will be overwritten during the function. The result
 * value in iv may be used as initialization vector for a chained ica_3des_cfb
 * call with the same key if data_length in the preceding call is a multiple of
 * lcfb.
 * @param lcfb
 * Length in bytes of the cipher feedback which is a value greater than or
 * equal to 1 and less than or equal to the cipher block size (i.e. 8 for
 * 3DES).
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_3des_cfb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, unsigned char *key,
			  unsigned char *iv, unsigned int lcfb,
			  unsigned int direction);

/**
 * Encrypt or decrypt data with an 3DES key using Counter (CTR) mode as
 * described in NIST Special Publication 800-38A Chapter 6.5. With the counter
 * mode each message block of size cipher block size (i.e. 8 bytes for 3DES) is
 * combined with a counter value of the same size during encryption and
 * decryption. Starting with an initial counter value to be combined with the
 * first message block subsequent counter values to be combined with subsequent
 * message blocks will be derived from preceding counter values by an increment
 * function. The increment function used in ica_3des_ctr is s an arithmetic
 * increment without carry on the U least significant bits in the counter
 * where M is a parameter to ica_3des_ctr.
 *
 * Required HW Support
 * KMCTR-TDEA-192
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data.
 * @param key
 * Pointer to a valid 3DES key of 24 bytes length.
 * @param ctr
 * Pointer to a readable and writable buffer of size cipher block size bytes.
 * ctr contains an initialization value for a counter function and it will be
 * replaced by a new value. That new value can be used as an initialization
 * value for a counter function in a chained ica_3des_ctr call with the same
 * key if data_length used in the preceding call is a multiple of the cipher
 * block size.
 * @param ctr_width
 * A number U between 8 and cipher block size in bits. The value is used by the
 * counter increment function which increments a counter value by incrementing
 * without carry the least significant U bits of the counter value. The value
 * must be a multiple of 8. When in FIPS mode, an additional counter overflow
 * check is performed, so that the given data length, divided by the cipher
 * block size, is not greater than 2 to the power of U.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_3des_ctr(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length,
			  unsigned char *key,
			  unsigned char *ctr, unsigned int ctr_width,
			  unsigned int direction);

/**
 * Encrypt or decrypt data with an 3DES key using Counter (CTR) mode as
 * described in NIST Special Publication 800-38A ,Chapter 6.5. With the counter
 * mode each message block of size cipher block size is combined with a counter
 * value of the same size during encryption and decryption. The
 * ica_3des_ctrlist function assumes that a list n of precomputed counter
 * values is provided where n is the smallest integer that is less or equal to
 * the message size divided by the cipher block size. This function allows to
 * optimally exploit System z HW support for non-standard counter functions.
 *
 * Required HW Support
 * KMCTR-TDEA-192
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. If data_length is a multiple of the cipher block size
 * then calls of ica_3des_ctrlist with the same key can be chained if ctrlist
 * argument of the chained call contains a list of counters that follows the
 * counters used in the first call and data_length used in the preceding call
 * is a multiple of the cipher block size.
 * @param key
 * Pointer to an 3DES key of 24 bytes length.
 * @param ctrlist
 * Pointer to a readable buffer of that is both of size greater than or equal
 * to data_length and a multiple of the cipher block size (i.e. 8 bytes for
 * 3DES). ctrlist should contain a list of precomputed counter values of size
 * cipher block size each.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_3des_ctrlist(const unsigned char *in_data, unsigned char *out_data,
			      unsigned long data_length,
			      unsigned char *key,
			      const unsigned char *ctrlist,
			      unsigned int direction);

/**
 * Encrypt or decrypt data with an 3DES key using Output Feedback (OFB) mode as
 * described in NIST Special Publication 800-38A Chapter 6.4.
 *
 * Required HW Support
 * KMO-TDEA-192
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that contains the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data.
 * @param key
 * Pointer to a valid 3DES key of 24 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes (8 bytes
 * for DES). This vector will be overwritten during the function. If
 * data_length is a multiple of the cipher block size (i.e. a multiple of 8 for
 * 3DES) the result value in iv may be used as initialization vector for a
 * chained ica_3DES_ofb call with the same key.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_3des_ofb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, unsigned char *key,
			  unsigned char *iv, unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an 3DES key
 * using the Block Cipher Based Message Authentication Code (CMAC) mode as
 * described in NIST Special Publication 800-38B.
 * ica_3des_cmac can be used to authenticate or verify the authenticity of a
 * complete message.
 *
 * Required HW Support
 * KMAC-TDEA-192
 * PCC-Compute-Last_block-CMAC-Using-TDEA-192
 *
 * @param message
 * Pointer to a readable buffer of size greater than or equal to
 * message_length bytes. It contains a message  to be authenticated or of
 * which the authenticity shall be verified.
 * @param message_length
 * Length in bytes of the message to be authenticated or verified.
 * @param mac
 * Pointer to a buffer of size greater than or equal to mac_length bytes.
 * If direction is 1 the buffer must be writable and a message authentication
 * code for the message in message of size mac_length bytes will be written to
 * the buffer.
 * If direction is 0 the buffer must be readable and contain a message
 * authentication code that will be verified against the message in message.
 * @param mac_length
 * Length in bytes of the message authentication code mac in bytes that is less
 * than or equal to the cipher block size (i.e. 8 bytes for TDES). It is
 * recommended to use values greater than or equal to 8.
 * @param key
 * Pointer to a valid 3DES key of 24 bytes length.
 * @param direction
 * 0 or 1:
 * 0 Verify message authentication code
 * 1 Compute message authentication code for the message
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 * EFAULT if direction is 0 and the verification of the message authentication
 * code fails.
 */
ICA_EXPORT
unsigned int ica_3des_cmac(const unsigned char *message, unsigned long message_length,
			   unsigned char *mac, unsigned int mac_length,
			   unsigned char *key,
			   unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an 3DES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B.
 * ica_3des_cmc_intermediate and ica_3des_cmac_last can be used when the
 * message to be authenticated or to be verified using CMAC is supplied in
 * multiple chunks. ica_3des_cmac_intermediate is used to process all but the
 * last chunk. All message chunks to preprocessed by
 * ica_3des_cmac_intermediate must have a size that is a multiple of the
 * cipher block size (i.e a multiple of 8 bytes for 3DES).
 * Note: ica_3des_cmac_intermediate has no direction argument it can be used
 * during an authentication and during authenticity verification.
 *
 * Required HW Support
 * KMAC-TDEA-192,
 *
 * @param message
 * Pointer to a readable buffer of size greater than or equal to message_length
 * bytes. It contains a non final part of a message which shall be
 * authenticated or of which the authenticity shall be verified.
 * @param message_length
 * Length in bytes of the message part in message. It must be a multiple of the
 * cipher block size.
 * @param key
 * Pointer to a valid 3DES key of 24 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of size cipher block size
 * (i.e. 8 bytes for 3DES). For the first message part it must be set to a
 * string of zeros. For processing the n-th message part it must be the
 * resulting iv value of the ica_3des_cmac_intermediate applied to the
 * (n-1)-th message part. This vector will be overwritten during the function.
 * The result value in iv may be used as initialization vector for a chained
 * call to ica_3des_cmac_initermediate or to ica_3des_cmac_last with the same key.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_3des_cmac_intermediate(const unsigned char *message, unsigned long message_length,
					unsigned char *key,
					unsigned char *iv);

/**
 * Authenticate data or verify the authenticity of data with an 3DES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B.
 * ica_3des_cmac_last can be used to authenticate or verify the authenticity
 * of a complete message or of the final part of a message for which all
 * preceding parts were preprocessed with ica_3des_cmac_intermediate.
 *
 * Required HW Support
 * KMAC-TDEA-192,
 * PCC-Compute-Last_block-CMAC-Using-TDEA-192
 *
 * @param message
 * Pointer to a readable buffer of size greater than or equal to message_length
 * bytes. It contains a message or the final part of a message to be
 * authenticated or of which the authenticity shall be verified.
 * @param message_length
 * Length in bytes of the message to be authenticated or verified.
 * @param mac
 * Pointer to a buffer of size greater than or equal to mac_length bytes.
 * If direction is 1 the buffer must be writable and a message authentication
 * code for the message in message of size mac_length bytes will be written to
 * the buffer.
 * If direction is 0 the buffer must be readable and contain a message
 * authentication code that will be verified against the message in message.
 * @param mac_length
 * Length in bytes of the message authentication code mac in bytes that is
 * less than or equal to the cipher block size (I.e. 8 bytes for DES). It is
 * recommended to use values greater than or equal to 8.
 * @param key
 * Pointer to a valid  3DES key of 24 bytes length.
 * @param iv
 * Pointer to a valid initialization vector of size cipher block size. If iv
 * is NULL message is assumed to be the complete message to be processed.
 * Otherwise message is the final part of a composite message to be processed
 * and iv contains the output vector resulting from processing all previous
 * parts with chained calls to ica_3des_cmac_intermediate, i.e. the value
 * returned in iv of the ica_3des_cmac_intermediate call applied to the
 * penultimate message part.
 * @param direction
 * 0 or 1:
 * 0 Verify message authentication code
 * 1 Compute message authentication code for the message
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 * EFAULT if direction is 0 and the verification of the message authentication
 * code fails.
 */
ICA_EXPORT
unsigned int ica_3des_cmac_last(const unsigned char *message, unsigned long message_length,
				unsigned char *mac, unsigned int mac_length,
				unsigned char *key, unsigned char *iv,
				unsigned int direction);

/**
 * Encrypt or decrypt data with an AES key using Electronic Cook Book (ECB)
 * mode as described in NIST Special Publication 800-38A Chapter 6.1.
 *
 * Required HW Support
 * KM-AES-128, KM-AES-192 or KM-AES-256
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. data_length must be a multiple of the cipher block
 * size (i.e. a multiple of 16 for AES).
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_ecb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned int key_length,
			 unsigned int direction);

/**
 * Encrypt or decrypt data with an AES key using Cipher Block Chaining (CBC)
 * mode as described in NIST Special Publication 800-38A Chapter 6.2.
 *
 * Required HW Support
 * KMC-AES-128, KMC-AES-192 or KMC-AES-256
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. data_length must be a multiple of the cipher block
 * size (i.e. a multiple of 16 for AES).
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param iv
 * Pointer to a valid initialization vector of size cipher block size. This
 * vector will be overwritten during the function. The result value in iv may
 * be used as initialization vector for a chained ica_aes_cbc call with the
 * same key.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_cbc(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned int key_length, unsigned char *iv,
			 unsigned int direction);

/**
 * Encrypt or decrypt data with an AES key using Cipher Block Chaining with
 * Ciphertext Stealing (CBC-CS) mode as described in NIST Special Publication
 * 800-38A Chapter 6.2 and the Addendum to NIST Special Publication 800-38A on
 * "Recommendation for Block Cipher Modes of Operation: Three Variants of
 * Ciphertext Stealing for CBC Mode":
 * ica_aes_cbc_cs may be used to encrypt or decrypt the last chunk of a
 * message consisting of multiple chunks where all but the last chunk are
 * encrypted or decrypted by chained calls to ica_aes_cbc and the resulting
 * iv of the last call to ica_aes_cbc is fed into the iv of the
 * ica_aes_cbc_cs call provided the chunk is greater than cipher block size
 * (greater than 16 bytes for AES).
 *
 * Required HW Support
 * KMC-AES-128, KMC-AES-192 or KMC-AES-256
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer
 * in bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. data_length must be greater than or equal to the
 * cipher block size (i.e. a multiple of 16 bytes for AES).
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros:
 * AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes. This
 * vector will be overwritten during the function. For variant equals 1 or
 * variant equals 2 the result value in iv may be used as initialization vector
 * for a chained ica_aes_cbc call with the same key if data_length is a
 * multiple of the cipher block size.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 * @param variant
 * 1 Use variant CBC-CS1 of the Addendum to NIST Special Publication 800-38A
 *   to encrypt or decrypt the message: keep last two blocks in order.
 * 2 Use variant CBC-CS2 of the Addendum to NIST Special Publication 800-38A
 *   to encrypt or decrypt the message: switch order of the last two blocks
 *   if data_length is not a multiple of the cipher block size (i.e. a
 *   multiple of 8 for DES).
 * 3 Use variant CBC-CS3 of the Addendum to NIST Special Publication 800-38A
 *   to encrypt or decrypt the message: always switch order of the last two
 *   blocks.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			    unsigned long data_length,
			    unsigned char *key, unsigned int key_length,
			    unsigned char *iv,
			    unsigned int direction, unsigned int variant);

/**
 * Encrypt or decrypt data with an AES key using Cipher Feedback (CFB) mode as
 * described in NIST Special Publication 800-38A Chapter 6.3.
 *
 * Required HW Support
 * KMF-AES-128, KMF-AES-192 or KMF-AES-256
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data.
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param iv
 * Pointer to a valid initialization vector of cipher block size bytes (16
 * bytes for AES). This vector will be overwritten during the function. The
 * result value in iv may be used as initialization vector for a chained
 * ica_aes_cfb call with the same key if data_length in the preceding call is a
 * multiple of lcfb.
 * @param lcfb
 * Length in bytes of the cipher feedback which is a value greater than or
 * equal to 1 and less than or equal to the cipher block size (i.e. 16 for
 * AES).
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_cfb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned int key_length, unsigned char *iv, unsigned int lcfb,
			 unsigned int direction);

/**
 * Encrypt or decrypt data with an AES key using Counter (CTR) mode as
 * described in NIST Special Publication 800-38A Chapter 6.5. With the counter
 * mode each message block of size cipher block size (i.e. 16 bytes for AES) is
 * combined with a counter value of the same size during encryption and
 * decryption. Starting with an initial counter value to be combined with the
 * first message block subsequent counter values to be combined with subsequent
 * message blocks will be derived from preceding counter values by an increment
 * function. The increment function used in ica_aes_ctr is s an arithmetic
 * increment without carry on the U least significant bits in the counter
 * where M is a parameter to ica_aes_ctr.
 *
 * Required HW Support
 * KMCTR-AES-128, KMCTR-AES-192 or KMCTR-AES-256
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data.
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param ctr
 * Pointer to a readable and writable buffer of size cipher block size bytes.
 * ctr contains an initialization value for a counter function and it will be
 * replaced by a new value. That new value can be used as an initialization
 * value for a counter function in a chained ica_aes_ctr call with the same key
 * if data_length used in the preceding call is a multiple of the cipher block
 * size.
 * @param ctr_width
 * A number U between 8 and cipher block size in bits. The value is used by the
 * counter increment function which increments a counter value by incrementing
 * without carry the least significant U bits of the counter value. The value
 * must be a multiple of 8. When in FIPS mode, an additional counter overflow
 * check is performed, so that the given data length, divided by the cipher
 * block size, is not greater than 2 to the power of U.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 unsigned char *key, unsigned int key_length,
			 unsigned char *ctr, unsigned int ctr_width,
			 unsigned int direction);

/**
 * Encrypt or decrypt data with an AES key using Counter (CTR) mode as
 * described in NIST Special Publication 800-38A ,Chapter 6.5. With the counter
 * mode each message block of size cipher block size is combined with a counter
 * value of the same size during encryption and decryption. The ica_aes_ctrlist
 * function assumes that a list n of precomputed counter values is provided
 * where n is the smallest integer that is less or equal to the message size
 * divided by the cipher block size. This function allows to optimally exploit
 * System z HW support for non-standard counter functions.
 *
 * Required HW Support
 * KMCTR-AES-128, KMCTR-AES-192 or KMCTR-AES-256
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. If data_length is a multiple of the cipher block size
 * then calls of ica_aes_ctrlist with the same key can be chained if ctrlist
 * argument of the chained call contains a list of counters that follows the
 * counters used in the first call and data_length used in the preceding call
 * is a multiple of the cipher block size.
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param ctrlist
 * Pointer to a readable buffer of that is both of size greater than or equal
 * to data_length and a multiple of the cipher block size (i.e. 16 bytes for
 * AES). ctrlist should contain a list of precomputed counter values of size
 * cipher block size each.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_ctrlist(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     unsigned char *key, unsigned int key_length,
			     const unsigned char *ctrlist,
			     unsigned int direction);

/**
 * Encrypt or decrypt data with an AES key using Output Feedback (OFB) mode as
 * described in NIST Special Publication 800-38A Chapter 6.4.
 *
 * Required HW Support
 * KMO-AES-128, KMO-AES-192 or KMO-AES-256
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that contains the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data.
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param iv
 * Pointer to a valid 16 byte initialization vector. This vector will be
 * overwritten during the function. If data_length is a multiple of the cipher
 * block size (i.e. a multiple of 16 for AES) the result value in iv may be
 * used as initialization vector for a chained ica_aes_ofb call with the same
 * key.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_ofb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, unsigned char *key,
			 unsigned int key_length, unsigned char *iv,
			 unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an AES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B. ica_aes_cmac can be used to
 * authenticate or verify the authenticity of a complete message.
 *
 * Required HW Support
 * KMAC-AES-128, KMAC-AES-192 or KMAC-AES-256
 * PCC-Compute-Last_block-CMAC-Using-AES-128,
 * PCC-Compute-Last_block-CMAC-Using-AES-192 or
 * PCC-Compute-Last_block-CMAC-Using-AES-256
 *
 * @param message
 * Pointer to a readable buffer of size greater than or equal to message_length
 * bytes. It contains a message to be authenticated or of which the
 * authenticity shall be verified.
 * @param message_length
 * Length in bytes of the message to be authenticated or verified.
 * @param mac
 * Pointer to a buffer of size greater than or equal to mac_length bytes. If
 * direction is 1 the buffer must be writable and a message authentication code
 * for the message in message of size mac_length bytes will be written to the
 * buffer. If direction is 0 the buffer must be readable and contain a message
 * authentication code that will be verified against the message in message
 * @param mac_length
 * Length in bytes of the message authentication code mac in bytes that is less
 * than or equal to the cipher block size (I.e. 16 bytes for AES). It is
 * recommended to use values greater than or equal to 8.
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param direction
 * 0 or 1:
 * 0 Verify message authentication code
 * 1 Compute message authentication code for the message
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 * EFAULT if direction is 0 and the verification of the message authentication code fails.
 */
ICA_EXPORT
unsigned int ica_aes_cmac(const unsigned char *message, unsigned long message_length,
			  unsigned char *mac, unsigned int mac_length,
			  unsigned char *key, unsigned int key_length,
			  unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an AES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B.
 * ica_aes_cmc_intermediate and ica_aes_cmac_last can be used when the message
 * to be authenticated or to be verified using CMAC is supplied in multiple
 * chunks. ica_aes_cmac_intermediate is used to process all but the last
 * chunk. All message chunks to preprocessed by ica_aes_cmac_intermediate
 * must have a size that is a multiple of the cipher block size (i.e. a
 * multiple of 16 bytes for AES).
 * Note: ica_aes_cmac_intermediate has no direction argument it can be used
 * during an authentication and during authenticity verification.
 *
 * Required HW Support
 * KMAC-AES-128, KMAC-AES-192 or KMAC-AES-256
 *
 * @param message
 * Pointer to a readable buffer of size greater than or equal to message_length
 * bytes. It contains a non final part of a message which shall be
 * authenticated or of which the authenticity shall be verified.
 * @param message_length
 * Length in bytes of the message part in message. It must be a multiple of
 * the cipher block size.
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param iv
 * Pointer to a valid  initialization vector of size cipher block size (i.e.
 * 16 bytes for AES). For the first message part it must be set to a string
 * of zeros. For processing the n-th message part it must be the resulting iv
 * value of the ica_aes_cmac_intermediate applied to the (n-1)-th message
 * part. This vector will be overwritten during the function.
 * The result value in iv may be used as initialization vector for a chained
 * call to ica_aes_cmac_initermediate or to ica_aes_cmac_last with the
 * same key.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_cmac_intermediate(const unsigned char *message,
				       unsigned long message_length,
				       unsigned char *key, unsigned int key_length,
				       unsigned char *iv);

/**
 * Authenticate data or verify the authenticity of data with an AES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as
 * described in NIST Special Publication 800-38B.
 * ica_aes_cmac_last can be used to authenticate or verify the authenticity of
 * a complete message or of the final part of a message for which all
 * preceding parts were preprocessed with ica_aes_cmac_intermediate.
 *
 * Required HW Support
 * KMAC-AES-128, KMAC-AES-192 or KMAC-AES-256
 * PCC-Compute-Last_block-CMAC-Using-AES-128,
 * PCC-Compute-Last_block-CMAC-Using-AES-192 or
 * PCC-Compute-Last_block-CMAC-Using-AES-256.
 *
 * @param message
 * Pointer to a readable buffer of size greater than or equal to message_length
 * bytes. It contains a message or the final part of a message to be
 * authenticated or of which the authenticity shall be verified.
 * @param message_length
 * Length in bytes of the message to be authenticated or verified.
 * @param mac
 * Pointer to a buffer of size greater than or equal to mac_length bytes.
 * If direction is 1 the buffer must be writable and a message authentication
 * code for the message in message of size mac_length bytes will be written to
 * the buffer.
 * If direction is 0 the buffer must be readable and contain a message
 * authentication code that will be verified against the message in message.
 * @param mac_length
 * Length in bytes of the message authentication code mac in bytes that is less
 * than or equal to the cipher block size (I.e. 16 bytes for AES). It is
 * recommended to use values greater than or equal to 8.
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param iv
 * Pointer to a valid initialization vector of size cipher block size. If iv
 * is NULL message is assumed to be the complete message to be processed.
 * Otherwise message is the final part of a composite message to be processed
 * and iv contains the output vector resulting from processing all previous
 * parts with chained calls to ica_aes_cmac_intermediate, i.e. the value
 * returned in iv of the ica_aes_cmac_intermediate call applied to the
 * penultimate message part.
 * @param direction
 * 0 or 1:
 * 0 Verify message authentication code
 * 1 Compute message authentication code for the message
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 * EFAULT if direction is 0 and the verification of the message authentication
 * code fails.
 */
ICA_EXPORT
unsigned int ica_aes_cmac_last(const unsigned char *message, unsigned long message_length,
			       unsigned char *mac, unsigned int mac_length,
			       unsigned char *key, unsigned int key_length,
			       unsigned char *iv,
			       unsigned int direction);

/**
 * Encrypt or decrypt data with an AES key using the XEX Tweakable Block Cipher
 * with Ciphertext Stealing (XTS) mode as described in NIST Special Publication
 * 800-38E and IEEE standard 1619-2007.
 *
 * Required HW Support
 * KM-XTS-AES-128 or KM-XTS-AES-256
 * PCC-Compute-XTS-Parameter-Using-AES-128 or
 * PCC-Compute-XTS-Parameter-Using-AES-256
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. The minimal value of data_length is cipher block size
 * (i.e. a multiple of 16 for AES).
 * @param key1
 * Pointer to a buffer containing a valid AES key. key1 is used for the actual
 * encryption of the message buffer combined some vector computed from the
 * tweak value (Key1 in IEEE Std 1619-2007).
 * @param key2
 * Pointer to a buffer containing a valid AES key key2 is used to encrypt the
 * tweak (Key2 in IEEE Std 1619-2007).
 * @param key_length
 * The length in bytes of the AES key. For XTS supported AES key sizes are 16
 * and 32 for AES-128 and AES-256 respectively.
 * @param tweak
 * Pointer to a valid 16 byte tweak value (as in IEEE Std 1619-2007).
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_xts(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 unsigned char *key1, unsigned char *key2,
			 unsigned int key_length, unsigned char *tweak,
			 unsigned int direction);

/**
 * Encrypt or decrypt data with an AES key using the XEX Tweakable Block Cipher
 * with Ciphertext Stealing (XTS) mode as described in NIST Special Publication
 * 800-38E and IEEE standard 1619-2007.
 * This function supports multi-part operations, whereas the ica_aes_xts
 * function supports single-part operation only.
 *
 * Required HW Support
 * KM-XTS-AES-128 or KM-XTS-AES-256
 * PCC-Compute-XTS-Parameter-Using-AES-128 or
 * PCC-Compute-XTS-Parameter-Using-AES-256
 *
 * @param in_data
 * Pointer to a readable buffer, that contains the message to be en/decrypted.
 * The size of the message in bytes is data_length. The size of this buffer in
 * bytes must be at least as big as data_length.
 * @param out_data
 * Pointer to a writable buffer, that will contain the resulting en/decrypted
 * message. The size of this buffer in bytes must be at least as big as
 * data_length.
 * @param data_length
 * Length in bytes of the message to be en/decrypted, which resides at the
 * beginning of in_data. The minimal value of data_length is cipher block size
 * (i.e. a multiple of 16 for AES).
 * For multi-part operations, data_length must be a multiple of the cipher
 * block size, unless for the final part. For the final part, the data_length
 * must be at least one full cipher block.
 * @param key1
 * Pointer to a buffer containing a valid AES key. key1 is used for the actual
 * encryption of the message buffer combined some vector computed from the
 * tweak value (Key1 in IEEE Std 1619-2007).
 * @param key2
 * Pointer to a buffer containing a valid AES key key2 is used to encrypt the
 * tweak (Key2 in IEEE Std 1619-2007).
 * @param key_length
 * The length in bytes of the AES key. For XTS supported AES key sizes are 16
 * and 32 for AES-128 and AES-256 respectively.
 * @param tweak
 * Pointer to a valid 16 byte tweak value (as in IEEE Std 1619-2007).
 * For multi-part operations the tweak must only be specified for the initial
 * part. For subsequent parts, the tweak parameter must be NULL.
 * @param iv
 * Pointer to the initialization vector to be used for multi-part operations.
 * If the tweak parameter is NULL, then the operation uses the initialization
 * vector specified with this parameter. On return the initialization vector
 * is updated with the output vector that can be used as initialization vector
 * for the next part. For single part operations, this parameter can be NULL.
 * @param direction
 * 0 or 1:
 * 0 Use the decrypt function.
 * 1 Use the encrypt function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
unsigned int ica_aes_xts_ex(const unsigned char *in_data,
			    unsigned char *out_data,
			    unsigned long data_length,
			    unsigned char *key1, unsigned char *key2,
			    unsigned int key_length, unsigned char *tweak,
			    unsigned char *iv, unsigned int direction);

/**
 * Encrypt and authenticate or decrypt data and check authenticity of data with
 * an AES key using Counter with Cipher Block Chaining Message Authentication
 * Code (CCM) mode as described in NIST Special Publication 800-38C.
 * Formatting and counter functions are implemented according to
 * NIST 800-38C Appendix A.
 *
 * Required HW Support
 * KMCTR-AES-128, KMCTR-AES-192 or KMCTR-AES-256
 * KMAC-AES-128, KMAC-AES-192 or KMAC-AES-256
 *
 * @param payload
 * Pointer to a buffer of size greater than or equal to payload_length bytes.
 * If direction equals 1 the payload buffer must be readable and contain a
 * payload message of size payload_length that will be encrypted.
 * If direction equals 0 the payload buffer must be writable. If the
 * authentication verification succeeds the decrypted message in the most
 * significant payload_length bytes of ciphertext_n_mac will be written to
 * the buffer otherwise the contents of the buffer will be undefined.
 * @param payload_length
 * Length in bytes of the message to be en/decrypted, it may be 0 unless
 * assoc_data_length is 0.
 * @param ciphertext_n_mac
 * Pointer to a buffer of size greater than or equal to payload_length plus
 * mac_length bytes.
 * If direction equals 1 then the buffer must be writable and the encrypted
 * message from payload followed by the message authentication code for the
 * nonce, the payload and associated data will be written to that buffer.
 * If direction equals 0 then the buffer is readable and contains an encrypted
 * message of length payload_length followed by a message authentication code
 * of length mac_length.
 * @param mac_length
 * Length in bytes of the message authentication code in bytes.
 * Valid values are 4, 6, 8, 10, 12, 16.
 * @param assoc_data
 * Pointer to a readable buffer of size greater than or equal to
 * assoc_data_length bytes. The associated data in the most significant
 * assoc_data_lenght bytes is subject to the authentication code computation
 * but will not be encrypted.
 * @param assoc_data_length
 * Length of the associated data in assoc_data. It may be 0 unless
 * payload_length is 0.
 * @param nonce
 * Pointer to readable buffer of size greater than or equal to nonce_length
 * bytes that contains a nonce of size nonce_length bytes.
 * @param nonce_length
 * Length of the nonce in nonce in bytes. Valid values a greater than 6 and
 * less than 14.
 * @param key
 * Pointer to a valid  AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param direction
 * 0 or 1:
 * 0 Verify message authentication code and decrypt encrypted payload.
 * 1 Encrypt payload and compute message authentication code for the nonce,
 * the associated data and the payload.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 * EFAULT if direction is 0 and the verification of the message authentication
 * code fails.
 */
ICA_EXPORT
unsigned int ica_aes_ccm(unsigned char *payload, unsigned long payload_length,
			 unsigned char *ciphertext_n_mac, unsigned int mac_length,
			 const unsigned char *assoc_data, unsigned long assoc_data_length,
			 const unsigned char *nonce, unsigned int nonce_length,
			 unsigned char *key, unsigned int key_length,
			 unsigned int direction);

/**
 * This parameter description applies to:
 * ica_aes_gcm(), ica_aes_gcm_initialize(), ica_aes_gcm_initialize_fips(),
 * ica_aes_gcm_intermediate() and ica_aes_gcm_last()
 *
 * Note for fips mode: ica_aes_gcm_initialize_fips() allows to create the iv
 * internally via an approved random source and pass it back to the
 * application via the iv parm. So here the iv is an output parm and the
 * application must provide a writable buffer of sufficient length to receive
 * the internal iv. The minimum iv_length in fips mode is 12 bytes.
 *
 * Encrypt and authenticate or decrypt data and check authenticity data with
 * an AES key using the Galois/Counter (GCM) mode as described in NIST Special
 * Publication 800-38D.
 * If no message needs to be encrypted or decrypted and only authentication or
 * authentication checks are requested then this method implements the GMAC
 * mode.
 *
 * Required HW Support
 * KM-AES-128, KM-AES-192 or KM-AES-256
 * KIMD-GHASH
 * KMCTR-AES-128, KMCTR_AES-192 or KMCTR-AES-256
 *
 * @param plaintext
 * Pointer to a buffer of size greater than or equal to plaintext_length bytes.
 * If direction equals 1 the plaintext buffer must be readable and contain a
 * payload message of size plaintext_length that will be encrypted.
 * If direction equals 0 the plaintext buffer must be writable. If the
 * authentication verification succeeds  the decrypted message in the most
 * significant plaintext_length bytes of ciphertext will be written to the
 * buffer otherwise the contents of the buffer will be undefined.
 * @param plaintext_length
 * Length in bytes of the message to be en/decrypted. It must be equal or
 * greater than 0 and less than (2^36)-32.
 * In case of intermediate operations the length must not be multiple of
 * blocksize. Padding will be done automatically. Be aware that this is only
 * useful when this is the last block.
 * @param ciphertext
 * Pointer to a buffer of size greater than or equal to plaintext_length
 * bytes.
 * If direction equals 1 then the buffer must be writable and the encrypted
 * message from plaintext will be written to that buffer.
 * If direction equals 0 then the buffer is readable and contains an encrypted
 * message of length plaintext_length.
 * @param iv
 * Pointer to a readable buffer of size greater than or equal to iv_length
 * bytes, that contains an initialization vector of size iv_length.
 * @param iv_length
 * Length in bytes of the initialization vector in iv. It must be greater
 * than 0 and less than 2^61. A length of 12 is recommended.
 * When running in fips mode, the minimum iv_length is 12 bytes.
 * @param aad
 * Pointer to a readable buffer of size greater than or equal to aad_length
 * bytes. The additional authenticated data in the most significant aad_length
 * bytes is subject to the authentication code computation but will not be
 * encrypted.
 * @param aad_length
 * Length in bytes of the additional authenticated data in aad. It must be
 * equal or greater than 0 and less than 2^61.
 * In case of ica_aes_gcm_last(), 'aad_length' contains the overall
 * length of authentication data, cumulated over all intermediate operations.
 * @param tag
 * Pointer to a buffer of size greater than or equal to tag_length bytes.
 * If direction is 1 the buffer must be writable and a message authentication
 * code for the additional authenticated data in aad and the plain text in
 * plaintext of size tag_length bytes will be written to the buffer.
 * If direction is 0 the buffer must be readable and contain a message
 * authentication code that will be verified against the additional
 * authenticated data in aad and decrypted cipher text from ciphertext.
 * In case of intermediate operations, ica_aes_gcm_intermediate() or
 * ica_aes_gcm_last(), 'tag' contains the temporary hash/tag value.
 * @param tag_length
 * Length in bytes of the message authentication code tag in bytes.
 * Valid values are 4, 8, 12, 13, 14, 15, 16.
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 * @param icb
 * initial counter block - Pointer to a writable buffer that will be created
 * during ica_aes_gcm_initialize() and will be used in ica_aes_gcm_last() for
 * the final tag computation.
 * The length of this counter block is AES_BLOCK_SIZE (16 bytes).
 * @param ucb
 * usage counter block - Pointer to a writable buffer that will be created
 * during ica_aes_gcm_initialize() and will be updated (increased) during the
 * intermediate update operations.
 * The length of this counter block is AES_BLOCK_SIZE (16 bytes).
 * @param subkey
 * Pointer to a writable buffer, generated in ica_aes_gcm_initialize() and used in
 * ica_aes_gcm_intermediate() and ica_aes_gcm_last().
 * The length of this buffer is AES_BLOCK_SIZE (16 bytes).
 * @param ciph_length
 * Length in bytes of the overall ciphertext, cumulated over all intermediate
 * operations.
 * @param final_tag
 * Pointer to a readable buffer of size greater than or equal to
 * final_tag_length bytes. If direction is 1 the buffer is not used.
 * If direction is 0 this message authentication code (tag) will be verified
 * with the computed message authentication code computed over the intermediate
 * update operations.
 * @param final_tag_length
 * Length in bytes of the final message authentication code (tag).
 * @param direction
 * 0 or 1:
 * 0 Verify message authentication code and decrypt encrypted payload.
 * 1 Encrypt payload and compute message authentication code for the additional
 * authenticated data and the payload.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 * EFAULT if direction is 0 and the verification of the message authentication
 * code fails.
 */
ICA_EXPORT
unsigned int ica_aes_gcm(unsigned char *plaintext, unsigned long plaintext_length,
			 unsigned char *ciphertext,
			 const unsigned char *iv, unsigned int iv_length,
			 const unsigned char *aad, unsigned long aad_length,
			 unsigned char *tag, unsigned int tag_length,
			 unsigned char *key, unsigned int key_length,
			 unsigned int direction);

ICA_EXPORT
unsigned int ica_aes_gcm_initialize(const unsigned char *iv,
					unsigned int iv_length,
					unsigned char *key, unsigned int key_length,
					unsigned char *icb, unsigned char *ucb,
					unsigned char *subkey, unsigned int direction);

ICA_EXPORT
unsigned int ica_aes_gcm_initialize_fips(unsigned char *iv,
		unsigned int iv_length, unsigned char *key, unsigned int key_length,
		unsigned char *icb, unsigned char *ucb, unsigned char *subkey,
		unsigned int direction);

ICA_EXPORT
unsigned int ica_aes_gcm_intermediate(unsigned char *plaintext,
					unsigned long plaintext_length, unsigned char *ciphertext,
					unsigned char *ucb,
					unsigned char *aad, unsigned long aad_length,
					unsigned char *tag, unsigned int tag_length,
					unsigned char *key, unsigned int key_length,
					unsigned char *subkey, unsigned int direction);

ICA_EXPORT
unsigned int ica_aes_gcm_last(unsigned char *icb, unsigned long aad_length,
					unsigned long ciph_length, unsigned char *tag,
					unsigned char *final_tag, unsigned int final_tag_length,
					unsigned char *key, unsigned int key_length,
					unsigned char *subkey, unsigned int direction);

/*******************************************************************************
 *
 *                       New gcm API based on KMA.
 */


typedef struct kma_ctx_t kma_ctx;

/**
 * Allocate a gcm context. This context is used by ica_aes_gcm_kma_init(),
 * ica_aes_gcm_kma_update(), ica_aes_gcm_kma_get_tag(), and
 * ica_aes_gcm_kma_verify_tag(). It must be freed by
 * ica_aes_gcm_kma_ctx_free() when no longer needed.
 *
 * @return Pointer to opaque kma_ctx structure if success.
 * NULL if no memory could be allocated.
 */
ICA_EXPORT
kma_ctx* ica_aes_gcm_kma_ctx_new();

/**
 * Initialize the GCM context.
 *
 * @param direction
 * 0 or 1:
 * 0 when initialized for decryption.
 * 1 when initialized for encryption.
 *
 * @param iv
 * Pointer to a readable buffer of size greater than or equal to iv_length
 * bytes, that contains an initialization vector of size iv_length.
 * The pointer may alternatively be NULL, in which case the iv is created
 * internally via an approved random source. The iv can then be obtained via
 * API function ica_aes_gcm_kma_get_iv. This is intended to be used in fips
 * mode, where an external iv is not allowed, but can also be used in non-fips
 * mode for increased security. The internal iv in the context is not changed
 * by subsequent crypto operations. It can be safely obtained even after
 * intermediate and last operations have been performed.
 *
 * @param iv_length
 * Length in bytes of the initialization vector in iv. It must be greater
 * than 0 and less than 2^61. A length of 12 is recommended.
 * When running in fips mode, the minimum iv_length is 12 bytes.
 *
 * @param key
 * Pointer to a valid AES key.
 *
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
 *
 * @param ctx
 * Pointer to a previously allocated gcm context. This buffer is internally used
 * as a working area by all other ica_aes_gcm_kma API functions and must not be
 * changed by the application. The ctx must be established by calling ica_aes_gcm_ctx_new()
 * before any call to any other ica_aes_gcm_kma function, and must be freed by calling
 * ica_aes_gcm_ctx_free() after the last call to any ica_aes_gcm_kma function.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
int ica_aes_gcm_kma_init(unsigned int direction,
					const unsigned char *iv, unsigned int iv_length,
					const unsigned char *key, unsigned int key_length,
					kma_ctx* ctx);

/**
 * Perform encryption or decryption with authentication, depending on the
 * direction specified in ica_aes_gcm_kma_init().
 *
 * @param in_data
 * Pointer to a readable buffer of size greater than or equal to data_length bytes.
 * If direction equals 1 the in_data must contain a payload message of size
 * data_length that will be encrypted and authenticated.
 * If direction equals 0 the in_data buffer must contain an encrypted message
 * that will be decrypted and verified.
 *
 * @param out_data
 * Pointer to a writable buffer of size greater than or equal to data_length bytes.
 * If direction equals 1 then the encrypted message from in_data will be written to
 * that buffer.
 * If direction equals 0 then the decrypted message from in_data will be written to
 * that buffer.
 *
 * @param data_length
 * Length in bytes of the message to be en/decrypted. It must be equal or
 * greater than 0 and less than (2^36)-32.
 *
 * @param aad
 * Pointer to a readable buffer of size greater than or equal to aad_length
 * bytes. The additional authenticated data in the most significant aad_length
 * bytes is subject to the authentication code computation but will not be
 * encrypted.
 *
 * @param aad_length
 * Length in bytes of the additional authenticated data in aad. It must be
 * equal or greater than 0 and less than 2^61.
 * In case of ica_aes_gcm_last(), 'aad_length' contains the overall
 * length of authentication data, cumulated over all intermediate operations.
 *
 * @param end_of_aad
 * 0 or 1:
 * 0 The application indicates that the current aad is not the last aad chunk. In
 * this case, the aad_length must be a multiple of the AES block size (16 bytes).
 * 1 The application indicates that the current aad is a single or last aad chunk,
 * or the last aad chunk has been provided in an earlier call to ica_aes_gcm_kma.
 * In this case, aad_length can have any non-negative value.
 * When both, end_of_aad and end_of_data are specified, the process ends.
 *
 * @param end_of_data
 * 0 or 1:
 * 0 The application indicates that the current in_data is not the last in_data chunk.
 * In this case, the data_length must be a multiple of the AES block size (16 bytes).
 * 1 The application indicates that the current in_data is a single or last in_data
 * chunk. In this case, aad_length can have any non-negative value. When both, end_of_aad
 * and end_of_data are specified, the process ends.
 *
 * @param ctx
 * Pointer to gcm context.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given.
 * EPERM if required hardware support is not available.
 * EIO if the operation fails.
 */
ICA_EXPORT
int ica_aes_gcm_kma_update(const unsigned char *in_data,
		unsigned char *out_data, unsigned long data_length,
		const unsigned char *aad, unsigned long aad_length,
		unsigned int end_of_aad, unsigned int end_of_data,
		kma_ctx* ctx);

/**
 * Obtain the calculated authentication tag after an encryption process.
 *
 * @param tag
 * Pointer to a writable buffer to return the calculated authentication tag.
 *
 * @param tag_length
 * Length in bytes of the message authentication code tag. Valid tag lengths
 * are 4, 8, 12, 13, 14, 15, and 16.
 *
 * @param ctx
 * Pointer to gcm context.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given
 * EFAULT if direction is 0.
 */
ICA_EXPORT
int ica_aes_gcm_kma_get_tag(unsigned char *tag, unsigned int tag_length,
		const kma_ctx* ctx);

/**
 * Verify if the specified known authentication tag is identical to the
 * calculated tag after a decryption process.
 *
 * @param known_tag
 * Pointer to a readable buffer containing a known authentication tag.
 *
 * @param tag_length
 * Length in bytes of the message authentication code tag. Valid tag lengths
 * are 4, 8, 12, 13, 14, 15, and 16.
 *
 * @param ctx
 * Pointer to gcm context.
 *
 * @return 0 on success
 * EINVAL if at least one invalid parameter is given or direction is 1.
 * EFAULT if the verification of the message authentication code fails.
 */
ICA_EXPORT
int ica_aes_gcm_kma_verify_tag(const unsigned char* known_tag, unsigned int tag_length,
		const kma_ctx* ctx);

/**
 * Obtain the iv from the given context. This function is mainly intended to
 * allow applications to query an internally created iv when running in fips
 * mode, but can also be used in non-fips mode. When encrypting, FIPS requires
 * the internal creation of the iv via an approved random source. The internal
 * iv can then be queried for use at decryption.
 *
 * @param ctx
 * Pointer to gcm context.
 *
 * @param iv
 * A writable buffer large enough to receive the iv from given ctx. Specifying
 * NULL queries the size of the internal iv. The size is then returned in
 * parameter *iv_length.
 *
 * @param iv_length
 * A pointer to an unsigned integer buffer indicating the size of the application
 * provided buffer to receive the internal iv from the ctx.
 *
 * @return 0 on success
 * EINVAL if the ctx is NULL.
 * ENOMEM if *iv_length is too small to receive the internal iv.
 */
ICA_EXPORT
int ica_aes_gcm_kma_get_iv(const kma_ctx* ctx, unsigned char *iv, unsigned int *iv_length);

/**
 * Free gcm context.
 *
 * @param ctx
 * Pointer to gcm context.
 */
ICA_EXPORT
void ica_aes_gcm_kma_ctx_free(kma_ctx* ctx);


 /**
  *
  *             End of new gcm API based on KMA.
  *
  ******************************************************************************/

/**
 * Return processor's highest message security assist (MSA) level.
 *
 * Refer to IBM Z Principles of Operation for details about MSA levels.
 *
 * @return 0 if msa level could not determined successfully
 *         >0 msa level according to Principles of Operation
 */
ICA_EXPORT
int ica_get_msa_level(void);

/**
 * Return libica version information.
 * @param version_info
 * Pointer to a libica_version_info structure. The structure will be
 * filled with the current libica version information.
 *
 * @return 0 if version could be determined successfully
 *         EIO if version could not be determined
 *         EINVAL if parameter version_info is NULL
 */
ICA_EXPORT
unsigned int ica_get_version(libica_version_info *version_info);

/**
 * Function that returns a list of crypto mechanisms supported by libica.
 * @param pmech_list
 *    Pointer to an array of libica_func_list_element
 *    If NULL, the API will return the number of elements to allocate
 *    in the @mech_list_len parameter.
 *    If not NULL, libica will assume @mech_list is an array that has
 *    @num elements.
 *    On success, @mech_list will be filled out with the supported libica
 *    crypto mechanisms.
 * @param pmech_list_len
 *    number of list entries
 *    On input, pointer to the number of elements allocated in the
 *    @mech_list array.
 *    On output, @mech_list_len will contain the number of items copied to
 *    the @mech_list array, or the number of items libica would have returned
 *    in case the @mech_list parameter is set to NULL.
 * @return
 *    0 on success
 *    EINVAL if at least one invalid parameter is given
 *
 *   A typical usage scenario would be that an exploiter makes a first call to
 *   ica_get_functionlist() with @mech_list set to NULL in order to determine
 *   the number of elements to allocate. This is followed by a second call to
 *   ica_get_functionlist() with a valid pointer @list to an array of
 *   libica_func_list_element structures with @mech_list_len elements.
 */
ICA_EXPORT
unsigned int ica_get_functionlist(libica_func_list_element *pmech_list,
					unsigned int *pmech_list_len);

static inline unsigned int des_directed_fc(int direction)
{
	if (direction)
		return DEA_ENCRYPT;
	return DEA_DECRYPT;
}

static inline unsigned int tdes_directed_fc(int direction)
{
	if (direction)
		return TDEA_192_ENCRYPT;
	return TDEA_192_DECRYPT;
}

static inline unsigned int aes_directed_fc(unsigned int key_length, int direction)
{
	switch (key_length) {
	case AES_KEY_LEN128:
		return (direction == ICA_DECRYPT) ?
			AES_128_DECRYPT : AES_128_ENCRYPT;
	case AES_KEY_LEN192:
		return (direction == ICA_DECRYPT) ?
			AES_192_DECRYPT : AES_192_ENCRYPT;
	case AES_KEY_LEN256:
		return (direction == ICA_DECRYPT) ?
			AES_256_DECRYPT : AES_256_ENCRYPT;
	}
	return 0;
}

/*
 * ica_drbg: libica's Deterministic Random Bit Generator
 *	     (conforming to NIST SP 800-90A)
 *
 * Table of currently supported DRBG mechanisms:
 *
 * DRBG mechanism	supported security	max. byte length
 *			  strengths (bits)	   of pers / add
 * -------------------------------------------------------------
 * DRBG_SHA512		112, 128, 196, 256	       256 / 256
 *
 * An ica_drbg_t object holds the internal state of a DRBG instantiation. A
 * DRBG instantiation is identified by an associated ica_drbg_t * pointer
 * (state handle).
 * State handles that do not identify any DRBG instantiation SHALL be NULL
 * (invalid). Therefore a new state handle SHALL be initialized to NULL.
 *
 * If a catastrophic error (<0) is detected, all existing DRBG instantiations
 * of the corresponding mechanism are in error state making uninstantiation
 * their only permitted operation. Creation of new DRBG instantiations of
 * this mechanism are not permitted.
 */
ICA_EXPORT
extern ica_drbg_mech_t *const ICA_DRBG_SHA512;


/*
 * Instantiate function
 * (create a new DRBG instantiation)
 *
 * @sh: State Handle pointer. The (invalid) state handle is set to identify the
 * new DRBG instantiation and thus becomes valid.
 * @sec: requested instantiation SECurity strength (bits). The new DRBG
 * instantiation's security strength is set to the lowest security strength
 * supported by it's DRBG mechanism (see table) that is greater than or equal
 * to @sec.
 * @pr: Prediction Resistance flag. Indicates whether or not prediction
 * resistance may be required by the consuming application during one or more
 * requests for pseudorandom bytes.
 * @mech: MECHanism. The new DRBG instantiation is of this mechanism type.
 * @pers: PERSonalization string. An optional input that provides
 * personalization information. The personalisation string SHALL be unique for
 * all instantiations of the same mechanism type. NULL indicates that no
 * personalization string is used (not recommended).
 * @pers_len: Byte length of @pers.
 *
 * @return:
 * 0				Success.
 * ENOMEM			Out of memory.
 * EINVAL			At least one argument is invalid.
 * ENOTSUP			Prediction resistance or the requested security
 *				strength is not supported.
 * EPERM			Failed to obtain a valid timestamp from clock.
 * ICA_DRBG_HEALTH_TEST_FAIL	Health test failed.
 * ICA_DRBG_ENTROPY_SOURCE_FAIL	Entropy source failed.
 */
ICA_EXPORT
int ica_drbg_instantiate(ica_drbg_t **sh,
			 int sec,
			 bool pr,
			 ica_drbg_mech_t *mech,
			 const unsigned char *pers,
			 size_t pers_len);

/*
 * Reseed function
 * (reseed a DRBG instantiation)
 *
 * @sh: State Handle. Identifies the DRBG instantiation to be reseeded.
 * @pr: Prediction Resistance request. Indicates whether or not prediction
 * resistance is required.
 * @add: ADDitional input: An optional input. NULL indicates that no additional
 * input is used.
 * @add_len: Byte length of @add.
 *
 * @return:
 * 0				Success.
 * ENOMEM			Out of memory.
 * EINVAL			At least one argument is invalid.
 * ENOTSUP			Prediction resistance is not supported.
 * ICA_DRBG_HEALTH_TEST_FAIL	Health test failed.
 * ICA_DRBG_ENTROPY_SOURCE_FAIL	Entropy source failed.
 */
ICA_EXPORT
int ica_drbg_reseed(ica_drbg_t *sh,
		    bool pr,
		    const unsigned char *add,
		    size_t add_len);
/*
 * Generate function
 * (request pseudorandom bytes from a DRBG instantiation)
 *
 * @sh: State Handle. Identifies the DRBG instantiation from which pseudorandom
 * bytes are requested.
 * @sec: requested SECurity strength: Minimum bits of security that the
 * generated pseudorandom bytes SHALL offer.
 * @pr: Prediction Resistance request. Indicates whether or not prediction
 * resistance is required.
 * @add: ADDitional input. An optional input. NULL indicates that no additional input
 * is used.
 * @add_len: Byte length of @add.
 * @prnd: PseudoRaNDom bytes.
 * @prnd_len: Byte length of @prnd. Requested number of pseudorandom bytes.
 *
 * @return:
 * 0				Success.
 * ENOMEM			Out of memory.
 * EINVAL			At least one argument is invalid.
 * ENOTSUP			Prediction resistance or the requested security
 *				strength is not supported.
 * EPERM			Reseed required.
 * ICA_DRBG_HEALTH_TEST_FAIL	Health test failed.
 * ICA_DRBG_ENTROPY_SOURCE_FAIL	Entropy source failed.
 */
ICA_EXPORT
int ica_drbg_generate(ica_drbg_t *sh,
		      int sec,
		      bool pr,
		      const unsigned char *add,
		      size_t add_len,
		      unsigned char *prnd,
		      size_t prnd_len);

/*
 * Uninstantiate function
 * (destroy an existing DRBG instantiation)
 *
 * @sh: State Handle pointer. The corresponding DRBG instantiation is destroyed
 * and the state handle is set to NULL (invalid).
 *
 * @return:
 * 0				Success.
 * EINVAL			At least one argument is invalid.
 */
ICA_EXPORT
int ica_drbg_uninstantiate(ica_drbg_t **sh);

/*
 * Health test function
 * (run health test for a DRBG mechanism function)
 *
 * @func: FUNCtion. Pointer indicating which function should be tested. Options
 * are "ica_drbg_instantiate", "ica_drbg_reseed" and "ica_drbg_generate". The
 * uninstantiate function is tested whenever other functions are tested.
 * @sec: SECurity strength. Argument for the call to @func.
 * @pr: PRediction resistance. Argument for the call to @func.
 * @mech: MECHanism. The mechanism to be tested.
 *
 * @return:
 * 0				Success.
 * EINVAL			At least one argument is invalid.
 * ENOTSUP			Prediction resistance or security strength is
 *				not supported (when testing instantiate).
 * ICA_DRBG_HEALTH_TEST_FAIL	Health test failed.
 * ICA_DRBG_ENTROPY_SOURCE_FAIL	Entropy source failed.
 */
ICA_EXPORT
int ica_drbg_health_test(void *func,
			 int sec,
			 bool pr,
			 ica_drbg_mech_t *mech);

/*
 * ica_mp: libica's multiple-precision arithmetic interface
 *
 * Numbers are represented in radix 2^64. The least-significant digit is stored
 * at array element zero.
 *
 * Example:
 *
 * uint64_t a[] = {3, 4, 5};	// a = 5*(2^64)^2 + 4*(2^64) + 3
 */

/*
 * Multiply the zero-padded 512-bit numbers @a and @b. The zero-padded 1024-bit
 * result is stored at @r.
 *
 * @r: 1024-bit produkt (@r = @a * @b)
 * @a:  512-bit factor 1
 * @b:  512-bit factor 2
 *
 * @return:
 * 0				Success.
 * != 0				Vector facilities are not enabled.
 */
ICA_EXPORT
int ica_mp_mul512(uint64_t r[16], const uint64_t a[8], const uint64_t b[8]);

/*
 * Square the zero-padded 512-bit number @a. The zero-padded 1024-bit result is
 * stored at @r.
 *
 * @r: 1024-bit square (@r = @a ^ 2)
 * @a:  512-bit base
 *
 * @return:
 * 0				Success.
 * != 0				Vector facilities are not enabled.
 */
ICA_EXPORT
int ica_mp_sqr512(uint64_t r[16], const uint64_t a[8]);

/*
 * FIPS status output interface.
 *
 * @return:
 * Returns flags indicating the module status. See the ICA_FIPS_* flags.
 */
ICA_EXPORT
int ica_fips_status(void);

#ifdef ICA_FIPS
/*
 * Additional FIPS interfaces are available for built-in FIPS mode.
 */

/*
 * FIPS powerups tests.
 *
 * The test results can be viewed via the ica_fips_status function.
 */
ICA_EXPORT
void ica_fips_powerup_tests(void);
#endif /* ICA_FIPS */

/*
 * Cleanup ICA resources. Should be called before the application terminates,
 * or the libica library is unloaded.
 *
 */
ICA_EXPORT
void ica_cleanup(void);

#endif /* __ICA_API_H__ */

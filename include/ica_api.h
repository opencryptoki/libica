/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001,2005,2009    */

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

#include <stdint.h>

#define ica_adapter_handle_t int
typedef ica_adapter_handle_t ICA_ADAPTER_HANDLE;

/**
 * @deprecated.
 * RSA key generation options - public exponent types
 * These are used to tell deprecated functions:
 * - icaRsaKeyGenerateModExpo
 * - icaRsaKeyGenerateCrt
 * which public exponent to take. They are not used within the new API functions. 
 */
#define RSA_PUBLIC_RANDOM 0
#define RSA_PUBLIC_3      1
#define RSA_PUBLIC_65537  2
#define RSA_PUBLIC_FIXED  3

/**
 * @deprecated exponent types. These have been used internally only. They are
 * not used at all, now.
 */
#define  RSA_EXPONENT_RANDOM      1
#define  RSA_EXPONENT_3           2
#define  RSA_EXPONENT_65537       3
#define  RSA_EXPONENT_2           4
#define  RSA_EXPONENT_FIXED       5

/**
 * @deprecated RSA key token types
 */
#define RSA_PRIVATE_CHINESE_REMAINDER		1
#define RSA_PRIVATE_MODULUS_EXPONENT		2
#define RSA_PUBLIC_MODULUS_EXPONENT		3
#define RSA_X931_PRIVATE_CHINESE_REMAINDER	4
#define RSA_X931_PRIVATE_MODULUS_EXPONENT	5
#define RSA_PKCS_PRIVATE_CHINESE_REMAINDER	6
#define RSA_PKCS_X931_PRIVATE_CHINESE_REMAINDER	7
#define KEYTYPE_MODEXPO				1
#define KEYTYPE_PKCSCRT				2

/**
 * Symetric encryption/decryption modes ECB & CBC
 */
#define MODE_ECB 		1
#define MODE_CBC 		2

/**
 * @deprecated
 * Use MODE_ECB, MODE_CBC instead.
 */
#define MODE_DES_ECB		MODE_ECB
#define MODE_DES_CBC		MODE_CBC
#define MODE_AES_ECB		MODE_ECB
#define MODE_AES_CBC		MODE_CBC

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

/**
 * @deprecated
 * Do not use LENGTH_SHA_HASH, LENGTH_SHA224_HASH, LENGTH_SHA256_HASH,
 * LENGTH_SHA384_HASH, LENGTH_SHA512_HASH anymore!
 *
 * Use SHA_HASH_LENGTH, SHA224_HASH_LENGTH, SHA256_HASH_LENGTH,
 * SHA384_HASH_LENGTH, SHA512_HASH_LENGTH instead.
 */
#define LENGTH_SHA_HASH		SHA_HASH_LENGTH	
#define LENGTH_SHA224_HASH	SHA224_HASH_LENGTH	
#define LENGTH_SHA256_HASH	SHA256_HASH_LENGTH	
#define LENGTH_SHA384_HASH	SHA384_HASH_LENGTH	
#define LENGTH_SHA512_HASH	SHA512_HASH_LENGTH

/**
 * @deprecated
 * ICA_CALL is unneccessary. Do not use it anymore.
 */
#define ICA_CALL

/**
 * Context for SHA1 operations
 */
typedef struct {
	uint64_t runningLength;
	unsigned char shaHash[LENGTH_SHA_HASH];
} sha_context_t;
/**
 * @deprecated
 */
typedef sha_context_t SHA_CONTEXT;
#define LENGTH_SHA_CONTEXT	sizeof(sha_context_t)

/**
 * Context for SHA256 and SHA128 operations
 */
typedef struct {
	uint64_t runningLength;
	unsigned char sha256Hash[LENGTH_SHA256_HASH];
} sha256_context_t;
/**
 * @deprecated
 */
typedef sha256_context_t SHA256_CONTEXT;
#define LENGTH_SHA256_CONTEXT	sizeof(sha256_context_t)

/**
 * Context for SHA512 and SHA384 operations
 */
typedef struct {
	uint64_t runningLengthHigh;
	uint64_t runningLengthLow;
	unsigned char sha512Hash[LENGTH_SHA512_HASH];
} sha512_context_t;
/**
 * @deprecated
 */
typedef sha512_context_t SHA512_CONTEXT;
#define LENGTH_SHA512_CONTEXT	sizeof(sha512_context_t)

/**
 * @deprecated
 * MAX_EXP_SIZE, MAX_MODULUS_SIZE, MAX_MODEXP_SIZE, MAX_OPERAND_SIZE
 * are no longer needed. These values will be deleted with the next update.
 *
 * All data elements of the RSA key are in big-endian format
 * Modulus-Exponent form of key
 */
#define MAX_EXP_SIZE		256
#define MAX_MODULUS_SIZE	256
#define MAX_MODEXP_SIZE		(MAX_EXP_SIZE + MAX_MODULUS_SIZE)
#define MAX_OPERAND_SIZE	MAX_EXP_SIZE
 /**
 *
 *    _             ___________  <-base address + MAX_EXP_SIZE
 *    |
 *    |
 *    |
 *    |
 * MAX_EXPO_SIZE
 *    |              Modulus
 *    |             ----------  <-base address + sizeof(exponent)
 *    |
 *    |              Exponent
 *    _             ___________ <-base address of key
 *
 *   The Exponent and Modulus lengths are multiples of 32 bytes.
 *
 */

/**
 * @deprecated
 */
typedef unsigned char ICA_KEY_RSA_MODEXPO_REC[MAX_MODEXP_SIZE];
/**
 * @deprecated MAX_BP_SIZE, MAX_BQ_SIZE, MAX_NP_SIZE, MAX_NQ_SIZE,
 * MAX_QINV_SIZE, MAX_RSACRT_SIZE, RSA_GEN_OPERAND_MAX are no longer needed
 * and will be deleted with the next update.
 *
 * All data elements of the RSA key are in big-endian format
 * Chinese Remainder Theorem(CRT) form of key
 * Used only for Decrypt, the encrypt form is typically Modulus-Exponent
 */
#define MAX_BP_SIZE		136
#define MAX_BQ_SIZE		128
#define MAX_NP_SIZE		136
#define MAX_NQ_SIZE		128
#define MAX_QINV_SIZE		136
#define MAX_RSACRT_SIZE (MAX_BP_SIZE+MAX_BQ_SIZE+MAX_NP_SIZE+MAX_NQ_SIZE+MAX_QINV_SIZE)
#define RSA_GEN_OPERAND_MAX	256	/* bytes */
 /**
 *
 *    _             ___________  <-base address + MAX_RSACRT_SIZE
 *    |
 *    |              QINV(U)
 *    |             ----------  <-base address + sizeof(Bp)+sizeof(Bq)+sizeof(Np)+sizeof(Nq)
 *    |              Nq
 *    |             ----------  <-base address + sizeof(Bp)+sizeof(Bq)+sizeof(Np)
 *    |              Np
 *    |             ----------  <-base address + sizeof(Bp)+sizeof(Bq)
 * MAX_RSACRT_SIZE
 *    |              Bq
 *    |             ----------  <-base address + sizeofBp)
 *    |              Bp
 *    _             ___________ <-base address of key
 *
 *
 */

/**
 * @deprecated
 */
typedef unsigned char ICA_KEY_RSA_CRT_REC[MAX_RSACRT_SIZE];

/**
 * @deprecated
 */
/**
 * struct ICA_KEY_RSA_MODEXPO:
 */
typedef struct _ICA_KEY_RSA_MODEXPO {
	unsigned int keyType;	/* RSA key type.               */
	unsigned int keyLength;	/* Total length of the token.  */
	unsigned int modulusBitLength;	/* Modulus n bit length.       */
	/* -- Start of the data length. */
	unsigned int nLength;	/* Modulus n = p * q           */
	unsigned int expLength;	/* exponent (public or private) */
	/*   e = 1/d * mod(p-1)(q-1)   */
	/* -- Start of the data offsets */
	unsigned int nOffset;	/* Modulus n .                 */
	unsigned int expOffset;	/* exponent (public or private) */
	unsigned char reserved[112];	/* reserved area               */
	/* -- Start of the variable -- */
	/* -- length token data.    -- */
	ICA_KEY_RSA_MODEXPO_REC keyRecord;
} ICA_KEY_RSA_MODEXPO;
#define SZ_HEADER_MODEXPO (7 * sizeof(unsigned int) + 112);

/**
 * @deprecated
 */
/**
 * struct ICA_KEY_RSA_CRT:
 */
typedef struct _ICA_KEY_RSA_CRT {
	unsigned int keyType;	/* RSA key type.               */
	unsigned int keyLength;	/* Total length of the token.  */
	unsigned int modulusBitLength;	/* Modulus n bit length.       */
	unsigned int pLength;	/* Prime number p .            */
	unsigned int qLength;	/* Prime number q .            */
	unsigned int dpLength;	/* dp = d * mod(p-1) .         */
	unsigned int dqLength;	/* dq = d * mod(q-1) .         */
	unsigned int qInvLength;	/* PKCS: qInv = Ap/q           */
	/* -- Start of the data offsets */
	unsigned int pOffset;	/* Prime number p .            */
	unsigned int qOffset;	/* Prime number q .            */
	unsigned int dpOffset;	/* dp .                        */
	unsigned int dqOffset;	/* dq .                        */
	unsigned int qInvOffset;	/* qInv for PKCS               */
	unsigned char reserved[88];	/* reserved area               */
	/* -- Start of the variable -- */
	/* -- length token data.    -- */
	ICA_KEY_RSA_CRT_REC keyRecord;
} ICA_KEY_RSA_CRT;
#define SZ_HEADER_CRT (13 * sizeof(unsigned int) + 88)

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
#define ica_aes_key_t ica_key_t

/**
 * @deprecated
 * Deprecated typedefs: Use the new ones instead.
 * ICA_DES_VECTOR, ICA_KEY_DES_SINGLE, ICA_KEY_DES_TRIPLE, ICA_AES_VECTOR,
 * ICA_KEY_AES_SINGLE, ICA_KEY_AES_LEN128, ICA_KEY_AES_LEN192,
 * ICA_KEY_AES_LEN256
 * They will be deleted with the next update.
 */
typedef ica_des_vector_t ICA_DES_VECTOR;
typedef ica_des_key_single_t ICA_KEY_DES_SINGLE;
typedef ica_des_key_triple_t ICA_KEY_DES_TRIPLE;
typedef ica_aes_vector_t ICA_AES_VECTOR;
typedef ica_aes_key_single_t ICA_KEY_AES_SINGLE;
typedef ica_aes_key_len_128_t ICA_KEY_AES_LEN128;
typedef ica_aes_key_len_192_t ICA_KEY_AES_LEN192;
typedef ica_aes_key_len_256_t ICA_KEY_AES_LEN256;

/*
 * OLD & DEPRECATED FUNCTION PROTOTYPES
 *
 * Do not use them anylonger! Use the new functions instead!
 * Deprecated function prototypes will be removed with the next version.
 *
 */

/**
 * @deprecated Opens the specified adapter. Use ica_open_adapter() instead.
 * @param adapter_id
 * The adapter number. Can be anything. Is not needed anymore.
 * @param adapter_handle
 * Pointer to the file descriptor
 *
 * @see ica_open_adapter()
 * @return 0 as long as a valid parameter is given,
 * EINVAL for invalid parameter.
 */
__attribute__ ((__deprecated__))
unsigned int icaOpenAdapter(unsigned int adapter_id,
			    ica_adapter_handle_t *adapter_handle);

/**
 * @deprecated Closes a device handle. Usa ica_close_adapter() instead.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 *
 * @see ica_close_adapter()
 * @return 0 if successful.
 * errno of close() if unsuccessful
 */
__attribute__ ((__deprecated__))
unsigned int icaCloseAdapter(ica_adapter_handle_t adapter_handle);

/**
 * @deprecated Use ica_rsa_mod_expo() instead.
 * @see ica_rsa_mod_expo()
 * @brief Perform a RSA encryption/decryption operation using a key in
 * modulus/exponent form.
 *
 * Make sure your message is padded before using this function. Otherwise you
 * will risk security!
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param input_length
 * The byte length of the input data and must be 1 to 256 inclusive.
 * @param input_data
 * Pointer to input data to be encrypted/decrypted and is in big endian format.
 * Make sure input data is not longer than bit length of the key! Byte length
 * has to be the same. Thus right justify input data inside the data block.
 * @param rsa_key Pointer to the key to be used, in modulus/exponent format.
 * @param output_length
 * On input it contains the byte length of output_data and must be as large as
 * the modulus byte length. On output it contains the actual byte length of
 * output_data.
 * @param output_data
 * Pointer to where the output results are to be placed.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * ENOMEM if memory allocation fails.
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaRsaModExpo(ica_adapter_handle_t adapter_handle,
			   unsigned int input_length,
			   unsigned char *input_data,
			   ICA_KEY_RSA_MODEXPO *rsa_key,
			   unsigned int *output_length,
			   unsigned char *output_data);

/**
 * @deprecated Use ica_rsa_crt() instead
 * @see ica_rsa_crt()
 * @brief Perform a RSA encryption/decryption operation using a key in CRT
 *	  form.
 *
 * Make sure your message is padded before using this function. Otherwise you
 * will risk security!
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param input_length
 * The byte length of the input data and must be 1 to 256 inclusive.
 * @param input_data
 * Pointer to input data to be encrypted/decrypted and is in big endian format.
 * Make sure input data is not longer than bit length of the key! Byte length
 * has to be the same. Thus right justify input data inside the data block.
 * @param rsa_key
 * Pointer to the key to be used, in CRT format.
 * @param output_length
 * On input it contains the byte length of output_data and must be as large as
 * the modulus byte length. On output it contains the actual byte length of
 * output_data.
 * @param output_data
 * Pointer to where the output results are to be placed.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * ENOMEM if memory allocation fails.
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaRsaCrt(ica_adapter_handle_t adapter_handle,
		       unsigned int input_length,
		       unsigned char *input_data,
		       ICA_KEY_RSA_CRT *rsa_key,
		       unsigned int *output_length,
		       unsigned char *output_data);

/**
 * @deprecated Use ica_rsa_key_gnerate_mod_expo() instead.
 * @see ica_rsa_key_gnerate_mod_expo()
 * Generate RSA keys in modulus/exponent format.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param modulus_bit_length
 * Specifies the bit length of the modulus.
 * @param public_exponent_type
 * Specifies the type of the public exponent and should be one of the
 * following:
 * 	0 - Full random public exponent
 *	1 - Fixed value 3 public exponent
 *	2 - Fixed value 65537 public exponent
 * @param public_key_length
 * On input is the length of the public_key buffer. On output contains the
 * actual length of the generated public key.
 * @param public_key
 * Pointer to where the generated public key is to be placed.
 * @param private_key_length
 * On input it contains the byte length of private_key. On output it contains
 * the actual length of the generated private key.
 * @param private_key
 * Pointer to where the generated private key is to be placed.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * errno of OpenSSL key generation if it should fail.
 */
__attribute__ ((__deprecated__))
unsigned int icaRsaKeyGenerateModExpo(ica_adapter_handle_t adapter_handle,
				      unsigned int modulus_bit_length,
				      unsigned int public_exponent_type,
				      unsigned int *public_key_length,
				      ICA_KEY_RSA_MODEXPO *public_key,
				      unsigned int *private_key_length,
				      ICA_KEY_RSA_MODEXPO *private_key);

/**
 * @deprecated Use ica_rsa_key_generate_crt() instead
 * Generate RSA keys in CRT format.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param modulus_bit_length
 * Specifies the bit length of the modulus.
 * @param public_exponent_type
 * Specifies the type of the public exponent and should be one of the
 * following:
 * 	0 - Full random public exponent
 *	1 - Fixed value 3 public exponent
 *	2 - Fixed value 65537 public exponent
 * @param public_key_length
 * On input is the length of the public_key buffer. On output contains the
 * actual length of the generated public key.
 * @param public_key
 * Pointer to where the generated public key is to be placed.
 * @param private_key_length
 * On input it contains the byte length of private_key. On output it contains
 * the actual length of the generated private key.
 * @param private_key
 * Pointer to where the generated private key is to be placed.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * errno of OpenSSL key generation if it should fail.
 */
__attribute__ ((__deprecated__))
unsigned int icaRsaKeyGenerateCrt(ica_adapter_handle_t adapter_handle,
				  unsigned int modulus_bit_length,
				  unsigned int public_exponent_type,
				  unsigned int *public_key_length,
				  ICA_KEY_RSA_MODEXPO *public_key,
				  unsigned int *private_key_length,
				  ICA_KEY_RSA_CRT *private_key);

/**
 * @deprecated use ica_des_encrypt() instead.
 * @see ica_des_encrypt()
 * Encrypt data using a single length DES key.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param mode
 * Specifies the operational mode and must be:
 *	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. Must be a mutiple of the cipher
 * block.
 * @param input_data
 * Pointer to the input data data to be encrypted.
 * @param iv
 * Pointer to a valid 8 byte initialization vector.
 * @param des_key
 * Pointer to a single length DES key.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be as large
 * as data_length. On output it contains the actual byte length of the data
 * returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting encrypted data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaDesEncrypt(ica_adapter_handle_t adapter_handle,
			   unsigned int mode,
	      		   unsigned int data_length,
	      		   unsigned char *input_data,
	      		   ica_des_vector_t *iv,
	      		   ica_des_key_single_t *des_key,
	      		   unsigned int *output_length,
			   unsigned char *output_data);


/**
 * @deprecated Use ica_des_decrypt() instead.
 * @see ica_des_decrypt()
 * Decrypt data using a single length DES key.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param mode
 * Specifies the operational mode and must be:
 * 	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. Must be a mutiple of the cipher
 * block.
 * @param input_data
 * Pointer to the input data data to be decrypted.
 * @param iv
 * Pointer to a valid 8 byte initialization vector.
 * @param des_key
 * Pointer to a single length DES key.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be as large
 * as data_length. On output it contains the actual byte length of the data
 * returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting decrypted data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaDesDecrypt(ica_adapter_handle_t adapter_handle,
			   unsigned int mode,
	      		   unsigned int data_length,
	      		   unsigned char *input_data,
	      		   ica_des_vector_t *iv,
	      		   ica_des_key_single_t *des_key,
	      		   unsigned int *output_length,
			   unsigned char *output_data);

/**
 * @deprecated Use ica_3des_encrypt() instead
 * @see ica_3des_encrypt()
 * Encrypt data using a triple length DES key.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param mode
 * Specifies the operational mode and must be:
 *	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. Must be a mutiple of the cipher
 * block.
 * @param input_data
 * Pointer to the input data data to be encrypted.
 * @param iv
 * Pointer to a valid 8 byte initialization vector.
 * @param des_key
 * Pointer to a triple length DES key.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be as large
 * as data_length. On output it contains the actual byte length of the data
 * returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting encrypted data.
 *
 * Returns 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaTDesEncrypt(ica_adapter_handle_t adapter_handle,
			    unsigned int mode,
			    unsigned int data_length,
			    unsigned char *input_data,
			    ica_des_vector_t *iv,
			    ica_des_key_triple_t *des_key,
			    unsigned int *output_length,
			    unsigned char *output_data);

/**
 * @deprecated Use ica_3des_decrypt() instead.
 * @see ica_3des_decrypt()
 * Decrypt data using a triple length DES key.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param mode
 * Specifies the operational mode and must be:
 *	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. Must be a mutiple of the cipher
 * block.
 * @param input_data
 * Pointer to the input data data to be decrypted.
 * @param iv
 * Pointer to a valid 8 byte initialization vector.
 * @param des_key
 * Pointer to a triple length DES key.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be as large
 * as data_length. On output it contains the actual byte length of the data
 * returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting decrypted data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaTDesDecrypt(ica_adapter_handle_t adapter_handle,
			    unsigned int mode,
			    unsigned int data_length,
			    unsigned char *input_data,
			    ica_des_vector_t *iv,
			    ica_des_key_triple_t *des_key,
			    unsigned int *output_length,
			    unsigned char *output_data);

/**
 * @deprecated Use ica_aes_encrypt() instead
 * @see ica_aes_encrypt()
 * Encrypt data using AES (key_length is 16, 24, or 32)
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param mode
 * Specifies the operational mode and must be:
 *	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. Must be a mutiple of the cipher
 * block.
 * @param input_data
 * Pointer to the input data data to be encrypted.
 * @param iv
 * Pointer to a valid 16 byte initialization vector.
 * @param key_length
 * Length of the AES key being used.
 * @param aes_key
 * Pointer to the AES key.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be as large
 * as data_length. On output it contains the actual byte length of the data
 * returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting encrypted data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaAesEncrypt(ica_adapter_handle_t adapter_handle,
			   unsigned int mode,
			   unsigned int data_length,
			   unsigned char *input_data,
			   ica_aes_vector_t *iv,
			   unsigned int key_length,
			   unsigned char *aes_key,
			   unsigned int *output_length,
			   unsigned char *output_data);

/**
 * @deprecated Use ica_aes_decrypt() instead.
 * @see ica_aes_decrypt()
 * Decrypt data using AES (key_length is 16, 24, or 32)
 * @adapter_handle
 * Pointer to a previously opened device handle.
 * @param mode
 * Specifies the operational mode and must be:
 *	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. Must be a mutiple of the cipher
 * block.
 * @param input_data
 * Pointer to the input data data to be decrypted.
 * @param iv
 * Pointer to a valid 16 byte initialization vector.
 * @param key_length
 * Length of the AES key being used.
 * @param aes_key
 * Pointer to the AES key.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be as large
 * as data_length. On output it contains the actual byte length of the data
 * returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting decrypted data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaAesDecrypt(ica_adapter_handle_t adapter_handle,
			   unsigned int mode,
			   unsigned int data_length,
			   unsigned char *input_data,
			   ica_aes_vector_t *iv,
			   unsigned int key_length,
			   unsigned char *aes_key,
			   unsigned int *output_length,
			   unsigned char *output_data);

/**
 * @deprecated icaDesMac(): This is no longer supported. Only a protoype.
 * Will be deleted with the next update.
 */
__attribute__ ((__deprecated__))
unsigned int icaDesMac(ICA_ADAPTER_HANDLE hAdapterHandle,
		       unsigned int dataLength,
		       unsigned char *pInputData,
		       ica_des_vector_t *pIcv,
		       ica_des_key_single_t *pKeyDes,
		       unsigned int *pOutputDataLength,
		       unsigned char *pOutputData);

/**
 * @deprecated icaTDesMac(): This is no longer supported. Only a prototype.
 * Will be deleted with the next updated.
 */
__attribute__ ((__deprecated__))
unsigned int icaTDesMac(ICA_ADAPTER_HANDLE hAdapterHandle,
			unsigned int inputDataLength,
			unsigned char *pInputData,
			ica_des_vector_t *pIcv,
			ica_des_key_triple_t *pKeyDes,
			unsigned int *pOutputDataLength,
			unsigned char *pOutputData);

/**
 * @deprecated Use ica_sha1() instead.
 * @see ica_sha1()
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-1 hashed and must be greater
 * than zero.
 * @param input_data
 * Pointer to the input data data.
 * @param context_length
 * Specifies the length of the SHA message context structure.
 * @param sha_context
 * Pointer to the SHA-1 context structure used to store the intermediate values
 * when chaining is used. The application must not modify the contents of this
 * structure when chaining is used.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be greater
 * than 20. On output it contains the actual byte length of the hash returned
 * in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaSha1(ica_adapter_handle_t adapter_handle,
		     unsigned int message_part,
		     unsigned int input_length,
		     unsigned char *input_data,
		     unsigned int context_length,
		     sha_context_t *sha_context,
		     unsigned int *output_length,
		     unsigned char *output_data);

/**
 * @deprecated Use ica_sha224() instead.
 * @see ica_sha224()
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-224 hashed and must be greater
 * than zero.
 * @param input_data
 * Pointer to the input data data.
 * @param context_length
 * Specifies the length of the SHA-256 message context structure.
 * @param sha256_context
 * Pointer to the SHA-256 context structure used to store the intermediate
 * values when chaining is used. The application must not modify the contents
 * of this structure when chaining is used.
 * Note: Due to the algorithm used by SHA-224 a SHA-256 context must be used.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be greater
 * than LENGTH_SHA256_HASH. On output itcontains the actual byte length of the
 * hash returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaSha224(ica_adapter_handle_t adapter_handle,
		       unsigned int message_part,
		       unsigned int input_length,
		       unsigned char *input_data,
		       unsigned int context_length,
		       sha256_context_t *sha256_context,
		       unsigned int *output_length,
		       unsigned char *output_data);

/**
 * @deprecated Use ica_sha256() instead.
 * @see ica_sha256()
 * Perform secure hash on input data using the SHA-256 algorithm.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-256 hashed and must be greater
 * than zero.
 * @param input_data
 * Pointer to the input data data.
 * @param context_length
 * Specifies the length of the SHA-256 message context structure.
 * @param sha256_context
 * Pointer to the SHA-256 context structure used to store the intermediate
 * values when chaining is used. The application must not modify the contents
 * of this structure when chaining is used.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be greater
 * than LENGTH_SHA256_HASH. On output it contains the actual byte length of the
 * hash returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaSha256(ica_adapter_handle_t adapter_handle,
		       unsigned int message_part,
		       unsigned int input_length,
		       unsigned char *input_data,
		       unsigned int context_length,
		       sha256_context_t *sha256_context,
		       unsigned int *output_length,
		       unsigned char *output_data);

/**
 * @deprecated Use ica_sha384() instead.
 * @see ica_sha384()
 * Perform secure hash on input data using the SHA-384 algorithm.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-384 hashed and must be greater
 * than zero.
 * @param input_data
 * Pointer to the input data data.
 * @param context_length
 * Specifies the length of the SHA-384 message context structure.
 * @param sha512_context
 * Pointer to the SHA-512 context structure used to store the intermediate
 * values when chaining is used. The application must not modify the contents
 * of this structure when chaining is used.
 * Note: Due to the algorithm used by SHA-384 a SHA-512 context must be used.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be greater
 * than LENGTH_SHA384_HASH. On output it contains the actual byte length of the
 * hash returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaSha384(ica_adapter_handle_t adapter_handle,
		       unsigned int message_part,
		       unsigned int input_length,
		       unsigned char *input_data,
		       unsigned int context_length,
		       sha512_context_t *sha512_context,
		       unsigned int *output_length,
		       unsigned char *output_data);

/**
 * @deprecated Use ica_sha512() instead
 * Perform secure hash on input data using the SHA-512 algorithm.
 * @param adapter_handle
 * Pointer to a previously opened device handle.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-512 hashed and must be
 * greater than zero.
 * @param input_data
 * Pointer to the input data data.
 * @param context_length
 * Specifies the length of the SHA-512 message context structure.
 * @param sha512_context
 * Pointer to the SHA-512 context structure used to store the intermediate
 * values when chaining is used. The application must not modify the contents
 * of this structure when chaining is used.
 * @param output_length
 * On input specifies the length of the output_data buffer and must be greater
 * than LENGTH_SHA512_HASH. On output it contains the actual byte length of
 * the hash returned in output_data.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
__attribute__ ((__deprecated__))
unsigned int icaSha512(ica_adapter_handle_t adapter_handle,
		       unsigned int message_part,
		       unsigned int input_length,
		       unsigned char *input_data,
		       unsigned int context_length,
		       sha512_context_t *sha512_context,
		       unsigned int *output_length,
		       unsigned char *output_data);

/**
 * @deprecated Use ica_random_number_generate() instead.
 * @see ica_random_number_generate()
 * Generate a random number.
 * @param adapter_handle
 * Dummy value.
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
__attribute__ ((__deprecated__))
unsigned int icaRandomNumberGenerate(ica_adapter_handle_t adapter_handle,
				     unsigned int output_length,
				     unsigned char *output_data);

struct mech_list_item;
void generate_pkcs11_mech_list(struct mech_list_item *head);




/*
 * NEW FUNCTION PROTOTYPES
 */

/**
 * Opens the specified adapter
 * @param adapter_handle Pointer to the file descriptor
 *
 * @return 0 as long as a valid parameter is given.
 * EINVAL for invalid parameter.
 */
unsigned int ica_open_adapter(ica_adapter_handle_t *adapter_handle);

/**
 * Closes a device handle.
 * @param adapter_handle Pointer to a previously opened device handle.
 *
 * @return 0 if successful.
 * errno of close() if unsuccessful
 */
unsigned int ica_close_adapter(ica_adapter_handle_t adapter_handle);

/**
 * Generate a random number.
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
unsigned int ica_random_number_generate(unsigned int output_length,
					unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-1 algorithm.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-1 hashed and must be greater
 * than zero.
 * @param input_data
 * Pointer to the input data data.
 * @param sha_context
 * Pointer to the SHA-1 context structure used to store the intermediate
 * values when chaining is used. The application must not modify the contents
 * of this structure when chaining is used.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_sha1(unsigned int message_part,
		      unsigned int input_length,
		      unsigned char *input_data,
		      sha_context_t *sha_context,
		      unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-224 algorithm.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-224 hashed and must be greater
 * than zero.
 * @param input_data
 * Pointer to the input data.
 * @param sha256_context
 * Pointer to the SHA-256 context structure used to store the intermediate
 * values when chaining is used. The application must not modify the contents
 * of this structure when chaining is used.
 * Note: Due to the algorithm used by SHA-224 a SHA-256 context must be used.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA224_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_sha224(unsigned int message_part,
	 		unsigned int input_length,
	 		unsigned char *input_data,
	 		sha256_context_t *sha256_context,
			unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-256 algorithm.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-256 hashed and must be greater
 * than zero.
 * @param input_data
 * Pointer to the input data.
 * @param sha256_context
 * Pointer to the SHA-256 context structure used to store the intermediate
 * values when chaining is used. The application must not modify the contents
 * of this structure when chaining is used.
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA256_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_sha256(unsigned int message_part,
			unsigned int input_length,
			unsigned char *input_data,
			sha256_context_t *sha256_context,
			unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-384 algorithm.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-384 hashed and must be greater
 * than zero.
 * @param input_data
 * Pointer to the input data.
 * @param sha512_context
 * Pointer to the SHA-512 context structure used to store the intermediate
 * values when chaining is used. The application must not modify the contents
 * of this structure when chaining is used.
 * Note: Due to the algorithm used by SHA-384 a SHA-512 context must be used.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA384_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_sha384(unsigned int message_part,
			uint64_t input_length,
			unsigned char *input_data,
			sha512_context_t *sha512_context,
			unsigned char *output_data);

/**
 * Perform secure hash on input data using the SHA-512 algorithm.
 * @param message_part
 * The message chaining state. Must be one of the following:
 *	SHA_MSG_PART_ONLY   - A single hash operation
 *	SHA_MSG_PART_FIRST  - The first part
 *	SHA_MSG_PART_MIDDLE - The middle part
 *	SHA_MSG_PART_FINAL  - The last part
 * @param input_length
 * The byte length of the input data to be SHA-512 hashed and must be greater
 * than zero.
 * @param input_data
 * Pointer to the input data.
 * @param sha512_context
 * Pointer to the SHA-512 context structure used to store the intermediate
 * values when chaining is used. The application must not modify the contents
 * of this structure when chaining is used.
 * @param output_data
 * Pointer to the buffer to contain the resulting hash data. The resulting
 * output data will have a length of SHA512_HASH_LENGTH. Make sure buffer has
 * at least this size.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_sha512(unsigned int message_part,
			uint64_t input_length,
			unsigned char *input_data,
			sha512_context_t *sha512_context,
			unsigned char *output_data);

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
 * well chosen exponent may result in the program loooping endlessly. Common
 * public exponents are 3 and 65537.
 * @param private_key
 * Pointer to where the generated private key in modulus/exponent format is to
 * be placed. Length of both private and public key should be set in bytes.
 * This value should comply with modulus bit length. Make sure that buffers in
 * the keys fit to this length.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * errno of OpenSSL key generation if it should fail.
 */
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
 * well chosen exponent may result in the program loooping endlessly. Common
 * public exponents are 3 and 65537.
 * @param private_key
 * Pointer to where the generated private key in CRT format is to be placed.
 * Length of both private and public key should be set in bytes. This value
 * should comply with modulus bit length. Make sure that buffers in the keys
 * fit to this length.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * errno of OpenSSL key generation if it should fail.
 */
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
 * ENOMEM if memory allocation fails.
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_rsa_mod_expo(ica_adapter_handle_t adapter_handle,
			      unsigned char *input_data,
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
 * ENOMEM if memory allocation fails.
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_rsa_crt(ica_adapter_handle_t adapter_handle,
			 unsigned char *input_data,
			 ica_rsa_key_crt_t *rsa_key,
			 unsigned char *output_data);

/**
 * Encrypt data using a single length DES key.
 * @param mode Specifies the operational mode and must be:
 *	       MODE_ECB - Use Electronic Code Book mode
 *	       MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. It has to be a multiple of the
 * cipher block which has a size of 8 byte.
 * @param input_data
 * Pointer to the input data data to be encrypted. Must be a multiple of the
 * cipher to use hw acceleration.
 * @param iv
 * Pointer to a valid 8 byte initialization vector when using CBC mode.
 * @param des_key
 * Pointer to a single length DES key.
 * @param output_data
 * Pointer to the buffer to contain the resulting encrypted data. Must be a
 * multiple of the cipher block and at least as big as the buffer for
 * input_data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_des_encrypt(unsigned int mode,
			     unsigned int data_length,
			     unsigned char *input_data,
			     ica_des_vector_t *iv,
			     ica_des_key_single_t *des_key,
			     unsigned char *output_data);

/**
 * Decrypt data using a single length DES key.
 * @param mode
 * Specifies the operational mode and must be:
 * 	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. It has to be a multiple of the
 * cipher block which has a size of 8 byte.
 * @param input_data
 * Pointer to the input data data to be decrypted. Must be a multiple of the
 * cipher to use hw acceleration.
 * @param iv
 * Pointer to a valid 8 byte initialization vector when using CBC mode.
 * @param des_key
 * Pointer to a single length DES key.
 * @param output_data
 * Pointer to the buffer to contain the resulting decrypted data. Must be a
 * multiple of the cipher block and at least as big as the buffer for
 * input_data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_des_decrypt(unsigned int mode,
			     unsigned int data_length,
			     unsigned char *input_data,
			     ica_des_vector_t *iv,
			     ica_des_key_single_t *des_key,
			     unsigned char *output_data);

/**
 * Encrypt data using a triple length DES key.
 * @param mode
 * Specifies the operational mode and must be:
 * 	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. It has to be a multiple of the
 * cipher block which has a size of 8 byte.
 * @param input_data
 * Pointer to the input data data to be encrypted. Must be a multiple of the
 * cipher block to use hw acceleration.
 * @param iv
 * Pointer to a valid 8 byte initialization vector when using CBC mode.
 * @param des_key
 * Pointer to a triple length DES key.
 * @param output_data
 * Pointer to the buffer to contain the resulting encrypted data. Must be a
 * multiple of the cipher block and at least as big as the buffer for
 * input_data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_3des_encrypt(unsigned int mode,
			      unsigned int data_length,
			      unsigned char *input_data,
			      ica_des_vector_t *iv,
			      ica_des_key_triple_t *des_key,
			      unsigned char *output_data);

/**
 * Decrypt data using a triple length DES key.
 * @param mode
 * Specifies the operational mode and must be:
 * 	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. It has to be a multiple of the
 * cipher block which has a size of 8 byte.
 * @param input_data
 * Pointer to the input data data to be decrypted. Must be a multiple of the
 * cipher block to use hw acceleration.
 * @param iv
 * Pointer to a valid 8 byte initialization vector when using CBC mode.
 * @param des_key
 * Pointer to a triple length DES key.
 * @param output_data
 * Pointer to the buffer to contain the resulting decrypted data. Must be a
 * multiple of the cipher block and at least as big as the buffer for
 * input_data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_3des_decrypt(unsigned int mode,
			      unsigned int data_length,
			      unsigned char *input_data,
			      ica_des_vector_t *iv,
			      ica_des_key_triple_t *des_key,
			      unsigned char *output_data);

/**
 * Encrypt data using AES (key_length is 16, 24, or 32)
 * @param mode
 * Specifies the operational mode and must be:
 * 	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. Input data length has to be
 * a multiple of the AES block length, which is 16 bytes.
 * @param input_data
 * Pointer to the input data data to be encrypted. Must be a multiple of the
 * cipher block to use hw acceleration.
 * @param iv
 * Pointer to a valid 16 byte initialization vector when using CBC mode.
 * @param key_length
 * Length of the AES key being used.
 * @param aes_key
 * Pointer to an AES key.
 * @param output_data
 * Pointer to the buffer to contain the resulting encrypted data. Must be a
 * multiple of the cipher block and at least as big as the buffer for
 * input_data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_aes_encrypt(unsigned int mode,
			     unsigned int data_length,
			     unsigned char *input_data,
			     ica_aes_vector_t *iv,
			     unsigned int key_length,
			     unsigned char *aes_key,
			     unsigned char *output_data);

/**
 * Decrypt data using AES (key_length is 16, 24, or 32)
 * @param mode
 * Specifies the operational mode and must be:
 * 	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. Input data length has to be
 * a multiple of the AES block length, which is 16 bytes.
 * @param input_data
 * Pointer to the input data data to be decrypted. Must be a multiple of the
 * cipher block to use hw acceleration.
 * @param iv
 * Pointer to a valid 16 byte initialization vector when using CBC mode.
 * @param key_length
 * Length of the AES key being used.
 * @param aes_key
 * Pointer to an AES key.
 * @param output_data
 * Pointer to the buffer to contain the resulting decrypted data. Must be a
 * multiple of the cipher block and at least as big as the buffer for
 * input_data.
 *
 * @return 0 if successful.
 * EINVAL if at least one invalid parameter is given.
 * EIO if the operation fails. This should never happen.
 */
unsigned int ica_aes_decrypt(unsigned int mode,
			     unsigned int data_length,
			     unsigned char *input_data,
			     ica_aes_vector_t *iv,
			     unsigned int key_length,
			     unsigned char *aes_key,
			     unsigned char *output_data);

#endif /* __ICA_API_H__ */

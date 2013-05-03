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

#include <stdint.h>

#define ica_adapter_handle_t int
typedef ica_adapter_handle_t ICA_ADAPTER_HANDLE;
#define DRIVER_NOT_LOADED -1

/**
 * Definitions to determine the direction of the symmetric
 * encryption/decryption functions.
 */
#define ICA_ENCRYPT 1
#define ICA_DECRYPT 0

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
 * Symetric encryption/decryption modes
 */
#define MODE_ECB 		1
#define MODE_CBC 		2
#define MODE_CFB 		3
#define MODE_OFB 		4
#define MODE_CTR 		5
#define MODE_XTS 		6
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
 * @deprecated
 * Use MODE_ECB, MODE_CBC instead.
 */
#define MODE_DES_ECB		MODE_ECB
#define MODE_DES_CBC		MODE_CBC
#define MODE_AES_ECB		MODE_ECB
#define MODE_AES_CBC		MODE_CBC

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
 * @param adapter_handle Pointer to the file descriptor for the adapter or
 * to DRIVER_NOT_LOADED if opening the crypto adapter failed.
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
unsigned int ica_sha1(unsigned int message_part,
		      unsigned int input_length,
		      unsigned char *input_data,
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
unsigned int ica_sha224(unsigned int message_part,
	 		unsigned int input_length,
	 		unsigned char *input_data,
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
unsigned int ica_sha256(unsigned int message_part,
			unsigned int input_length,
			unsigned char *input_data,
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
unsigned int ica_sha384(unsigned int message_part,
			uint64_t input_length,
			unsigned char *input_data,
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
 * @param input_data
 * Pointer to the input data.
 * @param sha512_context
 * Pointer to the SHA-512 context structure used to store intermediate values
 * needed when chaining is used. The contents are ignored for message part
 * SHA_MSG_PART_ONLY and SHA_MSG_PART_FIRST. This structuremust
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
 * @deprecated, use ica_des_ecb() or ica_des_cbc() instead.
 *
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
 * @deprecated, use ica_des_ecb() or ica_des_cbc() instead.
 *
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
 * @deprecated, use ica_3des_ecb() or ica_3des_cbc() instead.
 *
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
 * @deprecated, use ica_3des_ecb() or ica_3des_cbc() instead.
 *
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
 * @deprecated, use ica_aes_ecb() or ica_aes_cbc() instead.
 *
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
 * @deprecated, use ica_aes_ecb() or ica_aes_cbc() instead.
 *
 * Decrypt data using AES (key_length is 16, 24, or 32)
 * @param mode
 * Specifies the operational mode and must be:
 * 	MODE_ECB - Use Electronic Code Book mode
 *	MODE_CBC - Use Cipher Block Chaining mode
 * @param data_length
 * Specifies the byte length of the input data. Input data length has to be
 * a multiple of the AES block length, which is 16 bytes.
 * @param input_data
 * Pointer to the input data to be decrypted. Must be a multiple of the
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
unsigned int ica_des_ecb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
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
unsigned int ica_des_cbc(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
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
unsigned int ica_des_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			    unsigned long data_length, const unsigned char *key,
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
unsigned int ica_des_cfb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
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
 * increment without carry on the U least significant bytes in the counter
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
 * A number U between 1 and cipher block size. The value is used by the counter
 * increment function which increments a counter value by incrementing without
 * carry the least significant U bytes of the counter value.
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
unsigned int ica_des_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 const unsigned char *key,
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
unsigned int ica_des_ctrlist(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     const unsigned char *key,
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
unsigned int ica_des_ofb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
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
unsigned int ica_des_cmac(const unsigned char *message, unsigned long message_length,
			  unsigned char *mac, unsigned int mac_length,
			  const unsigned char *key,
			  unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an DES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B.
 * ica_des_cmc_intermediate and ica_des_cmac_last can be used when the message
 * to be authenticated or to be verfied using CMAC is supplied in multiple
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
unsigned int ica_des_cmac_intermediate(const unsigned char *message,
				       unsigned long message_length,
				       const unsigned char *key,
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
unsigned int ica_des_cmac_last(const unsigned char *message, unsigned long message_length,
			       unsigned char *mac, unsigned int mac_length,
			       const unsigned char *key,
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
unsigned int ica_3des_ecb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, const unsigned char *key,
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
unsigned int ica_3des_cbc(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, const unsigned char *key,
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
 * ica_3des_cbc_cs call provided the chunc is greater than cipher block size
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
unsigned int ica_3des_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     const unsigned char *key,
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
unsigned int ica_3des_cfb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, const unsigned char *key,
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
 * increment without carry on the U least significant bytes in the counter
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
 * A number U between 1 and cipher block size. The value is used by the counter
 * increment function which increments a counter value by incrementing without
 * carry the least significant U bytes of the counter value.
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
unsigned int ica_3des_ctr(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length,
			  const unsigned char *key,
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
unsigned int ica_3des_ctrlist(const unsigned char *in_data, unsigned char *out_data,
			      unsigned long data_length,
			      const unsigned char *key,
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
unsigned int ica_3des_ofb(const unsigned char *in_data, unsigned char *out_data,
			  unsigned long data_length, const unsigned char *key,
			  unsigned char *iv, unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an 3DES key
 * using the Block Cipher Based Message Authetication Code (CMAC) mode as
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
unsigned int ica_3des_cmac(const unsigned char *message, unsigned long message_length,
			   unsigned char *mac, unsigned int mac_length,
			   const unsigned char *key,
			   unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an 3DES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B.
 * ica_3des_cmc_intermediate and ica_3des_cmac_last can be used when the
 * message to be authenticated or to be verfied using CMAC is supplied in
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
unsigned int ica_3des_cmac_intermediate(const unsigned char *message, unsigned long message_length,
					const unsigned char *key,
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
unsigned int ica_3des_cmac_last(const unsigned char *message, unsigned long message_length,
				unsigned char *mac, unsigned int mac_length,
				const unsigned char *key, unsigned char *iv,
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
unsigned int ica_aes_ecb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
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
 * Pointer to a valid initialization vector of size chipher block size. This
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
unsigned int ica_aes_cbc(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
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
unsigned int ica_aes_cbc_cs(const unsigned char *in_data, unsigned char *out_data,
			    unsigned long data_length,
			    const unsigned char *key, unsigned int key_length,
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
unsigned int ica_aes_cfb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
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
 * increment without carry on the U least significant bytes in the counter
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
 * A number U between 1 and cipher block size. The value is used by the counter
 * increment function which increments a counter value by incrementing without
 * carry the least significant U bytes of the counter value.
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
unsigned int ica_aes_ctr(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 const unsigned char *key, unsigned int key_length,
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
unsigned int ica_aes_ctrlist(const unsigned char *in_data, unsigned char *out_data,
			     unsigned long data_length,
			     const unsigned char *key, unsigned int key_length,
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
unsigned int ica_aes_ofb(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length, const unsigned char *key,
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
unsigned int ica_aes_cmac(const unsigned char *message, unsigned long message_length,
			  unsigned char *mac, unsigned int mac_length,
			  const unsigned char *key, unsigned int key_length,
			  unsigned int direction);

/**
 * Authenticate data or verify the authenticity of data with an AES key using
 * the Block Cipher Based Message Authentication Code (CMAC) mode as described
 * in NIST Special Publication 800-38B.
 * ica_aes_cmc_intermediate and ica_aes_cmac_last can be used when the message
 * to be authenticated or to be verfied using CMAC is supplied in multiple
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
unsigned int ica_aes_cmac_intermediate(const unsigned char *message,
				       unsigned long message_length,
				       const unsigned char *key, unsigned int key_length,
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
unsigned int ica_aes_cmac_last(const unsigned char *message, unsigned long message_length,
			       unsigned char *mac, unsigned int mac_length,
			       const unsigned char *key, unsigned int key_length,
			       unsigned char *iv,
			       unsigned int direction);

/**
 * Encrypt or decrypt data with an AES key using the XEX Tweakable Bloc Cipher
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
 * tweek value (Key1 in IEEE Std 1619-2007).
 * @param key2
 * Pointer to a buffer containing a valid AES key key2 is used to encrypt the
 * tweak (Key2 in IEEE Std 1619-2007).
 * @param key_length
 * The length in bytes of the AES key. For XTS supported AES key sizes are 16
 * and 32 for AES-128 and AES-256 respectively.
 * @param tweak
 * Pointer to a valid 16 byte tweak value (as in IEEE Std 1619-2007). This
 * tweak will be overwritten during the function. If data_length is a multiple
 * of the cipher block size the result value in tweak may be used as tweak
 * value for a chained ica_aes_xts call with the same key pair.
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
unsigned int ica_aes_xts(const unsigned char *in_data, unsigned char *out_data,
			 unsigned long data_length,
			 const unsigned char *key1, const unsigned char *key2,
			 unsigned int key_length, unsigned char *tweak,
			 unsigned int direction);

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
unsigned int ica_aes_ccm(unsigned char *payload, unsigned long payload_length,
			 unsigned char *ciphertext_n_mac, unsigned int mac_length,
			 const unsigned char *assoc_data, unsigned long assoc_data_length,
			 const unsigned char *nonce, unsigned int nonce_length,
			 const unsigned char *key, unsigned int key_length,
			 unsigned int direction);

/**
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
 * @param aad
 * Pointer to a readable buffer of size greater than or equal to aad_length
 * bytes. The additional authenticated data in the most significant aad_length
 * bytes is subject to the authentication code computation but will not be
 * encrypted.
 * @param aad_length
 * Length in bytes of the additional authenticated data in aad. It must be
 * equal or greater than 0 and less than 2^61.
 * @param tag
 * Pointer to a buffer of size greater than or equal to tag_length bytes.
 * If direction is 1 the buffer must be writable and a message authentication
 * code for the additional authenticated data in aad and the plain text in
 * plaintext of size tag_length bytes will be written to the buffer.
 * If direction is 0 the buffer must be readable and contain a message
 * authentication code that will be verified against the additional
 * authenticated data in aad and decrypted cipher text from ciphertext.
 * @param tag_length
 * Length in bytes of the message authentication code tag in bytes.
 * Valid values are 4, 8, 12, 13, 14, 15, 16.
 * @param key
 * Pointer to a valid AES key.
 * @param key_length
 * Length in bytes of the AES key. Supported sizes are 16, 24, and 32 for
 * AES-128, AES-192 and AES-256 respectively. Therefore, you can use the
 * macros: AES_KEY_LEN128, AES_KEY_LEN192, and AES_KEY_LEN256.
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
unsigned int ica_aes_gcm(unsigned char *plaintext, unsigned long plaintext_length,
			 unsigned char *ciphertext,
			 const unsigned char *iv, unsigned int iv_length,
			 const unsigned char *aad, unsigned long aad_length,
			 unsigned char *tag, unsigned int tag_length,
			 const unsigned char *key, unsigned int key_length,
			 unsigned int direction);

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
unsigned int ica_get_functionlist(libica_func_list_element *pmech_list, 
					unsigned int *pmech_list_len);

#endif /* __ICA_API_H__ */
